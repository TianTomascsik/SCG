//! Firewall self-configuration (iptables interception rules).
//!
//! Implements the `NetworkManager` pattern described in the interface docs:
//! the gateway reads `intercept` blocks from its config and installs/tears down
//! the corresponding iptables chains and routing policy at startup/shutdown.
//!
//! Design choices:
//! - Idempotent: flushes and recreates owned chains on each setup.
//! - Fail-closed: any setup error rolls back and prevents startup.
//! - Loop avoidance: owner-uid RETURN rule prevents the gateway's own outbound
//!   traffic from being re-intercepted.
//! - Teardown removes only what was added (chains, jumps, routing policy).

use crate::management::config::{GatewayConfig, InterceptConfig, InterceptMode, Proto, RuleConfig};
use log::{debug, info};
use std::net::SocketAddr;
use std::process::Command;

// ─── Chain names (shared with preflight_check) ───────────────────────────────

const CHAIN_ENCRYPT: &str = "SCG_ENCRYPT";
const CHAIN_DECRYPT: &str = "SCG_DECRYPT";
const TPROXY_MARK: &str = "1";
const TPROXY_TABLE: &str = "100";

// ─── Public API ──────────────────────────────────────────────────────────────

/// Manages iptables rules derived from the gateway config.
/// Holds state needed to tear down rules on shutdown.
pub struct FirewallManager {
    /// Whether we created the SCG_ENCRYPT chain (nat) in iptables.
    owns_encrypt_chain: bool,
    /// Whether we created the SCG_ENCRYPT chain (nat) in ip6tables.
    owns_encrypt_chain_v6: bool,
    /// Whether we created the SCG_DECRYPT chain (mangle).
    owns_decrypt_chain: bool,
    /// Whether we added the ip rule + ip route for TPROXY.
    owns_routing_policy: bool,
}

impl FirewallManager {
    /// Build and apply firewall rules from the gateway configuration.
    ///
    /// Returns a `FirewallManager` that tracks what was created (for teardown),
    /// or an error string if setup fails.
    pub fn setup(config: &GatewayConfig) -> Result<Self, String> {
        let rules_with_intercept: Vec<&RuleConfig> =
            config.rules.iter().filter(|r| r.intercept.is_some()).collect();

        if rules_with_intercept.is_empty() {
            return Ok(Self {
                owns_encrypt_chain: false,
                owns_encrypt_chain_v6: false,
                owns_decrypt_chain: false,
                owns_routing_policy: false,
            });
        }

        // Classify which chains/features we need.
        let needs_encrypt_chain = rules_with_intercept.iter().any(|r| {
            matches!(
                r.intercept.as_ref().unwrap().mode,
                InterceptMode::IngressRedirect | InterceptMode::EgressRedirect
            )
        });
        let needs_decrypt_chain = rules_with_intercept
            .iter()
            .any(|r| r.intercept.as_ref().unwrap().mode == InterceptMode::Tproxy);

        let mut mgr = Self {
            owns_encrypt_chain: false,
            owns_encrypt_chain_v6: false,
            owns_decrypt_chain: false,
            owns_routing_policy: false,
        };

        // ── Setup encrypt chain ─────────────────────────────────────────────
        if needs_encrypt_chain {
            if let Err(e) = mgr.ensure_encrypt_chain(&rules_with_intercept) {
                mgr.teardown();
                return Err(e);
            }
        }

        // ── Setup decrypt chain (TPROXY) ────────────────────────────────────
        if needs_decrypt_chain {
            if let Err(e) = mgr.ensure_decrypt_chain(&rules_with_intercept) {
                mgr.teardown();
                return Err(e);
            }
        }

        let intercept_count = rules_with_intercept.len();
        info!(
            "Firewall self-configuration complete: {} intercept rule(s) installed",
            intercept_count
        );

        Ok(mgr)
    }

    /// Tear down all iptables rules and routing policy that this manager created.
    /// Safe to call multiple times (idempotent).
    pub fn teardown(&self) {
        if self.owns_encrypt_chain {
            Self::remove_chain("iptables", "nat", CHAIN_ENCRYPT);
        }
        if self.owns_encrypt_chain_v6 {
            Self::remove_chain("ip6tables", "nat", CHAIN_ENCRYPT);
        }
        if self.owns_decrypt_chain {
            Self::remove_chain("iptables", "mangle", CHAIN_DECRYPT);
        }
        if self.owns_routing_policy {
            Self::remove_routing_policy();
        }
        info!("Firewall rules torn down");
    }

    // ── Encrypt chain setup ─────────────────────────────────────────────────

    fn ensure_encrypt_chain(&mut self, rules: &[&RuleConfig]) -> Result<(), String> {
        // Create or flush the chain.
        Self::create_or_flush_chain("iptables", "nat", CHAIN_ENCRYPT)?;
        self.owns_encrypt_chain = true;

        // Ensure the jump from the parent chain exists.
        // ingress_redirect → PREROUTING; egress_redirect → OUTPUT.
        let has_ingress = rules.iter().any(|r| {
            r.intercept.as_ref().unwrap().mode == InterceptMode::IngressRedirect
        });
        let has_egress = rules.iter().any(|r| {
            r.intercept.as_ref().unwrap().mode == InterceptMode::EgressRedirect
        });

        if has_ingress {
            Self::ensure_jump("iptables", "nat", "PREROUTING", CHAIN_ENCRYPT)?;
        }
        if has_egress {
            Self::ensure_jump("iptables", "nat", "OUTPUT", CHAIN_ENCRYPT)?;
            // Loop avoidance: gateway's own uid returns immediately.
            let uid = unsafe { libc::geteuid() };
            run_nft("iptables", &[
                "-t", "nat", "-A", CHAIN_ENCRYPT,
                "-m", "owner", "--uid-owner", &uid.to_string(),
                "-j", "RETURN",
            ])?;

            // IPv6: set up equivalent chain for egress (browsers use ::1 for localhost).
            Self::create_or_flush_chain("ip6tables", "nat", CHAIN_ENCRYPT)?;
            self.owns_encrypt_chain_v6 = true;
            Self::ensure_jump("ip6tables", "nat", "OUTPUT", CHAIN_ENCRYPT)?;
            run_nft("ip6tables", &[
                "-t", "nat", "-A", CHAIN_ENCRYPT,
                "-m", "owner", "--uid-owner", &uid.to_string(),
                "-j", "RETURN",
            ])?;
        }

        // Add per-rule REDIRECT entries.
        for rule in rules {
            let ic = rule.intercept.as_ref().unwrap();
            if ic.mode != InterceptMode::IngressRedirect && ic.mode != InterceptMode::EgressRedirect
            {
                continue;
            }
            let listen_port = Self::listen_port(rule)?;
            let proto = Self::intercept_proto(rule, ic);

            match ic.mode {
                InterceptMode::IngressRedirect => {
                    let mut args = vec![
                        "-t", "nat", "-A", CHAIN_ENCRYPT,
                        "-p", &proto,
                    ];
                    let iface_owned;
                    if let Some(ref iface) = ic.in_interface {
                        iface_owned = iface.clone();
                        args.extend_from_slice(&["-i", &iface_owned]);
                    }
                    let dports = ic.match_dports.clone();
                    if dports.contains(',') || dports.contains(':') {
                        args.extend_from_slice(&["-m", "multiport", "--dports", &dports]);
                    } else {
                        args.extend_from_slice(&["--dport", &dports]);
                    }
                    let port_str = listen_port.to_string();
                    args.extend_from_slice(&["-j", "REDIRECT", "--to-port", &port_str]);
                    run_iptables(&args)?;
                    debug!("  [{}] ingress_redirect → :{}", rule.name, listen_port);
                }
                InterceptMode::EgressRedirect => {
                    let dports = ic.match_dports.clone();
                    let port_str = listen_port.to_string();
                    for dst in &ic.match_dst {
                        let mut args = vec![
                            "-t", "nat", "-A", CHAIN_ENCRYPT,
                            "-d", dst,
                            "-p", &proto,
                        ];
                        if dports.contains(',') || dports.contains(':') {
                            args.extend_from_slice(&["-m", "multiport", "--dports", &dports]);
                        } else {
                            args.extend_from_slice(&["--dport", &dports]);
                        }
                        args.extend_from_slice(&["-j", "REDIRECT", "--to-port", &port_str]);
                        run_nft("iptables", &args)?;

                        // IPv6 mirror: 127.0.0.1 → also cover ::1 via ip6tables.
                        if dst == "127.0.0.1" {
                            let mut args6 = vec![
                                "-t", "nat", "-A", CHAIN_ENCRYPT,
                                "-d", "::1",
                                "-p", &proto,
                            ];
                            if dports.contains(',') || dports.contains(':') {
                                args6.extend_from_slice(&["-m", "multiport", "--dports", &dports]);
                            } else {
                                args6.extend_from_slice(&["--dport", &dports]);
                            }
                            args6.extend_from_slice(&["-j", "REDIRECT", "--to-port", &port_str]);
                            run_nft("ip6tables", &args6)?;
                        }
                    }
                    debug!(
                        "  [{}] egress_redirect {} dst(s) → :{}",
                        rule.name,
                        ic.match_dst.len(),
                        listen_port
                    );
                }
                _ => unreachable!(),
            }
        }

        Ok(())
    }

    // ── Decrypt chain setup (TPROXY) ────────────────────────────────────────

    fn ensure_decrypt_chain(&mut self, rules: &[&RuleConfig]) -> Result<(), String> {
        // Routing policy (ip rule + ip route).
        Self::ensure_routing_policy()?;
        self.owns_routing_policy = true;

        // Create or flush the mangle chain.
        Self::create_or_flush_chain("iptables", "mangle", CHAIN_DECRYPT)?;
        self.owns_decrypt_chain = true;

        // Jump from PREROUTING.
        Self::ensure_jump("iptables", "mangle", "PREROUTING", CHAIN_DECRYPT)?;

        // Guard: let already-transparent connections bypass.
        run_iptables(&[
            "-t", "mangle", "-A", CHAIN_DECRYPT,
            "-m", "socket", "--transparent",
            "-j", "RETURN",
        ])?;

        // Exclude gateway's own listening ports from TPROXY (RETURN rules).
        for rule in rules {
            let ic = rule.intercept.as_ref().unwrap();
            if ic.mode != InterceptMode::Tproxy {
                continue;
            }
            let listen_port = Self::listen_port(rule)?;
            let proto = Self::intercept_proto(rule, ic);
            let port_str = listen_port.to_string();
            run_iptables(&[
                "-t", "mangle", "-A", CHAIN_DECRYPT,
                "-p", &proto, "--dport", &port_str,
                "-j", "RETURN",
            ])?;
        }

        // Per-rule TPROXY entries.
        for rule in rules {
            let ic = rule.intercept.as_ref().unwrap();
            if ic.mode != InterceptMode::Tproxy {
                continue;
            }
            let listen_port = Self::listen_port(rule)?;
            let proto = Self::intercept_proto(rule, ic);
            let dports = ic.match_dports.clone();
            let port_str = listen_port.to_string();
            let mark_spec = format!("{TPROXY_MARK}/{TPROXY_MARK}");

            for src in &ic.match_src {
                let mut args = vec![
                    "-t", "mangle", "-A", CHAIN_DECRYPT,
                    "-s", src,
                    "-p", &proto,
                ];
                if dports.contains(',') || dports.contains(':') {
                    args.extend_from_slice(&["-m", "multiport", "--dports", &dports]);
                } else {
                    args.extend_from_slice(&["--dport", &dports]);
                }
                args.extend_from_slice(&[
                    "-j", "TPROXY",
                    "--on-port", &port_str,
                    "--tproxy-mark", &mark_spec,
                ]);
                run_iptables(&args)?;
            }
            debug!(
                "  [{}] tproxy {} src(s) → :{}",
                rule.name,
                ic.match_src.len(),
                listen_port
            );
        }

        Ok(())
    }

    // ── Routing policy ──────────────────────────────────────────────────────

    fn ensure_routing_policy() -> Result<(), String> {
        // ip rule add fwmark 1 lookup 100
        let existing = Command::new("ip")
            .args(["rule", "show"])
            .output()
            .map_err(|e| format!("Failed to run 'ip rule show': {}", e))?;
        let out = String::from_utf8_lossy(&existing.stdout);
        if !out.contains("fwmark") || !out.contains(&format!("lookup {TPROXY_TABLE}")) {
            run_cmd("ip", &["rule", "add", "fwmark", TPROXY_MARK, "lookup", TPROXY_TABLE])?;
        }

        // ip route add local default dev lo table 100
        let existing_routes = Command::new("ip")
            .args(["route", "show", "table", TPROXY_TABLE])
            .output()
            .map_err(|e| format!("Failed to run 'ip route show': {}", e))?;
        let route_out = String::from_utf8_lossy(&existing_routes.stdout);
        if !route_out.contains("local default") {
            run_cmd(
                "ip",
                &["route", "add", "local", "default", "dev", "lo", "table", TPROXY_TABLE],
            )?;
        }

        Ok(())
    }

    fn remove_routing_policy() {
        let _ = Command::new("ip")
            .args(["rule", "del", "fwmark", TPROXY_MARK, "lookup", TPROXY_TABLE])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = Command::new("ip")
            .args(["route", "del", "local", "default", "dev", "lo", "table", TPROXY_TABLE])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn create_or_flush_chain(binary: &str, table: &str, chain: &str) -> Result<(), String> {
        // Check if chain exists already.
        let exists = Command::new(binary)
            .args(["-t", table, "-L", chain, "-n"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if exists {
            // Flush existing rules.
            run_nft(binary, &["-t", table, "-F", chain])?;
        } else {
            // Create new chain.
            run_nft(binary, &["-t", table, "-N", chain])?;
        }
        Ok(())
    }

    fn ensure_jump(binary: &str, table: &str, parent: &str, chain: &str) -> Result<(), String> {
        // Check if a jump already exists (idempotent).
        let check = Command::new(binary)
            .args(["-t", table, "-C", parent, "-j", chain])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match check {
            Ok(s) if s.success() => Ok(()), // already present
            _ => run_nft(binary, &["-t", table, "-A", parent, "-j", chain]),
        }
    }

    fn remove_chain(binary: &str, table: &str, chain: &str) {
        // Remove jumps from built-in chains.
        for parent in &["PREROUTING", "OUTPUT", "INPUT", "FORWARD", "POSTROUTING"] {
            let _ = Command::new(binary)
                .args(["-t", table, "-D", parent, "-j", chain])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        // Flush and delete the chain.
        let _ = Command::new(binary)
            .args(["-t", table, "-F", chain])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = Command::new(binary)
            .args(["-t", table, "-X", chain])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    fn listen_port(rule: &RuleConfig) -> Result<u16, String> {
        let addr: SocketAddr = rule.listen_addr.parse().map_err(|e| {
            format!(
                "Rule '{}': cannot parse listen_addr '{}': {}",
                rule.name, rule.listen_addr, e
            )
        })?;
        Ok(addr.port())
    }

    fn intercept_proto(rule: &RuleConfig, ic: &InterceptConfig) -> String {
        if let Some(ref p) = ic.protocol {
            p.clone()
        } else {
            match rule.listen_proto {
                Proto::Tcp => "tcp".to_string(),
                Proto::Udp => "udp".to_string(),
                // UDS/SHM should never reach here (caught by validation).
                _ => "tcp".to_string(),
            }
        }
    }
}

// ─── Command execution helpers ───────────────────────────────────────────────

fn run_iptables(args: &[&str]) -> Result<(), String> {
    run_cmd("iptables", args)
}

fn run_nft(binary: &str, args: &[&str]) -> Result<(), String> {
    run_cmd(binary, args)
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    debug!("exec: {} {}", cmd, args.join(" "));
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute '{}': {}", cmd, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "'{}' failed (exit {}): {}",
            format!("{} {}", cmd, args.join(" ")),
            output.status.code().unwrap_or(-1),
            stderr.trim()
        ));
    }
    Ok(())
}

// ─── Unit-testable plan builder ──────────────────────────────────────────────

/// A planned iptables command (for testing without execution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesCmd {
    pub program: String,
    pub args: Vec<String>,
}

/// Build the list of iptables/ip commands that `setup` would execute.
/// Pure function for unit testing.
pub fn plan_firewall_commands(config: &GatewayConfig) -> Vec<IptablesCmd> {
    let mut cmds = Vec::new();
    let rules_with_intercept: Vec<&RuleConfig> =
        config.rules.iter().filter(|r| r.intercept.is_some()).collect();

    if rules_with_intercept.is_empty() {
        return cmds;
    }

    let needs_encrypt = rules_with_intercept.iter().any(|r| {
        matches!(
            r.intercept.as_ref().unwrap().mode,
            InterceptMode::IngressRedirect | InterceptMode::EgressRedirect
        )
    });
    let needs_decrypt = rules_with_intercept
        .iter()
        .any(|r| r.intercept.as_ref().unwrap().mode == InterceptMode::Tproxy);

    let has_ingress = rules_with_intercept.iter().any(|r| {
        r.intercept.as_ref().unwrap().mode == InterceptMode::IngressRedirect
    });
    let has_egress = rules_with_intercept.iter().any(|r| {
        r.intercept.as_ref().unwrap().mode == InterceptMode::EgressRedirect
    });

    if needs_encrypt {
        // Create/flush chain.
        cmds.push(ipt(&["-t", "nat", "-N", CHAIN_ENCRYPT]));
        // Jumps.
        if has_ingress {
            cmds.push(ipt(&["-t", "nat", "-A", "PREROUTING", "-j", CHAIN_ENCRYPT]));
        }
        if has_egress {
            cmds.push(ipt(&["-t", "nat", "-A", "OUTPUT", "-j", CHAIN_ENCRYPT]));
            let uid = unsafe { libc::geteuid() };
            cmds.push(ipt(&[
                "-t", "nat", "-A", CHAIN_ENCRYPT,
                "-m", "owner", "--uid-owner", &uid.to_string(),
                "-j", "RETURN",
            ]));
            // IPv6 equivalent for egress (browsers use ::1 for localhost).
            cmds.push(ip6t(&["-t", "nat", "-N", CHAIN_ENCRYPT]));
            cmds.push(ip6t(&["-t", "nat", "-A", "OUTPUT", "-j", CHAIN_ENCRYPT]));
            cmds.push(ip6t(&[
                "-t", "nat", "-A", CHAIN_ENCRYPT,
                "-m", "owner", "--uid-owner", &uid.to_string(),
                "-j", "RETURN",
            ]));
        }

        // Per-rule entries.
        for rule in &rules_with_intercept {
            let ic = rule.intercept.as_ref().unwrap();
            if ic.mode != InterceptMode::IngressRedirect && ic.mode != InterceptMode::EgressRedirect
            {
                continue;
            }
            let listen_port = rule
                .listen_addr
                .parse::<SocketAddr>()
                .map(|a| a.port().to_string())
                .unwrap_or_default();
            let proto = if let Some(ref p) = ic.protocol {
                p.clone()
            } else {
                match rule.listen_proto {
                    Proto::Tcp => "tcp".to_string(),
                    Proto::Udp => "udp".to_string(),
                    _ => "tcp".to_string(),
                }
            };

            match ic.mode {
                InterceptMode::IngressRedirect => {
                    let mut args = vec![
                        "-t".to_string(), "nat".to_string(),
                        "-A".to_string(), CHAIN_ENCRYPT.to_string(),
                        "-p".to_string(), proto.clone(),
                    ];
                    if let Some(ref iface) = ic.in_interface {
                        args.push("-i".to_string());
                        args.push(iface.clone());
                    }
                    if ic.match_dports.contains(',') || ic.match_dports.contains(':') {
                        args.extend([
                            "-m".to_string(), "multiport".to_string(),
                            "--dports".to_string(), ic.match_dports.clone(),
                        ]);
                    } else {
                        args.extend(["--dport".to_string(), ic.match_dports.clone()]);
                    }
                    args.extend([
                        "-j".to_string(), "REDIRECT".to_string(),
                        "--to-port".to_string(), listen_port.clone(),
                    ]);
                    cmds.push(IptablesCmd {
                        program: "iptables".to_string(),
                        args,
                    });
                }
                InterceptMode::EgressRedirect => {
                    for dst in &ic.match_dst {
                        let mut args = vec![
                            "-t".to_string(), "nat".to_string(),
                            "-A".to_string(), CHAIN_ENCRYPT.to_string(),
                            "-d".to_string(), dst.clone(),
                            "-p".to_string(), proto.clone(),
                        ];
                        if ic.match_dports.contains(',') || ic.match_dports.contains(':') {
                            args.extend([
                                "-m".to_string(), "multiport".to_string(),
                                "--dports".to_string(), ic.match_dports.clone(),
                            ]);
                        } else {
                            args.extend(["--dport".to_string(), ic.match_dports.clone()]);
                        }
                        args.extend([
                            "-j".to_string(), "REDIRECT".to_string(),
                            "--to-port".to_string(), listen_port.clone(),
                        ]);
                        cmds.push(IptablesCmd {
                            program: "iptables".to_string(),
                            args,
                        });

                        // IPv6 mirror: 127.0.0.1 → also cover ::1.
                        if dst == "127.0.0.1" {
                            let mut args6 = vec![
                                "-t".to_string(), "nat".to_string(),
                                "-A".to_string(), CHAIN_ENCRYPT.to_string(),
                                "-d".to_string(), "::1".to_string(),
                                "-p".to_string(), proto.clone(),
                            ];
                            if ic.match_dports.contains(',') || ic.match_dports.contains(':') {
                                args6.extend([
                                    "-m".to_string(), "multiport".to_string(),
                                    "--dports".to_string(), ic.match_dports.clone(),
                                ]);
                            } else {
                                args6.extend(["--dport".to_string(), ic.match_dports.clone()]);
                            }
                            args6.extend([
                                "-j".to_string(), "REDIRECT".to_string(),
                                "--to-port".to_string(), listen_port.clone(),
                            ]);
                            cmds.push(IptablesCmd {
                                program: "ip6tables".to_string(),
                                args: args6,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if needs_decrypt {
        // Routing policy.
        cmds.push(IptablesCmd {
            program: "ip".to_string(),
            args: vec![
                "rule".to_string(), "add".to_string(),
                "fwmark".to_string(), TPROXY_MARK.to_string(),
                "lookup".to_string(), TPROXY_TABLE.to_string(),
            ],
        });
        cmds.push(IptablesCmd {
            program: "ip".to_string(),
            args: vec![
                "route".to_string(), "add".to_string(),
                "local".to_string(), "default".to_string(),
                "dev".to_string(), "lo".to_string(),
                "table".to_string(), TPROXY_TABLE.to_string(),
            ],
        });

        // Create/flush chain.
        cmds.push(ipt(&["-t", "mangle", "-N", CHAIN_DECRYPT]));
        cmds.push(ipt(&["-t", "mangle", "-A", "PREROUTING", "-j", CHAIN_DECRYPT]));

        // Transparent socket guard.
        cmds.push(ipt(&[
            "-t", "mangle", "-A", CHAIN_DECRYPT,
            "-m", "socket", "--transparent",
            "-j", "RETURN",
        ]));

        // RETURN for own listening ports.
        for rule in &rules_with_intercept {
            let ic = rule.intercept.as_ref().unwrap();
            if ic.mode != InterceptMode::Tproxy {
                continue;
            }
            let listen_port = rule
                .listen_addr
                .parse::<SocketAddr>()
                .map(|a| a.port().to_string())
                .unwrap_or_default();
            let proto = if let Some(ref p) = ic.protocol {
                p.clone()
            } else {
                match rule.listen_proto {
                    Proto::Tcp => "tcp".to_string(),
                    Proto::Udp => "udp".to_string(),
                    _ => "tcp".to_string(),
                }
            };
            cmds.push(ipt(&[
                "-t", "mangle", "-A", CHAIN_DECRYPT,
                "-p", &proto, "--dport", &listen_port,
                "-j", "RETURN",
            ]));
        }

        // Per-rule TPROXY entries.
        for rule in &rules_with_intercept {
            let ic = rule.intercept.as_ref().unwrap();
            if ic.mode != InterceptMode::Tproxy {
                continue;
            }
            let listen_port = rule
                .listen_addr
                .parse::<SocketAddr>()
                .map(|a| a.port().to_string())
                .unwrap_or_default();
            let proto = if let Some(ref p) = ic.protocol {
                p.clone()
            } else {
                match rule.listen_proto {
                    Proto::Tcp => "tcp".to_string(),
                    Proto::Udp => "udp".to_string(),
                    _ => "tcp".to_string(),
                }
            };
            let mark_spec = format!("{TPROXY_MARK}/{TPROXY_MARK}");

            for src in &ic.match_src {
                let mut args = vec![
                    "-t".to_string(), "mangle".to_string(),
                    "-A".to_string(), CHAIN_DECRYPT.to_string(),
                    "-s".to_string(), src.clone(),
                    "-p".to_string(), proto.clone(),
                ];
                if ic.match_dports.contains(',') || ic.match_dports.contains(':') {
                    args.extend([
                        "-m".to_string(), "multiport".to_string(),
                        "--dports".to_string(), ic.match_dports.clone(),
                    ]);
                } else {
                    args.extend(["--dport".to_string(), ic.match_dports.clone()]);
                }
                args.extend([
                    "-j".to_string(), "TPROXY".to_string(),
                    "--on-port".to_string(), listen_port.clone(),
                    "--tproxy-mark".to_string(), mark_spec.clone(),
                ]);
                cmds.push(IptablesCmd {
                    program: "iptables".to_string(),
                    args,
                });
            }
        }
    }

    cmds
}

fn ipt(args: &[&str]) -> IptablesCmd {
    IptablesCmd {
        program: "iptables".to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
    }
}

fn ip6t(args: &[&str]) -> IptablesCmd {
    IptablesCmd {
        program: "ip6tables".to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal config helper that builds a GatewayConfig from JSON.
    fn cfg(json: serde_json::Value) -> GatewayConfig {
        serde_json::from_value(json).expect("test config should parse")
    }

    #[test]
    fn no_intercept_produces_no_commands() {
        let config = cfg(serde_json::json!({
            "rules": [{
                "name": "basic",
                "direction": "encrypt",
                "listen_addr": "0.0.0.0:8443",
                "upstream_addr": "127.0.0.1:80"
            }]
        }));
        let cmds = plan_firewall_commands(&config);
        assert!(cmds.is_empty());
    }

    #[test]
    fn ingress_redirect_plan() {
        let config = cfg(serde_json::json!({
            "rules": [{
                "name": "web-redirect",
                "direction": "decrypt",
                "listen_addr": "0.0.0.0:8443",
                "upstream_addr": "127.0.0.1:80",
                "intercept": {
                    "mode": "ingress_redirect",
                    "in_interface": "eth0",
                    "match_dports": "8080"
                }
            }]
        }));
        let cmds = plan_firewall_commands(&config);
        // Should have: create chain, jump from PREROUTING, then the REDIRECT rule.
        assert!(cmds.len() >= 3, "expected >=3 commands, got {}: {:?}", cmds.len(), cmds);

        // The REDIRECT rule should target port 8443.
        let redirect = cmds.iter().find(|c| c.args.contains(&"REDIRECT".to_string()));
        assert!(redirect.is_some(), "no REDIRECT command found");
        let r = redirect.unwrap();
        assert!(r.args.contains(&"8443".to_string()));
        assert!(r.args.contains(&"eth0".to_string()));
        assert!(r.args.contains(&"8080".to_string()));
    }

    #[test]
    fn egress_redirect_plan_with_multiple_dst() {
        let config = cfg(serde_json::json!({
            "rules": [{
                "name": "enc-tcp",
                "direction": "encrypt",
                "listen_addr": "0.0.0.0:3128",
                "upstream_addr": "10.0.0.1:443",
                "intercept": {
                    "mode": "egress_redirect",
                    "match_dports": "4465:4467",
                    "match_dst": ["192.168.1.2", "192.168.1.3"]
                }
            }]
        }));
        let cmds = plan_firewall_commands(&config);
        // Should have create chain + jump OUTPUT + owner RETURN + 2 REDIRECT rules.
        let redirects: Vec<_> = cmds.iter().filter(|c| c.args.contains(&"REDIRECT".to_string())).collect();
        assert_eq!(redirects.len(), 2, "expected 2 REDIRECT rules for 2 dst IPs");
        // Both should use multiport.
        for r in &redirects {
            assert!(r.args.contains(&"multiport".to_string()));
            assert!(r.args.contains(&"4465:4467".to_string()));
            assert!(r.args.contains(&"3128".to_string()));
        }
        // One should target 192.168.1.2, the other 192.168.1.3.
        assert!(redirects[0].args.contains(&"192.168.1.2".to_string()));
        assert!(redirects[1].args.contains(&"192.168.1.3".to_string()));
    }

    #[test]
    fn tproxy_plan() {
        let config = cfg(serde_json::json!({
            "rules": [{
                "name": "dec-tproxy",
                "direction": "decrypt",
                "listen_addr": "0.0.0.0:4000",
                "upstream_addr": "auto",
                "transparent": true,
                "intercept": {
                    "mode": "tproxy",
                    "match_dports": "4465:4467",
                    "match_src": ["192.168.1.1", "192.168.1.2"]
                }
            }]
        }));
        let cmds = plan_firewall_commands(&config);
        // Should have ip rule, ip route, create chain, jump, socket RETURN,
        // port RETURN, and 2 TPROXY rules.
        let ip_cmds: Vec<_> = cmds.iter().filter(|c| c.program == "ip").collect();
        assert_eq!(ip_cmds.len(), 2, "expected ip rule + ip route");

        let tproxy_rules: Vec<_> = cmds.iter().filter(|c| c.args.contains(&"TPROXY".to_string())).collect();
        assert_eq!(tproxy_rules.len(), 2, "expected 2 TPROXY rules for 2 src IPs");
        for r in &tproxy_rules {
            assert!(r.args.contains(&"4000".to_string()));
            assert!(r.args.contains(&"1/1".to_string()));
        }
    }
}
