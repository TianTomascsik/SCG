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
use log::{debug, info, warn};
use std::net::SocketAddr;
use std::process::Command;

// ─── Chain names (shared with preflight_check) ───────────────────────────────

const CHAIN_ENCRYPT: &str = "SCG_ENCRYPT";
const CHAIN_DECRYPT: &str = "SCG_DECRYPT";
// Deliberately compile-time constants, not config knobs (CP-10): the fwmark/table
// are also referenced by `preflight_check` (`lookup 100`), so a knob would have to
// thread through both. Teardown now tracks created-vs-found ownership instead, so a
// co-resident proxy sharing these values is not disrupted.
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
    /// Whether *we* added the TPROXY `ip rule fwmark` (vs. it pre-existing, e.g. a
    /// co-resident transparent proxy). Teardown removes it only if we created it
    /// so we don't disrupt another owner (CP-10).
    owns_routing_rule: bool,
    /// Whether *we* added the TPROXY `ip route` in the lookup table (CP-10).
    owns_routing_route: bool,
}

impl FirewallManager {
    /// Build and apply firewall rules from the gateway configuration.
    ///
    /// Returns a `FirewallManager` that tracks what was created (for teardown),
    /// or an error string if setup fails.
    pub fn setup(config: &GatewayConfig) -> Result<Self, String> {
        // Pair each intercept rule with its `InterceptConfig` once (L34), so no
        // downstream code re-derives it with a `.unwrap()` that relies on this
        // filter's invariant holding at a distance.
        let rules_with_intercept: Vec<(&RuleConfig, &InterceptConfig)> = config
            .rules
            .iter()
            .filter_map(|r| r.intercept.as_ref().map(|ic| (r, ic)))
            .collect();

        if rules_with_intercept.is_empty() {
            return Ok(Self {
                owns_encrypt_chain: false,
                owns_encrypt_chain_v6: false,
                owns_decrypt_chain: false,
                owns_routing_rule: false,
                owns_routing_route: false,
            });
        }

        // Classify which chains/features we need.
        let needs_encrypt_chain = rules_with_intercept.iter().any(|(_, ic)| {
            matches!(
                ic.mode,
                InterceptMode::IngressRedirect | InterceptMode::EgressRedirect
            )
        });
        let needs_decrypt_chain = rules_with_intercept
            .iter()
            .any(|(_, ic)| ic.mode == InterceptMode::Tproxy);

        let mut mgr = Self {
            owns_encrypt_chain: false,
            owns_encrypt_chain_v6: false,
            owns_decrypt_chain: false,
            owns_routing_rule: false,
            owns_routing_route: false,
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
        // Remove only the routing elements we created, so a co-resident
        // transparent proxy sharing the fwmark rule/route is not disrupted (CP-10).
        if self.owns_routing_rule {
            Self::remove_routing_rule();
        }
        if self.owns_routing_route {
            Self::remove_routing_route();
        }
        info!("Firewall rules torn down");
    }

    // ── Encrypt chain setup ─────────────────────────────────────────────────

    fn ensure_encrypt_chain(
        &mut self,
        rules: &[(&RuleConfig, &InterceptConfig)],
    ) -> Result<(), String> {
        // Create or flush the chain.
        Self::create_or_flush_chain("iptables", "nat", CHAIN_ENCRYPT)?;
        self.owns_encrypt_chain = true;

        // Ensure the jump from the parent chain exists.
        // ingress_redirect → PREROUTING; egress_redirect → OUTPUT.
        let has_ingress = rules
            .iter()
            .any(|(_, ic)| ic.mode == InterceptMode::IngressRedirect);
        let has_egress = rules
            .iter()
            .any(|(_, ic)| ic.mode == InterceptMode::EgressRedirect);
        // The IPv6 mirror only exists so an egress `127.0.0.1` REDIRECT also
        // catches `::1` (M18): compute whether any egress rule actually needs
        // it, so we don't touch ip6tables at all when none does.
        let needs_v6_mirror = rules.iter().any(|(_, ic)| {
            ic.mode == InterceptMode::EgressRedirect
                && ic.match_dst.iter().any(|d| d == "127.0.0.1")
        });

        if has_ingress {
            Self::ensure_jump("iptables", "nat", "PREROUTING", CHAIN_ENCRYPT)?;
        }
        if has_egress {
            Self::ensure_jump("iptables", "nat", "OUTPUT", CHAIN_ENCRYPT)?;
            // Loop avoidance: gateway's own uid returns immediately.
            // SAFETY: `geteuid` is a parameterless POSIX syscall that always succeeds,
            // returns the caller's effective UID by value, takes no pointers, and never
            // sets errno; it has no preconditions and cannot cause undefined behaviour.
            let uid = unsafe { libc::geteuid() };
            run_iptables(&[
                "-t",
                "nat",
                "-A",
                CHAIN_ENCRYPT,
                "-m",
                "owner",
                "--uid-owner",
                &uid.to_string(),
                "-j",
                "RETURN",
            ])?;

            // IPv6 mirror (browsers use ::1 for localhost): best-effort, and
            // only when an egress rule actually redirects 127.0.0.1 (M18).
            // On hosts booted with ipv6.disable=1 or lacking the ip6tables nat
            // table, a failure here logs a warning and leaves the v4 setup
            // intact instead of aborting gateway startup.
            if needs_v6_mirror {
                if let Err(e) = Self::setup_v6_egress_return(uid) {
                    warn!("IPv6 loopback interception unavailable: {e}");
                } else {
                    self.owns_encrypt_chain_v6 = true;
                }
            }
        }

        // Add per-rule REDIRECT entries. TPROXY rules are handled by
        // `ensure_decrypt_chain`; skip them here so the `match` below is
        // exhaustive over `InterceptMode` without a panicking fallback arm (CP-13).
        for (rule, ic) in rules {
            if ic.mode == InterceptMode::Tproxy {
                continue;
            }
            let listen_port = Self::listen_port(rule)?;
            let proto = Self::intercept_proto(rule, ic);

            match ic.mode {
                InterceptMode::IngressRedirect => {
                    let mut args = vec!["-t", "nat", "-A", CHAIN_ENCRYPT, "-p", &proto];
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
                        let mut args =
                            vec!["-t", "nat", "-A", CHAIN_ENCRYPT, "-d", dst, "-p", &proto];
                        if dports.contains(',') || dports.contains(':') {
                            args.extend_from_slice(&["-m", "multiport", "--dports", &dports]);
                        } else {
                            args.extend_from_slice(&["--dport", &dports]);
                        }
                        args.extend_from_slice(&["-j", "REDIRECT", "--to-port", &port_str]);
                        run_iptables(&args)?;

                        // IPv6 mirror: 127.0.0.1 → also cover ::1 via ip6tables,
                        // but only if the v6 chain was actually set up, and
                        // best-effort (M18): a v6-disabled host must not fail.
                        if dst == "127.0.0.1" && self.owns_encrypt_chain_v6 {
                            let mut args6 =
                                vec!["-t", "nat", "-A", CHAIN_ENCRYPT, "-d", "::1", "-p", &proto];
                            if dports.contains(',') || dports.contains(':') {
                                args6.extend_from_slice(&["-m", "multiport", "--dports", &dports]);
                            } else {
                                args6.extend_from_slice(&["--dport", &dports]);
                            }
                            args6.extend_from_slice(&["-j", "REDIRECT", "--to-port", &port_str]);
                            if let Err(e) = run_cmd("ip6tables", &args6) {
                                warn!("[{}] IPv6 ::1 mirror rule failed: {e}", rule.name);
                            }
                        }
                    }
                    debug!(
                        "  [{}] egress_redirect {} dst(s) → :{}",
                        rule.name,
                        ic.match_dst.len(),
                        listen_port
                    );
                }
                // Skipped above; kept so the match is exhaustive without a panic.
                InterceptMode::Tproxy => continue,
            }
        }

        Ok(())
    }

    /// Best-effort setup of the ip6tables egress chain + owner-return rule that
    /// mirrors the v4 egress interception onto `::1` (M18). Returns `Err` if any
    /// ip6tables step fails (IPv6 disabled / no nat table); the caller downgrades
    /// that to a warning and continues with v4 only.
    fn setup_v6_egress_return(uid: libc::uid_t) -> Result<(), String> {
        Self::create_or_flush_chain("ip6tables", "nat", CHAIN_ENCRYPT)?;
        Self::ensure_jump("ip6tables", "nat", "OUTPUT", CHAIN_ENCRYPT)?;
        run_cmd(
            "ip6tables",
            &[
                "-t",
                "nat",
                "-A",
                CHAIN_ENCRYPT,
                "-m",
                "owner",
                "--uid-owner",
                &uid.to_string(),
                "-j",
                "RETURN",
            ],
        )
    }

    // ── Decrypt chain setup (TPROXY) ────────────────────────────────────────

    fn ensure_decrypt_chain(
        &mut self,
        rules: &[(&RuleConfig, &InterceptConfig)],
    ) -> Result<(), String> {
        // Routing policy (ip rule + ip route). Track which elements *we* created
        // (vs. found pre-existing) so teardown removes only ours (CP-10).
        let (rule_added, route_added) = Self::ensure_routing_policy()?;
        self.owns_routing_rule = rule_added;
        self.owns_routing_route = route_added;

        // Create or flush the mangle chain.
        Self::create_or_flush_chain("iptables", "mangle", CHAIN_DECRYPT)?;
        self.owns_decrypt_chain = true;

        // Jump from PREROUTING.
        Self::ensure_jump("iptables", "mangle", "PREROUTING", CHAIN_DECRYPT)?;

        // Guard: let already-transparent connections bypass.
        run_iptables(&[
            "-t",
            "mangle",
            "-A",
            CHAIN_DECRYPT,
            "-m",
            "socket",
            "--transparent",
            "-j",
            "RETURN",
        ])?;

        // Exclude gateway's own listening ports from TPROXY (RETURN rules).
        for (rule, ic) in rules {
            if ic.mode != InterceptMode::Tproxy {
                continue;
            }
            let listen_port = Self::listen_port(rule)?;
            let proto = Self::intercept_proto(rule, ic);
            let port_str = listen_port.to_string();
            run_iptables(&[
                "-t",
                "mangle",
                "-A",
                CHAIN_DECRYPT,
                "-p",
                &proto,
                "--dport",
                &port_str,
                "-j",
                "RETURN",
            ])?;
        }

        // Per-rule TPROXY entries.
        for (rule, ic) in rules {
            if ic.mode != InterceptMode::Tproxy {
                continue;
            }
            let listen_port = Self::listen_port(rule)?;
            let proto = Self::intercept_proto(rule, ic);
            let dports = ic.match_dports.clone();
            let port_str = listen_port.to_string();
            let mark_spec = format!("{TPROXY_MARK}/{TPROXY_MARK}");

            for src in &ic.match_src {
                let mut args = vec!["-t", "mangle", "-A", CHAIN_DECRYPT, "-s", src, "-p", &proto];
                if dports.contains(',') || dports.contains(':') {
                    args.extend_from_slice(&["-m", "multiport", "--dports", &dports]);
                } else {
                    args.extend_from_slice(&["--dport", &dports]);
                }
                args.extend_from_slice(&[
                    "-j",
                    "TPROXY",
                    "--on-port",
                    &port_str,
                    "--tproxy-mark",
                    &mark_spec,
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

    /// Add the TPROXY `ip rule`/`ip route` only where absent, returning
    /// `(rule_added, route_added)` so teardown removes only what we created (CP-10).
    fn ensure_routing_policy() -> Result<(bool, bool), String> {
        let existing = Command::new("ip")
            .args(["rule", "show"])
            .output()
            .map_err(|e| format!("Failed to run 'ip rule show': {}", e))?;
        let existing_routes = Command::new("ip")
            .args(["route", "show", "table", TPROXY_TABLE])
            .output()
            .map_err(|e| format!("Failed to run 'ip route show': {}", e))?;

        let (need_rule, need_route) = Self::routing_policy_needed(
            &String::from_utf8_lossy(&existing.stdout),
            &String::from_utf8_lossy(&existing_routes.stdout),
        );

        if need_rule {
            run_cmd(
                "ip",
                &["rule", "add", "fwmark", TPROXY_MARK, "lookup", TPROXY_TABLE],
            )?;
        }
        if need_route {
            if let Err(e) = run_cmd(
                "ip",
                &[
                    "route",
                    "add",
                    "local",
                    "default",
                    "dev",
                    "lo",
                    "table",
                    TPROXY_TABLE,
                ],
            ) {
                // Roll back the rule we just added before returning (M19): the
                // caller sets `owns_routing_rule` from our return value, so on
                // this early Err it would otherwise never learn to remove the
                // freshly-added fwmark rule — a leak past the aborted startup.
                if need_rule {
                    Self::remove_routing_rule();
                }
                return Err(e);
            }
        }
        Ok((need_rule, need_route))
    }

    /// Decide, from `ip rule show` / `ip route show table <T>` output, which TPROXY
    /// routing elements need creating. Pure so it is unit-testable without
    /// `CAP_NET_ADMIN`. `(rule_needed, route_needed)`.
    fn routing_policy_needed(rule_show: &str, route_show: &str) -> (bool, bool) {
        // The required rule must appear on a SINGLE line as both the mark and
        // the table lookup (M20): two unrelated pre-existing rules (e.g.
        // `fwmark 0x2 lookup 200` plus any `lookup 100`) must not be mistaken
        // for our `fwmark 1 lookup 100`, or we would skip installing it and
        // TPROXY-marked packets would never reach the local table. `ip rule
        // show` renders the mark in hex, so accept both `1` and `0x1`.
        let mark_dec = TPROXY_MARK;
        let mark_hex = format!("0x{:x}", TPROXY_MARK.parse::<u32>().unwrap_or(1));
        let have_rule = rule_show.lines().any(|line| {
            let toks: Vec<&str> = line.split_whitespace().collect();
            let mark_ok = toks
                .windows(2)
                .any(|w| w[0] == "fwmark" && (w[1] == mark_dec || w[1] == mark_hex.as_str()));
            let table_ok = toks
                .windows(2)
                .any(|w| w[0] == "lookup" && w[1] == TPROXY_TABLE);
            mark_ok && table_ok
        });
        let rule_needed = !have_rule;
        let route_needed = !route_show.contains("local default");
        (rule_needed, route_needed)
    }

    fn remove_routing_rule() {
        let _ = Command::new("ip")
            .args(["rule", "del", "fwmark", TPROXY_MARK, "lookup", TPROXY_TABLE])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    fn remove_routing_route() {
        let _ = Command::new("ip")
            .args([
                "route",
                "del",
                "local",
                "default",
                "dev",
                "lo",
                "table",
                TPROXY_TABLE,
            ])
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
            run_cmd(binary, &["-t", table, "-F", chain])?;
        } else {
            // Create new chain.
            run_cmd(binary, &["-t", table, "-N", chain])?;
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
            _ => run_cmd(binary, &["-t", table, "-A", parent, "-j", chain]),
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

fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    debug!("exec: {} {}", cmd, args.join(" "));
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute '{}': {}", cmd, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let cmdline = format!("{} {}", cmd, args.join(" "));
        return Err(format!(
            "'{}' failed (exit {}): {}",
            cmdline,
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
    let rules_with_intercept: Vec<(&RuleConfig, &InterceptConfig)> = config
        .rules
        .iter()
        .filter_map(|r| r.intercept.as_ref().map(|ic| (r, ic)))
        .collect();

    if rules_with_intercept.is_empty() {
        return cmds;
    }

    let needs_encrypt = rules_with_intercept.iter().any(|(_, ic)| {
        matches!(
            ic.mode,
            InterceptMode::IngressRedirect | InterceptMode::EgressRedirect
        )
    });
    let needs_decrypt = rules_with_intercept
        .iter()
        .any(|(_, ic)| ic.mode == InterceptMode::Tproxy);

    let has_ingress = rules_with_intercept
        .iter()
        .any(|(_, ic)| ic.mode == InterceptMode::IngressRedirect);
    let has_egress = rules_with_intercept
        .iter()
        .any(|(_, ic)| ic.mode == InterceptMode::EgressRedirect);

    if needs_encrypt {
        // Create/flush chain.
        cmds.push(ipt(&["-t", "nat", "-N", CHAIN_ENCRYPT]));
        // Jumps.
        if has_ingress {
            cmds.push(ipt(&["-t", "nat", "-A", "PREROUTING", "-j", CHAIN_ENCRYPT]));
        }
        if has_egress {
            cmds.push(ipt(&["-t", "nat", "-A", "OUTPUT", "-j", CHAIN_ENCRYPT]));
            // SAFETY: `geteuid` is a parameterless POSIX syscall that always succeeds,
            // returns the caller's effective UID by value, takes no pointers, and never
            // sets errno; it has no preconditions and cannot cause undefined behaviour.
            let uid = unsafe { libc::geteuid() };
            cmds.push(ipt(&[
                "-t",
                "nat",
                "-A",
                CHAIN_ENCRYPT,
                "-m",
                "owner",
                "--uid-owner",
                &uid.to_string(),
                "-j",
                "RETURN",
            ]));
            // IPv6 equivalent for egress (browsers use ::1 for localhost).
            cmds.push(ip6t(&["-t", "nat", "-N", CHAIN_ENCRYPT]));
            cmds.push(ip6t(&["-t", "nat", "-A", "OUTPUT", "-j", CHAIN_ENCRYPT]));
            cmds.push(ip6t(&[
                "-t",
                "nat",
                "-A",
                CHAIN_ENCRYPT,
                "-m",
                "owner",
                "--uid-owner",
                &uid.to_string(),
                "-j",
                "RETURN",
            ]));
        }

        // Per-rule entries.
        for (rule, ic) in &rules_with_intercept {
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
                        "-t".to_string(),
                        "nat".to_string(),
                        "-A".to_string(),
                        CHAIN_ENCRYPT.to_string(),
                        "-p".to_string(),
                        proto.clone(),
                    ];
                    if let Some(ref iface) = ic.in_interface {
                        args.push("-i".to_string());
                        args.push(iface.clone());
                    }
                    if ic.match_dports.contains(',') || ic.match_dports.contains(':') {
                        args.extend([
                            "-m".to_string(),
                            "multiport".to_string(),
                            "--dports".to_string(),
                            ic.match_dports.clone(),
                        ]);
                    } else {
                        args.extend(["--dport".to_string(), ic.match_dports.clone()]);
                    }
                    args.extend([
                        "-j".to_string(),
                        "REDIRECT".to_string(),
                        "--to-port".to_string(),
                        listen_port.clone(),
                    ]);
                    cmds.push(IptablesCmd {
                        program: "iptables".to_string(),
                        args,
                    });
                }
                InterceptMode::EgressRedirect => {
                    for dst in &ic.match_dst {
                        let mut args = vec![
                            "-t".to_string(),
                            "nat".to_string(),
                            "-A".to_string(),
                            CHAIN_ENCRYPT.to_string(),
                            "-d".to_string(),
                            dst.clone(),
                            "-p".to_string(),
                            proto.clone(),
                        ];
                        if ic.match_dports.contains(',') || ic.match_dports.contains(':') {
                            args.extend([
                                "-m".to_string(),
                                "multiport".to_string(),
                                "--dports".to_string(),
                                ic.match_dports.clone(),
                            ]);
                        } else {
                            args.extend(["--dport".to_string(), ic.match_dports.clone()]);
                        }
                        args.extend([
                            "-j".to_string(),
                            "REDIRECT".to_string(),
                            "--to-port".to_string(),
                            listen_port.clone(),
                        ]);
                        cmds.push(IptablesCmd {
                            program: "iptables".to_string(),
                            args,
                        });

                        // IPv6 mirror: 127.0.0.1 → also cover ::1.
                        if dst == "127.0.0.1" {
                            let mut args6 = vec![
                                "-t".to_string(),
                                "nat".to_string(),
                                "-A".to_string(),
                                CHAIN_ENCRYPT.to_string(),
                                "-d".to_string(),
                                "::1".to_string(),
                                "-p".to_string(),
                                proto.clone(),
                            ];
                            if ic.match_dports.contains(',') || ic.match_dports.contains(':') {
                                args6.extend([
                                    "-m".to_string(),
                                    "multiport".to_string(),
                                    "--dports".to_string(),
                                    ic.match_dports.clone(),
                                ]);
                            } else {
                                args6.extend(["--dport".to_string(), ic.match_dports.clone()]);
                            }
                            args6.extend([
                                "-j".to_string(),
                                "REDIRECT".to_string(),
                                "--to-port".to_string(),
                                listen_port.clone(),
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
                "rule".to_string(),
                "add".to_string(),
                "fwmark".to_string(),
                TPROXY_MARK.to_string(),
                "lookup".to_string(),
                TPROXY_TABLE.to_string(),
            ],
        });
        cmds.push(IptablesCmd {
            program: "ip".to_string(),
            args: vec![
                "route".to_string(),
                "add".to_string(),
                "local".to_string(),
                "default".to_string(),
                "dev".to_string(),
                "lo".to_string(),
                "table".to_string(),
                TPROXY_TABLE.to_string(),
            ],
        });

        // Create/flush chain.
        cmds.push(ipt(&["-t", "mangle", "-N", CHAIN_DECRYPT]));
        cmds.push(ipt(&[
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-j",
            CHAIN_DECRYPT,
        ]));

        // Transparent socket guard.
        cmds.push(ipt(&[
            "-t",
            "mangle",
            "-A",
            CHAIN_DECRYPT,
            "-m",
            "socket",
            "--transparent",
            "-j",
            "RETURN",
        ]));

        // RETURN for own listening ports.
        for (rule, ic) in &rules_with_intercept {
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
                "-t",
                "mangle",
                "-A",
                CHAIN_DECRYPT,
                "-p",
                &proto,
                "--dport",
                &listen_port,
                "-j",
                "RETURN",
            ]));
        }

        // Per-rule TPROXY entries.
        for (rule, ic) in &rules_with_intercept {
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
                    "-t".to_string(),
                    "mangle".to_string(),
                    "-A".to_string(),
                    CHAIN_DECRYPT.to_string(),
                    "-s".to_string(),
                    src.clone(),
                    "-p".to_string(),
                    proto.clone(),
                ];
                if ic.match_dports.contains(',') || ic.match_dports.contains(':') {
                    args.extend([
                        "-m".to_string(),
                        "multiport".to_string(),
                        "--dports".to_string(),
                        ic.match_dports.clone(),
                    ]);
                } else {
                    args.extend(["--dport".to_string(), ic.match_dports.clone()]);
                }
                args.extend([
                    "-j".to_string(),
                    "TPROXY".to_string(),
                    "--on-port".to_string(),
                    listen_port.clone(),
                    "--tproxy-mark".to_string(),
                    mark_spec.clone(),
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

    // CP-10: created-vs-found decision is pure and testable without CAP_NET_ADMIN.
    #[test]
    fn routing_policy_needed_detects_existing() {
        // Both present → nothing to create.
        let rule_show = "32765:\tfrom all fwmark 0x1 lookup 100\n";
        let route_show = "local default dev lo scope host\n";
        assert_eq!(
            FirewallManager::routing_policy_needed(rule_show, route_show),
            (false, false)
        );
    }

    #[test]
    fn routing_policy_needed_when_absent() {
        // Neither present → create both.
        assert_eq!(FirewallManager::routing_policy_needed("", ""), (true, true));
        // Rule present, route absent → create only the route.
        assert_eq!(
            FirewallManager::routing_policy_needed("from all fwmark 0x1 lookup 100", ""),
            (false, true)
        );
    }

    // M20: the mark and table must be on the SAME line. Two unrelated
    // pre-existing rules (another proxy's fwmark 0x2 lookup 200, plus some
    // other lookup 100) must NOT be mistaken for our fwmark 1 lookup 100, or we
    // would skip installing the rule TPROXY needs.
    #[test]
    fn routing_policy_needed_ignores_cross_line_substrings() {
        let rule_show =
            "0:\tfrom all lookup local\n32000:\tfrom all fwmark 0x2 lookup 200\n32001:\tfrom all lookup 100\n";
        // fwmark 0x2 and lookup 100 exist, but never together → rule needed.
        assert!(FirewallManager::routing_policy_needed(rule_show, "local default dev lo").0);
    }

    #[test]
    fn routing_policy_needed_accepts_decimal_and_hex_mark() {
        for line in [
            "32765:\tfrom all fwmark 0x1 lookup 100\n",
            "32765:\tfrom all fwmark 1 lookup 100\n",
        ] {
            assert!(
                !FirewallManager::routing_policy_needed(line, "local default dev lo").0,
                "line should satisfy the rule: {line:?}"
            );
        }
    }

    // CP-13: a mixed tproxy + egress config plans commands for both modes without
    // crossing chains (proves the exhaustive match handles every InterceptMode).
    #[test]
    fn mixed_modes_do_not_cross_chains() {
        let config = cfg(serde_json::json!({
            "rules": [
                {
                    "name": "tp",
                    "direction": "decrypt",
                    "listen_addr": "0.0.0.0:9443",
                    "upstream_addr": "auto",
                    "transparent": true,
                    "intercept": { "mode": "tproxy", "match_dports": "443", "match_src": ["10.0.0.0/8"] }
                },
                {
                    "name": "eg",
                    "direction": "encrypt",
                    "listen_addr": "127.0.0.1:8443",
                    "upstream_addr": "127.0.0.1:80",
                    "intercept": { "mode": "egress_redirect", "match_dst": ["10.0.0.1"], "match_dports": "80" }
                }
            ]
        }));
        let cmds = plan_firewall_commands(&config);
        let has = |needle: &str| cmds.iter().any(|c| c.args.contains(&needle.to_string()));
        // Both modes plan their own target.
        assert!(has("TPROXY"), "tproxy rule missing");
        assert!(has("REDIRECT"), "egress redirect rule missing");
        // No cross-chain leakage: TPROXY only in mangle, REDIRECT only in nat.
        for c in &cmds {
            if c.args.contains(&"mangle".to_string()) {
                assert!(
                    !c.args.contains(&"REDIRECT".to_string()),
                    "REDIRECT leaked into mangle: {c:?}"
                );
            }
            if c.args.contains(&"nat".to_string()) {
                assert!(
                    !c.args.contains(&"TPROXY".to_string()),
                    "TPROXY leaked into nat: {c:?}"
                );
            }
        }
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
        assert!(
            cmds.len() >= 3,
            "expected >=3 commands, got {}: {:?}",
            cmds.len(),
            cmds
        );

        // The REDIRECT rule should target port 8443.
        let redirect = cmds
            .iter()
            .find(|c| c.args.contains(&"REDIRECT".to_string()));
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
        let redirects: Vec<_> = cmds
            .iter()
            .filter(|c| c.args.contains(&"REDIRECT".to_string()))
            .collect();
        assert_eq!(
            redirects.len(),
            2,
            "expected 2 REDIRECT rules for 2 dst IPs"
        );
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

        let tproxy_rules: Vec<_> = cmds
            .iter()
            .filter(|c| c.args.contains(&"TPROXY".to_string()))
            .collect();
        assert_eq!(
            tproxy_rules.len(),
            2,
            "expected 2 TPROXY rules for 2 src IPs"
        );
        for r in &tproxy_rules {
            assert!(r.args.contains(&"4000".to_string()));
            assert!(r.args.contains(&"1/1".to_string()));
        }
    }
}
