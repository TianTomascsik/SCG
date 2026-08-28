//! Processing Core subsystem.
//!
//! Orchestrates proxy rule startup, dispatches to appropriate security engines
//! via the provider registry, and manages per-rule lifecycle.

pub mod cache;
pub mod lifecycle;
pub mod policy;
pub mod registry;
pub mod traffic_analyzer;

use crate::management::config::{
    Direction, GatewayConfig, Proto, QosPolicy, RuleConfig, TlsMode, TrafficClass,
};
use crate::management::telemetry::RuleMetrics;
use crate::security::conn_pool::ConnectionPool;
use log::{debug, error, info, warn};
use registry::ProviderRegistry;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use policy::PolicyManager;
use traffic_analyzer::TrafficAnalyzer;

// ─── Rule context ────────────────────────────────────────────────────────────

/// Shared context for a proxy rule, replacing 10+ individual function parameters.
pub struct RuleContext {
    pub rule_name: String,
    pub listen_addr: String,
    pub listen_proto: Proto,
    pub upstream_addr: String,
    pub upstream_proto: Proto,
    pub tls_mode: TlsMode,
    pub security_provider: String,
    pub transparent: bool,
    pub sock_buf_size: usize,
    pub metrics: Arc<RuleMetrics>,
    pub shutdown: Arc<AtomicBool>,
    /// Provider-specific parameters (from the rule's generic `provider_params`).
    /// Custom/external crypto providers read their own settings from here.
    pub provider_params: std::collections::HashMap<String, serde_json::Value>,
    // Traffic policy fields (optional — None means policy pipeline is not active)
    pub traffic_class: TrafficClass,
    /// Resolved QoS policy (egress DSCP tag / preservation + SO_PRIORITY) for
    /// this rule's sockets. Applied at every socket creation point.
    pub qos: QosPolicy,
    pub traffic_analyzer: Option<Arc<TrafficAnalyzer>>,
    pub policy_manager: Option<Arc<RwLock<PolicyManager>>>,
    pub simulated_delay_ms: u64,
    pub protocol_version: Option<String>,
    /// Application-level framing for UDP-over-TLS paths: `"ale"` (Subset-098
    /// AU1/AU2 handshake + ALEPKT framing, the default) or `"raw"` (4-byte LE
    /// length-prefix, no handshake).
    pub app_protocol: String,
    /// Resolved performance knobs (cork / busy-poll) for this rule's data path.
    pub perf: crate::management::config::PerfKnobs,
    /// Shared connection thread pool (TCP encrypt/decrypt handlers).
    pub conn_pool: Arc<ConnectionPool>,
}

impl RuleContext {
    /// Run traffic classification + policy check for a connection/datagram.
    /// Returns `true` if the traffic is allowed, `false` if it should be dropped.
    pub fn classify_and_check_policy(
        &self,
        src: &std::net::SocketAddr,
        dst: &std::net::SocketAddr,
    ) -> bool {
        // Classify the traffic (if analyzer is configured)
        let traffic_class = if let Some(ref analyzer) = self.traffic_analyzer {
            match analyzer.classify(src, dst) {
                Some(result) => {
                    debug!(
                        "[{}] Classified {} -> {} as {} (app_id={}, traffic_id={})",
                        self.rule_name,
                        src,
                        dst,
                        result.traffic_class,
                        result.app_id,
                        result.traffic_id.0
                    );
                    result.traffic_class
                }
                None => self.traffic_class, // Fall back to rule-level class
            }
        } else {
            self.traffic_class
        };

        // Policy check (if policy manager is configured)
        if let Some(ref pm) = self.policy_manager {
            let pm_guard = pm.read().unwrap();
            if !pm_guard.check_allowed(src, dst, traffic_class) {
                warn!("[{}] Policy DENIED: {} -> {}", self.rule_name, src, dst);
                return false;
            }
        }

        true
    }

    /// Resolve an upstream `target` (`host:port` or `ip:port`) to a single
    /// [`SocketAddr`](std::net::SocketAddr) for the policy gate and
    /// session/connection setup.
    ///
    /// DNS resolution happens **once per session / relay start** — callers must
    /// never call this per datagram (DNS-per-packet would be a self-inflicted
    /// DoS). A hostname that cannot be resolved returns `None` so the caller can
    /// fail closed. This restores functionality for legitimate DNS-name
    /// upstreams that the strict `IP:port`-only policy gate  would
    /// otherwise drop entirely (TRA #73).
    pub fn resolve_upstream_target(&self, target: &str) -> Option<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        match target.to_socket_addrs() {
            Ok(mut addrs) => addrs.next(),
            Err(e) => {
                warn!(
                    "[{}] cannot resolve upstream target '{target}': {e}",
                    self.rule_name
                );
                None
            }
        }
    }

    /// Classify + policy-gate a flow whose destination is still a `target` string
    /// (e.g. the configured `upstream_addr`). Fails **closed** when the target is
    /// not a parseable `IP:port`: the flow is dropped and an `AUDIT deny`
    /// line is emitted, rather than silently skipping the default-deny/source
    /// whitelist gate. Callers must treat `false` as "drop this connection".
    ///
    /// This accepts only literal `IP:port`; a hostname upstream must first be
    /// resolved once via [`resolve_upstream_target`](Self::resolve_upstream_target)
    /// and gated through [`classify_and_check_policy`](Self::classify_and_check_policy)
    /// on the resolved address (TRA #73).
    pub fn classify_and_check_policy_target(
        &self,
        src: &std::net::SocketAddr,
        target: &str,
    ) -> bool {
        match target.parse::<std::net::SocketAddr>() {
            Ok(dst) => self.classify_and_check_policy(src, &dst),
            Err(_) => {
                warn!(
                    "[{}] AUDIT deny op=policy_gate src={src}: upstream target '{target}' \
                     is not an IP:port; failing closed",
                    self.rule_name
                );
                false
            }
        }
    }

    /// Apply this rule's egress QoS (DSCP tag/preservation + SO_PRIORITY) to a
    /// socket. `is_v6` selects the IPv4/IPv6 option family; `sampled_inbound`
    /// is the DSCP read from the ingress side for preservation (pass `None`
    /// when no inbound sample is available — Safety still gets its EF default).
    pub fn apply_egress_qos(
        &self,
        fd: std::os::unix::io::RawFd,
        is_v6: bool,
        sampled_inbound: Option<u8>,
    ) {
        crate::networking::socket_manager::apply_egress_qos(
            fd,
            self.qos.egress_dscp(sampled_inbound),
            self.qos.so_priority(),
            is_v6,
        );
    }

    /// Enable inbound DSCP sampling (RECVTOS) on an ingress socket when this
    /// rule requests DSCP preservation. No-op otherwise.
    pub fn enable_inbound_dscp_sampling(&self, fd: std::os::unix::io::RawFd, is_v6: bool) {
        if self.qos.needs_inbound_dscp() {
            crate::networking::socket_manager::enable_recvtos(fd, is_v6);
        }
    }
}

/// Pipeline components shared across rules.
pub struct PipelineComponents {
    pub traffic_analyzer: Option<Arc<TrafficAnalyzer>>,
    pub policy_manager: Arc<RwLock<PolicyManager>>,
}

/// Per-rule shutdown flags, keyed by rule name, shared for hot-reload.
pub type RuleShutdownMap = Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>;

/// Start all proxy rules. Returns join handles for the listener threads
/// and a map of rule names -> shutdown flags for per-rule hot-reload.
pub fn start_rules(
    config: &GatewayConfig,
    shutdown: Arc<AtomicBool>,
    registry: Arc<ProviderRegistry>,
    pipeline: Arc<PipelineComponents>,
) -> (Vec<thread::JoinHandle<()>>, RuleShutdownMap) {
    let mut handles = Vec::new();
    let rule_shutdowns: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Preflight: safety-class rules want elevated scheduling priority, which
    // needs CAP_SYS_NICE. Warn once if it is missing so the operator knows
    // safety threads will fall back to default nice (DSCP/SO_PRIORITY marking
    // is unaffected and still works).
    if config
        .rules
        .iter()
        .any(|r| r.traffic_class == TrafficClass::Safety)
        && !crate::networking::socket_manager::has_cap_sys_nice()
    {
        warn!(
            "Safety-class rules are configured but the process lacks CAP_SYS_NICE; \
             safety threads cannot raise their scheduling priority and will run at \
             the default nice value (DSCP / SO_PRIORITY marking is unaffected)."
        );
    }

    for rule in &config.rules {
        // uds/shm rules are templates consumed by the InterfaceManager and
        // started on demand via the management API — not as static listeners.
        if matches!(rule.listen_proto, Proto::Uds | Proto::Shm) {
            debug!(
                "[{}] uds/shm rule registered as a local-interface template (started on demand)",
                rule.name
            );
            continue;
        }
        let handle = start_single_rule(
            rule,
            config,
            shutdown.clone(),
            rule_shutdowns.clone(),
            registry.clone(),
            pipeline.clone(),
        );
        handles.push(handle);
    }

    (handles, rule_shutdowns)
}

/// Start a single proxy rule (used by initial startup and hot-reload).
pub fn start_single_rule(
    rule: &RuleConfig,
    config: &GatewayConfig,
    global_shutdown: Arc<AtomicBool>,
    rule_shutdowns: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    registry: Arc<ProviderRegistry>,
    pipeline: Arc<PipelineComponents>,
) -> thread::JoinHandle<()> {
    let rule_name = rule.name.clone();
    let direction = rule.direction;
    let priority = rule.priority;
    let configured_provider = rule.effective_security_provider().to_string();
    let app_protocol = rule.effective_app_protocol();

    if let Some(app_id) = &rule.app_id {
        debug!(
            "[{}] Rule metadata: app_id={} app_protocol={}",
            rule_name, app_id, app_protocol
        );
    }

    // Resolve the effective crypto engine, applying the kTLS preference. kTLS
    // only offloads the default AES-GCM, server-authenticated path, so a
    // non-offloadable `ktls` rule (custom profile, peer verification or PSK)
    // falls back to userspace `tls`; conversely an offloadable userspace `tls`
    // rule is upgraded to the zero-copy kTLS engine when `prefer_ktls` is set
    // and the kernel exposes the `tls` ULP. (integrity-only on kTLS is rejected
    // earlier at config-load time.)
    let offloadable = matches!(configured_provider.as_str(), "tls" | "ktls")
        && crate::security::tls_engine::params::TlsSecurityParams::from_params(
            &rule.provider_params,
            rule.protocol_version.as_deref(),
        )
        .map(|p| p.is_ktls_offloadable())
        .unwrap_or(false);
    let kernel_ktls = ktls_pipe::kernel_supports_ktls();
    // Surface the kernel-side fallback once per rule: without the `tls` ULP the
    // connections silently run on userspace TLS, and the preflight warning only
    // appears at --validate/startup preflight, not in the rule's own log.
    if configured_provider == "ktls" && !kernel_ktls {
        warn!(
            "[{}] rule requests kTLS but the kernel TLS ULP is unavailable \
             (try: modprobe tls); the rule runs on userspace TLS",
            rule_name
        );
    }
    let security_provider = crate::management::config::resolve_crypto_provider(
        &configured_provider,
        offloadable,
        config.prefer_ktls,
        kernel_ktls,
    )
    .to_string();
    if security_provider != configured_provider {
        if security_provider == "ktls" {
            info!(
                "[{}] preferring kTLS over userspace TLS (kernel `tls` ULP available)",
                rule_name
            );
        } else {
            warn!(
                "[{}] rule requests kTLS but its crypto parameters are not \
                 offloadable (kTLS offloads only the AES-GCM record-layer \
                 profiles); falling back to userspace TLS",
                rule_name
            );
        }
    }

    // Per-rule shutdown flag (for hot-reload)
    let rule_shutdown = Arc::new(AtomicBool::new(false));
    rule_shutdowns
        .lock()
        .unwrap()
        .insert(rule_name.clone(), rule_shutdown.clone());

    let rule_metrics = Arc::new(RuleMetrics::new(
        &rule_name,
        &direction.to_string(),
        &security_provider,
    ));
    let rule_metrics_summary = rule_metrics.clone();

    let shutdown_stats = global_shutdown.clone();
    let rule_shutdown_stats = rule_shutdown.clone();
    let stats_rule_name = rule_name.clone();

    // Build the connection pool for this rule. Defaults to 2× CPUs, but an
    // operator may raise it via `conn_pool_size` when driving more concurrent
    // connections than that (relay jobs are long-lived and Normal pools don't
    // overflow, so excess connections queue behind the base workers). The value
    // is range-checked in `GatewayConfig::validate` (TRA #57). Safety rules get a
    // class-aware pool: reserved minimum workers at elevated priority so a
    // normal-traffic storm cannot starve safety capacity.
    let pool_size = config
        .conn_pool_size
        .unwrap_or_else(ConnectionPool::default_size);
    let conn_pool = Arc::new(ConnectionPool::new_for_class(
        pool_size,
        &rule.name,
        rule.traffic_class,
    ));

    // Derive tls_mode from the effective security provider name so that
    // `"security_provider": "ktls"` in the config correctly activates kTLS,
    // even when the legacy `tls_mode` field is absent (defaults to Tls).
    let effective_tls_mode = match security_provider.as_str() {
        "ktls" => TlsMode::Ktls,
        "dtls" => TlsMode::Dtls,
        _ => rule.tls_mode, // "tls" or custom providers: use legacy field
    };

    // Build the RuleContext (moved into the thread)
    let perf = rule.perf_knobs(config.perf_profile, config.sock_buf_size);
    let ctx = RuleContext {
        rule_name: rule.name.clone(),
        listen_addr: rule.listen_addr.clone(),
        listen_proto: rule.listen_proto,
        upstream_addr: rule.upstream_addr.clone(),
        upstream_proto: rule.upstream_proto,
        tls_mode: effective_tls_mode,
        security_provider: security_provider.clone(),
        transparent: rule.transparent,
        sock_buf_size: perf.sock_buf_size,
        metrics: rule_metrics,
        shutdown: Arc::new(AtomicBool::new(false)), // placeholder, replaced below
        provider_params: rule.provider_params.clone(),
        traffic_class: rule.traffic_class,
        qos: rule.qos(),
        traffic_analyzer: pipeline.traffic_analyzer.clone(),
        policy_manager: Some(pipeline.policy_manager.clone()),
        simulated_delay_ms: rule.simulated_delay_ms,
        protocol_version: rule.protocol_version.clone(),
        app_protocol: app_protocol.to_string(),
        perf,
        conn_pool,
    };

    let global = global_shutdown.clone();
    let per_rule = rule_shutdown.clone();

    let handle = thread::Builder::new()
        .name(format!("rule-{}", rule_name))
        .spawn(move || {
            if priority != 0 {
                // SAFETY: `setpriority` is a thin FFI wrapper taking only scalar
                // (non-pointer) arguments; `PRIO_PROCESS` with `who == 0` selects
                // the calling thread, and `priority` is a plain `c_int`, so there
                // are no memory-safety preconditions to uphold and the call cannot
                // cause undefined behaviour regardless of its return value.
                unsafe {
                    libc::setpriority(libc::PRIO_PROCESS, 0, priority);
                }
            }

            // Combined shutdown: fires when either global or per-rule shutdown is set.
            let combined_shutdown = Arc::new(AtomicBool::new(false));
            {
                let combined = combined_shutdown.clone();
                let global = global.clone();
                let per_rule = per_rule.clone();
                thread::spawn(move || loop {
                    if global.load(Ordering::Relaxed) || per_rule.load(Ordering::Relaxed) {
                        combined.store(true, Ordering::SeqCst);
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                });
            }

            // Overwrite the placeholder shutdown with the combined flag
            let ctx = RuleContext {
                shutdown: combined_shutdown,
                ..ctx
            };

            // Dispatch to the registered crypto provider
            let provider = match registry.find_crypto(&ctx.security_provider) {
                Some(p) => p,
                None => {
                    error!(
                        "[{}] ERROR: unknown security provider '{}'. Available: {:?}",
                        ctx.rule_name,
                        ctx.security_provider,
                        registry.crypto_names(),
                    );
                    return;
                }
            };

            let result = match direction {
                Direction::Encrypt => provider.run_encrypt(&ctx),
                Direction::Decrypt => provider.run_decrypt(&ctx),
            };

            if let Err(e) = result {
                error!("[{}] ERROR: {}", ctx.rule_name, e);
            }
        })
        .unwrap_or_else(|e| {
            panic!(
                "Failed to spawn thread for rule '{}': {}",
                stats_rule_name, e
            )
        });

    // Spawn periodic stats printer
    thread::Builder::new()
        .name(format!("stats-{}", stats_rule_name))
        .spawn(move || {
            while !shutdown_stats.load(Ordering::Relaxed)
                && !rule_shutdown_stats.load(Ordering::Relaxed)
            {
                thread::sleep(Duration::from_secs(10));
                rule_metrics_summary.print_summary(10.0);
            }
        })
        .ok();

    handle
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::config::GatewayConfig;
    use std::net::SocketAddr;

    fn ctx_with_policy(policy: Option<Arc<RwLock<PolicyManager>>>) -> RuleContext {
        let json = r#"{"rules":[{
            "name":"dp07","direction":"encrypt",
            "listen_addr":"127.0.0.1:0","listen_proto":"tcp",
            "upstream_addr":"127.0.0.1:9","upstream_proto":"tcp",
            "security_provider":"routing"
        }]}"#;
        let cfg: GatewayConfig = serde_json::from_str(json).unwrap();
        let rule = &cfg.rules[0];
        let perf = rule.perf_knobs(cfg.perf_profile, cfg.sock_buf_size);
        RuleContext {
            rule_name: rule.name.clone(),
            listen_addr: rule.listen_addr.clone(),
            listen_proto: rule.listen_proto,
            upstream_addr: rule.upstream_addr.clone(),
            upstream_proto: rule.upstream_proto,
            tls_mode: TlsMode::Tls,
            security_provider: rule.security_provider.clone(),
            transparent: rule.transparent,
            sock_buf_size: perf.sock_buf_size,
            metrics: Arc::new(RuleMetrics::new(&rule.name, "encrypt", "routing")),
            shutdown: Arc::new(AtomicBool::new(false)),
            provider_params: rule.provider_params.clone(),
            traffic_class: rule.traffic_class,
            qos: rule.qos(),
            traffic_analyzer: None,
            policy_manager: policy,
            simulated_delay_ms: 0,
            protocol_version: None,
            app_protocol: "raw".to_string(),
            perf,
            conn_pool: Arc::new(ConnectionPool::new(1, "dp07-test")),
        }
    }

    // An upstream target that is not a parseable IP:port must fail closed
    // (drop), not silently skip the policy gate. With no policy manager the
    // delegate path would *allow*, so a `false` here proves the fail-closed branch.
    #[test]
    fn unparseable_target_fails_closed() {
        let ctx = ctx_with_policy(None);
        let src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        assert!(!ctx.classify_and_check_policy_target(&src, "backend.example.com:443"));
        assert!(!ctx.classify_and_check_policy_target(&src, "not-an-address"));
    }

    // A parseable target delegates to the normal gate (allow when no policy set).
    #[test]
    fn parseable_target_delegates() {
        let ctx = ctx_with_policy(None);
        let src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        assert!(ctx.classify_and_check_policy_target(&src, "127.0.0.1:9000"));
    }

    // TRA #73: a hostname upstream resolves once to a concrete address that can
    // then be policy-gated; an unresolvable name fails closed (None).
    #[test]
    fn resolve_upstream_target_resolves_and_fails_closed() {
        let ctx = ctx_with_policy(None);
        // localhost always resolves to a loopback address.
        let resolved = ctx
            .resolve_upstream_target("localhost:9000")
            .expect("localhost must resolve");
        assert!(resolved.ip().is_loopback());
        assert_eq!(resolved.port(), 9000);
        // A literal IP:port passes straight through.
        assert_eq!(
            ctx.resolve_upstream_target("127.0.0.1:9000"),
            Some("127.0.0.1:9000".parse().unwrap())
        );
        // The reserved.invalid TLD never resolves → fail closed.
        assert!(ctx
            .resolve_upstream_target("nonexistent.invalid:443")
            .is_none());
    }

    // A parseable target that a default-deny policy rejects is still dropped.
    #[test]
    fn parseable_target_denied_by_policy() {
        let cfg: GatewayConfig = serde_json::from_str(
            r#"{"rules":[],"policy":{"default_action":"deny","whitelist":[
                {"source":"10.0.0.1/32","destination":"127.0.0.1:1"}
            ]}}"#,
        )
        .unwrap();
        let pm = Arc::new(RwLock::new(PolicyManager::new(cfg.policy.as_ref())));
        let ctx = ctx_with_policy(Some(pm));
        let src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        // Destination not whitelisted → denied; unparseable → also denied.
        assert!(!ctx.classify_and_check_policy_target(&src, "127.0.0.1:9000"));
        assert!(!ctx.classify_and_check_policy_target(&src, "backend:443"));
    }
}
