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
    Direction, GatewayConfig, Proto, RuleConfig, TlsMode, TrafficClass,
};
use crate::management::telemetry::RuleMetrics;
use crate::security::conn_pool::ConnectionPool;
use log::{debug, error, warn};
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
    pub measure_latency: bool,
    pub sock_buf_size: usize,
    pub log_dir: String,
    pub run_id: String,
    pub metrics: Arc<RuleMetrics>,
    pub shutdown: Arc<AtomicBool>,
    /// Provider-specific parameters (from the rule's generic `provider_params`).
    /// Custom/external crypto providers read their own settings from here.
    pub provider_params: std::collections::HashMap<String, serde_json::Value>,
    // Traffic policy fields (optional — None means policy pipeline is not active)
    pub traffic_class: TrafficClass,
    pub traffic_analyzer: Option<Arc<TrafficAnalyzer>>,
    pub policy_manager: Option<Arc<RwLock<PolicyManager>>>,
    pub simulated_delay_ms: u64,
    pub protocol_version: Option<String>,
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
}

// ─── Rule runner ─────────────────────────────────────────────────────────────

/// Pipeline components shared across rules.
pub struct PipelineComponents {
    pub traffic_analyzer: Option<Arc<TrafficAnalyzer>>,
    pub policy_manager: Arc<RwLock<PolicyManager>>,
}

/// Start all proxy rules. Returns join handles for the listener threads
/// and a map of rule names -> shutdown flags for per-rule hot-reload.
pub fn start_rules(
    config: &GatewayConfig,
    shutdown: Arc<AtomicBool>,
    registry: Arc<ProviderRegistry>,
    pipeline: Arc<PipelineComponents>,
) -> (
    Vec<thread::JoinHandle<()>>,
    Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
) {
    let mut handles = Vec::new();
    let rule_shutdowns: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>> =
        Arc::new(Mutex::new(HashMap::new()));

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
    let security_provider = rule.effective_security_provider().to_string();
    let app_protocol = rule.effective_app_protocol();

    if let Some(app_id) = &rule.app_id {
        debug!(
            "[{}] Rule metadata: app_id={} app_protocol={}",
            rule_name, app_id, app_protocol
        );
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

    // Build the connection pool for this rule (2× CPUs)
    let pool_size = ConnectionPool::default_size();
    let conn_pool = Arc::new(ConnectionPool::new(pool_size, &rule.name));

    // Derive tls_mode from the effective security provider name so that
    // `"security_provider": "ktls"` in the config correctly activates kTLS,
    // even when the legacy `tls_mode` field is absent (defaults to Tls).
    let effective_tls_mode = match security_provider.as_str() {
        "ktls" => TlsMode::Ktls,
        "dtls" => TlsMode::Dtls,
        _ => rule.tls_mode, // "tls" or custom providers: use legacy field
    };

    // Build the RuleContext (moved into the thread)
    let ctx = RuleContext {
        rule_name: rule.name.clone(),
        listen_addr: rule.listen_addr.clone(),
        listen_proto: rule.listen_proto,
        upstream_addr: rule.upstream_addr.clone(),
        upstream_proto: rule.upstream_proto,
        tls_mode: effective_tls_mode,
        security_provider: security_provider.clone(),
        transparent: rule.transparent,
        measure_latency: config.latency,
        sock_buf_size: config.sock_buf_size,
        log_dir: config.log_dir.clone(),
        run_id: config.run_id.clone(),
        metrics: rule_metrics,
        shutdown: Arc::new(AtomicBool::new(false)), // placeholder, replaced below
        provider_params: rule.provider_params.clone(),
        traffic_class: rule.traffic_class,
        traffic_analyzer: pipeline.traffic_analyzer.clone(),
        policy_manager: Some(pipeline.policy_manager.clone()),
        simulated_delay_ms: rule.simulated_delay_ms,
        protocol_version: rule.protocol_version.clone(),
        conn_pool,
    };

    let global = global_shutdown.clone();
    let per_rule = rule_shutdown.clone();

    let handle = thread::Builder::new()
        .name(format!("rule-{}", rule_name))
        .spawn(move || {
            if priority != 0 {
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
