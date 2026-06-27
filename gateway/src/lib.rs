//! Secure Communication Gateway — library core.
//!
//! A configurable proxy that transparently encrypts or decrypts traffic:
//!
//! - **Encrypt direction**: Accept plain TCP/UDP -> forward as TLS/kTLS/DTLS or
//!   any registered custom provider.
//! - **Decrypt direction**: Accept TLS/kTLS/DTLS (or custom) -> forward as plain
//!   TCP/UDP.
//!
//! The gateway is exposed as a library so that downstream binaries can register
//! additional providers (for example proprietary crypto) on top of the built-in
//! set before starting the runtime via [`run`].
//!
//! Supports:
//! - Pluggable security providers (TLS, kTLS, DTLS, or custom)
//! - Pluggable app-level protocol providers (ALE, Raw, or custom)
//! - TPROXY transparent proxying with `IP_TRANSPARENT` and `SO_ORIGINAL_DST`
//! - Hot-reload: SIGHUP or file change reloads config without interrupting transfers

pub mod api;
pub mod app_protocols;
pub mod interfaces;
pub mod management;
pub mod networking;
pub mod processing;
pub mod security;

use app_protocols::ale_provider::AleProtocolProvider;
use app_protocols::provider::AppProtocolProvider;
use app_protocols::raw_provider::RawProtocolProvider;
use log::{error, info, warn};
use management::config::GatewayConfig;
use management::config_manager::{spawn_config_watcher, SharedConfig};
use management::lite_config::{self, LiteSource};
use networking::firewall::FirewallManager;
use processing::cache::TrafficCache;
use processing::lifecycle::{LifecycleEvent, LifecycleOrchestrator};
use processing::policy::PolicyManager;
use processing::registry::ProviderRegistry;
use processing::traffic_analyzer::TrafficAnalyzer;
use security::provider::CryptoProvider;
use security::providers::dtls_provider::DtlsProvider;
use security::providers::ktls_provider::KtlsProvider;
use security::providers::routing_provider::RoutingProvider;
use security::providers::tls_provider::TlsProvider;
use security::providers::wireguard_provider::WireguardProvider;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::path::{Path, PathBuf};

/// Run the gateway runtime.
///
/// The built-in TLS/kTLS/DTLS/WireGuard/routing crypto providers and ALE/Raw
/// app-protocol providers are always registered. `extra_crypto` and `extra_app` let a
/// downstream binary register additional providers (e.g. proprietary crypto)
/// before startup. Pass empty vectors for the default open configuration.
///
/// This function parses the process arguments, loads configuration, and blocks
/// until shutdown.
pub fn run(
    extra_crypto: Vec<Box<dyn CryptoProvider>>,
    extra_app: Vec<Box<dyn AppProtocolProvider>>,
) {
    let args: Vec<String> = std::env::args().collect();

    // Build the provider registry: built-in providers plus any extras supplied
    // by the caller. Constructing the registry has no side effects, so it is
    // safe to do before argument handling (needed to print provider names).
    let mut registry = ProviderRegistry::new();
    registry.register_crypto(Box::new(TlsProvider));
    registry.register_crypto(Box::new(KtlsProvider));
    registry.register_crypto(Box::new(DtlsProvider));
    registry.register_crypto(Box::new(WireguardProvider));
    registry.register_crypto(Box::new(RoutingProvider));
    for provider in extra_crypto {
        registry.register_crypto(provider);
    }
    registry.register_app_protocol(Box::new(AleProtocolProvider));
    registry.register_app_protocol(Box::new(RawProtocolProvider));
    for provider in extra_app {
        registry.register_app_protocol(provider);
    }

    if args.len() < 2 || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_usage(&args[0], &registry);
        std::process::exit(0);
    }

    // Parse --config flag
    let validate_only = args.contains(&"--validate".to_string());
    let log_stdout = args.contains(&"--log-stdout".to_string());

    // ── Resolve the configuration source ─────────────────────────────────────
    // Two mutually-exclusive modes:
    //   --config PATH     ... classic single-file gateway config
    //   --config-dir DIR  ... layered "lite" config (signed defaults + user)
    //
    // In lite mode the directory is loaded through the layered pipeline, which
    // verifies the detached Ed25519 signatures and the pinned schema hash
    // (fail-closed) before mapping connections to data-plane rules. The trust
    // anchor is `--config-pubkey PATH` or `<dir>/trust/config-signing.pub.pem`.
    let config_dir = args
        .iter()
        .position(|a| a == "--config-dir")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let config_pubkey = args
        .iter()
        .position(|a| a == "--config-pubkey")
        .and_then(|i| args.get(i + 1))
        .cloned();

    let (config, lite_warnings, config_watch_path, lite_source) = if let Some(dir) = config_dir {
        let pubkey = config_pubkey.clone().map(PathBuf::from);
        match lite_config::load_with_warnings(Path::new(&dir), pubkey.as_deref()) {
            Ok((c, w)) => {
                let source = LiteSource {
                    dir: PathBuf::from(&dir),
                    pubkey,
                };
                let watch = source.watch_path().to_string_lossy().into_owned();
                (c, w, watch, Some(source))
            }
            Err(e) => {
                eprintln!("Configuration error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        let config_path = args
            .iter()
            .position(|a| a == "--config")
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| {
                eprintln!("Error: --config PATH or --config-dir DIR is required");
                print_usage(&args[0], &registry);
                std::process::exit(1);
            });
        match GatewayConfig::load(&config_path) {
            Ok(c) => (c, Vec::new(), config_path, None),
            Err(e) => {
                eprintln!("Configuration error: {}", e);
                std::process::exit(1);
            }
        }
    };

    // Parse --log-level CLI flag (overrides config log_level)
    let cli_log_level = args
        .iter()
        .position(|a| a == "--log-level")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Resolve log level: CLI > config > default ("info")
    let log_level_str = cli_log_level
        .or_else(|| config.log_level.clone())
        .unwrap_or_else(|| "info".to_string());

    let log_level = match log_level_str.to_lowercase().as_str() {
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "info" => log::LevelFilter::Info,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        other => {
            eprintln!(
                "Warning: unknown log level '{}', defaulting to 'info'",
                other
            );
            log::LevelFilter::Info
        }
    };

    // Initialize the logger
    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_millis()
        .init();

    // Surface any warnings collected while loading a lite config (deferred or
    // downgraded features) now that the logger is up.
    for w in &lite_warnings {
        warn!("[lite-config] {}", w);
    }

    let enable_watch = args.contains(&"--watch".to_string());

    // --validate: check config + preflight, then exit
    if validate_only {
        info!("=== Configuration Validation ===");
        config.print_summary();

        let (warnings, errors) = config.preflight_check();

        if !warnings.is_empty() {
            info!("Warnings:");
            for w in &warnings {
                warn!("  {}", w);
            }
        }

        if !errors.is_empty() {
            info!("Errors:");
            for e in &errors {
                error!("  {}", e);
            }
            error!(
                "Validation FAILED ({} error(s), {} warning(s))",
                errors.len(),
                warnings.len()
            );
            std::process::exit(1);
        }

        if warnings.is_empty() {
            info!("Validation PASSED (no warnings)");
        } else {
            info!("Validation PASSED ({} warning(s))", warnings.len());
        }
        std::process::exit(0);
    }

    // Finalize the registry for sharing across rule threads.
    let registry = registry.into_arc();

    // Print config summary
    config.print_summary();

    // Run preflight checks (warnings only -- don't block startup for non-fatal issues)
    let (warnings, errors) = config.preflight_check();
    for w in &warnings {
        warn!("{}", w);
    }
    for e in &errors {
        error!("{}", e);
    }
    if !errors.is_empty() {
        error!(
            "{} preflight error(s) detected -- startup may fail",
            errors.len()
        );
        error!("Run with --validate for details, or fix the issues above");
    }

    // ── Firewall self-configuration (iptables intercept rules) ───────────────
    // Must run before listeners start so redirected traffic has somewhere to go.
    let firewall = if config.rules.iter().any(|r| r.intercept.is_some()) {
        match FirewallManager::setup(&config) {
            Ok(fw) => {
                info!("Firewall intercept rules installed (will tear down on shutdown)");
                Some(fw)
            }
            Err(e) => {
                error!("Failed to set up firewall intercept rules: {}", e);
                error!("Fix the issue or remove 'intercept' from the config");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Shutdown signal handling
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_signal = shutdown.clone();

    ctrlc_handler(shutdown_signal);

    // ── Instantiate traffic pipeline components ──────────────────────────────
    let pipeline_enabled = !config.traffic_rules.is_empty()
        || config.policy.is_some()
        || config
            .rules
            .iter()
            .any(|r| r.traffic_class != management::config::TrafficClass::Normal);

    // Traffic cache (shared across all rules for classification lookup)
    let cache_cfg = config.cache.as_ref();
    let traffic_cache = Arc::new(TrafficCache::new(
        cache_cfg.map_or(10_000, |c| c.max_entries),
        cache_cfg.map_or(300, |c| c.ttl_secs),
    ));

    // Traffic analyzer (classifies flows by source/dest)
    let traffic_analyzer = if !config.traffic_rules.is_empty() {
        Some(Arc::new(TrafficAnalyzer::new(
            &config.traffic_rules,
            traffic_cache.clone(),
        )))
    } else {
        None
    };

    // Policy manager (whitelist-based allow/deny)
    let policy_manager = Arc::new(RwLock::new(PolicyManager::new(config.policy.as_ref())));

    // Lifecycle orchestrator (event-driven cache/policy management)
    let (orchestrator, lifecycle_tx) = LifecycleOrchestrator::new(
        traffic_cache.clone(),
        policy_manager.clone(),
        shutdown.clone(),
    );

    // Spawn orchestrator thread
    let _orchestrator_handle = std::thread::Builder::new()
        .name("lifecycle-orchestrator".to_string())
        .spawn(move || orchestrator.run())
        .expect("Failed to spawn lifecycle orchestrator");

    if pipeline_enabled {
        info!(
            "Traffic pipeline enabled (analyzer={}, policy={}, cache={})",
            traffic_analyzer.is_some(),
            config.policy.is_some(),
            cache_cfg.is_some(),
        );
    }

    // Start all proxy rules
    let pipeline = Arc::new(processing::PipelineComponents {
        traffic_analyzer: traffic_analyzer.clone(),
        policy_manager: policy_manager.clone(),
    });
    let (handles, rule_shutdowns) = processing::start_rules(
        &config,
        shutdown.clone(),
        registry.clone(),
        pipeline.clone(),
    );

    // Build the interface manager (owns dynamically-created UDS/SHM endpoints)
    // and start the management API (gRPC) on a dedicated thread, off the data path.
    let interface_manager = interfaces::manager::InterfaceManager::new(
        &config,
        env!("CARGO_PKG_VERSION"),
        shutdown.clone(),
    );
    let api_cfg = config.api.clone().unwrap_or_default();
    let mgmt_handle = if api_cfg.enabled {
        match api::grpc::start_management_server(interface_manager.clone(), api_cfg, shutdown.clone())
        {
            Ok(h) => Some(h),
            Err(e) => {
                error!("Failed to start management API: {}", e);
                None
            }
        }
    } else {
        info!("Management API disabled (api.enabled = false)");
        None
    };

    // Start config watcher for hot-reload (if --watch or always via SIGHUP)
    let shared_config = match &lite_source {
        Some(source) => SharedConfig::new_lite(config.clone(), source.clone()),
        None => SharedConfig::new(config.clone(), &config_watch_path),
    };
    let watcher_shutdown = shutdown.clone();
    let watcher_rule_shutdowns = rule_shutdowns.clone();
    let watcher_config = shared_config.clone();
    let watcher_global_shutdown = shutdown.clone();
    let watcher_registry = registry.clone();
    let watcher_pipeline = pipeline.clone();
    let watcher_lifecycle_tx = lifecycle_tx.clone();

    let _watcher_handle = spawn_config_watcher(shared_config, watcher_shutdown, move |diff| {
        // Stop removed rules
        for name in &diff.removed {
            if let Some(flag) = watcher_rule_shutdowns.lock().unwrap().get(name) {
                flag.store(true, Ordering::SeqCst);
                info!("Stopped rule: \"{}\"", name);
            }
        }

        // Notify lifecycle orchestrator of config change
        let current_config = watcher_config.read();
        let _ = watcher_lifecycle_tx.send(LifecycleEvent::ConfigChanged {
            diff: current_config.diff(&current_config), // Pass a fresh diff for the orchestrator
            new_policy: current_config.policy.clone(),
        });

        // Start added rules
        for rule in &diff.added {
            info!("Starting new rule: \"{}\"", rule.name);
            let _handle = processing::start_single_rule(
                rule,
                &current_config,
                watcher_global_shutdown.clone(),
                watcher_rule_shutdowns.clone(),
                watcher_registry.clone(),
                watcher_pipeline.clone(),
            );
            // Note: handle is detached (thread runs independently)
        }
    });

    // Log to stdout if requested (for journald/container use)
    if log_stdout {
        info!("--log-stdout: log output will also go to stdout");
    }

    if enable_watch {
        info!("Hot-reload enabled -- edit config or send SIGHUP to reload");
    } else {
        info!("Send SIGHUP to reload configuration without restart");
    }
    info!("Running -- press Ctrl+C to stop");

    // Wait for all listener threads to finish with a timeout.
    // Spawn a watchdog that force-exits after 5 seconds to prevent hanging.
    let shutdown_watchdog = shutdown.clone();
    std::thread::Builder::new()
        .name("shutdown-watchdog".to_string())
        .spawn(move || {
            // Wait until shutdown is signaled
            while !shutdown_watchdog.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            // Give threads 5 seconds to finish gracefully
            std::thread::sleep(std::time::Duration::from_secs(5));
            eprintln!("[gateway] Shutdown timeout reached, forcing exit");
            // SAFETY: `_exit(2)` is an FFI call that takes no pointers and only
            // terminates the process immediately. It is sound to call here from
            // the watchdog thread; bypassing atexit handlers/destructors is the
            // intended behaviour for the forced-shutdown timeout path.
            unsafe {
                libc::_exit(1);
            }
        })
        .ok();

    for handle in handles {
        let _ = handle.join();
    }

    // If only on-demand interfaces are configured (no static listeners above),
    // block on the management server so the gateway stays alive until shutdown.
    if let Some(h) = mgmt_handle {
        let _ = h.join();
    }

    // Shutdown has fired: tear down any live UDS/SHM endpoints.
    interface_manager.shutdown_all();

    // Tear down firewall intercept rules (iptables chains + routing policy).
    if let Some(ref fw) = firewall {
        fw.teardown();
    }

    info!("Shutdown complete");
}

fn ctrlc_handler(shutdown: Arc<AtomicBool>) {
    // Install signal handlers for graceful shutdown.
    // Uses sigaction (not signal) for reliable behavior across invocations.
    // SAFETY: `libc::sigaction` is an all-zero-valid POSIX struct, so `zeroed()`
    // is a valid initial value; `signal_handler` is a correctly-typed `extern "C"`
    // function whose body only calls async-signal-safe operations. `sigemptyset`
    // and `sigaction` receive valid, fully-initialised pointers to `sa`/`sa_mask`
    // that live for the duration of each call, and we pass a null `oldact` pointer
    // (permitted: the previous disposition is discarded).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = signal_handler as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
    // Store the shutdown flag globally for the signal handler
    SHUTDOWN_FLAG
        .set(shutdown)
        .expect("SHUTDOWN_FLAG already set");
}

static SHUTDOWN_FLAG: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

extern "C" fn signal_handler(_sig: libc::c_int) {
    // A signal handler may only call async-signal-safe functions. `eprintln!`
    // is NOT one (it takes the stdio lock and may allocate) and can deadlock if
    // the signal interrupts a thread already holding that lock or the allocator.
    // `OnceLock::get`, `AtomicBool` ops, `write(2)`, and `_exit(2)` are all
    // async-signal-safe, so the handler uses only those.
    if let Some(flag) = SHUTDOWN_FLAG.get() {
        if flag.load(Ordering::SeqCst) {
            // Second signal -- force exit immediately.
            write_stderr(b"\n[gateway] Forced shutdown (second signal)\n");
            // SAFETY: `_exit(2)` is async-signal-safe and terminates the process
            // immediately without running atexit handlers or destructors (which
            // would not be signal-safe).
            unsafe {
                libc::_exit(1);
            }
        }
        flag.store(true, Ordering::SeqCst);
    }
    write_stderr(b"\n[gateway] Shutdown signal received, stopping... (send again to force quit)\n");
}

/// Write a fixed byte string to stderr using only the async-signal-safe
/// `write(2)` syscall, so it is safe to call from a signal handler. Best-effort:
/// the result (including short writes / `EINTR`) is intentionally ignored.
fn write_stderr(msg: &[u8]) {
    // SAFETY: `write(2)` is async-signal-safe. `msg` is a valid readable slice
    // of exactly `msg.len()` bytes; we pass its pointer and length unchanged and
    // ignore the return value (diagnostics are best-effort on the shutdown path).
    unsafe {
        let _ = libc::write(
            libc::STDERR_FILENO,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
        );
    }
}

fn print_usage(prog: &str, registry: &ProviderRegistry) {
    eprintln!("Usage: {} (--config PATH | --config-dir DIR) [OPTIONS]", prog);
    eprintln!();
    eprintln!("  Transparent encryption proxy gateway with extensible provider architecture");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --config PATH        Path to a classic single-file JSON config");
    eprintln!("  --config-dir DIR     Path to a layered 'lite' config dir (signed");
    eprintln!("                       scg.defaults.json + scg.user.json + schema)");
    eprintln!("  --config-pubkey PATH Ed25519 signing public key (trust anchor) for");
    eprintln!("                       --config-dir; defaults to DIR/trust/config-signing.pub.pem");
    eprintln!("  --validate           Validate config and environment, then exit");
    eprintln!("  --log-level LVL      Set log level: error, warn, info, debug, trace (default: info)");
    eprintln!("  --watch              Enable config hot-reload via file watching");
    eprintln!("  --log-stdout         Copy log output to stdout (for journald/containers)");
    eprintln!("  --help               Show this help");
    eprintln!();
    eprintln!("Validation (--validate):");
    eprintln!("  Checks: JSON syntax, rule consistency, port conflicts, CAP_NET_ADMIN,");
    eprintln!("  iptables chains, TPROXY routing policy, kTLS support.");
    eprintln!("  Exits 0 on success, 1 on failure. Safe to run -- makes no changes.");
    eprintln!();
    eprintln!("Hot-reload:");
    eprintln!("  SIGHUP signal always triggers a config reload (even without --watch).");
    eprintln!("  With --watch, the config file is polled every 2s for changes.");
    eprintln!("  Existing connections are NOT interrupted -- only new connections use new rules.");
    eprintln!();
    eprintln!("Configuration file format (JSON):");
    eprintln!();
    eprintln!("  {{");
    eprintln!("    \"rules\": [");
    eprintln!("      {{");
    eprintln!("        \"name\": \"web-encrypt\",");
    eprintln!("        \"direction\": \"encrypt\",");
    eprintln!("        \"listen_addr\": \"0.0.0.0:8080\",");
    eprintln!("        \"listen_proto\": \"tcp\",");
    eprintln!("        \"upstream_addr\": \"backend:443\",");
    eprintln!("        \"security_provider\": \"ktls\"");
    eprintln!("      }}");
    eprintln!("    ]");
    eprintln!("  }}");
    eprintln!();
    eprintln!("Security providers: {}", registry.crypto_names().join(", "));
    eprintln!(
        "App protocols (for UDP-over-TLS): {}",
        registry.app_protocol_names().join(", ")
    );
}
