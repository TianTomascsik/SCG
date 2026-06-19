//! Shared helpers for the local-interface integration tests.
//!
//! Provides a self-contained TLS echo upstream, a temp-dir helper, a config
//! builder that mirrors how the gateway is configured in production, and a
//! small "wait until the management socket is connectable" poll. Everything
//! here runs unprivileged: the runtime directory is a throwaway temp dir, and
//! memfd / eventfd / socket creation need no special capabilities on Linux.

#![allow(dead_code)]

pub mod dtls;
pub mod pki;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gateway::management::config::GatewayConfig;
use gateway::security::tls_engine::build_tls_acceptor;
use gateway::security::tls_engine::params::TlsSecurityParams;

use gateway::app_protocols::ale_provider::AleProtocolProvider;
use gateway::app_protocols::raw_provider::RawProtocolProvider;
use gateway::processing::policy::PolicyManager;
use gateway::processing::registry::ProviderRegistry;
use gateway::processing::{start_rules, PipelineComponents};
use gateway::security::providers::dtls_provider::DtlsProvider;
use gateway::security::providers::ktls_provider::KtlsProvider;
use gateway::security::providers::routing_provider::RoutingProvider;
use gateway::security::providers::tls_provider::TlsProvider;

/// A loopback TLS server that echoes every byte it receives back to the sender.
///
/// The gateway connects to this as its TLS upstream; whatever framed bytes the
/// gateway forwards are reflected verbatim, so a client `send` comes back as an
/// identical `recv` after a full client → gateway → upstream → gateway → client
/// round-trip.
pub struct EchoServer {
    /// `127.0.0.1:<port>` address the gateway should use as `upstream_addr`.
    pub addr: String,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl EchoServer {
    /// Bind on an ephemeral loopback port and start accepting TLS connections.
    pub fn start() -> EchoServer {
        EchoServer::start_with_params(TlsSecurityParams::default())
    }

    /// Like [`EchoServer::start`] but with explicit TLS security parameters
    /// (file identity, `verify = mutual` for client-cert enforcement, etc.).
    pub fn start_with_params(params: TlsSecurityParams) -> EchoServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo upstream");
        let addr = listener.local_addr().expect("echo local_addr").to_string();
        listener
            .set_nonblocking(true)
            .expect("echo set_nonblocking");

        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = shutdown.clone();
        let handle = std::thread::spawn(move || {
            let acceptor =
                build_tls_acceptor(&params).expect("build tls acceptor");
            while !sd.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _peer)) => {
                        let acc = acceptor.clone();
                        let conn_sd = sd.clone();
                        std::thread::spawn(move || {
                            // Accepted sockets must be blocking for the handshake.
                            let _ = stream.set_nonblocking(false);
                            let mut tls = match acc.accept(stream) {
                                Ok(s) => s,
                                Err(_) => return,
                            };
                            let mut buf = [0u8; 16 * 1024];
                            loop {
                                if conn_sd.load(Ordering::Relaxed) {
                                    break;
                                }
                                match tls.read(&mut buf) {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if tls.write_all(&buf[..n]).is_err() {
                                            break;
                                        }
                                        let _ = tls.flush();
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        EchoServer {
            addr,
            shutdown,
            handle: Some(handle),
        }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// A loopback **plain TCP** server that echoes every byte it receives.
///
/// Used by routing-only (no-TLS) and L4-passthrough tests where the upstream
/// must terminate plaintext rather than TLS.
pub struct PlainEchoServer {
    /// `127.0.0.1:<port>` address to use as `upstream_addr`.
    pub addr: String,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl PlainEchoServer {
    /// Bind on an ephemeral loopback port and start accepting plain TCP.
    pub fn start() -> PlainEchoServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind plain echo upstream");
        let addr = listener.local_addr().expect("echo local_addr").to_string();
        listener
            .set_nonblocking(true)
            .expect("echo set_nonblocking");

        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = shutdown.clone();
        let handle = std::thread::spawn(move || {
            while !sd.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        let conn_sd = sd.clone();
                        std::thread::spawn(move || {
                            let _ = stream.set_nonblocking(false);
                            let mut buf = [0u8; 16 * 1024];
                            loop {
                                if conn_sd.load(Ordering::Relaxed) {
                                    break;
                                }
                                match stream.read(&mut buf) {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if stream.write_all(&buf[..n]).is_err() {
                                            break;
                                        }
                                        let _ = stream.flush();
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        PlainEchoServer {
            addr,
            shutdown,
            handle: Some(handle),
        }
    }
}

impl Drop for PlainEchoServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Create a unique throwaway directory for sockets and the runtime dir.
pub fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("scg-itest-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Build a gateway config with one UDS and one SHM rule, both bound to the same
/// `app-test` app id, encrypting toward the supplied echo upstream. `uid` must
/// be the caller's effective uid so the local interface authorises it.
pub fn build_config(echo_addr: &str, uid: u32, tmp: &Path) -> GatewayConfig {
    let mgmt_sock = tmp.join("mgmt.sock");
    let runtime_dir = tmp.join("run");
    let json = format!(
        r#"{{
            "rules": [
                {{
                    "name": "uds-test",
                    "direction": "encrypt",
                    "listen_addr": "unused",
                    "listen_proto": "uds",
                    "upstream_addr": "{echo}",
                    "upstream_proto": "tcp",
                    "security_provider": "tls",
                    "traffic_class": "safety",
                    "app_id": "app-test",
                    "allowed_uids": [{uid}]
                }},
                {{
                    "name": "shm-test",
                    "direction": "encrypt",
                    "listen_addr": "unused",
                    "listen_proto": "shm",
                    "upstream_addr": "{echo}",
                    "upstream_proto": "tcp",
                    "security_provider": "tls",
                    "traffic_class": "safety",
                    "app_id": "app-test",
                    "allowed_uids": [{uid}]
                }}
            ],
            "api": {{
                "enabled": true,
                "uds_path": "{mgmt}",
                "runtime_dir": "{run}",
                "shm_ring_capacity": 65536
            }}
        }}"#,
        echo = echo_addr,
        uid = uid,
        mgmt = mgmt_sock.display(),
        run = runtime_dir.display(),
    );
    serde_json::from_str(&json).expect("parse integration test config")
}

/// Poll until `path` accepts a connection or the timeout elapses.
pub fn wait_for_socket(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

/// The caller's effective uid, used to authorise the local interface.
pub fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Grab a currently-free loopback TCP port (best-effort; closes the probe
/// socket before returning so a rule can bind it).
pub fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// A provider registry populated with every built-in crypto and app provider,
/// matching what `gateway::run` registers at start-up.
pub fn built_in_registry() -> Arc<ProviderRegistry> {
    let mut registry = ProviderRegistry::new();
    registry.register_crypto(Box::new(TlsProvider));
    registry.register_crypto(Box::new(KtlsProvider));
    registry.register_crypto(Box::new(DtlsProvider));
    registry.register_crypto(Box::new(RoutingProvider));
    registry.register_app_protocol(Box::new(AleProtocolProvider));
    registry.register_app_protocol(Box::new(RawProtocolProvider));
    registry.into_arc()
}

/// Spin up every rule in `config` with the built-in registry and a permissive
/// (no traffic analyzer) pipeline. Returns the join handles plus the shared
/// shutdown flag the caller flips to tear the rules down.
pub fn run_rules(config: &GatewayConfig) -> (Vec<JoinHandle<()>>, Arc<AtomicBool>) {
    let shutdown = Arc::new(AtomicBool::new(false));
    let pipeline = Arc::new(PipelineComponents {
        traffic_analyzer: None,
        policy_manager: Arc::new(RwLock::new(PolicyManager::new(None))),
    });
    let (handles, _rule_shutdowns) =
        start_rules(config, shutdown.clone(), built_in_registry(), pipeline);
    (handles, shutdown)
}

/// Connect to `addr` over plain TCP, retrying briefly while the rule's listener
/// comes up. Returns `None` if it never becomes connectable.
pub fn connect_tcp_with_retry(addr: &str, attempts: usize) -> Option<TcpStream> {
    for _ in 0..attempts {
        if let Ok(s) = TcpStream::connect(addr) {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Write a single-rule gateway config to `tmp/gw.json`, then load + validate it.
pub fn load_single_rule(tmp: &Path, rule: &str) -> GatewayConfig {
    let json = format!(
        r#"{{ "log_dir": "{log}", "rules": [{rule}] }}"#,
        log = tmp.display(),
        rule = rule,
    );
    let path = tmp.join("gw.json");
    std::fs::write(&path, json).unwrap();
    GatewayConfig::load(path.to_str().unwrap()).expect("config validates")
}

/// Plain-TCP client round-trip against an encrypt rule's listener: connect,
/// send `payload`, read back exactly `payload.len()` bytes. Returns `Err` when
/// the gateway tears the connection down (e.g. the upstream handshake failed),
/// which the negative tests assert on.
pub fn plain_round_trip(addr: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut c = connect_tcp_with_retry(addr, 60).expect("gateway listener never came up");
    c.set_read_timeout(Some(Duration::from_secs(5)))?;
    c.write_all(payload)?;
    c.flush()?;
    let mut buf = vec![0u8; payload.len()];
    c.read_exact(&mut buf)?;
    Ok(buf)
}
