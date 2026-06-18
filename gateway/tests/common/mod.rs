//! Shared helpers for the local-interface integration tests.
//!
//! Provides a self-contained TLS echo upstream, a temp-dir helper, a config
//! builder that mirrors how the gateway is configured in production, and a
//! small "wait until the management socket is connectable" poll. Everything
//! here runs unprivileged: the runtime directory is a throwaway temp dir, and
//! memfd / eventfd / socket creation need no special capabilities on Linux.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gateway::management::config::GatewayConfig;
use gateway::security::tls_engine::build_tls_acceptor;

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
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo upstream");
        let addr = listener.local_addr().expect("echo local_addr").to_string();
        listener
            .set_nonblocking(true)
            .expect("echo set_nonblocking");

        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = shutdown.clone();
        let handle = std::thread::spawn(move || {
            let acceptor = build_tls_acceptor(None).expect("build tls acceptor");
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
