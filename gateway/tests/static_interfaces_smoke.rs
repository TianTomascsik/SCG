//! Smoke tests for the static (config-driven) network interfaces.
//!
//! The TCP/UDP/TPROXY data paths are exercised in depth by the benchmark suite;
//! here we guard the config + relay plumbing against regressions while the local
//! interfaces are integrated by asserting the gateway still:
//!   1. relays a plain TCP connection through a TLS upstream end to end, and
//!   2. accepts representative UDP and TPROXY rule configurations through the
//!      real validator (`GatewayConfig::load`).
//!
//! Runs unprivileged: the TCP relay uses loopback + the gateway's self-signed
//! TLS, and the TPROXY rule is only validated (its data path needs
//! CAP_NET_ADMIN, covered by `preflight_check`).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use common::{temp_dir, EchoServer};

use gateway::app_protocols::ale_provider::AleProtocolProvider;
use gateway::app_protocols::raw_provider::RawProtocolProvider;
use gateway::management::config::GatewayConfig;
use gateway::processing::policy::PolicyManager;
use gateway::processing::registry::ProviderRegistry;
use gateway::processing::{start_rules, PipelineComponents};
use gateway::security::providers::dtls_provider::DtlsProvider;
use gateway::security::providers::ktls_provider::KtlsProvider;
use gateway::security::providers::tls_provider::TlsProvider;

/// Build a registry with the same built-in providers the gateway registers.
fn built_in_registry() -> Arc<ProviderRegistry> {
    let mut registry = ProviderRegistry::new();
    registry.register_crypto(Box::new(TlsProvider));
    registry.register_crypto(Box::new(KtlsProvider));
    registry.register_crypto(Box::new(DtlsProvider));
    registry.register_app_protocol(Box::new(AleProtocolProvider));
    registry.register_app_protocol(Box::new(RawProtocolProvider));
    registry.into_arc()
}

/// Grab an ephemeral loopback port, then release it for the gateway to bind.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

#[test]
fn tcp_encrypt_relay_round_trip() {
    let tmp = temp_dir("tcp-smoke");
    let echo = EchoServer::start();
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");

    // Safety class so the default deny-all policy (no policy configured) passes;
    // the encrypt relay path runs a policy check on every connection.
    let json = format!(
        r#"{{
            "rules": [{{
                "name": "tcp-encrypt",
                "direction": "encrypt",
                "listen_addr": "{listen}",
                "listen_proto": "tcp",
                "upstream_addr": "{echo}",
                "upstream_proto": "tcp",
                "security_provider": "tls",
                "traffic_class": "safety"
            }}]
        }}"#,
        listen = listen,
        echo = echo.addr,
    );
    let cfg_path = tmp.join("gw.json");
    std::fs::write(&cfg_path, &json).unwrap();
    let config = GatewayConfig::load(cfg_path.to_str().unwrap()).expect("TCP config validates");

    let shutdown = Arc::new(AtomicBool::new(false));
    let pipeline = Arc::new(PipelineComponents {
        traffic_analyzer: None,
        policy_manager: Arc::new(RwLock::new(PolicyManager::new(None))),
    });
    let (handles, _rule_shutdowns) =
        start_rules(&config, shutdown.clone(), built_in_registry(), pipeline);

    // Wait for the rule's listener to accept connections.
    let mut client = None;
    for _ in 0..60 {
        if let Ok(s) = TcpStream::connect(&listen) {
            client = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut client = client.expect("gateway TCP listener never came up");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    client.write_all(b"tcp-smoke-payload").expect("plain write");
    let _ = client.flush();

    let mut buf = [0u8; 64];
    let n = client.read(&mut buf).expect("read echoed reply");
    assert_eq!(
        &buf[..n],
        b"tcp-smoke-payload",
        "plain payload should round-trip through the TLS upstream"
    );

    drop(client);
    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn udp_and_tproxy_rules_validate() {
    let tmp = temp_dir("static-validate");
    let uport = free_port();
    let tport = free_port();

    let json = format!(
        r#"{{
            "rules": [
                {{
                    "name": "udp-encrypt",
                    "direction": "encrypt",
                    "listen_addr": "127.0.0.1:{uport}",
                    "listen_proto": "udp",
                    "upstream_addr": "127.0.0.1:8443",
                    "upstream_proto": "tcp",
                    "security_provider": "tls",
                    "app_protocol": "ale"
                }},
                {{
                    "name": "tproxy-encrypt",
                    "direction": "encrypt",
                    "listen_addr": "127.0.0.1:{tport}",
                    "listen_proto": "tcp",
                    "upstream_addr": "auto",
                    "upstream_proto": "tcp",
                    "security_provider": "tls",
                    "transparent": true
                }}
            ]
        }}"#,
    );
    let cfg_path = tmp.join("gw.json");
    std::fs::write(&cfg_path, &json).unwrap();

    let config = GatewayConfig::load(cfg_path.to_str().unwrap())
        .expect("UDP + TPROXY rules should pass validation");
    assert_eq!(config.rules.len(), 2);

    // Preflight is environment-sensitive (TPROXY needs CAP_NET_ADMIN); just
    // confirm it runs and reports rather than panicking.
    let (_warnings, _errors) = config.preflight_check();

    let _ = std::fs::remove_dir_all(&tmp);
}
