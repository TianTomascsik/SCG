//! Integration test for the routing-only (plaintext L4 passthrough) provider.
//!
//! Confirms that a `"security_provider": "routing"` rule forwards a plain TCP
//! connection to a plain TCP upstream verbatim, with no TLS on either leg.
//! Runs fully unprivileged on loopback.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use common::{temp_dir, PlainEchoServer};

use gateway::app_protocols::ale_provider::AleProtocolProvider;
use gateway::app_protocols::raw_provider::RawProtocolProvider;
use gateway::management::config::GatewayConfig;
use gateway::processing::policy::PolicyManager;
use gateway::processing::registry::ProviderRegistry;
use gateway::processing::{start_rules, PipelineComponents};
use gateway::security::providers::dtls_provider::DtlsProvider;
use gateway::security::providers::ktls_provider::KtlsProvider;
use gateway::security::providers::routing_provider::RoutingProvider;
use gateway::security::providers::tls_provider::TlsProvider;

fn built_in_registry() -> Arc<ProviderRegistry> {
    let mut registry = ProviderRegistry::new();
    registry.register_crypto(Box::new(TlsProvider));
    registry.register_crypto(Box::new(KtlsProvider));
    registry.register_crypto(Box::new(DtlsProvider));
    registry.register_crypto(Box::new(RoutingProvider));
    registry.register_app_protocol(Box::new(AleProtocolProvider));
    registry.register_app_protocol(Box::new(RawProtocolProvider));
    registry.into_arc()
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

#[test]
fn routing_plaintext_passthrough_round_trip() {
    let tmp = temp_dir("routing-smoke");
    let echo = PlainEchoServer::start();
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");

    // Safety class so the default deny-all policy passes the per-connection check.
    let json = format!(
        r#"{{
            "log_dir": "{log}",
            "rules": [{{
                "name": "route-1",
                "direction": "encrypt",
                "listen_addr": "{listen}",
                "listen_proto": "tcp",
                "upstream_addr": "{echo}",
                "upstream_proto": "tcp",
                "security_provider": "routing",
                "traffic_class": "safety"
            }}]
        }}"#,
        log = tmp.display(),
        listen = listen,
        echo = echo.addr,
    );
    let cfg_path = tmp.join("gw.json");
    std::fs::write(&cfg_path, &json).unwrap();
    let config = GatewayConfig::load(cfg_path.to_str().unwrap()).expect("routing config validates");

    let shutdown = Arc::new(AtomicBool::new(false));
    let pipeline = Arc::new(PipelineComponents {
        traffic_analyzer: None,
        policy_manager: Arc::new(RwLock::new(PolicyManager::new(None))),
    });
    let (handles, _rule_shutdowns) =
        start_rules(&config, shutdown.clone(), built_in_registry(), pipeline);

    // Wait for the routing listener to come up.
    let mut client = None;
    for _ in 0..60 {
        if let Ok(s) = TcpStream::connect(&listen) {
            client = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut client = client.expect("gateway routing listener never came up");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Send a payload large enough to exercise the splice path and verify it
    // round-trips byte-for-byte through the plaintext passthrough.
    let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    client.write_all(&payload).expect("plain write");
    let _ = client.flush();

    let mut received = vec![0u8; payload.len()];
    client
        .read_exact(&mut received)
        .expect("read echoed reply");
    assert_eq!(
        received, payload,
        "payload should round-trip verbatim through routing passthrough"
    );

    drop(client);
    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}
