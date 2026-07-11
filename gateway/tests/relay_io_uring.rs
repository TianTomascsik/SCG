//! Regression test for the experimental io_uring splice relay backend.
//!
//! Compiled only under `--features io_uring`. It forces the backend on via the
//! `SCG_RELAY_IO_URING` env var and drives a large payload through a plaintext
//! routing rule (which always takes the splice path), asserting it round-trips
//! byte-for-byte. This is its own test binary, so the process-global env var
//! cannot leak into other tests.

#![cfg(feature = "io_uring")]

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
fn io_uring_routing_passthrough_round_trip() {
    // Force the io_uring backend on for this process (read by the relay dispatcher).
    std::env::set_var("SCG_RELAY_IO_URING", "1");
    assert!(
        gateway::security::relay_uring::io_uring_relay_enabled(),
        "io_uring backend must be enabled for this test"
    );

    let tmp = temp_dir("routing-io-uring");
    let echo = PlainEchoServer::start();
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");

    let json = format!(
        r#"{{
            "rules": [{{
                "name": "route-uring",
                "direction": "encrypt",
                "listen_addr": "{listen}",
                "listen_proto": "tcp",
                "upstream_addr": "{echo}",
                "upstream_proto": "tcp",
                "security_provider": "routing",
                "traffic_class": "safety"
            }}]
        }}"#,
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

    // 256 KiB exercises many SpliceIn/SpliceOut iterations of the io_uring loop.
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let writer = {
        let mut w = client.try_clone().expect("clone client");
        let p = payload.clone();
        std::thread::spawn(move || {
            let _ = w.write_all(&p);
            let _ = w.flush();
        })
    };

    let mut received = vec![0u8; payload.len()];
    client
        .read_exact(&mut received)
        .expect("read echoed reply through io_uring splice relay");
    assert_eq!(
        received, payload,
        "payload must round-trip verbatim through the io_uring splice relay"
    );

    let _ = writer.join();
    drop(client);
    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}
