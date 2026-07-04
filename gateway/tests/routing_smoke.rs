//! Integration test for the routing-only (plaintext L4 passthrough) provider.
//!
//! Confirms that a `"security_provider": "routing"` rule forwards traffic to a
//! plain upstream verbatim, with no TLS on either leg — over TCP (byte stream)
//! and UDP (datagram). Runs fully unprivileged on loopback.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
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
    client.read_exact(&mut received).expect("read echoed reply");
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

#[test]
fn routing_udp_plaintext_datagram_round_trip() {
    let tmp = temp_dir("routing-udp-smoke");

    // Plaintext UDP echo backend: bounce each datagram back to its sender.
    let echo_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo_sock.local_addr().unwrap().to_string();
    echo_sock
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let echo_stop = Arc::new(AtomicBool::new(false));
    let echo_stop_t = echo_stop.clone();
    let echo_handle = std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        while !echo_stop_t.load(Ordering::Relaxed) {
            if let Ok((n, src)) = echo_sock.recv_from(&mut buf) {
                let _ = echo_sock.send_to(&buf[..n], src);
            }
        }
    });

    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    // Safety class so the default deny-all policy passes the per-datagram check.
    let json = format!(
        r#"{{
            "rules": [{{
                "name": "route-udp-1",
                "direction": "encrypt",
                "listen_addr": "{listen}",
                "listen_proto": "udp",
                "upstream_addr": "{echo_addr}",
                "upstream_proto": "udp",
                "security_provider": "routing",
                "traffic_class": "safety"
            }}]
        }}"#,
    );
    let cfg_path = tmp.join("gw.json");
    std::fs::write(&cfg_path, &json).unwrap();
    let config =
        GatewayConfig::load(cfg_path.to_str().unwrap()).expect("routing-udp config validates");

    let shutdown = Arc::new(AtomicBool::new(false));
    let pipeline = Arc::new(PipelineComponents {
        traffic_analyzer: None,
        policy_manager: Arc::new(RwLock::new(PolicyManager::new(None))),
    });
    let (handles, _rule_shutdowns) =
        start_rules(&config, shutdown.clone(), built_in_registry(), pipeline);

    // Drive one datagram: client → gateway (udp routing) → echo → back. Retry to
    // absorb listener-bind readiness (UDP has no connect handshake) — a datagram
    // sent before the gateway binds is simply lost.
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let payload: Vec<u8> = (0..1400).map(|i| (i % 251) as u8).collect();
    let mut received: Option<Vec<u8>> = None;
    for _ in 0..60 {
        let _ = client.send_to(&payload, &listen);
        let mut buf = vec![0u8; payload.len() + 16];
        match client.recv_from(&mut buf) {
            Ok((n, _)) => {
                received = Some(buf[..n].to_vec());
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let received = received.expect("gateway udp routing never echoed a datagram");
    assert_eq!(
        received, payload,
        "datagram should round-trip verbatim through udp routing"
    );

    drop(client);
    shutdown.store(true, Ordering::SeqCst);
    echo_stop.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = echo_handle.join();
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn routing_udp_multi_client_demux_no_cross_flow() {
    // Two distinct client sources through ONE routing_udp rule must each receive
    // their OWN echo back — the per-peer SocketAddr demux must not cross flows.
    let tmp = temp_dir("routing-udp-demux");

    // UDP echo that bounces each datagram back to its sender.
    let echo_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo_sock.local_addr().unwrap().to_string();
    echo_sock
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let echo_stop = Arc::new(AtomicBool::new(false));
    let echo_stop_t = echo_stop.clone();
    let echo_handle = std::thread::spawn(move || {
        let mut buf = vec![0u8; 4096];
        while !echo_stop_t.load(Ordering::Relaxed) {
            if let Ok((n, src)) = echo_sock.recv_from(&mut buf) {
                let _ = echo_sock.send_to(&buf[..n], src);
            }
        }
    });

    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let json = format!(
        r#"{{
            "rules": [{{
                "name": "route-udp-demux",
                "direction": "encrypt",
                "listen_addr": "{listen}",
                "listen_proto": "udp",
                "upstream_addr": "{echo_addr}",
                "upstream_proto": "udp",
                "security_provider": "routing",
                "traffic_class": "safety"
            }}]
        }}"#,
    );
    let cfg_path = tmp.join("gw.json");
    std::fs::write(&cfg_path, &json).unwrap();
    let config = GatewayConfig::load(cfg_path.to_str().unwrap()).expect("config validates");

    let shutdown = Arc::new(AtomicBool::new(false));
    let pipeline = Arc::new(PipelineComponents {
        traffic_analyzer: None,
        policy_manager: Arc::new(RwLock::new(PolicyManager::new(None))),
    });
    let (handles, _rule_shutdowns) =
        start_rules(&config, shutdown.clone(), built_in_registry(), pipeline);

    // Distinct payloads per source so a cross-flow leak would be detected.
    let client_a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client_b = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_a
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    client_b
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let payload_a = vec![0xAAu8; 512];
    let payload_b = vec![0xBBu8; 512];

    let recv_own = |sock: &UdpSocket, want: &[u8]| -> bool {
        let mut buf = vec![0u8; want.len() + 8];
        for _ in 0..40 {
            let _ = sock.send_to(want, &listen);
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                return &buf[..n] == want;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    };

    // Bring both sessions up (retry absorbs listener-bind readiness).
    assert!(
        recv_own(&client_a, &payload_a),
        "client A must receive its own datagram back"
    );
    assert!(
        recv_own(&client_b, &payload_b),
        "client B must receive its own datagram back"
    );

    // Interleave once more and assert each still gets ITS payload (not the other's).
    client_a.send_to(&payload_a, &listen).unwrap();
    client_b.send_to(&payload_b, &listen).unwrap();
    let mut buf = vec![0u8; 520];
    if let Ok((n, _)) = client_a.recv_from(&mut buf) {
        assert_eq!(
            &buf[..n],
            &payload_a[..],
            "client A must not receive B's flow"
        );
    }
    if let Ok((n, _)) = client_b.recv_from(&mut buf) {
        assert_eq!(
            &buf[..n],
            &payload_b[..],
            "client B must not receive A's flow"
        );
    }

    shutdown.store(true, Ordering::SeqCst);
    echo_stop.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = echo_handle.join();
    let _ = std::fs::remove_dir_all(&tmp);
}
