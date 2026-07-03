//! End-to-end loopback test for the dynamically-created local interfaces.
//!
//! Drives the real client library (`scg-client`) against an in-process gateway:
//! the management gRPC server creates a UDS or SHM endpoint on demand, the data
//! plane relays framed traffic through a TLS upstream, and a self-contained TLS
//! echo server reflects it. A successful round-trip proves the whole pipeline —
//! gRPC create, capability-token handshake, framing, ring/byte relay and TLS —
//! works together for both transports.
//!
//! The test runs unprivileged (temp runtime dir, no chown/root paths).

mod common;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{build_config, build_config_provider, current_uid, wait_for_socket, EchoServer};

use gateway::api::grpc::start_management_server;
use gateway::interfaces::manager::InterfaceManager;
use gateway::management::config::GatewayConfig;
use scg_client::{Direction, ScgClient, TrafficClass, Transport};

#[test]
fn uds_and_shm_round_trip_through_gateway() {
    let uid = current_uid();
    let tmp = common::temp_dir("e2e");
    let echo = EchoServer::start();
    let config = build_config(&echo.addr, uid, &tmp);
    round_trip_through_gateway(config, &tmp);
    let _ = echo;
}

/// kTLS upstream: exercises the zero-copy `splice(2)` fast-path in `relay_uds_tls`
/// when kTLS activates (ULP=tls), and the userspace SSL fallback (TRA #56) when it
/// does not. Either way the framed round-trip must succeed verbatim — proving the
/// splice delegation carries the `[len][traffic_id][data]` stream transparently
/// and never corrupts or drops frames.
#[test]
fn uds_and_shm_round_trip_ktls_upstream() {
    let uid = current_uid();
    let tmp = common::temp_dir("e2e-ktls");
    let echo = EchoServer::start_tls13();
    let config = build_config_provider(&echo.addr, uid, &tmp, "ktls");
    round_trip_through_gateway(config, &tmp);
    let _ = echo;
}

/// Drive one UDS and one SHM framed round-trip through an in-process gateway
/// built from `config`, then tear everything down. Shared by the userspace-TLS
/// and kTLS-upstream variants.
fn round_trip_through_gateway(config: GatewayConfig, tmp: &std::path::Path) {
    let api = config.api.clone().expect("api config present");

    let shutdown = Arc::new(AtomicBool::new(false));
    let manager = InterfaceManager::new(&config, "itest-1.0", shutdown.clone(), None);
    let mgmt_handle = start_management_server(manager.clone(), api.clone(), shutdown.clone())
        .expect("start management server");

    let mgmt_path = std::path::PathBuf::from(&api.uds_path);
    assert!(
        wait_for_socket(&mgmt_path, Duration::from_secs(5)),
        "management socket never became connectable"
    );

    // ── UDS transport ───────────────────────────────────────────────────────
    {
        let mut client = ScgClient::connect(
            Some(&mgmt_path),
            "app-test",
            Transport::Uds,
            TrafficClass::Safety,
            Direction::Encrypt,
        )
        .expect("UDS client connect");

        client.send(7, b"hello-over-uds").expect("UDS send");
        let msg = client
            .recv_timeout(Some(Duration::from_secs(5)))
            .expect("UDS recv")
            .expect("UDS round-trip timed out");
        assert_eq!(msg.0, 7, "UDS traffic id should be preserved");
        assert_eq!(
            &msg.1, b"hello-over-uds",
            "UDS payload should echo verbatim"
        );

        client.close().expect("UDS close");
    }

    // ── SHM transport ───────────────────────────────────────────────────────
    {
        let mut client = ScgClient::connect(
            Some(&mgmt_path),
            "app-test",
            Transport::Shm,
            TrafficClass::Safety,
            Direction::Encrypt,
        )
        .expect("SHM client connect");

        client.send(9, b"hello-over-shm-rings").expect("SHM send");
        let msg = client
            .recv_timeout(Some(Duration::from_secs(5)))
            .expect("SHM recv")
            .expect("SHM round-trip timed out");
        assert_eq!(msg.0, 9, "SHM traffic id should be preserved");
        assert_eq!(
            &msg.1, b"hello-over-shm-rings",
            "SHM payload should echo verbatim"
        );

        client.close().expect("SHM close");
    }

    // ── Teardown ────────────────────────────────────────────────────────────
    shutdown.store(true, Ordering::SeqCst);
    manager.shutdown_all();
    let _ = mgmt_handle.join();
    let _ = std::fs::remove_dir_all(tmp);
}

/// Stress the gateway→client SHM ring with a burst of frames, exercising the
/// batched `signal_g2c` (one wakeup per drained TLS read instead of one per
/// frame). A lost or coalesced-away wakeup would stall the client and surface as
/// a `recv` timeout below, so a clean N-in/N-out round-trip proves the batched
/// signalling wakes the consumer for every batch.
#[test]
fn shm_burst_round_trip_batched_signal() {
    const BURST: u32 = 256;

    let uid = current_uid();
    let tmp = common::temp_dir("e2e-shm-burst");
    let echo = EchoServer::start();
    let config = build_config(&echo.addr, uid, &tmp);
    let api = config.api.clone().expect("api config present");

    let shutdown = Arc::new(AtomicBool::new(false));
    let manager = InterfaceManager::new(&config, "itest-1.0", shutdown.clone(), None);
    let mgmt_handle = start_management_server(manager.clone(), api.clone(), shutdown.clone())
        .expect("start management server");

    let mgmt_path = std::path::PathBuf::from(&api.uds_path);
    assert!(
        wait_for_socket(&mgmt_path, Duration::from_secs(5)),
        "management socket never became connectable"
    );

    {
        let mut client = ScgClient::connect(
            Some(&mgmt_path),
            "app-test",
            Transport::Shm,
            TrafficClass::Safety,
            Direction::Encrypt,
        )
        .expect("SHM client connect");

        for i in 0..BURST {
            let payload = format!("shm-burst-frame-{i}");
            client.send(i, payload.as_bytes()).expect("SHM burst send");
        }
        for i in 0..BURST {
            let msg = client
                .recv_timeout(Some(Duration::from_secs(10)))
                .expect("SHM burst recv")
                .unwrap_or_else(|| panic!("SHM burst frame {i} timed out (lost wakeup?)"));
            assert_eq!(msg.0, i, "SHM burst frames must arrive in order");
            assert_eq!(
                msg.1,
                format!("shm-burst-frame-{i}").into_bytes(),
                "SHM burst payload {i} should echo verbatim"
            );
        }

        client.close().expect("SHM close");
    }

    shutdown.store(true, Ordering::SeqCst);
    manager.shutdown_all();
    let _ = mgmt_handle.join();
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = echo;
}

/// Build a gateway config that bridges a SHM **encrypt** endpoint to a SHM
/// **decrypt** endpoint over a loopback TCP, both in `routing` (plaintext) mode —
/// exactly the topology SESHAT's SHM throughput scenarios use. A client on the
/// encrypt endpoint floods `c2g`; the gateway relays it over `127.0.0.1:<port>`
/// to the decrypt endpoint, whose `g2c` ring a second client drains.
fn build_routing_shm_bridge(
    uid: u32,
    tmp: &std::path::Path,
    port: u16,
    ring_cap: usize,
) -> GatewayConfig {
    let mgmt_sock = tmp.join("mgmt.sock");
    let runtime_dir = tmp.join("run");
    let json = format!(
        r#"{{
            "rules": [
                {{
                    "name": "shm-flood-decrypt",
                    "direction": "decrypt",
                    "listen_addr": "unused",
                    "listen_proto": "shm",
                    "upstream_addr": "127.0.0.1:{port}",
                    "upstream_proto": "tcp",
                    "security_provider": "routing",
                    "verify": "none",
                    "traffic_class": "safety",
                    "app_id": "flood",
                    "allowed_uids": [{uid}]
                }},
                {{
                    "name": "shm-flood-encrypt",
                    "direction": "encrypt",
                    "listen_addr": "unused",
                    "listen_proto": "shm",
                    "upstream_addr": "127.0.0.1:{port}",
                    "upstream_proto": "tcp",
                    "security_provider": "routing",
                    "verify": "none",
                    "traffic_class": "safety",
                    "app_id": "flood",
                    "allowed_uids": [{uid}]
                }}
            ],
            "api": {{
                "enabled": true,
                "uds_path": "{mgmt}",
                "runtime_dir": "{run}",
                "shm_ring_capacity": {ring_cap}
            }}
        }}"#,
        port = port,
        uid = uid,
        mgmt = mgmt_sock.display(),
        run = runtime_dir.display(),
        ring_cap = ring_cap,
    );
    serde_json::from_str(&json).expect("parse routing-SHM-bridge config")
}

/// End-to-end smoke for the `routing` SHM bridge under a sustained flood: a
/// client floods the encrypt endpoint's `c2g` ring while a second client drains
/// the decrypt endpoint's `g2c` ring, with the gateway relaying plaintext over a
/// loopback TCP between them — the exact topology of SESHAT's `routing-only` SHM
/// throughput scenarios.
///
/// It samples how many frames the receiver drained *during* the flood (before any
/// post-flood settle): a healthy pipeline delivers many thousands. (The
/// deterministic guard for the underlying `coalesce_c2g_into` drain bound is the
/// `coalesce_c2g_is_bounded_per_call` unit test; this exercises the full path.)
#[test]
fn shm_routing_flood_delivers_under_load() {
    const MSG: usize = 4096; // the message size that livelocked under SESHAT affinity
    const FLOOD: Duration = Duration::from_secs(1);
    const MIN_DELIVERED: u64 = 1000;

    let uid = current_uid();
    let tmp = common::temp_dir("e2e-shm-flood");
    let port = common::free_port();
    let config = build_routing_shm_bridge(uid, &tmp, port, 1024 * 1024);
    let api = config.api.clone().expect("api config present");

    let shutdown = Arc::new(AtomicBool::new(false));
    let manager = InterfaceManager::new(&config, "itest-1.0", shutdown.clone(), None);
    let mgmt_handle = start_management_server(manager.clone(), api.clone(), shutdown.clone())
        .expect("start management server");

    let mgmt_path = std::path::PathBuf::from(&api.uds_path);
    assert!(
        wait_for_socket(&mgmt_path, Duration::from_secs(5)),
        "management socket never became connectable"
    );

    // Receiver (decrypt endpoint) first, so the decrypt relay is accepting on the
    // bridge port before the encrypt relay dials it.
    let mut rx = ScgClient::connect(
        Some(&mgmt_path),
        "flood",
        Transport::Shm,
        TrafficClass::Safety,
        Direction::Decrypt,
    )
    .expect("SHM rx connect");
    let mut tx = ScgClient::connect(
        Some(&mgmt_path),
        "flood",
        Transport::Shm,
        TrafficClass::Safety,
        Direction::Encrypt,
    )
    .expect("SHM tx connect");

    let received = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let received_rx = received.clone();
    let stop_rx = stop.clone();
    let recv_handle = std::thread::spawn(move || {
        let mut buf = vec![0u8; MSG];
        while !stop_rx.load(Ordering::Relaxed) {
            match rx.recv_into(&mut buf, Some(Duration::from_millis(50))) {
                Ok(Some((_id, len))) => {
                    assert_eq!(len, MSG, "payload length must be preserved");
                    received_rx.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
    });

    // Flood the encrypt ring as fast as it accepts, for FLOOD seconds.
    let payload = vec![0xABu8; MSG];
    let deadline = Instant::now() + FLOOD;
    let mut id = 0u32;
    while Instant::now() < deadline {
        if tx.try_send(id, &payload).expect("SHM send") {
            id = id.wrapping_add(1);
        } else {
            std::hint::spin_loop();
        }
    }
    // Sample delivery *during* the flood (a post-flood drain would mask a livelock
    // that only resolves once the producer stops).
    let delivered_during_flood = received.load(Ordering::Relaxed);

    stop.store(true, Ordering::Relaxed);
    let _ = recv_handle.join();
    let _ = tx.close();

    shutdown.store(true, Ordering::SeqCst);
    manager.shutdown_all();
    let _ = mgmt_handle.join();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        delivered_during_flood >= MIN_DELIVERED,
        "SHM relay delivered only {delivered_during_flood} frames during a {}s flood \
         (expected >= {MIN_DELIVERED}); the c2g drain livelocked",
        FLOOD.as_secs()
    );
}
