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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
    let manager = InterfaceManager::new(&config, "itest-1.0", shutdown.clone());
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
    let manager = InterfaceManager::new(&config, "itest-1.0", shutdown.clone());
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
