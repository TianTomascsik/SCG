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

use common::{build_config, current_uid, wait_for_socket, EchoServer};

use gateway::api::grpc::start_management_server;
use gateway::interfaces::manager::InterfaceManager;
use scg_client::{Direction, ScgClient, TrafficClass, Transport};

#[test]
fn uds_and_shm_round_trip_through_gateway() {
    let uid = current_uid();
    let tmp = common::temp_dir("e2e");
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
    let _ = std::fs::remove_dir_all(&tmp);
}
