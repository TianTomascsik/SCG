//! Security negatives for the dynamically-created local interfaces.
//!
//! These exercise the data-plane capability-token handshake directly with raw
//! Unix sockets, asserting the gateway rejects a forged token and a malformed
//! HELLO before any traffic is relayed. Authentication fails ahead of the
//! upstream connect, so no echo server is needed.
//!
//! The uid/pid `SO_PEERCRED` checks are covered by the manager unit tests
//! (`create_uds_wrong_uid_is_denied`, `create_shm_wrong_uid_is_denied`); they
//! cannot be exercised here without root to spoof peer credentials, so they are
//! intentionally not repeated. The read-only g2c ring sealing is verified in
//! the `scg-ipc` crate (writing a sealed mapping would fault this process).

mod common;

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use common::{build_config, current_uid, temp_dir, wait_for_socket};

use gateway::interfaces::manager::{CallerCred, InterfaceManager, UdsCreated};
use gateway::management::config::{Direction, TrafficClass};

use scg_ipc::{CapabilityToken, Hello, Role};

/// Create an in-process manager (UDS + SHM rules) and a UDS endpoint authorised
/// for the current uid. Returns everything the caller must keep alive plus the
/// bound socket path and the issued (valid) token.
fn fresh_uds_endpoint(tag: &str) -> (Arc<InterfaceManager>, std::path::PathBuf, UdsCreated) {
    let uid = current_uid();
    let tmp = temp_dir(tag);
    // The upstream is unreachable on purpose; auth must fail before relaying.
    let config = build_config("127.0.0.1:1", uid, &tmp);
    let shutdown = Arc::new(AtomicBool::new(false));
    let manager = InterfaceManager::new(&config, "itest-sec", shutdown);
    let caller = CallerCred {
        uid,
        gid: uid,
        pid: std::process::id() as i32,
    };
    let created = manager
        .create_uds(
            caller,
            "app-test",
            TrafficClass::Safety,
            Direction::Encrypt,
            0,
        )
        .expect("create_uds for an authorised uid");
    let path = std::path::PathBuf::from(&created.socket_path);
    assert!(
        wait_for_socket(&path, Duration::from_secs(5)),
        "UDS endpoint never started listening"
    );
    (manager, tmp, created)
}

/// Assert the gateway closed (EOF) or reset the connection promptly and never
/// relayed application bytes.
fn assert_rejected(stream: &mut UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(0) => {} // clean EOF — connection closed by the gateway
        Ok(n) => panic!("gateway relayed {n} bytes after a rejected handshake"),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {} // reset — rejected
        Err(e) => panic!(
            "expected EOF/reset after rejection, got error: {e} ({:?})",
            e.kind()
        ),
    }
}

#[test]
fn forged_token_is_rejected() {
    let (manager, tmp, created) = fresh_uds_endpoint("sec-forged");

    let mut stream = UnixStream::connect(&created.socket_path).expect("connect to endpoint");
    // A well-formed HELLO carrying a token that does not match the issued one.
    let forged = CapabilityToken::from_bytes([0xAA; 32]);
    let hello = Hello::new(Role::Producer, forged).encode();
    stream.write_all(&hello).expect("write forged HELLO");
    let _ = stream.flush();

    assert_rejected(&mut stream);

    manager.shutdown_all();
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn malformed_hello_is_rejected() {
    let (manager, tmp, created) = fresh_uds_endpoint("sec-malformed");

    let mut stream = UnixStream::connect(&created.socket_path).expect("connect to endpoint");
    // Fewer bytes than a HELLO, then half-close so the gateway's fixed-size
    // read hits EOF and the handshake fails.
    stream.write_all(&[0u8; 8]).expect("write short HELLO");
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);

    assert_rejected(&mut stream);

    manager.shutdown_all();
    let _ = std::fs::remove_dir_all(&tmp);
}
