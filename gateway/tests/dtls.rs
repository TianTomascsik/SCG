//! WP7 — DTLS engine hardening (`security_provider = dtls`).
//!
//! WP1 wired DTLS as a UDP-native crypto provider; WP7 brings its security
//! parameters to parity with the userspace TLS engine: peer **verify** modes,
//! CA pinning, file-based identities, SNI, and per-version cipher policy
//! (DTLS 1.0 CBC, DTLS 1.2 AEAD).
//!
//! Encrypt-direction tests put the gateway in the DTLS **client** role against
//! a [`DtlsEchoServer`] (exercises `build_dtls_connector`); decrypt-direction
//! tests put the gateway in the DTLS **server** role driven by a raw DTLS
//! client over a [`PlainUdpEchoServer`] backend (exercises
//! `build_dtls_acceptor`).
//!
//! All tests run unprivileged on loopback.

mod common;

use std::io;
use std::net::UdpSocket;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::dtls::{dtls_client_round_trip, DtlsEchoServer, PlainUdpEchoServer};
use common::pki::TestPki;
use common::{free_port, load_single_rule, run_rules, temp_dir};

/// Send one plaintext datagram to a gateway encrypt rule and read the echo.
///
/// Plain UDP has no retransmission, so the very first datagram can be lost
/// while the gateway is still binding its listen socket (surfacing as a
/// timeout or an ICMP `ConnectionRefused`). Resend a bounded number of times
/// so positive cases are not flaky; genuine handshake failures still exhaust
/// the attempts and return `Err`.
fn udp_round_trip(gateway: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    sock.connect(gateway)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;

    let mut last = io::Error::new(io::ErrorKind::TimedOut, "no reply");
    for _ in 0..8 {
        if let Err(e) = sock.send(payload) {
            last = e;
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        let mut buf = vec![0u8; payload.len().max(64)];
        match sock.recv(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(e) => {
                last = e;
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    Err(last)
}

/// Build a DTLS rule. `extra` carries optional security fields, e.g.
/// `,"verify":"server","ca_path":"/.../ca.pem"`.
fn dtls_rule(
    name: &str,
    direction: &str,
    listen: &str,
    upstream: &str,
    version: &str,
    extra: &str,
) -> String {
    format!(
        r#"{{
            "name": "{name}",
            "direction": "{direction}",
            "listen_addr": "{listen}",
            "listen_proto": "udp",
            "upstream_addr": "{upstream}",
            "upstream_proto": "udp",
            "security_provider": "dtls",
            "traffic_class": "safety",
            "protocol_version": "{version}"{extra}
        }}"#
    )
}

fn run<F: FnOnce()>(config: &gateway::management::config::GatewayConfig, body: F) {
    let (handles, shutdown) = run_rules(config);
    body();
    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
}

// =============================================================================
//  Encrypt direction — gateway is the DTLS client (build_dtls_connector)
// =============================================================================

#[test]
fn dtls12_round_trip() {
    let tmp = temp_dir("dtls12-ok");
    let pki = TestPki::generate(&tmp);
    let echo = DtlsEchoServer::start("dtls1.2", &pki.server_cert, &pki.server_key, None);
    let listen = format!("127.0.0.1:{}", free_port());
    let config = load_single_rule(
        &tmp,
        &dtls_rule("dtls12", "encrypt", &listen, &echo.addr, "dtls1.2", ""),
    );

    run(&config, || {
        let echoed = udp_round_trip(&listen, b"dtls12-payload")
            .expect("DTLS 1.2 datagram should round-trip");
        assert_eq!(echoed, b"dtls12-payload");
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dtls10_round_trip() {
    let tmp = temp_dir("dtls10-ok");
    let pki = TestPki::generate(&tmp);
    let echo = DtlsEchoServer::start("dtls1.0", &pki.server_cert, &pki.server_key, None);
    let listen = format!("127.0.0.1:{}", free_port());
    let config = load_single_rule(
        &tmp,
        &dtls_rule("dtls10", "encrypt", &listen, &echo.addr, "dtls1.0", ""),
    );

    run(&config, || {
        let echoed = udp_round_trip(&listen, b"dtls10-payload")
            .expect("DTLS 1.0 datagram should round-trip");
        assert_eq!(echoed, b"dtls10-payload");
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dtls_server_verify_round_trip() {
    let tmp = temp_dir("dtls-verify-ok");
    let pki = TestPki::generate(&tmp);
    let echo = DtlsEchoServer::start("dtls1.2", &pki.server_cert, &pki.server_key, None);
    let listen = format!("127.0.0.1:{}", free_port());
    let extra = format!(
        r#","verify":"server","ca_path":"{}","server_name":"localhost""#,
        pki.ca_cert.display()
    );
    let config = load_single_rule(
        &tmp,
        &dtls_rule("dtls-verify", "encrypt", &listen, &echo.addr, "dtls1.2", &extra),
    );

    run(&config, || {
        let echoed = udp_round_trip(&listen, b"dtls-verified")
            .expect("server-verified DTLS should round-trip against a trusted CA");
        assert_eq!(echoed, b"dtls-verified");
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dtls_server_verify_wrong_ca_fails() {
    let tmp = temp_dir("dtls-verify-bad");
    let pki = TestPki::generate(&tmp);
    let other = temp_dir("dtls-verify-bad-ca");
    let other_pki = TestPki::generate(&other);
    let echo = DtlsEchoServer::start("dtls1.2", &pki.server_cert, &pki.server_key, None);
    let listen = format!("127.0.0.1:{}", free_port());
    // Pin a CA that did NOT sign the echo server's certificate.
    let extra = format!(
        r#","verify":"server","ca_path":"{}","server_name":"localhost""#,
        other_pki.ca_cert.display()
    );
    let config = load_single_rule(
        &tmp,
        &dtls_rule("dtls-verify-bad", "encrypt", &listen, &echo.addr, "dtls1.2", &extra),
    );

    run(&config, || {
        assert!(
            udp_round_trip(&listen, b"should-not-arrive").is_err(),
            "DTLS handshake must fail against an untrusted CA",
        );
    });
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(&other);
}

#[test]
fn dtls_mutual_round_trip() {
    let tmp = temp_dir("dtls-mutual-ok");
    let pki = TestPki::generate(&tmp);
    // Echo server requires a client cert chaining to our CA.
    let echo = DtlsEchoServer::start(
        "dtls1.2",
        &pki.server_cert,
        &pki.server_key,
        Some(&pki.ca_cert),
    );
    let listen = format!("127.0.0.1:{}", free_port());
    let extra = format!(
        r#","verify":"mutual","ca_path":"{}","cert_path":"{}","key_path":"{}","server_name":"localhost""#,
        pki.ca_cert.display(),
        pki.client_cert.display(),
        pki.client_key.display()
    );
    let config = load_single_rule(
        &tmp,
        &dtls_rule("dtls-mutual", "encrypt", &listen, &echo.addr, "dtls1.2", &extra),
    );

    run(&config, || {
        let echoed = udp_round_trip(&listen, b"dtls-mutual")
            .expect("mutual DTLS should round-trip when the gateway presents a client cert");
        assert_eq!(echoed, b"dtls-mutual");
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dtls_mutual_missing_client_cert_fails() {
    let tmp = temp_dir("dtls-mutual-bad");
    let pki = TestPki::generate(&tmp);
    // Echo server still demands a client cert.
    let echo = DtlsEchoServer::start(
        "dtls1.2",
        &pki.server_cert,
        &pki.server_key,
        Some(&pki.ca_cert),
    );
    let listen = format!("127.0.0.1:{}", free_port());
    // Gateway only does server verification — presents no client cert.
    let extra = format!(
        r#","verify":"server","ca_path":"{}","server_name":"localhost""#,
        pki.ca_cert.display()
    );
    let config = load_single_rule(
        &tmp,
        &dtls_rule("dtls-mutual-bad", "encrypt", &listen, &echo.addr, "dtls1.2", &extra),
    );

    run(&config, || {
        assert!(
            udp_round_trip(&listen, b"no-client-cert").is_err(),
            "mutual-auth upstream must refuse a gateway that presents no client cert",
        );
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

// =============================================================================
//  Decrypt direction — gateway is the DTLS server (build_dtls_acceptor)
// =============================================================================

#[test]
fn dtls_decrypt_round_trip() {
    let tmp = temp_dir("dtls-dec-ok");
    let pki = TestPki::generate(&tmp);
    let backend = PlainUdpEchoServer::start();
    let listen = format!("127.0.0.1:{}", free_port());
    let extra = format!(
        r#","cert_path":"{}","key_path":"{}""#,
        pki.server_cert.display(),
        pki.server_key.display()
    );
    let config = load_single_rule(
        &tmp,
        &dtls_rule("dtls-dec", "decrypt", &listen, &backend.addr, "dtls1.2", &extra),
    );

    run(&config, || {
        let echoed = dtls_client_round_trip(&listen, "dtls1.2", None, b"dtls-decrypt")
            .expect("DTLS termination should forward to the plain UDP backend and echo back");
        assert_eq!(echoed, b"dtls-decrypt");
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dtls_decrypt_mutual_round_trip() {
    let tmp = temp_dir("dtls-dec-mutual-ok");
    let pki = TestPki::generate(&tmp);
    let backend = PlainUdpEchoServer::start();
    let listen = format!("127.0.0.1:{}", free_port());
    let extra = format!(
        r#","verify":"mutual","ca_path":"{}","cert_path":"{}","key_path":"{}""#,
        pki.ca_cert.display(),
        pki.server_cert.display(),
        pki.server_key.display()
    );
    let config = load_single_rule(
        &tmp,
        &dtls_rule("dtls-dec-mutual", "decrypt", &listen, &backend.addr, "dtls1.2", &extra),
    );

    run(&config, || {
        let echoed = dtls_client_round_trip(
            &listen,
            "dtls1.2",
            Some((&pki.client_cert, &pki.client_key)),
            b"dtls-dec-mutual",
        )
        .expect("mutual DTLS termination should round-trip with a valid client cert");
        assert_eq!(echoed, b"dtls-dec-mutual");
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dtls_decrypt_mutual_missing_client_cert_fails() {
    let tmp = temp_dir("dtls-dec-mutual-bad");
    let pki = TestPki::generate(&tmp);
    let backend = PlainUdpEchoServer::start();
    let listen = format!("127.0.0.1:{}", free_port());
    let extra = format!(
        r#","verify":"mutual","ca_path":"{}","cert_path":"{}","key_path":"{}""#,
        pki.ca_cert.display(),
        pki.server_cert.display(),
        pki.server_key.display()
    );
    let config = load_single_rule(
        &tmp,
        &dtls_rule("dtls-dec-mutual-bad", "decrypt", &listen, &backend.addr, "dtls1.2", &extra),
    );

    run(&config, || {
        assert!(
            dtls_client_round_trip(&listen, "dtls1.2", None, b"no-cert").is_err(),
            "mutual DTLS server must refuse a client that presents no certificate",
        );
    });
    let _ = std::fs::remove_dir_all(&tmp);
}
