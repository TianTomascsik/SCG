//! WP2 — TLS verification modes and HTTPS (L4) termination.
//!
//! Exercises the verify/identity wiring added in WP1 end-to-end against a real
//! CA-issued certificate chain (see [`common::pki::TestPki`]):
//!
//! * `server_verify_round_trip` — gateway verifies a trusted upstream.
//! * `server_verify_wrong_ca_fails` — gateway rejects an untrusted upstream.
//! * `mutual_tls_round_trip` — gateway presents a client cert (mTLS).
//! * `mutual_tls_missing_client_cert_fails` — upstream rejects a gateway with no
//!   client cert.
//! * `https_frontend_terminate_to_plain_backend` — a raw TLS client speaks HTTPS
//!   to the gateway, which decrypts and relays plaintext to a plain backend (TLS
//!   termination).
//!
//! All tests run unprivileged on loopback.

mod common;

use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::pki::TestPki;
use common::{
    connect_tcp_with_retry, free_port, load_single_rule, plain_round_trip, run_rules, temp_dir,
    EchoServer, PlainEchoServer,
};

use gateway::security::tls_engine::params::{TlsSecurityParams, VerifyMode};

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

#[test]
fn server_verify_round_trip() {
    let tmp = temp_dir("tls-verify-server");
    let pki = TestPki::generate(&tmp);

    // Upstream presents a CA-issued server cert; it does not verify the client.
    let echo = EchoServer::start_with_params(TlsSecurityParams {
        cert_path: Some(pki.server_cert.clone()),
        key_path: Some(pki.server_key.clone()),
        ..Default::default()
    });

    let listen = format!("127.0.0.1:{}", free_port());
    let rule = format!(
        r#"{{
            "name": "verify-server",
            "direction": "encrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{echo}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "verify": "server",
            "server_name": "localhost",
            "ca_path": "{ca}"
        }}"#,
        listen = listen,
        echo = echo.addr,
        ca = pki.ca_cert.display(),
    );
    let config = load_single_rule(&tmp, &rule);
    let (handles, shutdown) = run_rules(&config);

    let echoed = plain_round_trip(&listen, b"verify-server-payload")
        .expect("round-trip should succeed when the upstream cert chains to the trusted CA");
    assert_eq!(echoed, b"verify-server-payload");

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn server_verify_wrong_ca_fails() {
    let tmp = temp_dir("tls-verify-wrongca");
    let pki = TestPki::generate(&tmp);

    // A second, unrelated CA we will (wrongly) configure the gateway to trust.
    let other_dir = temp_dir("tls-verify-otherca");
    let other = TestPki::generate(&other_dir);

    let echo = EchoServer::start_with_params(TlsSecurityParams {
        cert_path: Some(pki.server_cert.clone()),
        key_path: Some(pki.server_key.clone()),
        ..Default::default()
    });

    let listen = format!("127.0.0.1:{}", free_port());
    let rule = format!(
        r#"{{
            "name": "verify-wrong-ca",
            "direction": "encrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{echo}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "verify": "server",
            "server_name": "localhost",
            "ca_path": "{ca}"
        }}"#,
        listen = listen,
        echo = echo.addr,
        ca = other.ca_cert.display(),
    );
    let config = load_single_rule(&tmp, &rule);
    let (handles, shutdown) = run_rules(&config);

    let result = plain_round_trip(&listen, b"should-not-pass");
    assert!(
        result.is_err(),
        "handshake must fail when the upstream cert does not chain to the configured CA"
    );

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(&other_dir);
}

#[test]
fn mutual_tls_round_trip() {
    let tmp = temp_dir("tls-mutual-ok");
    let pki = TestPki::generate(&tmp);

    // Upstream requires + verifies a client cert chaining to the CA.
    let echo = EchoServer::start_with_params(TlsSecurityParams {
        verify: VerifyMode::Mutual,
        cert_path: Some(pki.server_cert.clone()),
        key_path: Some(pki.server_key.clone()),
        ca_path: Some(pki.ca_cert.clone()),
        ..Default::default()
    });

    let listen = format!("127.0.0.1:{}", free_port());
    let rule = format!(
        r#"{{
            "name": "mutual-ok",
            "direction": "encrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{echo}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "verify": "mutual",
            "server_name": "localhost",
            "cert_path": "{cert}",
            "key_path": "{key}",
            "ca_path": "{ca}"
        }}"#,
        listen = listen,
        echo = echo.addr,
        cert = pki.client_cert.display(),
        key = pki.client_key.display(),
        ca = pki.ca_cert.display(),
    );
    let config = load_single_rule(&tmp, &rule);
    let (handles, shutdown) = run_rules(&config);

    let echoed = plain_round_trip(&listen, b"mutual-tls-payload")
        .expect("mutual handshake should succeed with a valid client cert");
    assert_eq!(echoed, b"mutual-tls-payload");

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn mutual_tls_missing_client_cert_fails() {
    let tmp = temp_dir("tls-mutual-missing");
    let pki = TestPki::generate(&tmp);

    // Upstream *requires* a client cert.
    let echo = EchoServer::start_with_params(TlsSecurityParams {
        verify: VerifyMode::Mutual,
        cert_path: Some(pki.server_cert.clone()),
        key_path: Some(pki.server_key.clone()),
        ca_path: Some(pki.ca_cert.clone()),
        ..Default::default()
    });

    let listen = format!("127.0.0.1:{}", free_port());
    // Gateway verifies the server but presents NO client cert (verify = server).
    let rule = format!(
        r#"{{
            "name": "mutual-missing",
            "direction": "encrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{echo}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "verify": "server",
            "server_name": "localhost",
            "ca_path": "{ca}"
        }}"#,
        listen = listen,
        echo = echo.addr,
        ca = pki.ca_cert.display(),
    );
    let config = load_single_rule(&tmp, &rule);
    let (handles, shutdown) = run_rules(&config);

    let result = plain_round_trip(&listen, b"no-client-cert");
    assert!(
        result.is_err(),
        "an upstream requiring mutual auth must reject a gateway presenting no client cert"
    );

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn https_frontend_terminate_to_plain_backend() {
    let tmp = temp_dir("https-frontend");
    let pki = TestPki::generate(&tmp);

    // Plain (non-TLS) backend behind the gateway.
    let backend = PlainEchoServer::start();

    let listen = format!("127.0.0.1:{}", free_port());
    // Decrypt rule: gateway terminates TLS on the listen side and relays
    // plaintext to the plain backend (HTTPS frontend → HTTP backend, L4).
    let rule = format!(
        r#"{{
            "name": "https-frontend",
            "direction": "decrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{backend}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "verify": "none",
            "cert_path": "{cert}",
            "key_path": "{key}"
        }}"#,
        listen = listen,
        backend = backend.addr,
        cert = pki.server_cert.display(),
        key = pki.server_key.display(),
    );
    let config = load_single_rule(&tmp, &rule);
    let (handles, shutdown) = run_rules(&config);

    // Raw TLS client: speak HTTPS to the gateway frontend.
    let tcp = connect_tcp_with_retry(&listen, 60).expect("decrypt listener never came up");
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let mut tls = connector
        .configure()
        .unwrap()
        .verify_hostname(false)
        .use_server_name_indication(true)
        .connect("localhost", tcp)
        .expect("TLS handshake with the gateway frontend should succeed");

    let payload = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    tls.write_all(payload).unwrap();
    tls.flush().unwrap();
    let mut buf = vec![0u8; payload.len()];
    tls.read_exact(&mut buf)
        .expect("the plain backend echo should come back through the TLS frontend");
    assert_eq!(
        &buf[..],
        &payload[..],
        "bytes should round-trip: HTTPS client → gateway (TLS terminate) → plain backend"
    );

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn kex_group_pin_is_enforced_on_handshake() {
    // A `groups` override pins the gateway's ECDHE key-exchange group. Prove it is actually
    // applied to the acceptor (TRA #84 apply path): a client offering the pinned group (P-256)
    // completes the handshake, while a client offering only a DIFFERENT strong group (X25519)
    // is refused — there is no shared group, so the pin cannot be silently ignored.
    let tmp = temp_dir("kex-group-pin");
    let pki = TestPki::generate(&tmp);
    let backend = PlainEchoServer::start();
    let listen = format!("127.0.0.1:{}", free_port());
    let rule = format!(
        r#"{{
            "name": "kex-pin",
            "direction": "decrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{backend}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "verify": "none",
            "cert_path": "{cert}",
            "key_path": "{key}",
            "groups": "P-256"
        }}"#,
        listen = listen,
        backend = backend.addr,
        cert = pki.server_cert.display(),
        key = pki.server_key.display(),
    );
    let config = load_single_rule(&tmp, &rule);
    let (handles, shutdown) = run_rules(&config);

    let client = |group: &str| {
        let tcp = connect_tcp_with_retry(&listen, 60).expect("listener never came up");
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        builder.set_groups_list(group).unwrap();
        builder
            .build()
            .configure()
            .unwrap()
            .verify_hostname(false)
            .use_server_name_indication(true)
            .connect("localhost", tcp)
    };

    // Matching group → handshake succeeds and bytes round-trip.
    let mut tls = client("P-256").expect("P-256 client must handshake with a P-256-pinned gateway");
    let payload = b"ping-over-p256";
    tls.write_all(payload).unwrap();
    tls.flush().unwrap();
    let mut buf = vec![0u8; payload.len()];
    tls.read_exact(&mut buf).expect("echo should round-trip");
    assert_eq!(&buf[..], &payload[..]);

    // Only a different group on offer → no shared group → handshake refused (pin is enforced).
    assert!(
        client("X25519").is_err(),
        "an X25519-only client must fail against a P-256-pinned gateway (group pin not applied?)"
    );

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}
