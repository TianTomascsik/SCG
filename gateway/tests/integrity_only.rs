//! WP5 — TLS integrity-only / NULL-cipher profile (`profile = integrity-only`).
//!
//! Authenticated-but-not-encrypted TLS using Subset-146 NULL-cipher suites
//! (`TLS_ECDHE_ECDSA_WITH_NULL_SHA` et al.), wired in WP1. Tests:
//!
//!   * `integrity_only_round_trip_negotiates_enull` — a raw TLS client that
//!     offers NULL ciphers terminates on a decrypt rule, the negotiated cipher
//!     reports `eNULL` (no bulk encryption, MAC present), and the payload
//!     round-trips via a plain backend. Skips with a warning if the linked
//!     OpenSSL was built without NULL ciphers (decision 6).
//!   * `ktls_integrity_only_rejected_at_config_load` — a `ktls` rule with the
//!     integrity-only profile is rejected at config load (decision 8): a NULL
//!     cipher has nothing to offload to the kernel.
//!
//! All tests run unprivileged on loopback.

mod common;

use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::pki::TestPki;
use common::{connect_tcp_with_retry, free_port, load_single_rule, run_rules, temp_dir, PlainEchoServer};

use gateway::management::config::GatewayConfig;
use gateway::security::tls_engine::params::openssl_supports_null_cipher;

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

#[test]
fn integrity_only_round_trip_negotiates_enull() {
    if !openssl_supports_null_cipher() {
        eprintln!(
            "skipping integrity_only_round_trip_negotiates_enull: \
             the linked OpenSSL was built without NULL-encryption ciphers"
        );
        return;
    }

    let tmp = temp_dir("integrity-only");
    let pki = TestPki::generate(&tmp);
    let backend = PlainEchoServer::start();

    let listen = format!("127.0.0.1:{}", free_port());
    // Decrypt rule: integrity-only TLS frontend → plain backend, pinned to
    // TLS 1.2 where the NULL-SHA cipher suites live.
    let rule = format!(
        r#"{{
            "name": "integrity-only",
            "direction": "decrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{backend}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "protocol_version": "tls1.2",
            "profile": "integrity-only",
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

    // Raw TLS client offering the same NULL-cipher policy.
    let tcp = connect_tcp_with_retry(&listen, 60).expect("decrypt listener never came up");
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    builder
        .set_cipher_list("ECDHE-ECDSA-NULL-SHA:ECDHE-RSA-NULL-SHA:NULL-SHA256:NULL-SHA:@SECLEVEL=0")
        .unwrap();
    let connector = builder.build();
    let mut tls = connector
        .configure()
        .unwrap()
        .verify_hostname(false)
        .use_server_name_indication(true)
        .connect("localhost", tcp)
        .expect("integrity-only TLS handshake should succeed");

    // The negotiated cipher must be a NULL-encryption (eNULL) suite.
    let cipher = tls
        .ssl()
        .current_cipher()
        .map(|c| c.name().to_string())
        .unwrap_or_default();
    assert!(
        cipher.contains("NULL"),
        "expected a NULL-encryption cipher, negotiated {cipher:?}"
    );

    let payload = b"integrity-only-authenticated-but-cleartext";
    tls.write_all(payload).unwrap();
    tls.flush().unwrap();
    let mut buf = vec![0u8; payload.len()];
    tls.read_exact(&mut buf)
        .expect("payload should round-trip through the integrity-only frontend");
    assert_eq!(&buf[..], &payload[..]);

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn ktls_integrity_only_rejected_at_config_load() {
    let tmp = temp_dir("integrity-ktls-reject");
    let rule = r#"{
        "name": "ktls-integrity",
        "direction": "decrypt",
        "listen_addr": "127.0.0.1:9",
        "listen_proto": "tcp",
        "upstream_addr": "127.0.0.1:10",
        "upstream_proto": "tcp",
        "security_provider": "ktls",
        "traffic_class": "safety",
        "protocol_version": "tls1.2",
        "profile": "integrity-only"
    }"#;
    let json = format!(
        r#"{{ "rules": [{rule}] }}"#,
        rule = rule,
    );
    let path = tmp.join("gw.json");
    std::fs::write(&path, json).unwrap();

    let result = GatewayConfig::load(path.to_str().unwrap());
    assert!(
        result.is_err(),
        "ktls + integrity-only must be rejected at config load (a NULL cipher cannot be offloaded)"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
