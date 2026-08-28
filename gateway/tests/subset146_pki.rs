//! Subset-146 TLS PKI profile (`profile = subset146-pki`).
//!
//! The profile preset (mandatory mutual X.509 auth, ECDHE/ECDSA-GCM cipher
//! policy, TLS 1.2 + 1.3) is implemented in `TlsSecurityParams`. These tests
//! prove it end-to-end against an ECDSA (P-256) CA chain:
//!
//!   * `subset146_pki_tls12_round_trip` / `..._tls13_round_trip` — a full mutual
//!     ECDHE-ECDSA-GCM handshake round-trips on both TLS versions.
//!   * `subset146_pki_missing_client_cert_refused` — the profile forces mutual
//!     auth, so a gateway presenting no client cert is rejected (fail-closed).
//!   * `subset146_pki_untrusted_ca_refused` — an upstream cert that does not
//!     chain to the configured CA is rejected.
//!   * `subset146_pki_non_gcm_cipher_refused` — the profile pins AES-256-GCM and
//!     refuses to fall back to a weaker (AES-128-GCM) suite.
//!
//! All tests run unprivileged on loopback.

mod common;

use std::sync::atomic::Ordering;

use common::pki::TestPki;
use common::{free_port, load_single_rule, plain_round_trip, run_rules, temp_dir, EchoServer};

use gateway::security::tls_engine::params::{TlsProfile, TlsSecurityParams, VerifyMode};

/// Build a Subset-146-PKI echo upstream: ECDSA identity, requires + verifies a
/// client cert, pinned to `version` (`tls1.2` / `tls1.3`).
fn pki_echo(pki: &TestPki, version: &str) -> EchoServer {
    EchoServer::start_with_params(TlsSecurityParams {
        version: Some(version.to_string()),
        profile: TlsProfile::Subset146Pki,
        verify: VerifyMode::Mutual,
        cert_path: Some(pki.server_cert.clone()),
        key_path: Some(pki.server_key.clone()),
        ca_path: Some(pki.ca_cert.clone()),
        ..Default::default()
    })
}

fn run_pki_round_trip(version: &str, tag: &str) {
    let tmp = temp_dir(tag);
    let pki = TestPki::generate(&tmp);
    let echo = pki_echo(&pki, version);

    let listen = format!("127.0.0.1:{}", free_port());
    let rule = format!(
        r#"{{
            "name": "subset146-pki",
            "direction": "encrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{echo}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "protocol_version": "{version}",
            "profile": "subset146-pki",
            "server_name": "localhost",
            "cert_path": "{cert}",
            "key_path": "{key}",
            "ca_path": "{ca}"
        }}"#,
        listen = listen,
        echo = echo.addr,
        version = version,
        cert = pki.client_cert.display(),
        key = pki.client_key.display(),
        ca = pki.ca_cert.display(),
    );
    let config = load_single_rule(&tmp, &rule);
    let (handles, shutdown) = run_rules(&config);

    let payload = format!("subset146-pki-{version}-payload");
    let echoed = plain_round_trip(&listen, payload.as_bytes())
        .expect("Subset-146 PKI mutual handshake should round-trip");
    assert_eq!(echoed, payload.as_bytes());

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn subset146_pki_tls12_round_trip() {
    run_pki_round_trip("tls1.2", "s146-pki-12");
}

#[test]
fn subset146_pki_tls13_round_trip() {
    run_pki_round_trip("tls1.3", "s146-pki-13");
}

#[test]
fn subset146_pki_missing_client_cert_refused() {
    let tmp = temp_dir("s146-pki-nocert");
    let pki = TestPki::generate(&tmp);
    let echo = pki_echo(&pki, "tls1.2");

    let listen = format!("127.0.0.1:{}", free_port());
    // Gateway selects subset146-pki (verify = mutual is forced) and trusts the
    // CA, but presents NO client cert — the upstream must refuse it.
    let rule = format!(
        r#"{{
            "name": "subset146-pki-nocert",
            "direction": "encrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{echo}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "protocol_version": "tls1.2",
            "profile": "subset146-pki",
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
        "subset146-pki must fail closed when the gateway presents no client cert"
    );

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn subset146_pki_untrusted_ca_refused() {
    let tmp = temp_dir("s146-pki-badca");
    let pki = TestPki::generate(&tmp);
    let other_dir = temp_dir("s146-pki-otherca");
    let other = TestPki::generate(&other_dir);
    let echo = pki_echo(&pki, "tls1.2");

    let listen = format!("127.0.0.1:{}", free_port());
    // Valid client cert, but the gateway trusts the wrong CA for the upstream.
    let rule = format!(
        r#"{{
            "name": "subset146-pki-badca",
            "direction": "encrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{echo}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "protocol_version": "tls1.2",
            "profile": "subset146-pki",
            "server_name": "localhost",
            "cert_path": "{cert}",
            "key_path": "{key}",
            "ca_path": "{ca}"
        }}"#,
        listen = listen,
        echo = echo.addr,
        cert = pki.client_cert.display(),
        key = pki.client_key.display(),
        ca = other.ca_cert.display(),
    );
    let config = load_single_rule(&tmp, &rule);
    let (handles, shutdown) = run_rules(&config);

    let result = plain_round_trip(&listen, b"untrusted-ca");
    assert!(
        result.is_err(),
        "subset146-pki must refuse an upstream cert that does not chain to the configured CA"
    );

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(&other_dir);
}

#[test]
fn subset146_pki_non_gcm_cipher_refused() {
    let tmp = temp_dir("s146-pki-cipher");
    let pki = TestPki::generate(&tmp);

    // Upstream offers ONLY AES-128-GCM (not the Subset-146 AES-256-GCM suite),
    // pinned to TLS 1.2 where the cipher list governs negotiation.
    let echo = EchoServer::start_with_params(TlsSecurityParams {
        version: Some("tls1.2".to_string()),
        cert_path: Some(pki.server_cert.clone()),
        key_path: Some(pki.server_key.clone()),
        cipher_list: Some("ECDHE-ECDSA-AES128-GCM-SHA256".to_string()),
        ..Default::default()
    });

    let listen = format!("127.0.0.1:{}", free_port());
    let rule = format!(
        r#"{{
            "name": "subset146-pki-cipher",
            "direction": "encrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{echo}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "protocol_version": "tls1.2",
            "profile": "subset146-pki",
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

    let result = plain_round_trip(&listen, b"weak-cipher");
    assert!(
        result.is_err(),
        "subset146-pki pins AES-256-GCM and must not negotiate a weaker AES-128-GCM suite"
    );

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}
