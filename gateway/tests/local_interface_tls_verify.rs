//! DP-01 / KC-05 — the UDS/SHM local-interface **kTLS** path must honour the
//! rule's `verify` mode, CA/cert and PSK, exactly like the userspace TLS path.
//!
//! Before the fix, [`connect_tls_upstream`]/[`accept_tls_upstream`] built their
//! kTLS contexts with a bench helper hardcoded to `SslVerifyMode::NONE`, silently
//! discarding the operator's verification configuration on the local-interface
//! path. These tests drive the endpoint functions directly:
//!
//! * `local_ktls_connect_verifies_upstream_cert` — kTLS connect rejects an
//!   untrusted upstream cert (wrong CA) and accepts a trusted one.
//! * `local_ktls_accept_mutual_rejects_certless_client` — a `verify=mutual` kTLS
//!   acceptor demands a client certificate.
//! * `local_ktls_connect_keeps_psk_callback` — a `subset146-psk` kTLS connect
//!   still presents its PSK (matching key handshakes, wrong key is refused).
//!
//! All tests run unprivileged on loopback; kTLS activation is not required for the
//! handshake/verification to run (the record-layer offload is transparent to it).

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use serde_json::{json, Value};

use common::pki::TestPki;
use common::{connect_tcp_with_retry, free_port, temp_dir, EchoServer};

use gateway::interfaces::endpoint::{accept_tls_upstream, connect_tls_upstream};
use gateway::management::config::{QosPolicy, TlsMode, TrafficClass};
use gateway::security::tls_engine::params::{TlsProfile, TlsSecurityParams};

fn params_from(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn qos() -> QosPolicy {
    QosPolicy {
        dscp_tag: None,
        preserve_inbound_dscp: false,
        traffic_class: TrafficClass::Normal,
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn local_ktls_connect_verifies_upstream_cert() {
    let tmp = temp_dir("dp01-connect");
    // Upstream is authenticated by CA-A; CA-B is an unrelated trust anchor.
    let (dir_a, dir_b) = (tmp.join("a"), tmp.join("b"));
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    let pki_a = TestPki::generate(&dir_a);
    let pki_b = TestPki::generate(&dir_b);

    // TLS echo upstream presenting CA-A's server leaf.
    let echo = EchoServer::start_with_params(TlsSecurityParams {
        cert_path: Some(pki_a.server_cert.clone()),
        key_path: Some(pki_a.server_key.clone()),
        ..TlsSecurityParams::default()
    });
    let shutdown = AtomicBool::new(false);

    // Wrong CA → the kTLS connector must reject the upstream certificate.
    let wrong = params_from(&[
        ("verify", json!("server")),
        ("ca_path", json!(pki_b.ca_cert.to_str().unwrap())),
    ]);
    let r = connect_tls_upstream(
        "dp01",
        &echo.addr,
        TlsMode::Ktls,
        &wrong,
        None,
        0,
        qos(),
        None,
        &shutdown,
    );
    assert!(
        r.is_err(),
        "kTLS connect must fail verification against the wrong CA (DP-01)"
    );

    // Right CA → verification succeeds.
    let right = params_from(&[
        ("verify", json!("server")),
        ("ca_path", json!(pki_a.ca_cert.to_str().unwrap())),
    ]);
    let r = connect_tls_upstream(
        "dp01",
        &echo.addr,
        TlsMode::Ktls,
        &right,
        None,
        0,
        qos(),
        None,
        &shutdown,
    );
    assert!(
        r.is_ok(),
        "kTLS connect must succeed against the trusted CA: {:?}",
        r.err()
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

/// Complete a raw TLS client handshake to `addr`, optionally presenting a client
/// identity. Returns whether the handshake succeeded. The server's (self-signed)
/// certificate is not verified — the test exercises *client* authentication.
fn client_handshake(addr: &str, identity: Option<(&Path, &Path)>) -> bool {
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_verify(SslVerifyMode::NONE);
    if let Some((cert, key)) = identity {
        b.set_certificate_file(cert, SslFiletype::PEM).unwrap();
        b.set_private_key_file(key, SslFiletype::PEM).unwrap();
    }
    let connector = b.build();
    let Some(stream) = connect_tcp_with_retry(addr, 40) else {
        return false;
    };
    stream.set_nonblocking(false).ok();
    connector.connect("localhost", stream).is_ok()
}

#[test]
fn local_ktls_accept_mutual_rejects_certless_client() {
    let tmp = temp_dir("dp01-accept");
    let pki = TestPki::generate(&tmp);

    // A `verify=mutual` kTLS acceptor trusting the test CA for client certs.
    let mutual = params_from(&[
        ("verify", json!("mutual")),
        ("ca_path", json!(pki.ca_cert.to_str().unwrap())),
    ]);

    // Certless client → the acceptor must reject (FAIL_IF_NO_PEER_CERT).
    {
        let listen = format!("127.0.0.1:{}", free_port());
        let sd = Arc::new(AtomicBool::new(false));
        let (listen_c, sd_c, params) = (listen.clone(), sd.clone(), mutual.clone());
        let server = thread::spawn(move || {
            accept_tls_upstream(
                "dp01",
                &listen_c,
                TlsMode::Ktls,
                &params,
                None,
                0,
                qos(),
                None,
                &sd_c,
            )
            .is_ok()
        });
        let client_ok = client_handshake(&listen, None);
        let accepted = server.join().unwrap();
        assert!(!accepted, "mutual acceptor must reject a certless client");
        assert!(!client_ok, "certless client handshake must fail");
    }

    // Client presenting a CA-issued cert → the acceptor completes the handshake.
    {
        let listen = format!("127.0.0.1:{}", free_port());
        let sd = Arc::new(AtomicBool::new(false));
        let (listen_c, sd_c, params) = (listen.clone(), sd.clone(), mutual.clone());
        let server = thread::spawn(move || {
            accept_tls_upstream(
                "dp01",
                &listen_c,
                TlsMode::Ktls,
                &params,
                None,
                0,
                qos(),
                None,
                &sd_c,
            )
            .is_ok()
        });
        let client_ok = client_handshake(&listen, Some((&pki.client_cert, &pki.client_key)));
        let accepted = server.join().unwrap();
        assert!(
            accepted && client_ok,
            "mutual acceptor must accept a CA-issued client cert (accepted={accepted}, client_ok={client_ok})"
        );
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn local_ktls_connect_keeps_psk_callback() {
    // KC-05: the kTLS local path must retain the PSK callback for subset146-psk.
    const PSK: &str = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee";
    const OTHER: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    const IDENTITY: &str = "rail-onboard-1";

    let tmp = temp_dir("kc05-psk");
    let echo = EchoServer::start_with_params(TlsSecurityParams {
        version: Some("tls1.2".to_string()),
        profile: TlsProfile::Subset146Psk,
        psk_identity: Some(IDENTITY.to_string()),
        psk_key: Some(zeroize::Zeroizing::new(hex(PSK))),
        ..TlsSecurityParams::default()
    });
    let shutdown = AtomicBool::new(false);

    let base = |psk_hex: &str| {
        params_from(&[
            ("profile", json!("subset146-psk")),
            ("verify", json!("none")),
            ("psk_identity", json!(IDENTITY)),
            ("psk_hex", json!(psk_hex)),
        ])
    };

    // Matching key → the PSK handshake completes on the kTLS path.
    let ok = connect_tls_upstream(
        "kc05",
        &echo.addr,
        TlsMode::Ktls,
        &base(PSK),
        Some("tls1.2"),
        0,
        qos(),
        None,
        &shutdown,
    );
    assert!(
        ok.is_ok(),
        "matching PSK must handshake on the kTLS path: {:?}",
        ok.err()
    );

    // Wrong key → the callback runs but the Finished MAC fails.
    let bad = connect_tls_upstream(
        "kc05",
        &echo.addr,
        TlsMode::Ktls,
        &base(OTHER),
        Some("tls1.2"),
        0,
        qos(),
        None,
        &shutdown,
    );
    assert!(bad.is_err(), "wrong PSK must be refused on the kTLS path");

    let _ = std::fs::remove_dir_all(&tmp);
}
