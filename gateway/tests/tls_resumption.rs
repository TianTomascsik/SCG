//! Task S2 — upstream TLS session resumption on the TCP encrypt path (TRA #78–#80).
//!
//! The gateway's client-side session cache (B18) is keyed by the full
//! upstream identity + crypto-policy fingerprint and gated behind the per-rule
//! `resumption` toggle (default off). These tests drive the **TCP encrypt
//! listener** path end-to-end against a ticket-issuing upstream:
//!
//! * `second_connection_resumes_on_tcp_encrypt_path` — with `resumption: true`
//!   the first upstream handshake is full and a reconnect resumes.
//! * `no_resume_across_tightened_posture` — the #79 negative control: a session
//!   cached under a looser verify posture must NOT resume once the posture
//!   tightens (different policy fingerprint ⇒ cache miss ⇒ full, fully-verified
//!   handshake), and the tightened posture then resumes only against its own key.
//! * `resumption_off_never_resumes` — the default-off posture stays full-handshake.
//!
//! All tests run unprivileged on loopback.

mod common;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::pki::TestPki;
use common::{free_port, load_single_rule, plain_round_trip, run_rules, temp_dir, EchoServer};

use gateway::security::tls_engine::params::TlsSecurityParams;

/// Wait until the echo server has counted `expected` completed accepts in
/// total (resumed + full), so assertions never race the accept thread.
fn wait_for_accepts(echo: &EchoServer, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let total =
            echo.resumed_accepts.load(Ordering::SeqCst) + echo.full_accepts.load(Ordering::SeqCst);
        if total >= expected {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A ticket-issuing upstream (server-side resumption on) presenting the
/// CA-issued server identity; version negotiation stays at the defaults.
fn ticket_issuing_upstream(pki: &TestPki) -> EchoServer {
    EchoServer::start_with_params(TlsSecurityParams {
        cert_path: Some(pki.server_cert.clone()),
        key_path: Some(pki.server_key.clone()),
        resumption: true,
        ..Default::default()
    })
}

#[test]
fn second_connection_resumes_on_tcp_encrypt_path() {
    let tmp = temp_dir("tls-resume-tcp");
    let pki = TestPki::generate(&tmp);
    let echo = ticket_issuing_upstream(&pki);

    let listen = format!("127.0.0.1:{}", free_port());
    let rule = format!(
        r#"{{
            "name": "resume-encrypt",
            "direction": "encrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{echo}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "verify": "server",
            "server_name": "localhost",
            "ca_path": "{ca}",
            "resumption": true
        }}"#,
        listen = listen,
        echo = echo.addr,
        ca = pki.ca_cert.display(),
    );
    let config = load_single_rule(&tmp, &rule);
    let (handles, shutdown) = run_rules(&config);

    // First connection: full handshake; the new-session callback caches the ticket.
    let echoed = plain_round_trip(&listen, b"prime").expect("first round-trip");
    assert_eq!(echoed, b"prime");
    wait_for_accepts(&echo, 1);
    assert_eq!(echo.full_accepts.load(Ordering::SeqCst), 1);
    assert_eq!(echo.resumed_accepts.load(Ordering::SeqCst), 0);

    // Second connection: the encrypt connector primes the cached session and resumes.
    let echoed = plain_round_trip(&listen, b"resume").expect("second round-trip");
    assert_eq!(echoed, b"resume");
    wait_for_accepts(&echo, 2);
    assert_eq!(
        echo.resumed_accepts.load(Ordering::SeqCst),
        1,
        "reconnect under the same posture should resume the cached session"
    );
    assert_eq!(echo.full_accepts.load(Ordering::SeqCst), 1);

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn no_resume_across_tightened_posture() {
    // TRA #79 negative control: a ticket cached under `verify: none` must never
    // be presented once the rule posture tightens to `verify: server` + CA —
    // the policy-fingerprint key must miss and force a fresh, fully-verified
    // handshake.
    let tmp_a = temp_dir("tls-resume-loose");
    let tmp_b = temp_dir("tls-resume-tight");
    let pki = TestPki::generate(&tmp_a);
    let echo = ticket_issuing_upstream(&pki);

    // Rule A — loose posture (verify: none), resumption on. Primes the cache
    // under fingerprint A.
    let listen_a = format!("127.0.0.1:{}", free_port());
    let rule_a = format!(
        r#"{{
            "name": "resume-loose",
            "direction": "encrypt",
            "listen_addr": "{listen_a}",
            "listen_proto": "tcp",
            "upstream_addr": "{echo}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "verify": "none",
            "resumption": true
        }}"#,
        listen_a = listen_a,
        echo = echo.addr,
    );
    let config_a = load_single_rule(&tmp_a, &rule_a);
    let (handles_a, shutdown_a) = run_rules(&config_a);

    let echoed = plain_round_trip(&listen_a, b"loose").expect("loose round-trip");
    assert_eq!(echoed, b"loose");
    wait_for_accepts(&echo, 1);
    assert_eq!(echo.full_accepts.load(Ordering::SeqCst), 1);
    assert_eq!(echo.resumed_accepts.load(Ordering::SeqCst), 0);

    // Rule B — tightened posture (verify: server + CA) against the SAME
    // upstream. Its fingerprint differs, so the loose session must not resume.
    let listen_b = format!("127.0.0.1:{}", free_port());
    let rule_b = format!(
        r#"{{
            "name": "resume-tight",
            "direction": "encrypt",
            "listen_addr": "{listen_b}",
            "listen_proto": "tcp",
            "upstream_addr": "{echo}",
            "upstream_proto": "tcp",
            "security_provider": "tls",
            "traffic_class": "safety",
            "verify": "server",
            "server_name": "localhost",
            "ca_path": "{ca}",
            "resumption": true
        }}"#,
        listen_b = listen_b,
        echo = echo.addr,
        ca = pki.ca_cert.display(),
    );
    let config_b = load_single_rule(&tmp_b, &rule_b);
    let (handles_b, shutdown_b) = run_rules(&config_b);

    let echoed = plain_round_trip(&listen_b, b"tight").expect("tight round-trip");
    assert_eq!(echoed, b"tight");
    wait_for_accepts(&echo, 2);
    assert_eq!(
        echo.resumed_accepts.load(Ordering::SeqCst),
        0,
        "a posture change must miss the session cache (TRA #79)"
    );
    assert_eq!(echo.full_accepts.load(Ordering::SeqCst), 2);

    // The tightened posture then resumes only against its own fingerprint.
    let echoed = plain_round_trip(&listen_b, b"tight2").expect("tight reconnect");
    assert_eq!(echoed, b"tight2");
    wait_for_accepts(&echo, 3);
    assert_eq!(
        echo.resumed_accepts.load(Ordering::SeqCst),
        1,
        "reconnect under the tightened posture should resume its own session"
    );

    shutdown_a.store(true, Ordering::SeqCst);
    shutdown_b.store(true, Ordering::SeqCst);
    for h in handles_a.into_iter().chain(handles_b) {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp_a);
    let _ = std::fs::remove_dir_all(&tmp_b);
}

#[test]
fn resumption_off_never_resumes() {
    // Default posture: without `resumption: true` every handshake stays full
    // (the connector sets NO_TICKET and never primes a session).
    let tmp = temp_dir("tls-resume-off");
    let pki = TestPki::generate(&tmp);
    let echo = ticket_issuing_upstream(&pki);

    let listen = format!("127.0.0.1:{}", free_port());
    let rule = format!(
        r#"{{
            "name": "resume-off",
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

    for payload in [b"one".as_slice(), b"two".as_slice()] {
        let echoed = plain_round_trip(&listen, payload).expect("round-trip");
        assert_eq!(echoed, payload);
    }
    wait_for_accepts(&echo, 2);
    assert_eq!(
        echo.resumed_accepts.load(Ordering::SeqCst),
        0,
        "resumption must stay off by default"
    );
    assert_eq!(echo.full_accepts.load(Ordering::SeqCst), 2);

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}
