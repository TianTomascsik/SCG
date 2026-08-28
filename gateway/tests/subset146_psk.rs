//! Subset-146 TLS PSK profile (`profile = subset146-psk`).
//!
//! TLS-PSK (DHE-PSK-AES256-GCM-SHA384, TLS 1.2) wired via OpenSSL PSK
//! callbacks. These tests prove it end-to-end with no certificates involved:
//!
//!   * `subset146_psk_round_trip`            — matching identity + key handshake.
//!   * `subset146_psk_wrong_key_refused`     — same identity, wrong key.
//!   * `subset146_psk_unknown_identity_refused` — identity the server rejects.
//!   * `ktls_psk_falls_back_to_userspace_tls` — decision 8: a `ktls` rule with a
//!     non-offloadable PSK profile auto-falls-back to userspace `tls` and still
//!     completes the PSK handshake.
//!
//! All tests run unprivileged on loopback.

mod common;

use std::sync::atomic::Ordering;

use common::{free_port, load_single_rule, plain_round_trip, run_rules, temp_dir, EchoServer};

use gateway::security::tls_engine::params::{TlsProfile, TlsSecurityParams};

/// 32-byte pre-shared key (AES-256).
const PSK_HEX: &str = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee";
const OTHER_HEX: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
const IDENTITY: &str = "rail-onboard-1";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A PSK echo upstream pinned to TLS 1.2 with the given identity + key.
fn psk_echo(identity: &str, psk_hex: &str) -> EchoServer {
    EchoServer::start_with_params(TlsSecurityParams {
        version: Some("tls1.2".to_string()),
        profile: TlsProfile::Subset146Psk,
        psk_identity: Some(identity.to_string()),
        psk_key: Some(zeroize::Zeroizing::new(hex(psk_hex))),
        ..Default::default()
    })
}

/// Build a PSK encrypt rule on `security_provider` with the given identity/key.
fn psk_rule(provider: &str, listen: &str, echo: &str, identity: &str, psk_hex: &str) -> String {
    format!(
        r#"{{
            "name": "subset146-psk",
            "direction": "encrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{echo}",
            "upstream_proto": "tcp",
            "security_provider": "{provider}",
            "traffic_class": "safety",
            "protocol_version": "tls1.2",
            "profile": "subset146-psk",
            "verify": "none",
            "psk_identity": "{identity}",
            "psk_hex": "{psk_hex}"
        }}"#,
        listen = listen,
        echo = echo,
        provider = provider,
        identity = identity,
        psk_hex = psk_hex,
    )
}

#[test]
fn subset146_psk_round_trip() {
    let tmp = temp_dir("s146-psk-ok");
    let echo = psk_echo(IDENTITY, PSK_HEX);
    let listen = format!("127.0.0.1:{}", free_port());
    let config = load_single_rule(
        &tmp,
        &psk_rule("tls", &listen, &echo.addr, IDENTITY, PSK_HEX),
    );
    let (handles, shutdown) = run_rules(&config);

    let echoed = plain_round_trip(&listen, b"subset146-psk-payload")
        .expect("PSK handshake should round-trip with a matching identity and key");
    assert_eq!(echoed, b"subset146-psk-payload");

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn subset146_psk_wrong_key_refused() {
    let tmp = temp_dir("s146-psk-wrongkey");
    let echo = psk_echo(IDENTITY, PSK_HEX);
    let listen = format!("127.0.0.1:{}", free_port());
    // Same identity the server accepts, but the wrong key → Finished MAC fails.
    let config = load_single_rule(
        &tmp,
        &psk_rule("tls", &listen, &echo.addr, IDENTITY, OTHER_HEX),
    );
    let (handles, shutdown) = run_rules(&config);

    let result = plain_round_trip(&listen, b"wrong-key");
    assert!(
        result.is_err(),
        "PSK handshake must fail when the pre-shared key does not match"
    );

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn subset146_psk_unknown_identity_refused() {
    let tmp = temp_dir("s146-psk-unknownid");
    let echo = psk_echo(IDENTITY, PSK_HEX);
    let listen = format!("127.0.0.1:{}", free_port());
    // Identity the server does not recognise → server callback rejects (returns 0).
    let config = load_single_rule(
        &tmp,
        &psk_rule("tls", &listen, &echo.addr, "intruder", PSK_HEX),
    );
    let (handles, shutdown) = run_rules(&config);

    let result = plain_round_trip(&listen, b"unknown-id");
    assert!(
        result.is_err(),
        "PSK handshake must fail for an identity the server does not accept"
    );

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn ktls_psk_falls_back_to_userspace_tls() {
    let tmp = temp_dir("s146-psk-ktls");
    let echo = psk_echo(IDENTITY, PSK_HEX);
    let listen = format!("127.0.0.1:{}", free_port());
    // Request kTLS with a PSK profile: not offloadable, so the gateway must
    // auto-fall-back to userspace TLS (decision 8) and still complete the PSK
    // handshake — proving the fallback preserves the security parameters.
    let config = load_single_rule(
        &tmp,
        &psk_rule("ktls", &listen, &echo.addr, IDENTITY, PSK_HEX),
    );
    let (handles, shutdown) = run_rules(&config);

    let echoed = plain_round_trip(&listen, b"ktls-psk-fallback")
        .expect("ktls+psk should fall back to userspace tls and round-trip");
    assert_eq!(echoed, b"ktls-psk-fallback");

    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}
