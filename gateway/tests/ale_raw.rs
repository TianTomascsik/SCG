//! WP8 — UDP-over-TLS application framing (`app_protocol = ale | raw`).
//!
//! UDP traffic tunnelled through TLS is framed at the application layer so the
//! TLS byte stream can be split back into datagrams on the far side. Two
//! framings are selectable per rule via `app_protocol`:
//!
//!   * **`ale`** (the default) — ETCS Subset-098 ALEPKT framing with the
//!     AU1/AU2 association handshake, DT data packets and a DI disconnect.
//!   * **`raw`** — a 4-byte little-endian length prefix per datagram and no
//!     handshake, tunnelling UDP through TLS without the ALE overhead.
//!
//! Each test wires a full encrypt -> decrypt chain on loopback:
//!
//! ```text
//!   UDP client --> [encrypt udp/tls] --TLS/TCP--> [decrypt tcp/tls] --> UDP echo
//! ```
//!
//! The encrypt rule frames + TLS-wraps client datagrams; the decrypt rule
//! TLS-unwraps + deframes them to the plain-UDP backend, and the echo travels
//! back the same way. A successful round-trip proves the framing matches end to
//! end (and, for ALE, that the AU1/AU2 handshake completes). All tests run
//! unprivileged on loopback.

mod common;

use std::io;
use std::net::UdpSocket;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::dtls::PlainUdpEchoServer;
use common::pki::TestPki;
use common::{free_port, run_rules, temp_dir};
use gateway::management::config::GatewayConfig;

/// Plain-UDP client round-trip against an encrypt rule's UDP listener.
///
/// Plain UDP has no retransmission and the encrypt tunnel is established lazily
/// on the first datagram, so the initial sends overlap the TCP+TLS+ALE
/// handshake. Resend a bounded number of times so positive cases are not flaky;
/// a genuinely broken framing still exhausts the attempts and returns `Err`.
fn udp_round_trip(gateway: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    sock.connect(gateway)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;

    let mut last = io::Error::new(io::ErrorKind::TimedOut, "no reply");
    for _ in 0..20 {
        if let Err(e) = sock.send(payload) {
            last = e;
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        let mut buf = vec![0u8; payload.len().max(2048)];
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

/// Build a two-rule encrypt -> decrypt UDP-over-TLS chain. Both rules carry the
/// same `app_protocol` so the framing matches end to end. `app_protocol = None`
/// omits the field entirely, exercising the built-in default (ALE).
fn chain_config(
    tmp: &Path,
    pki: &TestPki,
    enc_listen: &str,
    dec_listen: &str,
    backend: &str,
    app_protocol: Option<&str>,
) -> GatewayConfig {
    let app_field = match app_protocol {
        Some(p) => format!(r#","app_protocol":"{p}""#),
        None => String::new(),
    };
    let json = format!(
        r#"{{
            "rules": [
                {{
                    "name": "udp-encrypt",
                    "direction": "encrypt",
                    "listen_addr": "{enc_listen}",
                    "listen_proto": "udp",
                    "upstream_addr": "{dec_listen}",
                    "upstream_proto": "tcp",
                    "security_provider": "tls",
                    "verify": "none",
                    "traffic_class": "safety"{app_field}
                }},
                {{
                    "name": "udp-decrypt",
                    "direction": "decrypt",
                    "listen_addr": "{dec_listen}",
                    "listen_proto": "tcp",
                    "upstream_addr": "{backend}",
                    "upstream_proto": "udp",
                    "security_provider": "tls",
                    "traffic_class": "safety",
                    "verify": "none",
                    "cert_path": "{cert}",
                    "key_path": "{key}"{app_field}
                }}
            ]
        }}"#,
        cert = pki.server_cert.display(),
        key = pki.server_key.display(),
    );
    let path = tmp.join("gw.json");
    std::fs::write(&path, json).unwrap();
    GatewayConfig::load(path.to_str().unwrap()).expect("chain config validates")
}

fn run<F: FnOnce()>(config: &GatewayConfig, body: F) {
    let (handles, shutdown) = run_rules(config);
    body();
    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
}

/// ALE framing (explicit): a datagram round-trips through the TLS tunnel,
/// which also proves the AU1/AU2 association handshake completes.
#[test]
fn ale_udp_over_tls_round_trip() {
    let tmp = temp_dir("ale-chain");
    let pki = TestPki::generate(&tmp);
    let backend = PlainUdpEchoServer::start();
    let enc_listen = format!("127.0.0.1:{}", free_port());
    let dec_listen = format!("127.0.0.1:{}", free_port());
    let config = chain_config(
        &tmp,
        &pki,
        &enc_listen,
        &dec_listen,
        &backend.addr,
        Some("ale"),
    );

    run(&config, || {
        let echoed = udp_round_trip(&enc_listen, b"ale-datagram")
            .expect("ALE-framed UDP datagram should round-trip through the TLS tunnel");
        assert_eq!(echoed, b"ale-datagram");
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Raw framing: a datagram round-trips with no association handshake, using the
/// 4-byte length-prefix framing instead of ALE.
#[test]
fn raw_udp_over_tls_round_trip() {
    let tmp = temp_dir("raw-chain");
    let pki = TestPki::generate(&tmp);
    let backend = PlainUdpEchoServer::start();
    let enc_listen = format!("127.0.0.1:{}", free_port());
    let dec_listen = format!("127.0.0.1:{}", free_port());
    let config = chain_config(
        &tmp,
        &pki,
        &enc_listen,
        &dec_listen,
        &backend.addr,
        Some("raw"),
    );

    run(&config, || {
        let echoed = udp_round_trip(&enc_listen, b"raw-datagram")
            .expect("raw-framed UDP datagram should round-trip through the TLS tunnel");
        assert_eq!(echoed, b"raw-datagram");
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Raw framing preserves datagram boundaries: a payload larger than the 4-byte
/// length prefix round-trips intact (exercises the length-prefix reassembly).
#[test]
fn raw_preserves_large_datagram() {
    let tmp = temp_dir("raw-large");
    let pki = TestPki::generate(&tmp);
    let backend = PlainUdpEchoServer::start();
    let enc_listen = format!("127.0.0.1:{}", free_port());
    let dec_listen = format!("127.0.0.1:{}", free_port());
    let config = chain_config(
        &tmp,
        &pki,
        &enc_listen,
        &dec_listen,
        &backend.addr,
        Some("raw"),
    );

    let payload: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
    run(&config, || {
        let echoed = udp_round_trip(&enc_listen, &payload)
            .expect("a large raw-framed datagram should round-trip intact");
        assert_eq!(
            echoed, payload,
            "raw framing must preserve the datagram verbatim"
        );
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Omitting `app_protocol` defaults to ALE on both rules, so the chain still
/// round-trips (guards the `effective_app_protocol` default).
#[test]
fn default_app_protocol_is_ale() {
    let tmp = temp_dir("ale-default");
    let pki = TestPki::generate(&tmp);
    let backend = PlainUdpEchoServer::start();
    let enc_listen = format!("127.0.0.1:{}", free_port());
    let dec_listen = format!("127.0.0.1:{}", free_port());
    let config = chain_config(&tmp, &pki, &enc_listen, &dec_listen, &backend.addr, None);

    run(&config, || {
        let echoed = udp_round_trip(&enc_listen, b"default-ale")
            .expect("the default (ALE) framing should round-trip through the TLS tunnel");
        assert_eq!(echoed, b"default-ale");
    });
    let _ = std::fs::remove_dir_all(&tmp);
}
