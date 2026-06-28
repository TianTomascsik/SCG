//! WP7 — End-to-end DSCP tagging / preservation + safety-priority tests.
//!
//! The gateway marks the DiffServ (DSCP) field on its **upstream** egress
//! socket. These tests put a DSCP-recording echo backend ([`DscpUdpSink`] /
//! [`DscpTcpSink`]) behind a rule and assert the DS field the backend observes:
//!
//! * **tag** — `Safety` defaults to EF (46); an explicit `dscp_tag` overrides it.
//! * **preserve** — `preserve_inbound_dscp` carries the client's DS field through
//!   to the upstream (DTLS, where the gateway owns the per-datagram read).
//!
//! Coverage spans DTLS-decrypt (UDP) and routing (TCP) over both IPv4 and IPv6,
//! plus a safety-priority functional check and a config-validation negative.
//! All tests run unprivileged on loopback.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::dtls::{dtls_client_round_trip_opts, DtlsClientOpts};
use common::pki::TestPki;
use common::qos::{DscpTcpSink, DscpUdpSink};
use common::{free_port, load_single_rule, plain_round_trip, run_rules, temp_dir};

use gateway::management::config::{GatewayConfig, TrafficClass, DSCP_EF};

/// Run every rule in `config`, execute `body`, then tear the rules down.
fn run<F: FnOnce()>(config: &GatewayConfig, body: F) {
    let (handles, shutdown) = run_rules(config);
    body();
    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
}

/// Poll the sink briefly for an observed DSCP (the forward datagram is recorded
/// before the echo is sent, so this resolves immediately in practice).
fn wait_udp_dscp(sink: &DscpUdpSink) -> Option<u8> {
    for _ in 0..50 {
        if let Some(d) = sink.last_dscp() {
            return Some(d);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    sink.last_dscp()
}

/// Build a DTLS **decrypt** rule (gateway is the DTLS server). `qos` carries the
/// optional per-rule QoS fields, e.g. `,"dscp_tag":10` or
/// `,"preserve_inbound_dscp":true`.
fn dtls_decrypt_rule(name: &str, listen: &str, upstream: &str, pki: &TestPki, qos: &str) -> String {
    format!(
        r#"{{
            "name": "{name}",
            "direction": "decrypt",
            "listen_addr": "{listen}",
            "listen_proto": "udp",
            "upstream_addr": "{upstream}",
            "upstream_proto": "udp",
            "security_provider": "dtls",
            "traffic_class": "safety",
            "protocol_version": "dtls1.2",
            "verify": "none",
            "cert_path": "{cert}",
            "key_path": "{key}"{qos}
        }}"#,
        cert = pki.server_cert.display(),
        key = pki.server_key.display(),
    )
}

/// Build a plaintext **routing** (L4 passthrough) rule.
fn routing_rule(name: &str, listen: &str, upstream: &str, qos: &str) -> String {
    format!(
        r#"{{
            "name": "{name}",
            "direction": "encrypt",
            "listen_addr": "{listen}",
            "listen_proto": "tcp",
            "upstream_addr": "{upstream}",
            "upstream_proto": "tcp",
            "security_provider": "routing",
            "traffic_class": "safety"{qos}
        }}"#
    )
}

// =============================================================================
//  DTLS decrypt (UDP) — tagging
// =============================================================================

fn dtls_tag_ef_case(tag: &str, listen_host: &str, sink_bind: &str, client_bind: &str) {
    let tmp = temp_dir(tag);
    let pki = TestPki::generate(&tmp);
    let sink = DscpUdpSink::start(sink_bind);
    let listen = format!("{listen_host}:{}", free_port());
    let config = load_single_rule(
        &tmp,
        &dtls_decrypt_rule("dtls-ef", &listen, &sink.addr, &pki, ""),
    );

    run(&config, || {
        let opts = DtlsClientOpts {
            bind_addr: client_bind,
            ..Default::default()
        };
        let echoed = dtls_client_round_trip_opts(&listen, opts, b"ef-tag")
            .expect("DTLS decrypt should forward to the plain UDP sink and echo back");
        assert_eq!(echoed, b"ef-tag");
        assert_eq!(
            wait_udp_dscp(&sink),
            Some(DSCP_EF),
            "safety default must tag the upstream with EF (46)"
        );
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dtls_decrypt_safety_tags_ef_ipv4() {
    dtls_tag_ef_case("dscp-dtls-ef-v4", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:0");
}

#[test]
fn dtls_decrypt_safety_tags_ef_ipv6() {
    dtls_tag_ef_case("dscp-dtls-ef-v6", "[::1]", "[::1]:0", "[::1]:0");
}

fn dtls_explicit_tag_case(tag: &str, listen_host: &str, sink_bind: &str, client_bind: &str) {
    const EXPLICIT: u8 = 10; // AF11
    let tmp = temp_dir(tag);
    let pki = TestPki::generate(&tmp);
    let sink = DscpUdpSink::start(sink_bind);
    let listen = format!("{listen_host}:{}", free_port());
    let config = load_single_rule(
        &tmp,
        &dtls_decrypt_rule("dtls-tag", &listen, &sink.addr, &pki, r#","dscp_tag":10"#),
    );

    run(&config, || {
        let opts = DtlsClientOpts {
            bind_addr: client_bind,
            ..Default::default()
        };
        let echoed = dtls_client_round_trip_opts(&listen, opts, b"explicit-tag")
            .expect("DTLS decrypt should forward and echo back");
        assert_eq!(echoed, b"explicit-tag");
        assert_eq!(
            wait_udp_dscp(&sink),
            Some(EXPLICIT),
            "explicit dscp_tag must override the class default"
        );
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dtls_decrypt_explicit_tag_ipv4() {
    dtls_explicit_tag_case(
        "dscp-dtls-tag-v4",
        "127.0.0.1",
        "127.0.0.1:0",
        "127.0.0.1:0",
    );
}

#[test]
fn dtls_decrypt_explicit_tag_ipv6() {
    dtls_explicit_tag_case("dscp-dtls-tag-v6", "[::1]", "[::1]:0", "[::1]:0");
}

// =============================================================================
//  DTLS decrypt (UDP) — preservation
// =============================================================================

fn dtls_preserve_case(tag: &str, listen_host: &str, sink_bind: &str, client_bind: &str) {
    const CLIENT_DSCP: u8 = 24; // CS3 — distinct from the EF (46) fallback
    let tmp = temp_dir(tag);
    let pki = TestPki::generate(&tmp);
    let sink = DscpUdpSink::start(sink_bind);
    let listen = format!("{listen_host}:{}", free_port());
    let config = load_single_rule(
        &tmp,
        &dtls_decrypt_rule(
            "dtls-pres",
            &listen,
            &sink.addr,
            &pki,
            r#","preserve_inbound_dscp":true"#,
        ),
    );

    run(&config, || {
        let opts = DtlsClientOpts {
            bind_addr: client_bind,
            client_dscp: Some(CLIENT_DSCP),
            ..Default::default()
        };
        let echoed = dtls_client_round_trip_opts(&listen, opts, b"preserve")
            .expect("DTLS decrypt should forward and echo back");
        assert_eq!(echoed, b"preserve");
        assert_eq!(
            wait_udp_dscp(&sink),
            Some(CLIENT_DSCP),
            "preserve must carry the client's inbound DSCP (not fall back to EF)"
        );
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dtls_decrypt_preserves_inbound_ipv4() {
    dtls_preserve_case(
        "dscp-dtls-pres-v4",
        "127.0.0.1",
        "127.0.0.1:0",
        "127.0.0.1:0",
    );
}

#[test]
fn dtls_decrypt_preserves_inbound_ipv6() {
    dtls_preserve_case("dscp-dtls-pres-v6", "[::1]", "[::1]:0", "[::1]:0");
}

// =============================================================================
//  Routing (TCP) — egress tagging
// =============================================================================
//
// NOTE ON LOOPBACK: Linux only surfaces the received DS field to a *receiver*
// via `IP_RECVTOS`/`IPV6_RECVTCLASS` for **UDP**; for **TCP** over the loopback
// interface the cmsg is not delivered (verified empirically). So these tests
// assert the data path stays intact while the safety-class egress QoS is
// applied on the splice upstream, and assert the DS field *only when* the
// platform actually surfaces it (e.g. a real NIC). The egress TOS value itself
// is proven at the syscall layer by the WP1 `set_dscp`/`apply_egress_qos`
// getsockopt round-trips and by the WP2 `QosPolicy::egress_dscp` unit tests.

fn routing_tag_case(tag: &str, listen_host: &str, sink_bind: &str) {
    let tmp = temp_dir(tag);
    let sink = DscpTcpSink::start(sink_bind);
    let listen = format!("{listen_host}:{}", free_port());
    let config = load_single_rule(&tmp, &routing_rule("route-ef", &listen, &sink.addr, ""));

    run(&config, || {
        let echoed = plain_round_trip(&listen, b"route-ef")
            .expect("safety routing should pass through and echo (egress QoS applied)");
        assert_eq!(echoed, b"route-ef");
        // The sink records DSCP before echoing, so this is already resolved.
        if let Some(d) = sink.last_dscp() {
            assert_eq!(
                d, DSCP_EF,
                "when the DS field is observable, safety routing must tag it EF (46)"
            );
        }
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn routing_tcp_safety_path_ipv4() {
    routing_tag_case("dscp-route-ef-v4", "127.0.0.1", "127.0.0.1:0");
}

#[test]
fn routing_tcp_safety_path_ipv6() {
    routing_tag_case("dscp-route-ef-v6", "[::1]", "[::1]:0");
}

// =============================================================================
//  Safety priority — functional
// =============================================================================

#[test]
fn safety_priority_never_deprioritizes_and_normal_is_noop() {
    use gateway::networking::socket_manager::apply_safety_priority;

    // Run on a dedicated thread so we never perturb the test runner's nice.
    let handle = std::thread::spawn(|| {
        let before = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };

        // Normal class is always a no-op.
        apply_safety_priority(TrafficClass::Normal);
        let after_normal = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
        assert_eq!(after_normal, before, "Normal class must not change nice");

        // Safety lowers nice (higher priority) when the process holds
        // CAP_SYS_NICE; unprivileged it is a silent no-op. Either way it must
        // never *raise* the nice value (never deprioritize safety).
        apply_safety_priority(TrafficClass::Safety);
        let after_safety = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
        assert!(
            after_safety <= before,
            "Safety must not deprioritize (nice {after_safety} > {before})"
        );
    });
    handle.join().unwrap();
}

// =============================================================================
//  Negative — config validation
// =============================================================================

#[test]
fn dscp_tag_out_of_range_is_rejected() {
    let tmp = temp_dir("dscp-neg");
    let listen = format!("127.0.0.1:{}", free_port());
    let json = format!(
        r#"{{
            "rules": [{{
                "name": "bad-dscp",
                "direction": "encrypt",
                "listen_addr": "{listen}",
                "listen_proto": "tcp",
                "upstream_addr": "127.0.0.1:9",
                "upstream_proto": "tcp",
                "security_provider": "routing",
                "traffic_class": "safety",
                "dscp_tag": 64
            }}]
        }}"#,
    );
    let path = tmp.join("gw.json");
    std::fs::write(&path, json).unwrap();
    let res = GatewayConfig::load(path.to_str().unwrap());
    assert!(
        res.is_err(),
        "dscp_tag > 63 must be rejected at config load"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
