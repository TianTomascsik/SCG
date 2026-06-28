//! WireGuard kernel-offload crypto provider (`security_provider = wireguard`).
//!
//! Two layers of coverage:
//!
//!   * **Relay data path (unprivileged, always runs)** — with
//!     `manage_interface = false` the provider does no kernel work; it only
//!     relays plaintext UDP through a (here, loopback) tunnel. These tests drive
//!     a full client → encrypt-rule → decrypt-rule → echo round-trip, exercising
//!     the bidirectional relay and the return-path tracking in-process.
//!
//!   * **Real interface provisioning (privileged, auto-skips)** — gated on
//!     [`wireguard_available`]: provisions a genuine kernel `wg` interface via
//!     the `wg`/`ip` tools and asserts it is created and torn down. Skips
//!     cleanly when the wireguard module / tools / CAP_NET_ADMIN are absent, so
//!     ordinary `cargo test` stays green. The full encrypted gateway-to-gateway
//!     path (two netns) is validated by the SESHAT perf-gate.

mod common;

use std::io;
use std::net::UdpSocket;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::dtls::PlainUdpEchoServer;
use common::{free_port, run_rules, temp_dir};

use gateway::management::config::GatewayConfig;
use gateway::security::wireguard_engine::wireguard_available;

// Two real X25519 keypairs (derived with OpenSSL). Benchmark/test material only
// — not secret. Gateway A's private pairs with Gateway B's public, and vice
// versa, exactly as a gateway-to-gateway WireGuard tunnel is keyed.
const A_PRIV: &str = "YIU06CCTQAWakOr4BzFQm12PHbSrbLS6AoHXwYRzf2s=";
const A_PUB: &str = "9ZbRNWy7qc+1SSM04oB0lsbRwi6JxBypHIJ+pDYuOyI=";
const B_PRIV: &str = "KIfGAY5onof5FlOhwqH83HbK00vFrhq/Za5thhxOYVQ=";
const B_PUB: &str = "E8wSpx1wNz0iDPMOswelLLwGrXSaWkZN+zhuve7QUEo=";

/// Send one datagram to a gateway rule and read the echo, retrying briefly
/// (plain UDP has no retransmission and the listener may still be binding).
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

/// Write a multi-rule config to `tmp/gw.json`, then load + validate it.
fn load_rules(tmp: &Path, rules: &[String]) -> GatewayConfig {
    load_rules_with_policy(tmp, rules, None)
}

/// Build a config from `rules`, optionally embedding a `policy` block. With no
/// policy the gateway is deny-by-default (`PolicyManager::new(None)`), so a
/// round-trip test must pass an allow policy to exercise the WireGuard relay's
/// policy gate (#38) in its allow path; omitting it exercises the deny path.
fn load_rules_with_policy(tmp: &Path, rules: &[String], policy: Option<&str>) -> GatewayConfig {
    let policy_field = policy
        .map(|p| format!(r#""policy": {p}, "#))
        .unwrap_or_default();
    let json = format!(r#"{{ {policy_field}"rules": [{}] }}"#, rules.join(","));
    let path = tmp.join("gw.json");
    std::fs::write(&path, json).unwrap();
    GatewayConfig::load(path.to_str().unwrap()).expect("config validates")
}

#[allow(clippy::too_many_arguments)]
fn wg_rule(
    name: &str,
    direction: &str,
    listen: &str,
    upstream: &str,
    iface: &str,
    private_key: &str,
    peer_public_key: &str,
    wg_listen_port: u16,
    peer_endpoint: &str,
    tunnel_local_ip: &str,
    peer_allowed_ips: &str,
    manage_interface: bool,
) -> String {
    format!(
        r#"{{
            "name": "{name}",
            "direction": "{direction}",
            "listen_addr": "{listen}",
            "listen_proto": "udp",
            "upstream_addr": "{upstream}",
            "upstream_proto": "udp",
            "security_provider": "wireguard",
            "manage_interface": {manage_interface},
            "wg_interface": "{iface}",
            "private_key": "{private_key}",
            "peer_public_key": "{peer_public_key}",
            "wg_listen_port": {wg_listen_port},
            "peer_endpoint": "{peer_endpoint}",
            "tunnel_local_ip": "{tunnel_local_ip}",
            "peer_allowed_ips": "{peer_allowed_ips}"
        }}"#
    )
}

fn run<F: FnOnce()>(config: &GatewayConfig, body: F) {
    let (handles, shutdown) = run_rules(config);
    body();
    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
}

/// Unprivileged: a full client → encrypt → decrypt → echo round-trip with
/// `manage_interface = false`. No kernel WireGuard is involved (the "tunnel" is
/// loopback), so this isolates and verifies the relay's bidirectional forwarding
/// and return-path tracking — the in-process logic — on any host.
#[test]
fn wireguard_relay_round_trip_external_interface() {
    let tmp = temp_dir("wg-relay");
    let echo = PlainUdpEchoServer::start();

    let p_enc = free_port();
    let p_dec = free_port();
    let wg_a = free_port();
    let wg_b = free_port();
    let enc_listen = format!("127.0.0.1:{p_enc}");
    let dec_listen = format!("127.0.0.1:{p_dec}");

    let encrypt = wg_rule(
        "wg-enc",
        "encrypt",
        &enc_listen,
        &dec_listen, // forward to the decrypt rule (stands in for the tunnel)
        "wg-ext-a",
        A_PRIV,
        B_PUB,
        wg_a,
        &format!("127.0.0.1:{wg_b}"),
        "10.0.0.1/32",
        "10.0.0.2/32",
        false,
    );
    let decrypt = wg_rule(
        "wg-dec",
        "decrypt",
        &dec_listen,
        &echo.addr,
        "wg-ext-b",
        B_PRIV,
        A_PUB,
        wg_b,
        &format!("127.0.0.1:{wg_a}"),
        "10.0.0.2/32",
        "10.0.0.1/32",
        false,
    );

    // Allow policy so the relay's policy gate (#38) admits normal-class traffic.
    let config = load_rules_with_policy(
        &tmp,
        &[encrypt, decrypt],
        Some(r#"{ "default_action": "allow" }"#),
    );
    run(&config, || {
        let echoed = udp_round_trip(&enc_listen, b"wg-relay-payload")
            .expect("datagram should round-trip through the WireGuard relay pair");
        assert_eq!(echoed, b"wg-relay-payload");
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

/// The WireGuard plaintext relay must enforce the policy whitelist / default-deny
/// like every other relay direction (#38). Under the deny-by-default policy
/// (no `policy` block) a `normal`-class datagram must NOT round-trip.
#[test]
fn wireguard_relay_policy_denied_is_not_forwarded() {
    let tmp = temp_dir("wg-deny");
    let echo = PlainUdpEchoServer::start();

    let p_enc = free_port();
    let p_dec = free_port();
    let wg_a = free_port();
    let wg_b = free_port();
    let enc_listen = format!("127.0.0.1:{p_enc}");
    let dec_listen = format!("127.0.0.1:{p_dec}");

    let encrypt = wg_rule(
        "wg-enc-d",
        "encrypt",
        &enc_listen,
        &dec_listen,
        "wg-deny-a",
        A_PRIV,
        B_PUB,
        wg_a,
        &format!("127.0.0.1:{wg_b}"),
        "10.0.0.1/32",
        "10.0.0.2/32",
        false,
    );
    let decrypt = wg_rule(
        "wg-dec-d",
        "decrypt",
        &dec_listen,
        &echo.addr,
        "wg-deny-b",
        B_PRIV,
        A_PUB,
        wg_b,
        &format!("127.0.0.1:{wg_a}"),
        "10.0.0.2/32",
        "10.0.0.1/32",
        false,
    );

    // No policy block => deny-by-default; the normal-class flow is dropped at
    // the gate and never reaches the echo backend.
    let config = load_rules(&tmp, &[encrypt, decrypt]);
    run(&config, || {
        assert!(
            udp_round_trip(&enc_listen, b"denied-payload").is_err(),
            "policy-denied WireGuard traffic must not round-trip (#38)"
        );
    });
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Privileged (auto-skips): provision a real kernel WireGuard interface through
/// the public rule API and assert it is created, then removed on shutdown.
#[test]
fn wireguard_provisions_real_interface_when_privileged() {
    if !wireguard_available() {
        eprintln!(
            "SKIP wireguard_provisions_real_interface_when_privileged: \
             needs the wireguard module, `wg`/`ip`, and CAP_NET_ADMIN"
        );
        return;
    }

    let tmp = temp_dir("wg-provision");
    let iface = "wg-scgtst0";
    let sys_path = format!("/sys/class/net/{iface}");
    // Clean slate in case a previous aborted run left the interface behind.
    let _ = std::process::Command::new("ip")
        .args(["link", "del", "dev", iface])
        .output();

    let listen = format!("127.0.0.1:{}", free_port());
    let dummy_upstream = format!("127.0.0.1:{}", free_port());
    let rule = wg_rule(
        "wg-prov",
        "encrypt",
        &listen,
        &dummy_upstream,
        iface,
        A_PRIV,
        B_PUB,
        free_port(),
        "192.0.2.2:51820",
        "10.0.0.1/32",
        "10.0.0.2/32",
        true,
    );
    let config = load_rules(&tmp, &[rule]);

    let (handles, shutdown) = run_rules(&config);

    // Wait for the rule thread to provision the interface.
    let created = wait_until(Duration::from_secs(3), || Path::new(&sys_path).exists());
    // Tear the rule down before asserting, so the interface is always cleaned up.
    shutdown.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    let removed = wait_until(Duration::from_secs(3), || !Path::new(&sys_path).exists());

    // Belt-and-suspenders cleanup if teardown somehow failed.
    let _ = std::process::Command::new("ip")
        .args(["link", "del", "dev", iface])
        .output();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        created,
        "WireGuard interface {iface} should have been provisioned"
    );
    assert!(
        removed,
        "WireGuard interface {iface} should have been removed on shutdown"
    );
}

fn wait_until<F: Fn() -> bool>(timeout: Duration, cond: F) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}
