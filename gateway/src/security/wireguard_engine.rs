//! WireGuard support — kernel-offload UDP encryption/decryption relay.
//!
//! Unlike the TLS/DTLS engines, the WireGuard provider does **not** perform any
//! per-packet cryptography in userspace. It provisions an in-kernel `wireguard`
//! interface (via the `wg` + `ip` tools — see the `admin` submodule) and then runs a plain
//! UDP relay that *steers* application datagrams through that tunnel, exactly as
//! `ktls` offloads the TLS record layer to the kernel. The kernel performs the
//! Noise_IKpsk2 handshake and ChaCha20-Poly1305 transport encryption.
//!
//! Topology (gateway-to-gateway):
//!
//! ```text
//! app --plain UDP--> [encrypt rule listen_addr] --relay--> peer tunnel IP
//!     kernel routes via wgEnc -> ENCRYPTS -> WG/UDP -> [decrypt rule wg port]
//!     -> kernel DECRYPTS -> plaintext on wgDec -> [decrypt rule] -> real upstream
//! ```
//!
//! The relay itself carries opaque datagram payloads, so WireGuard's
//! allowed-IPs / cryptokey routing is irrelevant to the payload — it only
//! governs which tunnel address the kernel encrypts toward.
//!
//! Running this provider requires the `wireguard` kernel module, the `wg` and
//! `ip` tools, and `CAP_NET_ADMIN`. When those are absent the provider fails
//! fast with a descriptive error (it never panics); tests gate on
//! [`wireguard_available`] and skip when unprivileged.

pub(crate) mod admin;

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::Ordering;

use log::{debug, error, info, warn};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::networking::socket_manager::{
    apply_safety_priority, bind_udp_socket, poll_two_fds, recvmsg_from_with_dscp,
    tune_socket_buffers,
};
use crate::processing::RuleContext;
use crate::security::relay::apply_geo_delay;
use crate::security::UDP_BUF_SIZE;

/// Maximum length of a Linux network interface name (`IFNAMSIZ - 1`).
const IFNAME_MAX: usize = 15;

// =============================================================================
//                     Secret — masked, zeroized key material
// =============================================================================

/// A base64-encoded secret (WireGuard private key or preshared key).
///
/// The inner string is zeroized on drop. Its `Debug` and `Display` never reveal
/// the bytes — they print `***` — so a secret can sit inside `WgProviderConfig`
/// without risk of leaking through a stray `{:?}`/log line.
pub(crate) struct Secret(Zeroizing<String>);

impl Secret {
    fn new(s: String) -> Self {
        Secret(Zeroizing::new(s))
    }

    /// Expose the raw base64 text. Used only to write the key to a `0600` file
    /// that `wg` reads — never to a log, an error message, or a process argv.
    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

// =============================================================================
//                     base64 / key validation (zero-dependency)
// =============================================================================

/// Decode standard (RFC 4648) base64 into bytes, validating the alphabet and
/// padding. Returns `Err(())` on any malformed input. The decoded buffer is
/// returned zeroizing so a decoded **private** key never lingers in memory.
fn b64_decode(s: &str) -> Result<Zeroizing<Vec<u8>>, ()> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(());
    }
    let chunks = bytes.len() / 4;
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(chunks * 3));
    for (ci, chunk) in bytes.chunks(4).enumerate() {
        let is_last = ci + 1 == chunks;
        let mut acc: u32 = 0;
        let mut pad = 0u8;
        for &c in chunk {
            acc <<= 6;
            if c == b'=' {
                pad += 1;
            } else if pad > 0 {
                // A non-pad character after a pad character is malformed.
                return Err(());
            } else {
                acc |= u32::from(val(c).ok_or(())?);
            }
        }
        // Padding is only ever valid in the final quad, and at most two bytes.
        if pad > 0 && (!is_last || pad > 2) {
            return Err(());
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Ok(out)
}

/// Validate that `value` is a base64-encoded **32-byte** key (the X25519 /
/// preshared-key size WireGuard uses). Errors mention only the field name —
/// never the key bytes.
fn validate_key32(field: &str, value: &str) -> Result<(), String> {
    match b64_decode(value) {
        Ok(bytes) if bytes.len() == 32 => Ok(()),
        Ok(bytes) => Err(format!(
            "wireguard: '{field}' decodes to {} bytes, expected 32 (a base64 X25519 key)",
            bytes.len()
        )),
        Err(()) => Err(format!("wireguard: '{field}' is not valid base64")),
    }
}

/// Validate a Linux interface name: 1..=15 chars, `[A-Za-z0-9_-]`, no `/` so it
/// cannot be confused for a path or option by `ip`/`wg`.
fn validate_iface(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > IFNAME_MAX {
        return Err(format!(
            "wireguard: 'wg_interface' must be 1..={IFNAME_MAX} characters"
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("wireguard: 'wg_interface' may only contain [A-Za-z0-9_-]".to_string());
    }
    Ok(())
}

/// Validate a `host:port` endpoint: must contain a port that parses as a `u16`.
fn validate_endpoint(field: &str, value: &str) -> Result<(), String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("wireguard: '{field}' must be HOST:PORT"))?;
    if host.is_empty() {
        return Err(format!("wireguard: '{field}' has an empty host"));
    }
    port.parse::<u16>()
        .map(|_| ())
        .map_err(|_| format!("wireguard: '{field}' has an invalid port"))
}

/// Validate a comma-separated list of IP addresses or CIDRs (e.g. allowed-IPs).
fn validate_cidr_list(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("wireguard: '{field}' must not be empty"));
    }
    for entry in value.split(',') {
        let entry = entry.trim();
        let ok = match entry.split_once('/') {
            Some((ip, prefix)) => {
                ip.parse::<std::net::IpAddr>().is_ok() && prefix.parse::<u8>().is_ok()
            }
            None => entry.parse::<std::net::IpAddr>().is_ok(),
        };
        if !ok {
            return Err(format!(
                "wireguard: '{field}' entry '{entry}' is not a valid IP or CIDR"
            ));
        }
    }
    Ok(())
}

// =============================================================================
//                     WgProviderConfig — parsed provider_params
// =============================================================================

/// Validated WireGuard provider configuration, parsed from a rule's
/// `provider_params`. Secret fields are masked in `Debug` and zeroized on drop.
pub(crate) struct WgProviderConfig {
    /// Kernel interface name to manage, e.g. `wg-scg0`.
    pub(crate) wg_interface: String,
    /// This gateway's X25519 private key (base64). Secret.
    pub(crate) private_key: Secret,
    /// UDP port the kernel WireGuard interface listens on.
    pub(crate) wg_listen_port: u16,
    /// The peer gateway's X25519 public key (base64). Public material.
    pub(crate) peer_public_key: String,
    /// The peer gateway's WireGuard endpoint on the real network (`host:port`).
    pub(crate) peer_endpoint: String,
    /// This interface's tunnel address (CIDR), e.g. `10.0.0.1/32`.
    pub(crate) tunnel_local_ip: String,
    /// Allowed-IPs / route for the peer, e.g. `10.0.0.2/32`.
    pub(crate) peer_allowed_ips: String,
    /// Optional preshared key (Noise_IKpsk2, base64). Secret.
    pub(crate) preshared_key: Option<Secret>,
    /// Optional persistent-keepalive interval in seconds.
    pub(crate) persistent_keepalive: Option<u16>,
    /// When `true` (default) the provider creates/destroys the interface. When
    /// `false` it attaches to a pre-existing, externally-provisioned interface.
    pub(crate) manage_interface: bool,
}

impl fmt::Debug for WgProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgProviderConfig")
            .field("wg_interface", &self.wg_interface)
            .field("private_key", &self.private_key)
            .field("wg_listen_port", &self.wg_listen_port)
            .field("peer_public_key", &self.peer_public_key)
            .field("peer_endpoint", &self.peer_endpoint)
            .field("tunnel_local_ip", &self.tunnel_local_ip)
            .field("peer_allowed_ips", &self.peer_allowed_ips)
            .field("preshared_key", &self.preshared_key)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("manage_interface", &self.manage_interface)
            .finish()
    }
}

/// Fetch a required string field from `provider_params`.
fn req_str<'a>(params: &'a HashMap<String, Value>, field: &str) -> Result<&'a str, String> {
    params
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("wireguard: '{field}' is required"))
}

/// Parse an optional `u16` field, rejecting out-of-range values without any
/// silent narrowing (`as`).
fn opt_u16(params: &HashMap<String, Value>, field: &str) -> Result<Option<u16>, String> {
    match params.get(field) {
        None => Ok(None),
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| format!("wireguard: '{field}' must be a non-negative integer"))?;
            let n = u16::try_from(n)
                .map_err(|_| format!("wireguard: '{field}' must be in 0..=65535"))?;
            Ok(Some(n))
        }
    }
}

impl WgProviderConfig {
    /// Parse and validate WireGuard parameters from a rule's `provider_params`.
    ///
    /// This is the security-critical entry point: it validates every field
    /// (key sizes, port/keepalive ranges, interface name, addresses) up front so
    /// `gateway --validate` rejects malformed config, and it never echoes key
    /// material into an error string. It does not touch the kernel.
    pub(crate) fn from_params(params: &HashMap<String, Value>) -> Result<Self, String> {
        let wg_interface = req_str(params, "wg_interface")?.to_string();
        validate_iface(&wg_interface)?;

        let private_key = req_str(params, "private_key")?;
        validate_key32("private_key", private_key)?;
        let private_key = Secret::new(private_key.to_string());

        let port = params
            .get("wg_listen_port")
            .and_then(Value::as_u64)
            .ok_or_else(|| "wireguard: 'wg_listen_port' is required".to_string())?;
        let wg_listen_port = u16::try_from(port)
            .map_err(|_| "wireguard: 'wg_listen_port' must be in 1..=65535".to_string())?;
        if wg_listen_port == 0 {
            return Err("wireguard: 'wg_listen_port' must be in 1..=65535".to_string());
        }

        let peer_public_key = req_str(params, "peer_public_key")?;
        validate_key32("peer_public_key", peer_public_key)?;
        let peer_public_key = peer_public_key.to_string();

        let peer_endpoint = req_str(params, "peer_endpoint")?.to_string();
        validate_endpoint("peer_endpoint", &peer_endpoint)?;

        let tunnel_local_ip = req_str(params, "tunnel_local_ip")?.to_string();
        validate_cidr_list("tunnel_local_ip", &tunnel_local_ip)?;

        let peer_allowed_ips = req_str(params, "peer_allowed_ips")?.to_string();
        validate_cidr_list("peer_allowed_ips", &peer_allowed_ips)?;

        let preshared_key = match params.get("preshared_key").and_then(Value::as_str) {
            Some(psk) if !psk.is_empty() => {
                validate_key32("preshared_key", psk)?;
                Some(Secret::new(psk.to_string()))
            }
            _ => None,
        };

        let persistent_keepalive = opt_u16(params, "persistent_keepalive")?.filter(|&n| n != 0);

        let manage_interface = params
            .get("manage_interface")
            .and_then(Value::as_bool)
            .unwrap_or(true);

        Ok(WgProviderConfig {
            wg_interface,
            private_key,
            wg_listen_port,
            peer_public_key,
            peer_endpoint,
            tunnel_local_ip,
            peer_allowed_ips,
            preshared_key,
            persistent_keepalive,
            manage_interface,
        })
    }
}

// =============================================================================
//                     Capability detection
// =============================================================================

/// Find an executable named `bin` on `PATH`.
fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let p = dir.join(bin);
                std::fs::metadata(&p).map(|m| m.is_file()).unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// True if the effective user is root or holds `CAP_NET_ADMIN` (bit 12).
fn has_net_admin() -> bool {
    // SAFETY: `geteuid` takes no arguments, has no preconditions, and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            if let Ok(caps) = u64::from_str_radix(hex.trim(), 16) {
                return caps & (1 << 12) != 0; // CAP_NET_ADMIN
            }
        }
    }
    false
}

/// True if the `wireguard` kernel module is loaded.
fn module_loaded() -> bool {
    std::path::Path::new("/sys/module/wireguard").exists()
}

/// Whether this host can run the kernel WireGuard provider: the `wg`/`ip` tools
/// are present, the `wireguard` module is loaded, and we have `CAP_NET_ADMIN`.
///
/// Integration tests and the SESHAT perf-gate use this to skip (rather than
/// fail) on unprivileged hosts.
pub fn wireguard_available() -> bool {
    which("wg") && which("ip") && module_loaded() && has_net_admin()
}

/// A human-readable explanation of why [`wireguard_available`] is false, for
/// fail-fast error messages and preflight warnings.
pub(crate) fn unavailable_reason() -> String {
    let mut missing = Vec::new();
    if !which("wg") {
        missing.push("the `wg` tool (install wireguard-tools)");
    }
    if !which("ip") {
        missing.push("the `ip` tool (install iproute2)");
    }
    if !module_loaded() {
        missing.push("the wireguard kernel module (try: modprobe wireguard)");
    }
    if !has_net_admin() {
        missing.push("CAP_NET_ADMIN (run as root or grant the capability)");
    }
    if missing.is_empty() {
        "WireGuard prerequisites are satisfied".to_string()
    } else {
        format!("WireGuard requires {}", missing.join(", "))
    }
}

// =============================================================================
//                     Plain UDP relay (kernel does the crypto)
// =============================================================================

/// Bind an ephemeral UDP socket of the same address family as `target` and
/// `connect` it, so `send`/`recv` go to/from that single peer.
fn connected_udp(target: &str) -> io::Result<UdpSocket> {
    let addr = target
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address resolved"))?;
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(addr)?;
    Ok(sock)
}

/// Relay plaintext UDP datagrams between this rule's `listen_addr` and a single
/// `upstream` target, in both directions, until shutdown.
///
/// For an **encrypt** rule, `upstream` is the peer's tunnel address — sending to
/// it routes through the kernel WireGuard interface, which encrypts. For a
/// **decrypt** rule, the listen socket is bound on the tunnel interface and
/// receives already-decrypted datagrams, which are forwarded to the real
/// backend. The relay carries opaque payloads and tracks the most recent source
/// for the return path (gateway-to-gateway is a single logical flow).
fn run_plain_udp_relay(ctx: &RuleContext, upstream: &str) -> Result<(), String> {
    let listen = bind_udp_socket(&ctx.listen_addr, ctx.transparent, &ctx.rule_name)
        .ok_or_else(|| format!("failed to bind UDP listen socket on {}", ctx.listen_addr))?;
    apply_safety_priority(ctx.traffic_class);
    listen.set_nonblocking(true).ok();
    tune_socket_buffers(listen.as_raw_fd(), ctx.sock_buf_size);
    let listen_is_v6 = listen.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    ctx.apply_egress_qos(listen.as_raw_fd(), listen_is_v6, None);
    ctx.enable_inbound_dscp_sampling(listen.as_raw_fd(), listen_is_v6);

    let upstream_sock = connected_udp(upstream)
        .map_err(|e| format!("failed to connect upstream {upstream}: {e}"))?;
    upstream_sock.set_nonblocking(true).ok();
    tune_socket_buffers(upstream_sock.as_raw_fd(), ctx.sock_buf_size);
    let up_is_v6 = upstream_sock
        .peer_addr()
        .map(|a| a.is_ipv6())
        .unwrap_or(false);
    ctx.apply_egress_qos(upstream_sock.as_raw_fd(), up_is_v6, None);

    let listen_fd = listen.as_raw_fd();
    let upstream_fd = upstream_sock.as_raw_fd();
    let mut fwd_buf = vec![0u8; UDP_BUF_SIZE];
    let mut rev_buf = vec![0u8; UDP_BUF_SIZE];
    let mut last_client: Option<SocketAddr> = None;

    ctx.metrics.connection_opened();
    info!(
        "[{}] WireGuard relay up: {} <-> {} (kernel-encrypted)",
        ctx.rule_name, ctx.listen_addr, upstream
    );

    while !ctx.shutdown.load(Ordering::Relaxed) {
        let (listen_ready, upstream_ready) = match poll_two_fds(listen_fd, upstream_fd, 0, 1000) {
            Ok(r) => r,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                error!("[{}] WireGuard relay poll error: {}", ctx.rule_name, e);
                break;
            }
        };

        // Forward: plaintext from the app side -> upstream (kernel encrypts).
        if listen_ready {
            loop {
                match recvmsg_from_with_dscp(listen_fd, &mut fwd_buf) {
                    Ok((n, peer, _dscp)) => {
                        last_client = Some(peer);
                        apply_geo_delay(ctx.simulated_delay_ms);
                        if let Err(e) = upstream_sock.send(&fwd_buf[..n]) {
                            if e.kind() != io::ErrorKind::WouldBlock {
                                debug!("[{}] upstream send dropped: {}", ctx.rule_name, e);
                            }
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        debug!("[{}] listen recv error: {}", ctx.rule_name, e);
                        break;
                    }
                }
            }
        }

        // Return: replies from upstream -> the most recent app client.
        if upstream_ready {
            loop {
                match upstream_sock.recv(&mut rev_buf) {
                    Ok(n) => {
                        if let Some(client) = last_client {
                            if let Err(e) = listen.send_to(&rev_buf[..n], client) {
                                if e.kind() != io::ErrorKind::WouldBlock {
                                    debug!("[{}] client send dropped: {}", ctx.rule_name, e);
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        debug!("[{}] upstream recv error: {}", ctx.rule_name, e);
                        break;
                    }
                }
            }
        }
    }

    ctx.metrics.connection_closed();
    Ok(())
}

/// Shared startup for both directions: validate config, check capabilities,
/// provision the kernel interface (unless attaching to an external one), run the
/// relay, then tear the interface down on shutdown.
fn run_wireguard_relay(ctx: &RuleContext) -> Result<(), String> {
    let cfg = WgProviderConfig::from_params(&ctx.provider_params)
        .map_err(|e| format!("[{}] {}", ctx.rule_name, e))?;

    if cfg.manage_interface {
        // Creating/configuring a kernel interface needs the wireguard module,
        // the `wg`/`ip` tools, and CAP_NET_ADMIN. Fail fast with a clear reason.
        if !wireguard_available() {
            return Err(format!("[{}] {}", ctx.rule_name, unavailable_reason()));
        }
        admin::provision(&cfg)
            .map_err(|e| format!("[{}] WireGuard provisioning failed: {}", ctx.rule_name, e))?;
    } else {
        // Attaching to an externally-provisioned interface (e.g. set up by
        // SCG-deploy-methods): the gateway only relays plaintext through the
        // existing tunnel, so it needs no privilege of its own.
        debug!(
            "[{}] WireGuard manage_interface=false; attaching to existing '{}'",
            ctx.rule_name, cfg.wg_interface
        );
    }

    let result = run_plain_udp_relay(ctx, &ctx.upstream_addr);

    if cfg.manage_interface {
        if let Err(e) = admin::teardown(&cfg.wg_interface) {
            warn!(
                "[{}] WireGuard interface '{}' teardown failed: {}",
                ctx.rule_name, cfg.wg_interface, e
            );
        }
    }

    result
}

/// Encrypt direction: this gateway steers plaintext into the tunnel toward the
/// peer gateway, which the kernel encrypts.
pub(crate) fn run_wireguard_encrypt_relay(ctx: &RuleContext) -> Result<(), String> {
    run_wireguard_relay(ctx)
}

/// Decrypt direction: this gateway receives kernel-decrypted plaintext from the
/// tunnel and forwards it to the real upstream.
pub(crate) fn run_wireguard_decrypt_relay(ctx: &RuleContext) -> Result<(), String> {
    run_wireguard_relay(ctx)
}

// =============================================================================
//                                  Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A known-good base64 X25519 key (32 bytes → 44 base64 chars).
    const KEY_A: &str = "QID5p0yqzAGq2gA1nF3w8H6+6N0eX0K3nG3vJ8h0VFg=";
    const KEY_B: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

    fn base_params() -> HashMap<String, Value> {
        let mut p = HashMap::new();
        p.insert("wg_interface".into(), json!("wg-test0"));
        p.insert("private_key".into(), json!(KEY_A));
        p.insert("wg_listen_port".into(), json!(51820));
        p.insert("peer_public_key".into(), json!(KEY_B));
        p.insert("peer_endpoint".into(), json!("192.0.2.2:51820"));
        p.insert("tunnel_local_ip".into(), json!("10.0.0.1/32"));
        p.insert("peer_allowed_ips".into(), json!("10.0.0.2/32"));
        p
    }

    #[test]
    fn b64_decodes_32_byte_key() {
        assert_eq!(b64_decode(KEY_A).unwrap().len(), 32);
        assert_eq!(b64_decode(KEY_B).unwrap().len(), 32);
    }

    #[test]
    fn b64_rejects_garbage() {
        assert!(b64_decode("not base64!!").is_err());
        assert!(b64_decode("====").is_err());
        assert!(b64_decode("AB=C").is_err()); // pad before data
    }

    #[test]
    fn parses_valid_config() {
        let cfg = WgProviderConfig::from_params(&base_params()).expect("valid config");
        assert_eq!(cfg.wg_interface, "wg-test0");
        assert_eq!(cfg.wg_listen_port, 51820);
        assert!(cfg.manage_interface);
        assert!(cfg.preshared_key.is_none());
        assert!(cfg.persistent_keepalive.is_none());
    }

    #[test]
    fn parses_optional_psk_and_keepalive() {
        let mut p = base_params();
        p.insert("preshared_key".into(), json!(KEY_B));
        p.insert("persistent_keepalive".into(), json!(25));
        p.insert("manage_interface".into(), json!(false));
        let cfg = WgProviderConfig::from_params(&p).expect("valid");
        assert!(cfg.preshared_key.is_some());
        assert_eq!(cfg.persistent_keepalive, Some(25));
        assert!(!cfg.manage_interface);
    }

    #[test]
    fn zero_keepalive_is_disabled() {
        let mut p = base_params();
        p.insert("persistent_keepalive".into(), json!(0));
        let cfg = WgProviderConfig::from_params(&p).expect("valid");
        assert_eq!(cfg.persistent_keepalive, None);
    }

    #[test]
    fn rejects_missing_private_key() {
        let mut p = base_params();
        p.remove("private_key");
        let err = WgProviderConfig::from_params(&p).unwrap_err();
        assert!(err.contains("private_key"));
    }

    #[test]
    fn rejects_short_key_without_leaking_bytes() {
        let mut p = base_params();
        let short = "QUJD"; // base64 of "ABC" → 3 bytes
        p.insert("private_key".into(), json!(short));
        let err = WgProviderConfig::from_params(&p).unwrap_err();
        assert!(err.contains("private_key"));
        assert!(err.contains("expected 32"));
        assert!(!err.contains(short), "error must not echo the key bytes");
    }

    #[test]
    fn rejects_non_base64_key() {
        let mut p = base_params();
        p.insert(
            "peer_public_key".into(),
            json!("################################"),
        );
        let err = WgProviderConfig::from_params(&p).unwrap_err();
        assert!(err.contains("peer_public_key"));
        assert!(err.contains("base64"));
    }

    #[test]
    fn rejects_keepalive_overflow() {
        let mut p = base_params();
        p.insert("persistent_keepalive".into(), json!(70000));
        let err = WgProviderConfig::from_params(&p).unwrap_err();
        assert!(err.contains("persistent_keepalive"));
    }

    #[test]
    fn rejects_bad_interface_name() {
        let mut p = base_params();
        p.insert("wg_interface".into(), json!("wg/with/slashes"));
        assert!(WgProviderConfig::from_params(&p).is_err());

        let mut p = base_params();
        p.insert("wg_interface".into(), json!("this-name-is-way-too-long"));
        assert!(WgProviderConfig::from_params(&p).is_err());
    }

    #[test]
    fn rejects_bad_endpoint_and_cidr() {
        let mut p = base_params();
        p.insert("peer_endpoint".into(), json!("no-port"));
        assert!(WgProviderConfig::from_params(&p).is_err());

        let mut p = base_params();
        p.insert("peer_allowed_ips".into(), json!("not-an-ip"));
        assert!(WgProviderConfig::from_params(&p).is_err());
    }

    #[test]
    fn debug_masks_secrets() {
        let cfg = WgProviderConfig::from_params(&base_params()).expect("valid");
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("***"), "private key must be masked");
        assert!(!dbg.contains(KEY_A), "private key bytes must not appear");
        // The public key is not secret and may appear.
        assert!(dbg.contains("peer_public_key"));
    }

    #[test]
    fn secret_debug_is_masked() {
        let s = Secret::new(KEY_A.to_string());
        assert_eq!(format!("{s:?}"), "***");
        assert_eq!(s.expose(), KEY_A);
    }
}
