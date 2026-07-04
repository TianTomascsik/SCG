//! DTLS support -- native UDP encryption/decryption relay.
//!
//! Provides DTLS (Datagram TLS) relaying that preserves UDP semantics:
//! no ordering guarantee, no head-of-line blocking. Unlike UDP-over-TLS
//! (which tunnels through TCP), DTLS keeps the transport as UDP end-to-end.

use crate::management::cert_store::{get_or_init_cert, load_identity_pem};
use crate::networking::socket_manager::{
    apply_safety_priority, bind_udp_socket, peek_from_with_dscp, poll_two_fds,
    recvmsg_from_with_dscp, set_nonblocking_fd, tune_socket_buffers, write_all_nb,
};
use crate::processing::RuleContext;
use crate::security::relay::apply_geo_delay;
use crate::security::tls_engine::params::{TlsSecurityParams, VerifyMode};
use crate::security::udp_session::{session_admitted, stale_peers};
use crate::security::{RELAY_BUF_SIZE, UDP_BUF_SIZE};

use crate::management::config::Proto;
use crate::management::telemetry::{format_rate, ConnectionMetrics};
use log::{debug, error, info, warn};

use openssl::ssl::{
    ErrorCode, SslAcceptor, SslConnector, SslContextBuilder, SslMethod, SslOptions, SslRef,
    SslStream, SslVerifyMode, SslVersion,
};

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// =============================================================================
//                     DtlsUdpStream -- UDP wrapper for OpenSSL DTLS
// =============================================================================

/// Wraps a connected UdpSocket to implement Read + Write for OpenSSL's DTLS.
/// "Connected" means `socket.connect(peer)` was called, so send()/recv() work.
#[derive(Debug)]
pub(crate) struct DtlsUdpStream {
    sock: UdpSocket,
}

impl DtlsUdpStream {
    fn new(sock: UdpSocket) -> Self {
        Self { sock }
    }
}

impl Read for DtlsUdpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.sock.recv(buf)
    }
}

impl Write for DtlsUdpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sock.send(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// =============================================================================
//                     DTLS builders
// =============================================================================

/// Pin the DTLS protocol version (min == max).
fn pin_dtls_version(builder: &mut SslContextBuilder, is_dtls10: bool) -> Result<(), String> {
    let v = if is_dtls10 {
        SslVersion::DTLS1
    } else {
        SslVersion::DTLS1_2
    };
    builder
        .set_min_proto_version(Some(v))
        .map_err(|e| format!("dtls min version: {e}"))?;
    builder
        .set_max_proto_version(Some(v))
        .map_err(|e| format!("dtls max version: {e}"))?;
    Ok(())
}

/// Apply the DTLS cipher policy: an explicit `cipher_list` override wins,
/// otherwise a version-appropriate default (DTLS 1.0 = CBC, DTLS 1.2 = AEAD).
/// Both defaults offer ECDHE-ECDSA/RSA so either an RSA or an ECDSA identity
/// works and the handshake has forward secrecy.
fn set_dtls_cipher_list(
    builder: &mut SslContextBuilder,
    params: &TlsSecurityParams,
    is_dtls10: bool,
) -> Result<(), String> {
    let list = params.cipher_list.clone().unwrap_or_else(|| {
        if is_dtls10 {
            // DTLS 1.0 predates AEAD — CBC/SHA-1 only. SECLEVEL is lowered so
            // the legacy MAC suites needed for interop are not filtered out.
            "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA:AES256-SHA:@SECLEVEL=0"
                .to_string()
        } else {
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
             ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
                .to_string()
        }
    });
    builder
        .set_cipher_list(&list)
        .map_err(|e| format!("dtls cipher list '{list}': {e}"))
}

/// Load the configured CA bundle into the trust store, if any.
fn set_dtls_ca(builder: &mut SslContextBuilder, params: &TlsSecurityParams) -> Result<(), String> {
    if let Some(ref ca) = params.ca_path {
        builder
            .set_ca_file(ca)
            .map_err(|e| format!("dtls ca_file '{}': {e}", ca.display()))?;
    }
    Ok(())
}

/// Server-side peer verification: mutual auth requires + verifies a client cert.
fn apply_dtls_acceptor_verify(
    builder: &mut SslContextBuilder,
    params: &TlsSecurityParams,
) -> Result<(), String> {
    match params.verify {
        VerifyMode::Mutual => {
            builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            set_dtls_ca(builder, params)?;
        }
        VerifyMode::None | VerifyMode::Server => builder.set_verify(SslVerifyMode::NONE),
    }
    Ok(())
}

/// Client-side peer verification: server or mutual mode verifies the peer cert
/// against the configured CA.
fn apply_dtls_connector_verify(
    builder: &mut SslContextBuilder,
    params: &TlsSecurityParams,
) -> Result<(), String> {
    match params.verify {
        VerifyMode::Server | VerifyMode::Mutual => {
            builder.set_verify(SslVerifyMode::PEER);
            set_dtls_ca(builder, params)?;
        }
        VerifyMode::None => builder.set_verify(SslVerifyMode::NONE),
    }
    Ok(())
}

/// Build a DTLS `SslConnector` (client side) from resolved security params.
///
/// Honours the verify mode (server/mutual cert verification + CA trust store),
/// an optional client identity for mutual auth, and the DTLS-version cipher
/// policy. With no params this is the legacy behaviour: verify none, no client
/// cert, version-default ciphers.
fn build_dtls_connector(params: &TlsSecurityParams) -> Result<SslConnector, String> {
    let mut builder =
        SslConnector::builder(SslMethod::dtls()).map_err(|e| format!("dtls connector: {e}"))?;

    let is_dtls10 = matches!(params.version.as_deref(), Some("dtls1.0"));
    pin_dtls_version(&mut builder, is_dtls10)?;
    set_dtls_cipher_list(&mut builder, params, is_dtls10)?;

    // Optional client identity (required when the upstream demands mutual auth).
    if let Some(ref cert_path) = params.cert_path {
        let key_path = params
            .key_path
            .as_ref()
            .ok_or_else(|| "cert_path requires key_path".to_string())?;
        let (pkey, cert) = load_identity_pem(cert_path, key_path)?;
        builder
            .set_certificate(&cert)
            .map_err(|e| format!("dtls client cert: {e}"))?;
        builder
            .set_private_key(&pkey)
            .map_err(|e| format!("dtls client key: {e}"))?;
        builder
            .check_private_key()
            .map_err(|e| format!("dtls client key mismatch: {e}"))?;
    }

    apply_dtls_connector_verify(&mut builder, params)?;
    Ok(builder.build())
}

/// Maximum time a DTLS decrypt accept may block on one peer's handshake. Kept
/// short so a peer that completes the stateless cookie exchange but then stalls
/// the handshake cannot wedge the (serial) accept loop for long. Combined with
/// the cookie exchange below, this bounds the spoofed-source DoS (CWE-400).
/// Shares the gateway-wide [`crate::security::HANDSHAKE_TIMEOUT`] with the TCP
/// TLS/kTLS handshake bound (DoS-01).
const DTLS_HANDSHAKE_TIMEOUT: Duration = crate::security::HANDSHAKE_TIMEOUT;

thread_local! {
    /// Peer address the current DTLS accept is bound to. The decrypt accept loop
    /// is serial and connects its socket to one peer before `accept()`, so the
    /// cookie callbacks (invoked synchronously on this thread during `accept`)
    /// can read the peer here to bind the cookie to it.
    static CURRENT_DTLS_PEER: std::cell::Cell<Option<SocketAddr>> =
        const { std::cell::Cell::new(None) };
}

/// Process-lifetime secret keying the DTLS HelloVerifyRequest cookie HMAC.
///
/// Fails **closed** if the CSPRNG is unavailable (KC-03): the sticky `None` makes
/// every cookie compute/verify error out rather than falling back to an all-zero
/// (predictable) key. The DTLS rule refuses to start (see `build_dtls_acceptor`).
fn dtls_cookie_secret() -> Result<&'static [u8; 32], openssl::error::ErrorStack> {
    static SECRET: std::sync::OnceLock<Option<[u8; 32]>> = std::sync::OnceLock::new();
    SECRET
        .get_or_init(|| {
            let mut s = [0u8; 32];
            openssl::rand::rand_bytes(&mut s).ok().map(|_| s)
        })
        .as_ref()
        .ok_or_else(openssl::error::ErrorStack::get)
}

/// Compute the stateless cookie `HMAC-SHA256(secret, peer)` into `out`,
/// returning the number of bytes written (truncated to `out`).
fn compute_dtls_cookie(
    peer: &SocketAddr,
    out: &mut [u8],
) -> Result<usize, openssl::error::ErrorStack> {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;
    let key = PKey::hmac(dtls_cookie_secret()?)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(peer.to_string().as_bytes())?;
    let mac = signer.sign_to_vec()?;
    let n = mac.len().min(out.len());
    out[..n].copy_from_slice(&mac[..n]);
    Ok(n)
}

/// DTLS cookie-generate callback: bind the cookie to the connected peer.
fn dtls_cookie_generate(
    _ssl: &mut SslRef,
    buf: &mut [u8],
) -> Result<usize, openssl::error::ErrorStack> {
    match CURRENT_DTLS_PEER.with(|c| c.get()) {
        Some(peer) => compute_dtls_cookie(&peer, buf),
        None => Ok(0),
    }
}

/// DTLS cookie-verify callback: accept only a cookie matching the peer binding,
/// compared in constant time.
fn dtls_cookie_verify(_ssl: &mut SslRef, cookie: &[u8]) -> bool {
    let Some(peer) = CURRENT_DTLS_PEER.with(|c| c.get()) else {
        return false;
    };
    let mut expected = [0u8; 32];
    match compute_dtls_cookie(&peer, &mut expected) {
        Ok(n) if n == cookie.len() => openssl::memcmp::eq(&expected[..n], cookie),
        _ => false,
    }
}

/// Build a DTLS `SslAcceptor` (server side) from resolved security params.
///
/// Uses a file-based identity when `cert_path`/`key_path` are configured, else
/// the self-signed development certificate. Applies verify mode (mutual auth
/// requires a client cert), CA trust store, and the DTLS-version cipher policy.
fn build_dtls_acceptor(params: &TlsSecurityParams) -> Result<SslAcceptor, String> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::dtls())
        .map_err(|e| format!("dtls acceptor: {e}"))?;

    match (&params.cert_path, &params.key_path) {
        (Some(cert_path), Some(key_path)) => {
            let (pkey, cert) = load_identity_pem(cert_path, key_path)?;
            builder
                .set_private_key(&pkey)
                .map_err(|e| format!("dtls key: {e}"))?;
            builder
                .set_certificate(&cert)
                .map_err(|e| format!("dtls cert: {e}"))?;
        }
        _ => {
            let (pkey, cert) = get_or_init_cert().map_err(|e| format!("dtls self-signed: {e}"))?;
            builder
                .set_private_key(pkey)
                .map_err(|e| format!("dtls key: {e}"))?;
            builder
                .set_certificate(cert)
                .map_err(|e| format!("dtls cert: {e}"))?;
        }
    }
    builder
        .check_private_key()
        .map_err(|e| format!("dtls key mismatch: {e}"))?;

    let is_dtls10 = matches!(params.version.as_deref(), Some("dtls1.0"));
    pin_dtls_version(&mut builder, is_dtls10)?;
    set_dtls_cipher_list(&mut builder, params, is_dtls10)?;
    apply_dtls_acceptor_verify(&mut builder, params)?;

    // Stateless DTLS cookie exchange (RFC 6347 §4.2.1): the client must echo a
    // keyed-HMAC cookie, bound to its (connected) source address, before the
    // server commits to the expensive handshake — blunting spoofed-source
    // floods. The cookie is transparent to compliant clients (OpenSSL answers
    // the HelloVerifyRequest automatically).
    //
    // SSL_OP_COOKIE_EXCHANGE is REQUIRED: without it `SSL_accept` skips the
    // HelloVerifyRequest round-trip entirely and the callbacks below are never
    // invoked (the cookie protection would be silently inert).
    builder.set_options(SslOptions::COOKIE_EXCHANGE);
    // Eagerly key the cookie secret so a DTLS rule fails to start on RNG failure
    // (KC-03), rather than accepting handshakes with a predictable/zero cookie.
    dtls_cookie_secret()
        .map_err(|e| format!("DTLS cookie secret unavailable (RNG failure): {e}"))?;
    builder.set_cookie_generate_cb(dtls_cookie_generate);
    builder.set_cookie_verify_cb(dtls_cookie_verify);
    Ok(builder.build())
}

// =============================================================================
//                     SO_REUSEPORT UDP socket
// =============================================================================

/// Create a UDP socket with SO_REUSEADDR + SO_REUSEPORT set **before** bind.
/// This is required for multiple sockets bound to the same address (one per
/// DTLS peer -- the connected socket for the active session and the listen
/// socket for incoming connections).
fn create_reuseport_udp(addr: &str) -> io::Result<UdpSocket> {
    let parsed: SocketAddr = addr
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let domain = if parsed.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: `libc::socket` takes only by-value integer arguments (`domain`,
    // type, protocol) and allocates a fresh kernel resource; there are no
    // pointers or borrowed state involved. The returned fd is checked for the
    // `< 0` error case immediately below before any further use.
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let one: libc::c_int = 1;
    // SAFETY: `fd` is the valid socket descriptor returned by `libc::socket`
    // above (verified `>= 0`). For both calls the option-value pointer is
    // `&one`, a live `libc::c_int` that outlives the calls, and the length
    // passed is exactly `size_of::<c_int>()`, matching the pointee — so the
    // kernel reads a correctly-sized, fully-initialised option value.
    // (L19): both results are checked — the decrypt accept loop re-binds the
    // listen address every iteration alongside per-peer connected sockets, so
    // a silently-failed REUSEADDR/REUSEPORT would surface later as a confusing
    // AddrInUse that kills the whole rule after one session.
    let opt_ret = unsafe {
        let r1 = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let r2 = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if r1 == 0 {
            r2
        } else {
            r1
        }
    };
    if opt_ret != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: `fd` is the valid descriptor from `libc::socket` above and is
        // not used after this call; closing it exactly once on the error path
        // avoids leaking the descriptor.
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    let bind_result = match parsed {
        SocketAddr::V4(ref v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `fd` is the valid socket descriptor from `libc::socket`
            // above. `sa` is a fully-initialised `sockaddr_in` (all fields set)
            // that lives for the duration of the call; it is passed as a
            // `*const sockaddr` with length exactly `size_of::<sockaddr_in>()`,
            // so the kernel reads a correctly-typed, in-bounds address struct.
            // The return value is checked via `bind_result` below.
            unsafe {
                libc::bind(
                    fd,
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(ref v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: `fd` is the valid socket descriptor from `libc::socket`
            // above. `sa` is a fully-initialised `sockaddr_in6` (all fields set)
            // that lives for the duration of the call; it is passed as a
            // `*const sockaddr` with length exactly `size_of::<sockaddr_in6>()`,
            // so the kernel reads a correctly-typed, in-bounds address struct.
            // The return value is checked via `bind_result` below.
            unsafe {
                libc::bind(
                    fd,
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };

    if bind_result < 0 {
        let e = io::Error::last_os_error();
        // SAFETY: `fd` is the valid descriptor opened by `libc::socket` above
        // and has not yet been wrapped in any owning type, so this function
        // still exclusively owns it. Closing it exactly once here on the bind
        // failure path releases the kernel resource; `fd` is not used again
        // afterwards (we return immediately), preventing any double-close.
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }

    // SAFETY: `fd` is a valid, open SOCK_DGRAM descriptor that was just
    // successfully created and bound, and ownership of it has not been
    // transferred anywhere else. `from_raw_fd` takes sole ownership, so the
    // resulting `UdpSocket` is the unique owner responsible for closing `fd`.
    Ok(unsafe { UdpSocket::from_raw_fd(fd) })
}

/// Poll `revents` mask meaning "there is something to service on this fd":
/// data, hangup, **or an error condition** (H6). `poll()` reports `POLLERR`
/// and `POLLNVAL` regardless of the requested `events`; on a connected UDP
/// socket a pending ICMP error (e.g. port-unreachable from a restarted
/// upstream) sets `POLLERR`, and the error is only cleared by a subsequent
/// recv/send. Masking on `POLLIN|POLLHUP` alone would leave `poll()` returning
/// immediately every iteration → a 100%-CPU busy-spin that also pins the
/// socket and its bounded session slot. Including the error bits lets the
/// following read surface the pending error and hit the teardown path.
#[inline]
fn revents_ready(revents: libc::c_short) -> bool {
    revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
}

/// Classify a non-blocking DTLS `ssl_write` error: a transient
/// `WANT_READ`/`WANT_WRITE` (send-buffer backpressure or a renegotiation read)
/// means "drop this one datagram, keep the session" (M23); anything else is a
/// fatal session error. For UDP a blocked record cannot be resumed mid-write,
/// so dropping the datagram is the correct recovery — tearing the whole DTLS
/// session down on momentary backpressure would force a full re-handshake.
#[inline]
fn dtls_write_is_fatal(err: &openssl::ssl::Error) -> bool {
    !matches!(err.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE)
}

// =============================================================================
//                   ENCRYPT DIRECTION: UDP -> DTLS (native UDP)
// =============================================================================

/// Shut down and remove every DTLS session idle for at least `ttl` (selection via
/// the shared [`stale_peers`](crate::security::udp_session::stale_peers) helper).
fn evict_idle_sessions(
    sessions: &mut HashMap<SocketAddr, (SslStream<DtlsUdpStream>, Instant)>,
    ttl: Duration,
    now: Instant,
    rule_name: &str,
) {
    let snapshot: Vec<(SocketAddr, Instant)> = sessions
        .iter()
        .map(|(peer, (_, last))| (*peer, *last))
        .collect();
    for peer in stale_peers(&snapshot, ttl, now) {
        if let Some((mut ssl, _)) = sessions.remove(&peer) {
            let _ = ssl.shutdown();
            debug!(
                "[{}] DTLS session evicted (idle {:?}) for {}",
                rule_name, ttl, peer
            );
        }
    }
}

/// DTLS encrypt relay: receives plaintext UDP datagrams, encrypts each via
/// DTLS, and sends as encrypted UDP to upstream. Preserves UDP semantics:
/// no ordering guarantee, no head-of-line blocking.
///
/// Unlike UDP-over-TLS (which tunnels through TCP), DTLS keeps the transport
/// as UDP end-to-end -- lower latency but packets can be lost.
pub(crate) fn run_dtls_encrypt_relay(ctx: &RuleContext) {
    // Bind plain UDP socket to receive unencrypted traffic
    let plain_socket = match bind_udp_socket(&ctx.listen_addr, ctx.transparent, &ctx.rule_name) {
        Some(s) => s,
        None => return,
    };

    // Safety traffic always runs at elevated thread priority.
    apply_safety_priority(ctx.traffic_class);

    // Non-blocking for poll()-based bidirectional I/O
    plain_socket.set_nonblocking(true).ok();
    tune_socket_buffers(plain_socket.as_raw_fd(), ctx.sock_buf_size);
    // Prioritise the client-facing UDP return path; sample inbound DSCP when
    // the rule preserves it.
    let plain_is_v6 = plain_socket
        .local_addr()
        .map(|a| a.is_ipv6())
        .unwrap_or(false);
    ctx.apply_egress_qos(plain_socket.as_raw_fd(), plain_is_v6, None);
    ctx.enable_inbound_dscp_sampling(plain_socket.as_raw_fd(), plain_is_v6);

    // Resolve the upstream ONCE for the whole relay (M4/#73, H5/M21).
    // `auto` is rejected at config validation because DTLS has no
    // original-destination recovery (TRA #74); this defensive guard stops a
    // stray "auto" that somehow reached runtime from being dialled literally.
    // A DNS-name upstream is resolved here (never per datagram) so both the
    // policy gate and session setup use the concrete address; an unresolvable
    // name fails closed (the rule cannot forward).
    if ctx.upstream_addr == "auto" {
        error!(
            "[{}] DTLS does not support upstream_addr=\"auto\" (rejected at validation); \
             not relaying",
            ctx.rule_name
        );
        return;
    }
    let target_addr = match ctx.resolve_upstream_target(&ctx.upstream_addr) {
        Some(a) => a,
        None => {
            error!(
                "[{}] cannot resolve DTLS upstream '{}'; not relaying",
                ctx.rule_name, ctx.upstream_addr
            );
            return;
        }
    };

    // Resolve typed security parameters and build the DTLS connector.
    let tls_params =
        match TlsSecurityParams::from_params(&ctx.provider_params, ctx.protocol_version.as_deref())
        {
            Ok(p) => p,
            Err(e) => {
                error!("[{}] DTLS parameter error: {}", ctx.rule_name, e);
                return;
            }
        };
    let connector = match build_dtls_connector(&tls_params) {
        Ok(c) => c,
        Err(e) => {
            error!("[{}] DTLS connector error: {}", ctx.rule_name, e);
            return;
        }
    };

    // Per-peer DTLS sessions (since UDP is connectionless, we track sessions by
    // peer addr). Each entry carries its last-activity instant so idle sessions
    // can be evicted; admission is bounded by `max_sessions` to resist a
    // source-address-spoofing flood (CWE-400).
    let mut sessions: HashMap<SocketAddr, (SslStream<DtlsUdpStream>, Instant)> = HashMap::new();
    let max_sessions = tls_params.max_sessions;
    let idle_ttl = Duration::from_secs(tls_params.idle_ttl_secs);
    let mut last_evict = Instant::now();
    let mut conn_metrics =
        ConnectionMetrics::with_rule_metrics("encrypt-dtls", "dtls", ctx.metrics.clone());
    ctx.metrics.connection_opened();

    let mut fwd_buf = vec![0u8; UDP_BUF_SIZE];
    let mut rev_buf = vec![0u8; UDP_BUF_SIZE];
    let plain_fd = plain_socket.as_raw_fd();

    // Reused across iterations so a steady-state wakeup does not allocate two
    // fresh Vecs proportional to the session count every loop (L26). `clear()`
    // keeps the capacity.
    let mut pollfds: Vec<libc::pollfd> = Vec::new();
    let mut session_snapshot: Vec<(SocketAddr, RawFd)> = Vec::new();

    while !ctx.shutdown.load(Ordering::Relaxed) {
        // Reclaim idle sessions at most ~once per second so a flood of
        // short-lived peers cannot pin resources between admissions.
        let now = Instant::now();
        if now.saturating_duration_since(last_evict) >= Duration::from_secs(1) {
            evict_idle_sessions(&mut sessions, idle_ttl, now, &ctx.rule_name);
            last_evict = now;
        }

        // Build dynamic pollfd array: [plain_socket, ...dtls_upstream_fds]
        pollfds.clear();
        pollfds.push(libc::pollfd {
            fd: plain_fd,
            events: libc::POLLIN,
            revents: 0,
        });
        session_snapshot.clear();
        session_snapshot.extend(
            sessions
                .iter()
                .map(|(peer, (ssl, _))| (*peer, ssl.get_ref().sock.as_raw_fd())),
        );
        for &(_, fd) in &session_snapshot {
            pollfds.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }

        // SAFETY: `pollfds` is a live `Vec<libc::pollfd>` whose every element is
        // fully initialised above; `as_mut_ptr()`/`len()` describe exactly that
        // contiguous, writable buffer, and the length passed matches the number
        // of elements, so `poll` only reads/writes in-bounds entries for the
        // duration of this call (the Vec outlives it). The result is checked below.
        let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 1000) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if ret == 0 {
            continue;
        }

        // -- Forward: plain UDP -> DTLS (encrypt and send to upstream) --------
        if pollfds[0].revents & libc::POLLIN != 0 {
            loop {
                match recvmsg_from_with_dscp(plain_fd, &mut fwd_buf) {
                    Ok((n, peer_addr, inbound_dscp)) => {
                        // Admission control FIRST (DoS-06): refuse a *new* peer once
                        // the session cap is reached, before spending any classify /
                        // traffic-cache work on it. The cap only ever drops *more*
                        // than the policy gate would, and every datagram that reaches
                        // the policy check and session creation below still passes the
                        // gate — so ordering admission first never bypasses policy.
                        // Idle sessions are reclaimed by the periodic eviction above.
                        if !sessions.contains_key(&peer_addr)
                            && !session_admitted(sessions.len(), max_sessions)
                        {
                            warn!(
                                "[{}] DTLS session cap {} reached; dropping new peer {}",
                                ctx.rule_name, max_sessions, peer_addr
                            );
                            continue;
                        }

                        // Policy check per datagram against the pre-resolved
                        // upstream address (DP-07, fail closed).
                        if !ctx.classify_and_check_policy(&peer_addr, &target_addr) {
                            continue; // Drop datagram — policy denied
                        }

                        conn_metrics.record_read(n);

                        // Get or create DTLS session for this peer
                        if let std::collections::hash_map::Entry::Vacant(e) =
                            sessions.entry(peer_addr)
                        {
                            // Bind the upstream UDP socket in the target's address
                            // family so IPv6 upstreams are first-class.
                            let bind_addr = if target_addr.is_ipv6() {
                                "[::]:0"
                            } else {
                                "0.0.0.0:0"
                            };
                            let upstream_sock = match UdpSocket::bind(bind_addr) {
                                Ok(s) => s,
                                Err(e) => {
                                    error!(
                                        "[{}] Failed to bind upstream UDP: {}",
                                        ctx.rule_name, e
                                    );
                                    continue;
                                }
                            };
                            if let Err(e) = upstream_sock.connect(target_addr) {
                                error!("[{}] Failed to connect upstream UDP: {}", ctx.rule_name, e);
                                continue;
                            }
                            tune_socket_buffers(upstream_sock.as_raw_fd(), ctx.sock_buf_size);
                            // Mark + prioritise the upstream DTLS egress socket,
                            // preserving the inbound DSCP when configured.
                            ctx.apply_egress_qos(
                                upstream_sock.as_raw_fd(),
                                target_addr.is_ipv6(),
                                inbound_dscp,
                            );
                            // Bound the blocking handshake read at
                            // DTLS_HANDSHAKE_TIMEOUT (M22): a black-hole
                            // upstream then stalls this relay for at most that
                            // window instead of the former 30 s, mirroring the
                            // decrypt side (#37). Reverse traffic for
                            // established peers is still served after the bound.
                            upstream_sock
                                .set_read_timeout(Some(DTLS_HANDSHAKE_TIMEOUT))
                                .ok();

                            let dtls_stream = DtlsUdpStream::new(upstream_sock);
                            let sni = tls_params.sni_name(&ctx.upstream_addr);
                            match connector.connect(&sni, dtls_stream) {
                                Ok(ssl_stream) => {
                                    info!(
                                        "[{}] DTLS session established for peer {}",
                                        ctx.rule_name, peer_addr
                                    );
                                    // Switch to non-blocking for poll() loop
                                    ssl_stream.get_ref().sock.set_nonblocking(true).ok();
                                    e.insert((ssl_stream, Instant::now()));
                                }
                                Err(e) => {
                                    error!(
                                        "[{}] DTLS handshake failed for {}: {}",
                                        ctx.rule_name, peer_addr, e
                                    );
                                    continue;
                                }
                            }
                        }

                        // Encrypt and send
                        if let Some(dtls) = sessions.get_mut(&peer_addr) {
                            apply_geo_delay(ctx.simulated_delay_ms);
                            match dtls.0.ssl_write(&fwd_buf[..n]) {
                                Ok(_) => {
                                    dtls.1 = Instant::now();
                                    conn_metrics.record_relay(n);
                                }
                                // Transient backpressure (M23): drop this one
                                // datagram, keep the session — a full teardown +
                                // re-handshake on a momentarily-full send buffer
                                // would be far worse for UDP.
                                Err(ref e) if !dtls_write_is_fatal(e) => {
                                    debug!(
                                        "[{}] DTLS write backpressure for {}; dropping datagram",
                                        ctx.rule_name, peer_addr
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        "[{}] DTLS write error for {}: {}",
                                        ctx.rule_name, peer_addr, e
                                    );
                                    sessions.remove(&peer_addr);
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        error!("[{}] UDP recv error: {}", ctx.rule_name, e);
                        break;
                    }
                }
            }
        }

        // -- Reverse: DTLS -> plain UDP (decrypt responses back to clients) ---
        let mut to_remove = Vec::new();
        for (i, &(peer_addr, _fd)) in session_snapshot.iter().enumerate() {
            // Include POLLERR/POLLNVAL (H6) so a pending socket error surfaces
            // through the ssl_read below instead of spinning the poll loop.
            if revents_ready(pollfds[i + 1].revents) {
                if let Some(dtls) = sessions.get_mut(&peer_addr) {
                    loop {
                        match dtls.0.ssl_read(&mut rev_buf) {
                            Ok(0) => {
                                to_remove.push(peer_addr);
                                break;
                            }
                            Ok(n) => {
                                dtls.1 = Instant::now();
                                conn_metrics.record_read(n);
                                // Count only what was actually sent to the
                                // client; a failed send is logged, not tallied
                                // as relayed (L20).
                                match plain_socket.send_to(&rev_buf[..n], peer_addr) {
                                    Ok(sent) => conn_metrics.record_relay(sent),
                                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                                    Err(e) => debug!(
                                        "[{}] client send error to {}: {}",
                                        ctx.rule_name, peer_addr, e
                                    ),
                                }
                            }
                            Err(ref e) if e.code() == ErrorCode::WANT_READ => break,
                            Err(e) => {
                                error!(
                                    "[{}] DTLS read error from {}: {}",
                                    ctx.rule_name, peer_addr, e
                                );
                                to_remove.push(peer_addr);
                                break;
                            }
                        }
                    }
                }
            }
        }
        for peer in to_remove {
            if let Some((mut ssl, _)) = sessions.remove(&peer) {
                let _ = ssl.shutdown();
                info!("[{}] DTLS session closed for {}", ctx.rule_name, peer);
            }
        }
    }

    // Shutdown all DTLS sessions
    for (peer, (mut dtls, _)) in sessions {
        let _ = dtls.shutdown();
        info!("[{}] DTLS session closed for {}", ctx.rule_name, peer);
    }

    let elapsed = conn_metrics.elapsed_secs();
    info!(
        "[{}] DTLS encrypt done: {:.3}s, {} msgs, {}",
        ctx.rule_name,
        elapsed,
        conn_metrics.msgs_relayed,
        format_rate(conn_metrics.bytes_out as f64 / elapsed)
    );

    ctx.metrics.merge_connection(&conn_metrics);
    ctx.metrics.connection_closed();
}

// =============================================================================
//                   DECRYPT DIRECTION: DTLS -> plain UDP
// =============================================================================

/// DTLS decrypt relay: listens for incoming DTLS connections on a UDP socket,
/// decrypts received datagrams, and forwards as plaintext UDP/TCP to upstream.
///
/// Strategy: create SO_REUSEPORT listen sockets so multiple connected sockets
/// (one per peer) can coexist with a fresh listen socket. For each peer:
///   1. `peek_from()` -- learn peer address without consuming ClientHello
///   2. `connect()` -- lock the socket to that peer; ClientHello stays buffered
///   3. `acceptor.accept()` -- OpenSSL reads ClientHello and does handshake
///   4. Spawn a relay thread, create a new listen socket for the next peer
pub(crate) fn run_dtls_decrypt_relay(ctx: &RuleContext) {
    let tls_params =
        match TlsSecurityParams::from_params(&ctx.provider_params, ctx.protocol_version.as_deref())
        {
            Ok(p) => p,
            Err(e) => {
                error!("[{}] DTLS parameter error: {}", ctx.rule_name, e);
                return;
            }
        };
    let acceptor = match build_dtls_acceptor(&tls_params) {
        Ok(a) => a,
        Err(e) => {
            error!("[{}] DTLS acceptor error: {}", ctx.rule_name, e);
            return;
        }
    };
    // Shared across per-session worker threads (each runs its own accept()).
    let acceptor = Arc::new(acceptor);
    // Bound concurrent in-flight handshakes + established sessions on the
    // decrypt path. This lets the blocking DTLS handshake run off the accept
    // loop (de-serialized, #37) without a flood of peers exhausting threads.
    let max_sessions = tls_params.max_sessions;
    let in_flight = Arc::new(AtomicUsize::new(0));
    // Idle eviction so the bounded slots above are reclaimed from quiet
    // sessions, mirroring the encrypt path (#48); 0 disables it.
    let idle_ttl_secs = tls_params.idle_ttl_secs;

    ctx.metrics.connection_opened();
    info!("[{}] DTLS decrypt relay ready", ctx.rule_name);

    // Accept loop: each iteration handles one DTLS peer
    while !ctx.shutdown.load(Ordering::Relaxed) {
        // Create a fresh SO_REUSEPORT socket each iteration so connected
        // per-peer sockets from previous iterations can coexist
        let listen_socket = if ctx.transparent {
            match bind_udp_socket(&ctx.listen_addr, true, &ctx.rule_name) {
                Some(s) => s,
                None => return,
            }
        } else {
            match create_reuseport_udp(&ctx.listen_addr) {
                Ok(s) => {
                    info!(
                        "[{}] DTLS-decrypt listening on {}",
                        ctx.rule_name, ctx.listen_addr
                    );
                    s
                }
                Err(e) => {
                    error!(
                        "[{}] Failed to bind UDP {}: {}",
                        ctx.rule_name, ctx.listen_addr, e
                    );
                    return;
                }
            }
        };

        // Short timeout so shutdown checks happen frequently
        listen_socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .ok();
        tune_socket_buffers(listen_socket.as_raw_fd(), ctx.sock_buf_size);
        // Prioritise the client-facing DTLS return path; sample inbound DSCP
        // when the rule preserves it.
        let listen_is_v6 = listen_socket
            .local_addr()
            .map(|a| a.is_ipv6())
            .unwrap_or(false);
        ctx.apply_egress_qos(listen_socket.as_raw_fd(), listen_is_v6, None);
        ctx.enable_inbound_dscp_sampling(listen_socket.as_raw_fd(), listen_is_v6);

        // -- Wait for a DTLS ClientHello using peek_from (MSG_PEEK) -----------
        let mut peek_buf = [0u8; 1500];
        let (peer_addr, inbound_dscp) = loop {
            if ctx.shutdown.load(Ordering::Relaxed) {
                return;
            }
            match peek_from_with_dscp(listen_socket.as_raw_fd(), &mut peek_buf) {
                Ok((_n, addr, dscp)) => break (addr, dscp),
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    continue
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    error!("[{}] peek error: {}", ctx.rule_name, e);
                    return;
                }
            }
        };

        debug!("[{}] DTLS peer detected: {}", ctx.rule_name, peer_addr);

        // Resolve the upstream target once (reused by the relay thread below)
        // and apply the classification + policy gate *before* the expensive
        // DTLS accept, matching the DTLS encrypt path (run_dtls_encrypt_relay)
        // and the TLS decrypt path (tls_engine::decrypt). A denied peer is
        // dropped without spending handshake CPU or opening an upstream socket.
        //
        // `auto` is rejected at config validation for DTLS (no
        // original-destination recovery — TRA #74); the former behaviour
        // reflected decrypted plaintext back to the peer's own source address
        // on the untrusted segment (H5). This defensive guard drops a stray
        // "auto" rather than dialling it. A DNS-name upstream is resolved here
        // once (never per datagram) and both the policy gate and the worker's
        // connect use the resolved address (M4/#73); an unresolvable name
        // fails closed.
        if ctx.upstream_addr == "auto" {
            error!(
                "[{}] DTLS does not support upstream_addr=\"auto\"; dropping peer {}",
                ctx.rule_name, peer_addr
            );
            continue;
        }
        let upstream_addr = match ctx.resolve_upstream_target(&ctx.upstream_addr) {
            Some(a) => a,
            None => {
                warn!(
                    "[{}] cannot resolve upstream '{}' for peer {}; dropping",
                    ctx.rule_name, ctx.upstream_addr, peer_addr
                );
                continue;
            }
        };
        if !ctx.classify_and_check_policy(&peer_addr, &upstream_addr) {
            continue; // policy denied -- drop and re-arm the listener
        }

        // Connect socket to this peer -- recv()/send() now locked to this
        // 4-tuple, and the peeked ClientHello stays in the receive buffer.
        if let Err(e) = listen_socket.connect(peer_addr) {
            error!(
                "[{}] Failed to connect to peer {}: {}",
                ctx.rule_name, peer_addr, e
            );
            continue;
        }

        // Bound the handshake-blocking window (see DTLS_HANDSHAKE_TIMEOUT). The
        // timeout travels with the socket into the worker thread below.
        listen_socket
            .set_read_timeout(Some(DTLS_HANDSHAKE_TIMEOUT))
            .ok();

        // Admission control (#37): reserve a session slot before spawning so the
        // count of concurrent in-flight handshakes + established sessions is
        // bounded by `max_sessions`. This lets the blocking handshake run off
        // the accept loop (below) without a flood of peers exhausting threads.
        // At capacity, drop this peer and immediately re-arm the listener.
        if !session_admitted(in_flight.load(Ordering::Relaxed), max_sessions) {
            warn!(
                "[{}] DTLS decrypt session cap {} reached; dropping new peer {}",
                ctx.rule_name, max_sessions, peer_addr
            );
            continue;
        }
        in_flight.fetch_add(1, Ordering::Relaxed);

        // The connected, peeked socket moves into the worker, which runs the
        // (blocking) handshake there rather than on this accept loop.
        let dtls_stream = DtlsUdpStream::new(listen_socket);

        // Clone context fields for the spawned thread (shadowing avoids _2 suffixes).
        // `upstream_addr` was already resolved (and policy-checked) above, so the
        // worker connects straight to it — no second resolution.
        let rule_name = ctx.rule_name.clone();
        let upstream_proto = ctx.upstream_proto;
        let shutdown = ctx.shutdown.clone();
        let metrics = ctx.metrics.clone();
        let simulated_delay_ms = ctx.simulated_delay_ms;
        let qos = ctx.qos;
        let traffic_class = ctx.traffic_class;
        let acceptor = Arc::clone(&acceptor);
        let in_flight_slot = Arc::clone(&in_flight);

        let spawned = thread::Builder::new()
            .name(format!("{}-dtls-dec-{}", rule_name, peer_addr))
            .spawn(move || {
                // Release the reserved session slot on every exit path (handshake
                // failure or relay end), mirroring the encrypt path's RAII bound.
                struct SessionSlot(Arc<AtomicUsize>);
                impl Drop for SessionSlot {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                let _slot = SessionSlot(in_flight_slot);

                // Safety traffic always runs at elevated thread priority.
                apply_safety_priority(traffic_class);

                // Bind the stateless cookie to THIS worker's thread-local before
                // the handshake. Per-worker thread-locals keep the binding
                // race-free now that handshakes run concurrently rather than on
                // one serial loop.
                CURRENT_DTLS_PEER.with(|c| c.set(Some(peer_addr)));

                // Run the (blocking, <= DTLS_HANDSHAKE_TIMEOUT) DTLS handshake
                // here, off the accept loop, so a slow or stalling peer cannot
                // head-of-line block admission of other peers (#37).
                let ssl_stream = match acceptor.accept(dtls_stream) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(
                            "[{}] DTLS accept failed from {}: {}",
                            rule_name, peer_addr, e
                        );
                        return;
                    }
                };

                info!("[{}] DTLS session accepted from {}", rule_name, peer_addr);

                let mut conn =
                    ConnectionMetrics::with_rule_metrics("decrypt-dtls", "dtls", metrics.clone());
                let mut ssl = ssl_stream;

                // Set DTLS socket to non-blocking for poll()-based bidirectional I/O
                let dtls_fd = ssl.get_ref().sock.as_raw_fd();
                set_nonblocking_fd(dtls_fd);

                // Idle eviction deadline (#48): a quiet session releases its
                // bounded `in_flight` slot + thread so the cap cannot be
                // permanently held by idle peers. `0` disables eviction.
                let idle_deadline = if idle_ttl_secs > 0 {
                    Some(Duration::from_secs(idle_ttl_secs))
                } else {
                    None
                };

                match upstream_proto {
                    Proto::Uds | Proto::Shm => {
                        error!(
                            "[{}] DTLS upstream protocol {} is not supported",
                            rule_name, upstream_proto
                        );
                        return;
                    }
                    Proto::Udp => {
                        let target = upstream_addr;
                        let bind_addr = if target.is_ipv6() {
                            "[::]:0"
                        } else {
                            "0.0.0.0:0"
                        };
                        let upstream = match UdpSocket::bind(bind_addr) {
                            Ok(s) => s,
                            Err(e) => {
                                error!("[{}] Upstream UDP bind error: {}", rule_name, e);
                                return;
                            }
                        };
                        if let Err(e) = upstream.connect(target) {
                            error!("[{}] Upstream UDP connect error: {}", rule_name, e);
                            return;
                        }
                        upstream.set_nonblocking(true).ok();
                        let up_fd = upstream.as_raw_fd();
                        crate::networking::socket_manager::apply_egress_qos(
                            up_fd,
                            qos.egress_dscp(inbound_dscp),
                            qos.so_priority(),
                            target.is_ipv6(),
                        );

                        let mut fwd_buf = vec![0u8; UDP_BUF_SIZE];
                        let mut rev_buf = vec![0u8; UDP_BUF_SIZE];
                        let mut last_activity = Instant::now();

                        'relay: loop {
                            if shutdown.load(Ordering::Relaxed) {
                                break;
                            }
                            // Shared two-fd poll (M30): POLLERR/POLLNVAL-aware
                            // (H6) so a pending ICMP error is reported ready and
                            // surfaced by the following recv/send.
                            let (dtls_ready, up_ready) = match poll_two_fds(dtls_fd, up_fd, 0, 1000)
                            {
                                Ok(r) => r,
                                Err(_) => break 'relay,
                            };
                            if !dtls_ready && !up_ready {
                                if let Some(ttl) = idle_deadline {
                                    if last_activity.elapsed() >= ttl {
                                        debug!(
                                            "[{}] DTLS decrypt session idle >= {}s; evicting",
                                            rule_name, idle_ttl_secs
                                        );
                                        break 'relay;
                                    }
                                }
                                continue;
                            }

                            // Forward: DTLS -> upstream UDP (decrypt).
                            if dtls_ready {
                                loop {
                                    match ssl.ssl_read(&mut fwd_buf) {
                                        Ok(0) => break 'relay,
                                        Ok(n) => {
                                            // last_activity only advances on real
                                            // byte movement (H6) so a POLLERR spin
                                            // cannot defeat idle eviction.
                                            last_activity = Instant::now();
                                            conn.record_read(n);
                                            apply_geo_delay(simulated_delay_ms);
                                            // Count only bytes actually sent
                                            // upstream (L20).
                                            match upstream.send(&fwd_buf[..n]) {
                                                Ok(sent) => conn.record_relay(sent),
                                                Err(ref e)
                                                    if e.kind() == io::ErrorKind::WouldBlock => {}
                                                Err(e) => debug!(
                                                    "[{}] upstream send error: {}",
                                                    rule_name, e
                                                ),
                                            }
                                        }
                                        Err(ref e) if e.code() == ErrorCode::WANT_READ => break,
                                        Err(e) => {
                                            error!("[{}] DTLS read error: {}", rule_name, e);
                                            break 'relay;
                                        }
                                    }
                                }
                            }

                            // Reverse: upstream UDP -> DTLS (encrypt response)
                            if up_ready {
                                loop {
                                    match upstream.recv(&mut rev_buf) {
                                        Ok(n) if n > 0 => {
                                            last_activity = Instant::now();
                                            conn.record_read(n);
                                            match ssl.ssl_write(&rev_buf[..n]) {
                                                Ok(_) => {
                                                    conn.record_relay(n);
                                                }
                                                // Transient backpressure (M23):
                                                // drop the datagram, keep the
                                                // session.
                                                Err(ref e) if !dtls_write_is_fatal(e) => {
                                                    debug!(
                                                        "[{}] DTLS write backpressure; dropping",
                                                        rule_name
                                                    );
                                                }
                                                Err(e) => {
                                                    error!(
                                                        "[{}] DTLS write error: {}",
                                                        rule_name, e
                                                    );
                                                    break 'relay;
                                                }
                                            }
                                        }
                                        // A legitimate zero-length datagram from
                                        // the trusted upstream is NOT a teardown
                                        // signal (L21): ssl_write(&[]) is a no-op,
                                        // so we simply keep the session.
                                        Ok(_) => {}
                                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                            break
                                        }
                                        Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {
                                            continue
                                        }
                                        // Real upstream recv error: log it (the
                                        // former catch-all swallowed it) and end
                                        // the session (L21).
                                        Err(e) => {
                                            error!("[{}] upstream recv error: {}", rule_name, e);
                                            break 'relay;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Proto::Tcp => {
                        let mut upstream = match TcpStream::connect(upstream_addr) {
                            Ok(s) => s,
                            Err(e) => {
                                error!("[{}] Upstream TCP connect error: {}", rule_name, e);
                                return;
                            }
                        };
                        upstream.set_nonblocking(true).ok();
                        let up_fd = upstream.as_raw_fd();
                        let up_is_v6 = upstream.peer_addr().map(|a| a.is_ipv6()).unwrap_or(false);
                        crate::networking::socket_manager::apply_egress_qos(
                            up_fd,
                            qos.egress_dscp(inbound_dscp),
                            qos.so_priority(),
                            up_is_v6,
                        );

                        let mut fwd_buf = vec![0u8; RELAY_BUF_SIZE];
                        let mut rev_buf = vec![0u8; RELAY_BUF_SIZE];
                        let mut last_activity = Instant::now();

                        'relay: loop {
                            if shutdown.load(Ordering::Relaxed) {
                                break;
                            }
                            // Shared two-fd poll (M30), POLLERR/POLLNVAL-aware (H6).
                            let (dtls_ready, up_ready) = match poll_two_fds(dtls_fd, up_fd, 0, 1000)
                            {
                                Ok(r) => r,
                                Err(_) => break 'relay,
                            };
                            if !dtls_ready && !up_ready {
                                if let Some(ttl) = idle_deadline {
                                    if last_activity.elapsed() >= ttl {
                                        debug!(
                                            "[{}] DTLS decrypt session idle >= {}s; evicting",
                                            rule_name, idle_ttl_secs
                                        );
                                        break 'relay;
                                    }
                                }
                                continue;
                            }

                            // Forward: DTLS -> upstream TCP (decrypt).
                            if dtls_ready {
                                loop {
                                    match ssl.ssl_read(&mut fwd_buf) {
                                        Ok(0) => {
                                            let _ = upstream.shutdown(std::net::Shutdown::Write);
                                            break 'relay;
                                        }
                                        Ok(n) => {
                                            last_activity = Instant::now();
                                            conn.record_read(n);
                                            apply_geo_delay(simulated_delay_ms);
                                            if write_all_nb(&mut upstream, &fwd_buf[..n]).is_err() {
                                                break 'relay;
                                            }
                                            conn.record_relay(n);
                                        }
                                        Err(ref e) if e.code() == ErrorCode::WANT_READ => break,
                                        Err(e) => {
                                            error!("[{}] DTLS read error: {}", rule_name, e);
                                            break 'relay;
                                        }
                                    }
                                }
                            }

                            // Reverse: upstream TCP -> DTLS (encrypt response)
                            if up_ready {
                                match upstream.read(&mut rev_buf) {
                                    Ok(0) => break 'relay,
                                    Ok(n) => {
                                        last_activity = Instant::now();
                                        conn.record_read(n);
                                        match ssl.ssl_write(&rev_buf[..n]) {
                                            Ok(_) => {
                                                conn.record_relay(n);
                                            }
                                            // Transient backpressure (M23).
                                            Err(ref e) if !dtls_write_is_fatal(e) => {
                                                debug!(
                                                    "[{}] DTLS write backpressure; dropping",
                                                    rule_name
                                                );
                                            }
                                            Err(e) => {
                                                error!("[{}] DTLS write error: {}", rule_name, e);
                                                break 'relay;
                                            }
                                        }
                                    }
                                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                                    Err(e) => {
                                        error!("[{}] Upstream read error: {}", rule_name, e);
                                        break 'relay;
                                    }
                                }
                            }
                        }
                    }
                }

                let _ = ssl.shutdown();
                let elapsed = conn.elapsed_secs();
                info!(
                    "[{}] DTLS decrypt session {} done: {:.3}s, {} msgs",
                    rule_name, peer_addr, elapsed, conn.msgs_relayed
                );

                metrics.merge_connection(&conn);
            });
        if spawned.is_err() {
            // Spawn failed: release the slot we reserved above so the cap does
            // not leak.
            in_flight.fetch_sub(1, Ordering::Relaxed);
            error!(
                "[{}] failed to spawn DTLS session thread for {}",
                ctx.rule_name, peer_addr
            );
        }

        // Loop continues -- next iteration creates a new listen socket
        // The spawned thread keeps the connected socket alive via SO_REUSEPORT
    }

    ctx.metrics.connection_closed();
    info!("[{}] DTLS decrypt relay shutting down", ctx.rule_name);
}

// `session_admitted` / `stale_peers` admission + idle-selection unit tests live
// with their definitions in `security::udp_session` (shared with UDP routing).

#[cfg(test)]
mod cookie_tests {
    use super::*;

    #[test]
    fn cookie_is_deterministic_per_peer() {
        let peer: SocketAddr = "203.0.113.5:5000".parse().unwrap();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let na = compute_dtls_cookie(&peer, &mut a).unwrap();
        let nb = compute_dtls_cookie(&peer, &mut b).unwrap();
        assert_eq!(na, nb);
        assert!(na > 0);
        assert_eq!(a, b, "same peer must yield the same cookie");
    }

    #[test]
    fn cookie_differs_across_peers() {
        let p1: SocketAddr = "203.0.113.5:5000".parse().unwrap();
        let p2: SocketAddr = "203.0.113.5:5001".parse().unwrap(); // different port
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        compute_dtls_cookie(&p1, &mut a).unwrap();
        compute_dtls_cookie(&p2, &mut b).unwrap();
        assert_ne!(a, b, "a different peer must yield a different cookie");
    }

    // KC-03: on a functioning host the secret is available and stable (same
    // pointer/bytes across calls). RNG failure is uninjectable without wrapping
    // OpenSSL, so the fail-closed path is documented rather than unit-tested; the
    // accessor now returns a `Result`, so a failure propagates instead of minting
    // an all-zero cookie key.
    #[test]
    fn cookie_secret_is_ok_and_stable() {
        let a = dtls_cookie_secret().expect("RNG available in tests");
        let b = dtls_cookie_secret().expect("RNG available in tests");
        assert!(
            std::ptr::eq(a, b),
            "secret must be the same cached instance"
        );
        assert_ne!(a, &[0u8; 32], "a real secret must not be all-zero");
    }

    // H6: an error-only wake (POLLERR / POLLNVAL, e.g. a pending ICMP error on
    // a connected UDP socket) must count as "ready" so the following recv/send
    // surfaces the error — otherwise the poll loop busy-spins at 100% CPU.
    #[test]
    fn revents_ready_includes_error_conditions() {
        assert!(revents_ready(libc::POLLIN));
        assert!(revents_ready(libc::POLLHUP));
        assert!(revents_ready(libc::POLLERR));
        assert!(revents_ready(libc::POLLNVAL));
        assert!(revents_ready(libc::POLLERR | libc::POLLIN));
        // No relevant bit set → not ready.
        assert!(!revents_ready(0));
        assert!(!revents_ready(libc::POLLOUT));
    }
}
