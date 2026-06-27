//! DTLS support -- native UDP encryption/decryption relay.
//!
//! Provides DTLS (Datagram TLS) relaying that preserves UDP semantics:
//! no ordering guarantee, no head-of-line blocking. Unlike UDP-over-TLS
//! (which tunnels through TCP), DTLS keeps the transport as UDP end-to-end.

use crate::management::cert_store::{get_or_init_cert, load_identity_pem};
use crate::networking::socket_manager::{
    apply_safety_priority, bind_udp_socket, peek_from_with_dscp, recvmsg_from_with_dscp,
    set_nonblocking_fd, tune_socket_buffers, write_all_nb,
};
use crate::processing::RuleContext;
use crate::security::relay::apply_geo_delay;
use crate::security::tls_engine::params::{TlsSecurityParams, VerifyMode};
use crate::security::{RELAY_BUF_SIZE, UDP_BUF_SIZE};

use crate::management::config::Proto;
use crate::management::telemetry::{format_rate, ConnectionMetrics};
use log::{debug, error, info};

use openssl::ssl::{
    ErrorCode, SslAcceptor, SslConnector, SslContextBuilder, SslMethod, SslStream, SslVerifyMode,
    SslVersion,
};

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

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

    // Enable cookie exchange for DTLS (DoS protection)
    // Note: stateless cookie verification adds complexity; skip for POC
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
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
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

// =============================================================================
//                   ENCRYPT DIRECTION: UDP -> DTLS (native UDP)
// =============================================================================

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
    let plain_is_v6 = plain_socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    ctx.apply_egress_qos(plain_socket.as_raw_fd(), plain_is_v6, None);
    ctx.enable_inbound_dscp_sampling(plain_socket.as_raw_fd(), plain_is_v6);

    // Resolve upstream for DTLS
    let dtls_target = if ctx.upstream_addr == "auto" {
        debug!(
            "[{}] DTLS auto mode -- will use per-packet original dst",
            ctx.rule_name
        );
        None
    } else {
        Some(ctx.upstream_addr.clone())
    };

    // Resolve typed security parameters and build the DTLS connector.
    let tls_params = match TlsSecurityParams::from_params(
        &ctx.provider_params,
        ctx.protocol_version.as_deref(),
    ) {
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

    // Per-peer DTLS sessions (since UDP is connectionless, we track sessions by peer addr)
    let mut sessions: HashMap<SocketAddr, SslStream<DtlsUdpStream>> = HashMap::new();
    let mut conn_metrics =
        ConnectionMetrics::with_rule_metrics("encrypt-dtls", "dtls", ctx.metrics.clone());
    ctx.metrics.connection_opened();

    let mut fwd_buf = vec![0u8; UDP_BUF_SIZE];
    let mut rev_buf = vec![0u8; UDP_BUF_SIZE];
    let plain_fd = plain_socket.as_raw_fd();

    while !ctx.shutdown.load(Ordering::Relaxed) {
        // Build dynamic pollfd array: [plain_socket, ...dtls_upstream_fds]
        let mut pollfds = vec![libc::pollfd {
            fd: plain_fd,
            events: libc::POLLIN,
            revents: 0,
        }];
        let session_snapshot: Vec<(SocketAddr, RawFd)> = sessions
            .iter()
            .map(|(peer, ssl)| (*peer, ssl.get_ref().sock.as_raw_fd()))
            .collect();
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
                        // Policy check per datagram
                        let target = match &dtls_target {
                            Some(addr) => addr.clone(),
                            None => ctx.upstream_addr.clone(),
                        };
                        if let Ok(dst_addr) = target.parse::<SocketAddr>() {
                            if !ctx.classify_and_check_policy(&peer_addr, &dst_addr) {
                                continue; // Drop datagram
                            }
                        }

                        conn_metrics.record_read(n);

                        // Get or create DTLS session for this peer
                        if let std::collections::hash_map::Entry::Vacant(e) = sessions.entry(peer_addr) {
                            let target_addr: SocketAddr = match target.parse() {
                                Ok(a) => a,
                                Err(e) => {
                                    error!(
                                        "[{}] Invalid upstream '{}': {}",
                                        ctx.rule_name, target, e
                                    );
                                    continue;
                                }
                            };
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
                            // Blocking during DTLS handshake
                            upstream_sock
                                .set_read_timeout(Some(Duration::from_secs(30)))
                                .ok();

                            let dtls_stream = DtlsUdpStream::new(upstream_sock);
                            let sni = tls_params.sni_name(&target);
                            match connector.connect(&sni, dtls_stream) {
                                Ok(ssl_stream) => {
                                    info!(
                                        "[{}] DTLS session established for peer {}",
                                        ctx.rule_name, peer_addr
                                    );
                                    // Switch to non-blocking for poll() loop
                                    ssl_stream.get_ref().sock.set_nonblocking(true).ok();
                                    e.insert(ssl_stream);
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
                            match dtls.ssl_write(&fwd_buf[..n]) {
                                Ok(_) => {
                                    conn_metrics.record_relay(n);
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
            if pollfds[i + 1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                if let Some(dtls) = sessions.get_mut(&peer_addr) {
                    loop {
                        match dtls.ssl_read(&mut rev_buf) {
                            Ok(0) => {
                                to_remove.push(peer_addr);
                                break;
                            }
                            Ok(n) => {
                                conn_metrics.record_read(n);
                                let _ = plain_socket.send_to(&rev_buf[..n], peer_addr);
                                conn_metrics.record_relay(n);
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
            if let Some(mut ssl) = sessions.remove(&peer) {
                let _ = ssl.shutdown();
                info!("[{}] DTLS session closed for {}", ctx.rule_name, peer);
            }
        }
    }

    // Shutdown all DTLS sessions
    for (peer, mut dtls) in sessions {
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
    let tls_params = match TlsSecurityParams::from_params(
        &ctx.provider_params,
        ctx.protocol_version.as_deref(),
    ) {
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
        let listen_is_v6 = listen_socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
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

        // Connect socket to this peer -- recv()/send() now locked to this
        // 4-tuple, and the peeked ClientHello stays in the receive buffer.
        if let Err(e) = listen_socket.connect(peer_addr) {
            error!(
                "[{}] Failed to connect to peer {}: {}",
                ctx.rule_name, peer_addr, e
            );
            continue;
        }

        // Increase timeout for handshake
        listen_socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();

        // DTLS accept
        let dtls_stream = DtlsUdpStream::new(listen_socket);
        let ssl_stream = match acceptor.accept(dtls_stream) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "[{}] DTLS accept failed from {}: {}",
                    ctx.rule_name, peer_addr, e
                );
                continue; // try next peer
            }
        };

        info!(
            "[{}] DTLS session accepted from {}",
            ctx.rule_name, peer_addr
        );

        // Clone context fields for the spawned thread (shadowing avoids _2 suffixes)
        let rule_name = ctx.rule_name.clone();
        let upstream_target = if ctx.upstream_addr == "auto" {
            peer_addr.to_string()
        } else {
            ctx.upstream_addr.clone()
        };
        let upstream_proto = ctx.upstream_proto;
        let shutdown = ctx.shutdown.clone();
        let metrics = ctx.metrics.clone();
        let simulated_delay_ms = ctx.simulated_delay_ms;
        let qos = ctx.qos;
        let traffic_class = ctx.traffic_class;

        thread::Builder::new()
            .name(format!("{}-dtls-dec-{}", rule_name, peer_addr))
            .spawn(move || {
                // Safety traffic always runs at elevated thread priority.
                apply_safety_priority(traffic_class);

                let mut conn =
                    ConnectionMetrics::with_rule_metrics("decrypt-dtls", "dtls", metrics.clone());
                let mut ssl = ssl_stream;

                // Set DTLS socket to non-blocking for poll()-based bidirectional I/O
                let dtls_fd = ssl.get_ref().sock.as_raw_fd();
                set_nonblocking_fd(dtls_fd);

                match upstream_proto {
                    Proto::Uds | Proto::Shm => {
                        error!(
                            "[{}] DTLS upstream protocol {} is not supported",
                            rule_name, upstream_proto
                        );
                        return;
                    }
                    Proto::Udp => {
                        let target: SocketAddr = match upstream_target.parse() {
                            Ok(a) => a,
                            Err(e) => {
                                error!(
                                    "[{}] Invalid upstream '{}': {}",
                                    rule_name, upstream_target, e
                                );
                                return;
                            }
                        };
                        let bind_addr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
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

                        'relay: loop {
                            if shutdown.load(Ordering::Relaxed) {
                                break;
                            }
                            let mut fds = [
                                libc::pollfd {
                                    fd: dtls_fd,
                                    events: libc::POLLIN,
                                    revents: 0,
                                },
                                libc::pollfd {
                                    fd: up_fd,
                                    events: libc::POLLIN,
                                    revents: 0,
                                },
                            ];
                            // SAFETY: `fds` is a live, fully-initialised
                            // `[libc::pollfd; 2]` array; `as_mut_ptr()` points to
                            // its first element and the passed count `2` matches
                            // the array length exactly, so `poll` only reads and
                            // writes the two in-bounds entries for the duration of
                            // the call (the array outlives it). `ret` is checked below.
                            let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, 1000) };
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

                            // Forward: DTLS -> upstream UDP (decrypt)
                            if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                                loop {
                                    match ssl.ssl_read(&mut fwd_buf) {
                                        Ok(0) => break 'relay,
                                        Ok(n) => {
                                            conn.record_read(n);
                                            apply_geo_delay(simulated_delay_ms);
                                            let _ = upstream.send(&fwd_buf[..n]);
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

                            // Reverse: upstream UDP -> DTLS (encrypt response)
                            if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                                loop {
                                    match upstream.recv(&mut rev_buf) {
                                        Ok(n) if n > 0 => {
                                            conn.record_read(n);
                                            match ssl.ssl_write(&rev_buf[..n]) {
                                                Ok(_) => {
                                                    conn.record_relay(n);
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
                                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                            break
                                        }
                                        Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {
                                            continue
                                        }
                                        _ => break 'relay,
                                    }
                                }
                            }
                        }
                    }
                    Proto::Tcp => {
                        let mut upstream = match TcpStream::connect(&upstream_target) {
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

                        'relay: loop {
                            if shutdown.load(Ordering::Relaxed) {
                                break;
                            }
                            let mut fds = [
                                libc::pollfd {
                                    fd: dtls_fd,
                                    events: libc::POLLIN,
                                    revents: 0,
                                },
                                libc::pollfd {
                                    fd: up_fd,
                                    events: libc::POLLIN,
                                    revents: 0,
                                },
                            ];
                            // SAFETY: `fds` is a live, fully-initialised
                            // `[libc::pollfd; 2]` array; `as_mut_ptr()` points to
                            // its first element and the passed count `2` matches
                            // the array length exactly, so `poll` only reads and
                            // writes the two in-bounds entries for the duration of
                            // the call (the array outlives it). `ret` is checked below.
                            let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, 1000) };
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

                            // Forward: DTLS -> upstream TCP (decrypt)
                            if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                                loop {
                                    match ssl.ssl_read(&mut fwd_buf) {
                                        Ok(0) => {
                                            let _ = upstream.shutdown(std::net::Shutdown::Write);
                                            break 'relay;
                                        }
                                        Ok(n) => {
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
                            if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                                match upstream.read(&mut rev_buf) {
                                    Ok(0) => break 'relay,
                                    Ok(n) => {
                                        conn.record_read(n);
                                        match ssl.ssl_write(&rev_buf[..n]) {
                                            Ok(_) => {
                                                conn.record_relay(n);
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
            })
            .ok();

        // Loop continues -- next iteration creates a new listen socket
        // The spawned thread keeps the connected socket alive via SO_REUSEPORT
    }

    ctx.metrics.connection_closed();
    info!("[{}] DTLS decrypt relay shutting down", ctx.rule_name);
}
