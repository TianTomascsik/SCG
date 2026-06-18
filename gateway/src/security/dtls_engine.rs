//! DTLS support -- native UDP encryption/decryption relay.
//!
//! Provides DTLS (Datagram TLS) relaying that preserves UDP semantics:
//! no ordering guarantee, no head-of-line blocking. Unlike UDP-over-TLS
//! (which tunnels through TCP), DTLS keeps the transport as UDP end-to-end.

use crate::management::cert_store::get_or_init_cert;
use crate::networking::socket_manager::{
    bind_udp_socket, set_nonblocking_fd, tune_socket_buffers, write_all_nb,
};
use crate::processing::RuleContext;
use crate::security::relay::apply_geo_delay;
use crate::security::{RELAY_BUF_SIZE, UDP_BUF_SIZE};

use crate::management::config::Proto;
use crate::management::telemetry::{format_rate, log_connection_csv, now_ns, ConnectionMetrics};
use log::{debug, error, info};

use bench_log::{compute_latency_stats, print_latency_stats, CsvLogger};
use openssl::ssl::{
    ErrorCode, SslAcceptor, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion,
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

/// Build a DTLS SslConnector (client side, no cert verification).
/// Accepts an optional protocol version: "dtls1.0" or "dtls1.2" (default).
fn build_dtls_connector(version: Option<&str>) -> Result<SslConnector, openssl::error::ErrorStack> {
    let mut builder = SslConnector::builder(SslMethod::dtls())?;
    builder.set_verify(SslVerifyMode::NONE);

    match version {
        Some("dtls1.0") => {
            // DTLS 1.0 does not support GCM ciphers — use CBC
            builder.set_cipher_list("AES128-SHA:AES256-SHA")?;
            builder.set_min_proto_version(Some(SslVersion::DTLS1))?;
            builder.set_max_proto_version(Some(SslVersion::DTLS1))?;
        }
        _ => {
            // Default: DTLS 1.2 with GCM
            builder.set_cipher_list("AES128-GCM-SHA256:AES256-GCM-SHA384")?;
            builder.set_min_proto_version(Some(SslVersion::DTLS1_2))?;
            builder.set_max_proto_version(Some(SslVersion::DTLS1_2))?;
        }
    }

    Ok(builder.build())
}

/// Build a DTLS SslAcceptor (server side) with self-signed cert.
/// Accepts an optional protocol version: "dtls1.0" or "dtls1.2" (default).
fn build_dtls_acceptor(version: Option<&str>) -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let (pkey, cert) = get_or_init_cert()?;
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::dtls())?;
    builder.set_private_key(pkey)?;
    builder.set_certificate(cert)?;
    builder.check_private_key()?;

    match version {
        Some("dtls1.0") => {
            // DTLS 1.0 does not support GCM ciphers — use CBC
            builder.set_cipher_list("AES128-SHA:AES256-SHA")?;
            builder.set_min_proto_version(Some(SslVersion::DTLS1))?;
            builder.set_max_proto_version(Some(SslVersion::DTLS1))?;
        }
        _ => {
            // Default: DTLS 1.2 with GCM
            builder.set_cipher_list("AES128-GCM-SHA256:AES256-GCM-SHA384")?;
            builder.set_min_proto_version(Some(SslVersion::DTLS1_2))?;
            builder.set_max_proto_version(Some(SslVersion::DTLS1_2))?;
        }
    }

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
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let one: libc::c_int = 1;
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
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }

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

    // Non-blocking for poll()-based bidirectional I/O
    plain_socket.set_nonblocking(true).ok();
    tune_socket_buffers(plain_socket.as_raw_fd(), ctx.sock_buf_size);

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

    // Build DTLS connector
    let connector = match build_dtls_connector(ctx.protocol_version.as_deref()) {
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
                match plain_socket.recv_from(&mut fwd_buf) {
                    Ok((n, peer_addr)) => {
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
                        let t0 = if ctx.measure_latency { now_ns() } else { 0 };

                        // Get or create DTLS session for this peer
                        if !sessions.contains_key(&peer_addr) {
                            let upstream_sock = match UdpSocket::bind("0.0.0.0:0") {
                                Ok(s) => s,
                                Err(e) => {
                                    error!(
                                        "[{}] Failed to bind upstream UDP: {}",
                                        ctx.rule_name, e
                                    );
                                    continue;
                                }
                            };
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
                            if let Err(e) = upstream_sock.connect(target_addr) {
                                error!("[{}] Failed to connect upstream UDP: {}", ctx.rule_name, e);
                                continue;
                            }
                            tune_socket_buffers(upstream_sock.as_raw_fd(), ctx.sock_buf_size);
                            // Blocking during DTLS handshake
                            upstream_sock
                                .set_read_timeout(Some(Duration::from_secs(30)))
                                .ok();

                            let dtls_stream = DtlsUdpStream::new(upstream_sock);
                            match connector.connect("gateway", dtls_stream) {
                                Ok(ssl_stream) => {
                                    info!(
                                        "[{}] DTLS session established for peer {}",
                                        ctx.rule_name, peer_addr
                                    );
                                    // Switch to non-blocking for poll() loop
                                    ssl_stream.get_ref().sock.set_nonblocking(true).ok();
                                    sessions.insert(peer_addr, ssl_stream);
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
                                    let lat = if ctx.measure_latency {
                                        now_ns() - t0
                                    } else {
                                        0
                                    };
                                    conn_metrics.record_relay(
                                        n,
                                        if ctx.measure_latency { Some(lat) } else { None },
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
                                conn_metrics.record_relay(n, None);
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

    if ctx.measure_latency {
        if let Some(stats) = compute_latency_stats(&mut conn_metrics.latency_samples_ns) {
            print_latency_stats(0, &format!("{} relay", ctx.rule_name), &stats);
        }
    }

    if let Ok(mut logger) = CsvLogger::new(&ctx.log_dir, "gateway", "encrypt-dtls", &ctx.run_id) {
        log_connection_csv(&mut logger, &mut conn_metrics, &ctx.run_id);
    }

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
    let acceptor = match build_dtls_acceptor(ctx.protocol_version.as_deref()) {
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

        // -- Wait for a DTLS ClientHello using peek_from (MSG_PEEK) -----------
        let mut peek_buf = [0u8; 1500];
        let peer_addr = loop {
            if ctx.shutdown.load(Ordering::Relaxed) {
                return;
            }
            match listen_socket.peek_from(&mut peek_buf) {
                Ok((_n, addr)) => break addr,
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
        let measure_latency = ctx.measure_latency;
        let shutdown = ctx.shutdown.clone();
        let metrics = ctx.metrics.clone();
        let log_dir = ctx.log_dir.clone();
        let run_id = ctx.run_id.clone();
        let simulated_delay_ms = ctx.simulated_delay_ms;

        thread::Builder::new()
            .name(format!("{}-dtls-dec-{}", rule_name, peer_addr))
            .spawn(move || {
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
                        let upstream = match UdpSocket::bind("0.0.0.0:0") {
                            Ok(s) => s,
                            Err(e) => {
                                error!("[{}] Upstream UDP bind error: {}", rule_name, e);
                                return;
                            }
                        };
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
                        if let Err(e) = upstream.connect(target) {
                            error!("[{}] Upstream UDP connect error: {}", rule_name, e);
                            return;
                        }
                        upstream.set_nonblocking(true).ok();
                        let up_fd = upstream.as_raw_fd();

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
                                            let t0 = if measure_latency { now_ns() } else { 0 };
                                            let _ = upstream.send(&fwd_buf[..n]);
                                            let lat =
                                                if measure_latency { now_ns() - t0 } else { 0 };
                                            conn.record_relay(
                                                n,
                                                if measure_latency { Some(lat) } else { None },
                                            );
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
                                                    conn.record_relay(n, None);
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
                                            let t0 = if measure_latency { now_ns() } else { 0 };
                                            if write_all_nb(&mut upstream, &fwd_buf[..n]).is_err() {
                                                break 'relay;
                                            }
                                            let lat =
                                                if measure_latency { now_ns() - t0 } else { 0 };
                                            conn.record_relay(
                                                n,
                                                if measure_latency { Some(lat) } else { None },
                                            );
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
                                                conn.record_relay(n, None);
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

                if measure_latency {
                    if let Some(stats) = compute_latency_stats(&mut conn.latency_samples_ns) {
                        print_latency_stats(0, &format!("{} dtls-dec", rule_name), &stats);
                    }
                }

                if let Ok(mut logger) = CsvLogger::new(&log_dir, "gateway", "decrypt-dtls", &run_id)
                {
                    log_connection_csv(&mut logger, &mut conn, &run_id);
                }

                metrics.merge_connection(&conn);
            })
            .ok();

        // Loop continues -- next iteration creates a new listen socket
        // The spawned thread keeps the connected socket alive via SO_REUSEPORT
    }

    ctx.metrics.connection_closed();
    info!("[{}] DTLS decrypt relay shutting down", ctx.rule_name);
}
