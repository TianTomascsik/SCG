//! Encrypt direction proxy: plain TCP/UDP -> TLS/kTLS upstream.
//!
//! - `run_tcp_encrypt_listener` -- accept plain TCP, connect TLS/kTLS to upstream, relay
//! - `handle_tcp_encrypt` -- per-connection handler for a single TCP encrypt connection
//! - `run_udp_encrypt_relay` -- receive UDP datagrams, tunnel through TLS with framing

use super::{build_tls_connector, write_all_nb_proxy, ProxyStream};
use crate::networking::connector::{connect_with_retry, sleep_with_shutdown_check};
use crate::networking::socket_manager::{
    accept_with_timeout, bind_tcp_listener, bind_udp_socket, poll_two_fds, set_nodelay,
    set_nonblocking_fd, tune_socket_buffers,
};
use crate::processing::RuleContext;
use crate::security::relay::{
    apply_geo_delay, relay_bidirectional_splice, relay_encrypt_bidirectional,
};
use crate::security::{ACCEPT_TIMEOUT, RELAY_BUF_SIZE, UDP_BUF_SIZE};
use ale_pipe::{
    AleAu1Info, AleAu2Info, AleError, AleFrameReader, AleFrameWriter, ALE_CLASS_D, ALE_PKT_AU1,
    ALE_PKT_AU2, ALE_PKT_DI, ALE_PKT_DT,
};

use crate::interfaces::tproxy;
use crate::management::config::TlsMode;
use crate::management::telemetry::{format_rate, log_connection_csv, now_ns, ConnectionMetrics};

use bench_log::{compute_latency_stats, print_latency_stats, CsvLogger};
use foreign_types_shared::ForeignTypeRef;
use ktls_pipe::{
    build_client_connector as ktls_client_connector, enable_ktls_ssl, get_tcp_ulp,
    ktls_privilege_hint, KtlsSession,
};
use log::{debug, error, info, warn};

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// =============================================================================
//                         ENCRYPT DIRECTION: TCP -> TLS
// =============================================================================

/// Accept plain TCP connections and relay each through a TLS/kTLS upstream.
pub(crate) fn run_tcp_encrypt_listener(ctx: &RuleContext) {
    let listener = match bind_tcp_listener(&ctx.listen_addr, ctx.transparent, &ctx.rule_name) {
        Some(l) => l,
        None => return,
    };
    listener.set_nonblocking(false).ok();

    let csv_logger = Arc::new(Mutex::new(
        CsvLogger::new(
            &ctx.log_dir,
            "gateway",
            &format!("encrypt-{}", ctx.tls_mode),
            &ctx.run_id,
        )
        .ok(),
    ));

    while !ctx.shutdown.load(Ordering::Relaxed) {
        let (client_stream, peer_addr) = match accept_with_timeout(&listener, ACCEPT_TIMEOUT) {
            Some(Ok((s, a))) => (s, a),
            Some(Err(e)) => {
                error!("[{}] Accept error: {}", ctx.rule_name, e);
                continue;
            }
            None => continue, // timeout, check shutdown
        };

        // Determine upstream target (TPROXY may redirect to original destination)
        let target = if ctx.transparent {
            match tproxy::get_original_dst(client_stream.as_raw_fd()) {
                Ok(orig) => {
                    debug!(
                        "[{}] TPROXY {} \u{2192} {} (original dst)",
                        ctx.rule_name, peer_addr, orig
                    );
                    orig.to_string()
                }
                Err(e) => {
                    warn!(
                        "[{}] SO_ORIGINAL_DST failed: {}, using configured upstream",
                        ctx.rule_name, e
                    );
                    ctx.upstream_addr.clone()
                }
            }
        } else {
            ctx.upstream_addr.clone()
        };

        // Traffic classification + policy check
        if let Ok(dst_addr) = target.parse::<SocketAddr>() {
            if !ctx.classify_and_check_policy(&peer_addr, &dst_addr) {
                continue; // Drop connection — policy denied
            }
        }

        let fd = client_stream.as_raw_fd();
        tune_socket_buffers(fd, ctx.sock_buf_size);
        set_nodelay(fd, true);

        ctx.metrics.connection_opened();

        // Clone shared state for the per-connection thread
        let metrics = ctx.metrics.clone();
        let rule_name = ctx.rule_name.clone();
        let tls_mode = ctx.tls_mode;
        let csv_logger = csv_logger.clone();
        let run_id = ctx.run_id.clone();
        let shutdown = ctx.shutdown.clone();
        let measure_latency = ctx.measure_latency;
        let sock_buf_size = ctx.sock_buf_size;
        let traffic_class = ctx.traffic_class;
        let simulated_delay_ms = ctx.simulated_delay_ms;
        let protocol_version = ctx.protocol_version.clone();

        let pool = ctx.conn_pool.clone();
        pool.execute(move || {
            // Set higher OS thread priority for safety traffic
            if traffic_class == crate::management::config::TrafficClass::Safety {
                unsafe {
                    libc::setpriority(libc::PRIO_PROCESS, 0, -5);
                }
            }

            let mut conn_metrics = ConnectionMetrics::with_rule_metrics(
                "encrypt",
                &tls_mode.to_string(),
                metrics.clone(),
            );

            let result = handle_tcp_encrypt(
                &rule_name,
                client_stream,
                &target,
                tls_mode,
                measure_latency,
                sock_buf_size,
                &mut conn_metrics,
                &shutdown,
                simulated_delay_ms,
                protocol_version.as_deref(),
            );

            if let Err(e) = result {
                error!("[{}] Connection {} error: {}", rule_name, peer_addr, e);
            }

            let elapsed = conn_metrics.elapsed_secs();
            let out_bps = conn_metrics.bytes_out as f64 / elapsed;
            debug!(
                "[{}] {} done: {:.3}s, {} msgs, {} out",
                rule_name,
                peer_addr,
                elapsed,
                conn_metrics.msgs_relayed,
                format_rate(out_bps),
            );

            // Latency stats
            if measure_latency {
                if let Some(stats) = compute_latency_stats(&mut conn_metrics.latency_samples_ns) {
                    print_latency_stats(0, &format!("{} relay", rule_name), &stats);
                }
            }

            // CSV logging
            if let Ok(mut guard) = csv_logger.lock() {
                if let Some(ref mut logger) = *guard {
                    log_connection_csv(logger, &mut conn_metrics, &run_id);
                }
            }

            metrics.merge_connection(&conn_metrics);
            metrics.connection_closed();
        });
    }

    info!("[{}] Listener shutting down", ctx.rule_name);
}

/// Handle a single TCP -> TLS encrypt connection.
///
/// Connects to the upstream with retry, performs TLS/kTLS handshake,
/// then runs bidirectional relay between the plain client and encrypted upstream.
pub(crate) fn handle_tcp_encrypt(
    rule_name: &str,
    client: TcpStream,
    upstream_addr: &str,
    tls_mode: TlsMode,
    measure_latency: bool,
    sock_buf_size: usize,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &AtomicBool,
    delay_ms: u64,
    protocol_version: Option<&str>,
) -> io::Result<()> {
    // Connect to upstream with exponential backoff retry
    let upstream_tcp = connect_with_retry(
        upstream_addr,
        4,
        Duration::from_secs(1),
        Duration::from_secs(4),
        shutdown,
    )?;
    let up_fd = upstream_tcp.as_raw_fd();
    tune_socket_buffers(up_fd, sock_buf_size);
    set_nodelay(up_fd, true);

    // Establish TLS on the upstream connection
    let hs_start = Instant::now();
    let mut upstream: ProxyStream = match tls_mode {
        TlsMode::Tls => {
            let connector = build_tls_connector(protocol_version).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("TLS connector: {}", e))
            })?;
            let ssl_stream = connector.connect("gateway", upstream_tcp).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("TLS handshake: {}", e))
            })?;
            info!(
                "[{}] TLS handshake OK ({:.2} ms)",
                rule_name,
                hs_start.elapsed().as_secs_f64() * 1000.0
            );
            ProxyStream::Tls(ssl_stream)
        }
        TlsMode::Ktls => {
            let connector = ktls_client_connector(protocol_version).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("kTLS connector: {}", e))
            })?;
            let mut ssl = connector
                .configure()
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("kTLS configure: {}", e))
                })?
                .into_ssl("gateway")
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("kTLS SSL: {}", e)))?;
            ssl.set_connect_state();
            unsafe {
                enable_ktls_ssl(ssl.as_ptr());
            }
            let mut session = KtlsSession::new(ssl, up_fd as libc::c_int).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("kTLS session: {}", e))
            })?;
            session.connect().map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("kTLS handshake: {}", e))
            })?;

            let ulp = get_tcp_ulp(&upstream_tcp).unwrap_or_default();
            let ktls_active = ulp.starts_with("tls");
            debug!(
                "[{}] kTLS handshake OK ({:.2} ms, ULP={}, active={})",
                rule_name,
                hs_start.elapsed().as_secs_f64() * 1000.0,
                ulp,
                ktls_active
            );
            if !ktls_active {
                warn!(
                    "[{}] WARNING: kTLS not active.{}",
                    rule_name,
                    ktls_privilege_hint()
                );
            }

            ProxyStream::Ktls {
                session,
                _stream: upstream_tcp,
            }
        }
        TlsMode::Dtls => unreachable!("DTLS uses run_dtls_encrypt_relay, not tcp encrypt"),
    };
    conn_metrics.handshake_ms = hs_start.elapsed().as_secs_f64() * 1000.0;

    // Bidirectional relay: client (plain) <-> upstream (TLS)
    // Use zero-copy splice for kTLS, buffered relay for userspace TLS
    match tls_mode {
        TlsMode::Ktls => {
            let client_fd = client.as_raw_fd();
            let tls_fd = upstream.raw_fd();
            relay_bidirectional_splice(
                client_fd,
                tls_fd,
                measure_latency,
                conn_metrics,
                shutdown,
                delay_ms,
            )?;
        }
        _ => {
            relay_encrypt_bidirectional(
                client,
                &mut upstream,
                measure_latency,
                conn_metrics,
                shutdown,
                delay_ms,
            )?;
        }
    }

    upstream.shutdown_write();
    Ok(())
}

// =============================================================================
//                   ENCRYPT DIRECTION: UDP -> TLS (tunneled)
// =============================================================================

/// UDP encrypt relay: receives UDP datagrams, tunnels them through a single
/// TLS connection with length-prefixed framing.
///
/// Each datagram is sent as `[len:u32 LE][payload]` inside the TLS stream.
/// The TLS tunnel is established lazily on the first received UDP datagram,
/// avoiding blocking the gateway when upstream is unreachable at startup.
pub(crate) fn run_udp_encrypt_relay(ctx: &RuleContext) {
    let socket = match bind_udp_socket(&ctx.listen_addr, ctx.transparent, &ctx.rule_name) {
        Some(s) => s,
        None => return,
    };

    // Set timeout for shutdown checks
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok();
    tune_socket_buffers(socket.as_raw_fd(), ctx.sock_buf_size);

    // Lazy TLS tunnel: established on first UDP datagram, not at startup.
    let mut tls_stream: Option<ProxyStream> = None;
    info!(
        "[{}] Waiting for first UDP datagram before connecting TLS tunnel to {}",
        ctx.rule_name, ctx.upstream_addr
    );

    let mut conn_metrics = ConnectionMetrics::with_rule_metrics(
        "encrypt-udp",
        &ctx.tls_mode.to_string(),
        ctx.metrics.clone(),
    );
    ctx.metrics.connection_opened();

    let mut udp_buf = vec![0u8; UDP_BUF_SIZE];
    let mut tls_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut last_peer: Option<SocketAddr> = None;

    // Set non-blocking for poll-based bidirectional I/O
    socket.set_nonblocking(true).ok();

    // ALE framing state
    let mut ale_writer = AleFrameWriter::new(0x00); // default app type for gateway mode
    let mut ale_reader = AleFrameReader::new();
    let mut batch_buf: Vec<u8> = Vec::with_capacity(64 * 1024);

    while !ctx.shutdown.load(Ordering::Relaxed) {
        let udp_fd_raw = socket.as_raw_fd();

        // If tunnel not yet established, only poll the UDP socket
        if tls_stream.is_none() {
            let mut fds = [libc::pollfd {
                fd: udp_fd_raw,
                events: libc::POLLIN,
                revents: 0,
            }];
            let ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, 1000) };
            if ret <= 0 {
                continue;
            }
            if fds[0].revents & libc::POLLIN == 0 {
                continue;
            }

            // First datagram arrived -- establish TLS tunnel now
            info!(
                "[{}] First UDP datagram received, connecting TLS tunnel to {} ...",
                ctx.rule_name, ctx.upstream_addr
            );
            let mut retry_delay = Duration::from_secs(2);
            let max_retry_delay = Duration::from_secs(30);

            let established = loop {
                if ctx.shutdown.load(Ordering::Relaxed) {
                    return;
                }

                let upstream_target: SocketAddr = ctx.upstream_addr.parse().unwrap();
                let upstream_tcp =
                    match TcpStream::connect_timeout(&upstream_target, Duration::from_secs(5)) {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                            "[{}] FAILED to connect to upstream {}: {} \u{2014} retrying in {}s",
                            ctx.rule_name,
                            ctx.upstream_addr,
                            e,
                            retry_delay.as_secs()
                        );
                            if sleep_with_shutdown_check(retry_delay, &ctx.shutdown) {
                                return;
                            }
                            retry_delay = (retry_delay * 2).min(max_retry_delay);
                            continue;
                        }
                    };
                tune_socket_buffers(upstream_tcp.as_raw_fd(), ctx.sock_buf_size);
                set_nodelay(upstream_tcp.as_raw_fd(), true);

                let hs_start = Instant::now();
                let stream = match ctx.tls_mode {
                    TlsMode::Tls => {
                        let connector = match build_tls_connector(ctx.protocol_version.as_deref()) {
                            Ok(c) => c,
                            Err(e) => {
                                error!(
                                    "[{}] TLS connector error: {} \u{2014} retrying in {}s",
                                    ctx.rule_name,
                                    e,
                                    retry_delay.as_secs()
                                );
                                if sleep_with_shutdown_check(retry_delay, &ctx.shutdown) {
                                    return;
                                }
                                retry_delay = (retry_delay * 2).min(max_retry_delay);
                                continue;
                            }
                        };
                        match connector.connect("gateway", upstream_tcp) {
                            Ok(s) => {
                                info!(
                                    "[{}] TLS tunnel established ({:.2} ms)",
                                    ctx.rule_name,
                                    hs_start.elapsed().as_secs_f64() * 1000.0
                                );
                                ProxyStream::Tls(s)
                            }
                            Err(e) => {
                                error!(
                                    "[{}] TLS handshake failed: {} \u{2014} retrying in {}s",
                                    ctx.rule_name,
                                    e,
                                    retry_delay.as_secs()
                                );
                                if sleep_with_shutdown_check(retry_delay, &ctx.shutdown) {
                                    return;
                                }
                                retry_delay = (retry_delay * 2).min(max_retry_delay);
                                continue;
                            }
                        }
                    }
                    TlsMode::Ktls => {
                        let connector = match ktls_client_connector(ctx.protocol_version.as_deref())
                        {
                            Ok(c) => c,
                            Err(e) => {
                                error!(
                                    "[{}] kTLS connector error: {} \u{2014} retrying in {}s",
                                    ctx.rule_name,
                                    e,
                                    retry_delay.as_secs()
                                );
                                if sleep_with_shutdown_check(retry_delay, &ctx.shutdown) {
                                    return;
                                }
                                retry_delay = (retry_delay * 2).min(max_retry_delay);
                                continue;
                            }
                        };
                        let up_fd = upstream_tcp.as_raw_fd();
                        let ssl_result = connector
                            .configure()
                            .and_then(|c| c.into_ssl("gateway"))
                            .map_err(|e| {
                                error!("[{}] kTLS SSL setup error: {}", ctx.rule_name, e);
                            });
                        let mut ssl = match ssl_result {
                            Ok(s) => s,
                            Err(_) => {
                                if sleep_with_shutdown_check(retry_delay, &ctx.shutdown) {
                                    return;
                                }
                                retry_delay = (retry_delay * 2).min(max_retry_delay);
                                continue;
                            }
                        };
                        ssl.set_connect_state();
                        unsafe {
                            enable_ktls_ssl(ssl.as_ptr());
                        }
                        let mut session = match KtlsSession::new(ssl, up_fd as libc::c_int) {
                            Ok(s) => s,
                            Err(e) => {
                                error!(
                                    "[{}] kTLS session error: {} \u{2014} retrying in {}s",
                                    ctx.rule_name,
                                    e,
                                    retry_delay.as_secs()
                                );
                                if sleep_with_shutdown_check(retry_delay, &ctx.shutdown) {
                                    return;
                                }
                                retry_delay = (retry_delay * 2).min(max_retry_delay);
                                continue;
                            }
                        };
                        if let Err(e) = session.connect() {
                            error!(
                                "[{}] kTLS handshake failed: {} \u{2014} retrying in {}s",
                                ctx.rule_name,
                                e,
                                retry_delay.as_secs()
                            );
                            if sleep_with_shutdown_check(retry_delay, &ctx.shutdown) {
                                return;
                            }
                            retry_delay = (retry_delay * 2).min(max_retry_delay);
                            continue;
                        }
                        info!(
                            "[{}] kTLS tunnel established ({:.2} ms)",
                            ctx.rule_name,
                            hs_start.elapsed().as_secs_f64() * 1000.0
                        );
                        ProxyStream::Ktls {
                            session,
                            _stream: upstream_tcp,
                        }
                    }
                    TlsMode::Dtls => {
                        unreachable!("DTLS uses run_dtls_encrypt_relay, not udp encrypt")
                    }
                };
                conn_metrics.handshake_ms = hs_start.elapsed().as_secs_f64() * 1000.0;
                break stream;
            };

            // Set TLS fd to non-blocking for poll-based I/O
            set_nonblocking_fd(established.raw_fd());
            tls_stream = Some(established);

            // Perform ALE handshake (AU1 -> AU2) over the TLS stream
            {
                let tls = tls_stream.as_mut().unwrap();

                // Send AU1 (connection request)
                let au1_info = AleAu1Info {
                    calling_etcs_id: 0,
                    called_etcs_id: 0,
                    class_of_service: ALE_CLASS_D,
                };
                let au1_data = au1_info.encode(&[]);
                if let Err(e) = ale_writer.write_alepkt(tls, ALE_PKT_AU1, &au1_data) {
                    error!("[{}] ALE AU1 send failed: {}", ctx.rule_name, e);
                    tls_stream = None;
                    continue;
                }

                // Read AU2 response (blocking — fd is still non-blocking, use poll)
                let tls_fd = tls.raw_fd();
                let mut hs_reader = AleFrameReader::new();
                let mut hs_buf = [0u8; 256];
                let mut au2_ok = false;
                for _ in 0..50 {
                    // 50 * 100ms = 5s timeout
                    let mut fds = [libc::pollfd {
                        fd: tls_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    }];
                    let ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, 100) };
                    if ret <= 0 {
                        if ctx.shutdown.load(Ordering::Relaxed) {
                            return;
                        }
                        continue;
                    }
                    match tls.read(&mut hs_buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            match hs_reader.feed(&hs_buf[..n]) {
                                Ok(frames) => {
                                    for frame in frames {
                                        if frame.header.packet_type == ALE_PKT_AU2 {
                                            if let Some((au2, _)) =
                                                AleAu2Info::decode(&frame.user_data)
                                            {
                                                debug!(
                                                    "[{}] ALE handshake OK (responding ETCS-ID: 0x{:08X})",
                                                    ctx.rule_name, au2.responding_etcs_id
                                                );
                                            }
                                            au2_ok = true;
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("[{}] ALE handshake read error: {}", ctx.rule_name, e);
                                    break;
                                }
                            }
                            if au2_ok {
                                break;
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(e) => {
                            error!("[{}] ALE AU2 read error: {}", ctx.rule_name, e);
                            break;
                        }
                    }
                }
                if !au2_ok {
                    error!(
                        "[{}] ALE handshake timed out waiting for AU2",
                        ctx.rule_name
                    );
                    tls_stream = None;
                    continue;
                }
            }

            // Fall through to process the waiting datagram(s)
        }

        let tls = tls_stream.as_mut().unwrap();
        let tls_fd_raw = tls.raw_fd();
        let tls_pending = tls.ssl_pending();

        // Poll both UDP and TLS fds
        let (udp_ready, tls_ready) = match poll_two_fds(udp_fd_raw, tls_fd_raw, tls_pending, 1000) {
            Ok(r) => r,
            Err(_) => break,
        };
        if !udp_ready && !tls_ready {
            continue;
        }

        // Forward: UDP -> TLS (encrypt and tunnel with ALE framing)
        // Drain all pending UDP datagrams into a batch buffer, then flush once
        if udp_ready {
            batch_buf.clear();
            'udp_fwd: loop {
                match socket.recv_from(&mut udp_buf) {
                    Ok((n, src)) => {
                        last_peer = Some(src);
                        conn_metrics.record_read(n);
                        // Write ALE DT frame into batch buffer (infallible for Vec<u8>)
                        let _ = ale_writer.write_alepkt(&mut batch_buf, ALE_PKT_DT, &udp_buf[..n]);
                        conn_metrics.record_relay(n, None);
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break 'udp_fwd,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        error!("[{}] UDP recv error: {}", ctx.rule_name, e);
                        break 'udp_fwd;
                    }
                }
            }
            // Flush all accumulated ALE frames in a single TLS write
            if !batch_buf.is_empty() {
                apply_geo_delay(ctx.simulated_delay_ms);
                let t0 = if ctx.measure_latency { now_ns() } else { 0 };
                if write_all_nb_proxy(tls, &batch_buf).is_err() {
                    break; // TLS connection is dead — exit outer loop
                }
                if ctx.measure_latency {
                    let lat = now_ns() - t0;
                    conn_metrics.latency_samples_ns.push(lat);
                }
            }
        }

        // Reverse: TLS -> UDP (read ALE frames from TLS, send user data as datagrams back to client)
        if tls_ready {
            'tls_read: loop {
                match tls.read(&mut tls_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        match ale_reader.feed(&tls_buf[..n]) {
                            Ok(frames) => {
                                for frame in frames {
                                    match frame.header.packet_type {
                                        ALE_PKT_DT => {
                                            if let Some(peer) = last_peer {
                                                let _ = socket.send_to(&frame.user_data, peer);
                                            }
                                            let data_len = frame.user_data.len();
                                            conn_metrics.record_read(data_len);
                                            conn_metrics.record_relay(data_len, None);
                                        }
                                        ALE_PKT_DI => {
                                            debug!(
                                                "[{}] Received ALE DI (disconnect)",
                                                ctx.rule_name
                                            );
                                            break 'tls_read;
                                        }
                                        _ => {} // Ignore other packet types
                                    }
                                }
                            }
                            Err(AleError::ChecksumMismatch { expected, got }) => {
                                error!(
                                    "[{}] ALE checksum mismatch: expected 0x{:04X}, got 0x{:04X} — disconnecting",
                                    ctx.rule_name, expected, got
                                );
                                break 'tls_read;
                            }
                            Err(e) => {
                                error!("[{}] ALE frame error: {}", ctx.rule_name, e);
                                break 'tls_read;
                            }
                        }
                        if tls.ssl_pending() == 0 {
                            break 'tls_read;
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break 'tls_read,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break 'tls_read,
                }
            }
        }
    }

    // Send ALE DI and shutdown TLS tunnel if established
    if let Some(mut tls) = tls_stream {
        let _ = ale_writer.write_alepkt(&mut tls, ALE_PKT_DI, &[]);
        tls.shutdown_write();
    }

    let elapsed = conn_metrics.elapsed_secs();
    debug!(
        "[{}] UDP encrypt done: {:.3}s, {} msgs, {}",
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

    // CSV logging
    if let Ok(mut guard) = (Arc::new(Mutex::new(
        CsvLogger::new(
            &ctx.log_dir,
            "gateway",
            &format!("encrypt-udp-{}", ctx.tls_mode),
            &ctx.run_id,
        )
        .ok(),
    )))
    .lock()
    {
        if let Some(ref mut logger) = *guard {
            log_connection_csv(logger, &mut conn_metrics, &ctx.run_id);
        }
    }

    ctx.metrics.merge_connection(&conn_metrics);
    ctx.metrics.connection_closed();
}
