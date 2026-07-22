//! Encrypt direction proxy: plain TCP/UDP -> TLS/kTLS upstream.
//!
//! - `run_tcp_encrypt_listener` -- accept plain TCP, connect TLS/kTLS to upstream, relay
//! - `handle_tcp_encrypt` -- per-connection handler for a single TCP encrypt connection
//! - `run_udp_encrypt_relay` -- receive UDP datagrams, tunnel through TLS with framing

use super::params::TlsSecurityParams;
use super::{
    build_ktls_connector, build_tls_connector, prime_resumption, resumption_key,
    set_handshake_timeouts, write_all_nb_proxy, ProxyStream,
};
use crate::networking::connector::{connect_with_retry, sleep_with_shutdown_check};
use crate::networking::socket_manager::{
    accept_with_timeout, apply_egress_qos, apply_safety_priority, apply_tcp_latency_opts,
    bind_tcp_listener, bind_udp_socket, poll_two_fds, set_nodelay, set_nonblocking_fd,
    tune_socket_buffers, MmsgRecvBuf, MmsgSendBuf, UDP_MMSG_BATCH,
};
use crate::processing::RuleContext;
use crate::security::relay::{
    apply_geo_delay, relay_bidirectional_splice, relay_encrypt_bidirectional,
};
use crate::security::udp_framing::UdpFraming;
use crate::security::{ACCEPT_TIMEOUT, HANDSHAKE_TIMEOUT, RELAY_BUF_SIZE, UDP_BUF_SIZE};
use ale_pipe::{
    AleAu1Info, AleAu2Info, AleFrameReader, AleFrameWriter, ALE_CLASS_D, ALE_PKT_AU1, ALE_PKT_AU2,
};

use crate::interfaces::tproxy;
use crate::management::config::{PerfKnobs, QosPolicy, TlsMode};
use crate::management::telemetry::{format_rate, ConnectionMetrics};

use foreign_types_shared::ForeignTypeRef;
use ktls_pipe::{enable_ktls_ssl, get_tcp_ulp, ktls_privilege_hint, KtlsSession};
use log::{debug, error, info, warn};
use openssl::ssl::SslConnector;

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn build_connector_for_mode(
    tls_mode: TlsMode,
    params: &TlsSecurityParams,
) -> Result<SslConnector, String> {
    match tls_mode {
        TlsMode::Tls => build_tls_connector(params),
        TlsMode::Ktls => build_ktls_connector(params),
        TlsMode::Dtls => Err("DTLS does not use the TCP TLS connector".to_string()),
    }
}

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
    // Listener port, for original-destination recovery (M10).
    let listen_port = listener.local_addr().ok().map(|a| a.port());

    // Resolve typed security parameters once; shared by all connections.
    let tls_params =
        match TlsSecurityParams::from_params(&ctx.provider_params, ctx.protocol_version.as_deref())
        {
            Ok(p) => Arc::new(p),
            Err(e) => {
                error!("[{}] TLS parameter error: {}", ctx.rule_name, e);
                return;
            }
        };
    let tls_connector = match ctx.tls_mode {
        TlsMode::Tls | TlsMode::Ktls => match build_connector_for_mode(ctx.tls_mode, &tls_params) {
            Ok(connector) => Some(Arc::new(connector)),
            Err(e) => {
                error!(
                    "[{}] {} connector error: {}",
                    ctx.rule_name, ctx.tls_mode, e
                );
                return;
            }
        },
        TlsMode::Dtls => None,
    };

    while !ctx.shutdown.load(Ordering::Relaxed) {
        let (client_stream, peer_addr) = match accept_with_timeout(&listener, ACCEPT_TIMEOUT) {
            Some(Ok((s, a))) => (s, a),
            Some(Err(e)) => {
                error!("[{}] Accept error: {}", ctx.rule_name, e);
                continue;
            }
            None => continue, // timeout, check shutdown
        };

        // Determine upstream target. For a transparent rule with the `"auto"`
        // upstream, recover the original destination (REDIRECT/DNAT *or* true
        // TPROXY) and fail closed if it cannot be recovered — the old
        // SO_ORIGINAL_DST-only path silently misrouted TPROXY flows to the
        // configured upstream (M10). A transparent rule with an explicit
        // upstream is a fixed-forward interceptor and forwards there.
        let target = if ctx.transparent && ctx.upstream_addr == "auto" {
            match tproxy::recover_transparent_dst(client_stream.as_raw_fd(), listen_port) {
                Some(orig) => {
                    debug!(
                        "[{}] transparent {} \u{2192} {} (recovered original dst)",
                        ctx.rule_name, peer_addr, orig
                    );
                    orig.to_string()
                }
                None => {
                    warn!(
                        "[{}] dropping {}: could not recover transparent original dst",
                        ctx.rule_name, peer_addr
                    );
                    continue;
                }
            }
        } else {
            ctx.upstream_addr.clone()
        };

        // Traffic classification + policy check (fail closed on an unparseable
        // upstream target — DP-07).
        if !ctx.classify_and_check_policy_target(&peer_addr, &target) {
            continue; // Drop connection — policy denied or target unresolvable
        }

        let fd = client_stream.as_raw_fd();
        tune_socket_buffers(fd, ctx.sock_buf_size);
        set_nodelay(fd, true);
        apply_tcp_latency_opts(fd, ctx.perf.notsent_lowat, ctx.perf.busy_poll_us);
        // Prioritise the client-facing (SCG → client) return path.
        ctx.apply_egress_qos(fd, peer_addr.is_ipv6(), None);

        ctx.metrics.connection_opened();

        // Clone shared state for the per-connection thread
        let metrics = ctx.metrics.clone();
        let rule_name = ctx.rule_name.clone();
        let tls_mode = ctx.tls_mode;
        let shutdown = ctx.shutdown.clone();
        let sock_buf_size = ctx.sock_buf_size;
        let traffic_class = ctx.traffic_class;
        let simulated_delay_ms = ctx.simulated_delay_ms;
        let tls_params = tls_params.clone();
        let tls_connector = tls_connector.clone();
        let qos = ctx.qos;
        let perf = ctx.perf;

        let pool = ctx.conn_pool.clone();
        pool.execute(move || {
            // Safety traffic always runs at elevated thread priority.
            apply_safety_priority(traffic_class);

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
                sock_buf_size,
                &mut conn_metrics,
                &shutdown,
                simulated_delay_ms,
                &tls_params,
                tls_connector.as_deref(),
                qos,
                perf,
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
// Internal engine entry point; a param struct is a larger refactor than warranted here.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_tcp_encrypt(
    rule_name: &str,
    client: TcpStream,
    upstream_addr: &str,
    tls_mode: TlsMode,
    sock_buf_size: usize,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &AtomicBool,
    delay_ms: u64,
    params: &TlsSecurityParams,
    tls_connector: Option<&SslConnector>,
    qos: QosPolicy,
    perf: PerfKnobs,
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
    apply_tcp_latency_opts(up_fd, perf.notsent_lowat, perf.busy_poll_us);
    // Mark + prioritise the upstream (SCG → upstream) egress socket.
    let up_is_v6 = upstream_tcp
        .peer_addr()
        .map(|a| a.is_ipv6())
        .unwrap_or(false);
    apply_egress_qos(up_fd, qos.egress_dscp(None), qos.so_priority(), up_is_v6);

    // SNI / verification hostname for the upstream connection.
    let sni = params.sni_name(upstream_addr);

    // Bound the blocking handshake window so a black-holed or hijacked upstream
    // that accepts the TCP connection but stalls the handshake cannot pin this
    // worker (DoS-01). Cleared once the handshake completes, below.
    set_handshake_timeouts(&upstream_tcp, Some(HANDSHAKE_TIMEOUT))?;

    // Establish TLS on the upstream connection
    let hs_start = Instant::now();
    // True only when kTLS actually activates (ULP=tls) on the connect arm below.
    // The splice relay MUST gate on this, not on `tls_mode` — see TRA #56.
    let mut ktls_active = false;
    let mut upstream: ProxyStream = match tls_mode {
        TlsMode::Tls => {
            let connector = tls_connector
                .ok_or_else(|| io::Error::other("TLS connector was not initialised"))?;
            let ssl_stream = if params.resumption {
                // Present a cached ticket for this exact upstream + crypto policy so the
                // reconnect can resume (task S2 / TRA #78–#80), mirroring the interface
                // endpoint connector. `configure()` keeps the same SNI/verification
                // defaults as `connect()`, so priming is transparent.
                let key = resumption_key(params, upstream_addr, false);
                let mut config = connector
                    .configure()
                    .map_err(|e| io::Error::other(format!("TLS configure: {}", e)))?;
                prime_resumption(&mut config, key);
                config
                    .connect(&sni, upstream_tcp)
                    .map_err(|e| io::Error::other(format!("TLS handshake: {}", e)))?
            } else {
                connector
                    .connect(&sni, upstream_tcp)
                    .map_err(|e| io::Error::other(format!("TLS handshake: {}", e)))?
            };
            info!(
                "[{}] TLS handshake OK ({:.2} ms)",
                rule_name,
                hs_start.elapsed().as_secs_f64() * 1000.0
            );
            // Handshake done — restore blocking I/O for the relay phase.
            set_handshake_timeouts(ssl_stream.get_ref(), None)?;
            ProxyStream::Tls(ssl_stream)
        }
        TlsMode::Ktls => {
            let connector = tls_connector
                .ok_or_else(|| io::Error::other("kTLS connector was not initialised"))?;
            let mut ssl = connector
                .configure()
                .map_err(|e| io::Error::other(format!("kTLS configure: {}", e)))?
                .into_ssl(&sni)
                .map_err(|e| io::Error::other(format!("kTLS SSL: {}", e)))?;
            if params.resumption {
                // Resume this upstream+policy if a ticket is cached (task S2 / TRA #78–#80).
                prime_resumption(&mut ssl, resumption_key(params, upstream_addr, true));
            }
            ssl.set_connect_state();
            // SAFETY: `ssl.as_ptr()` returns a valid, non-null pointer to the live `SSL`
            // object owned by `ssl`, which outlives this call; `enable_ktls_ssl` only
            // configures kTLS on that handle and the handle is not aliased elsewhere here.
            unsafe {
                enable_ktls_ssl(ssl.as_ptr());
            }
            let mut session = KtlsSession::new(ssl, up_fd as libc::c_int)
                .map_err(|e| io::Error::other(format!("kTLS session: {}", e)))?;
            session
                .connect()
                .map_err(|e| io::Error::other(format!("kTLS handshake: {}", e)))?;

            let ulp = get_tcp_ulp(&upstream_tcp).unwrap_or_default();
            ktls_active = ulp.starts_with("tls");
            info!(
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

            // Handshake done — restore blocking I/O for the relay phase.
            set_handshake_timeouts(&upstream_tcp, None)?;
            ProxyStream::Ktls {
                session,
                _stream: upstream_tcp,
            }
        }
        TlsMode::Dtls => unreachable!("DTLS uses run_dtls_encrypt_relay, not tcp encrypt"),
    };

    // Bidirectional relay: client (plain) <-> upstream (TLS).
    // Zero-copy splice is correct ONLY when kTLS actually activated: the raw fd
    // then carries plaintext (the kernel does the crypto). If kTLS was requested
    // but did not activate, the fd carries ciphertext, so we relay through the
    // userspace SSL session instead — otherwise we would splice cleartext onto
    // the wire (TRA #56).
    if matches!(tls_mode, TlsMode::Ktls) && ktls_active {
        let client_fd = client.as_raw_fd();
        let tls_fd = upstream.raw_fd();
        relay_bidirectional_splice(
            client_fd,
            tls_fd,
            conn_metrics,
            shutdown,
            delay_ms,
            perf.pipe_size,
            perf.busy_poll_us,
            perf.bdp_adaptive,
            perf.bdp_queue_budget_us,
        )?;
    } else {
        relay_encrypt_bidirectional(
            client,
            &mut upstream,
            conn_metrics,
            shutdown,
            delay_ms,
            perf.enable_cork,
            perf.relay_buf_size,
            perf.busy_poll_us,
            perf.bdp_adaptive,
            perf.bdp_queue_budget_us,
        )?;
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

    // Safety traffic always runs at elevated thread priority.
    apply_safety_priority(ctx.traffic_class);

    // Set timeout for shutdown checks
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok();
    tune_socket_buffers(socket.as_raw_fd(), ctx.sock_buf_size);
    // Prioritise the client-facing UDP return path; sample inbound DSCP when
    // the rule preserves it.
    let udp_is_v6 = socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    ctx.apply_egress_qos(socket.as_raw_fd(), udp_is_v6, None);
    ctx.enable_inbound_dscp_sampling(socket.as_raw_fd(), udp_is_v6);
    let tls_params =
        match TlsSecurityParams::from_params(&ctx.provider_params, ctx.protocol_version.as_deref())
        {
            Ok(p) => p,
            Err(e) => {
                error!("[{}] TLS parameter error: {}", ctx.rule_name, e);
                return;
            }
        };
    let sni = tls_params.sni_name(&ctx.upstream_addr);

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

    let mut tls_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut last_peer: Option<SocketAddr> = None;
    // Batched UDP I/O: one `recvmmsg`/`sendmmsg` per drain amortises the
    // per-datagram syscall on the client-facing leg.
    let mut udp_rx = MmsgRecvBuf::new(UDP_MMSG_BATCH, UDP_BUF_SIZE);
    let mut udp_tx = MmsgSendBuf::new();

    // Set non-blocking for poll-based bidirectional I/O
    socket.set_nonblocking(true).ok();

    // UDP-over-TLS application framing: ALE (Subset-098) or raw length-prefix,
    // selected by the rule's `app_protocol`.
    let mut framing = UdpFraming::for_app_protocol(&ctx.app_protocol);
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
            // SAFETY: `fds` is a fully-initialised array of exactly one `libc::pollfd`;
            // `fds.as_mut_ptr()` is valid and writable for the `1` element passed as the
            // count, and `udp_fd_raw` is a live descriptor owned by `socket`. The return
            // value is checked below before `fds[0].revents` is read.
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

                let upstream_target: SocketAddr = match ctx.upstream_addr.parse() {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!(
                            "[{}] invalid upstream address '{}': {} \u{2014} stopping rule",
                            ctx.rule_name, ctx.upstream_addr, e
                        );
                        return;
                    }
                };
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
                // Mark + prioritise the upstream TLS-tunnel egress socket.
                let up_is_v6 = upstream_tcp
                    .peer_addr()
                    .map(|a| a.is_ipv6())
                    .unwrap_or(false);
                ctx.apply_egress_qos(upstream_tcp.as_raw_fd(), up_is_v6, None);

                // Bound the handshake window so a stalled upstream cannot wedge
                // this rule thread (DoS-01); best-effort, cleared on success below.
                let _ = set_handshake_timeouts(&upstream_tcp, Some(HANDSHAKE_TIMEOUT));

                let hs_start = Instant::now();
                let stream = match ctx.tls_mode {
                    TlsMode::Tls => {
                        let connector = match build_tls_connector(&tls_params) {
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
                        match connector.connect(&sni, upstream_tcp) {
                            Ok(s) => {
                                info!(
                                    "[{}] TLS tunnel established ({:.2} ms)",
                                    ctx.rule_name,
                                    hs_start.elapsed().as_secs_f64() * 1000.0
                                );
                                // Restore blocking I/O for the relay phase.
                                let _ = set_handshake_timeouts(s.get_ref(), None);
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
                        let connector = match build_ktls_connector(&tls_params) {
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
                            .and_then(|c| c.into_ssl(&sni))
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
                        // SAFETY: `ssl.as_ptr()` returns a valid, non-null pointer to the
                        // live `SSL` object owned by `ssl`, which outlives this call;
                        // `enable_ktls_ssl` only configures kTLS on that handle and the
                        // handle is not aliased elsewhere here.
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
                        // Restore blocking I/O for the relay phase.
                        let _ = set_handshake_timeouts(&upstream_tcp, None);
                        ProxyStream::Ktls {
                            session,
                            _stream: upstream_tcp,
                        }
                    }
                    TlsMode::Dtls => {
                        unreachable!("DTLS uses run_dtls_encrypt_relay, not udp encrypt")
                    }
                };
                break stream;
            };

            // Set TLS fd to non-blocking for poll-based I/O
            set_nonblocking_fd(established.raw_fd());
            tls_stream = Some(established);

            // Perform ALE handshake (AU1 -> AU2) over the TLS stream. Skipped
            // for raw framing, which has no association handshake.
            if framing.is_ale() {
                let tls = tls_stream.as_mut().unwrap();

                // Send AU1 (connection request)
                let mut ale_writer = AleFrameWriter::new(0x00);
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
                    // SAFETY: `fds` is a fully-initialised array of exactly one
                    // `libc::pollfd`; `fds.as_mut_ptr()` is valid and writable for the `1`
                    // element passed as the count, and `tls_fd` is a live descriptor owned
                    // by the established TLS stream. The return value is checked below.
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

        // Forward: UDP -> TLS (encrypt and tunnel with ALE framing).
        // Drain pending UDP datagrams in batched `recvmmsg` reads into a batch
        // buffer, then flush once. The single-client source pin is re-checked
        // PER datagram in the batch (TRA #7/#39): the kernel returns each
        // datagram's source in the `recvmmsg` batch, and a second source on this
        // identity-less single TLS/ALE stream is dropped, never multiplexed.
        if udp_ready {
            batch_buf.clear();
            'udp_fwd: loop {
                let count = match udp_rx.recv(udp_fd_raw) {
                    Ok(0) => break 'udp_fwd,
                    Ok(c) => c,
                    Err(e) => {
                        error!("[{}] UDP recv error: {}", ctx.rule_name, e);
                        break 'udp_fwd;
                    }
                };
                for i in 0..count {
                    let Some((src, payload)) = udp_rx.get(i) else {
                        continue;
                    };
                    match src {
                        Some(s) if accept_source(&mut last_peer, s) => {}
                        Some(s) => {
                            // Second client on this single-client encrypt stream:
                            // ignore rather than multiplex (would route reverse
                            // responses to the wrong client — CWE-200, #7/#39).
                            debug!(
                                "[{}] ignoring datagram from {} (stream pinned to {:?})",
                                ctx.rule_name, s, last_peer
                            );
                            continue;
                        }
                        None => continue, // unrecognised source address family
                    }
                    conn_metrics.record_read(payload.len());
                    framing.frame_into(payload, &mut batch_buf);
                    conn_metrics.record_relay(payload.len());
                }
            }
            // Flush all accumulated ALE frames in a single TLS write
            if !batch_buf.is_empty() {
                apply_geo_delay(ctx.simulated_delay_ms);
                if write_all_nb_proxy(tls, &batch_buf).is_err() {
                    break; // TLS connection is dead — exit outer loop
                }
            }
        }

        // Reverse: TLS -> UDP (deframe ALE/raw, send user data as datagrams back
        // to the pinned client in one `sendmmsg` per TLS read). Datagrams are
        // staged only when a client is pinned; with no peer yet they are dropped
        // (metrics still recorded), exactly as the prior `if let Some(peer)` did.
        if tls_ready {
            'tls_read: loop {
                match tls.read(&mut tls_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let disconnect =
                            framing.deframe_each(&ctx.rule_name, &tls_buf[..n], |datagram| {
                                if last_peer.is_some() {
                                    udp_tx.push(datagram);
                                }
                                let data_len = datagram.len();
                                conn_metrics.record_read(data_len);
                                conn_metrics.record_relay(data_len);
                            });
                        if let Some(peer) = last_peer {
                            if !udp_tx.is_empty() {
                                let _ = udp_tx.flush(udp_fd_raw, Some(peer));
                            }
                        }
                        if disconnect {
                            break 'tls_read;
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

    // Send ALE DI (no-op for raw) and shutdown TLS tunnel if established
    if let Some(mut tls) = tls_stream {
        framing.write_disconnect(&mut tls);
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

    ctx.metrics.merge_connection(&conn_metrics);
    ctx.metrics.connection_closed();
}

/// Pin a UDP-over-TLS encrypt stream to its first client.
///
/// Returns whether `src` is the bound client, binding it on the first call. A
/// second, distinct source is rejected: the relay multiplexes all UDP clients
/// over one TLS/ALE stream that carries no per-client identity, so accepting a
/// second client would let reverse responses be delivered to the wrong client
/// (cross-flow leak / injection — CWE-200). One client per encrypt stream is the
/// safe behaviour; true multiplexing would require per-client tunnels.
fn accept_source(bound: &mut Option<SocketAddr>, src: SocketAddr) -> bool {
    match *bound {
        None => {
            *bound = Some(src);
            true
        }
        Some(b) => b == src,
    }
}

#[cfg(test)]
mod single_client_tests {
    use super::accept_source;
    use std::net::SocketAddr;

    #[test]
    fn first_source_binds_then_only_it_is_accepted() {
        let a: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let mut bound = None;
        // First client binds and is accepted.
        assert!(accept_source(&mut bound, a));
        assert_eq!(bound, Some(a));
        // The bound client keeps being accepted.
        assert!(accept_source(&mut bound, a));
        // A second client is rejected and does not steal the binding.
        assert!(!accept_source(&mut bound, b));
        assert_eq!(bound, Some(a));
        // The original client still works afterwards.
        assert!(accept_source(&mut bound, a));
    }
}
