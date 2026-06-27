//! Decrypt direction: accept TLS/kTLS connections and relay to plain TCP/UDP upstream.

use super::params::TlsSecurityParams;
use super::{build_ktls_acceptor, build_tls_acceptor, ProxyStream};
use crate::networking::connector::connect_with_retry;
use crate::networking::socket_manager::{
    accept_with_timeout, apply_egress_qos, apply_safety_priority, apply_tcp_latency_opts,
    bind_tcp_listener, set_nodelay, tune_socket_buffers,
};
use crate::processing::RuleContext;
use crate::security::relay::{relay_bidirectional, relay_bidirectional_splice, relay_tls_to_udp};
use crate::security::udp_framing::UdpFraming;
use crate::security::ACCEPT_TIMEOUT;
use ale_pipe::{AleAu1Info, AleAu2Info, AleFrameReader, AleFrameWriter, ALE_PKT_AU1, ALE_PKT_AU2};

use crate::interfaces::tproxy;
use crate::management::config::{PerfKnobs, Proto, QosPolicy, TlsMode};
use crate::management::telemetry::{format_rate, ConnectionMetrics};

use foreign_types_shared::ForeignTypeRef;
use ktls_pipe::{enable_ktls_ssl, get_tcp_ulp, ktls_privilege_hint, KtlsSession};
use log::{debug, error, info, warn};
use openssl::ssl::{Ssl, SslAcceptor};

use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// =============================================================================
//                        DECRYPT DIRECTION: TLS → TCP/UDP
// =============================================================================

/// Accept TLS/kTLS connections and relay each to a plain TCP or UDP upstream.
///
/// For each accepted connection a handler thread is spawned that performs the
/// TLS handshake, connects to the upstream, and runs the bidirectional relay.
pub(crate) fn run_tcp_decrypt_listener(ctx: &RuleContext) {
    // Bind the TCP listener (TLS always runs over TCP on the listen side).
    let listener = match bind_tcp_listener(&ctx.listen_addr, ctx.transparent, &ctx.rule_name) {
        Some(l) => l,
        None => return,
    };
    listener.set_nonblocking(false).ok();

    info!(
        "[{}] Decrypt listener on {} ({}) → {} ({})",
        ctx.rule_name, ctx.listen_addr, ctx.tls_mode, ctx.upstream_addr, ctx.upstream_proto,
    );

    // Resolve typed security parameters from the rule's provider_params.
    let tls_params =
        TlsSecurityParams::from_params(&ctx.provider_params, ctx.protocol_version.as_deref())
            .unwrap_or_else(|e| {
                error!("[{}] TLS parameter error: {}", ctx.rule_name, e);
                std::process::exit(1);
            });

    // Build the TLS acceptor (reused across all connections).
    let acceptor = match ctx.tls_mode {
        TlsMode::Tls => Some(build_tls_acceptor(&tls_params).unwrap_or_else(|e| {
            error!("[{}] TLS acceptor error: {}", ctx.rule_name, e);
            std::process::exit(1);
        })),
        TlsMode::Ktls => Some(build_ktls_acceptor(&tls_params).unwrap_or_else(|e| {
            error!("[{}] kTLS acceptor error: {}", ctx.rule_name, e);
            std::process::exit(1);
        })),
        TlsMode::Dtls => unreachable!("DTLS uses run_dtls_decrypt_relay, not tcp decrypt"),
    };

    while !ctx.shutdown.load(Ordering::Relaxed) {
        let (stream, peer_addr) = match accept_with_timeout(&listener, ACCEPT_TIMEOUT) {
            Some(Ok((s, a))) => (s, a),
            Some(Err(e)) => {
                error!("[{}] Accept error: {}", ctx.rule_name, e);
                continue;
            }
            None => continue,
        };

        let fd = stream.as_raw_fd();
        tune_socket_buffers(fd, ctx.sock_buf_size);
        set_nodelay(fd, true);
        apply_tcp_latency_opts(fd, ctx.perf.notsent_lowat, ctx.perf.busy_poll_us);
        // Prioritise the client-facing (SCG → client) return path.
        ctx.apply_egress_qos(fd, peer_addr.is_ipv6(), None);
        // to discover the original destination IP:port, then forward locally.
        // We use the original destination IP (not 127.0.0.1) because some
        // applications (e.g. a multicast discovery channel) bind to specific
        // interface IPs rather than 0.0.0.0, so 127.0.0.1:{port} would get refused.
        let resolved_upstream = if ctx.upstream_addr == "auto" && ctx.transparent {
            match tproxy::get_original_dst(fd) {
                Ok(orig) => {
                    let local = orig.to_string();
                    debug!(
                        "[{}] TPROXY decrypt {} → {} (original dst {})",
                        ctx.rule_name, peer_addr, local, orig,
                    );
                    local
                }
                Err(e) => {
                    error!(
                        "[{}] SO_ORIGINAL_DST failed for decrypt {}: {}",
                        ctx.rule_name, peer_addr, e,
                    );
                    continue;
                }
            }
        } else {
            ctx.upstream_addr.clone()
        };

        // Traffic classification + policy check
        if let Ok(dst_addr) = resolved_upstream.parse::<SocketAddr>() {
            if !ctx.classify_and_check_policy(&peer_addr, &dst_addr) {
                continue; // Drop connection — policy denied
            }
        }

        ctx.metrics.connection_opened();

        // Clone what the handler thread needs — it outlives this loop iteration.
        let metrics = ctx.metrics.clone();
        let rule_name = ctx.rule_name.clone();
        let shutdown = ctx.shutdown.clone();
        let tls_mode = ctx.tls_mode;
        let upstream_proto = ctx.upstream_proto;
        let sock_buf_size = ctx.sock_buf_size;
        let acceptor = acceptor.clone();
        let traffic_class = ctx.traffic_class;
        let simulated_delay_ms = ctx.simulated_delay_ms;
        let app_protocol = ctx.app_protocol.clone();
        let qos = ctx.qos;
        let perf = ctx.perf;

        let pool = ctx.conn_pool.clone();
        pool.execute(move || {
            // Safety traffic always runs at elevated thread priority.
            apply_safety_priority(traffic_class);

            let mut conn_metrics = ConnectionMetrics::with_rule_metrics(
                "decrypt",
                &tls_mode.to_string(),
                metrics.clone(),
            );

            let result = handle_tcp_decrypt(
                &rule_name,
                stream,
                peer_addr,
                &resolved_upstream,
                upstream_proto,
                tls_mode,
                acceptor.as_ref().unwrap(),
                sock_buf_size,
                &mut conn_metrics,
                &shutdown,
                simulated_delay_ms,
                &app_protocol,
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

    info!("[{}] Decrypt listener shutting down", ctx.rule_name);
}

/// Handle a single TLS→plain decrypt connection.
///
/// Performs the TLS/kTLS handshake on the accepted stream, connects to the
/// plain upstream (TCP or UDP), and runs the bidirectional relay until one
/// side closes or the shutdown flag is set.
pub(crate) fn handle_tcp_decrypt(
    rule_name: &str,
    stream: TcpStream,
    peer_addr: SocketAddr,
    upstream_addr: &str,
    upstream_proto: Proto,
    tls_mode: TlsMode,
    acceptor: &SslAcceptor,
    sock_buf_size: usize,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &Arc<AtomicBool>,
    delay_ms: u64,
    app_protocol: &str,
    qos: QosPolicy,
    perf: PerfKnobs,
) -> io::Result<()> {
    // ── TLS handshake ────────────────────────────────────────────────────────
    let hs_start = Instant::now();
    let fd = stream.as_raw_fd();

    let mut tls_stream: ProxyStream = match tls_mode {
        TlsMode::Tls => {
            let ssl_stream = acceptor
                .accept(stream)
                .map_err(|e| io::Error::other(format!("TLS accept: {}", e)))?;
            info!(
                "[{}] TLS accept from {} ({:.2} ms)",
                rule_name,
                peer_addr,
                hs_start.elapsed().as_secs_f64() * 1000.0,
            );
            ProxyStream::Tls(ssl_stream)
        }
        TlsMode::Ktls => {
            let mut ssl = Ssl::new(acceptor.context()).map_err(|e| {
                io::Error::other(format!("kTLS SSL new: {}", e))
            })?;
            ssl.set_accept_state();
            // SAFETY: `ssl.as_ptr()` yields the raw `SSL*` of the locally owned,
            // freshly created `ssl` (still alive and not moved for this call);
            // `enable_ktls_ssl` only sets options on that live OpenSSL handle.
            unsafe {
                enable_ktls_ssl(ssl.as_ptr());
            }
            let mut session = KtlsSession::new(ssl, fd as libc::c_int).map_err(|e| {
                io::Error::other(format!("kTLS session: {}", e))
            })?;
            session
                .accept()
                .map_err(|e| io::Error::other(format!("kTLS accept: {}", e)))?;

            let ulp = get_tcp_ulp(&stream).unwrap_or_default();
            let ktls_active = ulp.starts_with("tls");
            info!(
                "[{}] kTLS accept from {} ({:.2} ms, ULP={}, active={})",
                rule_name,
                peer_addr,
                hs_start.elapsed().as_secs_f64() * 1000.0,
                ulp,
                ktls_active,
            );
            if !ktls_active {
                warn!(
                    "[{}] WARNING: kTLS may not be active.{}",
                    rule_name,
                    ktls_privilege_hint(),
                );
            }

            ProxyStream::Ktls {
                session,
                _stream: stream,
            }
        }
        TlsMode::Dtls => unreachable!("DTLS uses run_dtls_decrypt_relay"),
    };

    // ── Connect to upstream (plain) ──────────────────────────────────────────
    match upstream_proto {
        Proto::Uds | Proto::Shm => {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "upstream protocol {} is not valid on the TLS decrypt path",
                    upstream_proto
                ),
            ))
        }
        Proto::Tcp => {
            let upstream = connect_with_retry(
                upstream_addr,
                5,
                Duration::from_millis(500),
                Duration::from_secs(4),
                shutdown,
            )?;
            tune_socket_buffers(upstream.as_raw_fd(), sock_buf_size);
            set_nodelay(upstream.as_raw_fd(), true);
            apply_tcp_latency_opts(upstream.as_raw_fd(), perf.notsent_lowat, perf.busy_poll_us);
            // Mark + prioritise the upstream (SCG → upstream) egress socket.
            let up_is_v6 = upstream.peer_addr().map(|a| a.is_ipv6()).unwrap_or(false);
            apply_egress_qos(
                upstream.as_raw_fd(),
                qos.egress_dscp(None),
                qos.so_priority(),
                up_is_v6,
            );
            debug!(
                "[{}] Connected to upstream {} (TCP)",
                rule_name, upstream_addr
            );

            // Bidirectional relay: TLS <-> plain TCP
            // Use zero-copy splice for kTLS, buffered relay for userspace TLS
            match tls_mode {
                TlsMode::Ktls => {
                    let tls_fd = tls_stream.raw_fd();
                    let up_fd = upstream.as_raw_fd();
                    relay_bidirectional_splice(
                        tls_fd,
                        up_fd,
                        conn_metrics,
                        shutdown,
                        delay_ms,
                        perf.pipe_size,
                        perf.busy_poll_us,
                        perf.bdp_adaptive,
                        perf.bdp_queue_budget_us,
                    )
                }
                _ => relay_bidirectional(
                    &mut tls_stream,
                    upstream,
                    conn_metrics,
                    shutdown,
                    delay_ms,
                    perf.enable_cork,
                    perf.relay_buf_size,
                    perf.busy_poll_us,
                    perf.bdp_adaptive,
                    perf.bdp_queue_budget_us,
                ),
            }
        }
        Proto::Udp => {
            let target: SocketAddr = upstream_addr.parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("parse {}: {}", upstream_addr, e),
                )
            })?;
            // Bind the egress socket in the target's address family so IPv6
            // upstreams work (an IPv4 wildcard cannot connect to an IPv6 peer).
            let bind_addr = if target.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let upstream = UdpSocket::bind(bind_addr)
                .map_err(|e| io::Error::new(e.kind(), format!("UDP bind: {}", e)))?;
            upstream.connect(target)?;
            tune_socket_buffers(upstream.as_raw_fd(), sock_buf_size);
            // Mark + prioritise the upstream (SCG → upstream) UDP egress socket.
            apply_egress_qos(
                upstream.as_raw_fd(),
                qos.egress_dscp(None),
                qos.so_priority(),
                target.is_ipv6(),
            );
            debug!(
                "[{}] Connected to upstream {} (UDP)",
                rule_name, upstream_addr
            );

            // UDP-over-TLS application framing: ALE (Subset-098) or raw
            // length-prefix, selected by the rule's `app_protocol`.
            let framing = UdpFraming::for_app_protocol(app_protocol);

            // Perform ALE handshake as responder: read AU1, send AU2. Skipped
            // for raw framing, which has no association handshake.
            if framing.is_ale() {
                let mut ale_writer = AleFrameWriter::new(0x00);
                let mut ale_reader = AleFrameReader::new();
                let mut hs_buf = [0u8; 256];

                // Read AU1 from initiator
                let mut au1_ok = false;
                for _ in 0..50 {
                    // 50 * 100ms = 5s timeout
                    match tls_stream.read(&mut hs_buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            match ale_reader.feed(&hs_buf[..n]) {
                                Ok(frames) => {
                                    for frame in frames {
                                        if frame.header.packet_type == ALE_PKT_AU1 {
                                            if let Some((au1, _)) =
                                                AleAu1Info::decode(&frame.user_data)
                                            {
                                                debug!(
                                                    "[{}] ALE AU1 received (calling: 0x{:08X}, called: 0x{:08X})",
                                                    rule_name, au1.calling_etcs_id, au1.called_etcs_id
                                                );
                                            }
                                            au1_ok = true;
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("[{}] ALE AU1 read error: {}", rule_name, e);
                                    break;
                                }
                            }
                            if au1_ok {
                                break;
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                        Err(e) => {
                            error!("[{}] ALE AU1 read error: {}", rule_name, e);
                            break;
                        }
                    }
                }

                if !au1_ok {
                    error!("[{}] ALE handshake failed: no AU1 received", rule_name);
                    return Err(io::Error::other("ALE handshake failed"));
                }

                // Send AU2 response
                let au2_info = AleAu2Info {
                    responding_etcs_id: 0,
                };
                let au2_data = au2_info.encode(&[]);
                ale_writer
                    .write_alepkt(&mut tls_stream, ALE_PKT_AU2, &au2_data)
                    .map_err(|e| {
                        io::Error::other(format!("ALE AU2 send: {}", e))
                    })?;

                info!("[{}] ALE handshake complete (responder)", rule_name);
            }

            // TLS <-> UDP: deframe ALE/raw from TLS to UDP datagrams and back.
            relay_tls_to_udp(
                rule_name,
                &mut tls_stream,
                &upstream,
                conn_metrics,
                shutdown,
                delay_ms,
                framing,
            )
        }
    }
}
