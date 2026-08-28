//! Routing-only engine: plaintext L4 TCP passthrough (no encryption).
//!
//! Accepts plain TCP connections and relays bytes verbatim to a plain TCP
//! upstream using the zero-copy splice relay. This is used by the `routing`
//! crypto provider for rules that only need L4 forwarding plus traffic
//! classification / policy enforcement, with no TLS on either leg.

use crate::interfaces::tproxy;
use crate::management::config::{PerfKnobs, QosPolicy};
use crate::management::telemetry::{format_rate, ConnectionMetrics};
use crate::networking::connector::connect_with_retry;
use crate::networking::socket_manager::{
    accept_with_timeout, apply_egress_qos, apply_safety_priority, apply_tcp_latency_opts,
    bind_tcp_listener, bind_udp_socket, recvmsg_from_with_dscp, set_nodelay, tune_socket_buffers,
};
use crate::processing::RuleContext;
use crate::security::relay::{apply_geo_delay, relay_bidirectional_splice};
use crate::security::udp_session::{
    session_admitted, stale_peers, DEFAULT_UDP_IDLE_TTL_SECS, DEFAULT_UDP_MAX_SESSIONS,
};
use crate::security::{ACCEPT_TIMEOUT, UDP_BUF_SIZE};

use log::{debug, error, info, warn};

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Accept plain TCP connections and relay each to a plain TCP upstream.
pub(crate) fn run_tcp_routing_listener(ctx: &RuleContext) {
    let listener = match bind_tcp_listener(&ctx.listen_addr, ctx.transparent, &ctx.rule_name) {
        Some(l) => l,
        None => return,
    };
    listener.set_nonblocking(false).ok();

    info!(
        "[{}] Routing listener on {} (tcp) → {} (tcp, plaintext passthrough)",
        ctx.rule_name, ctx.listen_addr, ctx.upstream_addr,
    );

    // The listener's own port distinguishes a genuine TPROXY redirect (where the
    // accepted IP_TRANSPARENT socket's local port is the *original* destination)
    // from a direct connection to the listener (local port == listener port).
    let listen_port = listener.local_addr().ok().map(|a| a.port());

    while !ctx.shutdown.load(Ordering::Relaxed) {
        let (client_stream, peer_addr) = match accept_with_timeout(&listener, ACCEPT_TIMEOUT) {
            Some(Ok((s, a))) => (s, a),
            Some(Err(e)) => {
                error!("[{}] Accept error: {}", ctx.rule_name, e);
                continue;
            }
            None => continue, // timeout, check shutdown
        };

        // Determine the upstream target.
        //
        // A transparent rule with the `"auto"` upstream is a true transparent
        // proxy: forward to the destination the client actually dialed. Recover it
        // from the kernel — `SO_ORIGINAL_DST` for REDIRECT/DNAT, else `getsockname`
        // on the IP_TRANSPARENT socket for TPROXY (`SO_ORIGINAL_DST` only works for
        // conntrack NAT and always fails for TPROXY). If neither yields a real
        // destination, fail closed: dropping the connection is safer than
        // forwarding to a default and bypassing the destination policy (TRA #59).
        // A transparent rule with an *explicit* upstream is a fixed-forward
        // interceptor and forwards there directly.
        let target = if ctx.transparent && is_auto_upstream(&ctx.upstream_addr) {
            match tproxy::recover_transparent_dst(client_stream.as_raw_fd(), listen_port) {
                Some(dst) => {
                    debug!(
                        "[{}] transparent {} \u{2192} {} (recovered original dst)",
                        ctx.rule_name, peer_addr, dst
                    );
                    dst.to_string()
                }
                None => {
                    warn!(
                        "[{}] dropping {}: could not recover transparent original destination",
                        ctx.rule_name, peer_addr
                    );
                    continue;
                }
            }
        } else {
            ctx.upstream_addr.clone()
        };

        // Traffic classification + policy check (fail closed on an unparseable
        // target).
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

        let metrics = ctx.metrics.clone();
        let rule_name = ctx.rule_name.clone();
        let shutdown = ctx.shutdown.clone();
        let sock_buf_size = ctx.sock_buf_size;
        let perf = ctx.perf;
        let traffic_class = ctx.traffic_class;
        let simulated_delay_ms = ctx.simulated_delay_ms;
        let qos = ctx.qos;

        let pool = ctx.conn_pool.clone();
        pool.execute(move || {
            // Safety traffic always runs at elevated thread priority.
            apply_safety_priority(traffic_class);

            let mut conn_metrics =
                ConnectionMetrics::with_rule_metrics("routing", "routing", metrics.clone());

            let result = handle_tcp_routing(
                &rule_name,
                client_stream,
                &target,
                sock_buf_size,
                &mut conn_metrics,
                &shutdown,
                simulated_delay_ms,
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

    info!("[{}] Routing listener shutting down", ctx.rule_name);
}

/// Accept plaintext UDP datagrams on this rule's `listen_addr` and forward them,
/// unencrypted, to a fixed UDP `upstream` — the datagram analogue of
/// [`run_tcp_routing_listener`].
///
/// UDP is connectionless, so each distinct source address gets its own per-peer
/// session (a connected upstream socket) and its replies demux back to that
/// client. That per-source state is **bounded**: a `max_sessions` admission cap is
/// checked **before** any classify/forward work (so a spoofed-source flood is
/// refused cheaply, TRA #81), and idle sessions are evicted (~1 Hz). There is no
/// handshake and therefore no cookie (TRA #82, accepted residual) — the cap, the
/// per-datagram default-deny policy gate, and 1:1 forwarding to a single
/// pre-resolved upstream (no amplification) are the anti-spoof bounds.
pub(crate) fn run_udp_routing_listener(ctx: &RuleContext) {
    let listen = match bind_udp_socket(&ctx.listen_addr, ctx.transparent, &ctx.rule_name) {
        Some(s) => s,
        None => {
            error!(
                "[{}] failed to bind UDP routing listen socket on {}",
                ctx.rule_name, ctx.listen_addr
            );
            return;
        }
    };
    apply_safety_priority(ctx.traffic_class);
    listen.set_nonblocking(true).ok();
    tune_socket_buffers(listen.as_raw_fd(), ctx.sock_buf_size);
    let listen_is_v6 = listen.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    ctx.apply_egress_qos(listen.as_raw_fd(), listen_is_v6, None);
    ctx.enable_inbound_dscp_sampling(listen.as_raw_fd(), listen_is_v6);

    // Resolve the upstream ONCE (never per datagram): both the policy gate and per
    // peer socket setup use the concrete address, and a DNS name is not re-resolved
    // under load. `auto` is rejected at config validation (the fixed-upstream UDP
    // relay has no original-destination recovery); guard defensively here too.
    if is_auto_upstream(&ctx.upstream_addr) {
        error!(
            "[{}] routing over UDP does not support upstream_addr=\"auto\"; not relaying",
            ctx.rule_name
        );
        return;
    }
    let target_addr = match ctx.resolve_upstream_target(&ctx.upstream_addr) {
        Some(a) => a,
        None => {
            error!(
                "[{}] cannot resolve UDP routing upstream '{}'; not relaying",
                ctx.rule_name, ctx.upstream_addr
            );
            return;
        }
    };

    // Per-source bounds from the rule config, else the shared UDP defaults (which
    // match the DTLS engine). A zero/absent value falls back to the default; config
    // validation already forbids an explicit zero cap.
    let max_sessions = ctx
        .provider_params
        .get("max_sessions")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_UDP_MAX_SESSIONS);
    let idle_ttl = Duration::from_secs(
        ctx.provider_params
            .get("idle_ttl_secs")
            .and_then(|v| v.as_u64())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_UDP_IDLE_TTL_SECS),
    );

    let mut sessions: HashMap<SocketAddr, (UdpSocket, Instant)> = HashMap::new();
    let mut last_evict = Instant::now();
    let mut conn_metrics =
        ConnectionMetrics::with_rule_metrics("routing-udp", "routing", ctx.metrics.clone());
    ctx.metrics.connection_opened();
    info!(
        "[{}] Routing listener on {} (udp) → {} (udp, plaintext datagram passthrough)",
        ctx.rule_name, ctx.listen_addr, ctx.upstream_addr,
    );

    let mut fwd_buf = vec![0u8; UDP_BUF_SIZE];
    let mut rev_buf = vec![0u8; UDP_BUF_SIZE];
    let listen_fd = listen.as_raw_fd();
    // Reused across iterations so a steady-state wakeup doesn't allocate fresh Vecs
    // proportional to the session count every loop; `clear()` keeps the capacity.
    let mut pollfds: Vec<libc::pollfd> = Vec::new();
    let mut session_snapshot: Vec<(SocketAddr, RawFd)> = Vec::new();

    while !ctx.shutdown.load(Ordering::Relaxed) {
        // Reclaim idle sessions at most ~once per second so a flood of short-lived
        // peers cannot pin resources between admissions.
        let now = Instant::now();
        if now.saturating_duration_since(last_evict) >= Duration::from_secs(1) {
            evict_idle_udp_sessions(&mut sessions, idle_ttl, now, &ctx.rule_name);
            last_evict = now;
        }

        // Dynamic pollfd array: [listen_socket,...per-peer upstream fds].
        pollfds.clear();
        pollfds.push(libc::pollfd {
            fd: listen_fd,
            events: libc::POLLIN,
            revents: 0,
        });
        session_snapshot.clear();
        session_snapshot.extend(
            sessions
                .iter()
                .map(|(peer, (sock, _))| (*peer, sock.as_raw_fd())),
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
        // contiguous, writable buffer, the length matches the element count, and
        // the Vec outlives the call, so `poll` only reads/writes in-bounds entries.
        // The result is checked below.
        let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 1000) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            error!("[{}] UDP routing poll error: {}", ctx.rule_name, err);
            break;
        }
        if ret == 0 {
            continue;
        }

        // -- Forward: client → upstream --------------------------------------
        if pollfds[0].revents & libc::POLLIN != 0 {
            loop {
                match recvmsg_from_with_dscp(listen_fd, &mut fwd_buf) {
                    Ok((n, peer_addr, inbound_dscp)) => {
                        // Admission FIRST: refuse a *new* peer once the cap is
                        // reached, before spending any classify/forward work — the
                        // cap only ever drops *more* than the policy gate would, and
                        // every datagram that reaches the gate + session creation
                        // below still passes it, so ordering admission first never
                        // bypasses policy (idle sessions are reclaimed above).
                        if !sessions.contains_key(&peer_addr)
                            && !session_admitted(sessions.len(), max_sessions)
                        {
                            warn!(
                                "[{}] UDP routing session cap {} reached; dropping new peer {}",
                                ctx.rule_name, max_sessions, peer_addr
                            );
                            continue;
                        }
                        // Per-datagram default-deny policy gate (fail closed),
                        // against the pre-resolved upstream — identical to the
                        // crypto paths.
                        if !ctx.classify_and_check_policy(&peer_addr, &target_addr) {
                            continue;
                        }
                        conn_metrics.record_read(n);

                        // Get or create the per-peer upstream socket (no handshake).
                        if let std::collections::hash_map::Entry::Vacant(e) =
                            sessions.entry(peer_addr)
                        {
                            let bind_addr = if target_addr.is_ipv6() {
                                "[::]:0"
                            } else {
                                "0.0.0.0:0"
                            };
                            let up = match UdpSocket::bind(bind_addr) {
                                Ok(s) => s,
                                Err(e) => {
                                    error!(
                                        "[{}] failed to bind upstream UDP: {}",
                                        ctx.rule_name, e
                                    );
                                    continue;
                                }
                            };
                            if let Err(e) = up.connect(target_addr) {
                                error!(
                                    "[{}] failed to connect upstream UDP {}: {}",
                                    ctx.rule_name, target_addr, e
                                );
                                continue;
                            }
                            tune_socket_buffers(up.as_raw_fd(), ctx.sock_buf_size);
                            ctx.apply_egress_qos(
                                up.as_raw_fd(),
                                target_addr.is_ipv6(),
                                inbound_dscp,
                            );
                            up.set_nonblocking(true).ok();
                            e.insert((up, Instant::now()));
                            debug!(
                                "[{}] UDP routing session for peer {}",
                                ctx.rule_name, peer_addr
                            );
                        }

                        if let Some(sess) = sessions.get_mut(&peer_addr) {
                            apply_geo_delay(ctx.simulated_delay_ms);
                            match sess.0.send(&fwd_buf[..n]) {
                                Ok(_) => {
                                    sess.1 = Instant::now();
                                    conn_metrics.record_relay(n);
                                }
                                // Transient backpressure: drop this datagram, keep
                                // the session (tearing it down on a momentarily-full
                                // send buffer would be worse for UDP).
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    debug!(
                                        "[{}] UDP routing upstream backpressure for {}; dropping datagram",
                                        ctx.rule_name, peer_addr
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        "[{}] UDP routing upstream send error for {}: {}",
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
                        error!("[{}] UDP routing recv error: {}", ctx.rule_name, e);
                        break;
                    }
                }
            }
        }

        // -- Reverse: upstream → client --------------------------------------
        let mut to_remove = Vec::new();
        for (i, &(peer_addr, _fd)) in session_snapshot.iter().enumerate() {
            if pollfds[i + 1].revents & (libc::POLLIN | libc::POLLERR | libc::POLLNVAL) != 0 {
                if let Some(sess) = sessions.get_mut(&peer_addr) {
                    loop {
                        match sess.0.recv(&mut rev_buf) {
                            Ok(n) => {
                                sess.1 = Instant::now();
                                conn_metrics.record_read(n);
                                match listen.send_to(&rev_buf[..n], peer_addr) {
                                    Ok(sent) => conn_metrics.record_relay(sent),
                                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                                    Err(e) => debug!(
                                        "[{}] UDP routing client send error to {}: {}",
                                        ctx.rule_name, peer_addr, e
                                    ),
                                }
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) => {
                                error!(
                                    "[{}] UDP routing upstream recv error from {}: {}",
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
            sessions.remove(&peer);
        }
    }

    let elapsed = conn_metrics.elapsed_secs();
    info!(
        "[{}] UDP routing done: {:.3}s, {} msgs, {}",
        ctx.rule_name,
        elapsed,
        conn_metrics.msgs_relayed,
        format_rate(conn_metrics.bytes_out as f64 / elapsed)
    );
    ctx.metrics.merge_connection(&conn_metrics);
    ctx.metrics.connection_closed();
}

/// Remove UDP routing sessions idle for at least `ttl`; a removed session's
/// upstream socket is dropped (fd closed). Selection uses the shared
/// [`stale_peers`](crate::security::udp_session::stale_peers) helper.
fn evict_idle_udp_sessions(
    sessions: &mut HashMap<SocketAddr, (UdpSocket, Instant)>,
    ttl: Duration,
    now: Instant,
    rule_name: &str,
) {
    let snapshot: Vec<(SocketAddr, Instant)> = sessions
        .iter()
        .map(|(peer, (_, last))| (*peer, *last))
        .collect();
    for peer in stale_peers(&snapshot, ttl, now) {
        if sessions.remove(&peer).is_some() {
            debug!(
                "[{}] UDP routing session evicted (idle) for {}",
                rule_name, peer
            );
        }
    }
}

/// Handle a single plaintext TCP → TCP passthrough connection.
// Internal engine entry point; a param struct is a larger refactor than warranted here.
#[allow(clippy::too_many_arguments)]
fn handle_tcp_routing(
    _rule_name: &str,
    client: TcpStream,
    upstream_addr: &str,
    sock_buf_size: usize,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &AtomicBool,
    delay_ms: u64,
    qos: QosPolicy,
    perf: PerfKnobs,
) -> io::Result<()> {
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

    // Zero-copy splice passthrough between the two plain TCP sockets. Both
    // `client` and `upstream_tcp` stay owned (and thus open) for the duration.
    let client_fd = client.as_raw_fd();
    relay_bidirectional_splice(
        client_fd,
        up_fd,
        conn_metrics,
        shutdown,
        delay_ms,
        perf.pipe_size,
        perf.busy_poll_us,
        perf.bdp_adaptive,
        perf.bdp_queue_budget_us,
    )?;

    Ok(())
}

/// Whether a transparent rule's upstream is the `"auto"` placeholder, meaning
/// "forward to the destination the client originally dialed" rather than to a
/// fixed address.
fn is_auto_upstream(upstream: &str) -> bool {
    upstream.trim().eq_ignore_ascii_case("auto")
}

// The original-destination recovery logic (SO_ORIGINAL_DST → getsockname →
// fail-closed) now lives in `interfaces::tproxy::recover_transparent_dst`,
// shared with the TLS encrypt/decrypt paths. Its pure decision core is
// unit-tested there.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_upstream_detection() {
        assert!(is_auto_upstream("auto"));
        assert!(is_auto_upstream("  AUTO "));
        assert!(!is_auto_upstream("127.0.0.1:8080"));
        assert!(!is_auto_upstream(""));
    }

    #[test]
    fn evict_idle_udp_removes_only_idle_sessions() {
        let mut sessions: HashMap<SocketAddr, (UdpSocket, Instant)> = HashMap::new();
        let now = Instant::now();
        let ttl = Duration::from_secs(60);
        let fresh: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let idle: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let recent = now.checked_sub(Duration::from_secs(5)).unwrap_or(now);
        let old = now.checked_sub(Duration::from_secs(120)).unwrap_or(now);
        sessions.insert(fresh, (UdpSocket::bind("127.0.0.1:0").unwrap(), recent));
        sessions.insert(idle, (UdpSocket::bind("127.0.0.1:0").unwrap(), old));

        evict_idle_udp_sessions(&mut sessions, ttl, now, "test");

        assert!(sessions.contains_key(&fresh), "fresh session must be kept");
        assert!(
            !sessions.contains_key(&idle),
            "idle session must be evicted"
        );
        assert_eq!(sessions.len(), 1);
    }
}
