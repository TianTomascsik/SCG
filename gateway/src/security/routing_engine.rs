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
    bind_tcp_listener, set_nodelay, tune_socket_buffers,
};
use crate::processing::RuleContext;
use crate::security::relay::relay_bidirectional_splice;
use crate::security::ACCEPT_TIMEOUT;

use log::{debug, error, info, warn};

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
            let so_orig = tproxy::get_original_dst(client_stream.as_raw_fd()).ok();
            let local = client_stream.local_addr().ok();
            match local.and_then(|l| transparent_target(so_orig, l, listen_port)) {
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
        // target — DP-07).
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

/// Resolve the original destination of a transparent (TPROXY / REDIRECT)
/// connection, or `None` when it cannot be determined (the caller must then fail
/// closed).
///
/// * `so_original_dst` — the `SO_ORIGINAL_DST` result; `Some` for conntrack
///   REDIRECT/DNAT, `None` for TPROXY (the sockopt is NAT-only).
/// * `local_addr` — `getsockname` on the accepted socket. For a TPROXY-redirected
///   connection the IP_TRANSPARENT socket's local address *is* the original
///   destination; for a direct connection it is the listener's own address.
/// * `listen_port` — the listener's bound port, used to tell a genuine redirect
///   (different port) from a direct connection (same port).
fn transparent_target(
    so_original_dst: Option<SocketAddr>,
    local_addr: SocketAddr,
    listen_port: Option<u16>,
) -> Option<SocketAddr> {
    // REDIRECT/DNAT: conntrack returns the pre-translation destination, which
    // `getsockname` cannot (the kernel rewrote it to the local socket address).
    if let Some(orig) = so_original_dst {
        return Some(orig);
    }
    // TPROXY: a local port matching the listener's own port means this is a
    // direct, non-redirected connection that carries no original-destination
    // information — nothing to recover.
    match listen_port {
        Some(p) if local_addr.port() != p => Some(local_addr),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn auto_upstream_detection() {
        assert!(is_auto_upstream("auto"));
        assert!(is_auto_upstream("  AUTO "));
        assert!(!is_auto_upstream("127.0.0.1:8080"));
        assert!(!is_auto_upstream(""));
    }

    #[test]
    fn redirect_uses_so_original_dst() {
        // REDIRECT/DNAT: SO_ORIGINAL_DST wins regardless of the local address.
        let orig = sa("10.0.0.9:443");
        assert_eq!(
            transparent_target(Some(orig), sa("127.0.0.1:20002"), Some(20002)),
            Some(orig)
        );
    }

    #[test]
    fn tproxy_recovers_original_dst_from_local_addr() {
        // TPROXY: no SO_ORIGINAL_DST; the transparent socket's local addr (a port
        // other than the listener's) is the original destination.
        let local = sa("127.0.0.1:20001");
        assert_eq!(transparent_target(None, local, Some(20002)), Some(local));
    }

    #[test]
    fn direct_connection_fails_closed() {
        // A direct connection to the listener (local port == listener port) carries
        // no original-destination info → None → caller drops it.
        assert_eq!(
            transparent_target(None, sa("127.0.0.1:20002"), Some(20002)),
            None
        );
        // Unknown listener port is also not recoverable.
        assert_eq!(transparent_target(None, sa("127.0.0.1:20001"), None), None);
    }
}
