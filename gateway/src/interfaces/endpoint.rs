//! Shared helpers for the dynamically-created local message interfaces
//! (UDS and SHM).
//!
//! These endpoints are created on demand by the management API and bridge a
//! locally-authenticated application client to a TLS/kTLS upstream. The
//! `[len][traffic_id][data]` frame stream is carried transparently end-to-end,
//! so a UDS client on one gateway can interoperate with a SHM client on a peer
//! gateway: both sides see the same length-prefixed frame stream inside TLS.

use crate::management::config::{PerfKnobs, QosPolicy, TlsMode};
use crate::management::telemetry::ConnectionMetrics;
use crate::networking::connector::connect_with_retry;
use crate::networking::socket_manager::{
    accept_with_timeout, apply_egress_qos, bind_tcp_listener, poll_two_fds, set_nodelay,
    set_nonblocking_fd, tune_socket_buffers, write_all_nb,
};
use crate::security::relay::relay_bidirectional_splice;
use crate::security::tls_engine::params::TlsSecurityParams;
use crate::security::tls_engine::{
    build_tls_acceptor, build_tls_connector, write_all_nb_proxy, ProxyStream,
};
use crate::security::RELAY_BUF_SIZE;

use foreign_types_shared::ForeignTypeRef;
use ktls_pipe::{
    build_client_connector as ktls_client_connector, build_server_acceptor as ktls_server_acceptor,
    enable_ktls_ssl, get_tcp_ulp, ktls_privilege_hint, KtlsSession,
};
use log::{debug, info, warn};
use openssl::ssl::{Ssl, SslAcceptor};

use scg_ipc::handshake::{Hello, HELLO_LEN};
use scg_ipc::os::{self, PeerCred};
use scg_ipc::token::CapabilityToken;

use std::collections::HashMap;
use std::io::{self, Read};
use std::net::TcpStream;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Authenticate a freshly-accepted local connection on its control/data socket.
///
/// Peer-credential checks come first (cheap, and they reject the wrong uid
/// before the token is ever examined), then the single-use token carried in the
/// HELLO frame is validated in constant time and consumed under the lock. The
/// same routine guards both the UDS data socket and the SHM control socket.
pub fn authenticate_peer(
    stream: &UnixStream,
    allowed_uids: &[u32],
    allowed_pids: &[i32],
    owner_uid: u32,
    token: &Mutex<Option<CapabilityToken>>,
    hello_timeout: Duration,
) -> Result<PeerCred, String> {
    let fd = stream.as_raw_fd();
    let cred = os::get_peer_cred(fd).map_err(|e| format!("SO_PEERCRED failed: {e}"))?;

    if !allowed_uids.contains(&cred.uid) {
        return Err(format!(
            "uid {} is not in the rule's allowed_uids",
            cred.uid
        ));
    }
    if cred.uid != owner_uid {
        return Err(format!(
            "uid {} does not match the endpoint owner uid {}",
            cred.uid, owner_uid
        ));
    }
    if !allowed_pids.is_empty() {
        if !allowed_pids.contains(&cred.pid) {
            return Err(format!(
                "pid {} is not in the rule's allowed_pids",
                cred.pid
            ));
        }
        // Pin the authorized PID against reuse (#43). SO_PEERCRED reports the
        // connect-time PID, a value the kernel recycles once the process exits;
        // a `pidfd` instead refers to the exact process. If the peer process is
        // already gone we refuse rather than trust a credential whose PID may
        // have been handed to a different process. Defense-in-depth only: the
        // uid==owner_uid check above and the single-use token below remain the
        // authoritative gates. Where pidfd_open is unsupported (older kernels)
        // we fall back to the SO_PEERCRED pid check alone.
        match os::pidfd_open(cred.pid) {
            Ok(raw) => {
                // SAFETY: `raw` is a fresh, owned pidfd just returned by
                // pidfd_open; wrapping it in OwnedFd transfers ownership so the
                // descriptor is closed when `_pidfd` is dropped at scope end.
                let _pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
            }
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {
                return Err(format!(
                    "peer pid {} is no longer live (possible PID reuse)",
                    cred.pid
                ));
            }
            Err(e) => {
                debug!(
                    "pidfd liveness pin unavailable for pid {} ({e}); \
                     falling back to SO_PEERCRED pid check",
                    cred.pid
                );
            }
        }
    }

    // Read the fixed-size HELLO under a timeout so a silent peer cannot wedge
    // the endpoint.
    stream
        .set_read_timeout(Some(hello_timeout))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let mut hello_buf = [0u8; HELLO_LEN];
    {
        let mut reader: &UnixStream = stream;
        reader
            .read_exact(&mut hello_buf)
            .map_err(|e| format!("reading HELLO: {e}"))?;
    }
    let hello = Hello::decode(&hello_buf).map_err(|e| format!("decoding HELLO: {e}"))?;

    // Consume the single-use token under the lock so a racing connection cannot
    // reuse it.
    {
        let mut guard = token.lock().unwrap();
        match guard.as_ref() {
            Some(tok) if tok.ct_eq(hello.token.as_bytes()) => {
                *guard = None; // consume
            }
            Some(_) => return Err("capability token mismatch".to_string()),
            None => return Err("capability token already consumed".to_string()),
        }
    }

    // Restore blocking mode for whatever the caller does next.
    stream
        .set_read_timeout(None)
        .map_err(|e| format!("clearing read timeout: {e}"))?;
    Ok(cred)
}

/// Map a rule's effective security-provider name (plus its resolved security
/// parameters) to the TLS transport mode used for the upstream leg of a local
/// interface.
///
/// The UDS/SHM tunnel is stream-oriented, so DTLS is not applicable; unknown or
/// custom provider names fall back to userspace TLS.
///
/// kTLS offloads the AES-GCM record layer; how the peer is authenticated (verify
/// mode, PKI mutual cert, or PSK) is a handshake concern that completes before
/// kTLS activates, and the kTLS context applies the same verification/PSK setup as
/// userspace (see [`TlsSecurityParams::is_ktls_offloadable`]). So verified TLS and
/// the Subset-146 ETCS profiles stay on the kTLS path; only `integrity-only`
/// (NULL-encryption ciphers, no AES-GCM record layer) falls back to userspace
/// `Tls`. The relay separately guards the zero-copy splice on **runtime** kTLS
/// activation (TRA #56). If the parameters fail to parse, fall back to `Tls` so the
/// userspace path can surface the real error.
pub fn upstream_tls_mode(
    security_provider: &str,
    provider_params: &HashMap<String, serde_json::Value>,
    protocol_version: Option<&str>,
) -> TlsMode {
    match security_provider {
        "ktls" => match TlsSecurityParams::from_params(provider_params, protocol_version) {
            Ok(p) if p.is_ktls_offloadable() => TlsMode::Ktls,
            _ => TlsMode::Tls,
        },
        _ => TlsMode::Tls,
    }
}

/// Connect to `upstream_addr` over TCP and complete a TLS/kTLS client handshake,
/// returning a ready [`ProxyStream`].
///
/// This mirrors the upstream-connect logic of the TCP encrypt path so the local
/// interfaces behave identically to the static encrypt rules.
#[allow(clippy::too_many_arguments)]
pub fn connect_tls_upstream(
    label: &str,
    upstream_addr: &str,
    tls_mode: TlsMode,
    provider_params: &HashMap<String, serde_json::Value>,
    protocol_version: Option<&str>,
    sock_buf_size: usize,
    qos: QosPolicy,
    shutdown: &AtomicBool,
) -> io::Result<ProxyStream> {
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
    // Mark + prioritise the upstream (SCG → upstream) egress socket.
    let up_is_v6 = upstream_tcp
        .peer_addr()
        .map(|a| a.is_ipv6())
        .unwrap_or(false);
    apply_egress_qos(up_fd, qos.egress_dscp(None), qos.so_priority(), up_is_v6);

    // Honour the rule's configured TLS security parameters (verify mode,
    // cert/key/CA, profile) for the upstream connection, exactly like the
    // decrypt-side acceptor. Falling back to an empty map here would silently
    // ignore the operator's `verify` setting and connect without peer
    // verification.
    let params = TlsSecurityParams::from_params(provider_params, protocol_version)
        .map_err(io::Error::other)?;
    let sni = params.sni_name(upstream_addr);

    let hs_start = Instant::now();
    let proxy = match tls_mode {
        TlsMode::Tls => {
            let connector = build_tls_connector(&params)
                .map_err(|e| io::Error::other(format!("TLS connector: {e}")))?;
            let ssl_stream = connector
                .connect(&sni, upstream_tcp)
                .map_err(|e| io::Error::other(format!("TLS handshake: {e}")))?;
            info!(
                "[{label}] upstream TLS handshake OK ({:.2} ms)",
                hs_start.elapsed().as_secs_f64() * 1000.0
            );
            ProxyStream::Tls(ssl_stream)
        }
        TlsMode::Ktls => {
            let connector = ktls_client_connector(params.version.as_deref())
                .map_err(|e| io::Error::other(format!("kTLS connector: {e}")))?;
            let mut ssl = connector
                .configure()
                .map_err(|e| io::Error::other(format!("kTLS configure: {e}")))?
                .into_ssl(&sni)
                .map_err(|e| io::Error::other(format!("kTLS SSL: {e}")))?;
            ssl.set_connect_state();
            // SAFETY: enabling kTLS on the SSL object before the handshake is the
            // documented OpenSSL flow; the pointer is valid for the call.
            unsafe {
                enable_ktls_ssl(ssl.as_ptr());
            }
            let mut session = KtlsSession::new(ssl, up_fd as libc::c_int)
                .map_err(|e| io::Error::other(format!("kTLS session: {e}")))?;
            session
                .connect()
                .map_err(|e| io::Error::other(format!("kTLS handshake: {e}")))?;
            let ulp = get_tcp_ulp(&upstream_tcp).unwrap_or_default();
            if ulp.starts_with("tls") {
                debug!(
                    "[{label}] upstream kTLS handshake OK ({:.2} ms, ULP={ulp})",
                    hs_start.elapsed().as_secs_f64() * 1000.0
                );
            } else {
                warn!(
                    "[{label}] WARNING: kTLS not active.{}",
                    ktls_privilege_hint()
                );
            }
            ProxyStream::Ktls {
                session,
                _stream: upstream_tcp,
            }
        }
        TlsMode::Dtls => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DTLS is not supported for local UDS/SHM interfaces",
            ));
        }
    };
    Ok(proxy)
}

/// Bind a TCP listener on `listen_addr`, accept one inbound connection, and
/// complete a TLS/kTLS **server** handshake, returning a ready [`ProxyStream`].
///
/// This is the decrypt-direction counterpart to [`connect_tls_upstream`]: a
/// peer (or loopback) gateway's encrypt endpoint dials in, and this endpoint
/// terminates TLS so the decrypted `[len][traffic_id][data]` frame stream can
/// be relayed to the local UDS/SHM client. The relay itself is
/// direction-agnostic, so the only difference from the encrypt path is the
/// server- vs client-side handshake. The userspace-TLS identity honours the
/// rule's `cert_path`/`key_path`/profile, falling back to a cached self-signed
/// certificate for the default profile.
#[allow(clippy::too_many_arguments)]
pub fn accept_tls_upstream(
    label: &str,
    listen_addr: &str,
    tls_mode: TlsMode,
    provider_params: &HashMap<String, serde_json::Value>,
    protocol_version: Option<&str>,
    sock_buf_size: usize,
    qos: QosPolicy,
    shutdown: &AtomicBool,
) -> io::Result<ProxyStream> {
    let listener = bind_tcp_listener(listen_addr, false, label).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("failed to bind decrypt TLS listener on {listen_addr}"),
        )
    })?;
    listener.set_nonblocking(false).ok();

    // Build the server acceptor once. Userspace TLS honours the rule's
    // cert/key/profile (self-signed fallback for the default profile); kTLS only
    // needs the negotiated protocol version.
    let acceptor: Option<SslAcceptor> = match tls_mode {
        TlsMode::Tls => {
            let params = TlsSecurityParams::from_params(provider_params, protocol_version)
                .map_err(|e| io::Error::other(format!("TLS params: {e}")))?;
            Some(
                build_tls_acceptor(&params)
                    .map_err(|e| io::Error::other(format!("TLS acceptor: {e}")))?,
            )
        }
        TlsMode::Ktls => Some(
            ktls_server_acceptor(protocol_version)
                .map_err(|e| io::Error::other(format!("kTLS acceptor: {e}")))?,
        ),
        TlsMode::Dtls => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DTLS is not supported for local UDS/SHM interfaces",
            ));
        }
    };

    // Accept the first inbound connection, re-checking the shutdown flag between
    // polls so a never-arriving peer cannot wedge the endpoint thread.
    let (stream, peer_addr): (TcpStream, _) = loop {
        if shutdown.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "shutdown while awaiting decrypt TLS connection",
            ));
        }
        match accept_with_timeout(&listener, Duration::from_millis(200)) {
            Some(Ok(pair)) => break pair,
            Some(Err(e)) => return Err(e),
            None => continue,
        }
    };

    let fd = stream.as_raw_fd();
    tune_socket_buffers(fd, sock_buf_size);
    set_nodelay(fd, true);
    // Mark + prioritise the downstream (SCG → peer) egress socket.
    let is_v6 = peer_addr.is_ipv6();
    apply_egress_qos(fd, qos.egress_dscp(None), qos.so_priority(), is_v6);

    let hs_start = Instant::now();
    let proxy = match tls_mode {
        TlsMode::Tls => {
            let acceptor = acceptor.as_ref().expect("TLS acceptor built above");
            let ssl_stream = acceptor
                .accept(stream)
                .map_err(|e| io::Error::other(format!("TLS accept: {e}")))?;
            info!(
                "[{label}] downstream TLS accept from {peer_addr} ({:.2} ms)",
                hs_start.elapsed().as_secs_f64() * 1000.0
            );
            ProxyStream::Tls(ssl_stream)
        }
        TlsMode::Ktls => {
            let acceptor = acceptor.as_ref().expect("kTLS acceptor built above");
            let mut ssl = Ssl::new(acceptor.context())
                .map_err(|e| io::Error::other(format!("kTLS SSL: {e}")))?;
            ssl.set_accept_state();
            // SAFETY: enabling kTLS on the SSL object before the handshake is the
            // documented OpenSSL flow; the pointer is valid for the call.
            unsafe {
                enable_ktls_ssl(ssl.as_ptr());
            }
            let mut session = KtlsSession::new(ssl, fd as libc::c_int)
                .map_err(|e| io::Error::other(format!("kTLS session: {e}")))?;
            session
                .accept()
                .map_err(|e| io::Error::other(format!("kTLS accept: {e}")))?;
            let ulp = get_tcp_ulp(&stream).unwrap_or_default();
            if ulp.starts_with("tls") {
                debug!(
                    "[{label}] downstream kTLS accept from {peer_addr} ({:.2} ms, ULP={ulp})",
                    hs_start.elapsed().as_secs_f64() * 1000.0
                );
            } else {
                warn!(
                    "[{label}] WARNING: kTLS not active.{}",
                    ktls_privilege_hint()
                );
            }
            ProxyStream::Ktls {
                session,
                _stream: stream,
            }
        }
        TlsMode::Dtls => unreachable!("DTLS handled above"),
    };
    Ok(proxy)
}

/// Connect to `upstream_addr` over **plaintext TCP** (no TLS) for a `routing`
/// local endpoint — the encrypt-direction counterpart for the routing provider.
///
/// The local-caller authentication (`SO_PEERCRED` + owner-uid) has already
/// passed in the endpoint accept loop before this runs; this only sets up the
/// plaintext relay leg, exactly as the static TCP routing provider does. No
/// encryption is applied on this hop by design (TRA #58); a `--validate` posture
/// warning advises the operator.
pub fn connect_plain_upstream(
    label: &str,
    upstream_addr: &str,
    sock_buf_size: usize,
    qos: QosPolicy,
    shutdown: &AtomicBool,
) -> io::Result<ProxyStream> {
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
    let up_is_v6 = upstream_tcp
        .peer_addr()
        .map(|a| a.is_ipv6())
        .unwrap_or(false);
    apply_egress_qos(up_fd, qos.egress_dscp(None), qos.so_priority(), up_is_v6);
    info!("[{label}] routing upstream connected (plaintext, no TLS)");
    Ok(ProxyStream::Plain(upstream_tcp))
}

/// Accept one **plaintext TCP** connection (no TLS) on `listen_addr` for a
/// `routing` decrypt local endpoint — the plaintext counterpart to
/// [`accept_tls_upstream`].
pub fn accept_plain_upstream(
    label: &str,
    listen_addr: &str,
    sock_buf_size: usize,
    qos: QosPolicy,
    shutdown: &AtomicBool,
) -> io::Result<ProxyStream> {
    let listener = bind_tcp_listener(listen_addr, false, label).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("failed to bind routing listener on {listen_addr}"),
        )
    })?;
    listener.set_nonblocking(false).ok();

    let (stream, peer_addr): (TcpStream, _) = loop {
        if shutdown.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "shutdown while awaiting routing connection",
            ));
        }
        match accept_with_timeout(&listener, Duration::from_millis(200)) {
            Some(Ok(pair)) => break pair,
            Some(Err(e)) => return Err(e),
            None => continue,
        }
    };

    let fd = stream.as_raw_fd();
    tune_socket_buffers(fd, sock_buf_size);
    set_nodelay(fd, true);
    let is_v6 = peer_addr.is_ipv6();
    apply_egress_qos(fd, qos.egress_dscp(None), qos.so_priority(), is_v6);
    info!("[{label}] routing downstream accepted from {peer_addr} (plaintext, no TLS)");
    Ok(ProxyStream::Plain(stream))
}

/// Whether the UDS relay may use the zero-copy `splice(2)` fast-path.
///
/// Splicing the UDS socket straight to the upstream fd (and back) is correct
/// **only** when the upstream is kTLS *and* kTLS actually activated at runtime:
/// the raw fd then carries plaintext and the kernel performs the record-layer
/// crypto, exactly like the TCP encrypt path. If kTLS was requested but did not
/// activate (`ulp_active == false`), the fd carries ciphertext and we MUST relay
/// through the userspace SSL session instead — otherwise we would splice
/// cleartext onto the wire (TRA #56). Userspace TLS (`is_ktls == false`) likewise
/// has no spliceable plaintext fd.
///
/// Kept as a pure predicate so the TRA #56 guard is unit-testable without a live
/// socket.
#[inline]
fn should_splice_upstream(is_ktls: bool, ulp_active: bool) -> bool {
    is_ktls && ulp_active
}

/// Full-duplex byte-pipe relay between an authenticated local UDS client and a
/// TLS/kTLS upstream.
///
/// The `[len][traffic_id][data]` frame stream is carried transparently; for a
/// stream socket the gateway does not need to parse frames. When the upstream is
/// an active kTLS socket the relay delegates to the same zero-copy
/// [`relay_bidirectional_splice`] used by the TCP encrypt path — moving bytes
/// entirely in kernel space (UDS ↔ pipe ↔ kTLS), so a local interface reaches
/// the same throughput as kTLS-over-TCP. Otherwise it falls back to a
/// single-threaded userspace `poll()` loop, which both covers userspace TLS and
/// avoids concurrent read+write on the (non-thread-safe) `SslStream`.
pub fn relay_uds_tls(
    label: &str,
    mut plain: UnixStream,
    tls: &mut ProxyStream,
    conn_metrics: &mut ConnectionMetrics,
    perf: PerfKnobs,
    delay_ms: u64,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let tls_fd = tls.raw_fd();
    let plain_fd = plain.as_raw_fd();

    // Zero-copy fast-path: an active kTLS upstream means the kernel does the
    // crypto, so the UDS bytes can be spliced through a pipe to the upstream fd
    // (and back) with no userspace copies. Gated on *runtime* kTLS activation,
    // never on the requested mode alone (TRA #56).
    let is_ktls = matches!(tls, ProxyStream::Ktls { .. });
    if should_splice_upstream(is_ktls, tls.ktls_active()) {
        debug!("[{label}] UDS relay: zero-copy splice (kTLS upstream active)");
        return relay_bidirectional_splice(
            plain_fd,
            tls_fd,
            conn_metrics,
            shutdown,
            delay_ms,
            perf.pipe_size,
            perf.busy_poll_us,
            perf.bdp_adaptive,
            perf.bdp_queue_budget_us,
        );
    }

    set_nonblocking_fd(tls_fd);
    plain.set_nonblocking(true)?;
    set_nodelay(tls_fd, true);

    debug!("[{label}] UDS relay: userspace poll loop (local client <-> TLS upstream)");

    let mut buf = vec![0u8; perf.relay_buf_size.max(RELAY_BUF_SIZE)];

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let tls_pending = tls.ssl_pending();
        let (tls_ready, plain_ready) = poll_two_fds(tls_fd, plain_fd, tls_pending, 100)?;
        if !tls_ready && !plain_ready {
            continue;
        }

        // upstream (TLS) -> local client
        if tls_ready {
            loop {
                match tls.read(&mut buf) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        write_all_nb(&mut plain, &buf[..n])?;
                        conn_metrics.record_read(n);
                        conn_metrics.record_relay(n);
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
                if tls.ssl_pending() == 0 {
                    break;
                }
            }
        }

        // local client -> upstream (TLS)
        if plain_ready {
            loop {
                match plain.read(&mut buf) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        write_all_nb_proxy(tls, &buf[..n])?;
                        conn_metrics.record_read(n);
                        conn_metrics.record_relay(n);
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn params(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn ktls_offloadable_rule_stays_ktls() {
        // Default profile + verify:none + no PSK is offloadable → kTLS.
        let p = params(&[("verify", json!("none"))]);
        assert_eq!(upstream_tls_mode("ktls", &p, Some("tls1.3")), TlsMode::Ktls);
    }

    #[test]
    fn ktls_rule_with_verification_stays_ktls() {
        // Verified TLS (server- or mutual-auth) on the Default profile is now
        // kTLS-offloadable: the kTLS acceptor/connector apply the same CA trust +
        // client-cert verification as the userspace engine, and the relay
        // separately guards the splice path on runtime activation (TRA #56). So a
        // verify-requiring ktls rule STAYS kTLS rather than downgrading.
        let server = params(&[("verify", json!("server"))]);
        assert_eq!(
            upstream_tls_mode("ktls", &server, Some("tls1.3")),
            TlsMode::Ktls
        );

        let mutual = params(&[("verify", json!("mutual"))]);
        assert_eq!(
            upstream_tls_mode("ktls", &mutual, Some("tls1.2")),
            TlsMode::Ktls
        );
    }

    #[test]
    fn ktls_subset146_etcs_profiles_stay_ktls() {
        // The Subset-146 ETCS profiles negotiate AES-256-GCM, so their record
        // layer is kTLS-offloadable; PKI mutual / PSK auth is handshake-only and
        // the relay's #56 guard covers any runtime activation failure.
        let pki = params(&[("profile", json!("subset146-pki"))]);
        assert_eq!(
            upstream_tls_mode("ktls", &pki, Some("tls1.2")),
            TlsMode::Ktls
        );

        let psk = params(&[
            ("profile", json!("subset146-psk")),
            ("verify", json!("none")),
            ("psk_identity", json!("c1")),
            ("psk_hex", json!("00112233445566778899aabbccddeeff")),
        ]);
        assert_eq!(
            upstream_tls_mode("ktls", &psk, Some("tls1.2")),
            TlsMode::Ktls
        );
    }

    #[test]
    fn ktls_integrity_only_falls_back_to_userspace_tls() {
        // integrity-only uses NULL-encryption ciphers (no AES-GCM record layer),
        // so it is not kTLS-offloadable and falls back to the userspace engine.
        let integ = params(&[("profile", json!("integrity-only"))]);
        assert_eq!(
            upstream_tls_mode("ktls", &integ, Some("tls1.2")),
            TlsMode::Tls
        );
    }

    #[test]
    fn ktls_rule_with_unparseable_params_falls_back_to_tls() {
        // Default profile omitting `verify` is rejected by from_params
        // (fail-secure); the mode resolver conservatively falls back to Tls so
        // the userspace path surfaces the real error.
        let p = params(&[]);
        assert_eq!(upstream_tls_mode("ktls", &p, None), TlsMode::Tls);
    }

    #[test]
    fn non_ktls_provider_is_userspace_tls() {
        let p = params(&[("verify", json!("none"))]);
        assert_eq!(upstream_tls_mode("tls", &p, Some("tls1.3")), TlsMode::Tls);
    }

    #[test]
    fn splice_only_when_ktls_and_runtime_active() {
        // The TRA #56 guard: splice iff the upstream is kTLS AND kTLS actually
        // activated (ULP=tls). Every other combination must fall back to the
        // userspace SSL relay so ciphertext is never spliced onto the wire.
        assert!(should_splice_upstream(true, true)); // kTLS + active → splice
        assert!(!should_splice_upstream(true, false)); // kTLS requested, not active
        assert!(!should_splice_upstream(false, true)); // userspace TLS
        assert!(!should_splice_upstream(false, false)); // userspace TLS, nothing active
    }
}
