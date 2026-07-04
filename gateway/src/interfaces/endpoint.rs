//! Shared helpers for the dynamically-created local message interfaces
//! (UDS and SHM).
//!
//! These endpoints are created on demand by the management API and bridge a
//! locally-authenticated application client to a TLS/kTLS upstream. The
//! `[len][traffic_id][data]` frame stream is carried transparently end-to-end,
//! so a UDS client on one gateway can interoperate with a SHM client on a peer
//! gateway: both sides see the same length-prefixed frame stream inside TLS.

use crate::management::config::{Direction, PerfKnobs, QosPolicy, TlsMode, TrafficClass};
use crate::management::telemetry::ConnectionMetrics;
use crate::networking::connector::connect_with_retry;
use crate::networking::socket_manager::{
    accept_with_timeout, apply_egress_qos, bind_tcp_listener, poll_two_fds, set_nodelay,
    set_nonblocking_fd, tune_socket_buffers, write_all_nb,
};
use crate::processing::policy::PolicyManager;
use crate::security::relay::relay_bidirectional_splice;
use crate::security::tls_engine::params::TlsSecurityParams;
use crate::security::tls_engine::{
    build_ktls_acceptor, build_ktls_connector, build_tls_acceptor, build_tls_connector,
    prime_resumption, resumption_key, set_handshake_timeouts, write_all_nb_proxy, ProxyStream,
};
use crate::security::{HANDSHAKE_TIMEOUT, RELAY_BUF_SIZE};

use foreign_types_shared::ForeignTypeRef;
use ktls_pipe::{enable_ktls_ssl, get_tcp_ulp, ktls_privilege_hint, KtlsSession};
use log::{debug, error, info, warn};
use openssl::ssl::{Ssl, SslAcceptor};

use scg_ipc::handshake::{Hello, HELLO_LEN};
use scg_ipc::os::{self, PeerCred};
use scg_ipc::token::CapabilityToken;

use std::collections::HashMap;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::net::TcpStream;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Policy gate for a local endpoint's network leg (DP-08).
///
/// The local caller is authenticated out-of-band (uid + pid + single-use token),
/// so there is no meaningful network *source* on the app side. The encrypt
/// direction therefore gates the upstream **destination** (the network-meaningful
/// attribute of that leg), and the decrypt direction gates the real network
/// **peer** that dialed the endpoint's TLS listener — giving every local endpoint
/// the same default-deny second gate the TCP/UDP relays carry (register OQ2).
pub struct EndpointPolicy {
    /// Shared, hot-reloadable policy manager (same handle as the network paths).
    pub policy: Arc<RwLock<PolicyManager>>,
    /// The rule's traffic class (drives the Safety fail-open behaviour).
    pub traffic_class: TrafficClass,
}

impl EndpointPolicy {
    /// Gate an encrypt endpoint's upstream `target` (destination-only). Fails
    /// closed on an unparseable target, mirroring the network path (DP-07).
    pub fn allows_destination(&self, label: &str, target: &str) -> bool {
        let dst = match target.parse::<SocketAddr>() {
            Ok(d) => d,
            Err(_) => {
                warn!(
                    "[{label}] AUDIT deny op=local_upstream_policy target='{target}': \
                     not an IP:port; failing closed"
                );
                return false;
            }
        };
        let allowed = self
            .policy
            .read()
            .map(|p| p.check_allowed_destination(&dst, self.traffic_class))
            .unwrap_or(false);
        if !allowed {
            warn!(
                "[{label}] AUDIT deny op=local_upstream_policy dst={dst}: \
                 destination not permitted by policy"
            );
        }
        allowed
    }

    /// Gate a decrypt endpoint's real network `peer` against the source whitelist.
    /// The onward hop is address-less local IPC, so the endpoint's own `listen`
    /// address stands in as the destination (documented approximation).
    pub fn allows_peer(&self, label: &str, peer: SocketAddr, listen: &str) -> bool {
        let dst = listen.parse::<SocketAddr>().unwrap_or(peer);
        let allowed = self
            .policy
            .read()
            .map(|p| p.check_allowed(&peer, &dst, self.traffic_class))
            .unwrap_or(false);
        if !allowed {
            warn!(
                "[{label}] AUDIT deny op=local_peer_policy peer={peer}: \
                 source not permitted by policy"
            );
        }
        allowed
    }
}

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
    // reuse it. Recover a poisoned guard rather than panicking in library code
    // (L29): the token Option is a well-formed value regardless of any prior
    // panic, so continuing is safe.
    {
        let mut guard = token.lock().unwrap_or_else(|e| e.into_inner());
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
/// kTLS activates. [`connect_tls_upstream`]/[`accept_tls_upstream`] build the kTLS
/// context through [`crate::security::tls_engine::build_ktls_connector`] /
/// [`crate::security::tls_engine::build_ktls_acceptor`], which apply the rule's
/// verify/CA/cert and PSK setup identically to userspace TLS (DP-01). So verified
/// TLS and the Subset-146 ETCS profiles stay on the kTLS path; only `integrity-only`
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
    policy: Option<&EndpointPolicy>,
    shutdown: &AtomicBool,
) -> io::Result<ProxyStream> {
    // Second gate (DP-08): a default-deny policy must permit this upstream before
    // we dial it, mirroring the TCP/UDP relay paths.
    if let Some(p) = policy {
        if !p.allows_destination(label, upstream_addr) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local endpoint upstream denied by policy",
            ));
        }
    }
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

    // Bound the blocking handshake window so a stalled upstream cannot wedge this
    // endpoint thread (DoS-01); cleared once the handshake completes, below.
    set_handshake_timeouts(&upstream_tcp, Some(HANDSHAKE_TIMEOUT))?;

    let hs_start = Instant::now();
    let proxy = match tls_mode {
        TlsMode::Tls => {
            let connector = build_tls_connector(&params)
                .map_err(|e| io::Error::other(format!("TLS connector: {e}")))?;
            let ssl_stream = if params.resumption {
                // Present a cached ticket for this exact upstream + crypto policy so the
                // reconnect can resume (task S2 / TRA #78–#80). `configure()` carries the same
                // SNI + hostname-verification defaults as `connect()`, so priming is transparent.
                let key = resumption_key(&params, upstream_addr, false);
                let mut config = connector
                    .configure()
                    .map_err(|e| io::Error::other(format!("TLS configure: {e}")))?;
                prime_resumption(&mut config, key);
                config
                    .connect(&sni, upstream_tcp)
                    .map_err(|e| io::Error::other(format!("TLS handshake: {e}")))?
            } else {
                connector
                    .connect(&sni, upstream_tcp)
                    .map_err(|e| io::Error::other(format!("TLS handshake: {e}")))?
            };
            info!(
                "[{label}] upstream TLS handshake OK ({:.2} ms)",
                hs_start.elapsed().as_secs_f64() * 1000.0
            );
            // Handshake done — restore blocking I/O for the relay phase.
            set_handshake_timeouts(ssl_stream.get_ref(), None)?;
            ProxyStream::Tls(ssl_stream)
        }
        TlsMode::Ktls => {
            // Build the kTLS connector through the tls_engine so the rule's
            // verify mode, CA/cert and PSK callback are applied identically to
            // userspace TLS (DP-01). The former `ktls_pipe::build_client_connector`
            // hardcoded SslVerifyMode::NONE and silently discarded them.
            let connector = build_ktls_connector(&params)
                .map_err(|e| io::Error::other(format!("kTLS connector: {e}")))?;
            let mut ssl = connector
                .configure()
                .map_err(|e| io::Error::other(format!("kTLS configure: {e}")))?
                .into_ssl(&sni)
                .map_err(|e| io::Error::other(format!("kTLS SSL: {e}")))?;
            if params.resumption {
                // Resume this upstream+policy if a ticket is cached (task S2 / TRA #78–#80).
                prime_resumption(&mut ssl, resumption_key(&params, upstream_addr, true));
            }
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
            // Handshake done — restore blocking I/O for the relay phase.
            set_handshake_timeouts(&upstream_tcp, None)?;
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
    policy: Option<&EndpointPolicy>,
    shutdown: &AtomicBool,
) -> io::Result<ProxyStream> {
    let listener = bind_tcp_listener(listen_addr, false, label).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("failed to bind decrypt TLS listener on {listen_addr}"),
        )
    })?;
    listener.set_nonblocking(false).ok();

    // Parse the rule's TLS security parameters once; both the userspace and the
    // kTLS acceptor honour verify mode / CA / cert / PSK identically (DP-01).
    let params = TlsSecurityParams::from_params(provider_params, protocol_version)
        .map_err(|e| io::Error::other(format!("TLS params: {e}")))?;

    // Build the server acceptor once (fail fast on bad config before we block on
    // accept). Userspace TLS honours the rule's cert/key/profile (self-signed
    // fallback for the default profile); kTLS goes through the same
    // verify-honouring builder rather than the former no-verify bench acceptor.
    let acceptor: SslAcceptor = match tls_mode {
        TlsMode::Tls => build_tls_acceptor(&params)
            .map_err(|e| io::Error::other(format!("TLS acceptor: {e}")))?,
        TlsMode::Ktls => build_ktls_acceptor(&params)
            .map_err(|e| io::Error::other(format!("kTLS acceptor: {e}")))?,
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
            Some(Ok((stream, peer))) => {
                // Second gate (DP-08): drop a peer the policy denies and keep
                // listening — a denied prober must not consume this single-use
                // endpoint or trigger the handshake.
                if let Some(p) = policy {
                    if !p.allows_peer(label, peer, listen_addr) {
                        continue;
                    }
                }
                break (stream, peer);
            }
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

    // Bound the blocking handshake window so a peer that connects but stalls the
    // ClientHello cannot wedge this endpoint thread (DoS-01); cleared below.
    set_handshake_timeouts(&stream, Some(HANDSHAKE_TIMEOUT))?;

    let hs_start = Instant::now();
    let proxy = match tls_mode {
        TlsMode::Tls => {
            let ssl_stream = acceptor
                .accept(stream)
                .map_err(|e| io::Error::other(format!("TLS accept: {e}")))?;
            info!(
                "[{label}] downstream TLS accept from {peer_addr} ({:.2} ms)",
                hs_start.elapsed().as_secs_f64() * 1000.0
            );
            // Handshake done — restore blocking I/O for the relay phase.
            set_handshake_timeouts(ssl_stream.get_ref(), None)?;
            ProxyStream::Tls(ssl_stream)
        }
        TlsMode::Ktls => {
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
            // Handshake done — restore blocking I/O for the relay phase.
            set_handshake_timeouts(&stream, None)?;
            ProxyStream::Ktls {
                session,
                _stream: stream,
            }
        }
        // Unreachable in practice (the acceptor build above returns for DTLS),
        // but expressed as a fail-secure error rather than a library panic.
        TlsMode::Dtls => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DTLS is not supported for local UDS/SHM interfaces",
            ));
        }
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
    policy: Option<&EndpointPolicy>,
    shutdown: &AtomicBool,
) -> io::Result<ProxyStream> {
    // Second gate (DP-08): routing over UDS/SHM is policy-gated exactly like the
    // TCP routing provider (register #38 parity).
    if let Some(p) = policy {
        if !p.allows_destination(label, upstream_addr) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local routing upstream denied by policy",
            ));
        }
    }
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
    policy: Option<&EndpointPolicy>,
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
            Some(Ok((stream, peer))) => {
                // Second gate (DP-08): drop a policy-denied peer, keep listening.
                if let Some(p) = policy {
                    if !p.allows_peer(label, peer, listen_addr) {
                        continue;
                    }
                }
                break (stream, peer);
            }
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

/// Establish the upstream leg for a local (UDS/SHM) endpoint, collapsing the
/// 4-way `(routing, direction)` dispatch and its error-verb logging that
/// `uds::serve` and `shm::serve` previously duplicated verbatim (M27).
///
/// Returns `None` after logging on failure so the caller simply `return`s from
/// its serve loop.
#[allow(clippy::too_many_arguments)]
pub(crate) fn establish_upstream(
    label: &str,
    routing: bool,
    direction: Direction,
    upstream_addr: &str,
    tls_mode: TlsMode,
    provider_params: &HashMap<String, serde_json::Value>,
    protocol_version: Option<&str>,
    sock_buf_size: usize,
    qos: QosPolicy,
    policy: Option<&EndpointPolicy>,
    shutdown: &AtomicBool,
) -> Option<ProxyStream> {
    // Routing endpoints relay plaintext (no TLS) on the upstream leg, exactly
    // like the TCP routing provider (TRA #58); the local-caller auth already
    // passed before this call. TLS/kTLS endpoints take the encrypted path.
    let result = match (routing, direction) {
        (true, Direction::Encrypt) => {
            connect_plain_upstream(label, upstream_addr, sock_buf_size, qos, policy, shutdown)
        }
        (true, Direction::Decrypt) => {
            accept_plain_upstream(label, upstream_addr, sock_buf_size, qos, policy, shutdown)
        }
        (false, Direction::Encrypt) => connect_tls_upstream(
            label,
            upstream_addr,
            tls_mode,
            provider_params,
            protocol_version,
            sock_buf_size,
            qos,
            policy,
            shutdown,
        ),
        (false, Direction::Decrypt) => accept_tls_upstream(
            label,
            upstream_addr,
            tls_mode,
            provider_params,
            protocol_version,
            sock_buf_size,
            qos,
            policy,
            shutdown,
        ),
    };
    match result {
        Ok(t) => Some(t),
        Err(e) => {
            let verb = match direction {
                Direction::Encrypt => "connect",
                Direction::Decrypt => "accept",
            };
            error!("[{label}] upstream {verb} failed: {e}");
            None
        }
    }
}

/// Poll a single fd for readability with a timeout; retries on `EINTR`.
/// Shared by the UDS and SHM serve loops (M27).
pub(crate) fn poll_readable(fd: std::os::unix::io::RawFd, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: `pfd` is a live, fully-initialised single `pollfd`; the
        // pointer/count pair (1) is valid for the call and `poll` only writes
        // `revents`. The negative return is checked and `EINTR` retried below.
        let ret = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout_ms) };
        if ret < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return false;
        }
        return ret > 0 && (pfd.revents & libc::POLLIN) != 0;
    }
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

    // DP-08: EndpointPolicy gates the network leg of a local endpoint.
    use crate::management::config::{PolicyAction, PolicyConfig, WhitelistEntry};

    fn endpoint_policy(whitelist: Vec<WhitelistEntry>, class: TrafficClass) -> EndpointPolicy {
        let cfg = PolicyConfig {
            default_action: PolicyAction::Deny,
            whitelist,
            enforce_policy_on_safety: false,
        };
        EndpointPolicy {
            policy: Arc::new(RwLock::new(PolicyManager::new(Some(&cfg)))),
            traffic_class: class,
        }
    }

    #[test]
    fn endpoint_policy_gates_destination() {
        let ep = endpoint_policy(
            vec![WhitelistEntry {
                source: "any".into(),
                destination: "10.0.0.0/8".into(),
            }],
            TrafficClass::Normal,
        );
        assert!(ep.allows_destination("t", "10.1.2.3:443"));
        assert!(!ep.allows_destination("t", "192.168.1.1:443"));
        // Fail closed on an unparseable target (mirrors DP-07).
        assert!(!ep.allows_destination("t", "backend.example.com:443"));
    }

    #[test]
    fn endpoint_policy_gates_peer_source() {
        let ep = endpoint_policy(
            vec![WhitelistEntry {
                source: "10.0.0.0/8".into(),
                destination: "any".into(),
            }],
            TrafficClass::Normal,
        );
        let allowed: SocketAddr = "10.9.9.9:5000".parse().unwrap();
        let denied: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        assert!(ep.allows_peer("t", allowed, "127.0.0.1:8443"));
        assert!(!ep.allows_peer("t", denied, "127.0.0.1:8443"));
    }

    #[test]
    fn endpoint_policy_safety_fail_open() {
        // Safety class with no opt-in bypasses the gate (railway availability).
        let ep = endpoint_policy(Vec::new(), TrafficClass::Safety);
        assert!(ep.allows_destination("t", "203.0.113.1:443"));
        let peer: SocketAddr = "203.0.113.1:5000".parse().unwrap();
        assert!(ep.allows_peer("t", peer, "127.0.0.1:8443"));
    }
}
