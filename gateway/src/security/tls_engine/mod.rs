//! TLS/kTLS engine — ProxyStream abstraction, TLS builders, and write helpers.

pub mod decrypt;
pub mod encrypt;
pub mod params;

use crate::management::cert_store::{get_or_init_cert, load_identity_pem};

use ktls_pipe::{enable_ktls_ctx, get_tcp_ulp, KtlsSession};
use openssl::ssl::{
    SslAcceptor, SslConnector, SslContextBuilder, SslMethod, SslOptions, SslSessionCacheMode,
    SslStream, SslVerifyMode, SslVersion,
};

use params::{TlsProfile, TlsSecurityParams, VerifyMode};

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

// ─── ProxyStream ─────────────────────────────────────────────────────────────

/// A bidirectional stream — userspace TLS, kTLS, or plaintext.
///
/// `Plain` carries no crypto: it is used **only** by `routing` local endpoints
/// (UDS/SHM), where the gateway is a plaintext passthrough exactly like the TCP
/// routing provider. TLS/kTLS endpoints never construct it, so the encrypted
/// data path is unchanged (TRA #58).
pub enum ProxyStream {
    Tls(SslStream<TcpStream>),
    Ktls {
        session: KtlsSession,
        /// Keep the TcpStream alive (KtlsSession borrows the fd).
        _stream: TcpStream,
    },
    /// Plaintext passthrough (routing local endpoints only — no encryption).
    Plain(TcpStream),
}

impl ProxyStream {
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ProxyStream::Tls(s) => s.read(buf),
            ProxyStream::Ktls { session, .. } => session.read(buf),
            ProxyStream::Plain(s) => s.read(buf),
        }
    }

    pub fn shutdown_write(&mut self) {
        match self {
            ProxyStream::Tls(s) => {
                let _ = s.shutdown();
            }
            ProxyStream::Ktls { session, .. } => {
                session.shutdown();
            }
            ProxyStream::Plain(s) => {
                let _ = s.shutdown(std::net::Shutdown::Write);
            }
        }
    }

    /// Get the raw file descriptor of the underlying TCP socket.
    pub fn raw_fd(&self) -> RawFd {
        match self {
            ProxyStream::Tls(s) => s.get_ref().as_raw_fd(),
            ProxyStream::Ktls { _stream, .. } => _stream.as_raw_fd(),
            ProxyStream::Plain(s) => s.as_raw_fd(),
        }
    }

    /// Check how many bytes are buffered in the SSL layer (0 for kTLS/plaintext).
    pub fn ssl_pending(&self) -> usize {
        match self {
            ProxyStream::Tls(s) => s.ssl().pending(),
            ProxyStream::Ktls { .. } => 0,
            ProxyStream::Plain(_) => 0,
        }
    }

    /// Whether kTLS is *actually* active on the underlying socket — i.e. the
    /// kernel `tls` ULP attached after the handshake (`get_tcp_ulp` == `"tls"`).
    ///
    /// Returns `false` for userspace TLS, and crucially also `false` when kTLS
    /// was *requested* but did not activate (missing privilege / unsupported
    /// cipher): in that case the raw fd still carries ciphertext, so any
    /// zero-copy splice fast-path MUST gate on this and fall back to the
    /// userspace SSL path — otherwise it would splice cleartext onto the wire
    /// (TRA #56).
    pub fn ktls_active(&self) -> bool {
        match self {
            ProxyStream::Ktls { _stream, .. } => get_tcp_ulp(_stream)
                .map(|ulp| ulp.starts_with("tls"))
                .unwrap_or(false),
            ProxyStream::Tls(_) | ProxyStream::Plain(_) => false,
        }
    }

    /// Whether this is the plaintext (`routing`) upstream — no crypto on the leg.
    /// The SHM zero-copy client→gateway drain gates on this: only for a plaintext
    /// upstream may a frame be written straight from peer-writable shared memory
    /// (TRA #77 — a mutating client can then corrupt only its own flow, never a
    /// TLS `SSL_write` same-buffer contract or another flow's data).
    pub fn is_plain(&self) -> bool {
        matches!(self, ProxyStream::Plain(_))
    }
}

impl io::Read for ProxyStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ProxyStream::Tls(s) => s.read(buf),
            ProxyStream::Ktls { session, .. } => session.read(buf),
            ProxyStream::Plain(s) => s.read(buf),
        }
    }
}

impl io::Write for ProxyStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ProxyStream::Tls(s) => s.write(buf),
            ProxyStream::Ktls { session, .. } => session.write(buf),
            ProxyStream::Plain(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ProxyStream::Tls(s) => s.flush(),
            ProxyStream::Ktls { session, .. } => session.flush(),
            ProxyStream::Plain(s) => s.flush(),
        }
    }
}

// ─── TLS builders ────────────────────────────────────────────────────────────
/// Stable session-id context so a resuming peer is recognised across
/// connections served by the same gateway process (required for server-side
/// TLS 1.2 session reuse and harmless for TLS 1.3 tickets).
const SESSION_ID_CONTEXT: &[u8] = b"scg-gateway";
/// Build a userspace TLS `SslAcceptor` from resolved security parameters.
///
/// Honours the rule's profile (cipher policy), peer verification (`verify`),
/// file-based identity (`cert_path`/`key_path`), CA trust (`ca_path`) and PSK
/// configuration. With default parameters this reproduces the historical
/// behaviour (self-signed cert, `SslVerifyMode::NONE`, AES-GCM).
pub fn build_tls_acceptor(params: &TlsSecurityParams) -> Result<SslAcceptor, String> {
    build_acceptor(params, false)
}

/// Build a kTLS-capable `SslAcceptor` from the same typed security parameters
/// as the userspace TLS path. The OpenSSL context is identical apart from the
/// `SSL_OP_ENABLE_KTLS` option, so file-based identities, CA trust, cipher
/// policy and resumption behave consistently across `tls` and `ktls`.
pub fn build_ktls_acceptor(params: &TlsSecurityParams) -> Result<SslAcceptor, String> {
    build_acceptor(params, true)
}

fn build_acceptor(
    params: &TlsSecurityParams,
    enable_kernel_tls: bool,
) -> Result<SslAcceptor, String> {
    let is13 = params.is_tls13();
    let mut builder = if is13 {
        SslAcceptor::mozilla_modern_v5(SslMethod::tls())
    } else {
        SslAcceptor::mozilla_intermediate(SslMethod::tls())
    }
    .map_err(|e| format!("acceptor builder: {}", e))?;

    // PSK handshakes carry no certificate; everything else needs an identity.
    if params.profile != TlsProfile::Subset146Psk {
        apply_identity(&mut builder, params)?;
    }
    if enable_kernel_tls {
        // SAFETY: `builder.as_ptr()` returns the live `SSL_CTX*` owned by `builder`,
        // which outlives this call; `enable_ktls_ctx` only sets the kTLS option on
        // that context and does not retain the pointer beyond the call.
        unsafe {
            enable_ktls_ctx(builder.as_ptr());
        }
    }

    apply_cipher_policy(&mut builder, params, is13)?;
    apply_acceptor_verify(&mut builder, params)?;
    apply_psk_server(&mut builder, params)?;
    pin_version(&mut builder, is13)?;
    apply_resumption(&mut builder, params, true)?;

    Ok(builder.build())
}

/// Build a userspace TLS `SslConnector` from resolved security parameters.
///
/// With default parameters verification is disabled (legacy behaviour). When
/// `verify` is `server`/`mutual` the server certificate is validated against
/// `ca_path` (and hostname checked at `connect` time); `mutual` additionally
/// presents the client identity from `cert_path`/`key_path`.
pub fn build_tls_connector(params: &TlsSecurityParams) -> Result<SslConnector, String> {
    build_connector(params, false)
}

/// Build a kTLS-capable `SslConnector` from the same typed security parameters
/// as the userspace TLS path.
pub fn build_ktls_connector(params: &TlsSecurityParams) -> Result<SslConnector, String> {
    build_connector(params, true)
}

fn build_connector(
    params: &TlsSecurityParams,
    enable_kernel_tls: bool,
) -> Result<SslConnector, String> {
    let is13 = params.is_tls13();
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| format!("connector builder: {}", e))?;

    // Present a client identity when configured (required for mutual auth).
    if params.cert_path.is_some() {
        apply_identity(&mut builder, params)?;
    }
    if enable_kernel_tls {
        // SAFETY: `builder.as_ptr()` returns the live `SSL_CTX*` owned by `builder`,
        // which outlives this call; `enable_ktls_ctx` only sets the kTLS option on
        // that context and does not retain the pointer beyond the call.
        unsafe {
            enable_ktls_ctx(builder.as_ptr());
        }
    }

    apply_cipher_policy(&mut builder, params, is13)?;
    apply_connector_verify(&mut builder, params)?;
    apply_psk_client(&mut builder, params)?;
    pin_version(&mut builder, is13)?;
    apply_resumption(&mut builder, params, false)?;

    Ok(builder.build())
}

/// Bound (or clear) the blocking window of a TLS/kTLS handshake on `stream`
/// (DoS-01). Pass `Some(timeout)` before `accept()`/`connect()` so a peer that
/// opens the TCP connection but stalls the handshake cannot pin the worker (or
/// rule thread) indefinitely; pass `None` afterwards to restore blocking I/O for
/// the relay phase. Both the read and write directions are bounded — a zero-window
/// peer can otherwise stall the server/client flight on the write side.
pub(crate) fn set_handshake_timeouts(
    stream: &TcpStream,
    timeout: Option<Duration>,
) -> io::Result<()> {
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    Ok(())
}

// ─── Builder helpers ─────────────────────────────────────────────────────────

/// Load the file-based identity if configured, otherwise the cached self-signed
/// certificate. Applies it to the builder and verifies the key matches.
fn apply_identity(
    builder: &mut SslContextBuilder,
    params: &TlsSecurityParams,
) -> Result<(), String> {
    match (&params.cert_path, &params.key_path) {
        (Some(cert), Some(key)) => {
            let (pkey, x509) = load_identity_pem(cert, key)?;
            builder
                .set_private_key(&pkey)
                .map_err(|e| format!("set private key: {}", e))?;
            builder
                .set_certificate(&x509)
                .map_err(|e| format!("set certificate: {}", e))?;
        }
        _ => {
            let (pkey, x509) =
                get_or_init_cert().map_err(|e| format!("self-signed cert: {}", e))?;
            builder
                .set_private_key(pkey)
                .map_err(|e| format!("set private key: {}", e))?;
            builder
                .set_certificate(x509)
                .map_err(|e| format!("set certificate: {}", e))?;
        }
    }
    builder
        .check_private_key()
        .map_err(|e| format!("certificate/key mismatch: {}", e))?;
    Ok(())
}

/// Apply the profile-derived (or explicitly overridden) cipher policy.
fn apply_cipher_policy(
    builder: &mut SslContextBuilder,
    params: &TlsSecurityParams,
    is13: bool,
) -> Result<(), String> {
    let (list, suites) = params.cipher_policy();
    if is13 {
        if let Some(suites) = suites {
            builder
                .set_ciphersuites(&suites)
                .map_err(|e| format!("set ciphersuites '{}': {}", suites, e))?;
        }
    } else if let Some(list) = list {
        builder
            .set_cipher_list(&list)
            .map_err(|e| format!("set cipher list '{}': {}", list, e))?;
    }
    Ok(())
}

/// Configure verification for the listen (server) side of a rule.
///
/// Only `mutual` requires the client to present a certificate; `none`/`server`
/// accept any client (a server cannot meaningfully "verify the server").
fn apply_acceptor_verify(
    builder: &mut SslContextBuilder,
    params: &TlsSecurityParams,
) -> Result<(), String> {
    match params.verify {
        VerifyMode::Mutual => {
            set_ca(builder, params)?;
            builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        }
        VerifyMode::None | VerifyMode::Server => {
            builder.set_verify(SslVerifyMode::NONE);
        }
    }
    Ok(())
}

/// Configure verification for the upstream (client) side of a rule.
///
/// `server`/`mutual` validate the upstream certificate chain against `ca_path`;
/// hostname checking is performed by `connect()` using the SNI name.
fn apply_connector_verify(
    builder: &mut SslContextBuilder,
    params: &TlsSecurityParams,
) -> Result<(), String> {
    match params.verify {
        VerifyMode::Server | VerifyMode::Mutual => {
            set_ca(builder, params)?;
            builder.set_verify(SslVerifyMode::PEER);
        }
        VerifyMode::None => {
            builder.set_verify(SslVerifyMode::NONE);
        }
    }
    Ok(())
}

/// Load the configured CA bundle into the builder's trust store.
fn set_ca(builder: &mut SslContextBuilder, params: &TlsSecurityParams) -> Result<(), String> {
    if let Some(ca) = &params.ca_path {
        builder
            .set_ca_file(ca)
            .map_err(|e| format!("load ca_path '{}': {}", ca.display(), e))?;
    }
    Ok(())
}

/// Wire the server-side PSK callback for the `subset146-psk` profile.
fn apply_psk_server(
    builder: &mut SslContextBuilder,
    params: &TlsSecurityParams,
) -> Result<(), String> {
    if params.profile != TlsProfile::Subset146Psk {
        return Ok(());
    }
    let expected_identity = params.psk_identity.clone().unwrap_or_default();
    let key = params.psk_key.clone().unwrap_or_default();
    #[allow(deprecated)]
    builder.set_psk_server_callback(move |_ssl, client_identity, psk_out| {
        let matches = client_identity
            .map(|id| id == expected_identity.as_bytes())
            .unwrap_or(false);
        if !matches || key.len() > psk_out.len() {
            return Ok(0); // reject: identity mismatch or buffer too small
        }
        psk_out[..key.len()].copy_from_slice(&key);
        Ok(key.len())
    });
    Ok(())
}

/// Wire the client-side PSK callback for the `subset146-psk` profile.
fn apply_psk_client(
    builder: &mut SslContextBuilder,
    params: &TlsSecurityParams,
) -> Result<(), String> {
    if params.profile != TlsProfile::Subset146Psk {
        return Ok(());
    }
    let identity = params.psk_identity.clone().unwrap_or_default();
    let key = params.psk_key.clone().unwrap_or_default();
    #[allow(deprecated)]
    builder.set_psk_client_callback(move |_ssl, _hint, identity_out, psk_out| {
        // identity_out must be NUL-terminated, so reserve one byte.
        if identity.len() + 1 > identity_out.len() || key.len() > psk_out.len() {
            return Ok(0);
        }
        identity_out[..identity.len()].copy_from_slice(identity.as_bytes());
        identity_out[identity.len()] = 0;
        psk_out[..key.len()].copy_from_slice(&key);
        Ok(key.len())
    });
    Ok(())
}

/// Pin the protocol version (min == max) to the selected TLS version.
fn pin_version(builder: &mut SslContextBuilder, is13: bool) -> Result<(), String> {
    let v = if is13 {
        SslVersion::TLS1_3
    } else {
        SslVersion::TLS1_2
    };
    builder
        .set_min_proto_version(Some(v))
        .map_err(|e| format!("set min version: {}", e))?;
    builder
        .set_max_proto_version(Some(v))
        .map_err(|e| format!("set max version: {}", e))?;
    Ok(())
}

/// Configure TLS session resumption per the rule's `resumption` toggle.
///
/// When enabled, a reconnecting peer can skip the full handshake:
/// the server side advertises tickets and keeps a session cache keyed by a
/// stable session-id context, and the client side caches the sessions/tickets
/// the upstream issues. When disabled, tickets and the session cache are turned
/// off so every connection performs a fresh handshake.
fn apply_resumption(
    builder: &mut SslContextBuilder,
    params: &TlsSecurityParams,
    is_server: bool,
) -> Result<(), String> {
    if params.resumption {
        if is_server {
            builder
                .set_session_id_context(SESSION_ID_CONTEXT)
                .map_err(|e| format!("set session id context: {}", e))?;
            builder.set_session_cache_mode(SslSessionCacheMode::SERVER);
        } else {
            builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        }
    } else {
        builder.set_options(SslOptions::NO_TICKET);
        // TLS 1.3 issues tickets independently of the cache; silence them too.
        builder.set_num_tickets(0).ok();
        builder.set_session_cache_mode(SslSessionCacheMode::OFF);
    }
    Ok(())
}

// ─── ProxyStream write helpers ───────────────────────────────────────────────

/// Poll the underlying fd of a ProxyStream for write readiness.
/// Sleeps the thread in the kernel instead of spin-yielding.
#[inline]
fn poll_proxy_write_ready(stream: &ProxyStream, timeout_ms: i32) -> io::Result<()> {
    let fd = stream.raw_fd();
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: `&mut pfd` points to a single fully-initialised `libc::pollfd`, so the
    // pointer/count pair (`&mut pfd`, `1`) is valid for `poll`; `pfd.fd` is the live
    // descriptor borrowed from `stream` for the duration of the call, and the return
    // value is checked below.
    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
    Ok(())
}

/// Write all bytes to a ProxyStream, waiting for write readiness on WouldBlock.
pub fn write_all_nb_proxy(stream: &mut ProxyStream, data: &[u8]) -> io::Result<()> {
    let mut pos = 0;
    while pos < data.len() {
        let n = match stream {
            ProxyStream::Tls(s) => match s.write(&data[pos..]) {
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    poll_proxy_write_ready(stream, 100)?;
                    continue;
                }
                Err(e) => return Err(e),
            },
            ProxyStream::Ktls { session, .. } => match session.write(&data[pos..]) {
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    poll_proxy_write_ready(stream, 100)?;
                    continue;
                }
                Err(e) => return Err(e),
            },
            ProxyStream::Plain(s) => match s.write(&data[pos..]) {
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    poll_proxy_write_ready(stream, 100)?;
                    continue;
                }
                Err(e) => return Err(e),
            },
        };
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero"));
        }
        pos += n;
    }
    Ok(())
}

/// Write all bytes to a ProxyStream with a wall-clock time limit.
/// Gives up if no progress is made within `timeout_ms` milliseconds.
#[allow(dead_code)]
pub fn write_nb_proxy_timed(
    stream: &mut ProxyStream,
    data: &[u8],
    timeout_ms: u64,
) -> io::Result<()> {
    let timeout = Duration::from_millis(timeout_ms);
    let mut pos = 0;
    let mut last_progress = Instant::now();
    while pos < data.len() {
        let n = match stream {
            ProxyStream::Tls(s) => match s.write(&data[pos..]) {
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if last_progress.elapsed() > timeout {
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    poll_proxy_write_ready(stream, 100)?;
                    continue;
                }
                Err(e) => return Err(e),
            },
            ProxyStream::Ktls { session, .. } => match session.write(&data[pos..]) {
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if last_progress.elapsed() > timeout {
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    poll_proxy_write_ready(stream, 100)?;
                    continue;
                }
                Err(e) => return Err(e),
            },
            ProxyStream::Plain(s) => match s.write(&data[pos..]) {
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if last_progress.elapsed() > timeout {
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    poll_proxy_write_ready(stream, 100)?;
                    continue;
                }
                Err(e) => return Err(e),
            },
        };
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero"));
        }
        pos += n;
        last_progress = Instant::now();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_ktls_acceptor, build_ktls_connector, build_tls_acceptor, build_tls_connector,
        set_handshake_timeouts, ProxyStream,
    };
    use crate::security::tls_engine::params::TlsSecurityParams;
    use openssl::ssl::SslVerifyMode;
    use serde_json::json;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::{Duration, Instant};

    fn params_from(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    // DP-01: the kTLS connector used by the UDS/SHM local-interface path must
    // apply the rule's verify mode, exactly like the userspace connector — the
    // former bench builder hardcoded SslVerifyMode::NONE.
    #[test]
    fn ktls_connector_applies_verify_mode() {
        let server =
            TlsSecurityParams::from_params(&params_from(&[("verify", json!("server"))]), None)
                .unwrap();
        let c = build_ktls_connector(&server).unwrap();
        assert_eq!(c.context().verify_mode(), SslVerifyMode::PEER);

        let none = TlsSecurityParams::from_params(&params_from(&[("verify", json!("none"))]), None)
            .unwrap();
        let ck = build_ktls_connector(&none).unwrap();
        let cu = build_tls_connector(&none).unwrap();
        assert_eq!(ck.context().verify_mode(), SslVerifyMode::NONE);
        // kTLS and userspace connectors must agree on the verify wiring.
        assert_eq!(ck.context().verify_mode(), cu.context().verify_mode());
    }

    // DP-01/KC-05: a `verify=mutual` kTLS acceptor must demand a client cert
    // (PEER | FAIL_IF_NO_PEER_CERT), not accept any client.
    #[test]
    fn ktls_acceptor_mutual_requires_client_cert() {
        let mutual =
            TlsSecurityParams::from_params(&params_from(&[("verify", json!("mutual"))]), None)
                .unwrap();
        let a = build_ktls_acceptor(&mutual).unwrap();
        assert_eq!(
            a.context().verify_mode(),
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
        );

        let none = TlsSecurityParams::from_params(&params_from(&[("verify", json!("none"))]), None)
            .unwrap();
        let a = build_ktls_acceptor(&none).unwrap();
        assert_eq!(a.context().verify_mode(), SslVerifyMode::NONE);
    }

    // DoS-01: the handshake-timeout helper sets both directions and clears them.
    #[test]
    fn handshake_timeouts_set_and_cleared() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        let t = Duration::from_secs(5);
        set_handshake_timeouts(&server, Some(t)).unwrap();
        assert_eq!(server.read_timeout().unwrap(), Some(t));
        assert_eq!(server.write_timeout().unwrap(), Some(t));

        set_handshake_timeouts(&server, None).unwrap();
        assert_eq!(server.read_timeout().unwrap(), None);
        assert_eq!(server.write_timeout().unwrap(), None);
    }

    // DoS-01: a stalled client cannot pin a decrypt worker — with SO_RCVTIMEO the
    // blocking TLS accept aborts instead of blocking forever. Uses a short timeout
    // so the test is fast; production uses `HANDSHAKE_TIMEOUT` (5 s).
    #[test]
    fn stalled_client_handshake_aborts_within_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Client connects and then sends nothing (stalls the ClientHello).
        let _client = TcpStream::connect(addr).unwrap();

        let (server, _) = listener.accept().unwrap();
        let params =
            TlsSecurityParams::from_params(&params_from(&[("verify", json!("none"))]), None)
                .unwrap();
        let acceptor = build_tls_acceptor(&params).unwrap();
        set_handshake_timeouts(&server, Some(Duration::from_millis(300))).unwrap();

        let start = Instant::now();
        let result = acceptor.accept(server);
        let elapsed = start.elapsed();
        assert!(result.is_err(), "stalled handshake must abort, not hang");
        assert!(
            elapsed < Duration::from_secs(3),
            "handshake should abort near the timeout, took {elapsed:?}"
        );
    }

    // DoS-01 (connect side): a fake upstream that accepts TCP but never speaks TLS
    // must not pin the connector past the handshake timeout.
    #[test]
    fn stalled_upstream_handshake_aborts_within_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept the TCP connection but never respond to the TLS handshake.
        let _srv = thread::spawn(move || {
            let (_s, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(2));
        });

        let stream = TcpStream::connect(addr).unwrap();
        set_handshake_timeouts(&stream, Some(Duration::from_millis(300))).unwrap();
        let params =
            TlsSecurityParams::from_params(&params_from(&[("verify", json!("none"))]), None)
                .unwrap();
        let connector = build_tls_connector(&params).unwrap();

        let start = Instant::now();
        let result = connector.connect("localhost", stream);
        let elapsed = start.elapsed();
        assert!(result.is_err(), "stalled upstream handshake must abort");
        assert!(
            elapsed < Duration::from_secs(3),
            "connect should abort near the timeout, took {elapsed:?}"
        );
    }

    #[test]
    fn plain_proxy_stream_round_trips_plaintext() {
        // ProxyStream::Plain (routing local endpoints, TRA #58) is a no-crypto
        // passthrough: bytes written through it arrive verbatim on the peer with
        // no TLS framing, it never buffers in an SSL layer, and never reports
        // kTLS active (so the splice fast-path treats it correctly).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 5];
            sock.read_exact(&mut buf).unwrap();
            buf
        });
        let client = TcpStream::connect(addr).unwrap();
        let mut plain = ProxyStream::Plain(client);
        plain.write_all(b"hello").unwrap();
        plain.flush().unwrap();
        assert_eq!(&server.join().unwrap(), b"hello");
        assert_eq!(plain.ssl_pending(), 0);
        assert!(!plain.ktls_active());
    }
}
