//! TLS/kTLS engine — ProxyStream abstraction, TLS builders, and write helpers.

pub mod decrypt;
pub mod encrypt;
pub mod params;

use crate::management::cert_store::{get_or_init_cert, load_identity_pem};

use ktls_pipe::KtlsSession;
use openssl::ssl::{
    SslAcceptor, SslConnector, SslContextBuilder, SslMethod, SslStream, SslVerifyMode, SslVersion,
};

use params::{TlsProfile, TlsSecurityParams, VerifyMode};

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

// ─── ProxyStream ─────────────────────────────────────────────────────────────

/// A bidirectional stream — either userspace TLS or kTLS.
pub enum ProxyStream {
    Tls(SslStream<TcpStream>),
    Ktls {
        session: KtlsSession,
        /// Keep the TcpStream alive (KtlsSession borrows the fd).
        _stream: TcpStream,
    },
}

impl ProxyStream {
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ProxyStream::Tls(s) => s.read(buf),
            ProxyStream::Ktls { session, .. } => session.read(buf),
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
        }
    }

    /// Get the raw file descriptor of the underlying TCP socket.
    pub fn raw_fd(&self) -> RawFd {
        match self {
            ProxyStream::Tls(s) => s.get_ref().as_raw_fd(),
            ProxyStream::Ktls { _stream, .. } => _stream.as_raw_fd(),
        }
    }

    /// Check how many bytes are buffered in the SSL layer (0 for kTLS).
    pub fn ssl_pending(&self) -> usize {
        match self {
            ProxyStream::Tls(s) => s.ssl().pending() as usize,
            ProxyStream::Ktls { .. } => 0,
        }
    }
}

impl io::Read for ProxyStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ProxyStream::Tls(s) => s.read(buf),
            ProxyStream::Ktls { session, .. } => session.read(buf),
        }
    }
}

impl io::Write for ProxyStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ProxyStream::Tls(s) => s.write(buf),
            ProxyStream::Ktls { session, .. } => session.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ProxyStream::Tls(s) => s.flush(),
            ProxyStream::Ktls { session, .. } => session.flush(),
        }
    }
}

// ─── TLS builders ────────────────────────────────────────────────────────────

/// Build a userspace TLS `SslAcceptor` from resolved security parameters.
///
/// Honours the rule's profile (cipher policy), peer verification (`verify`),
/// file-based identity (`cert_path`/`key_path`), CA trust (`ca_path`) and PSK
/// configuration. With default parameters this reproduces the historical
/// behaviour (self-signed cert, `SslVerifyMode::NONE`, AES-GCM).
pub fn build_tls_acceptor(params: &TlsSecurityParams) -> Result<SslAcceptor, String> {
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

    apply_cipher_policy(&mut builder, params, is13)?;
    apply_acceptor_verify(&mut builder, params)?;
    apply_psk_server(&mut builder, params)?;
    pin_version(&mut builder, is13)?;

    Ok(builder.build())
}

/// Build a userspace TLS `SslConnector` from resolved security parameters.
///
/// With default parameters verification is disabled (legacy behaviour). When
/// `verify` is `server`/`mutual` the server certificate is validated against
/// `ca_path` (and hostname checked at `connect` time); `mutual` additionally
/// presents the client identity from `cert_path`/`key_path`.
pub fn build_tls_connector(params: &TlsSecurityParams) -> Result<SslConnector, String> {
    let is13 = params.is_tls13();
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| format!("connector builder: {}", e))?;

    // Present a client identity when configured (required for mutual auth).
    if params.cert_path.is_some() {
        apply_identity(&mut builder, params)?;
    }

    apply_cipher_policy(&mut builder, params, is13)?;
    apply_connector_verify(&mut builder, params)?;
    apply_psk_client(&mut builder, params)?;
    pin_version(&mut builder, is13)?;

    Ok(builder.build())
}

// ─── Builder helpers ─────────────────────────────────────────────────────────

/// Load the file-based identity if configured, otherwise the cached self-signed
/// certificate. Applies it to the builder and verifies the key matches.
fn apply_identity(builder: &mut SslContextBuilder, params: &TlsSecurityParams) -> Result<(), String> {
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
            let (pkey, x509) = get_or_init_cert().map_err(|e| format!("self-signed cert: {}", e))?;
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
fn apply_psk_server(builder: &mut SslContextBuilder, params: &TlsSecurityParams) -> Result<(), String> {
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
fn apply_psk_client(builder: &mut SslContextBuilder, params: &TlsSecurityParams) -> Result<(), String> {
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
        };
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero"));
        }
        pos += n;
        last_progress = Instant::now();
    }
    Ok(())
}
