//! TLS/kTLS engine — ProxyStream abstraction, TLS builders, and write helpers.

pub mod decrypt;
pub mod encrypt;

use crate::management::cert_store::get_or_init_cert;

use ktls_pipe::KtlsSession;
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};

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

/// Build a userspace TLS SslAcceptor (no kTLS).
/// Accepts an optional protocol version: "tls1.2" (default) or "tls1.3".
pub fn build_tls_acceptor(
    version: Option<&str>,
) -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let (pkey, cert) = get_or_init_cert()?;

    match version {
        Some("tls1.3") => {
            // TLS 1.3 requires a plain builder — mozilla_intermediate restricts protocols
            let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls())?;
            builder.set_private_key(pkey)?;
            builder.set_certificate(cert)?;
            builder.check_private_key()?;
            builder.set_ciphersuites("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")?;
            builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
            Ok(builder.build())
        }
        _ => {
            // Default: TLS 1.2
            let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
            builder.set_private_key(pkey)?;
            builder.set_certificate(cert)?;
            builder.check_private_key()?;
            builder.set_cipher_list("AES128-GCM-SHA256:AES256-GCM-SHA384")?;
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
            Ok(builder.build())
        }
    }
}

/// Build a userspace TLS SslConnector (no kTLS, no cert verification).
/// Accepts an optional protocol version: "tls1.2" (default) or "tls1.3".
pub fn build_tls_connector(
    version: Option<&str>,
) -> Result<SslConnector, openssl::error::ErrorStack> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_verify(SslVerifyMode::NONE);

    match version {
        Some("tls1.3") => {
            builder.set_ciphersuites("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")?;
            builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        }
        _ => {
            // Default: TLS 1.2
            builder.set_cipher_list("AES128-GCM-SHA256:AES256-GCM-SHA384")?;
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        }
    }

    Ok(builder.build())
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
