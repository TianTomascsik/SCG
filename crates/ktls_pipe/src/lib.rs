//! kTLS primitives shared by the SCG gateway data plane.
//!
//! This crate provides the small, production-facing kTLS surface:
//!
//! - [`KtlsSession`] — a low-level wrapper around an OpenSSL `Ssl` bound to a
//!   raw fd via `SSL_set_fd` (required for kTLS offload), implementing
//!   [`Read`]/[`Write`] over `SSL_read`/`SSL_write`.
//! - [`enable_ktls_ctx`] / [`enable_ktls_ssl`] — set `SSL_OP_ENABLE_KTLS` on a
//!   context / connection.
//! - [`get_tcp_ulp`] — query a socket's upper-layer protocol to verify the
//!   kernel actually attached the `tls` ULP.
//! - [`kernel_supports_ktls`] / [`ktls_privilege_hint`] — host capability probe
//!   and operator hint.
//!
//! The gateway builds its verify/cert/CA-honouring kTLS connectors and
//! acceptors in `security::tls_engine` (see TRA DP-01); this crate deliberately
//! contains no certificate or crypto-policy logic. The historical `KtlsPipe`
//! benchmark harness (io_uring / vmsplice / splice lanes and the `SCG_BENCH_*`
//! environment knobs) was removed in 2026-07 as orphaned code — recover it from
//! git history if ever needed.

use foreign_types_shared::ForeignTypeRef;
use openssl::error::ErrorStack;
use openssl::ssl::Ssl;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::OnceLock;

/// OpenSSL SSL_OP_ENABLE_KTLS = SSL_OP_BIT(3)
const SSL_OP_ENABLE_KTLS: libc::c_ulong = 1 << 3;

extern "C" {
    fn SSL_set_options(ssl: *mut openssl_sys::SSL, op: libc::c_ulong) -> libc::c_ulong;
    fn SSL_set_fd(ssl: *mut openssl_sys::SSL, fd: libc::c_int) -> libc::c_int;
}

// =========================================================================================
//                                  KtlsSession
// =========================================================================================

/// Low-level wrapper around an OpenSSL `Ssl` object with kTLS support.
/// Uses `SSL_set_fd` for direct FD access (required by kTLS).
pub struct KtlsSession {
    ssl: Ssl,
}

impl KtlsSession {
    pub fn new(ssl: Ssl, fd: libc::c_int) -> Result<Self, ErrorStack> {
        // SAFETY: `ssl.as_ptr()` returns the valid, non-null `SSL*` owned by the
        // `Ssl` we are about to take ownership of; `fd` is the caller-supplied
        // descriptor that OpenSSL will associate with this connection. The
        // return value is checked below.
        let ret = unsafe { SSL_set_fd(ssl.as_ptr(), fd) };
        if ret == 1 {
            Ok(Self { ssl })
        } else {
            Err(ErrorStack::get())
        }
    }

    pub fn accept(&mut self) -> Result<(), ErrorStack> {
        // SAFETY: `self.ssl.as_ptr()` is the valid, non-null `SSL*` owned by
        // `self` and kept alive for the duration of this call; the return value
        // is checked below.
        let ret = unsafe { openssl_sys::SSL_accept(self.ssl.as_ptr()) };
        if ret == 1 {
            Ok(())
        } else {
            Err(ErrorStack::get())
        }
    }

    pub fn connect(&mut self) -> Result<(), ErrorStack> {
        // SAFETY: `self.ssl.as_ptr()` is the valid, non-null `SSL*` owned by
        // `self` and kept alive for the duration of this call; the return value
        // is checked below.
        let ret = unsafe { openssl_sys::SSL_connect(self.ssl.as_ptr()) };
        if ret == 1 {
            Ok(())
        } else {
            Err(ErrorStack::get())
        }
    }

    pub fn ssl_ref(&self) -> &openssl::ssl::SslRef {
        &self.ssl
    }

    pub fn as_ptr(&self) -> *mut openssl_sys::SSL {
        self.ssl.as_ptr()
    }

    pub fn shutdown(&self) {
        // SAFETY: `self.ssl.as_ptr()` is the valid, non-null `SSL*` owned by
        // `self` and kept alive for the duration of this call.
        unsafe {
            openssl_sys::SSL_shutdown(self.ssl.as_ptr());
        }
    }
}

impl Read for KtlsSession {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = usize::min(buf.len(), libc::c_int::MAX as usize);
        // SAFETY: `self.ssl.as_ptr()` is a valid, non-null `SSL*` owned by
        // `self`; `buf.as_mut_ptr()` points to `buf.len()` writable bytes and
        // `len` is clamped to `c_int::MAX` so it never exceeds the buffer or
        // overflows the `c_int` length argument. The return value is checked
        // below.
        let ret = unsafe {
            openssl_sys::SSL_read(
                self.ssl.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                len as libc::c_int,
            )
        };
        if ret > 0 {
            return Ok(ret as usize);
        }

        // SAFETY: `self.ssl.as_ptr()` is a valid, non-null `SSL*` owned by
        // `self`; `ret` is the result just returned by `SSL_read` on the same
        // session, which is exactly what `SSL_get_error` expects.
        let err = unsafe { openssl_sys::SSL_get_error(self.ssl.as_ptr(), ret) };
        match err {
            openssl_sys::SSL_ERROR_WANT_READ | openssl_sys::SSL_ERROR_WANT_WRITE => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            openssl_sys::SSL_ERROR_ZERO_RETURN => Ok(0),
            openssl_sys::SSL_ERROR_SYSCALL => {
                let err = io::Error::last_os_error();
                if err.raw_os_error().is_none() {
                    return Ok(0);
                }
                Err(err)
            }
            _ => Err(io::Error::other(ErrorStack::get())),
        }
    }
}

impl Write for KtlsSession {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = usize::min(buf.len(), libc::c_int::MAX as usize);
        // SAFETY: `self.ssl.as_ptr()` is a valid, non-null `SSL*` owned by
        // `self`; `buf.as_ptr()` points to `buf.len()` readable bytes and `len`
        // is clamped to `c_int::MAX` so it never exceeds the buffer or overflows
        // the `c_int` length argument. The return value is checked below.
        let ret = unsafe {
            openssl_sys::SSL_write(
                self.ssl.as_ptr(),
                buf.as_ptr() as *const libc::c_void,
                len as libc::c_int,
            )
        };
        if ret > 0 {
            return Ok(ret as usize);
        }

        // SAFETY: `self.ssl.as_ptr()` is a valid, non-null `SSL*` owned by
        // `self`; `ret` is the result just returned by `SSL_write` on the same
        // session, which is exactly what `SSL_get_error` expects.
        let err = unsafe { openssl_sys::SSL_get_error(self.ssl.as_ptr(), ret) };
        match err {
            openssl_sys::SSL_ERROR_WANT_READ | openssl_sys::SSL_ERROR_WANT_WRITE => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            openssl_sys::SSL_ERROR_ZERO_RETURN => {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ssl closed"))
            }
            openssl_sys::SSL_ERROR_SYSCALL => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other(ErrorStack::get())),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// =========================================================================================
//                                TLS / kTLS helpers
// =========================================================================================

/// Enable kTLS on an OpenSSL context.
///
/// # Safety
///
/// `ctx` must be a valid, non-null `SSL_CTX*` whose lifetime outlives this call.
/// The caller is responsible for ensuring OpenSSL owns the context and that
/// setting options is synchronized with any concurrent context use.
pub unsafe fn enable_ktls_ctx(ctx: *mut openssl_sys::SSL_CTX) {
    openssl_sys::SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
}

/// Enable kTLS on an OpenSSL connection.
///
/// # Safety
///
/// `ssl` must be a valid, non-null `SSL*` whose lifetime outlives this call.
/// The caller is responsible for ensuring the connection is not concurrently
/// mutated while the option is set.
pub unsafe fn enable_ktls_ssl(ssl: *mut openssl_sys::SSL) {
    SSL_set_options(ssl, SSL_OP_ENABLE_KTLS);
}

pub fn get_tcp_ulp(stream: &TcpStream) -> io::Result<String> {
    const TCP_ULP: libc::c_int = 31;
    let fd = stream.as_raw_fd();
    let mut buf = [0u8; 16];
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: `fd` is the raw descriptor of the live, borrowed `stream`;
    // `buf.as_mut_ptr()`/`len` describe a 16-byte writable buffer and `len` is
    // initialised to its capacity, so the kernel writes at most that many bytes
    // and updates `len` in place. The return value is checked below.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_ULP,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len as *mut libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    let name = std::str::from_utf8(&buf[..len as usize]).unwrap_or("");
    Ok(name.trim_end_matches(char::from(0)).to_string())
}

pub fn ktls_privilege_hint() -> &'static str {
    // SAFETY: `geteuid` takes no arguments, never fails, and only reads the
    // calling process's effective user id, so the call is always sound.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        " Hint: run as root or grant CAP_NET_ADMIN (setcap cap_net_admin+ep <bin>)."
    } else {
        ""
    }
}

/// Whether the running kernel exposes the TLS upper-layer protocol (the `tls`
/// ULP), i.e. kTLS offload is available on this host.
///
/// Probes `/proc/sys/net/ipv4/tcp_available_ulp` once and caches the result —
/// the set of registered ULPs does not change at runtime. Returns `false` when
/// the file is absent or does not list `tls` (e.g. the `tls` module is not
/// loaded), which callers use to transparently stay on userspace TLS.
pub fn kernel_supports_ktls() -> bool {
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        fs::read_to_string("/proc/sys/net/ipv4/tcp_available_ulp")
            .map(|s| s.split_whitespace().any(|ulp| ulp == "tls"))
            .unwrap_or(false)
    })
}
