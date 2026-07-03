//! Shared kTLS pipe: sets up a TLS-encrypted TCP loopback connection using kTLS
//! and provides a simple write interface. A background sink thread drains the
//! encrypted data on the receiver side.
//!
//! Three write paths are available, in order of performance:
//!
//! 1. **io_uring zero-copy send** (`write_all_uring`) – batches sends via `io_uring`
//!    with `IORING_OP_SEND_ZC` (kernel ≥ 6.0). Single syscall for many sends.
//! 2. **vmsplice + splice** (`write_all_splice`) – maps userspace pages into a pipe
//!    via `vmsplice`, then `splice` from pipe to kTLS socket. Zero copies.
//! 3. **SSL_write** (`write_all`) – classic path through OpenSSL, one copy per call.
//!
//! Usage:
//! ```no_run
//! let mut pipe = ktls_pipe::KtlsPipe::new().expect("kTLS setup failed");
//! pipe.write_all(b"hello world").unwrap();
//! let stats = pipe.shutdown();
//! println!("kTLS bytes written: {}", stats.bytes_written);
//! ```

use foreign_types_shared::ForeignTypeRef;
use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{
    Ssl, SslAcceptor, SslConnector, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode,
    SslVersion,
};
use openssl::x509::X509;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::Instant;

// =========================================================================================
//                                     CONSTANTS
// =========================================================================================

/// OpenSSL SSL_OP_ENABLE_KTLS = SSL_OP_BIT(3)
const SSL_OP_ENABLE_KTLS: libc::c_ulong = 1 << 3;

/// Socket buffer sizes for high-throughput loopback (16 MiB each direction).
const SOCK_BUF_SIZE: libc::c_int = 16 * 1024 * 1024;

/// Sink thread drain buffer (8 MiB) – used only in the non-splice fallback path.
const SINK_BUF_SIZE: usize = 8 * 1024 * 1024;

/// Maximum bytes per splice() call (pipe capacity, typically 1 MiB on modern kernels).
const SPLICE_CHUNK: usize = 4 * 1024 * 1024;

/// Async writer channel depth: number of 4 MiB buffers that can be queued.
/// With 64 slots × 4 MiB = 256 MiB max outstanding. Provides back-pressure when full.
const ASYNC_CHANNEL_DEPTH: usize = 64;

/// Splice flags for zero-copy.
const SPLICE_F_MOVE: libc::c_uint = 1;
const SPLICE_F_MORE: libc::c_uint = 4;
const SPLICE_F_GIFT: libc::c_uint = 8;

extern "C" {
    fn SSL_set_options(ssl: *mut openssl_sys::SSL, op: libc::c_ulong) -> libc::c_ulong;
    fn SSL_set_fd(ssl: *mut openssl_sys::SSL, fd: libc::c_int) -> libc::c_int;
}

// =========================================================================================
//                             Cached TLS certificate (OnceLock)
// =========================================================================================

type CachedCert = (PKey<openssl::pkey::Private>, X509);

/// Process-wide cached self-signed certificate to avoid regenerating RSA-2048 keys
/// for every `KtlsPipe::new()` call.
static CACHED_CERT: OnceLock<CachedCert> = OnceLock::new();

fn get_or_init_cert() -> Result<&'static CachedCert, openssl::error::ErrorStack> {
    if let Some(cached) = CACHED_CERT.get() {
        return Ok(cached);
    }
    let cert = build_self_signed_cert()?;
    // Another thread may have raced us; that's fine.
    let _ = CACHED_CERT.set(cert);
    Ok(CACHED_CERT.get().unwrap())
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

/// Generate a self-signed RSA-2048 certificate at runtime (no files needed).
pub fn build_self_signed_cert(
) -> Result<(PKey<openssl::pkey::Private>, X509), openssl::error::ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;

    let mut name = openssl::x509::X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "localhost")?;
    let name = name.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    builder.sign(&pkey, MessageDigest::sha256())?;
    Ok((pkey, builder.build()))
}

/// Resolve the TLS protocol version for benchmarks. An explicit `override_`
/// (e.g. `Some("tls1.3")`) wins; otherwise the `SCG_BENCH_TLS_VERSION`
/// environment variable is consulted (default: TLS 1.2). Modern Linux kernels
/// offload both TLS 1.2 and TLS 1.3 records to the kernel TLS data path.
fn bench_tls_version(override_: Option<&str>) -> SslVersion {
    let raw = override_
        .map(str::to_string)
        .or_else(|| std::env::var("SCG_BENCH_TLS_VERSION").ok())
        .unwrap_or_default();
    let v = raw.trim().to_ascii_lowercase();
    let v = v.trim_start_matches("tls").trim_start_matches('v');
    match v {
        "" | "1.2" | "1-2" | "1_2" | "12" => SslVersion::TLS1_2,
        "1.3" | "1-3" | "1_3" | "13" => SslVersion::TLS1_3,
        other => {
            eprintln!(
                "[ktls] WARNING: unknown TLS version '{}', using TLS 1.2",
                other
            );
            SslVersion::TLS1_2
        }
    }
}

/// Configure the benchmark TLS version + AEAD cipher on `builder` from the
/// `SCG_BENCH_TLS_VERSION` / `SCG_BENCH_CIPHER` environment variables, so the
/// historical AES-128-GCM / TLS 1.2 baseline can be compared against modern,
/// forward-secret suites recommended by BSI TR-02102-2 and NIST SP 800-52r2 —
/// without recompiling. Every selected cipher is offloadable to the Linux
/// kernel TLS data path.
///
/// Cipher values (case-insensitive, `-`/`_` interchangeable):
///   * `aes128-gcm` (default), `aes256-gcm` (BSI + NIST), `chacha20-poly1305` (BSI)
fn configure_bench_crypto(
    builder: &mut SslContextBuilder,
    version: Option<&str>,
) -> Result<(), ErrorStack> {
    let ver = bench_tls_version(version);
    builder.set_min_proto_version(Some(ver))?;
    builder.set_max_proto_version(Some(ver))?;

    let raw = std::env::var("SCG_BENCH_CIPHER").unwrap_or_default();
    let cipher = raw.trim().to_ascii_lowercase().replace('_', "-");

    if ver == SslVersion::TLS1_3 {
        // `mozilla_intermediate()` disables TLS 1.3 via SSL_OP_NO_TLSv1_3; undo that
        // so the requested TLS 1.3 version is actually negotiable.
        builder.clear_options(SslOptions::NO_TLSV1_3);
        // Suppress post-handshake NewSessionTicket messages so the kernel TLS
        // receive path stays active for the whole TLS 1.3 session.
        builder.set_num_tickets(0)?;
        let suite = match cipher.as_str() {
            "" | "aes128-gcm" | "aes-128-gcm" => "TLS_AES_128_GCM_SHA256",
            "aes256-gcm" | "aes-256-gcm" => "TLS_AES_256_GCM_SHA384",
            "chacha20-poly1305" | "chacha20" | "chacha" => "TLS_CHACHA20_POLY1305_SHA256",
            other => {
                eprintln!(
                    "[ktls] WARNING: unknown SCG_BENCH_CIPHER='{}', using TLS_AES_128_GCM_SHA256",
                    other
                );
                "TLS_AES_128_GCM_SHA256"
            }
        };
        builder.set_ciphersuites(suite)?;
    } else {
        let list = match cipher.as_str() {
            "" | "aes128-gcm" | "aes-128-gcm" => "AES128-GCM-SHA256",
            "aes256-gcm" | "aes-256-gcm" => "ECDHE-RSA-AES256-GCM-SHA384",
            "chacha20-poly1305" | "chacha20" | "chacha" => "ECDHE-RSA-CHACHA20-POLY1305",
            other => {
                eprintln!(
                    "[ktls] WARNING: unknown SCG_BENCH_CIPHER='{}', using AES128-GCM-SHA256",
                    other
                );
                "AES128-GCM-SHA256"
            }
        };
        builder.set_cipher_list(list)?;
    }
    Ok(())
}

/// Build a kTLS-offload **server** acceptor for the crate's own benchmark lanes.
///
/// Benchmark-only: it presents a cached self-signed certificate and performs **no
/// client verification**. It is used solely by `KtlsPipeLane` to measure kTLS
/// record-layer throughput on loopback. The gateway data plane must NOT use it —
/// it builds its kTLS acceptor via
/// [`security::tls_engine::build_ktls_acceptor`](../../gateway) so the rule's
/// verify/CA/cert and PSK setup are applied (DP-01).
pub fn build_server_acceptor(
    version: Option<&str>,
) -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let (pkey, cert) = get_or_init_cert()?;
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_private_key(pkey)?;
    builder.set_certificate(cert)?;
    builder.check_private_key()?;
    // SAFETY: `builder.as_ptr()` returns the valid, non-null `SSL_CTX*` owned by
    // the live `builder` on the stack, so it outlives this call and is not
    // concurrently mutated; this satisfies `enable_ktls_ctx`'s safety contract.
    unsafe {
        enable_ktls_ctx(builder.as_ptr());
    }

    configure_bench_crypto(&mut builder, version)?;
    Ok(builder.build())
}

/// Build a kTLS-offload **client** connector for the crate's own benchmark lanes.
///
/// Benchmark-only: peer verification is intentionally `NONE`, so this offloads the
/// default AES-GCM, server-authentication-disabled path only. It exists purely to
/// let `KtlsPipeLane` measure kTLS record-layer throughput on loopback. **The
/// gateway data plane must NOT use it** — it builds its kTLS connector via
/// [`security::tls_engine::build_ktls_connector`](../../gateway) so the rule's
/// `verify`/CA/cert and PSK setup are honoured identically to userspace TLS
/// (DP-01). Do not route a gateway rule through this helper.
pub fn build_client_connector(
    version: Option<&str>,
) -> Result<SslConnector, openssl::error::ErrorStack> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    // SAFETY (security): NONE is correct only for this benchmark lane; the gateway
    // uses the verify-honouring tls_engine builders instead. See the doc above.
    builder.set_verify(SslVerifyMode::NONE);
    // SAFETY: `builder.as_ptr()` returns the valid, non-null `SSL_CTX*` owned by
    // the live `builder` on the stack, so it outlives this call and is not
    // concurrently mutated; this satisfies `enable_ktls_ctx`'s safety contract.
    unsafe {
        enable_ktls_ctx(builder.as_ptr());
    }

    configure_bench_crypto(&mut builder, version)?;
    Ok(builder.build())
}

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

pub fn get_tls_stat_total() -> io::Result<u64> {
    let data = fs::read_to_string("/proc/net/tls_stat")?;
    let mut total = 0u64;
    for line in data.lines() {
        let mut parts = line.split_whitespace();
        let _name = parts.next();
        let value = match parts.next() {
            Some(v) => v,
            None => continue,
        };
        if let Ok(parsed) = value.parse::<u64>() {
            total = total.saturating_add(parsed);
        }
    }
    Ok(total)
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

// =========================================================================================
//                              Socket & pipe helpers
// =========================================================================================

/// Set send/receive buffer sizes on a TCP socket to `SOCK_BUF_SIZE`.
fn tune_socket_buffers(fd: RawFd) {
    // SAFETY: `fd` is a raw socket descriptor supplied by the caller; `&val`
    // points to a live `c_int` whose size is passed explicitly via
    // `size_of::<c_int>()`, matching the `SO_SNDBUF`/`SO_RCVBUF` option type.
    // Best-effort tuning, so the return values are intentionally ignored.
    unsafe {
        let val = SOCK_BUF_SIZE;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Set TCP_NODELAY on a raw fd.
fn set_nodelay(fd: RawFd, on: bool) {
    let val: libc::c_int = if on { 1 } else { 0 };
    // SAFETY: `fd` is a raw socket descriptor supplied by the caller; `&val`
    // points to a live `c_int` whose size is passed explicitly via
    // `size_of::<c_int>()`, matching the `TCP_NODELAY` option type. Best-effort,
    // so the return value is intentionally ignored.
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Set TCP_CORK on a raw fd. When enabled, TCP coalesces small writes into
/// full MSS-sized segments. Disabling flushes the cork buffer.
fn set_tcp_cork(fd: RawFd, on: bool) {
    let val: libc::c_int = if on { 1 } else { 0 };
    // SAFETY: `fd` is a raw socket descriptor supplied by the caller; `&val`
    // points to a live `c_int` whose size is passed explicitly via
    // `size_of::<c_int>()`, matching the `TCP_CORK` option type. Best-effort,
    // so the return value is intentionally ignored.
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CORK,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Create a `pipe2(O_CLOEXEC)` pair, returns `(read_fd, write_fd)`.
fn make_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds.as_mut_ptr()` points to a writable array of exactly 2 `RawFd`
    // (`c_int`), which is what `pipe2` expects to fill; `O_CLOEXEC` is a valid
    // flag. The return value is checked below before the fds are used.
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // Grow pipe capacity to 1 MiB for better splice throughput.
    // SAFETY: `fds[0]` is the valid read-end descriptor just created by the
    // checked `pipe2` above; `F_SETPIPE_SZ` takes the pipe size as its `c_int`
    // argument. Best-effort tuning, so the return value is intentionally ignored.
    unsafe {
        libc::fcntl(fds[0], libc::F_SETPIPE_SZ, SPLICE_CHUNK as libc::c_int);
    }
    Ok((fds[0], fds[1]))
}

/// Close a raw fd if it is >= 0.
fn close_fd(fd: RawFd) {
    if fd >= 0 {
        // SAFETY: `fd` is non-negative (checked above) and is a descriptor owned
        // by the caller that is being relinquished here; closing it exactly once
        // is sound.
        unsafe {
            libc::close(fd);
        }
    }
}

// =========================================================================================
//                           Zero-copy write: vmsplice + splice
// =========================================================================================

/// Write `data` from userspace into the kTLS socket via `vmsplice` + `splice`.
///
/// Flow: userspace buffer → vmsplice() → kernel pipe → splice() → kTLS socket (encrypt + send).
/// No data copies cross the user-kernel boundary.
fn write_splice(
    pipe_write_fd: RawFd,
    pipe_read_fd: RawFd,
    sock_fd: RawFd,
    data: &[u8],
) -> io::Result<usize> {
    let mut total = 0usize;
    while total < data.len() {
        let remaining = &data[total..];
        let chunk = remaining.len().min(SPLICE_CHUNK);

        // 1) vmsplice: map userspace pages into the kernel pipe buffer.
        let mut vmspliced = 0usize;
        while vmspliced < chunk {
            let iov_remaining = libc::iovec {
                // SAFETY: `vmspliced < chunk <= remaining.len()` (loop guard), so
                // the offset stays within the same `remaining` allocation, which
                // is the in-bounds requirement of `<*const u8>::add`.
                iov_base: unsafe { remaining.as_ptr().add(vmspliced) } as *mut libc::c_void,
                iov_len: chunk - vmspliced,
            };
            // SAFETY: `pipe_write_fd` is a valid pipe write-end descriptor;
            // `&iov_remaining` points to one live `iovec` whose base/len describe
            // a readable in-bounds sub-slice of `remaining`, and the count `1`
            // matches. `remaining` (borrowed from `data`) outlives the call, and
            // the return value is checked below.
            let ret = unsafe {
                libc::vmsplice(
                    pipe_write_fd,
                    &iov_remaining as *const libc::iovec,
                    1,
                    SPLICE_F_GIFT as libc::c_uint,
                )
            };
            if ret < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            vmspliced += ret as usize;
        }

        // 2) splice: move data from pipe to the kTLS TCP socket.
        let mut spliced = 0usize;
        while spliced < vmspliced {
            // SAFETY: `pipe_read_fd` and `sock_fd` are valid descriptors owned by
            // the caller; the null offset pointers are explicitly permitted by
            // `splice` (kernel advances the file offsets), and the length is the
            // number of bytes previously placed in the pipe. The return value is
            // checked below.
            let ret = unsafe {
                libc::splice(
                    pipe_read_fd,
                    std::ptr::null_mut(),
                    sock_fd,
                    std::ptr::null_mut(),
                    (vmspliced - spliced) as libc::size_t,
                    (SPLICE_F_MOVE | SPLICE_F_MORE) as libc::c_uint,
                )
            };
            if ret < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if ret == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "splice returned 0",
                ));
            }
            spliced += ret as usize;
        }

        total += spliced;
    }
    Ok(total)
}

// =========================================================================================
//                          Zero-copy sink via splice-to-/dev/null
// =========================================================================================

/// Drain a kTLS socket by splicing to `/dev/null`. Returns total bytes drained.
///
/// This avoids any kernel→userspace copy on the receive side: the kernel decrypts
/// the TLS records and discards the plaintext directly.
fn splice_sink_loop(sock_fd: RawFd, stop: &AtomicBool) -> u64 {
    // SAFETY: the C string literal `c"/dev/null"` is a valid, NUL-terminated
    // path pointer that lives for the whole call, and `O_WRONLY` is a valid
    // open flag. The returned descriptor is checked below before use.
    let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
    if devnull < 0 {
        eprintln!(
            "kTLS sink: failed to open /dev/null: {}",
            io::Error::last_os_error()
        );
        return 0;
    }

    let mut total: u64 = 0;
    loop {
        // SAFETY: `sock_fd` is the caller-owned socket descriptor and `devnull`
        // is the valid descriptor opened and checked above; the null offset
        // pointers are explicitly permitted by `splice`. The return value is
        // checked below.
        let ret = unsafe {
            libc::splice(
                sock_fd,
                std::ptr::null_mut(),
                devnull,
                std::ptr::null_mut(),
                SPLICE_CHUNK as libc::size_t,
                SPLICE_F_MOVE as libc::c_uint,
            )
        };
        if ret > 0 {
            total += ret as u64;
        } else if ret == 0 {
            // EOF – sender closed connection.
            break;
        } else {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    continue;
                }
                _ => {
                    // EINVAL means kTLS splice-read may not be supported; fall through.
                    break;
                }
            }
        }
    }

    // SAFETY: `devnull` is the valid descriptor opened above and owned by this
    // function; it is no longer used after this point, so closing it once is sound.
    unsafe {
        libc::close(devnull);
    }
    total
}

/// Fallback drain loop using raw recv when splice is not available.
fn recv_sink_loop(sock_fd: RawFd, stop: &AtomicBool) -> u64 {
    let mut buf = vec![0u8; SINK_BUF_SIZE];
    let mut total: u64 = 0;
    loop {
        // SAFETY: `sock_fd` is the caller-owned socket descriptor;
        // `buf.as_mut_ptr()`/`buf.len()` describe the fully-allocated, writable
        // `SINK_BUF_SIZE` buffer, so the kernel writes at most `buf.len()` bytes.
        // The return value is checked below.
        let ret =
            unsafe { libc::recv(sock_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if ret > 0 {
            total += ret as u64;
            continue;
        }
        if ret == 0 {
            break;
        }

        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if e.kind() == io::ErrorKind::WouldBlock {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            continue;
        }
        break;
    }
    total
}

// =========================================================================================
//                              io_uring batched send path
// =========================================================================================

/// Holds an `io_uring` instance and the registered kTLS socket fd.
struct IoUringSender {
    ring: io_uring::IoUring,
    sock_fd: io_uring::types::Fd,
}

impl IoUringSender {
    fn new(sock_fd: RawFd) -> io::Result<Self> {
        let ring = io_uring::IoUring::builder()
            .setup_coop_taskrun()
            .build(1024)?;
        Ok(Self {
            ring,
            sock_fd: io_uring::types::Fd(sock_fd),
        })
    }

    /// Send `data` through the kTLS socket using io_uring batched sends.
    ///
    /// Uses regular `IORING_OP_SEND` (not `SendZc`) to avoid notification CQE
    /// complexity on kTLS sockets. Still benefits from io_uring's batched
    /// submission (fewer syscalls than plain `send()`).
    fn send_all(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut total = 0usize;
        // Batch multiple sends: fill the SQ with up to N chunks, then submit once.
        // Use 4 MiB chunks to match the flush threshold and reduce TLS record count.
        const CHUNK: usize = 4 * 1024 * 1024;
        const BATCH: usize = 64; // submit up to 64 ops per io_uring_enter()

        while total < data.len() {
            let mut submitted = 0usize;

            // Fill the submission queue with up to BATCH entries.
            {
                let mut sq = self.ring.submission();
                while submitted < BATCH && total + submitted * CHUNK < data.len() {
                    let off = total + submitted * CHUNK;
                    let end = (off + CHUNK).min(data.len());
                    let chunk = &data[off..end];

                    let entry = io_uring::opcode::Send::new(
                        self.sock_fd,
                        chunk.as_ptr(),
                        chunk.len() as u32,
                    )
                    .build()
                    .user_data(off as u64);

                    // Safety: `data` slice remains valid until we reap the completions.
                    match unsafe { sq.push(&entry) } {
                        Ok(()) => submitted += 1,
                        Err(_) => break, // SQ full, submit what we have
                    }
                }
            }

            if submitted == 0 {
                break;
            }

            // Single syscall for all submitted ops.
            self.ring.submit_and_wait(submitted)?;

            // Reap all completions.
            let mut reaped = 0usize;
            {
                let cq = self.ring.completion();
                for cqe in cq {
                    let ret = cqe.result();
                    if ret < 0 {
                        return Err(io::Error::from_raw_os_error(-ret));
                    }
                    total += ret as usize;
                    reaped += 1;
                }
            }

            if reaped == 0 {
                return Err(io::Error::other(
                    "io_uring: no completions after submit_and_wait",
                ));
            }
        }

        Ok(total)
    }
}

// =========================================================================================
//                          Async background writer thread
// =========================================================================================

/// Background writer thread that receives filled buffers over a channel and
/// sends them to the kTLS socket. With kTLS TX active, the kernel transparently
/// encrypts the data.
///
/// This decouples the IPC processing path from the kTLS write latency:
/// the caller's `write_all()` copies to a buffer and sends it to the channel
/// (non-blocking unless the channel is full), while the writer thread handles
/// the actual socket I/O in parallel.
fn writer_thread_loop(
    rx: mpsc::Receiver<Vec<u8>>,
    sock_fd: RawFd,
    mode: PipeMode,
    cork: Arc<AtomicBool>,
) {
    let mut uring_sender = if mode == PipeMode::IoUring {
        match IoUringSender::new(sock_fd) {
            Ok(sender) => Some(sender),
            Err(e) => {
                eprintln!("kTLS async writer: io_uring init failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    while let Ok(buf) = rx.recv() {
        let use_cork = cork.load(Ordering::Relaxed);
        if use_cork {
            set_tcp_cork(sock_fd, true);
        }

        if let Some(ref mut sender) = uring_sender {
            if let Err(e) = sender.send_all(&buf) {
                eprintln!("kTLS async writer: io_uring send error: {}", e);
                if use_cork {
                    set_tcp_cork(sock_fd, false);
                }
                return;
            }
            if use_cork {
                set_tcp_cork(sock_fd, false);
            }
            continue;
        }

        let mut sent = 0usize;
        while sent < buf.len() {
            let remaining = buf.len() - sent;
            // Use MSG_MORE when there's more data to send, hinting the kernel
            // to coalesce TLS records and reduce per-record overhead.
            let flags = if remaining > 16384 {
                libc::MSG_NOSIGNAL | libc::MSG_MORE
            } else {
                libc::MSG_NOSIGNAL
            };
            // SAFETY: `sock_fd` is the caller-owned socket descriptor;
            // `buf[sent..].as_ptr()` points to `remaining == buf.len() - sent`
            // readable bytes (the unsent tail of `buf`, with `sent < buf.len()`
            // per the loop guard); `flags` are valid `MSG_*` bits. The return
            // value is checked below.
            let ret = unsafe {
                libc::send(
                    sock_fd,
                    buf[sent..].as_ptr() as *const libc::c_void,
                    remaining,
                    flags,
                )
            };
            if ret > 0 {
                sent += ret as usize;
            } else if ret == 0 {
                if use_cork {
                    set_tcp_cork(sock_fd, false);
                }
                return; // Connection closed
            } else {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                eprintln!("kTLS async writer: send error: {}", e);
                if use_cork {
                    set_tcp_cork(sock_fd, false);
                }
                return;
            }
        }

        if use_cork {
            set_tcp_cork(sock_fd, false);
        }
    }
    // Channel closed — sender dropped, we're done.
}

fn send_blocking_sys(sock_fd: RawFd, data: &[u8]) -> io::Result<()> {
    let mut sent = 0usize;
    while sent < data.len() {
        let remaining = data.len() - sent;
        let flags = if remaining > 16384 {
            libc::MSG_NOSIGNAL | libc::MSG_MORE
        } else {
            libc::MSG_NOSIGNAL
        };
        // SAFETY: `sock_fd` is the caller-owned socket descriptor;
        // `data[sent..].as_ptr()` points to `remaining == data.len() - sent`
        // readable bytes (the unsent tail of `data`, with `sent < data.len()`
        // per the loop guard); `flags` are valid `MSG_*` bits. The return value
        // is checked below.
        let ret = unsafe {
            libc::send(
                sock_fd,
                data[sent..].as_ptr() as *const libc::c_void,
                remaining,
                flags,
            )
        };
        if ret > 0 {
            sent += ret as usize;
        } else if ret == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "socket closed"));
        } else {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
    }
    Ok(())
}

// =========================================================================================
//                                     KtlsPipe
// =========================================================================================

/// The I/O mode used by `KtlsPipe` for the write path and sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeMode {
    /// Classic `SSL_write()` / `SSL_read()` – always works, 1 copy per syscall.
    Classic,
    /// `vmsplice` + `splice` for writes, `splice`-to-/dev/null for sink – zero copies.
    Splice,
    /// `io_uring` batched sends for writes, `splice`-to-/dev/null for sink.
    IoUring,
}

/// Statistics returned when the pipe is shut down.
pub struct KtlsPipeStats {
    pub bytes_written: u64,
    pub bytes_drained: u64,
    pub handshake_ms: f64,
}

/// A single kTLS-encrypted loopback lane with a background sink thread.
///
/// This is the per-lane implementation used by `KtlsPipe` when multiple
/// parallel sender threads are enabled.
struct KtlsPipeLane {
    /// The TLS session – used for handshake and probe; not for data writes.
    session: KtlsSession,
    /// Raw socket fd (extracted from session after handshake).
    sock_fd: RawFd,
    /// Active mode.
    mode: PipeMode,
    /// vmsplice/splice pipe fds (read_fd, write_fd). Only set in Splice mode.
    splice_pipe: Option<(RawFd, RawFd)>,
    /// io_uring sender. Only set in IoUring mode.
    uring_sender: Option<IoUringSender>,
    /// Async writer channel: send filled buffers to the background writer thread.
    async_tx: Option<mpsc::SyncSender<Vec<u8>>>,
    /// Background writer thread handle.
    writer_handle: Option<JoinHandle<()>>,
    /// Internal write buffer for batching small writes.
    write_buf: Vec<u8>,
    /// Flush threshold – when `write_buf` reaches this size, flush it.
    flush_threshold: usize,
    bytes_written: u64,
    _tcp_stream: TcpStream, // keep alive
    sink_handle: Option<JoinHandle<u64>>,
    sink_stop: Arc<AtomicBool>,
    handshake_ms: f64,
    /// Shared flag checked by the writer thread each batch to toggle TCP_CORK.
    cork_enabled: Arc<AtomicBool>,
}

impl KtlsPipeLane {
    /// Create a new kTLS pipe with the best available I/O mode.
    ///
    /// Uses Classic mode with internal write buffering (1 MiB batches).
    /// This gives maximum throughput because:
    /// - Small writes are batched (128B × ~8000 → 1 MiB SSL_write)
    /// - kTLS TX is handled by the kernel (AES-NI accelerated)
    /// - No splice/io_uring blocking that could stall the caller
    ///
    /// Use `with_mode()` to explicitly select Splice or IoUring mode if desired.
    fn new(mode: PipeMode) -> Result<Self, Box<dyn std::error::Error>> {
        let acceptor = build_server_acceptor(None)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let local_addr = listener.local_addr()?;

        let sink_stop = Arc::new(AtomicBool::new(false));
        let stop_clone = sink_stop.clone();

        let use_splice_sink = mode != PipeMode::Classic;

        // Sink thread: accepts, does TLS handshake (server side), drains data.
        let sink_handle = std::thread::spawn(move || -> u64 {
            let (stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("kTLS sink: accept failed: {}", e);
                    return 0;
                }
            };
            let fd = stream.as_raw_fd();
            tune_socket_buffers(fd);
            set_nodelay(fd, true);

            let mut ssl = match Ssl::new(acceptor.context()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("kTLS sink: SSL_new failed: {}", e);
                    return 0;
                }
            };
            ssl.set_accept_state();
            // SAFETY: `ssl.as_ptr()` is the valid, non-null `SSL*` owned by the
            // live `ssl` on the stack, so it outlives this call and is not
            // concurrently mutated; this satisfies `enable_ktls_ssl`'s contract.
            unsafe {
                enable_ktls_ssl(ssl.as_ptr());
            }

            let mut session = match KtlsSession::new(ssl, fd as libc::c_int) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("kTLS sink: KtlsSession::new failed: {}", e);
                    return 0;
                }
            };
            if let Err(e) = session.accept() {
                eprintln!("kTLS sink: TLS accept failed: {}", e);
                return 0;
            }
            // SAFETY: `session.ssl_ref().as_ptr()` is the valid, non-null `SSL*`
            // owned by the live `session`; the handshake has completed and the
            // session is not used concurrently, so re-asserting the kTLS option
            // here satisfies `enable_ktls_ssl`'s contract.
            unsafe {
                enable_ktls_ssl(session.ssl_ref().as_ptr());
            }

            if use_splice_sink {
                // Try splice-to-/dev/null first (zero-copy drain).
                let total = splice_sink_loop(fd, &stop_clone);
                if total > 0 {
                    return total;
                }
                // Splice didn't work for reading (kTLS RX offload may not be active);
                // fall through to raw recv drain.
                eprintln!("kTLS sink: splice drain returned 0, falling back to recv()");
            }

            recv_sink_loop(fd, &stop_clone)
        });

        // Client side: connect + TLS handshake
        let stream = TcpStream::connect(local_addr)?;
        let client_fd = stream.as_raw_fd();
        tune_socket_buffers(client_fd);
        set_nodelay(client_fd, true);

        let connector = build_client_connector(None)?;
        let mut ssl = connector.configure()?.into_ssl("localhost")?;
        ssl.set_connect_state();
        // SAFETY: `ssl.as_ptr()` is the valid, non-null `SSL*` owned by the live
        // `ssl` on the stack, so it outlives this call and is not concurrently
        // mutated; this satisfies `enable_ktls_ssl`'s contract.
        unsafe {
            enable_ktls_ssl(ssl.as_ptr());
        }

        let mut session = KtlsSession::new(ssl, client_fd as libc::c_int)?;
        let hs_start = Instant::now();
        session.connect()?;
        let handshake_ms = hs_start.elapsed().as_secs_f64() * 1000.0;

        // SAFETY: `session.ssl_ref().as_ptr()` is the valid, non-null `SSL*`
        // owned by the live `session`; the handshake has completed and the
        // session is not used concurrently, so re-asserting the kTLS option here
        // satisfies `enable_ktls_ssl`'s contract.
        unsafe {
            enable_ktls_ssl(session.ssl_ref().as_ptr());
        }

        // Verify kTLS is active
        let tls_before = get_tls_stat_total().ok();
        // Write a small probe to trigger kTLS activation
        session.write_all(b"k")?;
        let tls_after = get_tls_stat_total().ok();

        let ulp = get_tcp_ulp(&stream).unwrap_or_default();
        let ktls_active = ulp.starts_with("tls")
            || match (tls_before, tls_after) {
                (Some(before), Some(after)) => after > before,
                _ => false,
            };

        if !ktls_active {
            let ssl_ref = session.ssl_ref();
            let cipher = ssl_ref
                .current_cipher()
                .map(|c| c.name())
                .unwrap_or("<none>");
            let version = ssl_ref.version_str();
            return Err(format!(
                "kTLS not enabled (TCP_ULP={}, TLS={}, cipher={}).{}",
                if ulp.is_empty() { "<empty>" } else { &ulp },
                version,
                cipher,
                ktls_privilege_hint()
            )
            .into());
        }

        // Set up the write-side infrastructure based on mode.
        let sock_fd = client_fd;
        let mut splice_pipe = None;
        let mut uring_sender = None;

        match mode {
            PipeMode::Splice => {
                let (rd, wr) = make_pipe()?;
                splice_pipe = Some((rd, wr));
            }
            PipeMode::IoUring => match IoUringSender::new(sock_fd) {
                Ok(sender) => uring_sender = Some(sender),
                Err(e) => {
                    return Err(format!("io_uring init failed: {}", e).into());
                }
            },
            PipeMode::Classic => {}
        }

        eprintln!(
            "kTLS pipe established (mode={:?}, handshake {:.2} ms, cipher={}, sock_bufs={}K)",
            mode,
            handshake_ms,
            session
                .ssl_ref()
                .current_cipher()
                .map(|c| c.name())
                .unwrap_or("?"),
            SOCK_BUF_SIZE / 1024,
        );

        // Probe: verify the chosen write path actually works by sending a small test payload.
        let probe_data = [0xABu8; 64];
        let probe_result = match mode {
            PipeMode::Classic => session.write_all(&probe_data).map(|_| 64usize),
            PipeMode::Splice => {
                let (rd, wr) = splice_pipe.unwrap();
                write_splice(wr, rd, sock_fd, &probe_data)
            }
            PipeMode::IoUring => {
                if let Some(ref mut sender) = uring_sender {
                    sender.send_all(&probe_data)
                } else {
                    Err(io::Error::other("no sender"))
                }
            }
        };
        match probe_result {
            Ok(n) if n > 0 => {
                eprintln!(
                    "kTLS pipe: {:?} write path verified ({} bytes probe)",
                    mode, n
                );
            }
            Ok(_) => {
                return Err(format!("kTLS pipe: {:?} write path probe sent 0 bytes", mode).into());
            }
            Err(e) => {
                return Err(format!("kTLS pipe: {:?} write path probe failed: {}", mode, e).into());
            }
        }

        // Spawn async writer thread. With kTLS TX active, raw send() on the
        // socket fd goes through the kernel's TLS encryption transparently.
        let cork_enabled = Arc::new(AtomicBool::new(false));
        let cork_clone = cork_enabled.clone();
        let (async_tx, async_rx) = mpsc::sync_channel::<Vec<u8>>(ASYNC_CHANNEL_DEPTH);
        let writer_fd = sock_fd;
        let writer_mode = mode;
        let writer_handle = std::thread::Builder::new()
            .name("ktls-writer".into())
            .spawn(move || writer_thread_loop(async_rx, writer_fd, writer_mode, cork_clone))?;

        // Use a 1 MiB write buffer for batching small writes.
        let flush_threshold = SPLICE_CHUNK;
        Ok(Self {
            session,
            sock_fd,
            mode,
            splice_pipe,
            uring_sender,
            async_tx: Some(async_tx),
            writer_handle: Some(writer_handle),
            write_buf: Vec::with_capacity(flush_threshold),
            flush_threshold,
            bytes_written: 0,
            _tcp_stream: stream,
            sink_handle: Some(sink_handle),
            sink_stop,
            handshake_ms,
            cork_enabled,
        })
    }

    /// Create a new kTLS pipe lane that connects to a remote TLS receiver.
    /// No local sink thread is spawned — data goes over the network to the receiver.
    fn new_remote(mode: PipeMode, addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(addr)?;
        let client_fd = stream.as_raw_fd();
        tune_socket_buffers(client_fd);
        set_nodelay(client_fd, true);

        let connector = build_client_connector(None)?;
        let mut ssl = connector.configure()?.into_ssl("benchmark")?;
        ssl.set_connect_state();
        // SAFETY: `ssl.as_ptr()` is the valid, non-null `SSL*` owned by the live
        // `ssl` on the stack, so it outlives this call and is not concurrently
        // mutated; this satisfies `enable_ktls_ssl`'s contract.
        unsafe {
            enable_ktls_ssl(ssl.as_ptr());
        }

        let mut session = KtlsSession::new(ssl, client_fd as libc::c_int)?;
        let hs_start = Instant::now();
        session.connect()?;
        let handshake_ms = hs_start.elapsed().as_secs_f64() * 1000.0;

        // SAFETY: `session.ssl_ref().as_ptr()` is the valid, non-null `SSL*`
        // owned by the live `session`; the handshake has completed and the
        // session is not used concurrently, so re-asserting the kTLS option here
        // satisfies `enable_ktls_ssl`'s contract.
        unsafe {
            enable_ktls_ssl(session.ssl_ref().as_ptr());
        }

        // Verify kTLS is active using TCP_ULP and /proc/net/tls_stat.
        // NOTE: We must NOT write any probe bytes here like in local mode,
        // because the remote receiver expects a structured protocol header as
        // the first data on the TLS stream. Any stray bytes would corrupt the
        // header and cause "Bad magic" errors.
        let ulp = get_tcp_ulp(&stream).unwrap_or_default();
        let tls_stat_active = match get_tls_stat_total().ok() {
            Some(total) => total > 0,
            None => false,
        };
        let ktls_active = ulp.starts_with("tls") || tls_stat_active;

        if !ktls_active {
            let ssl_ref = session.ssl_ref();
            let cipher = ssl_ref
                .current_cipher()
                .map(|c| c.name())
                .unwrap_or("<none>");
            let version = ssl_ref.version_str();
            return Err(format!(
                "kTLS not enabled on remote connection (TCP_ULP={}, TLS={}, cipher={}).{}",
                if ulp.is_empty() { "<empty>" } else { &ulp },
                version,
                cipher,
                ktls_privilege_hint()
            )
            .into());
        }

        let sock_fd = client_fd;
        let mut splice_pipe = None;
        let mut uring_sender = None;

        match mode {
            PipeMode::Splice => {
                let (rd, wr) = make_pipe()?;
                splice_pipe = Some((rd, wr));
            }
            PipeMode::IoUring => match IoUringSender::new(sock_fd) {
                Ok(sender) => uring_sender = Some(sender),
                Err(e) => {
                    return Err(format!("io_uring init failed: {}", e).into());
                }
            },
            PipeMode::Classic => {}
        }

        eprintln!(
            "kTLS pipe (remote → {}) established (mode={:?}, handshake {:.2} ms, cipher={})",
            addr,
            mode,
            handshake_ms,
            session
                .ssl_ref()
                .current_cipher()
                .map(|c| c.name())
                .unwrap_or("?"),
        );

        let cork_enabled = Arc::new(AtomicBool::new(false));
        let cork_clone = cork_enabled.clone();
        let (async_tx, async_rx) = mpsc::sync_channel::<Vec<u8>>(ASYNC_CHANNEL_DEPTH);
        let writer_fd = sock_fd;
        let writer_mode = mode;
        let writer_handle = std::thread::Builder::new()
            .name("ktls-remote-writer".into())
            .spawn(move || writer_thread_loop(async_rx, writer_fd, writer_mode, cork_clone))?;

        let flush_threshold = SPLICE_CHUNK;
        let sink_stop = Arc::new(AtomicBool::new(false));

        Ok(Self {
            session,
            sock_fd,
            mode,
            splice_pipe,
            uring_sender,
            async_tx: Some(async_tx),
            writer_handle: Some(writer_handle),
            write_buf: Vec::with_capacity(flush_threshold),
            flush_threshold,
            bytes_written: 0,
            _tcp_stream: stream,
            sink_handle: None, // No local sink for remote mode
            sink_stop,
            handshake_ms,
            cork_enabled,
        })
    }

    /// Write data through the kTLS pipe using the configured mode.
    ///
    /// Small writes are batched internally and flushed when the buffer
    /// reaches 1 MiB, amortizing syscall/splice overhead. Writes larger
    /// than the flush threshold bypass the buffer entirely.
    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.bytes_written += data.len() as u64;

        // Large writes: flush any pending buffer, then send directly.
        if data.len() >= self.flush_threshold {
            if !self.write_buf.is_empty() {
                self.flush_write_buf()?;
            }
            return self.send_raw(data);
        }

        // Small writes: accumulate in the buffer.
        self.write_buf.extend_from_slice(data);
        if self.write_buf.len() >= self.flush_threshold {
            self.flush_write_buf()?;
        }
        Ok(())
    }

    fn send_blocking(&mut self, data: &[u8]) -> io::Result<()> {
        match self.mode {
            PipeMode::Classic => send_blocking_sys(self.sock_fd, data),
            PipeMode::Splice => {
                if self.splice_pipe.is_none() {
                    let (rd, wr) = make_pipe()?;
                    self.splice_pipe = Some((rd, wr));
                }
                let (rd, wr) = self.splice_pipe.unwrap();
                let _ = write_splice(wr, rd, self.sock_fd, data)?;
                Ok(())
            }
            PipeMode::IoUring => {
                if self.uring_sender.is_none() {
                    self.uring_sender = Some(IoUringSender::new(self.sock_fd)?);
                }
                let sender = self.uring_sender.as_mut().unwrap();
                let _ = sender.send_all(data)?;
                Ok(())
            }
        }
    }

    fn flush_blocking(&mut self) -> io::Result<()> {
        if self.write_buf.is_empty() {
            return Ok(());
        }
        let buf = std::mem::replace(
            &mut self.write_buf,
            Vec::with_capacity(self.flush_threshold),
        );
        if buf.is_empty() {
            return Ok(());
        }
        self.send_blocking(&buf)
    }

    pub fn write_all_blocking(&mut self, data: &[u8]) -> io::Result<()> {
        self.bytes_written += data.len() as u64;
        self.flush_blocking()?;
        self.send_blocking(data)
    }

    /// Flush the internal write buffer through the configured I/O path.
    pub fn flush(&mut self) -> io::Result<()> {
        if !self.write_buf.is_empty() {
            self.flush_write_buf()?;
        }
        Ok(())
    }

    /// Internal: flush the write buffer by sending it to the async writer thread.
    fn flush_write_buf(&mut self) -> io::Result<()> {
        let buf = std::mem::replace(
            &mut self.write_buf,
            Vec::with_capacity(self.flush_threshold),
        );
        if buf.is_empty() {
            return Ok(());
        }
        self.send_async(buf)
    }

    /// Internal: send a buffer to the async writer thread via channel.
    fn send_async(&mut self, data: Vec<u8>) -> io::Result<()> {
        if let Some(ref tx) = self.async_tx {
            tx.send(data).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "kTLS async writer thread gone")
            })
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no async writer",
            ))
        }
    }

    /// Internal: send data directly (for large writes that bypass the buffer).
    fn send_raw(&mut self, data: &[u8]) -> io::Result<()> {
        // For large writes, send via the async channel too.
        self.send_async(data.to_vec())
    }

    /// Write data using splice zero-copy path explicitly.
    pub fn write_all_splice(&mut self, data: &[u8]) -> io::Result<()> {
        if self.splice_pipe.is_none() {
            let (rd, wr) = make_pipe()?;
            self.splice_pipe = Some((rd, wr));
        }
        let (rd, wr) = self.splice_pipe.unwrap();
        let written = write_splice(wr, rd, self.sock_fd, data)?;
        self.bytes_written += written as u64;
        Ok(())
    }

    /// Write data using io_uring path explicitly.
    pub fn write_all_uring(&mut self, data: &[u8]) -> io::Result<()> {
        if self.uring_sender.is_none() {
            self.uring_sender = Some(IoUringSender::new(self.sock_fd)?);
        }
        let sender = self.uring_sender.as_mut().unwrap();
        let written = sender.send_all(data)?;
        self.bytes_written += written as u64;
        Ok(())
    }

    /// Total bytes written to the kTLS session so far.
    #[allow(dead_code)]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Reset the byte counter (e.g. between payload-size runs).
    pub fn reset_bytes(&mut self) {
        let _ = self.flush();
        self.bytes_written = 0;
    }

    /// Get the active pipe mode.
    #[allow(dead_code)]
    pub fn mode(&self) -> PipeMode {
        self.mode
    }

    /// Shut down the TLS session and wait for the sink thread.
    pub fn shutdown(mut self) -> KtlsPipeStats {
        // Flush any remaining buffered data.
        let _ = self.flush();

        // Drop the async writer channel to signal the writer thread to finish,
        // then wait for it to drain all queued buffers.
        self.async_tx.take();
        if let Some(handle) = self.writer_handle.take() {
            let _ = handle.join();
        }

        // Close splice pipe write-end first so the sink sees EOF via splice.
        if let Some((rd, wr)) = self.splice_pipe.take() {
            close_fd(wr);
            close_fd(rd);
        }
        // Drop the io_uring sender before shutdown to flush pending ops.
        self.uring_sender.take();

        self.session.shutdown();
        self.sink_stop.store(true, Ordering::Relaxed);

        let bytes_drained = if let Some(handle) = self.sink_handle.take() {
            handle.join().unwrap_or(0)
        } else {
            0
        };

        KtlsPipeStats {
            bytes_written: self.bytes_written,
            bytes_drained,
            handshake_ms: self.handshake_ms,
        }
    }

    /// Get handshake time.
    #[allow(dead_code)]
    pub fn handshake_ms(&self) -> f64 {
        self.handshake_ms
    }
}

impl Drop for KtlsPipeLane {
    fn drop(&mut self) {
        if let Some((rd, wr)) = self.splice_pipe.take() {
            close_fd(wr);
            close_fd(rd);
        }
    }
}

/// A kTLS-encrypted pipe over TCP loopback with one or more parallel lanes.
///
/// Each lane owns its own loopback kTLS connection and background writer thread.
/// Writes are sharded round-robin across lanes to increase throughput on
/// multi-core systems.
pub struct KtlsPipe {
    lanes: Vec<KtlsPipeLane>,
    next_lane: usize,
    mode: PipeMode,
    remote_target: Option<String>,
}

impl KtlsPipe {
    /// Create a new kTLS pipe with the best available I/O mode (single lane).
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let lanes = default_lane_count();
        Self::with_mode_and_threads(PipeMode::IoUring, lanes)
    }

    /// Create a new kTLS pipe with a specific I/O mode (single lane).
    pub fn with_mode(mode: PipeMode) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_mode_and_threads(mode, 1)
    }

    /// Create a new kTLS pipe with a specific number of parallel lanes.
    pub fn with_threads(threads: usize) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_mode_and_threads(PipeMode::Classic, threads)
    }

    /// Create a new kTLS pipe with mode + number of parallel lanes.
    pub fn with_mode_and_threads(
        mode: PipeMode,
        threads: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let lane_count = threads.max(1);
        let build = |mode| -> Result<Self, Box<dyn std::error::Error>> {
            let mut lanes = Vec::with_capacity(lane_count);
            for _ in 0..lane_count {
                lanes.push(KtlsPipeLane::new(mode)?);
            }
            Ok(Self {
                lanes,
                next_lane: 0,
                mode,
                remote_target: None,
            })
        };

        if mode == PipeMode::IoUring {
            match build(PipeMode::IoUring) {
                Ok(pipe) => Ok(pipe),
                Err(err) => {
                    eprintln!(
                        "kTLS pipe: io_uring unavailable ({}), falling back to Classic",
                        err
                    );
                    build(PipeMode::Classic)
                }
            }
        } else {
            build(mode)
        }
    }

    /// Create a new kTLS pipe that connects to a remote TLS receiver.
    /// No local sink thread is spawned — data is sent over the network.
    pub fn with_remote_target(
        addr: &str,
        mode: PipeMode,
        threads: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let lane_count = threads.max(1);
        let build = |mode| -> Result<Self, Box<dyn std::error::Error>> {
            let mut lanes = Vec::with_capacity(lane_count);
            for _ in 0..lane_count {
                lanes.push(KtlsPipeLane::new_remote(mode, addr)?);
            }
            Ok(Self {
                lanes,
                next_lane: 0,
                mode,
                remote_target: Some(addr.to_string()),
            })
        };

        if mode == PipeMode::IoUring {
            match build(PipeMode::IoUring) {
                Ok(pipe) => Ok(pipe),
                Err(err) => {
                    eprintln!(
                        "kTLS pipe (remote): io_uring unavailable ({}), falling back to Classic",
                        err
                    );
                    build(PipeMode::Classic)
                }
            }
        } else {
            build(mode)
        }
    }

    /// Send a 16-byte protocol header through the first lane.
    /// Used by container mode to signal payload_size to the receiver.
    pub fn send_header(&mut self, payload_size: u32, flags: u32) -> io::Result<()> {
        let hdr = build_protocol_header(payload_size, flags);
        // Send through first lane only, blocking.
        if self.lanes.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "no lanes"));
        }
        self.lanes[0].send_blocking(&hdr)
    }

    /// Whether this pipe connects to a remote target.
    pub fn is_remote(&self) -> bool {
        self.remote_target.is_some()
    }

    fn pick_lane_mut(&mut self) -> &mut KtlsPipeLane {
        let idx = self.next_lane % self.lanes.len();
        self.next_lane = (self.next_lane + 1) % self.lanes.len();
        &mut self.lanes[idx]
    }

    /// Write data through the kTLS pipe using the configured mode.
    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.pick_lane_mut().write_all(data)
    }

    pub fn write_all_blocking(&mut self, data: &[u8]) -> io::Result<()> {
        self.pick_lane_mut().write_all_blocking(data)
    }

    /// Flush buffered data on all lanes.
    pub fn flush(&mut self) -> io::Result<()> {
        for lane in &mut self.lanes {
            lane.flush()?;
        }
        Ok(())
    }

    /// Write data using splice zero-copy path explicitly.
    pub fn write_all_splice(&mut self, data: &[u8]) -> io::Result<()> {
        self.pick_lane_mut().write_all_splice(data)
    }

    /// Write data using io_uring path explicitly.
    pub fn write_all_uring(&mut self, data: &[u8]) -> io::Result<()> {
        self.pick_lane_mut().write_all_uring(data)
    }

    /// Total bytes written to the kTLS sessions so far.
    pub fn bytes_written(&self) -> u64 {
        self.lanes.iter().map(|lane| lane.bytes_written).sum()
    }

    /// Reset the byte counters (e.g. between payload-size runs).
    pub fn reset_bytes(&mut self) {
        for lane in &mut self.lanes {
            lane.reset_bytes();
        }
    }

    /// Get the active pipe mode.
    pub fn mode(&self) -> PipeMode {
        self.mode
    }

    /// Shut down all lanes and wait for sink threads to finish.
    pub fn shutdown(mut self) -> KtlsPipeStats {
        let mut bytes_written = 0u64;
        let mut bytes_drained = 0u64;
        let mut handshake_ms: f64 = 0.0;
        for lane in self.lanes.drain(..) {
            let stats = lane.shutdown();
            bytes_written = bytes_written.saturating_add(stats.bytes_written);
            bytes_drained = bytes_drained.saturating_add(stats.bytes_drained);
            handshake_ms = handshake_ms.max(stats.handshake_ms);
        }
        KtlsPipeStats {
            bytes_written,
            bytes_drained,
            handshake_ms,
        }
    }

    /// Get the slowest handshake time across lanes.
    pub fn handshake_ms(&self) -> f64 {
        self.lanes
            .iter()
            .map(|lane| lane.handshake_ms)
            .fold(0.0, f64::max)
    }

    /// Enable or disable TCP_CORK on all lanes' writer threads.
    /// When enabled, each batch write is corked (coalescing small TLS records
    /// into full TCP segments) and uncorked after, improving throughput for
    /// small-to-medium payloads without affecting per-message latency.
    pub fn set_tcp_cork(&self, on: bool) {
        for lane in &self.lanes {
            lane.cork_enabled.store(on, Ordering::Relaxed);
        }
    }
}

fn default_lane_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
}

// =========================================================================================
//                                  Reporting helpers
// =========================================================================================

/// Print a dual-throughput header for IPC + kTLS benchmarks.
pub fn print_ktls_header(name: &str) {
    println!("\n=== BENCHMARK: {} (with kTLS pipe) ===", name);
    println!(
        "{:<12} | {:<15} | {:<15} | {:<15} | {:<10}",
        "Payload Size", "IPC Tput", "kTLS Tput", "Overhead", "Status"
    );
    println!(
        "{:-<12}-+-{:-<15}-+-{:-<15}-+-{:-<15}-+-{:-<10}",
        "", "", "", "", ""
    );
}

/// Print a dual-throughput result row.
pub fn print_ktls_result(
    payload_size: usize,
    ipc_payload_bps: f64,
    ipc_overhead_bps: f64,
    ktls_bps: f64,
) {
    let ipc_total = ipc_payload_bps + ipc_overhead_bps;
    let ipc_gib_s = ipc_total / 1024.0 / 1024.0 / 1024.0;
    let ktls_gib_s = ktls_bps / 1024.0 / 1024.0 / 1024.0;

    let overhead_pct = if ipc_total > 0.0 {
        (ipc_overhead_bps / ipc_total) * 100.0
    } else {
        0.0
    };

    println!(
        "{:<12} | {:>10.2} GiB/s | {:>10.2} GiB/s | {:>8.2} %      | Completed",
        format_size(payload_size),
        ipc_gib_s,
        ktls_gib_s,
        overhead_pct,
    );
}

pub fn format_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{} MB", bytes / 1024 / 1024)
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} B", bytes)
    }
}

// =========================================================================================
//                          Container protocol header
// =========================================================================================

/// Protocol magic: "BNCH" in LE.
const PROTOCOL_MAGIC: u32 = 0x48_43_4E_42;

/// Build a 16-byte protocol header for container-mode TLS connections.
/// Format: [MAGIC:u32][payload_size:u32][flags:u32][reserved:u32]
pub fn build_protocol_header(payload_size: u32, flags: u32) -> [u8; 16] {
    let mut hdr = [0u8; 16];
    hdr[0..4].copy_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
    hdr[4..8].copy_from_slice(&payload_size.to_le_bytes());
    hdr[8..12].copy_from_slice(&flags.to_le_bytes());
    hdr
}
