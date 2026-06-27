//! Shared userspace TLS pipe: sets up a TLS-encrypted TCP loopback connection
//! using OpenSSL in userspace (no kTLS kernel offload) and provides a simple
//! write interface. A background sink thread drains the encrypted data on the
//! receiver side using SSL_read.
//!
//! This is the userspace counterpart to `ktls_pipe`. All encryption and
//! decryption happens in userspace via OpenSSL, which allows comparison of
//! userspace TLS overhead against kernel TLS (kTLS).
//!
//! Usage:
//! ```no_run
//! let mut pipe = tls_pipe::TlsPipe::new().expect("TLS setup failed");
//! pipe.write_all(b"hello world").unwrap();
//! let stats = pipe.shutdown();
//! println!("TLS bytes written: {}", stats.bytes_written);
//! ```

use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{
    SslAcceptor, SslConnector, SslContextBuilder, SslMethod, SslOptions, SslStream, SslVerifyMode,
    SslVersion,
};
use openssl::x509::X509;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Instant;

// =========================================================================================
//                                     CONSTANTS
// =========================================================================================

/// Socket buffer sizes for high-throughput loopback (16 MiB each direction).
const SOCK_BUF_SIZE: libc::c_int = 16 * 1024 * 1024;

/// Sink thread drain buffer (8 MiB).
const SINK_BUF_SIZE: usize = 8 * 1024 * 1024;

/// Async writer channel depth: number of 4 MiB buffers that can be queued.
/// With 64 slots × 4 MiB = 256 MiB max outstanding. Provides back-pressure when full.
const ASYNC_CHANNEL_DEPTH: usize = 64;

/// Write buffer flush threshold (4 MiB) – batches small writes for efficiency.
const FLUSH_THRESHOLD: usize = 4 * 1024 * 1024;

// =========================================================================================
//                             Cached TLS certificate (OnceLock)
// =========================================================================================

type CachedCert = (PKey<openssl::pkey::Private>, X509);

/// Process-wide cached self-signed certificate to avoid regenerating RSA-2048 keys
/// for every `TlsPipe::new()` call.
static CACHED_CERT: OnceLock<CachedCert> = OnceLock::new();

fn get_or_init_cert() -> Result<&'static CachedCert, openssl::error::ErrorStack> {
    if let Some(cached) = CACHED_CERT.get() {
        return Ok(cached);
    }
    let cert = build_self_signed_cert()?;
    let _ = CACHED_CERT.set(cert);
    Ok(CACHED_CERT.get().unwrap())
}

// =========================================================================================
//                                TLS / helpers
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

/// Resolve the TLS protocol version for benchmarks from the
/// `SCG_BENCH_TLS_VERSION` environment variable (default: TLS 1.2).
fn bench_tls_version() -> SslVersion {
    let raw = std::env::var("SCG_BENCH_TLS_VERSION").unwrap_or_default();
    let v = raw.trim().to_ascii_lowercase();
    let v = v.trim_start_matches("tls").trim_start_matches('v');
    match v {
        "" | "1.2" | "1-2" | "1_2" | "12" => SslVersion::TLS1_2,
        "1.3" | "1-3" | "1_3" | "13" => SslVersion::TLS1_3,
        other => {
            eprintln!(
                "[tls] WARNING: unknown TLS version '{}', using TLS 1.2",
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
/// without recompiling.
///
/// Cipher values (case-insensitive, `-`/`_` interchangeable):
///   * `aes128-gcm` (default), `aes256-gcm` (BSI + NIST), `chacha20-poly1305` (BSI)
fn configure_bench_crypto(
    builder: &mut SslContextBuilder,
) -> Result<(), openssl::error::ErrorStack> {
    let ver = bench_tls_version();
    builder.set_min_proto_version(Some(ver))?;
    builder.set_max_proto_version(Some(ver))?;

    let raw = std::env::var("SCG_BENCH_CIPHER").unwrap_or_default();
    let cipher = raw.trim().to_ascii_lowercase().replace('_', "-");

    if ver == SslVersion::TLS1_3 {
        // `mozilla_intermediate()` disables TLS 1.3 via SSL_OP_NO_TLSv1_3; undo that
        // so the requested TLS 1.3 version is actually negotiable.
        builder.clear_options(SslOptions::NO_TLSV1_3);
        let suite = match cipher.as_str() {
            "" | "aes128-gcm" | "aes-128-gcm" => "TLS_AES_128_GCM_SHA256",
            "aes256-gcm" | "aes-256-gcm" => "TLS_AES_256_GCM_SHA384",
            "chacha20-poly1305" | "chacha20" | "chacha" => "TLS_CHACHA20_POLY1305_SHA256",
            other => {
                eprintln!(
                    "[tls] WARNING: unknown SCG_BENCH_CIPHER='{}', using TLS_AES_128_GCM_SHA256",
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
                    "[tls] WARNING: unknown SCG_BENCH_CIPHER='{}', using AES128-GCM-SHA256",
                    other
                );
                "AES128-GCM-SHA256"
            }
        };
        builder.set_cipher_list(list)?;
    }
    Ok(())
}

fn build_server_acceptor() -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let (pkey, cert) = get_or_init_cert()?;
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_private_key(pkey)?;
    builder.set_certificate(cert)?;
    builder.check_private_key()?;
    // No kTLS: we intentionally do NOT set SSL_OP_ENABLE_KTLS
    configure_bench_crypto(&mut builder)?;
    Ok(builder.build())
}

fn build_client_connector() -> Result<SslConnector, openssl::error::ErrorStack> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_verify(SslVerifyMode::NONE);
    // No kTLS: we intentionally do NOT set SSL_OP_ENABLE_KTLS
    configure_bench_crypto(&mut builder)?;
    Ok(builder.build())
}

// =========================================================================================
//                              Socket helpers
// =========================================================================================

/// Set send/receive buffer sizes on a TCP socket to `SOCK_BUF_SIZE`.
fn tune_socket_buffers(fd: RawFd) {
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

// =========================================================================================
//                          Sink thread: SSL_read drain loop
// =========================================================================================

/// Drain a TLS stream using SSL_read. Returns total plaintext bytes drained.
fn ssl_read_sink_loop(mut stream: SslStream<TcpStream>, stop: &AtomicBool) -> u64 {
    let mut buf = vec![0u8; SINK_BUF_SIZE];
    let mut total: u64 = 0;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break, // EOF
            Ok(n) => {
                total += n as u64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    total
}

// =========================================================================================
//                          Async background writer thread
// =========================================================================================

/// Background writer thread that receives filled buffers over a channel and
/// sends them through the TLS stream using SSL_write. OpenSSL performs the
/// encryption in userspace.
///
/// When `cork` is enabled, TCP_CORK is set before each batch write and cleared
/// after, coalescing small TLS records into full TCP segments for higher throughput.
fn writer_thread_loop(
    rx: mpsc::Receiver<Vec<u8>>,
    stream: Arc<Mutex<SslStream<TcpStream>>>,
    cork: Arc<AtomicBool>,
) {
    let fd = {
        let s = stream.lock().unwrap();
        s.get_ref().as_raw_fd()
    };
    while let Ok(buf) = rx.recv() {
        let use_cork = cork.load(Ordering::Relaxed);
        if use_cork {
            set_tcp_cork(fd, true);
        }
        let mut sent = 0usize;
        let mut guard = stream.lock().unwrap();
        while sent < buf.len() {
            match guard.write(&buf[sent..]) {
                Ok(n) => sent += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    eprintln!("TLS async writer: SSL_write error: {}", e);
                    drop(guard);
                    return;
                }
            }
        }
        drop(guard);
        if use_cork {
            set_tcp_cork(fd, false);
        }
    }
    // Channel closed — sender dropped, flush and we're done.
    let mut guard = stream.lock().unwrap();
    let _ = guard.shutdown();
}

// =========================================================================================
//                                     TlsPipe
// =========================================================================================

/// Statistics returned when the pipe is shut down.
pub struct TlsPipeStats {
    pub bytes_written: u64,
    pub bytes_drained: u64,
    pub handshake_ms: f64,
}

/// A single userspace-TLS loopback lane with a background sink thread.
struct TlsPipeLane {
    /// Async writer channel: send filled buffers to the background writer thread.
    async_tx: Option<mpsc::SyncSender<Vec<u8>>>,
    /// Background writer thread handle.
    writer_handle: Option<JoinHandle<()>>,
    /// Internal write buffer for batching small writes.
    write_buf: Vec<u8>,
    /// Flush threshold – when `write_buf` reaches this size, flush it.
    flush_threshold: usize,
    bytes_written: u64,
    _tcp_stream: TcpStream, // keep client TCP stream alive
    sink_handle: Option<JoinHandle<u64>>,
    sink_stop: Arc<AtomicBool>,
    handshake_ms: f64,
    /// Shared flag checked by the writer thread each batch to toggle TCP_CORK.
    cork_enabled: Arc<AtomicBool>,
    /// Shared SslStream for synchronous blocking writes (latency measurement).
    blocking_stream: Arc<Mutex<SslStream<TcpStream>>>,
}

impl TlsPipeLane {
    /// Create a new userspace TLS pipe lane.
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let acceptor = build_server_acceptor()?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let local_addr = listener.local_addr()?;

        let sink_stop = Arc::new(AtomicBool::new(false));
        let stop_clone = sink_stop.clone();

        // Sink thread: accepts, does TLS handshake (server side), drains data via SSL_read.
        let sink_handle = std::thread::spawn(move || -> u64 {
            let (stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("TLS sink: accept failed: {}", e);
                    return 0;
                }
            };
            let fd = stream.as_raw_fd();
            tune_socket_buffers(fd);
            set_nodelay(fd, true);

            let ssl_stream = match acceptor.accept(stream) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("TLS sink: TLS accept failed: {}", e);
                    return 0;
                }
            };

            ssl_read_sink_loop(ssl_stream, &stop_clone)
        });

        // Client side: connect + TLS handshake
        let stream = TcpStream::connect(local_addr)?;
        let client_fd = stream.as_raw_fd();
        tune_socket_buffers(client_fd);
        set_nodelay(client_fd, true);

        let connector = build_client_connector()?;
        let hs_start = Instant::now();
        let ssl_stream = connector.connect("localhost", stream.try_clone()?)?;
        let handshake_ms = hs_start.elapsed().as_secs_f64() * 1000.0;

        let cipher_name = ssl_stream
            .ssl()
            .current_cipher()
            .map(|c| c.name().to_string())
            .unwrap_or_else(|| "<none>".to_string());

        eprintln!(
            "TLS pipe established (userspace, handshake {:.2} ms, cipher={}, sock_bufs={}K)",
            handshake_ms,
            cipher_name,
            SOCK_BUF_SIZE / 1024,
        );

        // Spawn async writer thread that shares the SslStream via Arc<Mutex<>>.
        let cork_enabled = Arc::new(AtomicBool::new(false));
        let cork_clone = cork_enabled.clone();
        let ssl_stream = Arc::new(Mutex::new(ssl_stream));
        let ssl_stream_clone = ssl_stream.clone();
        let (async_tx, async_rx) = mpsc::sync_channel::<Vec<u8>>(ASYNC_CHANNEL_DEPTH);
        let writer_handle = std::thread::Builder::new()
            .name("tls-writer".into())
            .spawn(move || writer_thread_loop(async_rx, ssl_stream_clone, cork_clone))?;

        let flush_threshold = FLUSH_THRESHOLD;
        Ok(Self {
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
            blocking_stream: ssl_stream,
        })
    }

    /// Create a new userspace TLS pipe lane that connects to a remote TLS receiver.
    /// No local sink thread is spawned — data goes over the network to the receiver.
    fn new_remote(addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(addr)?;
        let client_fd = stream.as_raw_fd();
        tune_socket_buffers(client_fd);
        set_nodelay(client_fd, true);

        let connector = build_client_connector()?;
        let hs_start = Instant::now();
        let ssl_stream = connector.connect("benchmark", stream.try_clone()?)?;
        let handshake_ms = hs_start.elapsed().as_secs_f64() * 1000.0;

        let cipher_name = ssl_stream
            .ssl()
            .current_cipher()
            .map(|c| c.name().to_string())
            .unwrap_or_else(|| "<none>".to_string());

        eprintln!(
            "TLS pipe (remote → {}) established (userspace, handshake {:.2} ms, cipher={})",
            addr, handshake_ms, cipher_name,
        );

        let cork_enabled = Arc::new(AtomicBool::new(false));
        let cork_clone = cork_enabled.clone();
        let ssl_stream = Arc::new(Mutex::new(ssl_stream));
        let ssl_stream_clone = ssl_stream.clone();
        let (async_tx, async_rx) = mpsc::sync_channel::<Vec<u8>>(ASYNC_CHANNEL_DEPTH);
        let writer_handle = std::thread::Builder::new()
            .name("tls-remote-writer".into())
            .spawn(move || writer_thread_loop(async_rx, ssl_stream_clone, cork_clone))?;

        let flush_threshold = FLUSH_THRESHOLD;
        let sink_stop = Arc::new(AtomicBool::new(false));

        Ok(Self {
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
            blocking_stream: ssl_stream,
        })
    }

    /// Write data through the TLS pipe.
    ///
    /// Small writes are batched internally and flushed when the buffer
    /// reaches the flush threshold, amortizing SSL_write overhead.
    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.bytes_written += data.len() as u64;

        // Large writes: flush any pending buffer, then send directly.
        if data.len() >= self.flush_threshold {
            if !self.write_buf.is_empty() {
                self.flush_write_buf()?;
            }
            return self.send_async(data.to_vec());
        }

        // Small writes: accumulate in the buffer.
        self.write_buf.extend_from_slice(data);
        if self.write_buf.len() >= self.flush_threshold {
            self.flush_write_buf()?;
        }
        Ok(())
    }

    /// Write data synchronously (blocking) – bypasses the async channel and
    /// calls SSL_write directly on the caller's thread. This gives honest
    /// latency measurements that include encryption time.
    pub fn write_all_blocking(&mut self, data: &[u8]) -> io::Result<()> {
        self.bytes_written += data.len() as u64;
        // Flush pending async buffer first.
        if !self.write_buf.is_empty() {
            self.flush_write_buf()?;
        }
        // Synchronous SSL_write through the shared stream.
        let mut stream = self
            .blocking_stream
            .lock()
            .map_err(|_| io::Error::other("TLS stream mutex poisoned"))?;
        let mut sent = 0usize;
        while sent < data.len() {
            match stream.write(&data[sent..]) {
                Ok(n) => sent += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Flush the internal write buffer.
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
                io::Error::new(io::ErrorKind::BrokenPipe, "TLS async writer thread gone")
            })
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no async writer",
            ))
        }
    }

    /// Total bytes written so far.
    #[allow(dead_code)]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Reset the byte counter (e.g. between payload-size runs).
    pub fn reset_bytes(&mut self) {
        let _ = self.flush();
        self.bytes_written = 0;
    }

    /// Shut down the TLS session and wait for the sink thread.
    pub fn shutdown(mut self) -> TlsPipeStats {
        // Flush any remaining buffered data.
        let _ = self.flush();

        // Drop the async writer channel to signal the writer thread to finish,
        // then wait for it to drain all queued buffers.
        self.async_tx.take();
        if let Some(handle) = self.writer_handle.take() {
            let _ = handle.join();
        }

        self.sink_stop.store(true, Ordering::Relaxed);

        let bytes_drained = if let Some(handle) = self.sink_handle.take() {
            handle.join().unwrap_or(0)
        } else {
            0
        };

        TlsPipeStats {
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

// =========================================================================================
//                                  TlsPipe (multi-lane)
// =========================================================================================

/// A userspace-TLS pipe over TCP loopback with one or more parallel lanes.
///
/// Each lane owns its own loopback TLS connection and background writer thread.
/// Writes are sharded round-robin across lanes to increase throughput on
/// multi-core systems.
pub struct TlsPipe {
    lanes: Vec<TlsPipeLane>,
    next_lane: usize,
    remote_target: Option<String>,
}

impl TlsPipe {
    /// Create a new userspace TLS pipe with default thread count (CPU count).
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let lanes = default_lane_count();
        Self::with_threads(lanes)
    }

    /// Create a new userspace TLS pipe with a specific number of parallel lanes.
    pub fn with_threads(threads: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let lane_count = threads.max(1);
        let mut lanes = Vec::with_capacity(lane_count);
        for _ in 0..lane_count {
            lanes.push(TlsPipeLane::new()?);
        }
        Ok(Self {
            lanes,
            next_lane: 0,
            remote_target: None,
        })
    }

    /// Create a new userspace TLS pipe that connects to a remote TLS receiver.
    /// No local sink thread is spawned — data is sent over the network.
    pub fn with_remote_target(
        addr: &str,
        threads: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let lane_count = threads.max(1);
        let mut lanes = Vec::with_capacity(lane_count);
        for _ in 0..lane_count {
            lanes.push(TlsPipeLane::new_remote(addr)?);
        }
        Ok(Self {
            lanes,
            next_lane: 0,
            remote_target: Some(addr.to_string()),
        })
    }

    /// Send a 16-byte protocol header through the first lane.
    /// Used by container mode to signal payload_size to the receiver.
    pub fn send_header(&mut self, payload_size: u32, flags: u32) -> io::Result<()> {
        let hdr = build_protocol_header(payload_size, flags);
        if self.lanes.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "no lanes"));
        }
        // Send through first lane via the async channel.
        self.lanes[0].send_async(hdr.to_vec())
    }

    /// Whether this pipe connects to a remote target.
    pub fn is_remote(&self) -> bool {
        self.remote_target.is_some()
    }

    fn pick_lane_mut(&mut self) -> &mut TlsPipeLane {
        let idx = self.next_lane % self.lanes.len();
        self.next_lane = (self.next_lane + 1) % self.lanes.len();
        &mut self.lanes[idx]
    }

    /// Write data through the TLS pipe using the configured mode.
    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.pick_lane_mut().write_all(data)
    }

    /// Write data synchronously (blocking) for latency measurement.
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

    /// Total bytes written to the TLS sessions so far.
    pub fn bytes_written(&self) -> u64 {
        self.lanes.iter().map(|lane| lane.bytes_written).sum()
    }

    /// Reset the byte counters (e.g. between payload-size runs).
    pub fn reset_bytes(&mut self) {
        for lane in &mut self.lanes {
            lane.reset_bytes();
        }
    }

    /// Shut down all lanes and wait for sink threads to finish.
    pub fn shutdown(mut self) -> TlsPipeStats {
        let mut bytes_written = 0u64;
        let mut bytes_drained = 0u64;
        let mut handshake_ms: f64 = 0.0;
        for lane in self.lanes.drain(..) {
            let stats = lane.shutdown();
            bytes_written = bytes_written.saturating_add(stats.bytes_written);
            bytes_drained = bytes_drained.saturating_add(stats.bytes_drained);
            handshake_ms = handshake_ms.max(stats.handshake_ms);
        }
        TlsPipeStats {
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

/// Print a dual-throughput header for IPC + TLS benchmarks.
pub fn print_tls_header(name: &str) {
    println!("\n=== BENCHMARK: {} (with userspace TLS pipe) ===", name);
    println!(
        "{:<12} | {:<15} | {:<15} | {:<15} | {:<10}",
        "Payload Size", "IPC Tput", "TLS Tput", "Overhead", "Status"
    );
    println!(
        "{:-<12}-+-{:-<15}-+-{:-<15}-+-{:-<15}-+-{:-<10}",
        "", "", "", "", ""
    );
}

/// Print a dual-throughput result row.
pub fn print_tls_result(
    payload_size: usize,
    ipc_payload_bps: f64,
    ipc_overhead_bps: f64,
    tls_bps: f64,
) {
    let ipc_total = ipc_payload_bps + ipc_overhead_bps;
    let ipc_gib_s = ipc_total / 1024.0 / 1024.0 / 1024.0;
    let tls_gib_s = tls_bps / 1024.0 / 1024.0 / 1024.0;

    let overhead_pct = if ipc_total > 0.0 {
        (ipc_overhead_bps / ipc_total) * 100.0
    } else {
        0.0
    };

    println!(
        "{:<12} | {:>10.2} GiB/s | {:>10.2} GiB/s | {:>8.2} %      | Completed",
        format_size(payload_size),
        ipc_gib_s,
        tls_gib_s,
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
