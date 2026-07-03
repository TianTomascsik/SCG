//! Bidirectional relay functions for proxying data between streams.

use super::tls_engine::{write_all_nb_proxy, ProxyStream};
use crate::networking::socket_manager::{
    poll_two_fds, poll_two_fds_with_spin, set_nonblocking_fd, set_quickack, tune_socket_buffers,
    write_all_nb, MmsgRecvBuf, MmsgSendBuf, TcpCorkGuard, UDP_MMSG_BATCH,
};
use crate::security::udp_framing::UdpFraming;

use crate::management::telemetry::ConnectionMetrics;
use crate::security::{RELAY_BUF_SIZE, UDP_BUF_SIZE};

use log::debug;

use std::io::{self, Read};
use std::net::{TcpStream, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// ─── Splice constants ────────────────────────────────────────────────────────

// The pipe capacity / splice chunk size is now profile-driven (`pipe_size`),
// supplied per connection from the resolved `PerfKnobs`.
const SPLICE_F_MOVE: libc::c_uint = 1;
const SPLICE_F_MORE: libc::c_uint = 4;
const SPLICE_F_NONBLOCK: libc::c_uint = 2;

/// Apply a simulated network delay (geo-location simulation).
/// No-op when delay_ms is 0.
#[inline]
pub fn apply_geo_delay(delay_ms: u64) {
    if delay_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
    }
}

const ADAPTIVE_MIN_BUF_SIZE: usize = 64 * 1024;

struct AdaptiveBufferTuner {
    enabled: bool,
    target_queue_us: u64,
    min_size: usize,
    max_size: usize,
    current_size: usize,
    window_start: Instant,
    window_bytes: usize,
}

impl AdaptiveBufferTuner {
    fn new(enabled: bool, target_queue_us: u64, max_size: usize) -> Self {
        let max_size = max_size.max(ADAPTIVE_MIN_BUF_SIZE);
        Self {
            enabled: enabled && target_queue_us > 0,
            target_queue_us,
            min_size: ADAPTIVE_MIN_BUF_SIZE,
            max_size,
            current_size: max_size,
            window_start: Instant::now(),
            window_bytes: 0,
        }
    }

    fn record(&mut self, bytes: usize, socket_fds: &[RawFd], pipe_fds: &[RawFd]) {
        if !self.enabled || bytes == 0 {
            return;
        }
        self.window_bytes = self.window_bytes.saturating_add(bytes);
        let elapsed = self.window_start.elapsed();
        if elapsed < Duration::from_millis(250) {
            return;
        }

        let bytes_per_sec = self.window_bytes as f64 / elapsed.as_secs_f64();
        let desired = (bytes_per_sec * (self.target_queue_us as f64 / 1_000_000.0)).ceil() as usize;
        let desired = round_page(desired.clamp(self.min_size, self.max_size)).min(self.max_size);
        if desired.abs_diff(self.current_size) >= (self.current_size / 8).max(4096) {
            for &fd in socket_fds {
                tune_socket_buffers(fd, desired);
            }
            for &fd in pipe_fds {
                // SAFETY: `fd` is a live pipe descriptor passed in by the caller and kept
                // open for the duration of the relay; `F_SETPIPE_SZ` takes a single `c_int`
                // argument (`desired`) and performs no memory access, so this fcntl call has
                // no preconditions beyond `fd` being valid. The return value is intentionally
                // ignored as a best-effort resize.
                unsafe {
                    libc::fcntl(fd, libc::F_SETPIPE_SZ, desired as libc::c_int);
                }
            }
            self.current_size = desired;
        }

        self.window_start = Instant::now();
        self.window_bytes = 0;
    }
}

fn round_page(bytes: usize) -> usize {
    const PAGE: usize = 4096;
    bytes.div_ceil(PAGE) * PAGE
}

/// Bidirectional relay between a TLS ProxyStream and a plain TcpStream.
/// Uses poll()-based I/O for full-duplex forwarding in a single thread.
// Internal relay entry point; the parameter list mirrors the per-connection
// tuning surface and a param struct is a larger refactor than warranted here.
#[allow(clippy::too_many_arguments)]
pub fn relay_bidirectional(
    tls_stream: &mut ProxyStream,
    mut upstream: TcpStream,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &AtomicBool,
    delay_ms: u64,
    enable_cork: bool,
    relay_buf_size: usize,
    busy_poll_us: u32,
    bdp_adaptive: bool,
    bdp_queue_budget_us: u64,
) -> io::Result<()> {
    let tls_fd = tls_stream.raw_fd();
    let up_fd = upstream.as_raw_fd();

    set_nonblocking_fd(tls_fd);
    upstream.set_nonblocking(true)?;
    set_quickack(up_fd);
    set_quickack(tls_fd);

    // One-time connection-setup buffers; zero-init cost is negligible (not hot path).
    let mut buf_fwd = vec![0u8; relay_buf_size];
    let mut buf_rev = vec![0u8; relay_buf_size];
    let mut tuner = AdaptiveBufferTuner::new(bdp_adaptive, bdp_queue_budget_us, relay_buf_size);

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let tls_pending = tls_stream.ssl_pending();
        let (a_ready, b_ready) =
            poll_two_fds_with_spin(tls_fd, up_fd, tls_pending, busy_poll_us, 100)?;
        if !a_ready && !b_ready {
            continue;
        }

        // Forward: TLS → upstream (decrypt direction primary)
        if a_ready {
            let _cork = TcpCorkGuard::new(up_fd, enable_cork);
            loop {
                match tls_stream.read(&mut buf_fwd) {
                    Ok(0) => {
                        let _ = upstream.shutdown(std::net::Shutdown::Write);
                        return Ok(());
                    }
                    Ok(n) => {
                        apply_geo_delay(delay_ms);
                        write_all_nb(&mut upstream, &buf_fwd[..n])?;
                        tuner.record(n, &[tls_fd, up_fd], &[]);
                        conn_metrics.record_read(n);
                        conn_metrics.record_relay(n);
                        if tls_stream.ssl_pending() == 0 {
                            break;
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Ok(()),
                }
            }
        }

        // Reverse: upstream → TLS (response path) — drain loop
        if b_ready {
            let _cork = TcpCorkGuard::new(tls_fd, enable_cork);
            loop {
                match upstream.read(&mut buf_rev) {
                    Ok(0) => {
                        tls_stream.shutdown_write();
                        return Ok(());
                    }
                    Ok(n) => {
                        write_all_nb_proxy(tls_stream, &buf_rev[..n])?;
                        tuner.record(n, &[tls_fd, up_fd], &[]);
                        conn_metrics.record_read(n);
                        conn_metrics.record_relay(n);
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Ok(()),
                }
            }
        }
    }

    tls_stream.shutdown_write();
    let _ = upstream.shutdown(std::net::Shutdown::Write);
    Ok(())
}

/// Bidirectional relay between a TLS stream and a UDP socket, using ALE framing.
/// Forward: reads ALEPKTs from TLS, extracts user data, sends as UDP datagrams.
/// Reverse: receives UDP datagrams, wraps in ALEPKT DT frames, writes into TLS.
pub fn relay_tls_to_udp(
    rule_name: &str,
    tls_stream: &mut ProxyStream,
    upstream: &UdpSocket,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &AtomicBool,
    delay_ms: u64,
    mut framing: UdpFraming,
) -> io::Result<()> {
    let tls_fd = tls_stream.raw_fd();
    let udp_fd = upstream.as_raw_fd();

    set_nonblocking_fd(tls_fd);
    upstream.set_nonblocking(true)?;

    // One-time connection-setup buffers; zero-init cost is negligible (not hot path).
    let mut tls_buf = vec![0u8; RELAY_BUF_SIZE];
    // Batched UDP I/O: one `recvmmsg`/`sendmmsg` per drain amortises the
    // per-datagram syscall, the limiter on the plaintext-UDP leg toward 10 Gib/s.
    let mut udp_rx = MmsgRecvBuf::new(UDP_MMSG_BATCH, UDP_BUF_SIZE);
    let mut udp_tx = MmsgSendBuf::new();

    let mut batch_buf: Vec<u8> = Vec::with_capacity(64 * 1024);

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let tls_pending = tls_stream.ssl_pending();
        let (a_ready, b_ready) = poll_two_fds(tls_fd, udp_fd, tls_pending, 100)?;
        if !a_ready && !b_ready {
            continue;
        }

        // Forward: TLS → UDP (read ALE frames, send user data as datagrams).
        // Datagrams are staged and flushed with one `sendmmsg` per TLS read to
        // amortise the per-datagram `send` syscall. `upstream` is connected, so
        // the flush destination is `None`.
        if a_ready {
            'tls_read: loop {
                match tls_stream.read(&mut tls_buf) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        apply_geo_delay(delay_ms);
                        let disconnect =
                            framing.deframe_each(rule_name, &tls_buf[..n], |datagram| {
                                udp_tx.push(datagram);
                                let data_len = datagram.len();
                                conn_metrics.record_read(data_len);
                                conn_metrics.record_relay(data_len);
                            });
                        if !udp_tx.is_empty() {
                            let _ = udp_tx.flush(udp_fd, None);
                        }
                        if disconnect {
                            return Ok(());
                        }
                        if tls_stream.ssl_pending() == 0 {
                            break 'tls_read;
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break 'tls_read,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Ok(()),
                }
            }
        }

        // Reverse: UDP → TLS (receive datagrams in batches, frame ALE/raw, one
        // TLS write). `upstream` is connected, so every datagram is from the
        // pinned peer — no per-source check needed here.
        if b_ready {
            batch_buf.clear();
            'udp_read: loop {
                let count = match udp_rx.recv(udp_fd) {
                    Ok(0) => break 'udp_read,
                    Ok(c) => c,
                    Err(_) => return Ok(()),
                };
                for i in 0..count {
                    let (_src, payload) = udp_rx.get(i);
                    framing.frame_into(payload, &mut batch_buf);
                    conn_metrics.record_read(payload.len());
                    conn_metrics.record_relay(payload.len());
                }
            }
            // Flush batched frames to TLS in a single write
            if !batch_buf.is_empty() && write_all_nb_proxy(tls_stream, &batch_buf).is_err() {
                return Ok(());
            }
        }
    }

    // Send ALE DI before closing (no-op for raw framing)
    framing.write_disconnect(tls_stream);
    tls_stream.shutdown_write();
    Ok(())
}

/// Bidirectional relay for encrypt direction: client (plain TCP) <-> upstream (TLS).
// Internal relay entry point; a param struct is a larger refactor than warranted here.
#[allow(clippy::too_many_arguments)]
pub fn relay_encrypt_bidirectional(
    client: TcpStream,
    upstream: &mut ProxyStream,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &AtomicBool,
    delay_ms: u64,
    enable_cork: bool,
    relay_buf_size: usize,
    busy_poll_us: u32,
    bdp_adaptive: bool,
    bdp_queue_budget_us: u64,
) -> io::Result<()> {
    let client_fd = client.as_raw_fd();
    let tls_fd = upstream.raw_fd();

    set_nonblocking_fd(client_fd);
    set_nonblocking_fd(tls_fd);
    set_quickack(client_fd);
    set_quickack(tls_fd);

    // One-time connection-setup buffers; zero-init cost is negligible (not hot path).
    let mut buf_fwd = vec![0u8; relay_buf_size];
    let mut buf_rev = vec![0u8; relay_buf_size];
    let mut client_w = client.try_clone()?;
    let mut client_r = client;
    let mut tuner = AdaptiveBufferTuner::new(bdp_adaptive, bdp_queue_budget_us, relay_buf_size);

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let tls_pending = upstream.ssl_pending();
        // Note: for encrypt, fd_a=client, fd_b=tls upstream
        let (client_ready, tls_ready) =
            poll_two_fds_with_spin(client_fd, tls_fd, tls_pending, busy_poll_us, 100)?;
        if !client_ready && !tls_ready {
            continue;
        }

        // Forward: client → TLS upstream — drain loop
        if client_ready {
            let _cork = TcpCorkGuard::new(tls_fd, enable_cork);
            loop {
                match client_r.read(&mut buf_fwd) {
                    Ok(0) => {
                        upstream.shutdown_write();
                        return Ok(());
                    }
                    Ok(n) => {
                        apply_geo_delay(delay_ms);
                        write_all_nb_proxy(upstream, &buf_fwd[..n])?;
                        tuner.record(n, &[client_fd, tls_fd], &[]);
                        conn_metrics.record_read(n);
                        conn_metrics.record_relay(n);
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Ok(()),
                }
            }
        }

        // Reverse: TLS upstream → client
        if tls_ready {
            let _cork = TcpCorkGuard::new(client_fd, enable_cork);
            loop {
                match upstream.read(&mut buf_rev) {
                    Ok(0) => {
                        let _ = client_w.shutdown(std::net::Shutdown::Write);
                        return Ok(());
                    }
                    Ok(n) => {
                        write_all_nb(&mut client_w, &buf_rev[..n])?;
                        tuner.record(n, &[client_fd, tls_fd], &[]);
                        conn_metrics.record_read(n);
                        conn_metrics.record_relay(n);
                        if upstream.ssl_pending() == 0 {
                            break;
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Ok(()),
                }
            }
        }
    }

    upstream.shutdown_write();
    let _ = client_w.shutdown(std::net::Shutdown::Write);
    Ok(())
}

// ─── Splice helpers ──────────────────────────────────────────────────────────

/// Create a kernel pipe with enlarged capacity for splice operations.
fn make_splice_pipe(pipe_size: usize) -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds` is a stack-allocated `[RawFd; 2]`; `fds.as_mut_ptr()` points to a
    // fully-initialised array of exactly the 2 `c_int`s that `pipe2` writes, and the array
    // outlives the call. `O_CLOEXEC` is a valid flag. The negative return is checked below
    // before either descriptor is used.
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // Grow pipe capacity to the profile-driven `pipe_size` (throughput vs latency).
    // SAFETY: `fds[0]` is the read end of the pipe just successfully created by `pipe2`
    // above and is still open; `F_SETPIPE_SZ` takes a single `c_int` (`pipe_size`) and
    // accesses no memory, so the only precondition is a valid descriptor, which holds here.
    // The return value is ignored as a best-effort capacity hint.
    unsafe {
        libc::fcntl(fds[0], libc::F_SETPIPE_SZ, pipe_size as libc::c_int);
    }
    Ok((fds[0], fds[1]))
}

/// Close a pipe (both ends).
fn close_pipe(read_fd: RawFd, write_fd: RawFd) {
    // SAFETY: `read_fd` and `write_fd` are the two ends of a pipe owned by the caller and
    // are each closed exactly once here at end-of-relay; no further use of them occurs after
    // this point, so there is no double-close or use-after-close. `close` accesses no memory.
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}

/// Result of a splice operation.
enum SpliceResult {
    /// Moved N bytes (N > 0).
    Moved(usize),
    /// EOF — the source fd was closed.
    Eof,
    /// No data currently available (EAGAIN / EWOULDBLOCK).
    WouldBlock,
}

/// Splice data from one fd to another through a kernel pipe (zero-copy).
#[inline]
fn splice_one_direction(
    src_fd: RawFd,
    pipe_write: RawFd,
    pipe_read: RawFd,
    dst_fd: RawFd,
    chunk: usize,
) -> io::Result<SpliceResult> {
    // Step 1: splice src → pipe
    // SAFETY: `src_fd` and `pipe_write` are valid open descriptors owned by the caller for
    // the duration of this call; both offset pointers are deliberately `NULL`, which `splice`
    // accepts to mean "use/advance the file offset", so no memory is dereferenced; `chunk`
    // bounds the transfer and the flags are a valid `SPLICE_F_*` bitmask. The negative/zero
    // return is checked immediately below before `n` is used.
    let n = unsafe {
        libc::splice(
            src_fd,
            std::ptr::null_mut(),
            pipe_write,
            std::ptr::null_mut(),
            chunk,
            (SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK) as _,
        )
    };
    if n < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok(SpliceResult::WouldBlock);
        }
        return Err(err);
    }
    if n == 0 {
        return Ok(SpliceResult::Eof);
    }
    let total = n as usize;

    // Step 2: splice pipe → dst (drain all bytes from the pipe)
    let mut written = 0usize;
    while written < total {
        // SAFETY: `pipe_read` and `dst_fd` are valid open descriptors owned by the caller for
        // the duration of this call; both offset pointers are `NULL` (valid for `splice`), so
        // no memory is dereferenced; `total - written` is a non-negative count bounded by the
        // bytes already buffered in the pipe (`written < total` is the loop guard) and
        // `SPLICE_F_MOVE` is a valid flag. The negative/zero return is checked below before
        // `w` is added to `written`.
        let w = unsafe {
            libc::splice(
                pipe_read,
                std::ptr::null_mut(),
                dst_fd,
                std::ptr::null_mut(),
                total - written,
                SPLICE_F_MOVE as _,
            )
        };
        if w < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                // dst buffer full — poll for write readiness
                let mut pfd = libc::pollfd {
                    fd: dst_fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: `&mut pfd` points to a single fully-initialised `libc::pollfd`
                // living on this stack frame for the whole call, and the count `1` matches
                // exactly that one element, so `poll` reads/writes only within `pfd`. `100`
                // is a valid timeout in milliseconds. The result is intentionally ignored
                // (best-effort wait before retrying the splice).
                unsafe {
                    libc::poll(&mut pfd, 1, 100);
                }
                continue;
            }
            return Err(err);
        }
        if w == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "splice write zero",
            ));
        }
        written += w as usize;
    }

    Ok(SpliceResult::Moved(total))
}

/// Zero-copy bidirectional relay for kTLS connections using splice(2).
///
/// When kTLS is active the kernel handles TLS encryption/decryption on the
/// socket.  splice() moves data between the kTLS socket and the plain TCP
/// socket entirely in kernel space — no userspace copies at all.
///
/// Optimizations vs naive splice:
/// - Loop-drain each direction until WouldBlock before polling again
/// - Separate WouldBlock from EOF to avoid unnecessary recv(MSG_PEEK)
/// - 16 MiB pipe buffers for fewer splice calls per data volume
// Internal relay entry point; a param struct is a larger refactor than warranted here.
#[allow(clippy::too_many_arguments)]
pub fn relay_bidirectional_splice(
    tls_fd: RawFd,
    upstream_fd: RawFd,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &AtomicBool,
    delay_ms: u64,
    pipe_size: usize,
    busy_poll_us: u32,
    bdp_adaptive: bool,
    bdp_queue_budget_us: u64,
) -> io::Result<()> {
    set_nonblocking_fd(tls_fd);
    set_nonblocking_fd(upstream_fd);
    set_quickack(tls_fd);
    set_quickack(upstream_fd);

    // Create two pipes — one per direction
    let (pipe_fwd_r, pipe_fwd_w) = make_splice_pipe(pipe_size)?;
    let (pipe_rev_r, pipe_rev_w) = make_splice_pipe(pipe_size)?;
    let mut tuner = AdaptiveBufferTuner::new(bdp_adaptive, bdp_queue_budget_us, pipe_size);

    let result = (|| -> io::Result<()> {
        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Poll both fds for read readiness (ssl_pending is always 0 for kTLS)
            let (tls_ready, up_ready) =
                poll_two_fds_with_spin(tls_fd, upstream_fd, 0, busy_poll_us, 100)?;
            if !tls_ready && !up_ready {
                continue;
            }

            // Forward: kTLS fd → pipe → upstream fd
            // Loop-drain: keep splicing until WouldBlock to amortize poll() overhead
            if tls_ready {
                apply_geo_delay(delay_ms);
                loop {
                    match splice_one_direction(
                        tls_fd,
                        pipe_fwd_w,
                        pipe_fwd_r,
                        upstream_fd,
                        pipe_size,
                    ) {
                        Ok(SpliceResult::Moved(n)) => {
                            tuner.record(n, &[tls_fd, upstream_fd], &[pipe_fwd_r, pipe_rev_r]);
                            conn_metrics.record_read(n);
                            conn_metrics.record_relay(n);
                            // Continue draining
                        }
                        Ok(SpliceResult::WouldBlock) => break, // No more data, go back to poll
                        Ok(SpliceResult::Eof) => {
                            // SAFETY: `upstream_fd` is a valid open socket descriptor passed
                            // in by the caller and still open at this point; `shutdown` takes
                            // the fd and the `SHUT_WR` constant and accesses no memory. The
                            // return value is intentionally ignored on this teardown path.
                            unsafe {
                                libc::shutdown(upstream_fd, libc::SHUT_WR);
                            }
                            return Ok(());
                        }
                        Err(e) => {
                            debug!("splice fwd error: {}", e);
                            return Ok(());
                        }
                    }
                }
            }

            // Reverse: upstream fd → pipe → kTLS fd
            if up_ready {
                loop {
                    match splice_one_direction(
                        upstream_fd,
                        pipe_rev_w,
                        pipe_rev_r,
                        tls_fd,
                        pipe_size,
                    ) {
                        Ok(SpliceResult::Moved(n)) => {
                            tuner.record(n, &[tls_fd, upstream_fd], &[pipe_fwd_r, pipe_rev_r]);
                            conn_metrics.record_read(n);
                            conn_metrics.record_relay(n);
                        }
                        Ok(SpliceResult::WouldBlock) => break,
                        Ok(SpliceResult::Eof) => {
                            // SAFETY: `tls_fd` is a valid open socket descriptor passed in by
                            // the caller and still open at this point; `shutdown` takes the fd
                            // and the `SHUT_WR` constant and accesses no memory. The return
                            // value is intentionally ignored on this teardown path.
                            unsafe {
                                libc::shutdown(tls_fd, libc::SHUT_WR);
                            }
                            return Ok(());
                        }
                        Err(e) => {
                            debug!("splice rev error: {}", e);
                            return Ok(());
                        }
                    }
                }
            }
        }

        // SAFETY: `tls_fd` and `upstream_fd` are valid open socket descriptors passed in by
        // the caller and still open at this normal-exit point; `shutdown` takes each fd and
        // the `SHUT_WR` constant and accesses no memory. Both return values are intentionally
        // ignored on this teardown path.
        unsafe {
            libc::shutdown(tls_fd, libc::SHUT_WR);
            libc::shutdown(upstream_fd, libc::SHUT_WR);
        }
        Ok(())
    })();

    // Always close pipes
    close_pipe(pipe_fwd_r, pipe_fwd_w);
    close_pipe(pipe_rev_r, pipe_rev_w);

    result
}
