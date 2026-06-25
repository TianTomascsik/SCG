//! Bidirectional relay functions for proxying data between streams.

use super::tls_engine::{write_all_nb_proxy, ProxyStream};
use crate::networking::socket_manager::{
    poll_two_fds, set_nonblocking_fd, set_quickack, write_all_nb, TcpCorkGuard,
};
use crate::security::udp_framing::UdpFraming;

use crate::management::telemetry::ConnectionMetrics;
use crate::security::{RELAY_BUF_SIZE, UDP_BUF_SIZE};

use log::debug;

use std::io::{self, Read};
use std::net::{TcpStream, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

// ─── Splice constants ────────────────────────────────────────────────────────

/// Splice chunk size — matches the kernel pipe capacity we request.
/// Using 16 MiB for maximum throughput (requires pipe-max-size ≥ 16 MiB).
const SPLICE_CHUNK: usize = 16 * 1024 * 1024; // 16 MiB
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

/// Bidirectional relay between a TLS ProxyStream and a plain TcpStream.
/// Uses poll()-based I/O for full-duplex forwarding in a single thread.
pub fn relay_bidirectional(
    tls_stream: &mut ProxyStream,
    mut upstream: TcpStream,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &AtomicBool,
    delay_ms: u64,
    enable_cork: bool,
) -> io::Result<()> {
    let tls_fd = tls_stream.raw_fd();
    let up_fd = upstream.as_raw_fd();

    set_nonblocking_fd(tls_fd);
    upstream.set_nonblocking(true)?;
    set_quickack(up_fd);
    set_quickack(tls_fd);

    // One-time connection-setup buffers; zero-init cost is negligible (not hot path).
    let mut buf_fwd = vec![0u8; RELAY_BUF_SIZE];
    let mut buf_rev = vec![0u8; RELAY_BUF_SIZE];

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let tls_pending = tls_stream.ssl_pending();
        let (a_ready, b_ready) = poll_two_fds(tls_fd, up_fd, tls_pending, 100)?;
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
    let mut udp_buf = vec![0u8; UDP_BUF_SIZE];

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

        // Forward: TLS → UDP (read ALE frames, send user data as datagrams)
        if a_ready {
            'tls_read: loop {
                match tls_stream.read(&mut tls_buf) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        let deframed = framing.deframe(rule_name, &tls_buf[..n]);
                        for datagram in deframed.datagrams {
                            apply_geo_delay(delay_ms);
                            let _ = upstream.send(&datagram);
                            let data_len = datagram.len();
                            conn_metrics.record_read(data_len);
                            conn_metrics.record_relay(data_len);
                        }
                        if deframed.disconnect {
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

        // Reverse: UDP → TLS (receive datagrams, frame ALE/raw, batched)
        if b_ready {
            batch_buf.clear();
            'udp_read: loop {
                match upstream.recv(&mut udp_buf) {
                    Ok(n) => {
                        framing.frame_into(&udp_buf[..n], &mut batch_buf);
                        conn_metrics.record_read(n);
                        conn_metrics.record_relay(n);
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break 'udp_read,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Ok(()),
                }
            }
            // Flush batched frames to TLS in a single write
            if !batch_buf.is_empty() {
                if write_all_nb_proxy(tls_stream, &batch_buf).is_err() {
                    return Ok(());
                }
            }
        }
    }

    // Send ALE DI before closing (no-op for raw framing)
    framing.write_disconnect(tls_stream);
    tls_stream.shutdown_write();
    Ok(())
}

/// Bidirectional relay for encrypt direction: client (plain TCP) <-> upstream (TLS).
pub fn relay_encrypt_bidirectional(
    client: TcpStream,
    upstream: &mut ProxyStream,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &AtomicBool,
    delay_ms: u64,
    enable_cork: bool,
) -> io::Result<()> {
    let client_fd = client.as_raw_fd();
    let tls_fd = upstream.raw_fd();

    set_nonblocking_fd(client_fd);
    set_nonblocking_fd(tls_fd);
    set_quickack(client_fd);
    set_quickack(tls_fd);

    // One-time connection-setup buffers; zero-init cost is negligible (not hot path).
    let mut buf_fwd = vec![0u8; RELAY_BUF_SIZE];
    let mut buf_rev = vec![0u8; RELAY_BUF_SIZE];
    let mut client_w = client.try_clone()?;
    let mut client_r = client;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let tls_pending = upstream.ssl_pending();
        // Note: for encrypt, fd_a=client, fd_b=tls upstream
        let (client_ready, tls_ready) = poll_two_fds(client_fd, tls_fd, tls_pending, 100)?;
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
fn make_splice_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0 as RawFd; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // Grow pipe capacity to SPLICE_CHUNK for better throughput
    unsafe {
        libc::fcntl(fds[0], libc::F_SETPIPE_SZ, SPLICE_CHUNK as libc::c_int);
    }
    Ok((fds[0], fds[1]))
}

/// Close a pipe (both ends).
fn close_pipe(read_fd: RawFd, write_fd: RawFd) {
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
) -> io::Result<SpliceResult> {
    // Step 1: splice src → pipe
    let n = unsafe {
        libc::splice(
            src_fd,
            std::ptr::null_mut(),
            pipe_write,
            std::ptr::null_mut(),
            SPLICE_CHUNK,
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
pub fn relay_bidirectional_splice(
    tls_fd: RawFd,
    upstream_fd: RawFd,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &AtomicBool,
    delay_ms: u64,
) -> io::Result<()> {
    set_nonblocking_fd(tls_fd);
    set_nonblocking_fd(upstream_fd);
    set_quickack(tls_fd);
    set_quickack(upstream_fd);

    // Create two pipes — one per direction
    let (pipe_fwd_r, pipe_fwd_w) = make_splice_pipe()?;
    let (pipe_rev_r, pipe_rev_w) = make_splice_pipe()?;

    let result = (|| -> io::Result<()> {
        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Poll both fds for read readiness (ssl_pending is always 0 for kTLS)
            let (tls_ready, up_ready) = poll_two_fds(tls_fd, upstream_fd, 0, 100)?;
            if !tls_ready && !up_ready {
                continue;
            }

            // Forward: kTLS fd → pipe → upstream fd
            // Loop-drain: keep splicing until WouldBlock to amortize poll() overhead
            if tls_ready {
                apply_geo_delay(delay_ms);
                loop {
                    match splice_one_direction(tls_fd, pipe_fwd_w, pipe_fwd_r, upstream_fd) {
                        Ok(SpliceResult::Moved(n)) => {
                            conn_metrics.record_read(n);
                            conn_metrics.record_relay(n);
                            // Continue draining
                        }
                        Ok(SpliceResult::WouldBlock) => break, // No more data, go back to poll
                        Ok(SpliceResult::Eof) => {
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
                    match splice_one_direction(upstream_fd, pipe_rev_w, pipe_rev_r, tls_fd) {
                        Ok(SpliceResult::Moved(n)) => {
                            conn_metrics.record_read(n);
                            conn_metrics.record_relay(n);
                        }
                        Ok(SpliceResult::WouldBlock) => break,
                        Ok(SpliceResult::Eof) => {
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
