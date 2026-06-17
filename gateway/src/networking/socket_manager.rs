//! Socket Manager — low-level socket helpers used across proxy modules.

use crate::interfaces::tproxy;
use log::{error, info};

use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

// ─── Socket helpers ──────────────────────────────────────────────────────────

pub fn tune_socket_buffers(fd: RawFd, buf_size: usize) {
    let val = buf_size as libc::c_int;
    unsafe {
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

pub fn set_nodelay(fd: RawFd, on: bool) {
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

/// Enable TCP Quick ACK — disables delayed ACK for faster congestion window
/// growth. Note: the kernel may reset this after each ACK; setting it once at
/// connection start still improves the initial burst.
pub fn set_quickack(fd: RawFd) {
    let val: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Enable or disable TCP_CORK on a socket.
///
/// When enabled, TCP coalesces small writes into fewer, larger segments —
/// reducing per-packet overhead on the write path.  Toggle ON before a batch
/// of writes and OFF afterwards to flush the coalesced segment immediately.
#[inline]
pub fn set_tcp_cork(fd: RawFd, on: bool) {
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

/// Temporarily enable TCP_CORK for the current scope.
pub struct TcpCorkGuard {
    fd: RawFd,
    enabled: bool,
}

impl TcpCorkGuard {
    pub fn new(fd: RawFd, enabled: bool) -> Self {
        if enabled {
            set_tcp_cork(fd, true);
        }
        Self { fd, enabled }
    }
}

impl Drop for TcpCorkGuard {
    fn drop(&mut self) {
        if self.enabled {
            set_tcp_cork(self.fd, false);
        }
    }
}

/// Set a file descriptor to non-blocking mode via fcntl.
pub fn set_nonblocking_fd(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

pub fn accept_with_timeout(
    listener: &TcpListener,
    timeout: Duration,
) -> Option<io::Result<(TcpStream, SocketAddr)>> {
    let fd = listener.as_raw_fd();
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pfd, 1, timeout.as_millis() as libc::c_int) };
    if ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
        Some(listener.accept())
    } else {
        None
    }
}

// ─── Bind helpers ────────────────────────────────────────────────────────────

/// Bind a TCP listener, optionally with TPROXY transparent mode.
/// Returns `None` (and logs the error) if binding fails.
pub fn bind_tcp_listener(addr: &str, transparent: bool, rule_name: &str) -> Option<TcpListener> {
    if transparent {
        match tproxy::create_transparent_tcp_listener(addr) {
            Ok(l) => {
                info!("[{}] TPROXY TCP listener on {}", rule_name, addr);
                Some(l)
            }
            Err(e) => {
                error!("[{}] Failed to create TPROXY listener: {}", rule_name, e);
                None
            }
        }
    } else {
        match TcpListener::bind(addr) {
            Ok(l) => {
                info!("[{}] TCP listener on {}", rule_name, addr);
                Some(l)
            }
            Err(e) => {
                error!("[{}] Failed to bind {}: {}", rule_name, addr, e);
                None
            }
        }
    }
}

/// Bind a UDP socket, optionally with TPROXY transparent mode.
/// Returns `None` (and logs the error) if binding fails.
pub fn bind_udp_socket(addr: &str, transparent: bool, rule_name: &str) -> Option<UdpSocket> {
    if transparent {
        match tproxy::create_transparent_udp_socket(addr) {
            Ok(s) => {
                info!("[{}] TPROXY UDP socket on {}", rule_name, addr);
                Some(s)
            }
            Err(e) => {
                error!("[{}] Failed to create TPROXY UDP socket: {}", rule_name, e);
                None
            }
        }
    } else {
        match UdpSocket::bind(addr) {
            Ok(s) => {
                info!("[{}] UDP socket on {}", rule_name, addr);
                Some(s)
            }
            Err(e) => {
                error!("[{}] Failed to bind UDP {}: {}", rule_name, addr, e);
                None
            }
        }
    }
}

// ─── Poll helper ─────────────────────────────────────────────────────────────

/// Poll two file descriptors for POLLIN. Returns `(fd_a_ready, fd_b_ready)`.
///
/// When `tls_pending > 0`, **both** fds are returned as ready: the TLS fd
/// has buffered ciphertext that must be drained, and the other fd may also
/// have data waiting. This avoids stalls when the TLS fd is in position
/// fd_a (decrypt path) — previously only fd_b was marked.
///
/// Returns `Err` on poll error (non-EINTR), `Ok((false, false))` on timeout.
pub fn poll_two_fds(
    fd_a: RawFd,
    fd_b: RawFd,
    tls_pending: usize,
    timeout_ms: i32,
) -> io::Result<(bool, bool)> {
    if tls_pending > 0 {
        // TLS has buffered data — return both as ready so neither direction stalls.
        // The caller's inner loop will break on WouldBlock if the other fd has nothing.
        return Ok((true, true));
    }

    let mut fds = [
        libc::pollfd {
            fd: fd_a,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: fd_b,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok((false, false));
        }
        return Err(err);
    }
    if ret == 0 {
        return Ok((false, false));
    }

    let a_ready = fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0;
    let b_ready = fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0;
    Ok((a_ready, b_ready))
}

// ─── Write helpers ───────────────────────────────────────────────────────────

/// Poll a single fd for write readiness. Sleeps the thread in the kernel
/// instead of spin-yielding, freeing CPU for other connections.
#[inline]
fn poll_write_ready(fd: RawFd, timeout_ms: i32) -> io::Result<()> {
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

/// Write all bytes to a std::io::Write, waiting for write readiness on WouldBlock.
pub fn write_all_nb<W: Write + AsRawFd>(w: &mut W, data: &[u8]) -> io::Result<()> {
    let fd = w.as_raw_fd();
    let mut pos = 0;
    while pos < data.len() {
        match w.write(&data[pos..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")),
            Ok(n) => pos += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                poll_write_ready(fd, 100)?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
