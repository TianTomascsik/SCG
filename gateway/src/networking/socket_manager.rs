//! Socket Manager — low-level socket helpers used across proxy modules.

use crate::interfaces::tproxy;
use crate::management::config::{TrafficClass, SAFETY_THREAD_NICE};
use log::{error, info};

use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

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

/// Set `TCP_NOTSENT_LOWAT` — bound the unsent bytes the kernel keeps queued in
/// the socket's write buffer before reporting the socket writable. Smaller
/// values trim local send-queue (bufferbloat) latency at a small cost to peak
/// throughput; the `latency`/`balanced` profiles set a small value while the
/// `throughput` profile leaves the kernel default. Best-effort (errors ignored).
pub fn set_notsent_lowat(fd: RawFd, bytes: usize) {
    let val = bytes as libc::c_int;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NOTSENT_LOWAT,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Enable socket busy-polling (`SO_BUSY_POLL`) for `us` microseconds — the
/// kernel busy-waits briefly for incoming packets instead of sleeping, trading
/// CPU for lower wakeup latency. Applied by the `latency` profile. A value of 0
/// is a no-op. Requires `CAP_NET_ADMIN` (or a permissive `net.core.busy_poll`);
/// best-effort, so failures are silently ignored.
pub fn set_busy_poll(fd: RawFd, us: u32) {
    if us == 0 {
        return;
    }
    let val = us as libc::c_int;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BUSY_POLL,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Apply the profile's latency-shaping TCP options to a relay socket:
/// `TCP_NOTSENT_LOWAT` (when set) and `SO_BUSY_POLL` (when non-zero). Socket
/// buffer sizing is handled separately by [`tune_socket_buffers`].
pub fn apply_tcp_latency_opts(fd: RawFd, notsent_lowat: Option<usize>, busy_poll_us: u32) {
    if let Some(lowat) = notsent_lowat {
        set_notsent_lowat(fd, lowat);
    }
    set_busy_poll(fd, busy_poll_us);
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

// ─── QoS / DiffServ helpers (DSCP + SO_PRIORITY) ──────────────────────────────

/// Convert a 6-bit DSCP value (0..=63) into the 8-bit IP DS field byte, leaving
/// the two ECN bits cleared. EF (46) maps to `0xB8` (184).
#[inline]
pub fn dscp_to_tos(dscp: u8) -> u8 {
    (dscp & 0x3f) << 2
}

/// Set the DSCP value on packets sent from `fd`. Writes the IPv4 `IP_TOS` field
/// or the IPv6 `IPV6_TCLASS` field depending on `is_v6`. The ECN bits are left
/// at 0. Best-effort: failures are ignored (DSCP is an optimisation, not a
/// correctness requirement, and may be filtered by the network).
pub fn set_dscp(fd: RawFd, dscp: u8, is_v6: bool) {
    let tos = dscp_to_tos(dscp) as libc::c_int;
    let (level, optname) = if is_v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
    } else {
        (libc::IPPROTO_IP, libc::IP_TOS)
    };
    unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &tos as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Set `SO_PRIORITY` on `fd`. Values 0..=6 are unprivileged; values above 6
/// require `CAP_NET_ADMIN` and are silently clamped by the kernel otherwise.
/// Higher priority selects a higher-priority egress qdisc band, keeping safety
/// traffic ahead of normal traffic in the host's send queue. Best-effort.
pub fn set_so_priority(fd: RawFd, prio: i32) {
    let val = prio as libc::c_int;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PRIORITY,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Raise the calling thread's scheduling priority for Safety-class traffic so
/// safety data paths preempt normal traffic under contention. Best-effort: on
/// Linux `setpriority(PRIO_PROCESS, 0, n)` adjusts the *calling thread's* nice
/// value; negative values need `CAP_SYS_NICE` (failures are ignored). `Normal`
/// traffic is left at the default nice. Call once at the top of each
/// per-connection / per-peer data-path thread.
pub fn apply_safety_priority(class: TrafficClass) {
    if class == TrafficClass::Safety {
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, 0, SAFETY_THREAD_NICE);
        }
    }
}

/// Best-effort check whether the process holds `CAP_SYS_NICE` (required to lower
/// the nice value for Safety threads). Reads the effective capability set from
/// `/proc/self/status`. Returns `true` when the capability is present or the
/// check is inconclusive (so the preflight stays quiet rather than warning
/// spuriously).
pub fn has_cap_sys_nice() -> bool {
    // CAP_SYS_NICE is capability bit 23.
    const CAP_SYS_NICE_BIT: u64 = 23;
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(hex) = line.strip_prefix("CapEff:") {
                if let Ok(caps) = u64::from_str_radix(hex.trim(), 16) {
                    return (caps >> CAP_SYS_NICE_BIT) & 1 == 1;
                }
            }
        }
    }
    true
}

/// Request that `recvmsg` deliver the received DS field as ancillary data so the
/// inbound DSCP can be sampled for preservation. Enables IPv4 `IP_RECVTOS` or
/// IPv6 `IPV6_RECVTCLASS`. Best-effort.
pub fn enable_recvtos(fd: RawFd, is_v6: bool) {
    let on: libc::c_int = 1;
    let (level, optname) = if is_v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS)
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVTOS)
    };
    unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Receive from `fd` via `recvmsg`, returning the byte count and the DSCP value
/// (0..=63) extracted from the `IP_TOS` / `IPV6_TCLASS` control message, if any.
///
/// `enable_recvtos` must have been called on `fd` first; otherwise the kernel
/// delivers no TOS ancillary data and the returned DSCP is `None`. Works for
/// both datagram (UDP) and stream (TCP) sockets.
pub fn recvmsg_with_dscp(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, Option<u8>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // Control buffer sized for a single TOS/TCLASS ancillary message.
    let mut cmsg_buf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let dscp = unsafe { extract_dscp_cmsg(&msg) };
    Ok((n as usize, dscp))
}

/// Like [`recvmsg_with_dscp`] but also returns the datagram's source address,
/// for use on unconnected UDP sockets in place of `recv_from`. Returns
/// `(bytes, src, dscp)`.
pub fn recvmsg_from_with_dscp(
    fd: RawFd,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<u8>)> {
    recvmsg_from_with_dscp_flags(fd, buf, 0)
}

/// Like [`recvmsg_from_with_dscp`] but peeks (`MSG_PEEK`): the datagram stays in
/// the receive buffer so a subsequent `connect` + read still sees it. Used to
/// learn a DTLS peer's address and inbound DSCP from its ClientHello without
/// consuming it.
pub fn peek_from_with_dscp(
    fd: RawFd,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<u8>)> {
    recvmsg_from_with_dscp_flags(fd, buf, libc::MSG_PEEK)
}

fn recvmsg_from_with_dscp_flags(
    fd: RawFd,
    buf: &mut [u8],
    flags: libc::c_int,
) -> io::Result<(usize, SocketAddr, Option<u8>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut cmsg_buf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, flags) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let dscp = unsafe { extract_dscp_cmsg(&msg) };
    let src = sockaddr_storage_to_socketaddr(&name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unrecognised source address"))?;
    Ok((n as usize, src, dscp))
}

/// Walk a received `msghdr`'s control messages and return the DSCP (0..=63)
/// from the `IP_TOS` / `IPV6_TCLASS` ancillary data, if present.
///
/// # Safety
/// `msg` must be a fully-initialised `msghdr` returned by a successful
/// `recvmsg` whose `msg_control` buffer is still alive.
unsafe fn extract_dscp_cmsg(msg: &libc::msghdr) -> Option<u8> {
    let mut cmsg = libc::CMSG_FIRSTHDR(msg);
    let mut dscp: Option<u8> = None;
    while !cmsg.is_null() {
        let level = (*cmsg).cmsg_level;
        let ctype = (*cmsg).cmsg_type;
        if level == libc::IPPROTO_IP && ctype == libc::IP_TOS {
            // IPv4 delivers the DS field as a single byte.
            let tos = *libc::CMSG_DATA(cmsg);
            dscp = Some(tos >> 2);
        } else if level == libc::IPPROTO_IPV6 && ctype == libc::IPV6_TCLASS {
            // IPv6 delivers the traffic class as an int; take the low byte.
            let mut val: libc::c_int = 0;
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg),
                &mut val as *mut libc::c_int as *mut u8,
                std::mem::size_of::<libc::c_int>(),
            );
            dscp = Some(((val as u32 & 0xff) as u8) >> 2);
        }
        cmsg = libc::CMSG_NXTHDR(msg, cmsg);
    }
    dscp
}

/// Convert a kernel `sockaddr_storage` (as filled by `recvmsg`) into a Rust
/// [`SocketAddr`]. Returns `None` for address families other than IPv4/IPv6.
fn sockaddr_storage_to_socketaddr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::V4(std::net::SocketAddrV4::new(
                ip,
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// Apply egress DiffServ marking + scheduling priority to a socket in one call.
///
/// * `dscp = None` leaves the kernel default DS field untouched.
/// * `prio <= 0` leaves the default egress band.
///
/// Both underlying operations are best-effort (see [`set_dscp`] /
/// [`set_so_priority`]): a failure to mark never breaks the data path.
pub fn apply_egress_qos(fd: RawFd, dscp: Option<u8>, prio: i32, is_v6: bool) {
    if let Some(d) = dscp {
        set_dscp(fd, d, is_v6);
    }
    if prio > 0 {
        set_so_priority(fd, prio);
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

    poll_two_fds_once(fd_a, fd_b, timeout_ms)
}

/// Poll two fds with a short userspace spin phase before blocking.
///
/// Used by the latency profile to catch packets that arrive just after the relay
/// drains a direction, avoiding an avoidable scheduler sleep. The spin window is
/// bounded in microseconds and falls back to the regular blocking poll.
pub fn poll_two_fds_with_spin(
    fd_a: RawFd,
    fd_b: RawFd,
    tls_pending: usize,
    spin_us: u32,
    timeout_ms: i32,
) -> io::Result<(bool, bool)> {
    if tls_pending > 0 {
        return Ok((true, true));
    }
    if spin_us > 0 {
        let deadline = Instant::now() + Duration::from_micros(spin_us as u64);
        loop {
            let ready = poll_two_fds_once(fd_a, fd_b, 0)?;
            if ready.0 || ready.1 {
                return Ok(ready);
            }
            if Instant::now() >= deadline {
                break;
            }
            std::hint::spin_loop();
        }
    }

    poll_two_fds_once(fd_a, fd_b, timeout_ms)
}

fn poll_two_fds_once(fd_a: RawFd, fd_b: RawFd, timeout_ms: i32) -> io::Result<(bool, bool)> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::os::unix::net::UnixStream;

    /// Read back a socket option as a `c_int` for assertion in tests.
    fn getsockopt_int(fd: RawFd, level: libc::c_int, optname: libc::c_int) -> libc::c_int {
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                level,
                optname,
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(ret, 0, "getsockopt failed: {}", io::Error::last_os_error());
        val
    }

    #[test]
    fn dscp_to_tos_math() {
        assert_eq!(dscp_to_tos(0), 0);
        assert_eq!(dscp_to_tos(46), 184); // EF
        assert_eq!(dscp_to_tos(18), 72); // AF21
        assert_eq!(dscp_to_tos(48), 192); // CS6
        assert_eq!(dscp_to_tos(63), 252); // max
                                          // Values above 6 bits are masked, never bleeding into ECN.
        assert_eq!(dscp_to_tos(0xff), 252);
    }

    #[test]
    fn set_dscp_ipv4_roundtrip() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind v4");
        set_dscp(sock.as_raw_fd(), 46, false);
        let tos = getsockopt_int(sock.as_raw_fd(), libc::IPPROTO_IP, libc::IP_TOS);
        assert_eq!(tos, 184, "IPv4 IP_TOS should reflect EF (46 << 2)");
    }

    #[test]
    fn set_dscp_ipv6_roundtrip() {
        // IPv6 loopback may be unavailable in some CI sandboxes — skip gracefully.
        let sock = match UdpSocket::bind("[::1]:0") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping IPv6 DSCP test (no ::1): {e}");
                return;
            }
        };
        set_dscp(sock.as_raw_fd(), 46, true);
        let tclass = getsockopt_int(sock.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_TCLASS);
        assert_eq!(tclass, 184, "IPv6 IPV6_TCLASS should reflect EF (46 << 2)");
    }

    #[test]
    fn set_so_priority_roundtrip() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind v4");
        set_so_priority(sock.as_raw_fd(), 6);
        let prio = getsockopt_int(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PRIORITY);
        assert_eq!(prio, 6, "SO_PRIORITY should be 6 (highest unprivileged)");
    }

    #[test]
    fn set_notsent_lowat_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).expect("connect tcp");
        let (server, _) = listener.accept().expect("accept tcp");

        set_notsent_lowat(client.as_raw_fd(), 16 * 1024);
        let lowat = getsockopt_int(
            client.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_NOTSENT_LOWAT,
        );
        assert_eq!(lowat, 16 * 1024);

        drop(server);
    }

    #[test]
    fn poll_two_fds_with_spin_observes_ready_fd() {
        let (readable, mut peer) = UnixStream::pair().expect("pair a");
        let (idle, _idle_peer) = UnixStream::pair().expect("pair b");
        peer.write_all(b"x").expect("write readiness byte");

        let (a_ready, b_ready) =
            poll_two_fds_with_spin(readable.as_raw_fd(), idle.as_raw_fd(), 0, 50, 100)
                .expect("poll with spin");
        assert!(a_ready);
        assert!(!b_ready);
    }

    #[test]
    fn enable_recvtos_does_not_error() {
        // Smoke test: enabling RECVTOS must not panic and the option must stick.
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind v4");
        enable_recvtos(sock.as_raw_fd(), false);
        let on = getsockopt_int(sock.as_raw_fd(), libc::IPPROTO_IP, libc::IP_RECVTOS);
        assert_eq!(on, 1, "IP_RECVTOS should be enabled");
    }

    #[test]
    fn recvmsg_with_dscp_extracts_marking() {
        // Send a UDP datagram marked EF and confirm the receiver recovers DSCP 46.
        let rx = UdpSocket::bind("127.0.0.1:0").expect("bind rx");
        enable_recvtos(rx.as_raw_fd(), false);
        let rx_addr = rx.local_addr().unwrap();

        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind tx");
        set_dscp(tx.as_raw_fd(), 46, false);
        tx.send_to(b"ping", rx_addr).expect("send");

        let mut buf = [0u8; 64];
        let (n, dscp) = recvmsg_with_dscp(rx.as_raw_fd(), &mut buf).expect("recvmsg");
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(dscp, Some(46), "receiver should recover the EF marking");
    }
}
