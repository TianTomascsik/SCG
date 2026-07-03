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
    // SAFETY: `fd` is a caller-supplied socket descriptor; `&val` points to a live,
    // fully-initialised `c_int` whose byte length is passed as the option length, so
    // the kernel reads exactly `size_of::<c_int>()` valid bytes. Best-effort: the
    // return value is intentionally ignored.
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
    // SAFETY: `fd` is a caller-supplied socket descriptor; `&val` points to a live,
    // fully-initialised `c_int` whose byte length is passed as the option length, so
    // the kernel reads exactly `size_of::<c_int>()` valid bytes.
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
    // SAFETY: `fd` is a caller-supplied socket descriptor; `&val` points to a live,
    // fully-initialised `c_int` whose byte length is passed as the option length, so
    // the kernel reads exactly `size_of::<c_int>()` valid bytes.
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
    // SAFETY: `fd` is a caller-supplied socket descriptor; `&val` points to a live,
    // fully-initialised `c_int` whose byte length is passed as the option length, so
    // the kernel reads exactly `size_of::<c_int>()` valid bytes. Best-effort.
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
    // SAFETY: `fd` is a caller-supplied socket descriptor; `&val` points to a live,
    // fully-initialised `c_int` whose byte length is passed as the option length, so
    // the kernel reads exactly `size_of::<c_int>()` valid bytes. Best-effort.
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
    // SAFETY: `fd` is a caller-supplied socket descriptor; `&val` points to a live,
    // fully-initialised `c_int` whose byte length is passed as the option length, so
    // the kernel reads exactly `size_of::<c_int>()` valid bytes.
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
    // SAFETY: `fd` is a caller-supplied socket descriptor; `&tos` points to a live,
    // fully-initialised `c_int` whose byte length is passed as the option length, so
    // the kernel reads exactly `size_of::<c_int>()` valid bytes. Best-effort.
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
    // SAFETY: `fd` is a caller-supplied socket descriptor; `&val` points to a live,
    // fully-initialised `c_int` whose byte length is passed as the option length, so
    // the kernel reads exactly `size_of::<c_int>()` valid bytes. Best-effort.
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
        // SAFETY: `setpriority` is a thin libc syscall wrapper taking scalar
        // arguments (no pointers/buffers), so it cannot violate memory safety;
        // it adjusts the calling thread's nice value. Best-effort: the return
        // value is intentionally ignored (lowering nice needs CAP_SYS_NICE).
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
    // SAFETY: `fd` is a caller-supplied socket descriptor; `&on` points to a live,
    // fully-initialised `c_int` whose byte length is passed as the option length, so
    // the kernel reads exactly `size_of::<c_int>()` valid bytes. Best-effort.
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
    // SAFETY: `libc::msghdr` is a plain-old-data C struct for which an all-zero bit
    // pattern is a valid value; every field is explicitly overwritten below before use.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    // SAFETY: `fd` is a caller-supplied socket descriptor; `&mut msg` is a live,
    // fully-initialised `msghdr` whose `iov`/`control` buffers (`buf`, `cmsg_buf`)
    // outlive the call, and the return value is checked for error below.
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `recvmsg` succeeded, so `msg` is a fully-initialised `msghdr` and its
    // `cmsg_buf` control buffer is still alive in this scope, satisfying the contract
    // of `extract_dscp_cmsg`.
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
    // SAFETY: `sockaddr_storage` is a plain-old-data C struct sized to hold any
    // address family; an all-zero bit pattern is a valid value and the kernel fills
    // it during `recvmsg` (with `msg_namelen` set to its capacity below).
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut cmsg_buf = [0u8; 64];
    // SAFETY: `libc::msghdr` is a plain-old-data C struct for which an all-zero bit
    // pattern is a valid value; every field is explicitly overwritten below before use.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    // SAFETY: `fd` is a caller-supplied socket descriptor; `&mut msg` is a live,
    // fully-initialised `msghdr` whose `name`/`iov`/`control` buffers (`name`, `buf`,
    // `cmsg_buf`) outlive the call, and the return value is checked for error below.
    let n = unsafe { libc::recvmsg(fd, &mut msg, flags) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `recvmsg` succeeded, so `msg` is a fully-initialised `msghdr` and its
    // `cmsg_buf` control buffer is still alive in this scope, satisfying the contract
    // of `extract_dscp_cmsg`.
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
            // SAFETY: `ss_family` is `AF_INET`, so the kernel filled `storage` with a
            // `sockaddr_in`; `sockaddr_storage` is large enough and suitably aligned
            // for `sockaddr_in`, and the reference borrows the live `storage`.
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::V4(std::net::SocketAddrV4::new(
                ip,
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: `ss_family` is `AF_INET6`, so the kernel filled `storage` with a
            // `sockaddr_in6`; `sockaddr_storage` is large enough and suitably aligned
            // for `sockaddr_in6`, and the reference borrows the live `storage`.
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

/// Fill a `sockaddr_storage` from a Rust [`SocketAddr`], returning the address
/// length the kernel expects (`msg_namelen`). The inverse of
/// [`sockaddr_storage_to_socketaddr`].
fn fill_sockaddr_storage(
    addr: SocketAddr,
    storage: &mut libc::sockaddr_storage,
) -> libc::socklen_t {
    match addr {
        SocketAddr::V4(a) => {
            // SAFETY: `sockaddr_storage` is large enough and suitably aligned for
            // `sockaddr_in`; we write only the `sockaddr_in` fields through the
            // reborrowed pointer and return that struct's size as the length.
            let sin = unsafe { &mut *(storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = a.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(a.ip().octets()),
            };
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(a) => {
            // SAFETY: as above for `sockaddr_in6`.
            let sin6 = unsafe { &mut *(storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_flowinfo = a.flowinfo();
            sin6.sin6_scope_id = a.scope_id();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: a.ip().octets(),
            };
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

/// Largest datagram batch drained/flushed in a single `recvmmsg`/`sendmmsg`.
/// Amortises the per-datagram syscall on the UDP relay legs; matches SESHAT's
/// harness batch so a single connection can be driven and absorbed at the same
/// granularity.
pub const UDP_MMSG_BATCH: usize = 32;

/// Reusable receive state for batched UDP reads via `recvmmsg(2)`.
///
/// Owns `batch` fixed-size slots, so the buffers are allocated once per relay
/// connection (setup cost, not hot path); each [`recv`](MmsgRecvBuf::recv) fills
/// up to `batch` datagrams in one syscall. After a successful `recv` returning
/// `n`, the i-th datagram (`0 <= i < n`) is read with [`get`](MmsgRecvBuf::get),
/// which yields its source address (for the single-client source pin — TRA
/// #7/#39) and payload slice (length bounded by the slot, so a kernel-reported
/// `msg_len` can never index out of the allocation — TRA #16).
pub struct MmsgRecvBuf {
    batch: usize,
    slot_len: usize,
    data: Vec<u8>,
    names: Vec<libc::sockaddr_storage>,
    iovecs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
    lens: Vec<usize>,
    /// Datagram count from the most recent `recv`; bounds `get` (L35).
    last_n: usize,
}

impl MmsgRecvBuf {
    /// Allocate a batch buffer holding `batch` slots of `slot_len` bytes each.
    pub fn new(batch: usize, slot_len: usize) -> Self {
        let batch = batch.max(1);
        let slot_len = slot_len.max(1);
        Self {
            batch,
            slot_len,
            data: vec![0u8; batch * slot_len],
            // SAFETY: `sockaddr_storage`/`mmsghdr` are plain-old-data C structs for
            // which an all-zero bit pattern is valid; every field used is set in
            // `recv` before the syscall.
            names: vec![unsafe { std::mem::zeroed() }; batch],
            iovecs: vec![
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                };
                batch
            ],
            msgs: vec![unsafe { std::mem::zeroed() }; batch],
            lens: vec![0usize; batch],
            last_n: 0,
        }
    }

    /// Receive up to `batch` datagrams in one `recvmmsg`. Returns the count, or
    /// `0` on `WouldBlock`/`TimedOut`/`EINTR` so the caller's drain loop treats it
    /// as "no more data", exactly like the per-datagram `recv_from` it replaces.
    pub fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        let batch = self.batch;
        let slot_len = self.slot_len;
        let data_ptr = self.data.as_mut_ptr();
        let names_ptr = self.names.as_mut_ptr();
        let iov_ptr = self.iovecs.as_mut_ptr();
        for i in 0..batch {
            // SAFETY: `i < batch`; `data` holds `batch * slot_len` bytes so the
            // slot `[i*slot_len, (i+1)*slot_len)` is in bounds, and `iov_ptr`/
            // `names_ptr` index live `Vec`s of length `batch`. Each `mmsghdr`
            // points at its own slot and name buffer, all owned by `self` and
            // alive for the `recvmmsg` below.
            unsafe {
                *iov_ptr.add(i) = libc::iovec {
                    iov_base: data_ptr.add(i * slot_len) as *mut libc::c_void,
                    iov_len: slot_len,
                };
                let hdr = &mut (*self.msgs.as_mut_ptr().add(i)).msg_hdr;
                *hdr = std::mem::zeroed();
                hdr.msg_name = names_ptr.add(i) as *mut libc::c_void;
                hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                hdr.msg_iov = iov_ptr.add(i);
                hdr.msg_iovlen = 1;
                (*self.msgs.as_mut_ptr().add(i)).msg_len = 0;
            }
        }

        // SAFETY: `self.msgs` is a live array of `batch` initialised `mmsghdr`
        // whose `name`/`iov` buffers (`names`, `data`) outlive the call; `batch`
        // matches the array length; flags `0`, NULL timeout. The return is checked
        // below before any `msg_len` is read.
        let ret = unsafe {
            libc::recvmmsg(
                fd,
                self.msgs.as_mut_ptr(),
                batch as libc::c_uint,
                0,
                std::ptr::null_mut(),
            )
        };
        if ret < 0 {
            let e = io::Error::last_os_error();
            return match e.kind() {
                io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::Interrupted => Ok(0),
                _ => Err(e),
            };
        }
        let n = (ret as usize).min(batch);
        for i in 0..n {
            // Clamp the kernel-reported length to the slot capacity: a received
            // datagram never exceeds the slot it was read into, and clamping makes
            // the later slice index infallible (no narrowing, no overflow — #16).
            self.lens[i] = (self.msgs[i].msg_len as usize).min(slot_len);
        }
        self.last_n = n;
        Ok(n)
    }

    /// Source address + payload of the `i`-th datagram from the last `recv`,
    /// or `None` when `i` is beyond that recv's count (L35).
    ///
    /// Total over `i`: an out-of-range index returns `None` instead of panicking
    /// (`i >= batch`) or silently returning a previous batch's leftover
    /// address/payload (`last_n <= i < batch`) — the latter would misattribute
    /// a datagram to the wrong source, which the single-client source pin
    /// (TRA #7/#39) keys off.
    pub fn get(&self, i: usize) -> Option<(Option<SocketAddr>, &[u8])> {
        if i >= self.last_n {
            return None;
        }
        let len = self.lens[i].min(self.slot_len);
        let off = i * self.slot_len;
        let payload = &self.data[off..off + len];
        Some((sockaddr_storage_to_socketaddr(&self.names[i]), payload))
    }
}

/// Reusable send state for batched UDP writes via `sendmmsg(2)`.
///
/// Datagrams are staged (copied) into a contiguous buffer with [`push`](Self::push),
/// then flushed in one syscall with [`flush`](Self::flush). The copy is needed because the framer
/// hands out transient borrowed slices (an ALE reassembly buffer reused per
/// frame); copying post-decrypt plaintext is far cheaper than a syscall per
/// datagram.
pub struct MmsgSendBuf {
    staging: Vec<u8>,
    spans: Vec<(usize, usize)>,
    iovecs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
}

impl Default for MmsgSendBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl MmsgSendBuf {
    pub fn new() -> Self {
        Self {
            staging: Vec::with_capacity(UDP_MMSG_BATCH * 2048),
            spans: Vec::with_capacity(UDP_MMSG_BATCH),
            iovecs: Vec::with_capacity(UDP_MMSG_BATCH),
            msgs: Vec::with_capacity(UDP_MMSG_BATCH),
        }
    }

    /// Stage one datagram (copied) for the next [`flush`](Self::flush).
    pub fn push(&mut self, datagram: &[u8]) {
        let off = self.staging.len();
        self.staging.extend_from_slice(datagram);
        self.spans.push((off, datagram.len()));
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub fn len(&self) -> usize {
        self.spans.len()
    }

    fn clear(&mut self) {
        self.staging.clear();
        self.spans.clear();
    }

    /// Send all staged datagrams in one `sendmmsg`, then clear the buffer.
    /// `dst = Some(addr)` for an unconnected socket; `None` for a connected one.
    /// Returns the number of datagrams the kernel accepted. `WouldBlock`/`EINTR`
    /// map to `Ok(0)` — a momentarily full `SO_SNDBUF` drops the batch rather than
    /// aborting the relay, matching the best-effort single `send` it replaces.
    pub fn flush(&mut self, fd: RawFd, dst: Option<SocketAddr>) -> io::Result<usize> {
        if self.spans.is_empty() {
            return Ok(0);
        }
        let n = self.spans.len();
        let base = self.staging.as_ptr();

        // Destination address shared by every message (NULL for connected sockets).
        // SAFETY: zeroed `sockaddr_storage` is valid POD; `fill_sockaddr_storage`
        // initialises exactly the address family written.
        let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let (name_ptr, name_len) = match dst {
            Some(addr) => {
                let len = fill_sockaddr_storage(addr, &mut name);
                (&mut name as *mut _ as *mut libc::c_void, len)
            }
            None => (std::ptr::null_mut(), 0),
        };

        self.iovecs.clear();
        for &(off, len) in &self.spans {
            // SAFETY: `off + len <= staging.len()` by construction in `push`, so
            // the slice `[off, off+len)` is within the live `staging` allocation.
            self.iovecs.push(libc::iovec {
                iov_base: unsafe { base.add(off) } as *mut libc::c_void,
                iov_len: len,
            });
        }
        let iov_ptr = self.iovecs.as_mut_ptr();
        self.msgs.clear();
        for i in 0..n {
            // SAFETY: `libc::msghdr` POD; all used fields set here. `iov_ptr.add(i)`
            // indexes the live `iovecs` (length `n`); `name`/`staging` outlive the
            // syscall below.
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_name = name_ptr;
            hdr.msg_namelen = name_len;
            hdr.msg_iov = unsafe { iov_ptr.add(i) };
            hdr.msg_iovlen = 1;
            self.msgs.push(libc::mmsghdr {
                msg_hdr: hdr,
                msg_len: 0,
            });
        }

        // SAFETY: `self.msgs` is a live array of `n` initialised `mmsghdr` whose
        // iov/name buffers outlive the call; `n` matches the array length; flags 0.
        let ret = unsafe { libc::sendmmsg(fd, self.msgs.as_mut_ptr(), n as libc::c_uint, 0) };
        let result = if ret < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(0),
                _ => Err(e),
            }
        } else {
            Ok(ret as usize)
        };
        self.clear();
        result
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
    // SAFETY: `fcntl` is a libc syscall taking scalar arguments only (no buffers),
    // so it cannot violate memory safety; `fd` is a caller-supplied descriptor and
    // `F_GETFL`/`F_SETFL` merely read and rewrite the descriptor's status flags.
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
    // Clamp rather than truncate: a timeout exceeding i32::MAX milliseconds would
    // wrap to a negative value and make `poll` block indefinitely.
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: `pfd` is a valid, fully-initialised `pollfd` for one descriptor; we
    // pass `nfds = 1` matching the single-element buffer and a valid timeout.
    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        // EINTR is a benign wakeup — treat like a timeout so the caller loops.
        // Any other hard error is surfaced (L18) instead of being reported as a
        // timeout, which would otherwise let a persistent poll failure (e.g.
        // EBADF from an fd lifecycle bug) become a silent 100%-CPU spin.
        if err.kind() == io::ErrorKind::Interrupted {
            return None;
        }
        return Some(Err(err));
    }
    if pfd.revents & libc::POLLNVAL != 0 {
        return Some(Err(io::Error::from_raw_os_error(libc::EBADF)));
    }
    if ret > 0 && (pfd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP)) != 0 {
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
        match bind_retry_addr_in_use(|| TcpListener::bind(addr)) {
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

/// Retry a bind briefly while it fails with `AddrInUse`, so a hot-reload restart
/// of a changed rule can rebind a port the previous (non-`SO_REUSEADDR`) listener
/// is still releasing. Other errors fail immediately. ~2 s total before giving up.
fn bind_retry_addr_in_use<T, F: Fn() -> io::Result<T>>(bind: F) -> io::Result<T> {
    const ATTEMPTS: u32 = 20;
    const DELAY: Duration = Duration::from_millis(100);
    let mut last: Option<io::Error> = None;
    for _ in 0..ATTEMPTS {
        match bind() {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                last = Some(e);
                std::thread::sleep(DELAY);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrInUse, "bind retries exhausted")))
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
        match bind_retry_addr_in_use(|| UdpSocket::bind(addr)) {
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

    // SAFETY: `fds` is a live, fully-initialised two-element `pollfd` array; we pass
    // `nfds = 2` matching its length and a valid timeout, so `poll` reads/writes only
    // those two entries. The return value is checked below.
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

    // Include POLLERR/POLLNVAL, not just POLLIN/POLLHUP (H6): the kernel
    // reports error conditions regardless of the requested `events`, and on a
    // connected UDP socket a pending ICMP error (e.g. port-unreachable) sets
    // POLLERR until a recv/send clears it. Reporting the fd as ready lets the
    // caller's next read surface the error and tear down, instead of poll()
    // returning immediately every iteration → a 100%-CPU busy-spin.
    let mask = libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL;
    let a_ready = fds[0].revents & mask != 0;
    let b_ready = fds[1].revents & mask != 0;
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
    // SAFETY: `pfd` is a live, fully-initialised `pollfd` for one descriptor; we pass
    // `nfds = 1` matching the single-element buffer and a valid timeout, so `poll`
    // reads/writes only that entry. The return value is checked below.
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
        // SAFETY: `fd` is a valid open socket descriptor; `&mut val`/`&mut len` point to
        // a live `c_int` and `socklen_t`, with `len` initialised to the buffer's byte
        // size so the kernel writes at most `size_of::<c_int>()` valid bytes. The
        // return value is asserted to be 0 below.
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

    /// `recvmmsg` must surface each datagram's own source address — the basis for
    /// the per-datagram single-client source pin (TRA #7/#39). Two distinct
    /// senders into one unconnected socket must come back tagged with their
    /// respective sources and verbatim payloads.
    #[test]
    fn mmsg_recv_reports_per_datagram_source_and_payload() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let rx_addr = rx.local_addr().unwrap();

        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.send_to(b"a0", rx_addr).unwrap();
        a.send_to(b"a1", rx_addr).unwrap();
        b.send_to(b"b0", rx_addr).unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        let mut buf = MmsgRecvBuf::new(8, 2048);
        // Collect up to 3 datagrams across a few drain iterations (loopback
        // delivery is immediate but not strictly synchronous).
        let mut got: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        for _ in 0..100 {
            let n = buf.recv(rx.as_raw_fd()).unwrap();
            for i in 0..n {
                let (src, payload) = buf.get(i).expect("i < n is in range");
                got.push((src.expect("ipv4 source"), payload.to_vec()));
            }
            if got.len() >= 3 {
                break;
            }
        }
        assert_eq!(got.len(), 3, "all three datagrams received");
        let from_a: Vec<&[u8]> = got
            .iter()
            .filter(|(s, _)| *s == a_addr)
            .map(|(_, p)| p.as_slice())
            .collect();
        let from_b: Vec<&[u8]> = got
            .iter()
            .filter(|(s, _)| *s == b_addr)
            .map(|(_, p)| p.as_slice())
            .collect();
        assert_eq!(from_a, vec![b"a0".as_ref(), b"a1".as_ref()]);
        assert_eq!(from_b, vec![b"b0".as_ref()]);
    }

    /// A datagram larger than the slot must be clamped to the slot length — never
    /// indexed out of the allocation (TRA #16 / no narrowing).
    #[test]
    fn mmsg_recv_clamps_oversized_datagram_to_slot() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(&[0xABu8; 1000], rx_addr).unwrap();

        let mut buf = MmsgRecvBuf::new(4, 16);
        let mut len = 0;
        for _ in 0..100 {
            let n = buf.recv(rx.as_raw_fd()).unwrap();
            if n > 0 {
                len = buf.get(0).expect("first datagram present").1.len();
                break;
            }
        }
        assert_eq!(len, 16, "oversized datagram clamped to the 16-byte slot");
    }

    // L35: `get` is total — an index beyond the last recv's count returns None
    // instead of panicking or handing back a previous batch's stale data.
    #[test]
    fn mmsg_get_beyond_last_n_is_none() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"one", rx_addr).unwrap();

        let mut buf = MmsgRecvBuf::new(8, 2048);
        let mut n = 0;
        for _ in 0..100 {
            n = buf.recv(rx.as_raw_fd()).unwrap();
            if n > 0 {
                break;
            }
        }
        assert_eq!(n, 1);
        assert!(buf.get(0).is_some());
        // Index within the allocation but beyond this recv's count → None,
        // never the previous batch's leftover source/payload.
        assert!(buf.get(1).is_none());
        assert!(buf.get(7).is_none());
        // Index beyond the allocation → None (no panic).
        assert!(buf.get(999).is_none());
    }

    // L35: a fresh buffer (no recv yet) yields None for any index.
    #[test]
    fn mmsg_get_before_first_recv_is_none() {
        let buf = MmsgRecvBuf::new(4, 64);
        assert!(buf.get(0).is_none());
    }

    /// `sendmmsg` must deliver every staged datagram to the connected peer in
    /// order.
    #[test]
    fn mmsg_send_batch_delivers_all() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(rx_addr).unwrap();

        let mut sb = MmsgSendBuf::new();
        sb.push(b"one");
        sb.push(b"two");
        sb.push(b"three");
        assert_eq!(sb.len(), 3);
        let sent = sb.flush(tx.as_raw_fd(), None).unwrap();
        assert_eq!(sent, 3, "all three datagrams accepted by the kernel");
        assert!(sb.is_empty(), "flush clears the staging buffer");

        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut scratch = [0u8; 64];
        for _ in 0..100 {
            if let Ok(n) = rx.recv(&mut scratch) {
                seen.push(scratch[..n].to_vec());
            }
            if seen.len() >= 3 {
                break;
            }
        }
        assert_eq!(
            seen,
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );
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
