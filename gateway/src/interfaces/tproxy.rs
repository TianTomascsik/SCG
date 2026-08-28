//! TPROXY transparent proxy support.
//!
//! Provides helpers for:
//! - Setting `IP_TRANSPARENT` on sockets (allows binding to non-local addresses)
//! - Recovering the original destination via `SO_ORIGINAL_DST` (TCP)
//! - Setting up `IP_RECVORIGDSTADDR` and parsing cmsg for UDP
//! - Creating transparent TCP listeners
//!
//! Requires `CAP_NET_ADMIN` + `CAP_NET_RAW` (or root).

use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::io::RawFd;

// ─── Linux constants not in libc crate ───────────────────────────────────────

/// `IP_TRANSPARENT` — allows binding to non-local addresses (TPROXY).
const IP_TRANSPARENT: libc::c_int = 19;

/// `SO_ORIGINAL_DST` — recovers the original destination of a redirected connection.
const SO_ORIGINAL_DST: libc::c_int = 80;

/// `IP_RECVORIGDSTADDR` — enables receiving original destination in UDP cmsg.
const IP_RECVORIGDSTADDR: libc::c_int = 20;

// ─── Socket options ──────────────────────────────────────────────────────────

/// Set `IP_TRANSPARENT` on a socket, allowing it to accept TPROXY-redirected
/// connections and bind to non-local addresses.
///
/// # Safety
/// Requires `CAP_NET_ADMIN` capability.
pub fn set_ip_transparent(fd: RawFd) -> io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: `fd` is a socket descriptor supplied by the caller; `&one` points to a
    // fully-initialised `c_int` whose size is passed as the option length, so the
    // pointer/len pair are consistent. The return value is checked below.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_TRANSPARENT,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Set an integer socket option, returning an error on failure so transparent
/// socket setup checks each `setsockopt` result instead of ignoring it (L30).
fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    val: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `fd` is a valid socket descriptor; `&val` points to a
    // fully-initialised `c_int` whose size is passed as the option length, so
    // the pointer/len pair are consistent. The return value is checked below.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &val as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Recover the original destination of a **REDIRECT/DNAT**-redirected TCP
/// connection via the conntrack `SO_ORIGINAL_DST` sockopt.
///
/// This is REDIRECT/DNAT-only: for a true `-j TPROXY` flow the sockopt returns
/// `ENOENT` and the original destination must come from `getsockname()` on the
/// `IP_TRANSPARENT`-accepted socket instead. Use
/// [`recover_transparent_dst`] to handle both cases (it falls back to
/// `getsockname` and fails closed). Call on the fd returned by `accept()`.
pub fn get_original_dst(fd: RawFd) -> io::Result<SocketAddr> {
    // SAFETY: `libc::sockaddr_in` is a plain-old-data C struct for which an
    // all-zero bit pattern is a valid initialised value.
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    // SAFETY: `fd` is a socket descriptor supplied by the caller; `&mut addr` points
    // to a fully-allocated `sockaddr_in` and `len` holds its size, so the kernel
    // writes at most `len` bytes into a valid buffer. The return value is checked below.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

/// Recover the original destination of a transparent (TPROXY *or* REDIRECT/DNAT)
/// TCP connection from the accepted socket `fd`, or `None` when it cannot be
/// determined — in which case the caller MUST fail closed (drop the
/// connection) rather than forward to a default and bypass the destination
/// policy (TRA #59).
///
/// Recovery order:
/// * `SO_ORIGINAL_DST` first — the conntrack pre-translation destination for
///   REDIRECT/DNAT (`getsockname` cannot see it: the kernel rewrote the local
///   address).
/// * else `getsockname` on the `IP_TRANSPARENT` socket — for a TPROXY-redirected
///   connection its local address *is* the original destination. A local port
///   equal to `listen_port` marks a direct (non-redirected) connection that
///   carries no original-destination info → `None`.
pub fn recover_transparent_dst(fd: RawFd, listen_port: Option<u16>) -> Option<SocketAddr> {
    let so_orig = get_original_dst(fd).ok();
    let local = local_addr_of(fd);
    transparent_target(so_orig, local, listen_port)
}

/// Pure decision core of [`recover_transparent_dst`] (unit-testable without a
/// socket): pick the original destination from the `SO_ORIGINAL_DST` result and
/// the accepted socket's local address.
fn transparent_target(
    so_original_dst: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    listen_port: Option<u16>,
) -> Option<SocketAddr> {
    // REDIRECT/DNAT: conntrack returns the pre-translation destination.
    if let Some(orig) = so_original_dst {
        return Some(orig);
    }
    // TPROXY: the transparent socket's local address is the original dst — but a
    // local port equal to the listener's own marks a direct connection with
    // nothing to recover (fail closed).
    let local = local_addr?;
    match listen_port {
        Some(p) if local.port() != p => Some(local),
        _ => None,
    }
}

/// `getsockname(fd)` as a `SocketAddr` (IPv4/IPv6), or `None` on error.
fn local_addr_of(fd: RawFd) -> Option<SocketAddr> {
    // SAFETY: `sockaddr_storage` is plain-old-data; an all-zero bit pattern is a
    // valid initialised value large enough for any address family.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `fd` is a socket descriptor; `&mut storage`/`&mut len` describe a
    // buffer of exactly `len` bytes that the kernel writes at most `len` bytes
    // into and updates `len` in place. The return value is checked below.
    let ret =
        unsafe { libc::getsockname(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len) };
    if ret != 0 {
        return None;
    }
    sockaddr_storage_to_addr(&storage)
}

/// Convert a populated `sockaddr_storage` (AF_INET/AF_INET6) to a `SocketAddr`.
fn sockaddr_storage_to_addr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: the family is AF_INET, so the storage holds a valid,
            // fully-initialised `sockaddr_in` (a prefix of `sockaddr_storage`).
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: the family is AF_INET6, so the storage holds a valid,
            // fully-initialised `sockaddr_in6`.
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

/// Enable `IP_RECVORIGDSTADDR` on a UDP socket so that `recvmsg()` returns
/// the original destination address in ancillary data.
pub fn enable_recvorigdstaddr(fd: RawFd) -> io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: `fd` is a socket descriptor supplied by the caller; `&one` points to a
    // fully-initialised `c_int` whose size is passed as the option length, so the
    // pointer/len pair are consistent. The return value is checked below.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_RECVORIGDSTADDR,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ─── Transparent TCP listener ────────────────────────────────────────────────

/// Create a TCP listener with `IP_TRANSPARENT` set, suitable for TPROXY.
///
/// The listener can accept connections destined for any IP address (not just
/// addresses bound to this host).
pub fn create_transparent_tcp_listener(addr: &str) -> io::Result<TcpListener> {
    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let SocketAddr::V4(v4) = sock_addr else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Only IPv4 supported for TPROXY",
        ));
    };

    // Create raw socket to set options before bind
    // SAFETY: `libc::socket` takes only integer arguments and never dereferences a
    // pointer; the returned fd is validated (`fd < 0`) before any further use.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Own the fd immediately (L30): every early return below now drops `owned`,
    // which closes the socket — no hand-written `libc::close` per error path.
    // SAFETY: `fd` is a fresh, exclusively-owned socket descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let fd = owned.as_raw_fd();

    // SO_REUSEADDR (checked, L30).
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;

    // IP_TRANSPARENT — must be set before bind.
    set_ip_transparent(fd).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("IP_TRANSPARENT failed (need CAP_NET_ADMIN): {}", e),
        )
    })?;

    // Bind.
    // SAFETY: `libc::sockaddr_in` is plain-old-data (all-zero is valid); fields set below.
    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = v4.port().to_be();
    sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
    // SAFETY: `fd` is the valid socket; `&sin` is a fully-initialised `sockaddr_in`
    // whose size is passed as the address length. The return value is checked below.
    let ret = unsafe {
        libc::bind(
            fd,
            &sin as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    // Listen.
    // SAFETY: `fd` is the valid, bound socket; `libc::listen` takes only integer
    // arguments. The return value is checked below.
    let ret = unsafe { libc::listen(fd, 128) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    // Hand the owned descriptor to the std listener (no raw close race).
    Ok(TcpListener::from(owned))
}

/// Create a UDP socket with `IP_TRANSPARENT` and `IP_RECVORIGDSTADDR` set.
pub fn create_transparent_udp_socket(addr: &str) -> io::Result<UdpSocket> {
    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let SocketAddr::V4(v4) = sock_addr else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Only IPv4 supported for TPROXY",
        ));
    };

    // SAFETY: `libc::socket` takes only integer arguments and never dereferences a
    // pointer; the returned fd is validated (`fd < 0`) before any further use.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Own the fd immediately (L30): every early return below drops `owned`,
    // closing the socket — no hand-written `libc::close` per error path.
    // SAFETY: `fd` is a fresh, exclusively-owned socket descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let fd = owned.as_raw_fd();

    // SO_REUSEADDR (checked, L30).
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;

    set_ip_transparent(fd).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("IP_TRANSPARENT failed (need CAP_NET_ADMIN): {}", e),
        )
    })?;
    enable_recvorigdstaddr(fd)
        .map_err(|e| io::Error::other(format!("IP_RECVORIGDSTADDR failed: {}", e)))?;

    // SAFETY: `libc::sockaddr_in` is plain-old-data (all-zero is valid); fields set below.
    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = v4.port().to_be();
    sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
    // SAFETY: `fd` is the valid socket; `&sin` is a fully-initialised `sockaddr_in`
    // whose size is passed as the address length. The return value is checked below.
    let ret = unsafe {
        libc::bind(
            fd,
            &sin as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(UdpSocket::from(owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    // Original-destination recovery decision core.
    #[test]
    fn redirect_uses_so_original_dst() {
        // REDIRECT/DNAT: SO_ORIGINAL_DST wins regardless of the local address.
        let orig = sa("10.0.0.9:443");
        assert_eq!(
            transparent_target(Some(orig), Some(sa("127.0.0.1:20002")), Some(20002)),
            Some(orig)
        );
    }

    #[test]
    fn tproxy_recovers_original_dst_from_local_addr() {
        // TPROXY: no SO_ORIGINAL_DST; the transparent socket's local addr (a
        // port other than the listener's) is the original destination.
        let local = sa("127.0.0.1:20001");
        assert_eq!(
            transparent_target(None, Some(local), Some(20002)),
            Some(local)
        );
    }

    #[test]
    fn direct_connection_fails_closed() {
        // Local port == listener port → direct connection, nothing to recover.
        assert_eq!(
            transparent_target(None, Some(sa("127.0.0.1:20002")), Some(20002)),
            None
        );
        // Unknown listener port, or no local address → not recoverable.
        assert_eq!(
            transparent_target(None, Some(sa("127.0.0.1:20001")), None),
            None
        );
        assert_eq!(transparent_target(None, None, Some(20002)), None);
    }
}
