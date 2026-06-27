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

/// Recover the original destination address for a TCP connection that was
/// redirected via TPROXY or REDIRECT/DNAT.
///
/// Works on accepted TCP sockets — call on the fd returned by `accept()`.
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

    // Create raw socket to set options before bind
    // SAFETY: `libc::socket` takes only integer arguments and never dereferences a
    // pointer; the returned fd is validated (`fd < 0`) before any further use.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SO_REUSEADDR
    let one: libc::c_int = 1;
    // SAFETY: `fd` is the valid socket created above; `&one` points to a
    // fully-initialised `c_int` whose size is passed as the option length, so the
    // pointer/len pair are consistent.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // IP_TRANSPARENT — must be set before bind
    if let Err(e) = set_ip_transparent(fd) {
        // SAFETY: `fd` is the valid open socket created above and is not used again
        // on this error path, so closing it exactly once is sound.
        unsafe {
            libc::close(fd);
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("IP_TRANSPARENT failed (need CAP_NET_ADMIN): {}", e),
        ));
    }

    // Bind
    let sa = match sock_addr {
        SocketAddr::V4(v4) => {
            // SAFETY: `libc::sockaddr_in` is a plain-old-data C struct for which an
            // all-zero bit pattern is a valid initialised value; the fields are then set.
            let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
            sin
        }
        _ => {
            // SAFETY: `fd` is the valid open socket created above and is not used again
            // on this error path, so closing it exactly once is sound.
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Only IPv4 supported for TPROXY",
            ));
        }
    };

    // SAFETY: `fd` is the valid socket created above; `&sa` points to a
    // fully-initialised `sockaddr_in` and its size is passed as the address length,
    // so the kernel reads exactly a valid `sockaddr`. The return value is checked below.
    let ret = unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: `fd` is the valid open socket created above and is not used again
        // on this error path, so closing it exactly once is sound.
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    // Listen
    // SAFETY: `fd` is the valid, bound socket created above; `libc::listen` takes only
    // integer arguments and never dereferences a pointer. The return value is checked below.
    let ret = unsafe { libc::listen(fd, 128) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: `fd` is the valid open socket created above and is not used again
        // on this error path, so closing it exactly once is sound.
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    // Convert to std TcpListener
    use std::os::unix::io::FromRawFd;
    // SAFETY: `fd` is a valid open socket created above and not used afterwards, so
    // ownership can be transferred to `TcpListener`, which becomes its sole owner and
    // will close it on drop.
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    Ok(listener)
}

/// Create a UDP socket with `IP_TRANSPARENT` and `IP_RECVORIGDSTADDR` set.
pub fn create_transparent_udp_socket(addr: &str) -> io::Result<UdpSocket> {
    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // SAFETY: `libc::socket` takes only integer arguments and never dereferences a
    // pointer; the returned fd is validated (`fd < 0`) before any further use.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let one: libc::c_int = 1;
    // SAFETY: `fd` is the valid socket created above; `&one` points to a
    // fully-initialised `c_int` whose size is passed as the option length, so the
    // pointer/len pair are consistent.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    if let Err(e) = set_ip_transparent(fd) {
        // SAFETY: `fd` is the valid open socket created above and is not used again
        // on this error path, so closing it exactly once is sound.
        unsafe {
            libc::close(fd);
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("IP_TRANSPARENT failed (need CAP_NET_ADMIN): {}", e),
        ));
    }

    if let Err(e) = enable_recvorigdstaddr(fd) {
        // SAFETY: `fd` is the valid open socket created above and is not used again
        // on this error path, so closing it exactly once is sound.
        unsafe {
            libc::close(fd);
        }
        return Err(io::Error::other(
            format!("IP_RECVORIGDSTADDR failed: {}", e),
        ));
    }

    let sa = match sock_addr {
        SocketAddr::V4(v4) => {
            // SAFETY: `libc::sockaddr_in` is a plain-old-data C struct for which an
            // all-zero bit pattern is a valid initialised value; the fields are then set.
            let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
            sin
        }
        _ => {
            // SAFETY: `fd` is the valid open socket created above and is not used again
            // on this error path, so closing it exactly once is sound.
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Only IPv4 supported for TPROXY",
            ));
        }
    };

    // SAFETY: `fd` is the valid socket created above; `&sa` points to a
    // fully-initialised `sockaddr_in` and its size is passed as the address length,
    // so the kernel reads exactly a valid `sockaddr`. The return value is checked below.
    let ret = unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: `fd` is the valid open socket created above and is not used again
        // on this error path, so closing it exactly once is sound.
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    use std::os::unix::io::FromRawFd;
    // SAFETY: `fd` is a valid open socket created above and not used afterwards, so
    // ownership can be transferred to `UdpSocket`, which becomes its sole owner and
    // will close it on drop.
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };
    Ok(socket)
}
