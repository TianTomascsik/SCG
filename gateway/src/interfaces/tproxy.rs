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
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

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
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SO_REUSEADDR
    let one: libc::c_int = 1;
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
            let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
            sin
        }
        _ => {
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Only IPv4 supported for TPROXY",
            ));
        }
    };

    let ret = unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    // Listen
    let ret = unsafe { libc::listen(fd, 128) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    // Convert to std TcpListener
    use std::os::unix::io::FromRawFd;
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    Ok(listener)
}

/// Create a UDP socket with `IP_TRANSPARENT` and `IP_RECVORIGDSTADDR` set.
pub fn create_transparent_udp_socket(addr: &str) -> io::Result<UdpSocket> {
    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let one: libc::c_int = 1;
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
        unsafe {
            libc::close(fd);
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("IP_TRANSPARENT failed (need CAP_NET_ADMIN): {}", e),
        ));
    }

    if let Err(e) = enable_recvorigdstaddr(fd) {
        unsafe {
            libc::close(fd);
        }
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("IP_RECVORIGDSTADDR failed: {}", e),
        ));
    }

    let sa = match sock_addr {
        SocketAddr::V4(v4) => {
            let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
            sin
        }
        _ => {
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Only IPv4 supported for TPROXY",
            ));
        }
    };

    let ret = unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    use std::os::unix::io::FromRawFd;
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };
    Ok(socket)
}
