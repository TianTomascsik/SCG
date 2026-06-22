//! Test-only QoS plumbing for the WP7 DSCP integration tests.
//!
//! Provides loopback echo backends that record the DiffServ (DSCP) value of the
//! traffic they receive, so a test can assert what the gateway marked on its
//! upstream egress socket. Both reuse the gateway's own public socket helpers
//! ([`enable_recvtos`] + `recvmsg`-with-DSCP) so the test reads the DS field the
//! same way production code samples it.
//!
//! Everything runs unprivileged on loopback (IPv4 `127.0.0.1` or IPv6 `::1`).

#![allow(dead_code)]

use std::io;
use std::net::{TcpListener, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use gateway::networking::socket_manager::{
    enable_recvtos, recvmsg_from_with_dscp, recvmsg_with_dscp, set_dscp,
};

/// Set the egress DSCP (0..=63) on a socket fd for the given address family.
/// Thin wrapper over the gateway helper so tests can mark a client socket.
pub fn mark_socket_dscp(fd: std::os::unix::io::RawFd, dscp: u8, is_v6: bool) {
    set_dscp(fd, dscp, is_v6);
}

/// A plain-UDP echo backend that records the DSCP of the datagrams it receives.
///
/// Used as the upstream behind a gateway **decrypt** / **DTLS-decrypt** rule:
/// the gateway forwards decrypted datagrams here, and [`last_dscp`] reports the
/// DS field the gateway stamped on its upstream socket.
pub struct DscpUdpSink {
    pub addr: String,
    last_dscp: Arc<Mutex<Option<u8>>>,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl DscpUdpSink {
    /// Bind on `bind_addr` (e.g. `"127.0.0.1:0"` or `"[::1]:0"`) and echo every
    /// datagram, recording its DSCP.
    pub fn start(bind_addr: &str) -> DscpUdpSink {
        let sock = UdpSocket::bind(bind_addr).expect("bind dscp udp sink");
        let local = sock.local_addr().expect("udp sink local_addr");
        let addr = local.to_string();
        let is_v6 = local.is_ipv6();
        sock.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        enable_recvtos(sock.as_raw_fd(), is_v6);

        let last_dscp = Arc::new(Mutex::new(None));
        let last_w = last_dscp.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = shutdown.clone();
        let handle = thread::spawn(move || {
            let fd = sock.as_raw_fd();
            let mut buf = [0u8; 2048];
            while !sd.load(Ordering::Relaxed) {
                match recvmsg_from_with_dscp(fd, &mut buf) {
                    Ok((n, peer, dscp)) => {
                        if let Some(d) = dscp {
                            *last_w.lock().unwrap() = Some(d);
                        }
                        let _ = sock.send_to(&buf[..n], peer);
                    }
                    Err(ref e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue
                    }
                    Err(_) => continue,
                }
            }
        });

        DscpUdpSink {
            addr,
            last_dscp,
            shutdown,
            handle: Some(handle),
        }
    }

    /// The DSCP of the most recently received datagram, if any was sampled.
    pub fn last_dscp(&self) -> Option<u8> {
        *self.last_dscp.lock().unwrap()
    }
}

impl Drop for DscpUdpSink {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// A plain-TCP echo backend that records the DSCP of the segments it receives.
///
/// Used as the upstream behind a gateway **routing** / **decrypt** TCP rule.
pub struct DscpTcpSink {
    pub addr: String,
    last_dscp: Arc<Mutex<Option<u8>>>,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl DscpTcpSink {
    /// Bind on `bind_addr` (e.g. `"127.0.0.1:0"` or `"[::1]:0"`) and echo every
    /// accepted connection, recording the DSCP of its inbound segments.
    pub fn start(bind_addr: &str) -> DscpTcpSink {
        let listener = TcpListener::bind(bind_addr).expect("bind dscp tcp sink");
        let local = listener.local_addr().expect("tcp sink local_addr");
        let addr = local.to_string();
        let is_v6 = local.is_ipv6();
        listener.set_nonblocking(true).unwrap();
        // Enable TOS sampling on the *listener* so accepted sockets inherit it
        // at creation — otherwise the first data segment can be queued before
        // `IP_RECVTOS` is set on the accepted fd and its cmsg is lost.
        enable_recvtos(listener.as_raw_fd(), is_v6);

        let last_dscp = Arc::new(Mutex::new(None));
        let last_w = last_dscp.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = shutdown.clone();
        let handle = thread::spawn(move || {
            while !sd.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _peer)) => {
                        stream.set_nonblocking(false).ok();
                        stream
                            .set_read_timeout(Some(Duration::from_millis(300)))
                            .ok();
                        let fd = stream.as_raw_fd();
                        enable_recvtos(fd, is_v6);
                        let conn_sd = sd.clone();
                        let last_c = last_w.clone();
                        thread::spawn(move || {
                            let stream = stream;
                            let fd = stream.as_raw_fd();
                            let mut buf = [0u8; 16 * 1024];
                            loop {
                                if conn_sd.load(Ordering::Relaxed) {
                                    break;
                                }
                                match recvmsg_with_dscp(fd, &mut buf) {
                                    Ok((0, _)) => break,
                                    Ok((n, dscp)) => {
                                        if let Some(d) = dscp {
                                            *last_c.lock().unwrap() = Some(d);
                                        }
                                        let sent = unsafe {
                                            libc::send(
                                                fd,
                                                buf.as_ptr() as *const libc::c_void,
                                                n,
                                                0,
                                            )
                                        };
                                        if sent < 0 {
                                            break;
                                        }
                                    }
                                    Err(ref e)
                                        if e.kind() == io::ErrorKind::WouldBlock
                                            || e.kind() == io::ErrorKind::TimedOut =>
                                    {
                                        continue
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        DscpTcpSink {
            addr,
            last_dscp,
            shutdown,
            handle: Some(handle),
        }
    }

    /// The DSCP of the most recently received segment, if any was sampled.
    pub fn last_dscp(&self) -> Option<u8> {
        *self.last_dscp.lock().unwrap()
    }
}

impl Drop for DscpTcpSink {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
