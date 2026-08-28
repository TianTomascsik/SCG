//! Transport interface — REFERENCE STUB (not compiled).
//!
//! Status: PROPOSED. Abstracts TCP/UDP/UDS/SHM behind a factory so the same
//! security engine can run over different transports. Generalizes the free
//! functions in `networking/connector.rs`, `networking/socket_manager.rs`, and
//! the TPROXY helpers in `interfaces/tproxy.rs`.

use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::AtomicBool;

pub enum TransportKind {
    Stream,
    Datagram,
}

pub enum PeerAddr {
    Ip(std::net::SocketAddr),
    Unix(String),
    Shm(String),
}

pub struct Endpoint {
    pub addr: String,
    pub transparent: bool,
}

pub struct SocketOptions {
    pub send_buf: Option<usize>,
    pub recv_buf: Option<usize>,
    pub nodelay: bool,
    pub quickack: bool,
    pub reuse_addr: bool,
}

/// Constructs listeners and connectors for one transport kind, selected by name.
pub trait TransportFactory: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> TransportKind;
    fn listener(&self, ep: &Endpoint, opts: &SocketOptions) -> io::Result<Box<dyn TransportListener>>;
    fn connector(&self) -> Box<dyn TransportConnector>;
}

/// Stream transports (TCP, UDS-stream, SHM-stream).
pub trait TransportListener: Send {
    fn accept(&self) -> io::Result<(Box<dyn Conn>, PeerAddr)>;
    fn local_addr(&self) -> io::Result<PeerAddr>;
    fn set_nonblocking(&self, nb: bool) -> io::Result<()>;
}

pub trait TransportConnector: Send + Sync {
    fn connect(
        &self,
        ep: &Endpoint,
        opts: &SocketOptions,
        shutdown: &AtomicBool,
    ) -> io::Result<Box<dyn Conn>>;
}

/// A bidirectional stream connection.
pub trait Conn: io::Read + io::Write + Send {
    fn peer_addr(&self) -> io::Result<PeerAddr>;
    /// TPROXY SO_ORIGINAL_DST, when present (drives upstream_addr = "auto").
    fn original_dst(&self) -> Option<PeerAddr>;
    /// Real fd for kTLS/sockopt; None for SHM transports.
    fn raw_fd(&self) -> Option<RawFd>;
    fn shutdown_write(&self) -> io::Result<()>;
}

/// Datagram transports (UDP, UDS-datagram).
pub trait DatagramSocket: Send + Sync {
    /// Returns (len, source, optional original-dst under TPROXY).
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, PeerAddr, Option<PeerAddr>)>;
    fn send_to(&self, buf: &[u8], dst: &PeerAddr) -> io::Result<usize>;
    fn local_addr(&self) -> io::Result<PeerAddr>;
    fn raw_fd(&self) -> Option<RawFd>;
}
