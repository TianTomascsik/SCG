//! Dynamically-created shared-memory (SHM) local interface.
//!
//! Like the UDS interface, a SHM endpoint is created on demand by the
//! management API for a specific `(app_id, traffic_class, direction)`. Instead
//! of a byte-pipe socket, the data plane is a pair of lock-free SPSC rings in
//! sealed shared memory:
//!
//! ```text
//!   client ──c2g ring──▶ gateway ──TLS──▶ upstream      (encrypt direction)
//!   client ◀─g2c ring── gateway ◀─TLS──  upstream
//! ```
//!
//! The endpoint binds a private *control* UDS used only for the initial
//! handshake: the client connects, presents its single-use capability token in
//! a HELLO, and the gateway replies with the memfd/eventfd descriptors via
//! `SCM_RIGHTS`. After that the control socket carries no traffic; it stays open
//! purely as a liveness channel (its `POLLHUP` tells the gateway the client is
//! gone).
//!
//! The relay is a single-threaded `poll()` loop multiplexing the client→gateway
//! eventfd, the upstream TLS socket, and the control socket, mirroring the UDS
//! relay so the (non-thread-safe) `SslStream` is only ever touched from one
//! thread. The `[len][traffic_id][data]` frame stream is carried transparently
//! inside TLS, so a SHM client interoperates end-to-end with a UDS client on a
//! peer gateway.

use crate::interfaces::endpoint::{authenticate_peer, connect_tls_upstream};
use crate::management::config::{QosPolicy, TlsMode};
use crate::networking::socket_manager::{set_nodelay, set_nonblocking_fd};
use crate::security::tls_engine::{write_all_nb_proxy, ProxyStream};
use crate::security::RELAY_BUF_SIZE;

use scg_ipc::frame::{encode_into, FrameDecoder, DEFAULT_MAX_FRAME_LEN};
use scg_ipc::handshake::{ShmOffer, HELLO_VERSION, SHM_NOTIFY_EVENTFD};
use scg_ipc::notify::EventFd;
use scg_ipc::os::{self, MapProt, Mapping};
use scg_ipc::shm::{
    gateway_rings, RingConsumer, RingProducer, ShmControl, SHM_CONTROL_SIZE, SHM_FLAG_SEALED_G2C,
};
use scg_ipc::token::CapabilityToken;

use log::{debug, error, info, warn};

use std::io::{self};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Everything a SHM endpoint thread needs to authenticate a client, hand it the
/// ring descriptors, and relay framed traffic.
pub struct ShmEndpointTask {
    /// Human-readable label for logs (`"<rule>#<id>"`).
    pub label: String,
    /// Filesystem path of the control socket used for the descriptor handshake.
    pub control_socket_path: PathBuf,
    /// Upstream address the gateway connects to as a TLS client.
    pub upstream_addr: String,
    /// TLS transport mode for the upstream leg.
    pub tls_mode: TlsMode,
    /// Optional TLS protocol version override.
    pub protocol_version: Option<String>,
    /// Socket buffer tuning size for the upstream socket.
    pub sock_buf_size: usize,
    /// Resolved egress QoS policy (DSCP + SO_PRIORITY) for the upstream leg.
    pub qos: QosPolicy,
    /// Capacity in bytes of the client→gateway ring (rounded up to a page).
    pub cap_c2g: usize,
    /// Capacity in bytes of the gateway→client ring (rounded up to a page).
    pub cap_g2c: usize,
    /// uids permitted to connect (from the rule's `allowed_uids`).
    pub allowed_uids: Arc<Vec<u32>>,
    /// Optional pid allow-list (from the rule's `allowed_pids`).
    pub allowed_pids: Arc<Vec<i32>>,
    /// uid of the management-API caller that requested this endpoint.
    pub owner_uid: u32,
    /// Single-use capability token; consumed on the first valid HELLO.
    pub token: Arc<Mutex<Option<CapabilityToken>>>,
    /// Per-endpoint shutdown flag (set by the manager on close/shutdown).
    pub shutdown: Arc<AtomicBool>,
}

/// How long to wait between accept polls before re-checking the shutdown flag.
const ACCEPT_POLL_MS: i32 = 200;
/// Maximum time to wait for a client's HELLO before giving up on a connection.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Backoff while the gateway→client ring is full (client not draining).
const RING_FULL_BACKOFF: Duration = Duration::from_micros(50);

/// Bind the control socket, serve a single authenticated client, then clean up.
///
/// The endpoint is single-use: once a client presents the valid token it is
/// consumed, so the accept loop serves exactly one authorised session and then
/// removes the socket. Connections that fail authentication are rejected while
/// the loop keeps listening, so a denied attacker cannot block the legitimate
/// client.
pub fn run_shm_endpoint(task: ShmEndpointTask) {
    let _ = std::fs::remove_file(&task.control_socket_path);

    let listener = match UnixListener::bind(&task.control_socket_path) {
        Ok(l) => l,
        Err(e) => {
            error!(
                "[{}] failed to bind SHM control socket {}: {e}",
                task.label,
                task.control_socket_path.display()
            );
            return;
        }
    };

    // Tighten ownership/permissions on the control socket file.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        if let Err(e) = os::chown(&task.control_socket_path, task.owner_uid, task.owner_uid) {
            warn!(
                "[{}] chown control socket to uid {} failed: {e}",
                task.label, task.owner_uid
            );
        }
    }
    if let Err(e) = os::chmod(&task.control_socket_path, 0o600) {
        warn!(
            "[{}] chmod 0600 on {} failed: {e}",
            task.label,
            task.control_socket_path.display()
        );
    }

    if let Err(e) = listener.set_nonblocking(true) {
        error!("[{}] set_nonblocking failed: {e}", task.label);
        let _ = std::fs::remove_file(&task.control_socket_path);
        return;
    }

    info!(
        "[{}] SHM endpoint listening on {} (owner uid={}, upstream={}, {}, rings {}B/{}B)",
        task.label,
        task.control_socket_path.display(),
        task.owner_uid,
        task.upstream_addr,
        task.tls_mode,
        task.cap_c2g,
        task.cap_g2c
    );

    let listen_fd = listener.as_raw_fd();
    while !task.shutdown.load(Ordering::Relaxed) {
        if !poll_readable(listen_fd, ACCEPT_POLL_MS) {
            continue;
        }
        let stream = match listener.accept() {
            Ok((s, _addr)) => s,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                error!("[{}] accept failed: {e}", task.label);
                continue;
            }
        };

        match authenticate_peer(
            &stream,
            &task.allowed_uids,
            &task.allowed_pids,
            task.owner_uid,
            &task.token,
            HELLO_TIMEOUT,
        ) {
            Ok(cred) => {
                info!(
                    "[{}] client authenticated (uid={}, pid={})",
                    task.label, cred.uid, cred.pid
                );
                serve(&task, stream);
                // Single-use endpoint: the token is consumed, so stop here.
                break;
            }
            Err(reason) => {
                warn!("[{}] AUDIT deny op=shm_connect: {reason}", task.label);
            }
        }
    }

    let _ = std::fs::remove_file(&task.control_socket_path);
    info!("[{}] SHM endpoint closed", task.label);
}

/// Create the shared-memory segment, hand its descriptors to the client, then
/// relay framed traffic between the rings and the TLS upstream.
fn serve(task: &ShmEndpointTask, mut control: UnixStream) {
    let mut seg = match ShmSegment::create(task.cap_c2g, task.cap_g2c) {
        Ok(s) => s,
        Err(e) => {
            error!("[{}] failed to create SHM segment: {e}", task.label);
            return;
        }
    };

    // Offer the descriptors to the client over the control socket. The payload
    // carries the geometry; the memfds and eventfds travel via SCM_RIGHTS.
    let offer = ShmOffer {
        version: HELLO_VERSION,
        notify: SHM_NOTIFY_EVENTFD,
        n_fds: 5,
        cap_c2g: seg.cap_c2g as u64,
        cap_g2c: seg.cap_g2c as u64,
    };
    let fds = [
        seg.control_fd,
        seg.data_c2g_fd,
        seg.data_g2c_fd,
        seg.c2g_evt.as_raw_fd(),
        seg.g2c_evt.as_raw_fd(),
    ];
    if let Err(e) = os::send_with_fds(control.as_raw_fd(), &offer.encode(), &fds) {
        error!("[{}] passing SHM descriptors failed: {e}", task.label);
        return;
    }

    // The client now holds its own (dup'd) copies of the memfds; the gateway's
    // mappings keep the underlying memory alive, so close the gateway's memfd
    // descriptors. The eventfds stay open for the relay.
    seg.close_memfds();

    debug!("[{}] SHM descriptors delivered; connecting upstream", task.label);

    let mut tls = match connect_tls_upstream(
        &task.label,
        &task.upstream_addr,
        task.tls_mode,
        task.protocol_version.as_deref(),
        task.sock_buf_size,
        task.qos,
        &task.shutdown,
    ) {
        Ok(t) => t,
        Err(e) => {
            error!("[{}] upstream connect failed: {e}", task.label);
            return;
        }
    };

    if let Err(e) = relay(&task.label, &mut seg, &mut control, &mut tls, &task.shutdown) {
        if e.kind() != io::ErrorKind::UnexpectedEof {
            warn!("[{}] relay ended with error: {e}", task.label);
        }
    }
}

/// Single-threaded `poll()` relay between the SHM rings and the TLS upstream.
fn relay(
    label: &str,
    seg: &mut ShmSegment,
    control: &mut UnixStream,
    tls: &mut ProxyStream,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let tls_fd = tls.raw_fd();
    set_nonblocking_fd(tls_fd);
    set_nodelay(tls_fd, true);
    control.set_nonblocking(true)?;

    let evt_fd = seg.c2g_evt.as_raw_fd();
    let ctl_fd = control.as_raw_fd();

    debug!("[{label}] SHM relay started (rings <-> TLS upstream)");

    let mut decoder = FrameDecoder::new(DEFAULT_MAX_FRAME_LEN);
    let mut rbuf = vec![0u8; RELAY_BUF_SIZE];

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let tls_pending = tls.ssl_pending() > 0;
        let (tls_ready, evt_ready, ctl_hup) = poll_relay(tls_fd, evt_fd, ctl_fd, tls_pending, 100)?;
        if ctl_hup {
            debug!("[{label}] control socket hung up; client gone");
            break;
        }
        if evt_ready {
            let _ = seg.c2g_evt.drain();
        }

        // client -> gateway: drain the c2g ring unconditionally (covers any
        // coalesced/lost eventfd signal) and frame the payloads into TLS.
        while let Some((traffic_id, data)) = seg.consumer.try_pop() {
            let mut framed = Vec::with_capacity(8 + data.len());
            encode_into(&mut framed, traffic_id, &data);
            write_all_nb_proxy(tls, &framed)?;
        }

        // gateway -> client: read TLS bytes, reassemble frames, push into g2c.
        if tls_ready || tls_pending {
            loop {
                match tls.read(&mut rbuf) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        decoder.feed(&rbuf[..n]);
                        loop {
                            match decoder.next_frame() {
                                Ok(Some((traffic_id, payload))) => {
                                    push_g2c(seg, traffic_id, &payload, shutdown)?;
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
                if tls.ssl_pending() == 0 {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Push one frame into the gateway→client ring, applying backpressure (spin
/// with a short backoff) while the client has not drained enough space.
fn push_g2c(
    seg: &ShmSegment,
    traffic_id: u32,
    data: &[u8],
    shutdown: &AtomicBool,
) -> io::Result<()> {
    loop {
        match seg.producer.try_push(traffic_id, data) {
            Ok(true) => {
                let _ = seg.g2c_evt.signal();
                return Ok(());
            }
            Ok(false) => {
                if shutdown.load(Ordering::Relaxed) {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "shutdown while gateway->client ring full",
                    ));
                }
                // Nudge the client in case it is waiting, then back off.
                let _ = seg.g2c_evt.signal();
                std::thread::sleep(RING_FULL_BACKOFF);
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("gateway->client ring push: {e}"),
                ))
            }
        }
    }
}

/// Owns the gateway side of one SHM segment: the mappings, the gateway rings,
/// and the eventfd notifiers. Dropping it unmaps the memory and closes the
/// eventfds; the data memfd descriptors are closed earlier (once passed to the
/// client) via [`ShmSegment::close_memfds`].
struct ShmSegment {
    // Mappings are kept alive for the lifetime of the rings (the ring handles
    // hold raw pointers into them). Declared before the rings so they outlive
    // them on drop is not required (the ring handles have no Drop), but keeping
    // them here documents the ownership.
    _control_map: Mapping,
    _data_c2g_map: Mapping,
    _data_g2c_map: Mapping,
    consumer: RingConsumer,
    producer: RingProducer,
    cap_c2g: usize,
    cap_g2c: usize,
    control_fd: RawFd,
    data_c2g_fd: RawFd,
    data_g2c_fd: RawFd,
    c2g_evt: EventFd,
    g2c_evt: EventFd,
}

impl ShmSegment {
    /// Allocate and initialise the control page, both data rings, and the two
    /// eventfds. The gateway→client data memfd is sealed `F_SEAL_FUTURE_WRITE`
    /// after the gateway takes its writable mapping, so the client can only map
    /// it read-only.
    fn create(cap_c2g: usize, cap_g2c: usize) -> io::Result<ShmSegment> {
        let page = page_size();
        let cap_c2g = round_up(cap_c2g.max(page), page);
        let cap_g2c = round_up(cap_g2c.max(page), page);
        let ctl_len = round_up(SHM_CONTROL_SIZE, page);

        let control_fd = os::memfd_create("scg-shm-ctl")?;
        let data_c2g_fd = match os::memfd_create("scg-shm-c2g") {
            Ok(f) => f,
            Err(e) => {
                os::close(control_fd);
                return Err(e);
            }
        };
        let data_g2c_fd = match os::memfd_create("scg-shm-g2c") {
            Ok(f) => f,
            Err(e) => {
                os::close(control_fd);
                os::close(data_c2g_fd);
                return Err(e);
            }
        };

        // Everything fallible from here runs inside a closure so any error path
        // unmaps partial mappings (on closure return) and closes the memfds.
        let built = (|| -> io::Result<ShmSegment> {
            os::ftruncate(control_fd, ctl_len as u64)?;
            os::ftruncate(data_c2g_fd, cap_c2g as u64)?;
            os::ftruncate(data_g2c_fd, cap_g2c as u64)?;

            let control_map = os::mmap_shared(control_fd, ctl_len, MapProt::ReadWrite)?;
            // Gateway consumes c2g (read-only) and produces g2c (read/write).
            let data_c2g_map = os::mmap_shared(data_c2g_fd, cap_c2g, MapProt::Read)?;
            let data_g2c_map = os::mmap_shared(data_g2c_fd, cap_g2c, MapProt::ReadWrite)?;

            // Initialise the control page before either side touches the rings.
            // SAFETY: `control_map` is a fresh writable mapping of `ctl_len`
            // (>= SHM_CONTROL_SIZE) bytes that nothing else accesses yet.
            unsafe {
                ShmControl::init(control_map.as_ptr(), cap_c2g, cap_g2c, SHM_FLAG_SEALED_G2C);
            }

            // SAFETY: the three mappings live in the returned struct for as long
            // as the rings; geometry was validated by `init`.
            let (consumer, producer) = unsafe {
                gateway_rings(
                    control_map.as_ptr(),
                    ctl_len,
                    data_c2g_map.as_ptr() as *const u8,
                    cap_c2g,
                    data_g2c_map.as_ptr(),
                    cap_g2c,
                )
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("shm rings: {e}")))?
            };

            // Fix sizes everywhere; seal g2c future-write so the client can only
            // map it read-only while the gateway keeps its pre-seal RW mapping.
            os::add_seals(control_fd, os::F_SEAL_SHRINK | os::F_SEAL_GROW)?;
            os::add_seals(data_c2g_fd, os::F_SEAL_SHRINK | os::F_SEAL_GROW)?;
            os::add_seals(
                data_g2c_fd,
                os::F_SEAL_SHRINK | os::F_SEAL_GROW | os::F_SEAL_FUTURE_WRITE,
            )?;

            let c2g_evt = EventFd::new()?;
            let g2c_evt = EventFd::new()?;

            Ok(ShmSegment {
                _control_map: control_map,
                _data_c2g_map: data_c2g_map,
                _data_g2c_map: data_g2c_map,
                consumer,
                producer,
                cap_c2g,
                cap_g2c,
                control_fd,
                data_c2g_fd,
                data_g2c_fd,
                c2g_evt,
                g2c_evt,
            })
        })();

        match built {
            Ok(seg) => Ok(seg),
            Err(e) => {
                os::close(control_fd);
                os::close(data_c2g_fd);
                os::close(data_g2c_fd);
                Err(e)
            }
        }
    }

    /// Close the memfd descriptors once the client holds its own copies. The
    /// mappings keep the underlying memory alive.
    fn close_memfds(&mut self) {
        for fd in [self.control_fd, self.data_c2g_fd, self.data_g2c_fd] {
            if fd >= 0 {
                os::close(fd);
            }
        }
        self.control_fd = -1;
        self.data_c2g_fd = -1;
        self.data_g2c_fd = -1;
    }
}

/// Query the system page size (mappings and ring capacities are page-aligned).
fn page_size() -> usize {
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v <= 0 {
        4096
    } else {
        v as usize
    }
}

/// Round `n` up to the next multiple of `align` (a power of two).
fn round_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

/// Poll the TLS socket, the client→gateway eventfd, and the control socket.
///
/// Returns `(tls_ready, evt_ready, ctl_hup)`. When the TLS engine already has
/// buffered plaintext (`tls_pending`), the poll uses a zero timeout and TLS is
/// always reported ready so buffered bytes are drained promptly.
fn poll_relay(
    tls_fd: RawFd,
    evt_fd: RawFd,
    ctl_fd: RawFd,
    tls_pending: bool,
    timeout_ms: i32,
) -> io::Result<(bool, bool, bool)> {
    let mut fds = [
        libc::pollfd { fd: tls_fd, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: evt_fd, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: ctl_fd, events: libc::POLLIN, revents: 0 },
    ];
    let timeout = if tls_pending { 0 } else { timeout_ms };

    loop {
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        break;
    }

    let tls_ready = tls_pending
        || (fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0;
    let evt_ready = (fds[1].revents & libc::POLLIN) != 0;
    // The client never sends on the control socket after the handshake, so any
    // readiness there means it closed (POLLHUP) or errored.
    let ctl_hup = (fds[2].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLIN)) != 0;
    Ok((tls_ready, evt_ready, ctl_hup))
}

/// Poll a single fd for readability with a timeout; retries on `EINTR`.
fn poll_readable(fd: RawFd, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    loop {
        let ret = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout_ms) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return false;
        }
        return ret > 0 && (pfd.revents & libc::POLLIN) != 0;
    }
}
