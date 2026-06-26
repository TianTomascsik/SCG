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

use crate::interfaces::endpoint::{accept_tls_upstream, authenticate_peer, connect_tls_upstream};
use crate::management::config::{Direction, QosPolicy, ShmNotify, ShmRingKind, TlsMode};
use crate::networking::socket_manager::{set_nodelay, set_nonblocking_fd};
use crate::security::tls_engine::{write_all_nb_proxy, ProxyStream};
use crate::security::RELAY_BUF_SIZE;

use scg_ipc::frame::{encode_into, FrameDecoder, DEFAULT_MAX_FRAME_LEN};
use scg_ipc::handshake::{
    ShmOffer, HELLO_VERSION, SHM_NOTIFY_EVENTFD, SHM_NOTIFY_FUTEX, SHM_RING_BYTESTREAM,
    SHM_RING_SLOT,
};
use scg_ipc::notify::{futex_wake, EventFd};
use scg_ipc::os::{self, MapProt, Mapping};
use scg_ipc::shm::{
    gateway_rings, RingConsumer, RingProducer, ShmControl, ShmError, SHM_CONTROL_SIZE,
    SHM_FLAG_SEALED_G2C,
};
use scg_ipc::shm_slot::{
    gateway_slot_rings, init_slot_control, ring_data_bytes, segment_size_for, slot_control_size,
    PushOutcome, SlotConsumer, SlotProducer, CACHE_LINE,
};
use scg_ipc::token::CapabilityToken;

use log::{debug, error, info, warn};

use std::io::{self};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::HashMap;

/// Everything a SHM endpoint thread needs to authenticate a client, hand it the
/// ring descriptors, and relay framed traffic.
pub struct ShmEndpointTask {
    /// Human-readable label for logs (`"<rule>#<id>"`).
    pub label: String,
    /// Filesystem path of the control socket used for the descriptor handshake.
    pub control_socket_path: PathBuf,
    /// Direction of the security pipeline: `Encrypt` dials the upstream as a TLS
    /// client; `Decrypt` binds `upstream_addr` and terminates TLS as a server.
    pub direction: Direction,
    /// Upstream address. For `Encrypt` it is the TLS server to dial; for
    /// `Decrypt` it is the local address to bind the TLS listener on.
    pub upstream_addr: String,
    /// TLS transport mode for the upstream leg.
    pub tls_mode: TlsMode,
    /// Optional TLS protocol version override.
    pub protocol_version: Option<String>,
    /// Raw provider params used to build the decrypt-direction TLS acceptor.
    pub provider_params: HashMap<String, serde_json::Value>,
    /// Socket buffer tuning size for the upstream socket.
    pub sock_buf_size: usize,
    /// Resolved egress QoS policy (DSCP + SO_PRIORITY) for the upstream leg.
    pub qos: QosPolicy,
    /// Capacity in bytes of the client→gateway ring (rounded up to a page).
    pub cap_c2g: usize,
    /// Capacity in bytes of the gateway→client ring (rounded up to a page).
    pub cap_g2c: usize,
    /// SHM ring busy-poll window (microseconds) before blocking on the eventfd.
    /// Resolved from the rule's perf profile; 0 means block immediately.
    pub spin_wait_us: u64,
    /// SHM ring data structure to use (byte-stream or fixed-slot).
    pub ring_kind: ShmRingKind,
    /// Slot ring only: bytes per segment (rounded up to a 64-byte multiple).
    pub segment_size: usize,
    /// Slot ring only: number of segments per ring (rounded up to a power of two).
    pub num_segments: usize,
    /// Slot ring only: gateway→client wakeup mechanism.
    pub g2c_notify: ShmNotify,
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
    let mut seg = match ShmSegment::create(task) {
        Ok(s) => s,
        Err(e) => {
            error!("[{}] failed to create SHM segment: {e}", task.label);
            return;
        }
    };

    // Offer the descriptors to the client over the control socket. The payload
    // carries the geometry and ring kind; the memfds and eventfds travel via
    // SCM_RIGHTS.
    let offer = ShmOffer {
        version: HELLO_VERSION,
        notify: seg.g2c_notify,
        n_fds: 5,
        ring_kind: seg.ring_kind,
        cap_c2g: seg.cap_c2g as u64,
        cap_g2c: seg.cap_g2c as u64,
        capacity: seg.capacity,
        segment_size: seg.segment_size,
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

    let tls = match task.direction {
        Direction::Encrypt => connect_tls_upstream(
            &task.label,
            &task.upstream_addr,
            task.tls_mode,
            &task.provider_params,
            task.protocol_version.as_deref(),
            task.sock_buf_size,
            task.qos,
            &task.shutdown,
        ),
        Direction::Decrypt => accept_tls_upstream(
            &task.label,
            &task.upstream_addr,
            task.tls_mode,
            &task.provider_params,
            task.protocol_version.as_deref(),
            task.sock_buf_size,
            task.qos,
            &task.shutdown,
        ),
    };
    let mut tls = match tls {
        Ok(t) => t,
        Err(e) => {
            let verb = match task.direction {
                Direction::Encrypt => "connect",
                Direction::Decrypt => "accept",
            };
            error!("[{}] upstream {verb} failed: {e}", task.label);
            return;
        }
    };

    if let Err(e) = relay(
        &task.label,
        &mut seg,
        &mut control,
        &mut tls,
        &task.shutdown,
        task.spin_wait_us,
    ) {
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
    spin_wait_us: u64,
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
    // Reused scratch buffer for coalescing client→gateway frames into a single
    // TLS write (avoids a per-message allocation + syscall).
    let mut framed: Vec<u8> = Vec::with_capacity(RELAY_BUF_SIZE);
    // Reused payload buffer for draining the c2g ring (avoids a per-frame
    // allocation in the hot path; see `RingConsumer::try_pop_into`).
    let mut popbuf: Vec<u8> = Vec::with_capacity(DEFAULT_MAX_FRAME_LEN.min(RELAY_BUF_SIZE));

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Latency profile: briefly busy-poll the c2g ring before blocking, so
        // new client data is serviced without waiting for the (possibly
        // coalesced) eventfd wakeup. Falls back to blocking when idle.
        if spin_wait_us > 0 && seg.consumer_is_empty() {
            let deadline = Instant::now() + Duration::from_micros(spin_wait_us);
            while seg.consumer_is_empty() && Instant::now() < deadline {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                std::hint::spin_loop();
            }
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
        // coalesced/lost eventfd signal), coalescing all available frames into
        // one buffer and forwarding them with a single TLS write to amortise
        // the per-record syscall/crypto cost. The slot ring appends its frames
        // straight from shared memory (no staging copy / re-encode).
        framed.clear();
        seg.coalesce_c2g_into(&mut framed, &mut popbuf);
        if !framed.is_empty() {
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
                            match decoder.next_frame_borrowed() {
                                Ok(Some((traffic_id, payload))) => {
                                    push_g2c(seg, traffic_id, payload, shutdown)?;
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
        match seg.push_g2c_frame(traffic_id, data) {
            Ok(Some(was_empty)) => {
                seg.signal_g2c(was_empty);
                return Ok(());
            }
            Ok(None) => {
                if shutdown.load(Ordering::Relaxed) {
                    return Err(io::Error::other(
                        "shutdown while gateway->client ring full",
                    ));
                }
                // Nudge the client in case it is waiting, then back off.
                seg.signal_g2c(true);
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

/// The two interchangeable ring implementations behind a SHM segment.
enum RingBackend {
    /// Variable-length packed byte-stream ring.
    ByteStream {
        consumer: RingConsumer,
        producer: RingProducer,
    },
    /// Fixed-slot Vyukov ring.
    Slot {
        consumer: SlotConsumer,
        producer: SlotProducer,
    },
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
    backend: RingBackend,
    cap_c2g: usize,
    cap_g2c: usize,
    /// Ring kind advertised to the client ([`SHM_RING_BYTESTREAM`]/[`SHM_RING_SLOT`]).
    ring_kind: u8,
    /// Slot ring only: number of segments per ring (0 for byte-stream).
    capacity: u32,
    /// Slot ring only: bytes per segment (0 for byte-stream).
    segment_size: u32,
    /// Gateway→client wakeup mechanism ([`SHM_NOTIFY_EVENTFD`]/[`SHM_NOTIFY_FUTEX`]).
    g2c_notify: u8,
    control_fd: RawFd,
    data_c2g_fd: RawFd,
    data_g2c_fd: RawFd,
    c2g_evt: EventFd,
    g2c_evt: EventFd,
}

impl ShmSegment {
    /// Allocate and initialise the control page, both data rings, and the two
    /// eventfds for the ring kind requested by `task`. The gateway→client data
    /// memfd is sealed `F_SEAL_FUTURE_WRITE` after the gateway takes its
    /// writable mapping, so the client can only map it read-only. (For the slot
    /// ring the consumer writes only the control-page sequence array, never the
    /// payload region, so the seal still holds.)
    fn create(task: &ShmEndpointTask) -> io::Result<ShmSegment> {
        let page = page_size();

        // Resolve geometry and the control-page size for the chosen ring kind.
        let (ring_kind, capacity, segment_size, cap_c2g, cap_g2c, ctl_len) =
            match task.ring_kind {
                ShmRingKind::ByteStream => {
                    let c2g = round_up(task.cap_c2g.max(page), page);
                    let g2c = round_up(task.cap_g2c.max(page), page);
                    let ctl = round_up(SHM_CONTROL_SIZE, page);
                    (SHM_RING_BYTESTREAM, 0u32, 0u32, c2g, g2c, ctl)
                }
                ShmRingKind::Slot => {
                    let cap = (task.num_segments.max(2)).next_power_of_two();
                    let seg_sz = round_up(task.segment_size.max(segment_size_for(0)), CACHE_LINE);
                    let data = round_up(ring_data_bytes(cap, seg_sz).max(page), page);
                    let ctl = round_up(slot_control_size(cap).max(page), page);
                    (SHM_RING_SLOT, cap as u32, seg_sz as u32, data, data, ctl)
                }
            };

        let g2c_notify = match (task.ring_kind, task.g2c_notify) {
            (ShmRingKind::Slot, ShmNotify::Futex) => SHM_NOTIFY_FUTEX,
            _ => SHM_NOTIFY_EVENTFD,
        };

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

            // Initialise the control page before either side touches the rings,
            // then build the gateway-side ring handles.
            // SAFETY: the three mappings live in the returned struct for as long
            // as the rings; the control mapping is fresh and exclusive here.
            let backend = match task.ring_kind {
                ShmRingKind::ByteStream => unsafe {
                    ShmControl::init(control_map.as_ptr(), cap_c2g, cap_g2c, SHM_FLAG_SEALED_G2C);
                    let (consumer, producer) = gateway_rings(
                        control_map.as_ptr(),
                        ctl_len,
                        data_c2g_map.as_ptr() as *const u8,
                        cap_c2g,
                        data_g2c_map.as_ptr(),
                        cap_g2c,
                    )
                    .map_err(|e| io::Error::other(format!("shm rings: {e}")))?;
                    RingBackend::ByteStream { consumer, producer }
                },
                ShmRingKind::Slot => unsafe {
                    let cap = capacity as usize;
                    let seg_sz = segment_size as usize;
                    init_slot_control(control_map.as_ptr(), cap, seg_sz, 0)
                        .map_err(|e| io::Error::other(format!("slot control: {e}")))?;
                    let (consumer, producer) = gateway_slot_rings(
                        control_map.as_ptr(),
                        ctl_len,
                        cap,
                        seg_sz,
                        data_c2g_map.as_ptr() as *const u8,
                        cap_c2g,
                        data_g2c_map.as_ptr(),
                        cap_g2c,
                    )
                    .map_err(|e| io::Error::other(format!("slot rings: {e}")))?;
                    RingBackend::Slot { consumer, producer }
                },
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
                backend,
                cap_c2g,
                cap_g2c,
                ring_kind,
                capacity,
                segment_size,
                g2c_notify,
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

    /// Whether the client→gateway ring currently appears empty.
    #[inline]
    fn consumer_is_empty(&self) -> bool {
        match &self.backend {
            RingBackend::ByteStream { consumer, .. } => consumer.is_empty(),
            RingBackend::Slot { consumer, .. } => consumer.is_empty(),
        }
    }

    /// Coalesce all currently-available client→gateway frames into `framed`
    /// (the on-wire `[len|traffic_id|payload]` stream forwarded to the TLS
    /// upstream), returning the number of frames drained.
    ///
    /// For the slot ring the frame already sits in the data segment in on-wire
    /// layout, so it is appended with a single `memcpy` straight from shared
    /// memory — no intermediate `popbuf` copy and no header re-encode. The
    /// byte-stream ring stores bare payloads, so it still pops into `scratch`
    /// and re-frames via `encode_into`.
    #[inline]
    fn coalesce_c2g_into(&self, framed: &mut Vec<u8>, scratch: &mut Vec<u8>) -> usize {
        let mut n = 0;
        match &self.backend {
            RingBackend::Slot { consumer, .. } => {
                while let Some(frame) = consumer.peek_frame() {
                    framed.extend_from_slice(frame);
                    consumer.advance();
                    n += 1;
                }
            }
            RingBackend::ByteStream { consumer, .. } => {
                while let Some(traffic_id) = consumer.try_pop_into(scratch) {
                    encode_into(framed, traffic_id, scratch);
                    n += 1;
                }
            }
        }
        n
    }

    /// Push one frame into the gateway→client ring. Returns `Ok(Some(was_empty))`
    /// on success (whether the ring had been empty), `Ok(None)` if it is full.
    #[inline]
    fn push_g2c_frame(&self, traffic_id: u32, data: &[u8]) -> Result<Option<bool>, ShmError> {
        match &self.backend {
            RingBackend::ByteStream { producer, .. } => {
                // The byte-stream ring always signals (eventfd coalesces), so
                // report `was_empty = true` to preserve existing behaviour.
                Ok(producer.try_push(traffic_id, data)?.then_some(true))
            }
            RingBackend::Slot { producer, .. } => match producer.try_push(traffic_id, data)? {
                PushOutcome::Pushed { was_empty } => Ok(Some(was_empty)),
                PushOutcome::Full => Ok(None),
            },
        }
    }

    /// Wake the client's receive path after a gateway→client push. Uses the
    /// negotiated mechanism: a futex bump+wake on an empty→non-empty transition
    /// for the slot ring, otherwise an eventfd signal.
    #[inline]
    fn signal_g2c(&self, was_empty: bool) {
        if self.g2c_notify == SHM_NOTIFY_FUTEX {
            if let RingBackend::Slot { producer, .. } = &self.backend {
                if was_empty {
                    let w = producer.notify_word();
                    w.fetch_add(1, Ordering::Release);
                    let _ = futex_wake(w, 1);
                }
                return;
            }
        }
        let _ = self.g2c_evt.signal();
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
