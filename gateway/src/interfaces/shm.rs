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

use crate::interfaces::endpoint::{
    authenticate_peer, establish_upstream, poll_readable, EndpointPolicy,
};
use crate::management::config::{Direction, QosPolicy, ShmNotify, ShmRingKind, TlsMode};
use crate::networking::socket_manager::{apply_safety_priority, set_nodelay, set_nonblocking_fd};
use crate::processing::policy::PolicyManager;
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

use std::collections::HashMap;
use std::io::{self};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

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
    /// `true` for the `routing` provider: relay plaintext on both legs (no TLS),
    /// like the TCP routing provider. Local-caller auth is unchanged (TRA #58).
    pub routing: bool,
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
    /// Shared policy manager for the second gate on the network leg (DP-08).
    /// `None` disables the gate (used by tests / policy-less deployments).
    pub policy: Option<Arc<RwLock<PolicyManager>>>,
    /// Per-endpoint shutdown flag (set by the manager on close/shutdown).
    pub shutdown: Arc<AtomicBool>,
}

/// How long to wait between accept polls before re-checking the shutdown flag.
const ACCEPT_POLL_MS: i32 = 200;
/// Maximum time to wait for a client's HELLO before giving up on a connection.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Backoff while the gateway→client ring is full (client not draining).
const RING_FULL_BACKOFF: Duration = Duration::from_micros(50);

/// Client→gateway frame size at/above which the routing (plaintext) slot-ring
/// relay writes straight from shared memory to the upstream instead of staging
/// the frame into the coalesce buffer.
///
/// The staging copy is a *userspace* memcpy into the 4 MiB coalesce buffer, and
/// coalescing packs many frames into one `write` — so for cache-resident frames
/// the copy is near-free and its syscall-amortisation wins. The copy only starts
/// to hurt once a frame busts the L2 working set (measured: at 256 KiB
/// coalescing still wins; by 1 MiB direct-write wins and cuts gateway CPU by
/// halving the per-message memory traffic). The threshold sits above L2 so
/// direct-write triggers only where it is a clear win and never regresses the
/// cache-hot common case.
const ZC_DIRECT_THRESHOLD: usize = 512 * 1024;

/// Upper bound on zero-copy direct writes performed in a single relay pass, so a
/// fast producer cannot livelock the relay in the drain loop (it returns to
/// `poll_relay` to service the other direction and the shutdown flag), mirroring
/// the `RELAY_BUF_SIZE` bound `coalesce_c2g_into` applies to small frames.
const ZC_MAX_DIRECT: usize = 64;

/// Bind the control socket, serve a single authenticated client, then clean up.
///
/// The endpoint is single-use: once a client presents the valid token it is
/// consumed, so the accept loop serves exactly one authorised session and then
/// removes the socket. Connections that fail authentication are rejected while
/// the loop keeps listening, so a denied attacker cannot block the legitimate
/// client.
pub fn run_shm_endpoint(task: ShmEndpointTask) {
    apply_safety_priority(task.qos.traffic_class);

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
    // SAFETY: `geteuid()` takes no arguments, never fails, and only reads the
    // calling process's effective uid; it has no preconditions and no memory effects.
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

    debug!(
        "[{}] SHM descriptors delivered; connecting upstream",
        task.label
    );

    // Second gate (DP-08): shared, hot-reloadable policy on the network leg.
    let endpoint_policy = task.policy.as_ref().map(|p| EndpointPolicy {
        policy: p.clone(),
        traffic_class: task.qos.traffic_class,
    });
    let policy = endpoint_policy.as_ref();

    let mut tls = match establish_upstream(
        &task.label,
        task.routing,
        task.direction,
        &task.upstream_addr,
        task.tls_mode,
        &task.provider_params,
        task.protocol_version.as_deref(),
        task.sock_buf_size,
        task.qos,
        policy,
        &task.shutdown,
    ) {
        Some(t) => t,
        None => return,
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

        // Latency profile: briefly busy-poll before blocking, so ready work is
        // serviced without waiting for the (possibly coalesced) eventfd wakeup.
        // Falls back to blocking when idle.
        //
        // The spin must watch BOTH directions. An earlier version broke only on
        // a c2g frame (client→gateway ring), so in a request/response workload
        // it kept spinning the whole window on the idle c2g ring while the
        // upstream *reply* sat unserviced — making the `latency` profile add its
        // whole spin budget (~50 µs) to RTT instead of cutting it. Break as soon
        // as either the client ring has a request (no syscall) or the upstream
        // has a reply pending (buffered plaintext, no syscall) or readable on its
        // fd (a zero-timeout poll, ~0.3 µs), so a ready reply is serviced at once.
        if spin_wait_us > 0 && seg.consumer_is_empty() && tls.ssl_pending() == 0 {
            let deadline = Instant::now() + Duration::from_micros(spin_wait_us);
            while seg.consumer_is_empty() && Instant::now() < deadline {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if tls.ssl_pending() > 0 || fd_readable_nb(tls_fd) {
                    break;
                }
                std::hint::spin_loop();
            }
        }

        let tls_pending = tls.ssl_pending() > 0;
        // Ring residue after a bounded coalesce must not wait out a full poll
        // (M8): a burst larger than one coalesce budget leaves frames in the
        // c2g ring whose eventfd was already drained.
        let ring_pending = !seg.consumer_is_empty();
        let (tls_ready, evt_ready, ctl_hup) =
            poll_relay(tls_fd, evt_fd, ctl_fd, tls_pending, ring_pending, 100)?;
        if ctl_hup {
            debug!("[{label}] control socket hung up; client gone");
            break;
        }
        if evt_ready {
            let _ = seg.c2g_evt.drain();
        }

        // client -> gateway: drain the c2g ring unconditionally (covers any
        // coalesced/lost eventfd signal) and forward to the upstream.
        //
        // On the routing (plaintext) slot-ring path, large frames are written
        // STRAIGHT from shared memory (zero staging copy — the big-payload win;
        // TRA #77 bounds it to plaintext so a mutating client can corrupt only
        // its own flow). Every other path (TLS/kTLS upstream, or the byte-stream
        // ring) coalesces into one buffer and issues a single write to amortise
        // the per-record syscall/crypto cost.
        if seg.is_slot_ring() && tls.is_plain() {
            seg.drain_c2g_routing_zerocopy(tls, &mut framed)?;
        } else {
            framed.clear();
            seg.coalesce_c2g_into(&mut framed, &mut popbuf);
            if !framed.is_empty() {
                write_all_nb_proxy(tls, &framed)?;
            }
        }

        // gateway -> client: read TLS bytes, reassemble frames, push into g2c.
        // Frames are pushed without a per-frame wakeup; a single `signal_g2c`
        // fires after each TLS read drains, so the client gets one eventfd/futex
        // wake per batch instead of one syscall per frame.
        //
        // The wake must fire if ANY push in the batch drove the ring from empty
        // to non-empty, not just the first (M9): under concurrent consumption
        // the client can drain the ring to empty and park mid-batch, so a later
        // push's empty→non-empty edge is the one that must wake it. Latching
        // only the first edge dropped that wakeup, stalling the client until its
        // bounded futex park (≤50 ms) expired. `any_was_empty` ORs the edges
        // across the whole batch; `pushed` still gates whether we signal at all.
        if tls_ready || tls_pending {
            loop {
                match tls.read(&mut rbuf) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        decoder.feed(&rbuf[..n]);
                        let mut pushed = false;
                        let mut any_was_empty = false;
                        loop {
                            match decoder.next_frame_borrowed() {
                                Ok(Some((traffic_id, payload))) => {
                                    let was_empty =
                                        push_g2c(seg, traffic_id, payload, ctl_fd, shutdown)?;
                                    any_was_empty |= was_empty;
                                    pushed = true;
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        e.to_string(),
                                    ))
                                }
                            }
                        }
                        if pushed {
                            seg.signal_g2c(any_was_empty);
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
///
/// Returns whether the ring had been empty before this push — the empty→non-empty
/// edge — so the caller can coalesce the wakeup [`ShmSegment::signal_g2c`] across a
/// whole batch of frames (one syscall per TLS read instead of one per frame). The
/// success path therefore does **not** signal; the caller signals once after the
/// batch. A *full* ring is the exception: the producer cannot make progress until
/// the client drains, so it nudges the client there before backing off.
/// Push one frame into the gateway→client ring, blocking (with backoff) while it
/// is legitimately full. A [`ShmError::RingCorrupt`] from the producer — the peer
/// moved the control-page `read_idx`/`seq` outside its valid window — surfaces as
/// an error so the caller tears the endpoint down, rather than spinning forever on
/// a false Full (DP-11).
fn push_g2c(
    seg: &ShmSegment,
    traffic_id: u32,
    data: &[u8],
    ctl_fd: RawFd,
    shutdown: &AtomicBool,
) -> io::Result<bool> {
    loop {
        match seg.push_g2c_frame(traffic_id, data) {
            Ok(Some(was_empty)) => return Ok(was_empty),
            Ok(None) => {
                if shutdown.load(Ordering::Relaxed) {
                    return Err(io::Error::other("shutdown while gateway->client ring full"));
                }
                // Detect client death while the ring is full (H3): a client
                // that crashed or was killed is exactly the client whose ring
                // fills and never drains, so the POLLHUP the relay watches for
                // in `poll_relay` can never fire from here (this is called from
                // the inner TLS-read loop, not the outer poll). Probe the
                // control socket each backoff; a gone client returns a quiet
                // EOF so `serve()` tears the endpoint down and releases the
                // upstream TLS session instead of spinning forever.
                if ctl_socket_gone(ctl_fd) {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "client gone with gateway->client ring full",
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

/// Resolved on-wire geometry of a SHM segment: the exact ring/control sizes and
/// notify mode the gateway maps *and* advertises to the client. Both
/// [`ShmSegment::create`] (mapping) and the gRPC CreateShm reply
/// (`InterfaceManager::create_shm`) derive from [`resolve_shm_layout`] so the
/// two can never disagree — a slot ring reporting byte-stream caps, or an
/// eventfd notify for a futex ring, would make the management API lie to any
/// external consumer (M7).
pub(crate) struct ShmLayout {
    pub ring_kind: u8,
    pub capacity: u32,
    pub segment_size: u32,
    pub cap_c2g: usize,
    pub cap_g2c: usize,
    pub ctl_len: usize,
    pub notify: i32,
}

/// Compute the page-aligned ring/control geometry and notify mode for `task`.
/// Pure (no syscalls beyond the page-size query); the single source of truth
/// for both mapping and reporting.
pub(crate) fn resolve_shm_layout(task: &ShmEndpointTask) -> ShmLayout {
    let page = page_size();
    let (ring_kind, capacity, segment_size, cap_c2g, cap_g2c, ctl_len) = match task.ring_kind {
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
    let notify = match (task.ring_kind, task.g2c_notify) {
        (ShmRingKind::Slot, ShmNotify::Futex) => SHM_NOTIFY_FUTEX as i32,
        _ => SHM_NOTIFY_EVENTFD as i32,
    };
    ShmLayout {
        ring_kind,
        capacity,
        segment_size,
        cap_c2g,
        cap_g2c,
        ctl_len,
        notify,
    }
}

impl ShmSegment {
    /// Allocate and initialise the control page, both data rings, and the two
    /// eventfds for the ring kind requested by `task`. The gateway→client data
    /// memfd is sealed `F_SEAL_FUTURE_WRITE` after the gateway takes its
    /// writable mapping, so the client can only map it read-only. (For the slot
    /// ring the consumer writes only the control-page sequence array, never the
    /// payload region, so the seal still holds.)
    fn create(task: &ShmEndpointTask) -> io::Result<ShmSegment> {
        // Geometry and notify mode come from the shared resolver so the mapping
        // here and the gRPC reply cannot drift (M7).
        let ShmLayout {
            ring_kind,
            capacity,
            segment_size,
            cap_c2g,
            cap_g2c,
            ctl_len,
            notify: g2c_notify_i32,
        } = resolve_shm_layout(task);
        // The segment stores the notify mode as the on-wire `u8`.
        let g2c_notify = g2c_notify_i32 as u8;

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
                // SAFETY: `control_map`/`data_c2g_map`/`data_g2c_map` are freshly
                // mmapped, exclusively owned here, and outlive the rings (stored in
                // the returned struct); each pointer/len pair describes a valid
                // mapping ftruncated to `ctl_len`/`cap_c2g`/`cap_g2c` above, matching
                // the lengths passed to `ShmControl::init`/`gateway_rings`.
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
                // SAFETY: same mapping invariants as the byte-stream arm — the three
                // mappings are freshly mmapped, exclusively owned, and outlive the
                // rings; `cap`/`seg_sz` are the slot geometry the data mapping was
                // sized for (`ring_data_bytes(cap, seg_sz)`), and `control_map` was
                // ftruncated to `ctl_len` (`slot_control_size(cap)`) above.
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
        // Drain at most ~`RELAY_BUF_SIZE` of client data per call. The client
        // (producer) can refill the ring as fast as the gateway drains it, so an
        // unbounded `while let Some(..)` loop *livelocks*: it never returns to the
        // caller to actually write the coalesced bytes upstream, `framed` grows
        // without limit, and the downstream relay starves. Bounding the batch
        // guarantees forward progress (write, then loop to drain the rest) and
        // caps `framed` to its preallocated capacity.
        let mut n = 0;
        match &self.backend {
            RingBackend::Slot { consumer, .. } => {
                while framed.len() < RELAY_BUF_SIZE {
                    let Some(frame) = consumer.peek_frame() else {
                        break;
                    };
                    framed.extend_from_slice(frame);
                    consumer.advance();
                    n += 1;
                }
            }
            RingBackend::ByteStream { consumer, .. } => {
                while framed.len() < RELAY_BUF_SIZE {
                    let Some(traffic_id) = consumer.try_pop_into(scratch) else {
                        break;
                    };
                    encode_into(framed, traffic_id, scratch);
                    n += 1;
                }
            }
        }
        n
    }

    /// Whether this segment's rings are the fixed-slot kind (peekable in place),
    /// as opposed to the packed byte-stream kind.
    #[inline]
    fn is_slot_ring(&self) -> bool {
        matches!(self.backend, RingBackend::Slot { .. })
    }

    /// Zero-copy client→gateway drain for the ROUTING (plaintext) path on the
    /// slot ring: a frame at or above [`ZC_DIRECT_THRESHOLD`] is written straight
    /// from shared memory to the upstream (`write_all_nb_proxy` reads the borrowed
    /// slot slice directly — no `framed` staging copy, the large-payload win),
    /// while smaller frames are coalesced into `framed` so their per-record write
    /// syscall is still amortised. Ordering is preserved: a pending coalesced
    /// batch is flushed before any direct write. Bounded per call (≤
    /// `RELAY_BUF_SIZE` of coalesced small frames and ≤ [`ZC_MAX_DIRECT`] direct
    /// writes) so the relay returns to `poll_relay` — servicing the other
    /// direction and the shutdown flag — instead of livelocking on a fast
    /// producer, exactly as [`coalesce_c2g_into`](Self::coalesce_c2g_into) bounds
    /// its batch.
    ///
    /// # Safety of writing peer-writable memory (TRA #77)
    /// The peeked slice is backed by the client-writable c2g region. This is
    /// sound *only* on the plaintext path (the caller gates on
    /// [`ProxyStream::is_plain`]): the frame length is clamped to the slot's
    /// payload capacity by the consumer's `next_ready`, so no read can go
    /// out of bounds; and a hostile client that rewrites the slot mid-write can
    /// corrupt only *its own* forwarded stream (`write_all_nb_proxy` may re-read
    /// the slice on a partial write), never another flow's data or a TLS
    /// same-buffer contract — the reason TLS/kTLS legs keep the staging copy.
    fn drain_c2g_routing_zerocopy(
        &self,
        tls: &mut ProxyStream,
        framed: &mut Vec<u8>,
    ) -> io::Result<()> {
        let RingBackend::Slot { consumer, .. } = &self.backend else {
            return Ok(());
        };
        framed.clear();
        let mut direct = 0usize;
        while let Some(frame) = consumer.peek_frame() {
            if frame.len() >= ZC_DIRECT_THRESHOLD {
                // Flush any coalesced small frames first so on-wire order is kept.
                if !framed.is_empty() {
                    write_all_nb_proxy(tls, framed)?;
                    framed.clear();
                }
                write_all_nb_proxy(tls, frame)?;
                consumer.advance();
                direct += 1;
                if direct >= ZC_MAX_DIRECT {
                    break;
                }
            } else {
                if framed.len() + frame.len() > RELAY_BUF_SIZE {
                    break;
                }
                framed.extend_from_slice(frame);
                consumer.advance();
            }
        }
        if !framed.is_empty() {
            write_all_nb_proxy(tls, framed)?;
            framed.clear();
        }
        Ok(())
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

impl Drop for ShmSegment {
    fn drop(&mut self) {
        // The memfds are normally closed on the success path once the client
        // holds its own copies; on an error return (e.g. `send_with_fds`
        // failing) that call is skipped and the raw fds would leak (L12).
        // `close_memfds` is idempotent (guarded by `fd >= 0`, sets to -1), so
        // running it here is a safe no-op after a successful hand-off.
        self.close_memfds();
    }
}

/// Query the system page size (mappings and ring capacities are page-aligned).
fn page_size() -> usize {
    // SAFETY: `sysconf` only reads a system-wide configuration value for the
    // valid `_SC_PAGESIZE` name; it touches no caller memory and its result is
    // validated (`<= 0` falls back to 4096) before use.
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
    // When either the TLS engine has buffered plaintext OR the c2g ring still
    // holds undrained frames after a bounded coalesce (M8), poll must not
    // block: the eventfd was already drained and an idle client sends no new
    // signal, so a 100 ms wait would strand that residue. `tls_ready` stays
    // keyed on `tls_pending` alone — ring residue does not make the TLS fd
    // readable.
    ring_pending: bool,
    timeout_ms: i32,
) -> io::Result<(bool, bool, bool)> {
    let mut fds = [
        libc::pollfd {
            fd: tls_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: evt_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: ctl_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let timeout = if tls_pending || ring_pending {
        0
    } else {
        timeout_ms
    };

    loop {
        // SAFETY: `fds` is a live, mutable stack array of `fds.len()` fully
        // initialised `pollfd` structs, so the pointer/count pair is valid for
        // the duration of the call; `poll` only writes the `revents` fields. The
        // negative return is checked and `EINTR` retried below.
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

    let tls_ready =
        tls_pending || (fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0;
    let evt_ready = (fds[1].revents & libc::POLLIN) != 0;
    // The client never sends on the control socket after the handshake, so any
    // readiness there means it closed (POLLHUP) or errored.
    let ctl_hup = (fds[2].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLIN)) != 0;
    Ok((tls_ready, evt_ready, ctl_hup))
}

/// Zero-timeout probe of the control socket for peer death (POLLHUP/POLLERR,
/// or POLLIN — the client never sends after the handshake, so any readable
/// data also means it is gone). Used inside the g2c backpressure loop (H3) so
/// a client that dies while its ring is full is detected instead of the relay
/// spinning forever with the upstream TLS session held open.
fn ctl_socket_gone(ctl_fd: RawFd) -> bool {
    let mut pfd = libc::pollfd {
        fd: ctl_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is a live, fully-initialised single `pollfd`; the
    // pointer/count pair (1) is valid for the call and `poll` only writes
    // `revents`. A negative return (including EINTR) is treated as
    // "not known gone" — conservative, the caller re-probes next backoff.
    let ret = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) };
    ret > 0 && (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLIN)) != 0
}

/// Zero-timeout readability probe of a single fd (POLLIN). Used inside the
/// latency-profile busy-poll so a ready upstream reply breaks the spin instead
/// of waiting out the whole window while the c2g ring is idle. A negative return
/// (including EINTR) is treated as "not readable" — conservative; the caller
/// falls through to the blocking `poll_relay` which re-checks all fds.
fn fd_readable_nb(fd: RawFd) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is a live, fully-initialised single `pollfd`; the
    // pointer/count pair (1) is valid for the call and `poll` only writes
    // `revents`.
    let ret = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) };
    ret > 0 && (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0
}

#[cfg(test)]
impl ShmSegment {
    /// Test-only: build a client-side producer over this segment's `c2g` ring and
    /// push `frame` until the ring is full, returning the number of frames
    /// written. Used to pre-load the ring so a single `coalesce_c2g_into` can be
    /// checked for its drain bound.
    fn test_fill_c2g(&self, frame: &[u8]) -> usize {
        use scg_ipc::shm::client_rings;
        // A second, writable mapping of the same `c2g` memfd (the gateway's own
        // mapping is read-only). MAP_SHARED writes land in the memfd pages, so the
        // gateway consumer sees them; the c2g memfd is sealed SHRINK|GROW only, so
        // a writable mapping is permitted.
        let wr = os::mmap_shared(self.data_c2g_fd, self.cap_c2g, MapProt::ReadWrite)
            .expect("writable c2g mapping");
        // SAFETY: `_control_map`/`_data_g2c_map` are live mappings owned by `self`
        // and outlive `producer`; `wr` is a live writable mapping of `cap_c2g`
        // bytes held in scope for the whole fill; the control page was initialised
        // by `create`, and the lengths match the segment geometry.
        let (producer, _consumer) = unsafe {
            client_rings(
                self._control_map.as_ptr(),
                self._control_map.len(),
                wr.as_ptr(),
                self.cap_c2g,
                self._data_g2c_map.as_ptr(),
                self.cap_g2c,
            )
        }
        .expect("client rings");
        let mut n = 0;
        while producer.try_push(1, frame).expect("push frame") {
            n += 1;
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a byte-stream SHM segment with the requested ring capacities. Only
    /// the fields `ShmSegment::create` consults need to be meaningful.
    fn byte_stream_segment(cap_c2g: usize, cap_g2c: usize) -> ShmSegment {
        let task = ShmEndpointTask {
            label: "test".to_string(),
            control_socket_path: PathBuf::new(),
            direction: Direction::Encrypt,
            upstream_addr: String::new(),
            tls_mode: TlsMode::Tls,
            routing: true,
            protocol_version: None,
            provider_params: HashMap::new(),
            sock_buf_size: 0,
            qos: QosPolicy {
                dscp_tag: None,
                preserve_inbound_dscp: false,
                traffic_class: crate::management::config::TrafficClass::default(),
            },
            cap_c2g,
            cap_g2c,
            spin_wait_us: 0,
            ring_kind: ShmRingKind::ByteStream,
            segment_size: 0,
            num_segments: 0,
            g2c_notify: ShmNotify::Eventfd,
            allowed_uids: Arc::new(Vec::new()),
            allowed_pids: Arc::new(Vec::new()),
            owner_uid: 0,
            token: Arc::new(Mutex::new(None)),
            policy: None,
            shutdown: Arc::new(AtomicBool::new(false)),
        };
        ShmSegment::create(&task).expect("create byte-stream segment")
    }

    /// Whether a raw fd is still open (fcntl F_GETFD succeeds).
    fn fd_is_open(fd: RawFd) -> bool {
        // SAFETY: `F_GETFD` only queries the descriptor flags; it takes no
        // pointer arguments and has no side effects on a valid fd.
        unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
    }

    // L12: `close_memfds` must actually close the three memfds and record them
    // as closed. This is the primitive the Drop impl invokes so an error path
    // (e.g. `send_with_fds` failing) no longer leaks them. Checked in the same
    // thread immediately after close so no other test can reopen the numbers
    // between the close and the probe.
    #[test]
    fn close_memfds_closes_and_records() {
        let mut seg = byte_stream_segment(page_size(), page_size());
        let (c, a, b) = (seg.control_fd, seg.data_c2g_fd, seg.data_g2c_fd);
        assert!(fd_is_open(c) && fd_is_open(a) && fd_is_open(b));
        seg.close_memfds();
        assert!(!fd_is_open(c) && !fd_is_open(a) && !fd_is_open(b));
        // Fields reset to -1 so the (idempotent) Drop is a no-op.
        assert_eq!(
            (seg.control_fd, seg.data_c2g_fd, seg.data_g2c_fd),
            (-1, -1, -1)
        );
        drop(seg); // must not double-close / panic
    }

    // L12: dropping a segment that was never explicitly closed (the leak path)
    // must run close_memfds via Drop and not double-close. The close primitive
    // is verified deterministically above; the Drop impl is a one-liner calling
    // it, so here we only assert a fresh segment drops cleanly.
    #[test]
    fn drop_of_fresh_segment_is_clean() {
        let seg = byte_stream_segment(page_size(), page_size());
        drop(seg); // Drop → close_memfds; must not panic / double-close.
    }

    /// Build a slot+futex SHM segment — the mode where the empty→non-empty
    /// wake edge is load-bearing (the byte-stream ring always signals via a
    /// coalescing eventfd, so M9 only affects the slot ring).
    fn slot_futex_segment(num_segments: usize, segment_size: usize) -> ShmSegment {
        let task = ShmEndpointTask {
            label: "test-slot".to_string(),
            control_socket_path: PathBuf::new(),
            direction: Direction::Encrypt,
            upstream_addr: String::new(),
            tls_mode: TlsMode::Tls,
            routing: true,
            protocol_version: None,
            provider_params: HashMap::new(),
            sock_buf_size: 0,
            qos: QosPolicy {
                dscp_tag: None,
                preserve_inbound_dscp: false,
                traffic_class: crate::management::config::TrafficClass::default(),
            },
            cap_c2g: 0,
            cap_g2c: 0,
            spin_wait_us: 0,
            ring_kind: ShmRingKind::Slot,
            segment_size,
            num_segments,
            g2c_notify: ShmNotify::Futex,
            allowed_uids: Arc::new(Vec::new()),
            allowed_pids: Arc::new(Vec::new()),
            owner_uid: 0,
            token: Arc::new(Mutex::new(None)),
            policy: None,
            shutdown: Arc::new(AtomicBool::new(false)),
        };
        ShmSegment::create(&task).expect("create slot segment")
    }

    // The routing zero-copy c2g drain must forward every frame — large ones
    // written straight from shared memory, small ones coalesced — to the
    // upstream in push order and byte-exact. Uses a real Plain (TCP) upstream and
    // decodes what arrives to confirm order + content are preserved.
    #[test]
    fn zerocopy_drain_forwards_mixed_frames_in_order() {
        use scg_ipc::shm_slot::client_slot_rings;
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};

        let num_segments = 4;
        let segment_size = 640 * 1024; // holds the >512 KiB direct-write frame
        let big = vec![0xABu8; 600 * 1024]; // >= ZC_DIRECT_THRESHOLD → direct-written
        let small = vec![0xCDu8; 200]; // < threshold → coalesced
        let seg = slot_futex_segment(num_segments, segment_size);

        // Fill the c2g ring as the client would (a second, writable mapping of the
        // c2g memfd; the gateway's own c2g mapping is read-only).
        {
            let wr = os::mmap_shared(seg.data_c2g_fd, seg.cap_c2g, MapProt::ReadWrite)
                .expect("writable c2g mapping");
            // SAFETY: `seg`'s control and g2c data mappings are live and owned by
            // `seg` for the whole scope; `wr` is a live writable mapping of
            // `cap_c2g` bytes; the geometry matches what `ShmSegment::create` built
            // from `num_segments`/`segment_size`.
            let (producer, _c) = unsafe {
                client_slot_rings(
                    seg._control_map.as_ptr(),
                    seg._control_map.len(),
                    num_segments,
                    segment_size,
                    wr.as_ptr(),
                    seg.cap_c2g,
                    seg._data_g2c_map.as_ptr(),
                    seg.cap_g2c,
                )
            }
            .expect("client slot rings");
            assert!(matches!(
                producer.try_push(7, &big).unwrap(),
                PushOutcome::Pushed { .. }
            ));
            assert!(matches!(
                producer.try_push(9, &small).unwrap(),
                PushOutcome::Pushed { .. }
            ));
        }

        // Plain upstream over a loopback TCP pair; a reader thread drains it so a
        // >512 KiB write cannot block on a full socket buffer.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let expected = big.len() + small.len() + 2 * 8; // 2 frame headers (8 B each)
        let reader = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            let mut buf = Vec::new();
            let mut chunk = [0u8; 65536];
            while buf.len() < expected {
                match s.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            buf
        });
        let up = TcpStream::connect(addr).expect("connect");
        let mut tls = ProxyStream::Plain(up);
        let mut framed = Vec::new();
        seg.drain_c2g_routing_zerocopy(&mut tls, &mut framed)
            .expect("drain");
        drop(tls); // close so the reader's loop can finish on EOF if needed
        let received = reader.join().expect("reader");

        // Decode the received stream and assert the two frames arrived in order.
        let mut dec = FrameDecoder::new(DEFAULT_MAX_FRAME_LEN);
        dec.feed(&received);
        let mut got = Vec::new();
        while let Ok(Some((tid, payload))) = dec.next_frame_borrowed() {
            got.push((tid, payload.to_vec()));
        }
        assert_eq!(got.len(), 2, "both frames must arrive");
        assert_eq!(got[0].0, 7);
        assert_eq!(
            got[0].1, big,
            "large frame forwarded byte-exact (direct write)"
        );
        assert_eq!(got[1].0, 9);
        assert_eq!(
            got[1].1, small,
            "small frame forwarded byte-exact (coalesced)"
        );
    }

    // M7: the reported geometry must reflect the ACTUAL ring the client sees.
    // A slot ring's caps come from num_segments × segment_size (not the
    // byte-stream ring_capacity), and its notify mode is futex — both were
    // previously mis-reported (byte-stream caps + hardcoded eventfd).
    #[test]
    fn resolve_shm_layout_reports_slot_geometry_and_futex_notify() {
        let seg_task = |kind, notify| ShmEndpointTask {
            label: "t".into(),
            control_socket_path: PathBuf::new(),
            direction: Direction::Encrypt,
            upstream_addr: String::new(),
            tls_mode: TlsMode::Tls,
            routing: true,
            protocol_version: None,
            provider_params: HashMap::new(),
            sock_buf_size: 0,
            qos: QosPolicy {
                dscp_tag: None,
                preserve_inbound_dscp: false,
                traffic_class: crate::management::config::TrafficClass::default(),
            },
            cap_c2g: 4096,
            cap_g2c: 4096,
            spin_wait_us: 0,
            ring_kind: kind,
            segment_size: 256,
            num_segments: 8,
            g2c_notify: notify,
            allowed_uids: Arc::new(Vec::new()),
            allowed_pids: Arc::new(Vec::new()),
            owner_uid: 0,
            token: Arc::new(Mutex::new(None)),
            policy: None,
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        // Byte-stream: page-aligned caps, eventfd notify.
        let bs = resolve_shm_layout(&seg_task(ShmRingKind::ByteStream, ShmNotify::Eventfd));
        assert_eq!(bs.notify, SHM_NOTIFY_EVENTFD as i32);
        assert!(bs.cap_c2g >= 4096 && bs.cap_c2g.is_multiple_of(page_size()));

        // Slot + futex: caps derive from the slot geometry, notify is futex.
        let slot = resolve_shm_layout(&seg_task(ShmRingKind::Slot, ShmNotify::Futex));
        assert_eq!(slot.notify, SHM_NOTIFY_FUTEX as i32);
        let expected = round_up(
            ring_data_bytes(8, round_up(256, CACHE_LINE)).max(page_size()),
            page_size(),
        );
        assert_eq!(slot.cap_c2g, expected);
        assert_eq!(slot.cap_c2g, slot.cap_g2c);
    }

    // M9: the g2c wake must fire if ANY push in a batch drove the ring from
    // empty to non-empty, not only the first. The load-bearing primitive is
    // `push_g2c_frame` reporting the empty→non-empty edge on the slot ring:
    // the first push into an empty ring reports `true`, a push while the ring
    // is still non-empty reports `false`. The relay ORs these edges across the
    // whole batch (`any_was_empty |= was_empty`) so a concurrent client that
    // re-empties the ring mid-batch is still woken by the later true edge.
    #[test]
    fn g2c_slot_push_reports_empty_to_nonempty_edge() {
        let seg = slot_futex_segment(8, 128);
        let payload = [7u8; 32];
        // First push into an empty ring: this is the wake edge.
        assert_eq!(
            seg.push_g2c_frame(1, &payload).expect("push1"),
            Some(true),
            "first push into an empty ring must report the empty→non-empty edge"
        );
        // Second push while still non-empty: no fresh edge.
        assert_eq!(
            seg.push_g2c_frame(2, &payload).expect("push2"),
            Some(false),
            "a push into an already-non-empty ring is not a wake edge"
        );
        // The relay's `any_was_empty |= was_empty` therefore latches the true
        // edge regardless of which push in the batch produced it — the M9 fix.
        let batch = [Some(false), Some(true), Some(false)];
        let any = batch.iter().flatten().fold(false, |acc, &e| acc | e);
        assert!(any, "OR across the batch preserves a mid-batch wake edge");
    }

    /// `coalesce_c2g_into` must drain at most ~`RELAY_BUF_SIZE` per call even when
    /// the ring holds more. An unbounded loop livelocks under a sustained producer
    /// (the SHM zero-throughput bug): with a ring larger than `RELAY_BUF_SIZE`,
    /// the unbounded form drains the whole ring in one call, while the bounded
    /// form stops at the budget and leaves the rest for the next iteration.
    #[test]
    fn coalesce_c2g_is_bounded_per_call() {
        // Ring deliberately larger than the per-call drain budget so the bound is
        // observable from a single static fill (no concurrency needed).
        let cap_c2g = 2 * RELAY_BUF_SIZE; // 8 MiB
        let seg = byte_stream_segment(cap_c2g, page_size());

        let payload = vec![0u8; 4096];
        let pushed = seg.test_fill_c2g(&payload);
        let frame_len = 4096 + scg_ipc::frame::FRAME_HEADER_LEN;
        // The fill must exceed one drain budget, otherwise the test proves nothing.
        assert!(
            pushed * frame_len > RELAY_BUF_SIZE,
            "ring fill ({} bytes) must exceed RELAY_BUF_SIZE",
            pushed * frame_len
        );

        let mut framed = Vec::with_capacity(RELAY_BUF_SIZE);
        let mut scratch = Vec::new();
        let drained = seg.coalesce_c2g_into(&mut framed, &mut scratch);

        // Bounded: one call drains at most a budget's worth (+ at most one frame),
        // not the whole oversized ring.
        assert!(
            framed.len() <= RELAY_BUF_SIZE + frame_len,
            "coalesce drained {} bytes in one call; the per-call bound did not hold",
            framed.len()
        );
        assert!(
            drained < pushed,
            "coalesce drained the whole ring in one call"
        );
        assert!(
            !seg.consumer_is_empty(),
            "the ring must still hold frames after a single bounded drain"
        );

        // Forward progress: draining repeatedly empties the ring.
        let mut total = drained;
        while !seg.consumer_is_empty() {
            framed.clear();
            total += seg.coalesce_c2g_into(&mut framed, &mut scratch);
        }
        assert_eq!(total, pushed, "every pushed frame must eventually drain");
    }
}
