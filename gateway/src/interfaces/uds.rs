//! Dynamically-created Unix-domain-socket (UDS) local interface.
//!
//! An endpoint is created on demand by the management API for a specific
//! `(app_id, traffic_class, direction)`. It binds a private UDS in a per-uid
//! runtime directory, authenticates the connecting process by `SO_PEERCRED`
//! plus a single-use capability token, then relays the application's framed
//! traffic through a TLS/kTLS upstream.

use crate::interfaces::endpoint::{
    authenticate_peer, establish_upstream, poll_readable, relay_uds_tls, EndpointPolicy,
};
use crate::management::config::{Direction, PerfKnobs, QosPolicy, TlsMode};
use crate::management::telemetry::ConnectionMetrics;
use crate::networking::socket_manager::apply_safety_priority;
use crate::processing::policy::PolicyManager;

use scg_ipc::os::{self, PeerCred};
use scg_ipc::token::CapabilityToken;

use log::{error, info, warn};

use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// Everything a UDS endpoint thread needs to authenticate clients and relay.
pub struct UdsEndpointTask {
    /// Human-readable label for logs (`"<rule>#<id>"`).
    pub label: String,
    /// Filesystem path the endpoint binds and serves on.
    pub socket_path: PathBuf,
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
    /// Socket buffer tuning size.
    pub sock_buf_size: usize,
    /// Resolved low-level relay knobs (splice pipe size, busy-poll window, …)
    /// for the upstream leg, mirroring the static TCP encrypt path.
    pub perf: PerfKnobs,
    /// Resolved egress QoS policy (DSCP + SO_PRIORITY) for the upstream leg.
    pub qos: QosPolicy,
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

/// Bind the endpoint socket, serve a single authenticated client, then clean up.
///
/// The endpoint is single-use: once a client presents the valid token it is
/// consumed, so the accept loop serves exactly one authorised session and then
/// removes the socket. Connections that fail authentication are rejected while
/// the loop keeps listening, so a denied attacker cannot block the legitimate
/// client from connecting.
pub fn run_uds_endpoint(task: UdsEndpointTask) {
    apply_safety_priority(task.qos.traffic_class);

    // Remove any stale socket left by a previous run with the same path.
    let _ = std::fs::remove_file(&task.socket_path);

    let listener = match UnixListener::bind(&task.socket_path) {
        Ok(l) => l,
        Err(e) => {
            error!(
                "[{}] failed to bind UDS {}: {e}",
                task.label,
                task.socket_path.display()
            );
            return;
        }
    };

    // Tighten ownership/permissions on the socket file. When the gateway runs
    // privileged, hand the socket to the owning uid so only that user (and
    // root) can connect; the containing per-uid directory (0700) is the
    // primary gate, this is defense in depth.
    // SAFETY: `geteuid()` is a POSIX syscall that takes no arguments, dereferences no pointers, and always succeeds returning the caller's effective uid; it has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        if let Err(e) = os::chown(&task.socket_path, task.owner_uid, task.owner_uid) {
            warn!(
                "[{}] chown socket to uid {} failed: {e}",
                task.label, task.owner_uid
            );
        }
    }
    if let Err(e) = os::chmod(&task.socket_path, 0o600) {
        warn!(
            "[{}] chmod 0600 on {} failed: {e}",
            task.label,
            task.socket_path.display()
        );
    }

    if let Err(e) = listener.set_nonblocking(true) {
        error!("[{}] set_nonblocking failed: {e}", task.label);
        let _ = std::fs::remove_file(&task.socket_path);
        return;
    }

    info!(
        "[{}] UDS endpoint listening on {} (owner uid={}, upstream={}, {})",
        task.label,
        task.socket_path.display(),
        task.owner_uid,
        task.upstream_addr,
        task.tls_mode
    );

    let listen_fd = listener.as_raw_fd();
    while !task.shutdown.load(Ordering::Relaxed) {
        if !poll_readable(listen_fd, ACCEPT_POLL_MS) {
            continue;
        }
        let stream = match listener.accept() {
            Ok((s, _addr)) => s,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                error!("[{}] accept failed: {e}", task.label);
                continue;
            }
        };

        match authenticate(&stream, &task) {
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
                warn!("[{}] AUDIT deny op=uds_connect: {reason}", task.label);
                // Keep listening so the legitimate client can still connect.
            }
        }
    }

    let _ = std::fs::remove_file(&task.socket_path);
    info!("[{}] UDS endpoint closed", task.label);
}

/// Authenticate a freshly-accepted connection against this endpoint's policy.
fn authenticate(stream: &UnixStream, task: &UdsEndpointTask) -> Result<PeerCred, String> {
    authenticate_peer(
        stream,
        &task.allowed_uids,
        &task.allowed_pids,
        task.owner_uid,
        &task.token,
        HELLO_TIMEOUT,
    )
}

/// Establish the TLS upstream (dial for encrypt, accept for decrypt) and run the
/// bidirectional relay for one client.
fn serve(task: &UdsEndpointTask, stream: UnixStream) {
    // Second gate (DP-08): a shared, hot-reloadable policy handle, applied on the
    // network leg (destination for encrypt, network peer for decrypt).
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

    let direction = match task.direction {
        Direction::Encrypt => "encrypt",
        Direction::Decrypt => "decrypt",
    };
    let mut conn_metrics = ConnectionMetrics::standalone(direction, &task.tls_mode.to_string());

    // Local interfaces apply no geo-delay (loopback IPC bridged to the upstream),
    // so `delay_ms` is 0 — preserving the userspace relay's prior behaviour.
    if let Err(e) = relay_uds_tls(
        &task.label,
        stream,
        &mut tls,
        &mut conn_metrics,
        task.perf,
        0,
        &task.shutdown,
    ) {
        if e.kind() != std::io::ErrorKind::UnexpectedEof {
            warn!("[{}] relay ended with error: {e}", task.label);
        }
    }

    let elapsed = conn_metrics.elapsed_secs();
    info!(
        // bytes * 8 / 1e6 is decimal megabits (Mbit), not mebibits (L13).
        "[{}] UDS relay done: {:.3}s, {} msgs, {:.2} Mbit in / {:.2} Mbit out",
        task.label,
        elapsed,
        conn_metrics.msgs_relayed,
        conn_metrics.bytes_in as f64 * 8.0 / 1e6,
        conn_metrics.bytes_out as f64 * 8.0 / 1e6,
    );
}
