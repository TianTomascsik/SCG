//! Dynamically-created Unix-domain-socket (UDS) local interface.
//!
//! An endpoint is created on demand by the management API for a specific
//! `(app_id, traffic_class, direction)`. It binds a private UDS in a per-uid
//! runtime directory, authenticates the connecting process by `SO_PEERCRED`
//! plus a single-use capability token, then relays the application's framed
//! traffic through a TLS/kTLS upstream.

use crate::interfaces::endpoint::{authenticate_peer, connect_tls_upstream, relay_uds_tls};
use crate::management::config::TlsMode;

use scg_ipc::os::{self, PeerCred};
use scg_ipc::token::CapabilityToken;

use log::{error, info, warn};

use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Everything a UDS endpoint thread needs to authenticate clients and relay.
pub struct UdsEndpointTask {
    /// Human-readable label for logs (`"<rule>#<id>"`).
    pub label: String,
    /// Filesystem path the endpoint binds and serves on.
    pub socket_path: PathBuf,
    /// Upstream address the gateway connects to as a TLS client.
    pub upstream_addr: String,
    /// TLS transport mode for the upstream leg.
    pub tls_mode: TlsMode,
    /// Optional TLS protocol version override.
    pub protocol_version: Option<String>,
    /// Socket buffer tuning size.
    pub sock_buf_size: usize,
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

/// Bind the endpoint socket, serve a single authenticated client, then clean up.
///
/// The endpoint is single-use: once a client presents the valid token it is
/// consumed, so the accept loop serves exactly one authorised session and then
/// removes the socket. Connections that fail authentication are rejected while
/// the loop keeps listening, so a denied attacker cannot block the legitimate
/// client from connecting.
pub fn run_uds_endpoint(task: UdsEndpointTask) {
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

/// Connect the upstream and run the bidirectional relay for one client.
fn serve(task: &UdsEndpointTask, stream: UnixStream) {
    let mut tls = match connect_tls_upstream(
        &task.label,
        &task.upstream_addr,
        task.tls_mode,
        task.protocol_version.as_deref(),
        task.sock_buf_size,
        &task.shutdown,
    ) {
        Ok(t) => t,
        Err(e) => {
            error!("[{}] upstream connect failed: {e}", task.label);
            return;
        }
    };

    if let Err(e) = relay_uds_tls(&task.label, stream, &mut tls, &task.shutdown) {
        if e.kind() != std::io::ErrorKind::UnexpectedEof {
            warn!("[{}] relay ended with error: {e}", task.label);
        }
    }
}

/// Poll a single fd for readability with a timeout (ms). Returns `true` if the
/// fd is readable, `false` on timeout. Retries on `EINTR`.
fn poll_readable(fd: RawFd, timeout_ms: i32) -> bool {
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a valid, initialised pollfd for a single descriptor.
        let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if r < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        return r > 0 && (pfd.revents & libc::POLLIN) != 0;
    }
}
