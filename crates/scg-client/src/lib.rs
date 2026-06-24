//! `scg-client` — client library for the Secure Communication Gateway's local
//! interfaces.
//!
//! One synchronous Rust core drives two transports:
//!
//! * **UDS** — a framed byte pipe over a Unix-domain socket.
//! * **SHM** — a sealed two-ring shared-memory channel with `eventfd` wakeups.
//!
//! Both are bootstrapped the same way: a short gRPC call to the gateway's
//! management socket creates (or atomically replaces) an endpoint bound to a
//! pipeline rule (`app_id` + traffic class + direction) and returns a
//! single-use capability token. The token is presented in the first data-plane
//! frame; the gateway authenticates the peer's credentials *and* the token
//! before relaying any traffic.
//!
//! The same core is exposed to C and C++ through a small `extern "C"` ABI (see
//! [`ffi`]); a generated header (`include/scg_client.h`) and a header-only C++
//! RAII wrapper (`include/scg_client.hpp`) ship alongside the library.
//!
//! ```no_run
//! use scg_client::{ScgClient, Transport, TrafficClass, Direction};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Dial the default management socket and open a UDS encrypt endpoint.
//! let mut client = ScgClient::connect(
//!     None,
//!     "app-telemetry",
//!     Transport::Uds,
//!     TrafficClass::Safety,
//!     Direction::Encrypt,
//! )?;
//! client.send(1, b"hello gateway")?;
//! let (traffic_id, reply) = client.recv()?;
//! println!("got {} bytes on class {traffic_id}", reply.len());
//! client.close()?;
//! # Ok(())
//! # }
//! ```

#![cfg(target_os = "linux")]

mod error;
pub mod ffi;
mod mgmt;
mod poll;
mod shm;
mod uds;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use scg_ipc::{CapabilityToken, Role, TOKEN_LEN};

pub use error::{Result, ScgError};
pub use mgmt::DEFAULT_MGMT_SOCKET;

use shm::ShmClient;
use uds::UdsClient;

/// The management API registers an endpoint before its serving thread has
/// necessarily bound the returned Unix socket.  A client that dials in that
/// tiny window sees `ENOENT` (or, less commonly, `ECONNREFUSED`).  Bound the
/// retry so a real endpoint failure is still reported promptly.
const ENDPOINT_READY_TIMEOUT: Duration = Duration::from_secs(1);
const ENDPOINT_READY_RETRY: Duration = Duration::from_millis(10);

/// Which local transport to use for the data plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Transport {
    /// Framed byte pipe over a Unix-domain socket.
    Uds = 0,
    /// Sealed two-ring shared-memory channel.
    Shm = 1,
}

/// Traffic class of the pipeline (must match a configured rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TrafficClass {
    /// Best-effort / non-safety traffic.
    Normal = 0,
    /// Safety-critical traffic.
    Safety = 1,
}

/// Direction of the pipeline relative to the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Direction {
    /// Application sends plaintext; the gateway encrypts toward the upstream.
    Encrypt = 0,
    /// Application receives plaintext the gateway decrypted (v1: unsupported).
    Decrypt = 1,
}

impl Direction {
    fn role(self) -> Role {
        match self {
            Direction::Encrypt => Role::Producer,
            Direction::Decrypt => Role::Consumer,
        }
    }
}

enum Inner {
    Uds(UdsClient),
    Shm(ShmClient),
}

/// A connected client endpoint.
///
/// Holds the live data-plane transport plus enough management context to
/// deregister the endpoint on [`close`](ScgClient::close) (or on drop).
pub struct ScgClient {
    mgmt_socket: PathBuf,
    endpoint_id: u32,
    inner: Inner,
    deregistered: bool,
}

impl ScgClient {
    /// Create an endpoint via the management API and connect its data plane.
    ///
    /// `mgmt_socket` defaults to [`DEFAULT_MGMT_SOCKET`] when `None`.
    pub fn connect(
        mgmt_socket: Option<&Path>,
        app_id: &str,
        transport: Transport,
        class: TrafficClass,
        direction: Direction,
    ) -> Result<ScgClient> {
        Self::connect_with_capacity(mgmt_socket, app_id, transport, class, direction, 0)
    }

    /// Like [`connect`](ScgClient::connect) but requests a specific per-direction
    /// SHM ring capacity (bytes). `ring_capacity == 0` uses the rule default and
    /// is ignored by the UDS transport.
    pub fn connect_with_capacity(
        mgmt_socket: Option<&Path>,
        app_id: &str,
        transport: Transport,
        class: TrafficClass,
        direction: Direction,
        ring_capacity: u64,
    ) -> Result<ScgClient> {
        let mgmt_socket = mgmt_socket
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_MGMT_SOCKET));
        let role = direction.role();

        let created = mgmt::create_endpoint(
            &mgmt_socket,
            app_id,
            transport,
            class,
            direction,
            ring_capacity,
        )?;

        let (endpoint_id, inner) = match created {
            mgmt::Created::Uds {
                socket_path,
                token,
                endpoint_id,
            } => {
                let token = token_from_slice(&token)?;
                let c = connect_when_published(|| {
                    UdsClient::connect(&socket_path, token.clone(), role)
                })?;
                (endpoint_id, Inner::Uds(c))
            }
            mgmt::Created::Shm {
                control_socket_path,
                token,
                endpoint_id,
                ..
            } => {
                let token = token_from_slice(&token)?;
                let c = connect_when_published(|| {
                    ShmClient::connect(&control_socket_path, token.clone(), role)
                })?;
                (endpoint_id, Inner::Shm(c))
            }
        };

        Ok(ScgClient {
            mgmt_socket,
            endpoint_id,
            inner,
            deregistered: false,
        })
    }

    /// The gateway-assigned endpoint identifier.
    pub fn endpoint_id(&self) -> u32 {
        self.endpoint_id
    }

    /// Send one framed message (`traffic_id` is an application-defined tag).
    pub fn send(&mut self, traffic_id: u32, data: &[u8]) -> Result<()> {
        match &mut self.inner {
            Inner::Uds(c) => c.send(traffic_id, data),
            Inner::Shm(c) => c.send(traffic_id, data),
        }
    }

    /// Block until one framed message arrives.
    pub fn recv(&mut self) -> Result<(u32, Vec<u8>)> {
        match &mut self.inner {
            Inner::Uds(c) => c.recv(),
            Inner::Shm(c) => c.recv(),
        }
    }

    /// Wait up to `timeout` for a message; `None` blocks indefinitely.
    /// Returns `Ok(None)` on timeout.
    pub fn recv_timeout(&mut self, timeout: Option<Duration>) -> Result<Option<(u32, Vec<u8>)>> {
        match &mut self.inner {
            Inner::Uds(c) => c.recv_timeout(timeout),
            Inner::Shm(c) => c.recv_timeout(timeout),
        }
    }

    /// Deregister the endpoint on the gateway and tear down the data plane.
    pub fn close(mut self) -> Result<()> {
        self.deregister()
    }

    /// Best-effort management-side deregistration. Idempotent.
    fn deregister(&mut self) -> Result<()> {
        if self.deregistered {
            return Ok(());
        }
        self.deregistered = true;
        mgmt::close_endpoint(&self.mgmt_socket, self.endpoint_id)
    }
}

/// Connect to a just-created local endpoint once its listener has appeared.
///
/// Endpoint publication is asynchronous in the gateway: the gRPC response is
/// returned immediately after the endpoint thread is spawned.  Retrying only
/// the two publication-race errors avoids hiding permission, token, or framing
/// faults behind a delay.
fn connect_when_published<T>(mut connect: impl FnMut() -> Result<T>) -> Result<T> {
    let deadline = Instant::now() + ENDPOINT_READY_TIMEOUT;
    loop {
        match connect() {
            Ok(client) => return Ok(client),
            Err(err) if endpoint_not_ready(&err) && Instant::now() < deadline => {
                std::thread::sleep(ENDPOINT_READY_RETRY);
            }
            Err(err) => return Err(err),
        }
    }
}

fn endpoint_not_ready(err: &ScgError) -> bool {
    matches!(
        err,
        ScgError::Io(io)
            if matches!(
                io.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            )
    )
}

impl Drop for ScgClient {
    fn drop(&mut self) {
        // Best-effort: deregister the endpoint so it doesn't linger on the
        // gateway. The data-plane handle in `inner` is closed when fields drop.
        let _ = self.deregister();
    }
}

/// Convert the gateway-issued token bytes into a typed capability token.
fn token_from_slice(bytes: &[u8]) -> Result<CapabilityToken> {
    let arr: [u8; TOKEN_LEN] = bytes.try_into().map_err(|_| {
        ScgError::Management(format!(
            "capability token must be {TOKEN_LEN} bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(CapabilityToken::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_discriminants_match_proto_values() {
        assert_eq!(Transport::Uds as i32, 0);
        assert_eq!(Transport::Shm as i32, 1);
        assert_eq!(TrafficClass::Normal as i32, 0);
        assert_eq!(TrafficClass::Safety as i32, 1);
        assert_eq!(Direction::Encrypt as i32, 0);
        assert_eq!(Direction::Decrypt as i32, 1);
    }

    #[test]
    fn direction_maps_to_role() {
        assert_eq!(Direction::Encrypt.role(), Role::Producer);
        assert_eq!(Direction::Decrypt.role(), Role::Consumer);
    }

    #[test]
    fn token_from_slice_accepts_exact_length() {
        let bytes = [9u8; TOKEN_LEN];
        let token = token_from_slice(&bytes).expect("32 bytes is valid");
        assert!(token.ct_eq(&bytes));
    }

    #[test]
    fn token_from_slice_rejects_wrong_length() {
        assert!(token_from_slice(&[0u8; TOKEN_LEN - 1]).is_err());
        assert!(token_from_slice(&[0u8; TOKEN_LEN + 1]).is_err());
        assert!(token_from_slice(&[]).is_err());
    }

    #[test]
    fn only_endpoint_publication_races_are_retried() {
        assert!(endpoint_not_ready(&ScgError::Io(std::io::Error::from(
            std::io::ErrorKind::NotFound,
        ))));
        assert!(endpoint_not_ready(&ScgError::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused,
        ))));
        assert!(!endpoint_not_ready(&ScgError::Io(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        ))));
        assert!(!endpoint_not_ready(&ScgError::Closed));
    }

    #[test]
    fn endpoint_connection_retries_until_listener_is_published() {
        let mut attempts = 0;
        let connected = connect_when_published(|| {
            attempts += 1;
            if attempts < 3 {
                Err(ScgError::Io(std::io::Error::from(
                    std::io::ErrorKind::NotFound,
                )))
            } else {
                Ok("connected")
            }
        })
        .unwrap();

        assert_eq!(connected, "connected");
        assert_eq!(attempts, 3);
    }
}
