//! Security Enforcer subsystem.
//!
//! TLS/kTLS engine, DTLS engine, bidirectional relay, and stubs for
//! IPSec, WireGuard, and GDOI.

pub mod conn_pool;
pub mod dtls_engine;
#[allow(dead_code)]
pub mod provider;
pub mod providers;
pub mod relay;
pub mod stubs;
pub mod tls_engine;

use std::time::Duration;

/// Relay buffer size (4 MiB) — balances syscall overhead against memory/TLB
/// pressure. TLS reads are limited to ~16 KiB per record, so much larger
/// buffers give diminishing returns on the userspace TLS path.
pub(crate) const RELAY_BUF_SIZE: usize = 4 * 1024 * 1024;

/// UDP relay buffer (64 KiB — max UDP datagram).
pub const UDP_BUF_SIZE: usize = 65536;

/// Listener accept timeout (used for shutdown checks).
pub(crate) const ACCEPT_TIMEOUT: Duration = Duration::from_millis(500);
