//! Security Enforcer subsystem.
//!
//! TLS/kTLS engine, DTLS engine, kernel WireGuard engine, bidirectional relay,
//! and stubs for IPSec and GDOI.

pub mod conn_pool;
pub mod dtls_engine;
#[allow(dead_code)]
pub mod provider;
pub mod providers;
pub mod relay;
pub mod routing_engine;
pub mod stubs;
pub mod tls_engine;
pub mod udp_framing;
pub mod udp_session;
pub mod wireguard_engine;

use std::time::Duration;

/// Relay buffer size (4 MiB) — balances syscall overhead against memory/TLB
/// pressure. TLS reads are limited to ~16 KiB per record, so much larger
/// buffers give diminishing returns on the userspace TLS path.
pub(crate) const RELAY_BUF_SIZE: usize = 4 * 1024 * 1024;

/// UDP relay buffer (64 KiB — max UDP datagram).
pub const UDP_BUF_SIZE: usize = 65536;

/// Listener accept timeout (used for shutdown checks).
pub(crate) const ACCEPT_TIMEOUT: Duration = Duration::from_millis(500);

/// Bounds the blocking window of any TLS/kTLS/DTLS handshake so a stalling peer
/// cannot pin a per-rule worker or the rule thread (DoS-01). Applied via
/// `SO_RCVTIMEO`/`SO_SNDTIMEO` on the TCP paths and `set_read_timeout` on DTLS;
/// cleared before the relay phase (which drives non-blocking I/O).
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
