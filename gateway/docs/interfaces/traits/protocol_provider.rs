//! Application Protocol Provider interface — REFERENCE STUB (not compiled).
//!
//! Status: AS-BUILT. Mirrors `gateway/src/app_protocols/provider.rs`, which is
//! the source of truth. Defines datagram-over-stream framing for the
//! UDP-over-TLS tunnelling path.

use std::io;

/// An application-level protocol provider for framing datagrams over a stream.
/// Stateless factory selected by `name()` (the `app_protocol` config field).
pub trait AppProtocolProvider: Send + Sync {
    /// Unique name used in config (e.g., "ale", "raw").
    fn name(&self) -> &str;

    /// Human-readable description for logging.
    fn description(&self) -> &str;

    /// Create a new framing session for one connection/tunnel.
    fn create_session(&self) -> Box<dyn FramingSession>;
}

/// A stateful framing session for one connection/tunnel.
///
/// Handles handshake, datagram framing/deframing, and disconnect for one
/// logical connection over a byte stream. The session sees only the (decrypted)
/// byte stream and must not know about TLS.
pub trait FramingSession: Send {
    /// Connection-level handshake as the initiator (encrypt side). No-op Ok(())
    /// for protocols without a handshake.
    fn handshake_initiator(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()>;

    /// Connection-level handshake as the responder (decrypt side). No-op Ok(())
    /// for protocols without a handshake.
    fn handshake_responder(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()>;

    /// Frame one datagram; APPENDS framed bytes (header + payload) to `out`.
    /// Must tolerate a non-empty `out` (batching).
    fn frame_datagram(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()>;

    /// Feed raw stream bytes; return any complete datagrams. Must buffer partial
    /// frames internally across calls.
    fn deframe(&mut self, data: &[u8]) -> io::Result<DeframeResult>;

    /// Write a disconnect/close indication. No-op Ok(()) when unused.
    fn write_disconnect(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()>;
}

/// Result of deframing bytes from the stream.
pub struct DeframeResult {
    /// Extracted datagram payloads (may be empty if more data is needed).
    pub datagrams: Vec<Vec<u8>>,
    /// True if the peer sent a disconnect indication.
    pub disconnected: bool,
}

/// Trait alias for types that implement both Read and Write.
pub trait ReadWrite: io::Read + io::Write {}
impl<T: io::Read + io::Write> ReadWrite for T {}
