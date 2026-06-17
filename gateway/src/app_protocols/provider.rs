//! Application-level protocol provider trait for extensible framing.
//!
//! App protocol providers handle framing of UDP datagrams over a TLS stream,
//! including connection handshakes and disconnect signaling.
//! Built-in providers: ALE (UNISIG Subset-037/098), Raw (length-prefix).
//!
//! # Adding a new provider
//!
//! 1. Create a struct implementing `AppProtocolProvider`
//! 2. Implement `FramingSession` for the per-connection session
//! 3. Register it in `main.rs` via `registry.register_app_protocol(Box::new(MyProvider))`
//! 4. Use the provider's `name()` as the `"app_protocol"` value in config

use std::io;

/// An application-level protocol provider for framing datagrams over a stream.
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
/// Handles handshake, datagram framing/deframing, and disconnect
/// for one logical connection over a byte stream.
pub trait FramingSession: Send {
    /// Perform connection-level handshake as the initiator (client/encrypt side).
    /// For protocols without a handshake, this is a no-op returning Ok(()).
    fn handshake_initiator(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()>;

    /// Perform connection-level handshake as the responder (server/decrypt side).
    /// For protocols without a handshake, this is a no-op returning Ok(()).
    fn handshake_responder(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()>;

    /// Frame a datagram for writing into the stream.
    /// Appends the framed bytes (header + payload) to `out`.
    fn frame_datagram(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()>;

    /// Feed raw bytes from the stream, return extracted datagrams.
    fn deframe(&mut self, data: &[u8]) -> io::Result<DeframeResult>;

    /// Write a disconnect/close indication into the stream.
    /// For protocols without disconnect signaling, this is a no-op.
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
