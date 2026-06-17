//! Raw (length-prefix) app protocol provider.
//!
//! Simple framing using a 4-byte little-endian length prefix per datagram.
//! No handshake, no disconnect signaling. Suitable for tunneling UDP over
//! TLS without application-level protocol overhead.

use super::provider::{AppProtocolProvider, DeframeResult, FramingSession, ReadWrite};
use std::io;

/// Raw length-prefix protocol provider.
pub struct RawProtocolProvider;

impl AppProtocolProvider for RawProtocolProvider {
    fn name(&self) -> &str {
        "raw"
    }

    fn description(&self) -> &str {
        "Raw length-prefix framing (4-byte LE header, no handshake)"
    }

    fn create_session(&self) -> Box<dyn FramingSession> {
        Box::new(RawSession {
            pending: Vec::new(),
        })
    }
}

/// A raw framing session using [len:u32 LE][payload] encoding.
struct RawSession {
    /// Accumulation buffer for partial frames.
    pending: Vec<u8>,
}

impl FramingSession for RawSession {
    fn handshake_initiator(&mut self, _stream: &mut dyn ReadWrite) -> io::Result<()> {
        Ok(()) // No handshake
    }

    fn handshake_responder(&mut self, _stream: &mut dyn ReadWrite) -> io::Result<()> {
        Ok(()) // No handshake
    }

    fn frame_datagram(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let len = payload.len() as u32;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(payload);
        Ok(())
    }

    fn deframe(&mut self, data: &[u8]) -> io::Result<DeframeResult> {
        self.pending.extend_from_slice(data);
        let mut datagrams = Vec::new();

        loop {
            if self.pending.len() < 4 {
                break;
            }
            let len = u32::from_le_bytes([
                self.pending[0],
                self.pending[1],
                self.pending[2],
                self.pending[3],
            ]) as usize;
            if self.pending.len() < 4 + len {
                break;
            }
            let payload = self.pending[4..4 + len].to_vec();
            self.pending.drain(..4 + len);
            datagrams.push(payload);
        }

        Ok(DeframeResult {
            datagrams,
            disconnected: false,
        })
    }

    fn write_disconnect(&mut self, _stream: &mut dyn ReadWrite) -> io::Result<()> {
        Ok(()) // No disconnect signaling
    }
}
