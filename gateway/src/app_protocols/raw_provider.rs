//! Raw (length-prefix) app protocol provider.
//!
//! Simple framing using a 4-byte little-endian length prefix per datagram.
//! No handshake, no disconnect signaling. Suitable for tunneling UDP over
//! TLS without application-level protocol overhead.

use super::provider::{AppProtocolProvider, DeframeResult, FramingSession, ReadWrite};
use std::io;

/// Upper bound on a single reassembled datagram. The raw framing tunnels UDP
/// datagrams (max IPv4 UDP payload 65507 bytes); a larger advertised length is
/// rejected as corrupt/hostile rather than buffered, bounding memory use.
const MAX_RAW_DATAGRAM_LEN: usize = 65_535;

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
        // Use a checked conversion rather than `as u32`, which would silently
        // truncate the length (and corrupt the frame) for an oversized payload.
        let len = u32::try_from(payload.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "datagram exceeds u32::MAX")
        })?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(payload);
        Ok(())
    }

    fn deframe(&mut self, data: &[u8]) -> io::Result<DeframeResult> {
        self.pending.extend_from_slice(data);
        let mut datagrams = Vec::new();

        // The `len >= 4` / `len < 4 + len` guards below make every index in this
        // loop provably in bounds, so none of the slicing can panic.
        while self.pending.len() >= 4 {
            let len = u32::from_le_bytes([
                self.pending[0],
                self.pending[1],
                self.pending[2],
                self.pending[3],
            ]) as usize;
            if len > MAX_RAW_DATAGRAM_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("raw datagram length {len} exceeds maximum {MAX_RAW_DATAGRAM_LEN}"),
                ));
            }
            if self.pending.len() < 4 + len {
                break; // incomplete frame; wait for more bytes
            }
            datagrams.push(self.pending[4..4 + len].to_vec());
            self.pending.drain(..4 + len);
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

#[cfg(test)]
mod tests {
    use super::RawProtocolProvider;
    use crate::app_protocols::provider::AppProtocolProvider;
    use std::io;

    #[test]
    fn deframe_rejects_oversized() {
        let provider = RawProtocolProvider;
        let mut session = provider.create_session();
        let hdr = u32::MAX.to_le_bytes(); // ~4 GiB advertised length
        // DeframeResult is not Debug, so match instead of unwrap_err().
        match session.deframe(&hdr) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("expected oversized datagram to be rejected"),
        }
    }

    #[test]
    fn frame_then_deframe_roundtrips_chunked() {
        let provider = RawProtocolProvider;
        let mut tx = provider.create_session();
        let mut out = Vec::new();
        tx.frame_datagram(b"abcd", &mut out).unwrap();

        let mut rx = provider.create_session();
        let mut all: Vec<Vec<u8>> = Vec::new();
        // One byte at a time: no datagram until the frame is complete.
        for b in &out {
            let res = rx.deframe(&[*b]).unwrap();
            all.extend(res.datagrams);
        }
        assert_eq!(all, vec![b"abcd".to_vec()]);
    }
}
