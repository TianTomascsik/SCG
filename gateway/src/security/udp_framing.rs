//! UDP-over-TLS application framing selector.
//!
//! Two framings are supported on the UDP-over-TLS data path, selected by a
//! rule's `app_protocol`:
//!
//!   * **ALE** (`"ale"`, the default) — ETCS Subset-098 ALEPKT framing with the
//!     AU1/AU2 association handshake, DT data packets, a DI disconnect packet,
//!     and the ALE CRC. Backed by the `ale_pipe` crate.
//!   * **Raw** (`"raw"`) — a 4-byte little-endian length prefix per datagram
//!     and no handshake. Tunnels UDP through TLS without ALE overhead.
//!
//! The AU1/AU2 association handshake is performed inline by the encrypt/decrypt
//! relays (gated on [`UdpFraming::is_ale`]); per-datagram framing and inbound
//! reassembly go through [`UdpFraming::frame_into`] / [`UdpFraming::deframe_each`].

use ale_pipe::{AleError, AleFrameReader, AleFrameWriter, ALE_PKT_DI, ALE_PKT_DT};
use log::error;

/// Upper bound on a single reassembled raw datagram. The raw framing tunnels UDP
/// datagrams, which cannot exceed the IPv4 UDP payload limit (65507 bytes); we
/// cap at 65535 and treat any larger advertised length as corruption or a
/// hostile/buggy peer (disconnect) rather than buffering unboundedly — otherwise
/// a 4-byte header advertising a multi-gigabyte length would make the relay
/// accumulate that much memory waiting for the frame to complete.
const MAX_RAW_DATAGRAM_LEN: usize = 65_535;

/// Per-session UDP-over-TLS framing state.
pub enum UdpFraming {
    /// ETCS ALEPKT framing (Subset-098).
    Ale {
        writer: AleFrameWriter,
        reader: AleFrameReader,
    },
    /// 4-byte little-endian length-prefix framing (`[len:u32 LE][payload]`).
    Raw { pending: Vec<u8> },
}

impl UdpFraming {
    /// Build the framer for an `app_protocol` value. `"raw"` selects raw
    /// length-prefix framing; anything else (including `"ale"`) selects ALE.
    pub fn for_app_protocol(app_protocol: &str) -> Self {
        if app_protocol.eq_ignore_ascii_case("raw") {
            UdpFraming::Raw {
                pending: Vec::new(),
            }
        } else {
            UdpFraming::Ale {
                writer: AleFrameWriter::new(0x00),
                reader: AleFrameReader::new(),
            }
        }
    }

    /// Whether this is ALE framing (which needs the AU1/AU2 handshake and a DI
    /// disconnect on teardown). Raw framing is handshake-free.
    pub fn is_ale(&self) -> bool {
        matches!(self, UdpFraming::Ale { .. })
    }

    /// Frame one outbound datagram, appending it to `out` (the caller batches
    /// multiple frames and flushes them in a single TLS write).
    pub fn frame_into(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        match self {
            UdpFraming::Ale { writer, .. } => {
                // Infallible for an in-memory Vec sink.
                let _ = writer.write_alepkt(out, ALE_PKT_DT, payload);
            }
            UdpFraming::Raw { .. } => {
                // Outbound datagrams originate from UDP recv, so they are bounded
                // by the UDP payload limit; assert the invariant rather than
                // silently truncating the length in the `as u32` cast below.
                debug_assert!(
                    payload.len() <= MAX_RAW_DATAGRAM_LEN,
                    "raw outbound datagram {} exceeds max {}",
                    payload.len(),
                    MAX_RAW_DATAGRAM_LEN
                );
                out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                out.extend_from_slice(payload);
            }
        }
    }

    /// Feed inbound TLS bytes, invoking `on_datagram` with a borrowed slice for
    /// each complete reassembled datagram (in order) and returning whether the
    /// session should disconnect (ALE DI or a fatal framing error).
    ///
    /// The closure receives a slice that borrows the framer's internal buffer,
    /// so the relay can forward each datagram with no per-datagram heap
    /// allocation. For the raw framing the consumed prefix is dropped in a
    /// single trailing splice rather than once per datagram.
    pub fn deframe_each<F: FnMut(&[u8])>(
        &mut self,
        rule_name: &str,
        data: &[u8],
        mut on_datagram: F,
    ) -> bool {
        match self {
            UdpFraming::Ale { reader, .. } => {
                let mut disconnect = false;
                match reader.feed(data) {
                    Ok(frames) => {
                        for frame in frames {
                            match frame.header.packet_type {
                                ALE_PKT_DT => on_datagram(&frame.user_data),
                                ALE_PKT_DI => disconnect = true,
                                _ => {} // Ignore association/other packet types.
                            }
                        }
                    }
                    Err(AleError::ChecksumMismatch { expected, got }) => {
                        error!(
                            "[{}] ALE checksum mismatch: expected 0x{:04X}, got 0x{:04X} — disconnecting",
                            rule_name, expected, got
                        );
                        disconnect = true;
                    }
                    Err(e) => {
                        error!("[{}] ALE frame error: {}", rule_name, e);
                        disconnect = true;
                    }
                }
                disconnect
            }
            UdpFraming::Raw { pending } => {
                pending.extend_from_slice(data);
                let mut consumed = 0usize;
                loop {
                    let rem = &pending[consumed..];
                    if rem.len() < 4 {
                        break;
                    }
                    let len = u32::from_le_bytes([rem[0], rem[1], rem[2], rem[3]]) as usize;
                    if len > MAX_RAW_DATAGRAM_LEN {
                        error!(
                            "[{}] raw framing: datagram length {} exceeds maximum {} — disconnecting",
                            rule_name, len, MAX_RAW_DATAGRAM_LEN
                        );
                        return true;
                    }
                    if rem.len() < 4 + len {
                        break;
                    }
                    on_datagram(&rem[4..4 + len]);
                    consumed += 4 + len;
                }
                if consumed == pending.len() {
                    pending.clear();
                } else if consumed > 0 {
                    pending.drain(..consumed);
                }
                false
            }
        }
    }

    /// Write the ALE DI (disconnect) packet on teardown. No-op for raw framing.
    pub fn write_disconnect<W: std::io::Write>(&mut self, stream: &mut W) {
        if let UdpFraming::Ale { writer, .. } = self {
            let _ = writer.write_alepkt(stream, ALE_PKT_DI, &[]);
        }
    }
}

#[cfg(test)]
mod raw_bound_tests {
    use super::*;

    #[test]
    fn raw_oversized_length_disconnects_without_buffering() {
        let mut framing = UdpFraming::for_app_protocol("raw");
        // 4-byte header advertising a ~4 GiB datagram.
        let hdr = u32::MAX.to_le_bytes();
        let mut got: Vec<Vec<u8>> = Vec::new();
        let disconnect = framing.deframe_each("test", &hdr, |d| got.push(d.to_vec()));
        assert!(disconnect, "oversized advertised length must trigger disconnect");
        assert!(got.is_empty(), "no datagram should be emitted");
    }

    #[test]
    fn raw_roundtrip_within_bound_chunked() {
        let mut tx = UdpFraming::for_app_protocol("raw");
        let mut wire = Vec::new();
        tx.frame_into(b"hello", &mut wire);
        tx.frame_into(b"world", &mut wire);

        let mut rx = UdpFraming::for_app_protocol("raw");
        let mut got: Vec<Vec<u8>> = Vec::new();
        // Feed one byte at a time to exercise partial reassembly.
        for b in &wire {
            let disconnect = rx.deframe_each("test", &[*b], |d| got.push(d.to_vec()));
            assert!(!disconnect);
        }
        assert_eq!(got, vec![b"hello".to_vec(), b"world".to_vec()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_frame(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn raw_deframe_each_yields_borrowed_datagrams_and_drains_fully() {
        let mut f = UdpFraming::for_app_protocol("raw");
        let mut wire = raw_frame(b"hello");
        wire.extend_from_slice(&raw_frame(b"world"));

        let mut got: Vec<Vec<u8>> = Vec::new();
        let disconnect = f.deframe_each("t", &wire, |d| got.push(d.to_vec()));

        assert!(!disconnect);
        assert_eq!(got, vec![b"hello".to_vec(), b"world".to_vec()]);
        // A fully-consumed stream must leave no buffered bytes.
        match &f {
            UdpFraming::Raw { pending } => assert!(pending.is_empty()),
            _ => panic!("expected raw framing"),
        }
    }

    #[test]
    fn raw_deframe_each_buffers_partial_frame_across_feeds() {
        let mut f = UdpFraming::for_app_protocol("raw");
        let full = raw_frame(b"abcdef");
        let split = full.len() - 2;

        let mut count = 0usize;
        // First feed delivers only part of the frame: nothing is emitted yet.
        f.deframe_each("t", &full[..split], |_| count += 1);
        assert_eq!(count, 0);

        // Remaining bytes complete the frame on the next feed.
        let mut out = Vec::new();
        f.deframe_each("t", &full[split..], |d| out.push(d.to_vec()));
        assert_eq!(out, vec![b"abcdef".to_vec()]);
    }
}

