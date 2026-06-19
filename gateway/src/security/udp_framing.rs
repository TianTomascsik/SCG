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
//! reassembly go through [`UdpFraming::frame_into`] / [`UdpFraming::deframe`].

use ale_pipe::{AleError, AleFrameReader, AleFrameWriter, ALE_PKT_DI, ALE_PKT_DT};
use log::error;

/// The result of feeding received TLS bytes through the framer.
#[derive(Default)]
pub struct Deframed {
    /// Fully reassembled application datagrams, in order.
    pub datagrams: Vec<Vec<u8>>,
    /// The peer signalled a disconnect (ALE DI) or a fatal framing error was
    /// hit, so the session should be torn down.
    pub disconnect: bool,
}

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
                out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                out.extend_from_slice(payload);
            }
        }
    }

    /// Feed inbound TLS bytes, returning any complete datagrams and whether the
    /// session should disconnect.
    pub fn deframe(&mut self, rule_name: &str, data: &[u8]) -> Deframed {
        match self {
            UdpFraming::Ale { reader, .. } => {
                let mut out = Deframed::default();
                match reader.feed(data) {
                    Ok(frames) => {
                        for frame in frames {
                            match frame.header.packet_type {
                                ALE_PKT_DT => out.datagrams.push(frame.user_data),
                                ALE_PKT_DI => out.disconnect = true,
                                _ => {} // Ignore association/other packet types.
                            }
                        }
                    }
                    Err(AleError::ChecksumMismatch { expected, got }) => {
                        error!(
                            "[{}] ALE checksum mismatch: expected 0x{:04X}, got 0x{:04X} — disconnecting",
                            rule_name, expected, got
                        );
                        out.disconnect = true;
                    }
                    Err(e) => {
                        error!("[{}] ALE frame error: {}", rule_name, e);
                        out.disconnect = true;
                    }
                }
                out
            }
            UdpFraming::Raw { pending } => {
                pending.extend_from_slice(data);
                let mut datagrams = Vec::new();
                loop {
                    if pending.len() < 4 {
                        break;
                    }
                    let len =
                        u32::from_le_bytes([pending[0], pending[1], pending[2], pending[3]]) as usize;
                    if pending.len() < 4 + len {
                        break;
                    }
                    datagrams.push(pending[4..4 + len].to_vec());
                    pending.drain(..4 + len);
                }
                Deframed {
                    datagrams,
                    disconnect: false,
                }
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
