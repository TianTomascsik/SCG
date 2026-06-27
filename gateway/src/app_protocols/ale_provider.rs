//! ALE (Adaptation Layer Entity) app protocol provider.
//!
//! Wraps the `ale-frame` crate's framing and handshake logic into
//! the `FramingSession` trait for use in the UDP-over-TLS path.

use super::provider::{AppProtocolProvider, DeframeResult, FramingSession, ReadWrite};
use ale_pipe::{
    AleAu1Info, AleAu2Info, AleError, AleFrameReader, AleFrameWriter, ALE_CLASS_D, ALE_PKT_AU1,
    ALE_PKT_AU2, ALE_PKT_DI, ALE_PKT_DT,
};
use log::debug;
use std::io;

/// ALE protocol provider for EuroRadio ALEPKT framing (UNISIG Subset-037/098).
pub struct AleProtocolProvider;

impl AppProtocolProvider for AleProtocolProvider {
    fn name(&self) -> &str {
        "ale"
    }

    fn description(&self) -> &str {
        "ALE (UNISIG Subset-037/098) ALEPKT framing with AU1/AU2 handshake"
    }

    fn create_session(&self) -> Box<dyn FramingSession> {
        Box::new(AleSession {
            writer: AleFrameWriter::new(0x00),
            reader: AleFrameReader::new(),
        })
    }
}

/// A single ALE framing session for one connection/tunnel.
struct AleSession {
    writer: AleFrameWriter,
    reader: AleFrameReader,
}

impl FramingSession for AleSession {
    fn handshake_initiator(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()> {
        // Send AU1 (connection request)
        let au1_info = AleAu1Info {
            calling_etcs_id: 0,
            called_etcs_id: 0,
            class_of_service: ALE_CLASS_D,
        };
        let au1_data = au1_info.encode(&[]);
        let mut buf = Vec::new();
        self.writer
            .write_alepkt(&mut buf, ALE_PKT_AU1, &au1_data)
            .map_err(|e| io::Error::other(format!("ALE AU1 send: {}", e)))?;
        stream.write_all(&buf)?;

        // Read AU2 response with poll-based timeout (50 * 100ms = 5s)
        let mut hs_reader = AleFrameReader::new();
        let mut hs_buf = [0u8; 256];

        for _ in 0..50 {
            match stream.read(&mut hs_buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ALE handshake: connection closed before AU2",
                    ));
                }
                Ok(n) => match hs_reader.feed(&hs_buf[..n]) {
                    Ok(frames) => {
                        for frame in frames {
                            if frame.header.packet_type == ALE_PKT_AU2 {
                                if let Some((au2, _)) = AleAu2Info::decode(&frame.user_data) {
                                    debug!(
                                        "  ALE handshake OK (responding ETCS-ID: 0x{:08X})",
                                        au2.responding_etcs_id
                                    );
                                }
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("ALE handshake read error: {}", e),
                        ));
                    }
                },
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "ALE handshake timed out waiting for AU2",
        ))
    }

    fn handshake_responder(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()> {
        // Read AU1 from initiator
        let mut hs_reader = AleFrameReader::new();
        let mut hs_buf = [0u8; 256];

        for _ in 0..50 {
            match stream.read(&mut hs_buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ALE handshake: connection closed before AU1",
                    ));
                }
                Ok(n) => match hs_reader.feed(&hs_buf[..n]) {
                    Ok(frames) => {
                        for frame in frames {
                            if frame.header.packet_type == ALE_PKT_AU1 {
                                if let Some((au1, _)) = AleAu1Info::decode(&frame.user_data) {
                                    debug!(
                                        "  ALE AU1 received (calling: 0x{:08X}, called: 0x{:08X})",
                                        au1.calling_etcs_id, au1.called_etcs_id
                                    );
                                }

                                // Send AU2 response
                                let au2_info = AleAu2Info {
                                    responding_etcs_id: 0,
                                };
                                let au2_data = au2_info.encode(&[]);
                                let mut buf = Vec::new();
                                self.writer
                                    .write_alepkt(&mut buf, ALE_PKT_AU2, &au2_data)
                                    .map_err(|e| {
                                        io::Error::other(
                                            format!("ALE AU2 send: {}", e),
                                        )
                                    })?;
                                stream.write_all(&buf)?;
                                debug!("  ALE handshake complete (responder)");
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("ALE AU1 read error: {}", e),
                        ));
                    }
                },
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "ALE handshake failed: no AU1 received",
        ))
    }

    fn frame_datagram(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        self.writer
            .write_alepkt(out, ALE_PKT_DT, payload)
            .map_err(|e| io::Error::other(format!("ALE frame: {}", e)))
    }

    fn deframe(&mut self, data: &[u8]) -> io::Result<DeframeResult> {
        match self.reader.feed(data) {
            Ok(frames) => {
                let mut datagrams = Vec::new();
                let mut disconnected = false;
                for frame in frames {
                    match frame.header.packet_type {
                        ALE_PKT_DT => {
                            datagrams.push(frame.user_data);
                        }
                        ALE_PKT_DI => {
                            disconnected = true;
                            break;
                        }
                        _ => {} // Ignore AU1/AU2 during data phase
                    }
                }
                Ok(DeframeResult {
                    datagrams,
                    disconnected,
                })
            }
            Err(AleError::ChecksumMismatch { expected, got }) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ALE checksum mismatch: expected 0x{:04X}, got 0x{:04X}",
                    expected, got
                ),
            )),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ALE frame error: {}", e),
            )),
        }
    }

    fn write_disconnect(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()> {
        let mut buf = Vec::new();
        self.writer
            .write_alepkt(&mut buf, ALE_PKT_DI, &[])
            .map_err(|e| io::Error::other(format!("ALE DI: {}", e)))?;
        stream.write_all(&buf)
    }
}
