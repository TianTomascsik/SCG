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
                                        io::Error::other(format!("ALE AU2 send: {}", e))
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

#[cfg(test)]
mod tests {
    use super::AleProtocolProvider;
    use crate::app_protocols::provider::AppProtocolProvider;
    use std::io::{self, Read};
    use std::os::unix::net::UnixStream;

    #[test]
    fn provider_metadata_is_stable() {
        let p = AleProtocolProvider;
        assert_eq!(p.name(), "ale");
        assert!(p.description().contains("ALE"));
        // create_session yields a usable framing session.
        let mut s = p.create_session();
        let mut out = Vec::new();
        s.frame_datagram(b"x", &mut out).unwrap();
        assert!(!out.is_empty());
    }

    #[test]
    fn frame_then_deframe_roundtrips_chunked() {
        let p = AleProtocolProvider;
        let mut tx = p.create_session();
        let mut out = Vec::new();
        tx.frame_datagram(b"HELLO-ALE-DATA", &mut out).unwrap();

        // Feed one byte at a time: no datagram surfaces until the frame completes.
        let mut rx = p.create_session();
        let mut all: Vec<Vec<u8>> = Vec::new();
        for b in &out {
            let res = rx.deframe(&[*b]).unwrap();
            assert!(!res.disconnected);
            all.extend(res.datagrams);
        }
        assert_eq!(all, vec![b"HELLO-ALE-DATA".to_vec()]);
    }

    #[test]
    fn disconnect_frame_is_reported() {
        let p = AleProtocolProvider;
        let mut tx = p.create_session();
        // write_disconnect needs a Read+Write sink; Cursor<Vec<u8>> is both.
        let mut wire = io::Cursor::new(Vec::new());
        tx.write_disconnect(&mut wire).unwrap();

        let mut rx = p.create_session();
        let res = rx.deframe(&wire.into_inner()).unwrap();
        assert!(res.disconnected, "DI packet should set disconnected");
    }

    #[test]
    fn corrupted_frame_is_rejected() {
        let p = AleProtocolProvider;
        let mut tx = p.create_session();
        let mut out = Vec::new();
        tx.frame_datagram(b"payload-under-checksum", &mut out)
            .unwrap();
        // The ALEPKT CRC covers header bytes 0..8 (not the payload), so flip a
        // checksum-covered header byte to force a mismatch. DeframeResult is not
        // Debug, so match on the error.
        out[5] ^= 0xFF;
        let mut rx = p.create_session();
        match rx.deframe(&out) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("expected a checksum/frame error on a corrupted packet"),
        }
    }

    #[test]
    fn handshake_initiator_and_responder_complete() {
        let (mut a, mut b) = UnixStream::pair().expect("socketpair");
        let responder = std::thread::spawn(move || {
            let p = AleProtocolProvider;
            let mut s = p.create_session();
            s.handshake_responder(&mut b)
        });

        let p = AleProtocolProvider;
        let mut s = p.create_session();
        let init = s.handshake_initiator(&mut a);
        let resp = responder.join().expect("responder thread");

        assert!(init.is_ok(), "initiator handshake failed: {init:?}");
        assert!(resp.is_ok(), "responder handshake failed: {resp:?}");
    }

    #[test]
    fn handshake_initiator_errors_on_early_eof() {
        // Peer reads the AU1 request then closes without sending AU2, so the
        // initiator observes EOF and fails closed.
        let (mut a, b) = UnixStream::pair().expect("socketpair");
        let peer = std::thread::spawn(move || {
            let mut b = b;
            let mut buf = [0u8; 256];
            let _ = b.read(&mut buf); // consume AU1
            drop(b); // close → initiator's next read returns 0
        });

        let p = AleProtocolProvider;
        let mut s = p.create_session();
        let res = s.handshake_initiator(&mut a);
        peer.join().expect("peer thread");

        match res {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            Ok(()) => panic!("expected EOF error when AU2 never arrives"),
        }
    }
}
