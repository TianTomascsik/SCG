//! Framed-packet codec shared by every SCG data-plane transport.
//!
//! Wire format (all integers little-endian):
//!
//! ```text
//! ┌───────────┬──────────────┬─────────────────┐
//! │ len: u32  │ traffic_id:u32│ data: len bytes │
//! └───────────┴──────────────┴─────────────────┘
//! ```
//!
//! `len` is the length of `data` only (it does NOT include the 8-byte header).
//! The same framing is used on the UDS stream, inside the shared-memory rings,
//! and *inside* the TLS tunnel payload so that the `traffic_id` survives the
//! end-to-end encrypted hop.

use std::io::{self, Read, Write};

/// Number of header bytes preceding the payload (`len` + `traffic_id`).
pub const FRAME_HEADER_LEN: usize = 8;

/// Default upper bound on a single frame's payload (16 MiB). Frames larger than
/// this are rejected to bound memory use and reject corrupt/hostile lengths.
pub const DEFAULT_MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Encode a frame header into an 8-byte array.
#[inline]
pub fn encode_header(len: u32, traffic_id: u32) -> [u8; FRAME_HEADER_LEN] {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    hdr[0..4].copy_from_slice(&len.to_le_bytes());
    hdr[4..8].copy_from_slice(&traffic_id.to_le_bytes());
    hdr
}

/// Decode an 8-byte header into `(len, traffic_id)`.
#[inline]
pub fn decode_header(hdr: &[u8; FRAME_HEADER_LEN]) -> (u32, u32) {
    let len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let traffic_id = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    (len, traffic_id)
}

/// Append a fully encoded frame (`header || data`) to `out`.
pub fn encode_into(out: &mut Vec<u8>, traffic_id: u32, data: &[u8]) {
    out.extend_from_slice(&encode_header(data.len() as u32, traffic_id));
    out.extend_from_slice(data);
}

/// Write one frame to a blocking writer.
pub fn write_frame<W: Write>(w: &mut W, traffic_id: u32, data: &[u8]) -> io::Result<()> {
    let hdr = encode_header(data.len() as u32, traffic_id);
    w.write_all(&hdr)?;
    w.write_all(data)?;
    Ok(())
}

/// Read exactly one frame from a blocking reader.
///
/// Returns `Ok(None)` on a clean EOF that occurs on a frame boundary (i.e. no
/// header bytes were available), and an error if EOF happens mid-frame or the
/// advertised length exceeds `max_len`.
pub fn read_frame<R: Read>(r: &mut R, max_len: usize) -> io::Result<Option<(u32, Vec<u8>)>> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    match read_full_or_eof(r, &mut hdr)? {
        ReadOutcome::Eof => return Ok(None),
        ReadOutcome::Partial => {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated frame header"));
        }
        ReadOutcome::Full => {}
    }

    let (len, traffic_id) = decode_header(&hdr);
    let len = len as usize;
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame length {len} exceeds maximum {max_len}"),
        ));
    }

    let mut data = vec![0u8; len];
    r.read_exact(&mut data)?;
    Ok(Some((traffic_id, data)))
}

enum ReadOutcome {
    /// Buffer was filled completely.
    Full,
    /// Clean EOF before any byte was read.
    Eof,
    /// EOF after some but not all bytes were read.
    Partial,
}

/// Read until `buf` is full, distinguishing a clean boundary EOF from a
/// mid-buffer truncation.
fn read_full_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<ReadOutcome> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                return Ok(if filled == 0 { ReadOutcome::Eof } else { ReadOutcome::Partial });
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(ReadOutcome::Full)
}

/// Error from the incremental [`FrameDecoder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// A frame advertised a payload length larger than the configured maximum.
    TooLarge(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::TooLarge(len) => write!(f, "frame length {len} exceeds maximum"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Incremental frame decoder for byte streams (e.g. the TLS tunnel).
///
/// Bytes are appended with [`feed`](FrameDecoder::feed) as they arrive from a
/// non-blocking reader; complete frames are pulled out with
/// [`next_frame`](FrameDecoder::next_frame). This lets a single-threaded
/// `poll()` relay reassemble frames without ever blocking mid-frame, which the
/// blocking [`read_frame`] cannot do.
pub struct FrameDecoder {
    buf: Vec<u8>,
    pos: usize,
    max_len: usize,
}

impl FrameDecoder {
    /// Create a decoder that rejects any frame whose payload exceeds `max_len`.
    pub fn new(max_len: usize) -> Self {
        FrameDecoder {
            buf: Vec::new(),
            pos: 0,
            max_len,
        }
    }

    /// Append freshly-received bytes to the decoder's buffer, compacting any
    /// already-consumed prefix first to bound memory use.
    pub fn feed(&mut self, data: &[u8]) {
        if self.pos == self.buf.len() {
            // Everything consumed: reuse the allocation from the start.
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > 64 * 1024 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// Extract the next complete frame, if one is fully buffered.
    ///
    /// Returns `Ok(None)` when more bytes are needed, and
    /// `Err(FrameError::TooLarge)` if a frame's advertised length exceeds the
    /// configured maximum (a corrupt or hostile peer).
    pub fn next_frame(&mut self) -> Result<Option<(u32, Vec<u8>)>, FrameError> {
        let avail = self.buf.len() - self.pos;
        if avail < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let mut hdr = [0u8; FRAME_HEADER_LEN];
        hdr.copy_from_slice(&self.buf[self.pos..self.pos + FRAME_HEADER_LEN]);
        let (len, traffic_id) = decode_header(&hdr);
        let len = len as usize;
        if len > self.max_len {
            return Err(FrameError::TooLarge(len));
        }
        let total = FRAME_HEADER_LEN + len;
        if avail < total {
            return Ok(None);
        }
        let payload = self.buf[self.pos + FRAME_HEADER_LEN..self.pos + total].to_vec();
        self.pos += total;
        Ok(Some((traffic_id, payload)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn header_roundtrip() {
        let hdr = encode_header(0x1234_5678, 0x9abc_def0);
        let (len, tid) = decode_header(&hdr);
        assert_eq!(len, 0x1234_5678);
        assert_eq!(tid, 0x9abc_def0);
    }

    #[test]
    fn frame_roundtrip_stream() {
        let mut buf = Vec::new();
        write_frame(&mut buf, 7, b"hello").unwrap();
        write_frame(&mut buf, 42, b"").unwrap();
        write_frame(&mut buf, 1, &[0xAB; 1000]).unwrap();

        let mut cur = Cursor::new(buf);
        let (tid, data) = read_frame(&mut cur, DEFAULT_MAX_FRAME_LEN).unwrap().unwrap();
        assert_eq!(tid, 7);
        assert_eq!(data, b"hello");

        let (tid, data) = read_frame(&mut cur, DEFAULT_MAX_FRAME_LEN).unwrap().unwrap();
        assert_eq!(tid, 42);
        assert!(data.is_empty());

        let (tid, data) = read_frame(&mut cur, DEFAULT_MAX_FRAME_LEN).unwrap().unwrap();
        assert_eq!(tid, 1);
        assert_eq!(data.len(), 1000);

        assert!(read_frame(&mut cur, DEFAULT_MAX_FRAME_LEN).unwrap().is_none());
    }

    #[test]
    fn rejects_oversized() {
        let hdr = encode_header(100, 0);
        let mut cur = Cursor::new(hdr.to_vec());
        let err = read_frame(&mut cur, 10).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_header_is_error() {
        let mut cur = Cursor::new(vec![1u8, 2, 3]);
        let err = read_frame(&mut cur, DEFAULT_MAX_FRAME_LEN).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn decoder_reassembles_split_frames() {
        let mut wire = Vec::new();
        encode_into(&mut wire, 7, b"hello");
        encode_into(&mut wire, 42, b"");
        encode_into(&mut wire, 1, &[0xAB; 1000]);

        let mut dec = FrameDecoder::new(DEFAULT_MAX_FRAME_LEN);
        // Feed the stream one byte at a time to exercise partial-frame handling.
        let mut frames = Vec::new();
        for b in wire {
            dec.feed(&[b]);
            while let Some(frame) = dec.next_frame().unwrap() {
                frames.push(frame);
            }
        }
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], (7, b"hello".to_vec()));
        assert_eq!(frames[1], (42, Vec::new()));
        assert_eq!(frames[2].0, 1);
        assert_eq!(frames[2].1.len(), 1000);
    }

    #[test]
    fn decoder_handles_multiple_frames_in_one_chunk() {
        let mut wire = Vec::new();
        encode_into(&mut wire, 3, b"abc");
        encode_into(&mut wire, 9, b"defgh");

        let mut dec = FrameDecoder::new(DEFAULT_MAX_FRAME_LEN);
        dec.feed(&wire);
        assert_eq!(dec.next_frame().unwrap(), Some((3, b"abc".to_vec())));
        assert_eq!(dec.next_frame().unwrap(), Some((9, b"defgh".to_vec())));
        assert_eq!(dec.next_frame().unwrap(), None);
    }

    #[test]
    fn decoder_rejects_oversized_frame() {
        let hdr = encode_header(100, 0);
        let mut dec = FrameDecoder::new(10);
        dec.feed(&hdr);
        assert_eq!(dec.next_frame(), Err(FrameError::TooLarge(100)));
    }
}
