//! UDS data-plane client.
//!
//! After the gateway hands back a socket path + capability token, the client
//! connects, presents the token in the HELLO frame, and then exchanges
//! `[len][traffic_id][data]` frames with the gateway. The link is full duplex:
//! the application writes plaintext and reads back whatever the upstream
//! returns through the gateway.
//!
//! The framing on the wire is unchanged from the original per-message
//! implementation; this module only batches the syscalls around it. Sends can
//! be coalesced into vectored `writev` calls (one syscall for many frames) and
//! receives are re-framed from a buffered [`FrameDecoder`] fed by large reads,
//! instead of two blocking reads plus one heap allocation per frame.

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use scg_ipc::frame::{FrameDecoder, DEFAULT_MAX_FRAME_LEN, FRAME_HEADER_LEN};
use scg_ipc::{encode_header, write_frame, CapabilityToken, Hello, Role};

use crate::error::{Result, ScgError};
use crate::poll::poll_readable;

/// Frames per `writev` chunk: two iovecs per frame (header + payload) must fit
/// the kernel's `UIO_MAXIOV` (1024) iovec limit.
const SEND_BATCH_MAX: usize = 512;

/// Size of the buffered-receive staging read (one syscall can carry many
/// small frames).
const RECV_BUF_LEN: usize = 256 * 1024;

/// A connected UDS endpoint.
pub struct UdsClient {
    stream: UnixStream,
    /// Incremental re-framer for the buffered receive path. Every receive goes
    /// through it so buffered and framed views of the stream can never diverge.
    dec: FrameDecoder,
    /// Reusable staging buffer for receive reads.
    rbuf: Vec<u8>,
}

/// Outcome of one attempt to pull more bytes off the socket.
enum Fill {
    /// Bytes were appended to the decoder (or the read was interrupted and
    /// should simply be retried).
    Filled,
    /// Nothing readable within the poll timeout.
    Timeout,
    /// The gateway closed the stream.
    Eof,
}

impl UdsClient {
    /// Connect to `socket_path` and authenticate with `token`.
    pub fn connect(socket_path: &str, token: CapabilityToken, role: Role) -> Result<Self> {
        let mut stream = UnixStream::connect(socket_path)?;
        let hello = Hello::new(role, token).encode();
        stream.write_all(&hello)?;
        Ok(UdsClient {
            stream,
            dec: FrameDecoder::new(DEFAULT_MAX_FRAME_LEN),
            rbuf: vec![0u8; RECV_BUF_LEN],
        })
    }

    /// Send one framed message.
    pub fn send(&mut self, traffic_id: u32, data: &[u8]) -> Result<()> {
        write_frame(&mut self.stream, traffic_id, data)?;
        Ok(())
    }

    /// Send a batch of framed messages with as few `writev` syscalls as the
    /// kernel allows (two iovecs per frame — header and payload — so up to
    /// [`SEND_BATCH_MAX`] frames per call).
    ///
    /// The stream is blocking, so on success every message was fully written
    /// and the full count is returned; short vectored writes are resumed from
    /// the exact byte offset, preserving framing.
    pub fn send_batch(&mut self, traffic_id: u32, msgs: &[&[u8]]) -> Result<usize> {
        let fd = self.stream.as_raw_fd();
        let mut idx = 0usize;
        while idx < msgs.len() {
            let chunk = &msgs[idx..(idx + SEND_BATCH_MAX).min(msgs.len())];
            // Frame headers for this chunk must outlive the writev calls.
            let mut hdrs = [[0u8; FRAME_HEADER_LEN]; SEND_BATCH_MAX];
            let mut total = 0usize;
            for (i, m) in chunk.iter().enumerate() {
                let len = u32::try_from(m.len()).map_err(|_| {
                    ScgError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "frame payload exceeds u32::MAX",
                    ))
                })?;
                hdrs[i] = encode_header(len, traffic_id);
                total += FRAME_HEADER_LEN + m.len();
            }
            // Write the chunk fully, resuming from `off` after short writes.
            let mut off = 0usize;
            while off < total {
                let mut iov = [libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                }; 2 * SEND_BATCH_MAX];
                let mut n_iov = 0usize;
                let mut skip = off;
                for (i, m) in chunk.iter().enumerate() {
                    for seg in [&hdrs[i][..], *m] {
                        if skip >= seg.len() {
                            skip -= seg.len();
                            continue;
                        }
                        if !seg[skip..].is_empty() {
                            iov[n_iov] = libc::iovec {
                                iov_base: seg[skip..].as_ptr() as *mut libc::c_void,
                                iov_len: seg.len() - skip,
                            };
                            n_iov += 1;
                        }
                        skip = 0;
                    }
                }
                // SAFETY: fd is this client's connected blocking stream socket;
                // iov[..n_iov] points into `hdrs` and the caller's message
                // slices, all of which outlive the syscall.
                let ret = unsafe { libc::writev(fd, iov.as_ptr(), n_iov.min(1024) as libc::c_int) };
                if ret < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e.into());
                }
                if ret == 0 {
                    return Err(ScgError::Io(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "writev accepted zero bytes",
                    )));
                }
                off += ret as usize;
            }
            idx += chunk.len();
        }
        Ok(msgs.len())
    }

    /// One poll-and-read into the frame decoder.
    fn fill_once(&mut self, timeout: Option<Duration>) -> Result<Fill> {
        if !poll_readable(self.stream.as_raw_fd(), timeout)? {
            return Ok(Fill::Timeout);
        }
        match self.stream.read(&mut self.rbuf) {
            Ok(0) => Ok(Fill::Eof),
            Ok(n) => {
                self.dec.feed(&self.rbuf[..n]);
                Ok(Fill::Filled)
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(Fill::Filled),
            Err(e) => Err(e.into()),
        }
    }

    /// Pull the next buffered frame, mapping decoder errors.
    fn next_buffered(&mut self) -> Result<Option<(u32, Vec<u8>)>> {
        self.dec.next_frame().map_err(|_| ScgError::FrameTooLarge)
    }

    /// Block until one framed message arrives.
    pub fn recv(&mut self) -> Result<(u32, Vec<u8>)> {
        match self.recv_timeout(None)? {
            Some(frame) => Ok(frame),
            None => Err(ScgError::Closed),
        }
    }

    /// Wait up to `timeout` for a message. Returns `Ok(None)` on timeout.
    ///
    /// The timeout only gates the wait for readable data; buffered frames are
    /// returned immediately without touching the socket.
    pub fn recv_timeout(&mut self, timeout: Option<Duration>) -> Result<Option<(u32, Vec<u8>)>> {
        loop {
            if let Some(frame) = self.next_buffered()? {
                return Ok(Some(frame));
            }
            match self.fill_once(timeout)? {
                Fill::Filled => continue,
                Fill::Timeout => return Ok(None),
                Fill::Eof => return Err(ScgError::Closed),
            }
        }
    }

    /// Receive up to `lens.len()` frames in one go: frame `i`'s payload is
    /// copied to `out[i*stride..]` (truncated to `stride` bytes) and its length
    /// recorded in `lens[i]`. Waits up to `timeout` for the first frame, then
    /// drains whatever one read yielded without further blocking.
    ///
    /// Returns `Ok(None)` on timeout, `Err(ScgError::Closed)` on a clean EOF
    /// with nothing buffered, and `Ok(Some(count))` otherwise. No per-frame
    /// heap allocation.
    pub fn recv_batch_into(
        &mut self,
        out: &mut [u8],
        stride: usize,
        lens: &mut [usize],
        timeout: Option<Duration>,
    ) -> Result<Option<usize>> {
        if stride == 0 || lens.is_empty() || out.len() < stride {
            return Ok(None);
        }
        let cap = lens.len().min(out.len() / stride);
        loop {
            let mut count = 0usize;
            while count < cap {
                match self
                    .dec
                    .next_frame_borrowed()
                    .map_err(|_| ScgError::FrameTooLarge)?
                {
                    Some((_tid, payload)) => {
                        let n = payload.len().min(stride);
                        out[count * stride..count * stride + n].copy_from_slice(&payload[..n]);
                        lens[count] = n;
                        count += 1;
                    }
                    None => break,
                }
            }
            if count > 0 {
                return Ok(Some(count));
            }
            match self.fill_once(timeout)? {
                Fill::Filled => continue,
                Fill::Timeout => return Ok(None),
                Fill::Eof => return Err(ScgError::Closed),
            }
        }
    }
}

/// Drop closes the socket, which the gateway observes as a clean disconnect.
impl Drop for UdsClient {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

#[cfg(test)]
impl UdsClient {
    /// Wrap an already-connected stream (tests only — skips HELLO).
    fn from_stream(stream: UnixStream) -> Self {
        UdsClient {
            stream,
            dec: FrameDecoder::new(DEFAULT_MAX_FRAME_LEN),
            rbuf: vec![0u8; RECV_BUF_LEN],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scg_ipc::read_frame;

    #[test]
    fn send_batch_produces_identical_framing() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut client = UdsClient::from_stream(a);

        let msgs: Vec<Vec<u8>> = (0..40u8)
            .map(|i| vec![i; 50 + i as usize])
            .chain(std::iter::once(Vec::new())) // zero-length payload frame
            .collect();
        let slices: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        assert_eq!(client.send_batch(7, &slices).unwrap(), msgs.len());
        drop(client);

        // The peer must decode exactly the frames write_frame would produce.
        let mut peer = b;
        for m in &msgs {
            let (tid, data) = read_frame(&mut peer, DEFAULT_MAX_FRAME_LEN)
                .unwrap()
                .expect("frame present");
            assert_eq!(tid, 7);
            assert_eq!(&data, m);
        }
        assert!(read_frame(&mut peer, DEFAULT_MAX_FRAME_LEN)
            .unwrap()
            .is_none());
    }

    #[test]
    fn send_batch_chunks_past_the_iovec_limit() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut client = UdsClient::from_stream(a);
        // More frames than one 512-frame writev chunk can carry.
        let msg = vec![0xA5u8; 16];

        let expected = msg.clone();
        let writer = std::thread::spawn(move || {
            let slices: Vec<&[u8]> = std::iter::repeat_n(msg.as_slice(), 700).collect();
            assert_eq!(client.send_batch(3, &slices).unwrap(), 700);
        });
        let mut peer = b;
        for _ in 0..700 {
            let (tid, data) = read_frame(&mut peer, DEFAULT_MAX_FRAME_LEN)
                .unwrap()
                .expect("frame present");
            assert_eq!(tid, 3);
            assert_eq!(data, expected);
        }
        writer.join().unwrap();
    }

    #[test]
    fn recv_batch_into_drains_a_burst_without_alloc() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let mut client = UdsClient::from_stream(a);

        for i in 0..10u8 {
            write_frame(&mut b, u32::from(i), &[i; 32]).unwrap();
        }

        let stride = 32usize;
        let mut out = vec![0u8; stride * 16];
        let mut lens = [0usize; 16];
        let n = client
            .recv_batch_into(
                &mut out,
                stride,
                &mut lens,
                Some(Duration::from_millis(200)),
            )
            .unwrap()
            .expect("burst arrives");
        assert!(n > 1, "one read must yield several frames, got {n}");
        for i in 0..n {
            assert_eq!(lens[i], 32);
            assert_eq!(out[i * stride], i as u8);
        }

        // Idle socket → timeout, not an error.
        assert!(client
            .recv_batch_into(&mut out, stride, &mut lens, Some(Duration::from_millis(10)))
            .unwrap()
            .is_none());

        // Clean EOF → Closed.
        drop(b);
        // Drain any remaining frames first.
        loop {
            match client.recv_batch_into(
                &mut out,
                stride,
                &mut lens,
                Some(Duration::from_millis(50)),
            ) {
                Ok(Some(_)) => continue,
                Ok(None) => panic!("expected Closed after EOF"),
                Err(ScgError::Closed) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
    }

    #[test]
    fn buffered_and_single_recv_paths_share_the_decoder() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let mut client = UdsClient::from_stream(a);

        write_frame(&mut b, 1, b"first").unwrap();
        write_frame(&mut b, 2, b"second").unwrap();

        // One buffered read may pull both frames; the single-frame API must
        // still see the second (no bytes lost between the two paths).
        let (tid, data) = client.recv().unwrap();
        assert_eq!((tid, data.as_slice()), (1, b"first".as_slice()));
        let (tid, data) = client.recv().unwrap();
        assert_eq!((tid, data.as_slice()), (2, b"second".as_slice()));
    }
}
