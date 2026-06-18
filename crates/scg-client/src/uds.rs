//! UDS data-plane client.
//!
//! After the gateway hands back a socket path + capability token, the client
//! connects, presents the token in the HELLO frame, and then exchanges
//! `[len][traffic_id][data]` frames with the gateway. The link is full duplex:
//! the application writes plaintext and reads back whatever the upstream
//! returns through the gateway.

use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use scg_ipc::frame::DEFAULT_MAX_FRAME_LEN;
use scg_ipc::{read_frame, write_frame, CapabilityToken, Hello, Role};

use crate::error::{Result, ScgError};
use crate::poll::poll_readable;

/// A connected UDS endpoint.
pub struct UdsClient {
    stream: UnixStream,
}

impl UdsClient {
    /// Connect to `socket_path` and authenticate with `token`.
    pub fn connect(socket_path: &str, token: CapabilityToken, role: Role) -> Result<Self> {
        let mut stream = UnixStream::connect(socket_path)?;
        let hello = Hello::new(role, token).encode();
        use std::io::Write;
        stream.write_all(&hello)?;
        Ok(UdsClient { stream })
    }

    /// Send one framed message.
    pub fn send(&mut self, traffic_id: u32, data: &[u8]) -> Result<()> {
        write_frame(&mut self.stream, traffic_id, data)?;
        Ok(())
    }

    /// Block until one framed message arrives.
    pub fn recv(&mut self) -> Result<(u32, Vec<u8>)> {
        match read_frame(&mut self.stream, DEFAULT_MAX_FRAME_LEN)? {
            Some(frame) => Ok(frame),
            None => Err(ScgError::Closed),
        }
    }

    /// Wait up to `timeout` for a message. Returns `Ok(None)` on timeout.
    ///
    /// The timeout only gates the wait for the first byte; once the socket is
    /// readable the full frame is read with blocking semantics so framing can
    /// never be left half-consumed.
    pub fn recv_timeout(&mut self, timeout: Option<Duration>) -> Result<Option<(u32, Vec<u8>)>> {
        if !poll_readable(self.stream.as_raw_fd(), timeout)? {
            return Ok(None);
        }
        match read_frame(&mut self.stream, DEFAULT_MAX_FRAME_LEN)? {
            Some(frame) => Ok(Some(frame)),
            None => Err(ScgError::Closed),
        }
    }
}

/// Drop closes the socket, which the gateway observes as a clean disconnect.
impl Drop for UdsClient {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}
