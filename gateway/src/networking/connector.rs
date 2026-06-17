//! Outbound Connector — TCP connect with retry and shutdown-aware sleep.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Connect to a TCP target with exponential backoff retry.
/// `max_attempts` of 0 means infinite retries (for persistent tunnels).
pub fn connect_with_retry(
    addr: &str,
    max_attempts: u32,
    initial_delay: Duration,
    max_delay: Duration,
    shutdown: &AtomicBool,
) -> io::Result<TcpStream> {
    let target: SocketAddr = addr.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("parse {}: {}", addr, e),
        )
    })?;
    let mut retry_delay = initial_delay;
    let mut last_err: Option<io::Error>;

    let mut attempt = 0;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "shutdown"));
        }

        match TcpStream::connect_timeout(&target, Duration::from_secs(5)) {
            Ok(s) => return Ok(s),
            Err(e) => {
                last_err = Some(e);
                attempt += 1;
                if max_attempts > 0 && attempt >= max_attempts {
                    break;
                }
                if sleep_with_shutdown_check(retry_delay, shutdown) {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "shutdown"));
                }
                retry_delay = (retry_delay * 2).min(max_delay);
            }
        }
    }

    let e = last_err.unwrap();
    Err(io::Error::new(
        e.kind(),
        format!("connect to {}: {}", addr, e),
    ))
}

/// Sleep for the given duration, checking the shutdown flag every 500ms.
/// Returns `true` if shutdown was requested (caller should exit).
pub fn sleep_with_shutdown_check(delay: Duration, shutdown: &AtomicBool) -> bool {
    let deadline = Instant::now() + delay;
    while Instant::now() < deadline {
        if shutdown.load(Ordering::Relaxed) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}
