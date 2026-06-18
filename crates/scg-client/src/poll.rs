//! Minimal `poll(2)` wrapper for readiness waits with an optional timeout.

use std::io;
use std::os::unix::io::RawFd;
use std::time::Duration;

/// Wait until `fd` is readable, or until `timeout` elapses.
///
/// `timeout == None` blocks indefinitely. Returns `Ok(true)` if the fd became
/// readable (or hung up), `Ok(false)` on timeout. `EINTR` is retried.
pub fn poll_readable(fd: RawFd, timeout: Option<Duration>) -> io::Result<bool> {
    // Clamp the timeout to a c_int millisecond value; `-1` means "block".
    let timeout_ms: libc::c_int = match timeout {
        None => -1,
        Some(d) => {
            let ms = d.as_millis();
            if ms > libc::c_int::MAX as u128 {
                libc::c_int::MAX
            } else {
                ms as libc::c_int
            }
        }
    };

    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a valid, initialised single-element array.
        let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout_ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                // Retried with a (possibly) unchanged timeout. For a bounded
                // wait this can over-wait slightly on signal storms, which is
                // acceptable for a readiness probe.
                if timeout_ms == 0 {
                    return Ok(false);
                }
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            return Ok(false);
        }
        // Readable, error, or hang-up all mean "try to read now".
        return Ok(pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0);
    }
}
