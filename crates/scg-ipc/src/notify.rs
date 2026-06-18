//! Wakeup primitives for the shared-memory rings.
//!
//! Two mechanisms are provided:
//!
//! * [`EventFd`] — an `eventfd(2)` based notifier. Its descriptor can be added
//!   to `poll`/`epoll`, which is essential on the gateway side because a relay
//!   thread must wait on the SHM ring *and* the upstream socket in a single
//!   blocking call. This is the default the integration leans on.
//! * [`futex_wait`] / [`futex_wake`] — a futex on the ring header's notify
//!   word. Lower latency for a pure SHM hop, but not pollable, so it is only
//!   suitable where a thread waits solely on the ring.
//!
//! The final default is selected by the WP0 benchmark; both are kept so the
//! gateway and clients can negotiate whichever a deployment prefers.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::AtomicU32;

use libc::c_void;

/// Mechanism used to wake a waiter blocked on a shared-memory ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeMechanism {
    /// `eventfd`-based, pollable, used by the gateway relay.
    Eventfd,
    /// Futex on the ring header's notify word, lowest latency, not pollable.
    Futex,
}

/// An owned `eventfd` used as a semaphore-style notifier.
pub struct EventFd {
    fd: OwnedFd,
}

impl EventFd {
    /// Create a new non-blocking, close-on-exec eventfd initialised to zero.
    pub fn new() -> io::Result<EventFd> {
        // EFD_CLOEXEC = 0o2000000, EFD_NONBLOCK = 0o4000.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(EventFd { fd: unsafe { OwnedFd::from_raw_fd(fd) } })
    }

    /// Wrap an already-owned eventfd descriptor (e.g. one received over a
    /// control socket).
    ///
    /// # Safety
    /// `fd` must be a valid, owned eventfd descriptor that nothing else will
    /// close.
    pub unsafe fn from_raw_fd(fd: RawFd) -> EventFd {
        EventFd { fd: OwnedFd::from_raw_fd(fd) }
    }

    /// Signal the eventfd, incrementing its counter by one (wakes one poller).
    pub fn signal(&self) -> io::Result<()> {
        let val: u64 = 1;
        loop {
            let ret = unsafe {
                libc::write(self.fd.as_raw_fd(), &val as *const u64 as *const c_void, 8)
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                // A full counter (EAGAIN) still means a pending wakeup exists.
                if err.raw_os_error() == Some(libc::EAGAIN) {
                    return Ok(());
                }
                return Err(err);
            }
            return Ok(());
        }
    }

    /// Drain the eventfd counter (clears pending notifications). Returns the
    /// accumulated count, or zero if nothing was pending.
    pub fn drain(&self) -> io::Result<u64> {
        let mut val: u64 = 0;
        loop {
            let ret = unsafe {
                libc::read(self.fd.as_raw_fd(), &mut val as *mut u64 as *mut c_void, 8)
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if err.raw_os_error() == Some(libc::EAGAIN) {
                    return Ok(0);
                }
                return Err(err);
            }
            return Ok(val);
        }
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl From<OwnedFd> for EventFd {
    fn from(fd: OwnedFd) -> Self {
        EventFd { fd }
    }
}

// ── Futex primitives ────────────────────────────────────────────────────────

/// Block until the futex `word` changes away from `expected`, or until woken.
///
/// Spurious wakeups are possible; callers must re-check their condition. A
/// `None` timeout blocks indefinitely.
pub fn futex_wait(word: &AtomicU32, expected: u32, timeout: Option<std::time::Duration>) -> io::Result<()> {
    let ts = timeout.map(|d| libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as _,
    });
    let ts_ptr = ts.as_ref().map_or(std::ptr::null(), |t| t as *const libc::timespec);

    let ret = unsafe {
        libc::syscall(
            libc::SYS_futex,
            word.as_ptr(),
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected,
            ts_ptr,
            std::ptr::null::<u32>(),
            0u32,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        // These are normal, benign outcomes of a wait.
        match err.raw_os_error() {
            Some(libc::EAGAIN) | Some(libc::EINTR) | Some(libc::ETIMEDOUT) => Ok(()),
            _ => Err(err),
        }
    } else {
        Ok(())
    }
}

/// Wake up to `count` waiters blocked on the futex `word`.
pub fn futex_wake(word: &AtomicU32, count: u32) -> io::Result<u32> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_futex,
            word.as_ptr(),
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            count,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<u32>(),
            0u32,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eventfd_signal_then_drain() {
        let ev = EventFd::new().unwrap();
        ev.signal().unwrap();
        ev.signal().unwrap();
        let count = ev.drain().unwrap();
        assert_eq!(count, 2);
        // Nothing left pending.
        assert_eq!(ev.drain().unwrap(), 0);
    }

    #[test]
    fn futex_wake_no_waiters_is_ok() {
        let word = AtomicU32::new(0);
        let woken = futex_wake(&word, 1).unwrap();
        assert_eq!(woken, 0);
    }
}
