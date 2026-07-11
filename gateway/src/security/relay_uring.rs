//! Experimental io_uring backend for the zero-copy splice relay (evaluation PoC).
//!
//! This mirrors [`crate::security::relay::relay_bidirectional_splice`] but drives
//! readiness detection and the two splice legs of each direction through a single
//! `io_uring` submission/completion queue, so one `io_uring_enter(2)` replaces the
//! `poll(2)` plus the per-direction `splice(2)` calls of the poll+splice loop. The
//! goal is to measure whether that syscall reduction lowers per-connection context
//! switches and CPU cost under concurrency (the WP5 hypothesis); it is opt-in and
//! off by default.
//!
//! Safety note: every submitted operation (`Splice`, `PollAdd`) references only
//! file descriptors that this relay owns for its whole lifetime. Unlike a `Send`
//! op, no borrowed userspace buffer is handed to the kernel, so there is no
//! in-flight-buffer lifetime hazard; the descriptors simply must stay open until
//! the ring is dropped, which holds because the ring is dropped before the fds are
//! closed.

use io_uring::{opcode, squeue, types, IoUring};
use log::debug;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::management::telemetry::ConnectionMetrics;
use crate::networking::socket_manager::{set_nonblocking_fd, set_quickack};

const SPLICE_F_MOVE: u32 = 1;
const SPLICE_F_MORE: u32 = 4;

/// Wait window per `io_uring_enter`, matching the poll+splice relay's 100 ms poll
/// timeout so the shutdown flag stays responsive.
const WAIT_NSEC: u32 = 100_000_000;

/// Runtime gate: the io_uring backend engages only when this env var is truthy.
/// This lets the benchmark A/B the same feature-on binary (env set vs unset)
/// without a rebuild, and keeps the default path splice.
pub fn io_uring_relay_enabled() -> bool {
    matches!(
        std::env::var("SCG_RELAY_IO_URING").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Per-direction state machine. Each direction has at most one operation in flight
/// at a time, so a completion is interpreted against the current `Phase`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Need to wait for the source fd to become readable.
    PollIn,
    /// Need to splice source -> pipe.
    SpliceIn,
    /// Need to splice pipe -> destination; this many bytes remain in the pipe.
    SpliceOut(u32),
    /// Destination not writable; wait, then resume `SpliceOut(rem)`.
    PollOut(u32),
    /// Direction finished (EOF or error).
    Done,
}

struct Dir {
    src: RawFd,
    pipe_w: RawFd,
    pipe_r: RawFd,
    dst: RawFd,
    phase: Phase,
    in_flight: bool,
}

/// Create a kernel pipe with the profile-driven capacity, matching the splice path.
fn make_pipe(pipe_size: usize) -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds` is a stack `[RawFd; 2]`; `pipe2` writes exactly its two `c_int`s
    // into the array, which outlives the call. `O_CLOEXEC` is valid. The negative
    // return is checked before either descriptor is used.
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fds[0]` is the read end just created by `pipe2` and still open;
    // `F_SETPIPE_SZ` takes one `c_int` and touches no memory. Best-effort hint.
    unsafe {
        libc::fcntl(fds[0], libc::F_SETPIPE_SZ, pipe_size as libc::c_int);
    }
    Ok((fds[0], fds[1]))
}

fn close_pipe(read_fd: RawFd, write_fd: RawFd) {
    // SAFETY: both ends are owned by this relay and closed exactly once here, after
    // the ring (which referenced them) has stopped being used; no later use occurs.
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}

fn shutdown_write(fd: RawFd) {
    // SAFETY: `fd` is a valid open socket owned by the caller; `shutdown` takes the
    // fd and `SHUT_WR` and touches no memory. Best-effort teardown; result ignored.
    unsafe {
        libc::shutdown(fd, libc::SHUT_WR);
    }
}

/// Build the submission-queue entry for a direction's current phase.
/// `dir_id` (0 or 1) is stored as `user_data` so the completion can be routed back.
fn build_entry(d: &Dir, dir_id: u64, chunk: u32) -> Option<squeue::Entry> {
    let read_mask = (libc::POLLIN | libc::POLLERR | libc::POLLHUP) as u32;
    let write_mask = (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) as u32;
    let entry = match d.phase {
        Phase::SpliceIn => {
            opcode::Splice::new(types::Fd(d.src), -1, types::Fd(d.pipe_w), -1, chunk)
                .flags(SPLICE_F_MOVE | SPLICE_F_MORE)
                .build()
                .user_data(dir_id)
        }
        Phase::SpliceOut(rem) => {
            opcode::Splice::new(types::Fd(d.pipe_r), -1, types::Fd(d.dst), -1, rem)
                .flags(SPLICE_F_MOVE)
                .build()
                .user_data(dir_id)
        }
        Phase::PollIn => opcode::PollAdd::new(types::Fd(d.src), read_mask)
            .build()
            .user_data(dir_id),
        Phase::PollOut(_) => opcode::PollAdd::new(types::Fd(d.dst), write_mask)
            .build()
            .user_data(dir_id),
        Phase::Done => return None,
    };
    Some(entry)
}

/// io_uring analogue of `relay_bidirectional_splice`, with an identical signature so
/// it drops into the same call sites. Returns `Err` only when the ring or the pipes
/// cannot be created (before any bytes move), so the caller can safely fall back to
/// the splice path; once relaying it always tears down and returns `Ok(())`, exactly
/// like the poll+splice relay.
#[allow(clippy::too_many_arguments)]
pub fn relay_bidirectional_splice_uring(
    tls_fd: RawFd,
    upstream_fd: RawFd,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &AtomicBool,
    _delay_ms: u64,
    pipe_size: usize,
    _busy_poll_us: u32,
    _bdp_adaptive: bool,
    _bdp_queue_budget_us: u64,
) -> io::Result<()> {
    // Setup (fallible → caller falls back). No connection bytes have moved yet.
    // single_issuer: this ring is submitted from exactly one thread (the relay
    // thread), letting the kernel skip submitter-side locking. We deliberately do
    // NOT set coop/defer taskrun so that a plain `submit()` posts inline
    // completions immediately, which lets the loop drain many splices per wakeup
    // (see the submit-then-drain loop below).
    let mut ring: IoUring = IoUring::builder().setup_single_issuer().build(8)?;
    let (pipe_fwd_r, pipe_fwd_w) = make_pipe(pipe_size)?;
    let (pipe_rev_r, pipe_rev_w) = match make_pipe(pipe_size) {
        Ok(p) => p,
        Err(e) => {
            close_pipe(pipe_fwd_r, pipe_fwd_w);
            return Err(e);
        }
    };

    // Non-blocking fds: a splice with no data / no space returns EAGAIN inline
    // rather than being offloaded to an io-wq worker thread (which would add its
    // own context switches). The EAGAIN completion is reaped inline and the
    // direction parks on a PollAdd, so the relay only sleeps when genuinely idle.
    set_nonblocking_fd(tls_fd);
    set_nonblocking_fd(upstream_fd);
    set_quickack(tls_fd);
    set_quickack(upstream_fd);

    let chunk = pipe_size.min(u32::MAX as usize) as u32;
    let read_ready = libc::POLLIN as i32;
    let write_ready = libc::POLLOUT as i32;

    // dir 0: tls -> upstream ; dir 1: upstream -> tls. Both start by attempting a
    // splice; an idle fd yields EAGAIN and transitions to PollIn (which parks).
    let mut dirs = [
        Dir {
            src: tls_fd,
            pipe_w: pipe_fwd_w,
            pipe_r: pipe_fwd_r,
            dst: upstream_fd,
            phase: Phase::SpliceIn,
            in_flight: false,
        },
        Dir {
            src: upstream_fd,
            pipe_w: pipe_rev_w,
            pipe_r: pipe_rev_r,
            dst: tls_fd,
            phase: Phase::SpliceIn,
            in_flight: false,
        },
    ];

    let ts = types::Timespec::new().sec(0).nsec(WAIT_NSEC);
    let mut teardown = false;

    'relay: loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        if dirs.iter().all(|d| d.phase == Phase::Done) {
            break;
        }

        // Submit the next op for every direction that is runnable and idle.
        for (i, d) in dirs.iter_mut().enumerate() {
            if d.phase == Phase::Done || d.in_flight {
                continue;
            }
            if let Some(entry) = build_entry(d, i as u64, chunk) {
                // SAFETY: `entry` is a `Splice`/`PollAdd` SQE referencing only fds
                // this relay keeps open until after the ring is dropped; no borrowed
                // userspace buffer is passed, so the kernel dereferences no freed
                // memory while the op is in flight.
                let pushed = {
                    let mut sq = ring.submission();
                    unsafe { sq.push(&entry).is_ok() }
                };
                if pushed {
                    d.in_flight = true;
                }
            }
        }

        // Issue the queued SQEs without sleeping and reap whatever completed
        // inline. A busy connection keeps completing splices here, so it drains
        // many per loop turn without ever parking — matching the poll+splice
        // relay's synchronous drain and avoiding one wakeup per message.
        match ring.submit() {
            Ok(_) => {}
            Err(ref e) if e.raw_os_error() == Some(libc::EINTR) => {}
            Err(e) => {
                debug!("io_uring relay submit error: {e}");
                teardown = true;
                break;
            }
        }

        let mut events: [(u64, i32); 8] = [(0, 0); 8];
        let mut n_events = 0usize;
        {
            let mut cq = ring.completion();
            cq.sync();
            for cqe in &mut cq {
                if n_events < events.len() {
                    events[n_events] = (cqe.user_data(), cqe.result());
                    n_events += 1;
                }
            }
        }

        // Nothing completed inline: every runnable op is parked on its fd, so park
        // the thread until one completes or the shutdown-poll timeout fires. This
        // is the ONLY place the relay sleeps, so its wakeup count tracks genuine
        // idle transitions rather than per-message completions.
        if n_events == 0 {
            let args = types::SubmitArgs::new().timespec(&ts);
            match ring.submitter().submit_with_args(1, &args) {
                Ok(_) => {}
                Err(ref e) if e.raw_os_error() == Some(libc::ETIME) => {}
                Err(ref e) if e.raw_os_error() == Some(libc::EINTR) => {}
                Err(e) => {
                    debug!("io_uring relay ring error: {e}");
                    teardown = true;
                    break;
                }
            }
            let mut cq = ring.completion();
            cq.sync();
            for cqe in &mut cq {
                if n_events < events.len() {
                    events[n_events] = (cqe.user_data(), cqe.result());
                    n_events += 1;
                }
            }
        }

        for &(ud, res) in events.iter().take(n_events) {
            let i = ud as usize;
            if i >= dirs.len() {
                continue;
            }
            // Read the fd arrays before taking the &mut borrow of the direction.
            let fds = [tls_fd, upstream_fd];
            let _ = &fds; // reserved for optional adaptive tuning parity
            let d = &mut dirs[i];
            d.in_flight = false;
            match d.phase {
                Phase::PollIn => {
                    if res < 0 {
                        d.phase = Phase::Done;
                        shutdown_write(d.dst);
                        teardown = true;
                    } else if res & read_ready != 0 {
                        d.phase = Phase::SpliceIn;
                    } else {
                        // POLLHUP/POLLERR without readable data → EOF.
                        d.phase = Phase::Done;
                        shutdown_write(d.dst);
                        teardown = true;
                    }
                }
                Phase::SpliceIn => {
                    if res > 0 {
                        let moved = res as usize;
                        conn_metrics.record_read(moved);
                        conn_metrics.record_relay(moved);
                        d.phase = Phase::SpliceOut(res as u32);
                    } else if res == 0 {
                        d.phase = Phase::Done;
                        shutdown_write(d.dst);
                        teardown = true;
                    } else if res == -libc::EAGAIN {
                        d.phase = Phase::PollIn;
                    } else {
                        debug!("io_uring splice-in error: {res}");
                        d.phase = Phase::Done;
                        shutdown_write(d.dst);
                        teardown = true;
                    }
                }
                Phase::SpliceOut(rem) => {
                    if res > 0 {
                        let w = res as u32;
                        d.phase = if w < rem {
                            Phase::SpliceOut(rem - w)
                        } else {
                            Phase::SpliceIn
                        };
                    } else if res == -libc::EAGAIN {
                        d.phase = Phase::PollOut(rem);
                    } else {
                        debug!("io_uring splice-out error: {res}");
                        d.phase = Phase::Done;
                        shutdown_write(d.dst);
                        teardown = true;
                    }
                }
                Phase::PollOut(rem) => {
                    if res >= 0 && res & write_ready != 0 {
                        d.phase = Phase::SpliceOut(rem);
                    } else {
                        d.phase = Phase::Done;
                        shutdown_write(d.dst);
                        teardown = true;
                    }
                }
                Phase::Done => {}
            }
            if teardown {
                break 'relay;
            }
        }
    }

    // Teardown: drop the ring before closing the pipes so no op references a closed
    // fd, then mirror the splice path's final half-close of both sockets.
    drop(ring);
    close_pipe(pipe_fwd_r, pipe_fwd_w);
    close_pipe(pipe_rev_r, pipe_rev_w);
    shutdown_write(tls_fd);
    shutdown_write(upstream_fd);
    let _ = teardown;
    Ok(())
}

// ─── io_uring recv/send backend (copy-based, fast-poll path) ──────────────────

/// Per-direction state for the recv/send relay. `Recv` fills the direction's own
/// buffer; `Send` drains `filled` bytes of it to the destination.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RsPhase {
    Recv,
    Send { filled: u32, sent: u32 },
    Done,
}

struct RsDir {
    src: RawFd,
    dst: RawFd,
    phase: RsPhase,
    in_flight: bool,
}

/// io_uring relay using `recv`/`send` (not splice). Unlike `IORING_OP_SPLICE`,
/// `recv`/`send` are on io_uring's inline fast-poll path, so they do NOT get
/// offloaded to io-wq worker threads. This is the copy-based counterpart to the
/// poll(2)+read/write baseline and lets the relay-backend study answer whether io_uring
/// helps a path built from its fast-path ops. Same `Err`-only-before-bytes-move
/// contract as the splice backend, so the caller can fall back safely.
pub fn relay_bidirectional_recvsend_uring(
    tls_fd: RawFd,
    upstream_fd: RawFd,
    conn_metrics: &mut ConnectionMetrics,
    shutdown: &AtomicBool,
    buf_size: usize,
) -> io::Result<()> {
    let mut ring: IoUring = IoUring::builder().setup_single_issuer().build(8)?;
    let cap = buf_size.clamp(64 * 1024, 4 * 1024 * 1024);
    let mut bufs: [Vec<u8>; 2] = [vec![0u8; cap], vec![0u8; cap]];

    set_nonblocking_fd(tls_fd);
    set_nonblocking_fd(upstream_fd);
    set_quickack(tls_fd);
    set_quickack(upstream_fd);

    let mut dirs = [
        RsDir {
            src: tls_fd,
            dst: upstream_fd,
            phase: RsPhase::Recv,
            in_flight: false,
        },
        RsDir {
            src: upstream_fd,
            dst: tls_fd,
            phase: RsPhase::Recv,
            in_flight: false,
        },
    ];

    let ts = types::Timespec::new().sec(0).nsec(WAIT_NSEC);
    let mut teardown = false;

    'relay: loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        if dirs.iter().all(|d| d.phase == RsPhase::Done) {
            break;
        }

        for i in 0..dirs.len() {
            if dirs[i].phase == RsPhase::Done || dirs[i].in_flight {
                continue;
            }
            let entry = match dirs[i].phase {
                RsPhase::Recv => {
                    let len = bufs[i].len() as u32;
                    opcode::Recv::new(types::Fd(dirs[i].src), bufs[i].as_mut_ptr(), len)
                        .build()
                        .user_data(i as u64)
                }
                RsPhase::Send { filled, sent } => {
                    let slice = &bufs[i][sent as usize..filled as usize];
                    opcode::Send::new(types::Fd(dirs[i].dst), slice.as_ptr(), slice.len() as u32)
                        .build()
                        .user_data(i as u64)
                }
                RsPhase::Done => continue,
            };
            // SAFETY: the Recv/Send op holds a raw pointer into `bufs[i]`, which lives
            // for the whole relay and is dropped only after the ring. Each direction
            // has at most one op in flight (Recv XOR Send), so the buffer is never
            // read and written concurrently, and it is never resized while in flight.
            let pushed = {
                let mut sq = ring.submission();
                unsafe { sq.push(&entry).is_ok() }
            };
            if pushed {
                dirs[i].in_flight = true;
            }
        }

        match ring.submit() {
            Ok(_) => {}
            Err(ref e) if e.raw_os_error() == Some(libc::EINTR) => {}
            Err(e) => {
                debug!("io_uring recv/send submit error: {e}");
                teardown = true;
                break;
            }
        }

        let mut events: [(u64, i32); 8] = [(0, 0); 8];
        let mut n_events = 0usize;
        {
            let mut cq = ring.completion();
            cq.sync();
            for cqe in &mut cq {
                if n_events < events.len() {
                    events[n_events] = (cqe.user_data(), cqe.result());
                    n_events += 1;
                }
            }
        }

        if n_events == 0 {
            let args = types::SubmitArgs::new().timespec(&ts);
            match ring.submitter().submit_with_args(1, &args) {
                Ok(_) => {}
                Err(ref e) if e.raw_os_error() == Some(libc::ETIME) => {}
                Err(ref e) if e.raw_os_error() == Some(libc::EINTR) => {}
                Err(e) => {
                    debug!("io_uring recv/send ring error: {e}");
                    teardown = true;
                    break;
                }
            }
            let mut cq = ring.completion();
            cq.sync();
            for cqe in &mut cq {
                if n_events < events.len() {
                    events[n_events] = (cqe.user_data(), cqe.result());
                    n_events += 1;
                }
            }
        }

        for &(ud, res) in events.iter().take(n_events) {
            let i = ud as usize;
            if i >= dirs.len() {
                continue;
            }
            dirs[i].in_flight = false;
            match dirs[i].phase {
                RsPhase::Recv => {
                    if res > 0 {
                        let n = res as usize;
                        conn_metrics.record_read(n);
                        conn_metrics.record_relay(n);
                        dirs[i].phase = RsPhase::Send {
                            filled: res as u32,
                            sent: 0,
                        };
                    } else if res == 0 {
                        dirs[i].phase = RsPhase::Done;
                        shutdown_write(dirs[i].dst);
                        teardown = true;
                    } else if res == -libc::EAGAIN {
                        dirs[i].phase = RsPhase::Recv;
                    } else {
                        debug!("io_uring recv error: {res}");
                        dirs[i].phase = RsPhase::Done;
                        shutdown_write(dirs[i].dst);
                        teardown = true;
                    }
                }
                RsPhase::Send { filled, sent } => {
                    if res > 0 {
                        let new_sent = sent + res as u32;
                        dirs[i].phase = if new_sent < filled {
                            RsPhase::Send {
                                filled,
                                sent: new_sent,
                            }
                        } else {
                            RsPhase::Recv
                        };
                    } else if res == -libc::EAGAIN {
                        dirs[i].phase = RsPhase::Send { filled, sent };
                    } else {
                        debug!("io_uring send error: {res}");
                        dirs[i].phase = RsPhase::Done;
                        shutdown_write(dirs[i].dst);
                        teardown = true;
                    }
                }
                RsPhase::Done => {}
            }
            if teardown {
                break 'relay;
            }
        }
    }

    drop(ring);
    shutdown_write(tls_fd);
    shutdown_write(upstream_fd);
    let _ = teardown;
    Ok(())
}
