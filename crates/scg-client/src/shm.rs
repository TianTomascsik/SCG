//! Shared-memory data-plane client.
//!
//! After `CreateShmEndpoint` the gateway hands back a *control socket* path and
//! a capability token. The client connects to that socket, presents the token
//! in a HELLO frame, and receives — over `SCM_RIGHTS` — a [`ShmOffer`] plus the
//! five descriptors describing the two lock-free rings and their wakeup
//! `eventfd`s.
//!
//! Ring directions (from the client's point of view):
//! * `c2g` (client→gateway): the client **produces**; mapped read/write.
//! * `g2c` (gateway→client): the client **consumes**; mapped **read-only**
//!   (the gateway sealed it `F_SEAL_FUTURE_WRITE`).

use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use scg_ipc::handshake::{ShmOffer, SHM_NOTIFY_EVENTFD, SHM_NOTIFY_FUTEX, SHM_RING_SLOT};
use scg_ipc::notify::futex_wait;
use scg_ipc::os::{self, MapProt, Mapping};
use scg_ipc::shm::{client_rings, RingConsumer, RingProducer, SHM_CONTROL_SIZE};
use scg_ipc::shm_slot::{
    client_slot_rings, slot_control_size, PushOutcome, SlotConsumer, SlotProducer,
};
use scg_ipc::{
    EventFd, CapabilityToken, Hello, Role, SHM_FD_CONTROL, SHM_FD_DATA_C2G, SHM_FD_DATA_G2C,
    SHM_FD_EVT_C2G, SHM_FD_EVT_G2C, SHM_OFFER_LEN,
};

use crate::error::{Result, ScgError};
use crate::poll::poll_readable;

/// Back-off applied when the outbound ring is momentarily full.
const SEND_FULL_BACKOFF: Duration = Duration::from_micros(50);

/// Busy-poll window (microseconds) on the futex receive path before parking.
const FUTEX_SPIN_US: u64 = 15;

/// Maximum futex park before re-checking the ring (covers any missed wake).
const FUTEX_PARK: Duration = Duration::from_millis(50);

/// The two interchangeable client-side ring implementations.
enum ClientBackend {
    /// Variable-length packed byte-stream ring.
    ByteStream {
        producer: RingProducer,
        consumer: RingConsumer,
    },
    /// Fixed-slot Vyukov ring.
    Slot {
        producer: SlotProducer,
        consumer: SlotConsumer,
    },
}

impl ClientBackend {
    /// Try to push one frame to the gateway. `Ok(true)` on success, `Ok(false)`
    /// if the ring is full, `Err` if the frame can never fit.
    #[inline]
    fn try_push(&self, traffic_id: u32, data: &[u8]) -> Result<bool> {
        match self {
            ClientBackend::ByteStream { producer, .. } => producer
                .try_push(traffic_id, data)
                .map_err(|_| ScgError::FrameTooLarge),
            ClientBackend::Slot { producer, .. } => match producer
                .try_push(traffic_id, data)
                .map_err(|_| ScgError::FrameTooLarge)?
            {
                PushOutcome::Pushed { .. } => Ok(true),
                PushOutcome::Full => Ok(false),
            },
        }
    }

    /// Pop one frame from the gateway, if any.
    #[inline]
    fn try_pop(&self) -> Option<(u32, Vec<u8>)> {
        match self {
            ClientBackend::ByteStream { consumer, .. } => consumer.try_pop(),
            ClientBackend::Slot { consumer, .. } => consumer.try_pop(),
        }
    }

    /// Pop one frame's payload directly into a caller-owned slice, returning
    /// `(traffic_id, copied_len)`. Single-copy, allocation-free.
    #[inline]
    fn try_pop_into_slice(&self, out: &mut [u8]) -> Option<(u32, usize)> {
        match self {
            ClientBackend::ByteStream { consumer, .. } => consumer.try_pop_into_slice(out),
            ClientBackend::Slot { consumer, .. } => consumer.try_pop_into_slice(out),
        }
    }

    /// Whether the gateway→client ring currently appears empty.
    #[inline]
    fn consumer_is_empty(&self) -> bool {
        match self {
            ClientBackend::ByteStream { consumer, .. } => consumer.is_empty(),
            ClientBackend::Slot { consumer, .. } => consumer.is_empty(),
        }
    }

    /// The gateway→client futex word (slot ring only).
    #[inline]
    fn g2c_notify_word(&self) -> Option<&AtomicU32> {
        match self {
            ClientBackend::Slot { consumer, .. } => Some(consumer.notify_word()),
            ClientBackend::ByteStream { .. } => None,
        }
    }
}

/// A connected shared-memory endpoint.
pub struct ShmClient {
    // The control socket must stay open for the lifetime of the session: the
    // gateway watches it for hang-up to detect client disconnect.
    _control: UnixStream,
    // Mappings are kept alive for as long as the rings reference them.
    _control_map: Mapping,
    _data_c2g_map: Mapping,
    _data_g2c_map: Mapping,
    backend: ClientBackend,
    /// Gateway→client wakeup mechanism negotiated in the offer.
    notify: u8,
    c2g_evt: EventFd,
    g2c_evt: EventFd,
}

// SAFETY: the rings synchronise all shared access through atomics in the
// control page; the handle may be moved between threads.
unsafe impl Send for ShmClient {}

impl ShmClient {
    /// Connect to the control socket, authenticate, and map the rings.
    pub fn connect(control_socket_path: &str, token: CapabilityToken, role: Role) -> Result<Self> {
        let control = UnixStream::connect(control_socket_path)?;

        // Present the capability token.
        {
            use std::io::Write;
            let hello = Hello::new(role, token).encode();
            (&control).write_all(&hello)?;
        }

        // Receive the offer descriptor plus the five ring/eventfd descriptors.
        let mut payload = [0u8; SHM_OFFER_LEN];
        let received = os::recv_with_fds(control.as_raw_fd(), &mut payload)?;
        if received.bytes != SHM_OFFER_LEN {
            return Err(ScgError::BadOffer(format!(
                "short offer: {} of {} bytes",
                received.bytes, SHM_OFFER_LEN
            )));
        }

        let offer = ShmOffer::decode(&payload)
            .map_err(|e| ScgError::BadOffer(format!("decode failed: {e}")))?;

        if offer.notify != SHM_NOTIFY_EVENTFD && offer.notify != SHM_NOTIFY_FUTEX {
            return Err(ScgError::BadOffer(format!(
                "unsupported notify mode {}",
                offer.notify
            )));
        }

        let fds = received.fds;
        if fds.len() != 5 {
            close_all(&fds);
            return Err(ScgError::BadOffer(format!(
                "expected 5 descriptors, got {}",
                fds.len()
            )));
        }

        let control_fd = fds[SHM_FD_CONTROL];
        let data_c2g_fd = fds[SHM_FD_DATA_C2G];
        let data_g2c_fd = fds[SHM_FD_DATA_G2C];
        let c2g_evt_fd = fds[SHM_FD_EVT_C2G];
        let g2c_evt_fd = fds[SHM_FD_EVT_G2C];

        let cap_c2g = offer.cap_c2g as usize;
        let cap_g2c = offer.cap_g2c as usize;
        let is_slot = offer.ring_kind == SHM_RING_SLOT;
        let ctl_len = if is_slot {
            round_up(slot_control_size(offer.capacity as usize), page_size())
        } else {
            round_up(SHM_CONTROL_SIZE, page_size())
        };

        // Map the three regions. On any failure the remaining memfds and the
        // eventfds are closed before returning.
        let mapped = (|| -> Result<(Mapping, Mapping, Mapping)> {
            let control_map = os::mmap_shared(control_fd, ctl_len, MapProt::ReadWrite)?;
            // Client produces into c2g (RW) and consumes from g2c (RO).
            let data_c2g_map = os::mmap_shared(data_c2g_fd, cap_c2g, MapProt::ReadWrite)?;
            let data_g2c_map = os::mmap_shared(data_g2c_fd, cap_g2c, MapProt::Read)?;
            Ok((control_map, data_c2g_map, data_g2c_map))
        })();

        let (control_map, data_c2g_map, data_g2c_map) = match mapped {
            Ok(m) => m,
            Err(e) => {
                close_all(&fds);
                return Err(e);
            }
        };

        // The mappings now keep the memory alive; the memfd descriptors are no
        // longer needed. The eventfds are retained (wrapped below).
        os::close(control_fd);
        os::close(data_c2g_fd);
        os::close(data_g2c_fd);

        // SAFETY: the mappings are live and at least the stated lengths;
        // `data_g2c` is a read-only mapping, matching the consumer ring.
        let backend = if is_slot {
            let capacity = offer.capacity as usize;
            let segment_size = offer.segment_size as usize;
            let (producer, consumer) = unsafe {
                client_slot_rings(
                    control_map.as_ptr(),
                    ctl_len,
                    capacity,
                    segment_size,
                    data_c2g_map.as_ptr(),
                    cap_c2g,
                    data_g2c_map.as_ptr() as *const u8,
                    cap_g2c,
                )
                .map_err(|e| ScgError::BadOffer(format!("slot ring geometry: {e}")))?
            };
            ClientBackend::Slot { producer, consumer }
        } else {
            let (producer, consumer) = unsafe {
                client_rings(
                    control_map.as_ptr(),
                    ctl_len,
                    data_c2g_map.as_ptr(),
                    cap_c2g,
                    data_g2c_map.as_ptr() as *const u8,
                    cap_g2c,
                )
                .map_err(|e| ScgError::BadOffer(format!("ring geometry: {e}")))?
            };
            ClientBackend::ByteStream { producer, consumer }
        };

        // SAFETY: each eventfd descriptor was just received with CLOEXEC and is
        // owned exclusively by this client now.
        let c2g_evt = unsafe { EventFd::from_raw_fd(c2g_evt_fd) };
        let g2c_evt = unsafe { EventFd::from_raw_fd(g2c_evt_fd) };

        Ok(ShmClient {
            _control: control,
            _control_map: control_map,
            _data_c2g_map: data_c2g_map,
            _data_g2c_map: data_g2c_map,
            backend,
            notify: offer.notify,
            c2g_evt,
            g2c_evt,
        })
    }

    /// Push one framed message to the gateway, blocking while the ring is full.
    pub fn send(&mut self, traffic_id: u32, data: &[u8]) -> Result<()> {
        loop {
            match self.try_send(traffic_id, data)? {
                true => return Ok(()),
                false => {
                    // Ring full: nudge the gateway to drain, then back off.
                    std::thread::sleep(SEND_FULL_BACKOFF);
                }
            }
        }
    }

    /// Try to push one framed message without waiting for ring capacity.
    ///
    /// Returns `Ok(false)` when the ring is full. Callers that own a shutdown
    /// signal (such as SESHAT's sender loop) should use this form so they can
    /// observe cancellation instead of blocking forever after a peer exits.
    pub fn try_send(&mut self, traffic_id: u32, data: &[u8]) -> Result<bool> {
        let pushed = self.backend.try_push(traffic_id, data)?;
        // Wake the gateway whether or not we pushed (it may be sleeping before
        // it drains). The client→gateway direction always uses an eventfd.
        self.c2g_evt.signal()?;
        Ok(pushed)
    }

    /// Try to push a batch of framed messages, signalling the gateway **once**
    /// for the whole batch instead of once per message.
    ///
    /// Returns the number of leading messages accepted: pushing stops at the
    /// first message the ring rejects (full), so `Ok(n)` with `n < msgs.len()`
    /// means the caller should retry from index `n`. A single eventfd signal is
    /// emitted whenever at least one message was pushed, amortising the wakeup
    /// syscall across the batch (the gateway drains the ring to empty per wake).
    pub fn try_send_batch(&mut self, traffic_id: u32, msgs: &[&[u8]]) -> Result<usize> {
        let mut sent = 0;
        for m in msgs {
            if !self.backend.try_push(traffic_id, m)? {
                break;
            }
            sent += 1;
        }
        if sent > 0 {
            self.c2g_evt.signal()?;
        }
        Ok(sent)
    }

    /// Block until one framed message is available from the gateway.
    pub fn recv(&mut self) -> Result<(u32, Vec<u8>)> {
        loop {
            if let Some(frame) = self.backend.try_pop() {
                return Ok(frame);
            }
            self.wait_g2c(None)?;
        }
    }

    /// Wait up to `timeout` for a message. Returns `Ok(None)` on timeout.
    pub fn recv_timeout(&mut self, timeout: Option<Duration>) -> Result<Option<(u32, Vec<u8>)>> {
        if let Some(frame) = self.backend.try_pop() {
            return Ok(Some(frame));
        }
        if !self.wait_g2c(timeout)? {
            return Ok(None);
        }
        Ok(self.backend.try_pop())
    }

    /// Non-blocking single-copy receive: pop the next frame's payload directly
    /// into `out`, returning `(traffic_id, copied_len)` or `None` if the ring is
    /// empty. Performs no allocation and no wait — pair with
    /// [`wait_readable`](Self::wait_readable) to drain a batch after one wake.
    pub fn try_recv_into(&mut self, out: &mut [u8]) -> Result<Option<(u32, usize)>> {
        Ok(self.backend.try_pop_into_slice(out))
    }

    /// Blocking single-copy receive into `out`. Waits up to `timeout` for a
    /// frame, then copies its payload into `out`. Returns `Ok(None)` on timeout.
    pub fn recv_into(
        &mut self,
        out: &mut [u8],
        timeout: Option<Duration>,
    ) -> Result<Option<(u32, usize)>> {
        if let Some(r) = self.backend.try_pop_into_slice(out) {
            return Ok(Some(r));
        }
        if !self.wait_g2c(timeout)? {
            return Ok(None);
        }
        Ok(self.backend.try_pop_into_slice(out))
    }

    /// Wait for a gateway→client notification using the negotiated mechanism.
    /// Returns `Ok(true)` if it may now have data, `Ok(false)` on timeout.
    fn wait_g2c(&mut self, timeout: Option<Duration>) -> Result<bool> {
        if self.notify == SHM_NOTIFY_FUTEX {
            if let Some(word) = self.backend.g2c_notify_word() {
                // Spin briefly so a closely-following producer is caught without
                // a syscall, then park on the futex until the word changes.
                let observed = word.load(Ordering::Acquire);
                let deadline = Instant::now() + Duration::from_micros(FUTEX_SPIN_US);
                while self.backend.consumer_is_empty() && Instant::now() < deadline {
                    std::hint::spin_loop();
                }
                if !self.backend.consumer_is_empty() {
                    return Ok(true);
                }
                let park = match timeout {
                    Some(t) => t.min(FUTEX_PARK),
                    None => FUTEX_PARK,
                };
                let _ = futex_wait(word, observed, Some(park));
                return Ok(true);
            }
        }
        // eventfd path.
        if !poll_readable(self.g2c_evt.as_raw_fd(), timeout)? {
            return Ok(false);
        }
        let _ = self.g2c_evt.drain();
        Ok(true)
    }
}

fn close_all(fds: &[RawFd]) {
    for &fd in fds {
        os::close(fd);
    }
}

fn page_size() -> usize {
    // SAFETY: `sysconf` with a valid name has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 {
        v as usize
    } else {
        4096
    }
}

fn round_up(n: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (n + align - 1) & !(align - 1)
}
