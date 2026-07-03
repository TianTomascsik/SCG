//! Sealed shared-memory ring channel.
//!
//! # Topology
//!
//! An endpoint uses **two unidirectional SPSC rings** plus a small shared
//! control page:
//!
//! ```text
//!   client ──c2g ring──▶ gateway      (client produces, gateway consumes)
//!   client ◀─g2c ring── gateway       (gateway produces, client consumes)
//! ```
//!
//! # Why control and data are separate memfds
//!
//! A ring needs the *producer* to update `write_idx` and the *consumer* to
//! update `read_idx`. That makes a single fully-read-only mapping impossible
//! for either party. We therefore split each endpoint into:
//!
//! * a **control** memfd ([`ShmControl`]) holding both rings' indices/notify
//!   words — mapped read/write by both sides, but every value the gateway reads
//!   from it is validated (never trusted) on **both** the consume side (frame
//!   length clamped to the slot) and the produce side (the peer-written
//!   `read_idx`/`seq` is bounded to its valid window, else [`ShmError::RingCorrupt`]
//!   — DP-11);
//! * two **data** memfds holding only the ring bytes.
//!
//! The data memfd the gateway *produces* into (`g2c`) is sealed with
//! `F_SEAL_FUTURE_WRITE` *after* the gateway has its writable mapping: the
//! gateway keeps writing through its pre-seal mapping, while the client can only
//! `mmap` it `PROT_READ`. That realises the "consumer maps read-only, cannot
//! corrupt the producer" guarantee. (Plain `F_SEAL_WRITE` cannot be used on a
//! ring with a live producer, since it blocks the producer too.)
//!
//! The data memfd the client produces into (`c2g`) is left writable for the
//! client; the gateway maps it `PROT_READ` and consumes it defensively.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::frame::{decode_header, encode_header, FRAME_HEADER_LEN};

/// Control-page magic: ASCII "SCG1".
pub const SHM_MAGIC: u32 = 0x5343_4731;
/// Control-page format version.
pub const SHM_VERSION: u32 = 1;

/// Flag: the `g2c` data region is sealed read-only for the peer.
pub const SHM_FLAG_SEALED_G2C: u32 = 0x0000_0001;

/// Per-ring shared indices. One producer updates `write_idx`; one consumer
/// updates `read_idx`. `notify_word` backs the optional futex notifier.
#[repr(C)]
#[derive(Debug)]
pub struct RingIndices {
    /// Absolute count of bytes written by the producer (monotonic, wraps at u64).
    pub write_idx: AtomicU64,
    /// Absolute count of bytes consumed by the consumer.
    pub read_idx: AtomicU64,
    /// Futex word bumped by the producer to wake a futex-waiting consumer.
    pub notify_word: AtomicU32,
    _rsv: u32,
}

/// The shared control page for one endpoint (both rings).
#[repr(C, align(64))]
#[derive(Debug)]
pub struct ShmControl {
    /// Must equal [`SHM_MAGIC`].
    pub magic: u32,
    /// Must equal [`SHM_VERSION`].
    pub version: u32,
    /// Bitmask of `SHM_FLAG_*`.
    pub flags: u32,
    _rsv0: u32,
    /// Capacity in bytes of the client→gateway data region.
    pub cap_c2g: u64,
    /// Capacity in bytes of the gateway→client data region.
    pub cap_g2c: u64,
    /// Indices for the client→gateway ring (client produces).
    pub c2g: RingIndices,
    /// Indices for the gateway→client ring (gateway produces).
    pub g2c: RingIndices,
}

/// Size of the control page in bytes.
pub const SHM_CONTROL_SIZE: usize = std::mem::size_of::<ShmControl>();

/// Errors from attaching to or validating a shared-memory channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShmError {
    /// Mapping is smaller than the control structure.
    TooSmall,
    /// Control magic did not match [`SHM_MAGIC`].
    BadMagic,
    /// Control version did not match [`SHM_VERSION`].
    BadVersion,
    /// A data mapping is smaller than the capacity recorded in the control page.
    BadGeometry,
    /// A frame is larger than the ring can ever hold (`capacity - header`).
    FrameTooLarge,
    /// The peer-writable ring control state (slot `seq` / `read_idx`) is outside
    /// its valid window — a corrupt or hostile peer. The producer tears the ring
    /// down instead of stalling forever (DP-11).
    RingCorrupt,
}

impl std::fmt::Display for ShmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ShmError::TooSmall => "shm mapping smaller than control page",
            ShmError::BadMagic => "shm control magic mismatch",
            ShmError::BadVersion => "shm control version mismatch",
            ShmError::BadGeometry => "shm data mapping smaller than advertised capacity",
            ShmError::FrameTooLarge => "frame larger than ring capacity",
            ShmError::RingCorrupt => "shared ring control state outside its valid window",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ShmError {}

impl ShmControl {
    /// Initialise a freshly-mapped control page in place.
    ///
    /// # Safety
    /// `ptr` must point at a writable mapping of at least [`SHM_CONTROL_SIZE`]
    /// bytes that is not concurrently accessed.
    pub unsafe fn init(ptr: *mut u8, cap_c2g: usize, cap_g2c: usize, flags: u32) {
        let ctl = ptr as *mut ShmControl;
        std::ptr::write(
            ctl,
            ShmControl {
                magic: SHM_MAGIC,
                version: SHM_VERSION,
                flags,
                _rsv0: 0,
                cap_c2g: cap_c2g as u64,
                cap_g2c: cap_g2c as u64,
                c2g: RingIndices {
                    write_idx: AtomicU64::new(0),
                    read_idx: AtomicU64::new(0),
                    notify_word: AtomicU32::new(0),
                    _rsv: 0,
                },
                g2c: RingIndices {
                    write_idx: AtomicU64::new(0),
                    read_idx: AtomicU64::new(0),
                    notify_word: AtomicU32::new(0),
                    _rsv: 0,
                },
            },
        );
    }

    /// Validate and borrow a control page from a mapping.
    ///
    /// # Safety
    /// `ptr` must point at a mapping of at least `len` readable bytes that
    /// remains valid for `'a`.
    pub unsafe fn attach<'a>(ptr: *const u8, len: usize) -> Result<&'a ShmControl, ShmError> {
        if len < SHM_CONTROL_SIZE {
            return Err(ShmError::TooSmall);
        }
        let ctl = &*(ptr as *const ShmControl);
        if std::ptr::read_volatile(&ctl.magic) != SHM_MAGIC {
            return Err(ShmError::BadMagic);
        }
        if std::ptr::read_volatile(&ctl.version) != SHM_VERSION {
            return Err(ShmError::BadVersion);
        }
        Ok(ctl)
    }
}

/// Producer half of a unidirectional ring.
pub struct RingProducer {
    idx: *const RingIndices,
    data: *mut u8,
    cap: usize,
}

/// Consumer half of a unidirectional ring.
pub struct RingConsumer {
    idx: *const RingIndices,
    data: *const u8,
    cap: usize,
}

// SAFETY: each handle is used by a single thread; cross-thread/process
// synchronisation is provided by the Acquire/Release atomics in `RingIndices`,
// and the SPSC discipline guarantees the producer and consumer never touch the
// same bytes concurrently.
unsafe impl Send for RingProducer {}
// SAFETY: as above — the consumer handle owns only raw pointers into mappings
// shared via the Acquire/Release atomics in `RingIndices`, and the SPSC
// discipline keeps producer and consumer off the same bytes, so moving the
// handle to another thread is sound.
unsafe impl Send for RingConsumer {}

impl RingProducer {
    /// Build a producer over an index block and a writable data region.
    ///
    /// # Safety
    /// `idx` must point into a valid control mapping and `data` at a writable
    /// mapping of at least `cap` bytes, both outliving this handle. The caller
    /// must guarantee single-producer use.
    pub unsafe fn new(idx: *const RingIndices, data: *mut u8, cap: usize) -> RingProducer {
        RingProducer { idx, data, cap }
    }

    #[inline]
    fn indices(&self) -> &RingIndices {
        // SAFETY: validated, non-null index block living as long as `self`.
        unsafe { &*self.idx }
    }

    /// Futex word the consumer waits on; bump + wake after a push.
    pub fn notify_word(&self) -> &AtomicU32 {
        &self.indices().notify_word
    }

    /// Try to enqueue one frame. Returns `Ok(false)` if the ring is full, and
    /// `Err(FrameTooLarge)` if the frame can never fit.
    pub fn try_push(&self, traffic_id: u32, data: &[u8]) -> Result<bool, ShmError> {
        let total = FRAME_HEADER_LEN + data.len();
        if total > self.cap {
            return Err(ShmError::FrameTooLarge);
        }
        let ix = self.indices();
        let write = ix.write_idx.load(Ordering::Relaxed);
        // `read_idx` is written by the (possibly hostile) consumer on the shared
        // control page. A legal `used` is in `[0, cap]`; anything larger means the
        // peer moved `read_idx` outside its window, which would otherwise underflow
        // `cap - used` (silent wrap) or wedge the producer on a perpetual Full.
        // Report it so the endpoint tears down instead of stalling (DP-11).
        let read = ix.read_idx.load(Ordering::Acquire);
        let used = write.wrapping_sub(read) as usize;
        if used > self.cap {
            return Err(ShmError::RingCorrupt);
        }
        if self.cap - used < total {
            return Ok(false);
        }

        let header = encode_header(data.len() as u32, traffic_id);
        let mut off = (write % self.cap as u64) as usize;
        off = self.write_wrapping(off, &header);
        self.write_wrapping(off, data);
        ix.write_idx
            .store(write.wrapping_add(total as u64), Ordering::Release);
        Ok(true)
    }

    fn write_wrapping(&self, off: usize, src: &[u8]) -> usize {
        let n = src.len();
        if n == 0 {
            return off;
        }
        let first = std::cmp::min(n, self.cap - off);
        // SAFETY: `off < self.cap` and `first = min(n, cap - off)`, so the first
        // copy writes `first` bytes within `[off, cap)` of the `cap`-byte writable
        // `self.data` mapping; the second copy writes the remaining `n - first`
        // bytes from the start of `self.data`, and the caller guarantees `total`
        // (header + payload) <= `cap`, so neither copy exceeds the mapping. The
        // source slice `src` is `n` bytes and the two regions are disjoint.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), self.data.add(off), first);
            if n > first {
                std::ptr::copy_nonoverlapping(src.as_ptr().add(first), self.data, n - first);
            }
        }
        (off + n) % self.cap
    }
}

impl RingConsumer {
    /// Build a consumer over an index block and a readable data region.
    ///
    /// # Safety
    /// `idx` must point into a valid control mapping and `data` at a readable
    /// mapping of at least `cap` bytes, both outliving this handle. The caller
    /// must guarantee single-consumer use.
    pub unsafe fn new(idx: *const RingIndices, data: *const u8, cap: usize) -> RingConsumer {
        RingConsumer { idx, data, cap }
    }

    #[inline]
    fn indices(&self) -> &RingIndices {
        // SAFETY: validated, non-null index block living as long as `self`.
        unsafe { &*self.idx }
    }

    /// Futex word to wait on for a notification from the producer.
    pub fn notify_word(&self) -> &AtomicU32 {
        &self.indices().notify_word
    }

    /// Whether the ring currently appears empty.
    pub fn is_empty(&self) -> bool {
        let ix = self.indices();
        let write = ix.write_idx.load(Ordering::Acquire);
        let read = ix.read_idx.load(Ordering::Relaxed);
        write.wrapping_sub(read) < FRAME_HEADER_LEN as u64
    }

    /// Try to dequeue one frame, returning `(traffic_id, payload)`.
    ///
    /// The producer's `write_idx` is treated as untrusted: the available byte
    /// count is clamped to the ring capacity and the frame length is bounded so
    /// a hostile producer can never make the consumer read out of bounds.
    pub fn try_pop(&self) -> Option<(u32, Vec<u8>)> {
        let mut buf = Vec::new();
        let tid = self.try_pop_into(&mut buf)?;
        Some((tid, buf))
    }

    /// Locate and validate the next complete frame without consuming it.
    ///
    /// Shared prologue of [`try_pop_into`](Self::try_pop_into) and
    /// [`try_pop_into_slice`](Self::try_pop_into_slice), so the
    /// untrusted-producer clamps (available bytes bounded by capacity, frame
    /// length bounded by ring size and published bytes) exist exactly once.
    /// Returns `(read_idx, payload_offset, payload_len, traffic_id)`.
    #[inline]
    fn next_frame(&self) -> Option<(u64, usize, usize, u32)> {
        let ix = self.indices();
        let read = ix.read_idx.load(Ordering::Relaxed);
        let write = ix.write_idx.load(Ordering::Acquire);
        let avail_raw = write.wrapping_sub(read);
        // Clamp: a malicious/garbled producer index cannot exceed capacity.
        let avail = std::cmp::min(avail_raw as usize, self.cap);
        if avail < FRAME_HEADER_LEN {
            return None;
        }

        let mut header = [0u8; FRAME_HEADER_LEN];
        let off = (read % self.cap as u64) as usize;
        let next_off = self.read_wrapping(off, &mut header);
        let (len, traffic_id) = decode_header(&header);
        let len = len as usize;
        // The frame must fit in what the producer published and in the ring.
        if len > self.cap - FRAME_HEADER_LEN || avail < FRAME_HEADER_LEN + len {
            // Corrupt/incomplete: do not advance; report empty so the caller
            // can back off rather than spin on bad data.
            return None;
        }
        Some((read, next_off, len, traffic_id))
    }

    /// Consume the frame located by [`next_frame`](Self::next_frame): advance
    /// `read_idx` past its header + payload.
    #[inline]
    fn consume_frame(&self, read: u64, len: usize) {
        self.indices().read_idx.store(
            read.wrapping_add((FRAME_HEADER_LEN + len) as u64),
            Ordering::Release,
        );
    }

    /// Try to dequeue one frame into a caller-owned buffer, returning the
    /// frame's `traffic_id`.
    ///
    /// This is the allocation-free sibling of [`try_pop`](Self::try_pop): the
    /// payload is written into `dst` (which is resized to the frame length)
    /// instead of a freshly allocated `Vec`, so a hot relay loop can reuse one
    /// buffer across frames. The same untrusted-producer bounds checks apply.
    pub fn try_pop_into(&self, dst: &mut Vec<u8>) -> Option<u32> {
        let (read, next_off, len, traffic_id) = self.next_frame()?;

        // Resize without zero-filling the bytes we are about to overwrite.
        dst.clear();
        dst.reserve(len);
        // SAFETY: `dst.reserve(len)` guarantees `dst` has capacity for at least
        // `len` bytes, so `dst.as_mut_ptr()` points to `len` writable bytes as
        // required by `read_wrapping_ptr`; `read_wrapping_ptr` fully initialises
        // those `len` bytes (a frame of `len <= cap - header` was validated by
        // `next_frame`), so the subsequent `set_len(len)` only exposes
        // initialised data.
        unsafe {
            self.read_wrapping_ptr(next_off, dst.as_mut_ptr(), len);
            dst.set_len(len);
        }
        self.consume_frame(read, len);
        Some(traffic_id)
    }

    /// Try to dequeue one frame's payload directly into a caller-owned slice,
    /// returning `(traffic_id, copied_len)`.
    ///
    /// Single-copy, allocation-free sibling of [`try_pop_into`](Self::try_pop_into)
    /// for callers that already own a destination buffer: the payload is copied
    /// straight from the ring into `out` with no intermediate `Vec`. The copy is
    /// clamped to `out.len()` (an over-large frame is truncated to what the
    /// caller can hold) but the whole frame is always consumed from the ring.
    /// The same untrusted-producer bounds checks apply.
    pub fn try_pop_into_slice(&self, out: &mut [u8]) -> Option<(u32, usize)> {
        let (read, next_off, len, traffic_id) = self.next_frame()?;

        let n = len.min(out.len());
        // SAFETY: `n = min(len, out.len())`, so `out.as_mut_ptr()` points to at
        // least `n` writable bytes of the caller's slice, satisfying
        // `read_wrapping_ptr`'s contract; the read is clamped to what `out` can
        // hold while the frame length validated by `next_frame` keeps the
        // source within the ring.
        unsafe {
            self.read_wrapping_ptr(next_off, out.as_mut_ptr(), n);
        }
        self.consume_frame(read, len);
        Some((traffic_id, n))
    }

    fn read_wrapping(&self, off: usize, dst: &mut [u8]) -> usize {
        let n = dst.len();
        if n == 0 {
            return off;
        }
        let first = std::cmp::min(n, self.cap - off);
        // SAFETY: `off < self.cap` and `first = min(n, cap - off)`, so the first
        // copy reads `first` bytes within `[off, cap)` of the `cap`-byte readable
        // `self.data` mapping; the second copy reads the remaining `n - first`
        // bytes from the start of `self.data`. Callers only request `n <= cap`
        // bytes (header is fixed-size, payload bounded above), so neither read
        // exceeds the mapping, and `dst` is an `n`-byte slice disjoint from it.
        unsafe {
            std::ptr::copy_nonoverlapping(self.data.add(off), dst.as_mut_ptr(), first);
            if n > first {
                std::ptr::copy_nonoverlapping(self.data, dst.as_mut_ptr().add(first), n - first);
            }
        }
        (off + n) % self.cap
    }

    /// Raw-pointer variant of [`read_wrapping`](Self::read_wrapping) used by
    /// [`try_pop_into`](Self::try_pop_into) to fill uninitialized capacity.
    ///
    /// # Safety
    /// `dst` must point to at least `n` writable bytes.
    unsafe fn read_wrapping_ptr(&self, off: usize, dst: *mut u8, n: usize) {
        if n == 0 {
            return;
        }
        let first = std::cmp::min(n, self.cap - off);
        std::ptr::copy_nonoverlapping(self.data.add(off), dst, first);
        if n > first {
            std::ptr::copy_nonoverlapping(self.data, dst.add(first), n - first);
        }
    }
}

/// Gateway-side ring pair: consume from the client (`c2g`), produce to the
/// client (`g2c`).
///
/// # Safety
/// All pointers must reference live mappings of at least the stated lengths.
/// `data_c2g` may be a read-only mapping; `data_g2c` must be writable.
pub unsafe fn gateway_rings(
    control: *mut u8,
    control_len: usize,
    data_c2g: *const u8,
    cap_c2g: usize,
    data_g2c: *mut u8,
    cap_g2c: usize,
) -> Result<(RingConsumer, RingProducer), ShmError> {
    let ctl = ShmControl::attach(control as *const u8, control_len)?;
    if (ctl.cap_c2g as usize) > cap_c2g || (ctl.cap_g2c as usize) > cap_g2c {
        return Err(ShmError::BadGeometry);
    }
    let from_client = RingConsumer::new(&ctl.c2g, data_c2g, ctl.cap_c2g as usize);
    let to_client = RingProducer::new(&ctl.g2c, data_g2c, ctl.cap_g2c as usize);
    Ok((from_client, to_client))
}

/// Client-side ring pair: produce to the gateway (`c2g`), consume from the
/// gateway (`g2c`).
///
/// # Safety
/// All pointers must reference live mappings of at least the stated lengths.
/// `data_c2g` must be writable; `data_g2c` may be a read-only mapping.
pub unsafe fn client_rings(
    control: *mut u8,
    control_len: usize,
    data_c2g: *mut u8,
    cap_c2g: usize,
    data_g2c: *const u8,
    cap_g2c: usize,
) -> Result<(RingProducer, RingConsumer), ShmError> {
    let ctl = ShmControl::attach(control as *const u8, control_len)?;
    if (ctl.cap_c2g as usize) > cap_c2g || (ctl.cap_g2c as usize) > cap_g2c {
        return Err(ShmError::BadGeometry);
    }
    let to_gateway = RingProducer::new(&ctl.c2g, data_c2g, ctl.cap_c2g as usize);
    let from_gateway = RingConsumer::new(&ctl.g2c, data_g2c, ctl.cap_g2c as usize);
    Ok((to_gateway, from_gateway))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64-byte-aligned zeroed allocation that stands in for an `mmap` in unit
    /// tests (real mappings are page-aligned; `Box<[u8]>` is not, which would
    /// violate the atomic alignment requirements of [`ShmControl`]).
    struct Aligned {
        ptr: *mut u8,
        layout: std::alloc::Layout,
        len: usize,
    }

    impl Aligned {
        fn new(len: usize) -> Aligned {
            let layout = std::alloc::Layout::from_size_align(len.max(1), 64).unwrap();
            // SAFETY: `layout` has a non-zero size (`len.max(1)`), satisfying the
            // requirement of `alloc_zeroed`; the returned pointer is checked for
            // null below and the matching `layout` is stored for the eventual
            // `dealloc` in `Drop`.
            let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
            assert!(!ptr.is_null());
            Aligned { ptr, layout, len }
        }
        fn as_mut_ptr(&self) -> *mut u8 {
            self.ptr
        }
        fn as_ptr(&self) -> *const u8 {
            self.ptr
        }
        fn len(&self) -> usize {
            self.len
        }
    }

    impl Drop for Aligned {
        fn drop(&mut self) {
            // SAFETY: `self.ptr` was returned by `alloc_zeroed` with exactly
            // `self.layout` in `Aligned::new` and has not been freed before; this
            // `Drop` runs once, so the pointer/layout pair is valid to `dealloc`.
            unsafe { std::alloc::dealloc(self.ptr, self.layout) };
        }
    }

    /// Allocate an aligned buffer that can stand in for an mmap in unit tests.
    fn buf(len: usize) -> Aligned {
        Aligned::new(len)
    }

    /// The control page must be cache-line aligned and at least one line big
    /// (checked at compile time; a runtime assert on a constant is a lint).
    const _: () = assert!(SHM_CONTROL_SIZE >= 64);

    #[test]
    fn control_layout_is_aligned() {
        assert_eq!(std::mem::align_of::<ShmControl>(), 64);
    }

    #[test]
    fn single_ring_spsc_roundtrip() {
        let cap = 256usize;
        let control = buf(SHM_CONTROL_SIZE);
        let data = buf(cap);
        // SAFETY: `control` is a 64-byte-aligned `SHM_CONTROL_SIZE`-byte writable
        // allocation, not yet accessed, satisfying `init`'s contract.
        unsafe {
            ShmControl::init(control.as_mut_ptr(), cap, cap, 0);
        }
        // SAFETY: `control` is a live mapping of `control.len()` readable bytes
        // (>= SHM_CONTROL_SIZE) that outlives `ctl` for the rest of the test.
        let ctl = unsafe { ShmControl::attach(control.as_ptr(), control.len()).unwrap() };
        // SAFETY: `&ctl.c2g` points into the live control mapping and `data` is a
        // writable `cap`-byte allocation; both outlive the handle and this test is
        // the sole producer of the ring.
        let producer = unsafe { RingProducer::new(&ctl.c2g, data.as_mut_ptr(), cap) };
        // SAFETY: `&ctl.c2g` points into the live control mapping and `data` is a
        // readable `cap`-byte allocation; both outlive the handle and this test is
        // the sole consumer of the ring.
        let consumer = unsafe { RingConsumer::new(&ctl.c2g, data.as_ptr(), cap) };

        assert!(consumer.try_pop().is_none());
        assert!(producer.try_push(11, b"abc").unwrap());
        assert!(producer.try_push(22, b"defgh").unwrap());

        let (tid, payload) = consumer.try_pop().unwrap();
        assert_eq!(tid, 11);
        assert_eq!(payload, b"abc");
        let (tid, payload) = consumer.try_pop().unwrap();
        assert_eq!(tid, 22);
        assert_eq!(payload, b"defgh");
        assert!(consumer.try_pop().is_none());
    }

    // DP-11: a hostile consumer that moves `read_idx` outside `[write - cap, write]`
    // must yield RingCorrupt (endpoint teardown) instead of underflowing `cap - used`
    // or wedging the producer on a false Full.
    #[test]
    fn bytestream_bogus_read_idx_is_ring_corrupt() {
        let cap = 256usize;
        let control = buf(SHM_CONTROL_SIZE);
        let data = buf(cap);
        // SAFETY: `control` is a 64-byte-aligned writable `SHM_CONTROL_SIZE` region.
        unsafe { ShmControl::init(control.as_mut_ptr(), cap, cap, 0) };
        // SAFETY: `control` outlives `ctl` and is a live readable mapping.
        let ctl = unsafe { ShmControl::attach(control.as_ptr(), control.len()).unwrap() };
        // SAFETY: `&ctl.c2g` points into the live control mapping; `data` is writable.
        let producer = unsafe { RingProducer::new(&ctl.c2g, data.as_mut_ptr(), cap) };

        // read_idx ahead of write_idx (write == 0) → used wraps huge → corrupt.
        ctl.c2g.read_idx.store(1, Ordering::Release);
        assert_eq!(producer.try_push(1, b"x"), Err(ShmError::RingCorrupt));

        // read_idx more than a lap behind → used > cap → corrupt.
        ctl.c2g
            .read_idx
            .store(0u64.wrapping_sub(cap as u64 + 1), Ordering::Release);
        assert_eq!(producer.try_push(1, b"x"), Err(ShmError::RingCorrupt));

        // A legal read_idx (== write) lets the push proceed again.
        ctl.c2g.read_idx.store(0, Ordering::Release);
        assert!(producer.try_push(1, b"x").unwrap());
    }

    #[test]
    fn wrap_around_preserves_frames() {
        let cap = 64usize;
        let control = buf(SHM_CONTROL_SIZE);
        let data = buf(cap);
        // SAFETY: `control` is a 64-byte-aligned `SHM_CONTROL_SIZE`-byte writable
        // allocation, not yet accessed, satisfying `init`'s contract.
        unsafe { ShmControl::init(control.as_mut_ptr(), cap, cap, 0) };
        // SAFETY: `control` is a live mapping of `control.len()` readable bytes
        // (>= SHM_CONTROL_SIZE) that outlives `ctl` for the rest of the test.
        let ctl = unsafe { ShmControl::attach(control.as_ptr(), control.len()).unwrap() };
        // SAFETY: `&ctl.c2g` points into the live control mapping and `data` is a
        // writable `cap`-byte allocation; both outlive the handle and this test is
        // the sole producer of the ring.
        let producer = unsafe { RingProducer::new(&ctl.c2g, data.as_mut_ptr(), cap) };
        // SAFETY: `&ctl.c2g` points into the live control mapping and `data` is a
        // readable `cap`-byte allocation; both outlive the handle and this test is
        // the sole consumer of the ring.
        let consumer = unsafe { RingConsumer::new(&ctl.c2g, data.as_ptr(), cap) };

        // Push/pop many times so the absolute indices wrap past `cap` repeatedly.
        for i in 0..1000u32 {
            let payload = vec![(i & 0xff) as u8; 20];
            assert!(producer.try_push(i, &payload).unwrap());
            let (tid, got) = consumer.try_pop().unwrap();
            assert_eq!(tid, i);
            assert_eq!(got, payload);
        }
    }

    #[test]
    fn try_pop_into_matches_try_pop() {
        let cap = 64usize;
        let control = buf(SHM_CONTROL_SIZE);
        let data = buf(cap);
        // SAFETY: `control` is a 64-byte-aligned `SHM_CONTROL_SIZE`-byte writable
        // allocation, not yet accessed, satisfying `init`'s contract.
        unsafe { ShmControl::init(control.as_mut_ptr(), cap, cap, 0) };
        // SAFETY: `control` is a live mapping of `control.len()` readable bytes
        // (>= SHM_CONTROL_SIZE) that outlives `ctl` for the rest of the test.
        let ctl = unsafe { ShmControl::attach(control.as_ptr(), control.len()).unwrap() };
        // SAFETY: `&ctl.c2g` points into the live control mapping and `data` is a
        // writable `cap`-byte allocation; both outlive the handle and this test is
        // the sole producer of the ring.
        let producer = unsafe { RingProducer::new(&ctl.c2g, data.as_mut_ptr(), cap) };
        // SAFETY: `&ctl.c2g` points into the live control mapping and `data` is a
        // readable `cap`-byte allocation; both outlive the handle and this test is
        // the sole consumer of the ring.
        let consumer = unsafe { RingConsumer::new(&ctl.c2g, data.as_ptr(), cap) };

        // Empty ring yields None.
        let mut popbuf: Vec<u8> = Vec::new();
        assert!(consumer.try_pop_into(&mut popbuf).is_none());

        // Reuse one buffer across many wrapping frames of varying length.
        for i in 0..1000u32 {
            let len = 1 + (i as usize % 24);
            let payload = vec![(i & 0xff) as u8; len];
            assert!(producer.try_push(i, &payload).unwrap());
            let tid = consumer.try_pop_into(&mut popbuf).unwrap();
            assert_eq!(tid, i);
            assert_eq!(&popbuf[..], &payload[..]);
        }
        assert!(consumer.try_pop_into(&mut popbuf).is_none());
    }

    #[test]
    fn try_pop_into_slice_matches_try_pop() {
        let cap = 64usize;
        let control = buf(SHM_CONTROL_SIZE);
        let data = buf(cap);
        // SAFETY: `control` is a 64-byte-aligned `SHM_CONTROL_SIZE`-byte writable
        // allocation, not yet accessed, satisfying `init`'s contract.
        unsafe { ShmControl::init(control.as_mut_ptr(), cap, cap, 0) };
        // SAFETY: `control` is a live mapping of `control.len()` readable bytes
        // (>= SHM_CONTROL_SIZE) that outlives `ctl` for the rest of the test.
        let ctl = unsafe { ShmControl::attach(control.as_ptr(), control.len()).unwrap() };
        // SAFETY: `&ctl.c2g` points into the live control mapping and `data` is a
        // writable `cap`-byte allocation; both outlive the handle and this test is
        // the sole producer of the ring.
        let producer = unsafe { RingProducer::new(&ctl.c2g, data.as_mut_ptr(), cap) };
        // SAFETY: `&ctl.c2g` points into the live control mapping and `data` is a
        // readable `cap`-byte allocation; both outlive the handle and this test is
        // the sole consumer of the ring.
        let consumer = unsafe { RingConsumer::new(&ctl.c2g, data.as_ptr(), cap) };

        // Empty ring yields None.
        let mut out = [0u8; 64];
        assert!(consumer.try_pop_into_slice(&mut out).is_none());

        // Single-copy pop into a reused slice across many wrapping frames.
        for i in 0..1000u32 {
            let len = 1 + (i as usize % 24);
            let payload = vec![(i & 0xff) as u8; len];
            assert!(producer.try_push(i, &payload).unwrap());
            let (tid, n) = consumer.try_pop_into_slice(&mut out).unwrap();
            assert_eq!(tid, i);
            assert_eq!(n, len);
            assert_eq!(&out[..n], &payload[..]);
        }
        assert!(consumer.try_pop_into_slice(&mut out).is_none());
    }

    #[test]
    fn full_ring_reports_false() {
        let cap = 32usize;
        let control = buf(SHM_CONTROL_SIZE);
        let data = buf(cap);
        // SAFETY: `control` is a 64-byte-aligned `SHM_CONTROL_SIZE`-byte writable
        // allocation, not yet accessed, satisfying `init`'s contract.
        unsafe { ShmControl::init(control.as_mut_ptr(), cap, cap, 0) };
        // SAFETY: `control` is a live mapping of `control.len()` readable bytes
        // (>= SHM_CONTROL_SIZE) that outlives `ctl` for the rest of the test.
        let ctl = unsafe { ShmControl::attach(control.as_ptr(), control.len()).unwrap() };
        // SAFETY: `&ctl.c2g` points into the live control mapping and `data` is a
        // writable `cap`-byte allocation; both outlive the handle and this test is
        // the sole producer of the ring.
        let producer = unsafe { RingProducer::new(&ctl.c2g, data.as_mut_ptr(), cap) };

        // 8-byte header + 16 payload = 24 fits; a second won't.
        assert!(producer.try_push(1, &[0u8; 16]).unwrap());
        assert!(!producer.try_push(2, &[0u8; 16]).unwrap());
    }

    #[test]
    fn oversized_frame_errors() {
        let cap = 32usize;
        let control = buf(SHM_CONTROL_SIZE);
        let data = buf(cap);
        // SAFETY: `control` is a 64-byte-aligned `SHM_CONTROL_SIZE`-byte writable
        // allocation, not yet accessed, satisfying `init`'s contract.
        unsafe { ShmControl::init(control.as_mut_ptr(), cap, cap, 0) };
        // SAFETY: `control` is a live mapping of `control.len()` readable bytes
        // (>= SHM_CONTROL_SIZE) that outlives `ctl` for the rest of the test.
        let ctl = unsafe { ShmControl::attach(control.as_ptr(), control.len()).unwrap() };
        // SAFETY: `&ctl.c2g` points into the live control mapping and `data` is a
        // writable `cap`-byte allocation; both outlive the handle and this test is
        // the sole producer of the ring.
        let producer = unsafe { RingProducer::new(&ctl.c2g, data.as_mut_ptr(), cap) };
        assert_eq!(
            producer.try_push(1, &[0u8; 64]).unwrap_err(),
            ShmError::FrameTooLarge
        );
    }

    #[test]
    fn attach_rejects_bad_magic() {
        let control = buf(SHM_CONTROL_SIZE);
        // Never initialised → magic is zero.
        // SAFETY: `control` is a live mapping of `control.len()` readable bytes
        // (>= SHM_CONTROL_SIZE); `attach` only reads the magic/version words here.
        let err = unsafe { ShmControl::attach(control.as_ptr(), control.len()) }.unwrap_err();
        assert_eq!(err, ShmError::BadMagic);
    }
}
