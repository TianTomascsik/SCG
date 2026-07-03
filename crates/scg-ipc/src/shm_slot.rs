//! Bounded fixed-slot shared-memory ring (Vyukov-style).
//!
//! This is an **additive** alternative to the variable-length byte-stream ring
//! in [`crate::shm`]. It trades the byte-stream's tight packing for fixed-size
//! slots and a per-slot sequence number, which buys three things the WP0
//! benchmark cares about:
//!
//! * **Cache-line separation.** The producer's `write_pos` and the consumer's
//!   `read_pos` live on *separate* 64-byte cache lines (the byte-stream ring
//!   keeps `write_idx`/`read_idx` 8 bytes apart, so they false-share). The
//!   immutable geometry sits on its own line too.
//! * **Wake-on-empty.** A push reports whether the ring *was empty*, so the
//!   integration only issues a futex/eventfd wakeup when a consumer might
//!   actually be blocked, instead of once per frame.
//! * **Spin-then-block.** The per-slot `seq` lets a consumer cheaply spin on a
//!   single word for a few microseconds before parking on the futex.
//!
//! # Topology
//!
//! Like [`crate::shm`], an endpoint uses **two unidirectional SPSC rings** —
//! `c2g` (client produces) and `g2c` (gateway produces) — plus a shared control
//! page. The control page holds, per ring, the cache-line-separated positions,
//! the futex word, and the **sequence array**; the data memfd holds the segment
//! array (`capacity` slots of `segment_size` bytes each).
//!
//! # Why the sequence array lives in the control page
//!
//! A classic Vyukov queue stores each cell's `seq` *inline* with the cell's
//! payload. That cannot work with this crate's sealing model: the `g2c` payload
//! region is sealed read-only for the client so a malicious client cannot
//! corrupt the gateway's in-flight writes — but the consumer must *write* `seq`
//! to release a slot. We therefore keep the `seq` array in the **control page**
//! (mapped read/write by both sides) and keep only `[len][traffic_id][payload]`
//! in the sealable data segment. The consumer thus writes nothing into the
//! producer's payload region. Because the peer owns `seq`, the producer validates
//! it against its valid window on every push (free or one-lap-back full) and
//! returns [`ShmError::RingCorrupt`] otherwise, rather than trusting a hostile
//! value that would wedge it on a false Full (DP-11).
//!
//! The structure is single-producer / single-consumer today; the `seq`
//! protocol is the standard MPMC one, so it can be relaxed to MPSC later
//! without a layout change.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::frame::{decode_header, encode_header, FRAME_HEADER_LEN};
use crate::shm::ShmError;

/// Control-page magic for the slot ring: ASCII "SCG2".
pub const SLOT_MAGIC: u32 = 0x5343_4732;
/// Slot-ring control format version.
pub const SLOT_VERSION: u32 = 1;

/// Cache line size assumed for false-sharing avoidance.
pub const CACHE_LINE: usize = 64;

/// Per-ring control header. Each hot field sits on its own cache line so the
/// producer and consumer never write the same line.
///
/// Layout (4 cache lines = 256 bytes):
///
/// ```text
/// line 0: magic, version, flags, capacity, segment_size, header_size (immutable)
/// line 1: write_pos        (producer-owned)
/// line 2: read_pos         (consumer-owned)
/// line 3: futex_word       (producer bumps, consumer waits)
/// ```
#[repr(C, align(64))]
#[derive(Debug)]
pub struct SlotRingHeader {
    // ── cache line 0: immutable geometry ──
    /// Must equal [`SLOT_MAGIC`].
    pub magic: u32,
    /// Must equal [`SLOT_VERSION`].
    pub version: u32,
    /// Reserved bitflags.
    pub flags: u32,
    /// Number of segments. Always a power of two.
    pub capacity: u32,
    /// Bytes per segment slot (includes the 8-byte frame header). Multiple of
    /// [`CACHE_LINE`].
    pub segment_size: u32,
    /// Size in bytes of this header (so the seq array offset is discoverable).
    pub header_size: u32,
    _rsv_cfg: [u32; 10],

    // ── cache line 1: producer position ──
    /// Absolute count of frames published by the producer (monotonic).
    pub write_pos: AtomicU64,
    _pad1: [u64; 7],

    // ── cache line 2: consumer position ──
    /// Absolute count of frames consumed by the consumer.
    pub read_pos: AtomicU64,
    _pad2: [u64; 7],

    // ── cache line 3: futex word ──
    /// Bumped by the producer on a wake-on-empty transition; the consumer
    /// parks on it after spinning.
    pub futex_word: AtomicU32,
    _pad3: [u32; 15],
}

const _: () = assert!(std::mem::size_of::<SlotRingHeader>() == 4 * CACHE_LINE);
const _: () = assert!(std::mem::align_of::<SlotRingHeader>() == CACHE_LINE);

/// Size of one ring's header in bytes.
pub const SLOT_HEADER_SIZE: usize = std::mem::size_of::<SlotRingHeader>();

/// Round `v` up to the next multiple of `align` (a power of two).
#[inline]
const fn round_up(v: usize, align: usize) -> usize {
    (v + align - 1) & !(align - 1)
}

/// Bytes of control region used by one ring (header + cache-aligned seq array).
#[inline]
pub const fn ring_control_bytes(capacity: usize) -> usize {
    SLOT_HEADER_SIZE + round_up(capacity * std::mem::size_of::<u64>(), CACHE_LINE)
}

/// Total control-page size for an endpoint (two rings: `c2g` then `g2c`).
#[inline]
pub const fn slot_control_size(capacity: usize) -> usize {
    2 * ring_control_bytes(capacity)
}

/// Bytes of data region used by one ring's segment array.
#[inline]
pub const fn ring_data_bytes(capacity: usize, segment_size: usize) -> usize {
    capacity * segment_size
}

/// Choose a valid `segment_size` for a maximum payload: header + payload rounded
/// up to a cache line, with a one-line floor.
#[inline]
pub const fn segment_size_for(max_payload: usize) -> usize {
    let raw = FRAME_HEADER_LEN + max_payload;
    let r = round_up(raw, CACHE_LINE);
    if r < CACHE_LINE {
        CACHE_LINE
    } else {
        r
    }
}

/// Outcome of a [`SlotProducer::try_push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The ring was full; nothing was enqueued.
    Full,
    /// One frame was enqueued. `was_empty` is true if the ring had been empty
    /// just before this push, i.e. a blocked consumer should be woken.
    Pushed {
        /// Whether the ring transitioned from empty to non-empty.
        was_empty: bool,
    },
}

/// Producer half of a fixed-slot ring.
pub struct SlotProducer {
    hdr: *const SlotRingHeader,
    seq: *const AtomicU64,
    data: *mut u8,
    capacity: u64,
    mask: u64,
    segment_size: usize,
}

/// Consumer half of a fixed-slot ring.
pub struct SlotConsumer {
    hdr: *const SlotRingHeader,
    seq: *const AtomicU64,
    data: *const u8,
    capacity: usize,
    mask: u64,
    segment_size: usize,
}

// SAFETY: each handle is owned by a single thread; cross-thread/process
// ordering comes from the Acquire/Release atomics on `seq`/positions, and the
// SPSC discipline keeps producer and consumer off the same slot concurrently.
unsafe impl Send for SlotProducer {}
unsafe impl Send for SlotConsumer {}

#[inline]
fn validate_geometry(capacity: usize, segment_size: usize) -> Result<(), ShmError> {
    if capacity < 2 || !capacity.is_power_of_two() {
        return Err(ShmError::BadGeometry);
    }
    if segment_size < CACHE_LINE
        || !segment_size.is_multiple_of(CACHE_LINE)
        || segment_size <= FRAME_HEADER_LEN
    {
        return Err(ShmError::BadGeometry);
    }
    Ok(())
}

impl SlotProducer {
    /// Build a producer over a ring's header, seq array and writable data.
    ///
    /// # Safety
    /// `hdr`/`seq` must point into a valid control mapping and `data` at a
    /// writable mapping of at least `capacity * segment_size` bytes, all
    /// outliving this handle. The caller must guarantee single-producer use.
    pub unsafe fn new(
        hdr: *const SlotRingHeader,
        seq: *const AtomicU64,
        data: *mut u8,
        capacity: usize,
        segment_size: usize,
    ) -> SlotProducer {
        SlotProducer {
            hdr,
            seq,
            data,
            capacity: capacity as u64,
            mask: (capacity - 1) as u64,
            segment_size,
        }
    }

    #[inline]
    fn header(&self) -> &SlotRingHeader {
        // SAFETY: validated, non-null header living as long as `self`.
        unsafe { &*self.hdr }
    }

    #[inline]
    fn seq_at(&self, idx: usize) -> &AtomicU64 {
        // SAFETY: `idx < capacity`; the seq array has `capacity` entries.
        unsafe { &*self.seq.add(idx) }
    }

    /// Futex word the consumer waits on; bump + wake after a wake-on-empty push.
    pub fn notify_word(&self) -> &AtomicU32 {
        &self.header().futex_word
    }

    /// Maximum payload a single slot can carry.
    #[inline]
    pub fn max_payload(&self) -> usize {
        self.segment_size - FRAME_HEADER_LEN
    }

    /// Try to enqueue one frame.
    ///
    /// Returns [`PushOutcome::Full`] if the slot is not yet free, or
    /// `Err(FrameTooLarge)` if the payload cannot fit a slot.
    pub fn try_push(&self, traffic_id: u32, data: &[u8]) -> Result<PushOutcome, ShmError> {
        if data.len() > self.max_payload() {
            return Err(ShmError::FrameTooLarge);
        }
        let hdr = self.header();
        let pos = hdr.write_pos.load(Ordering::Relaxed);
        let idx = (pos & self.mask) as usize;
        let seq = self.seq_at(idx).load(Ordering::Acquire);
        // The consumer (a possibly-hostile peer) owns `seq` on the shared control
        // page, so validate it against the only two states legal at this producer
        // position (DP-11): `seq == pos` (slot free) or `seq == pos + 1 - capacity`
        // (occupied one lap back → genuinely full). Any other value means the peer
        // corrupted the ring; report it so the endpoint tears down instead of
        // spinning on a perpetual (false) Full.
        let diff = seq.wrapping_sub(pos) as i64;
        match diff {
            0 => {} // slot free — proceed
            d if d == 1 - self.capacity as i64 => return Ok(PushOutcome::Full),
            _ => return Err(ShmError::RingCorrupt),
        }

        // Was the ring empty before this push? (consumer has caught up)
        let was_empty = hdr.read_pos.load(Ordering::Acquire) == pos;

        // Write [len][traffic_id][payload] into the slot's data segment.
        // SAFETY: `idx < capacity` (masked) and `data` maps `capacity * segment_size`
        // writable bytes, so this offset stays within the segment array.
        let seg = unsafe { self.data.add(idx * self.segment_size) };
        let header = encode_header(data.len() as u32, traffic_id);
        // SAFETY: `seg` starts a `segment_size`-byte slot owned by this producer
        // (slot is free: `diff == 0`); `FRAME_HEADER_LEN + data.len() <= segment_size`
        // because `data.len() <= max_payload()`, so both copies stay in-slot, and the
        // source/destination regions do not overlap (distinct mapping vs. local/arg).
        unsafe {
            std::ptr::copy_nonoverlapping(header.as_ptr(), seg, FRAME_HEADER_LEN);
            std::ptr::copy_nonoverlapping(data.as_ptr(), seg.add(FRAME_HEADER_LEN), data.len());
        }

        // Publish: mark the slot READY, then advance our own position.
        self.seq_at(idx)
            .store(pos.wrapping_add(1), Ordering::Release);
        hdr.write_pos.store(pos.wrapping_add(1), Ordering::Relaxed);
        Ok(PushOutcome::Pushed { was_empty })
    }

    /// Reserve the next free slot for **in-place** production: returns a
    /// [`ReservedSlot`] whose [`payload_mut`](ReservedSlot::payload_mut) is a
    /// writable view straight into this producer's ring segment, so the caller
    /// can build or decrypt a payload directly into shared memory with no
    /// staging copy (the zero-copy sibling of [`try_push`](Self::try_push)).
    /// Publish it with [`commit`](ReservedSlot::commit); dropping a
    /// `ReservedSlot` without committing abandons it (the slot stays free and
    /// the next `reserve`/`try_push` reuses it, since `write_pos` never moved).
    ///
    /// Returns `Ok(None)` when the ring is full and `Err(ShmError::RingCorrupt)`
    /// if the (peer-owned) `seq` word is outside its two legal states — the same
    /// DP-11 hostile-`seq` guard as [`try_push`](Self::try_push).
    ///
    /// # Single-producer contract
    /// At most one `ReservedSlot` may be live at a time: `reserve` does not
    /// advance `write_pos`, so a second `reserve` before `commit` would hand out
    /// the *same* slot and two `&mut` views would alias. The crate's
    /// single-producer discipline (see [`SlotProducer::new`]'s safety contract)
    /// already guarantees a strict reserve → fill → commit sequence, exactly as
    /// [`peek_frame`](SlotConsumer::peek_frame)/[`advance`](SlotConsumer::advance)
    /// require one consumer.
    ///
    /// # `&mut` soundness
    /// A producer is the *only* writer of its ring's data region — the consumer
    /// maps it read-only (`g2c` is sealed `F_SEAL_FUTURE_WRITE`; `c2g` is written
    /// solely by the client) — so a reserved, unpublished slot is exclusively
    /// owned by this producer until `commit`. Only the shared control page
    /// (`seq`/positions) is peer-writable, and it is validated here (DP-11),
    /// never dereferenced as payload (contrast TRA #71 on the read side).
    pub fn reserve(&self) -> Result<Option<ReservedSlot<'_>>, ShmError> {
        let hdr = self.header();
        let pos = hdr.write_pos.load(Ordering::Relaxed);
        let idx = (pos & self.mask) as usize;
        let seq = self.seq_at(idx).load(Ordering::Acquire);
        // DP-11: identical hostile-`seq` validation to `try_push` — the only
        // states legal at this producer position are `seq == pos` (free) or
        // `seq == pos + 1 - capacity` (occupied one lap back → genuinely full).
        let diff = seq.wrapping_sub(pos) as i64;
        match diff {
            0 => {}                                                // slot free — reserve it
            d if d == 1 - self.capacity as i64 => return Ok(None), // full
            _ => return Err(ShmError::RingCorrupt),
        }
        // SAFETY: `idx < capacity` (masked) and `data` maps
        // `capacity * segment_size` writable bytes, so this offset starts a whole
        // in-bounds slot owned by this producer (the slot is free: `diff == 0`).
        let seg = unsafe { self.data.add(idx * self.segment_size) };
        Ok(Some(ReservedSlot {
            producer: self,
            idx,
            pos,
            seg,
        }))
    }
}

/// A slot reserved by [`SlotProducer::reserve`] for in-place production: a
/// writable view into the producer's own ring segment, published by
/// [`commit`](Self::commit) or abandoned on drop (no `Drop` work — an
/// uncommitted reserve simply never advanced `write_pos`).
///
/// Borrows the producer, so it cannot outlive the ring; the single-producer
/// discipline keeps at most one `ReservedSlot` live at a time (reserve → fill →
/// commit before the next `reserve`).
pub struct ReservedSlot<'p> {
    producer: &'p SlotProducer,
    idx: usize,
    pos: u64,
    seg: *mut u8,
}

impl ReservedSlot<'_> {
    /// Writable payload region of the reserved slot (`max_payload()` bytes).
    /// Fill it in place (e.g. `SSL_read` decrypts straight into it, or a client
    /// builds a request in it), then [`commit`](Self::commit) the number of
    /// bytes actually written.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        // SAFETY: `seg` starts a `segment_size`-byte slot exclusively owned by
        // this producer while reserved (the slot is free and unpublished, and the
        // consumer maps this ring's data region read-only), so the `max_payload()`
        // bytes after the fixed header are a valid, uniquely-borrowed writable
        // region living as long as the borrowed producer. `FRAME_HEADER_LEN +
        // max_payload() == segment_size`, so the slice stays inside the slot.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.seg.add(FRAME_HEADER_LEN),
                self.producer.max_payload(),
            )
        }
    }

    /// Publish `len` payload bytes (already written via [`payload_mut`]) under
    /// `traffic_id`, marking the slot READY for the consumer. `len` must be
    /// `<= max_payload()`; otherwise `Err(FrameTooLarge)` is returned and
    /// nothing is published. The publish step mirrors
    /// [`SlotProducer::try_push`] exactly (Release on `seq`, then Relaxed on
    /// `write_pos`), so only the header is written here — the payload is already
    /// in place.
    pub fn commit(self, traffic_id: u32, len: usize) -> Result<PushOutcome, ShmError> {
        let p = self.producer;
        if len > p.max_payload() {
            return Err(ShmError::FrameTooLarge);
        }
        // Was the ring empty just before publishing? (consumer had caught up) —
        // computed here, not at `reserve`, so a drain between reserve and commit
        // is reflected, matching `try_push`.
        let was_empty = p.header().read_pos.load(Ordering::Acquire) == self.pos;
        let header = encode_header(len as u32, traffic_id);
        // SAFETY: `self.seg` starts this producer's reserved (free) slot and
        // `FRAME_HEADER_LEN <= segment_size`, so the header write stays in-slot;
        // the source `header` is a distinct local array (no overlap).
        unsafe {
            std::ptr::copy_nonoverlapping(header.as_ptr(), self.seg, FRAME_HEADER_LEN);
        }
        // Publish: mark READY, then advance our own position.
        p.seq_at(self.idx)
            .store(self.pos.wrapping_add(1), Ordering::Release);
        p.header()
            .write_pos
            .store(self.pos.wrapping_add(1), Ordering::Relaxed);
        Ok(PushOutcome::Pushed { was_empty })
    }
}

impl SlotConsumer {
    /// Build a consumer over a ring's header, seq array and readable data.
    ///
    /// # Safety
    /// `hdr`/`seq` must point into a valid control mapping and `data` at a
    /// readable mapping of at least `capacity * segment_size` bytes, all
    /// outliving this handle. The caller must guarantee single-consumer use.
    pub unsafe fn new(
        hdr: *const SlotRingHeader,
        seq: *const AtomicU64,
        data: *const u8,
        capacity: usize,
        segment_size: usize,
    ) -> SlotConsumer {
        SlotConsumer {
            hdr,
            seq,
            data,
            capacity,
            mask: (capacity - 1) as u64,
            segment_size,
        }
    }

    #[inline]
    fn header(&self) -> &SlotRingHeader {
        // SAFETY: validated, non-null header living as long as `self`.
        unsafe { &*self.hdr }
    }

    #[inline]
    fn seq_at(&self, idx: usize) -> &AtomicU64 {
        // SAFETY: `idx < capacity`; the seq array has `capacity` entries.
        unsafe { &*self.seq.add(idx) }
    }

    /// Futex word to wait on for a notification from the producer.
    pub fn notify_word(&self) -> &AtomicU32 {
        &self.header().futex_word
    }

    /// Whether the ring currently appears empty (no READY slot at `read_pos`).
    pub fn is_empty(&self) -> bool {
        let hdr = self.header();
        let pos = hdr.read_pos.load(Ordering::Relaxed);
        let idx = (pos & self.mask) as usize;
        let seq = self.seq_at(idx).load(Ordering::Acquire);
        seq.wrapping_sub(pos.wrapping_add(1)) as i64 != 0
    }

    /// Try to dequeue one frame, returning `(traffic_id, payload)`.
    pub fn try_pop(&self) -> Option<(u32, Vec<u8>)> {
        let mut buf = Vec::new();
        let tid = self.try_pop_into(&mut buf)?;
        Some((tid, buf))
    }

    /// Locate the next READY slot, copy out and decode its frame header, and
    /// clamp the untrusted length — without consuming the slot.
    ///
    /// Shared prologue of [`try_pop_into`](Self::try_pop_into),
    /// [`try_pop_into_slice`](Self::try_pop_into_slice) and
    /// [`peek_frame`](Self::peek_frame), so the READY check, the header decode
    /// and the hostile-producer length clamp exist exactly once. Returns
    /// `(read_pos, slot_idx, slot_ptr, payload_len, traffic_id)`; the slot
    /// stays owned by this consumer until [`release_slot`](Self::release_slot).
    #[inline]
    fn next_ready(&self) -> Option<(u64, usize, *const u8, usize, u32)> {
        let hdr = self.header();
        let pos = hdr.read_pos.load(Ordering::Relaxed);
        let idx = (pos & self.mask) as usize;
        let seq = self.seq_at(idx).load(Ordering::Acquire);
        // diff == 0 → slot READY; diff < 0 → producer hasn't published it.
        if seq.wrapping_sub(pos.wrapping_add(1)) as i64 != 0 {
            return None;
        }

        // SAFETY: `idx < capacity` (masked) and `data` maps `capacity * segment_size`
        // readable bytes, so this offset stays within the segment array.
        let seg = unsafe { self.data.add(idx * self.segment_size) };
        let mut header = [0u8; FRAME_HEADER_LEN];
        // SAFETY (bounds): the slot spans `segment_size >= FRAME_HEADER_LEN` bytes
        // and `header` is a distinct local array of exactly that length, so the
        // copy stays in bounds and the regions cannot overlap. Concurrency: per
        // the seq protocol the READY slot is owned by this consumer, so an
        // *honest* producer does not touch it; the region remains peer-writable,
        // however, so a protocol-violating peer can mutate it concurrently and
        // this read may tear (TRA #71, accepted: the bytes are peer-controlled
        // data, and every bound below derives from this already-copied local
        // header, never re-read from shared memory).
        unsafe {
            std::ptr::copy_nonoverlapping(seg, header.as_mut_ptr(), FRAME_HEADER_LEN);
        }
        let (len, traffic_id) = decode_header(&header);
        // Clamp a hostile/garbled length to the slot's payload capacity.
        let len = (len as usize).min(self.max_payload());
        Some((pos, idx, seg, len, traffic_id))
    }

    /// Release the READY slot located by [`next_ready`](Self::next_ready) for
    /// producer reuse `capacity` laps ahead and advance the read position.
    #[inline]
    fn release_slot(&self, pos: u64, idx: usize) {
        self.seq_at(idx)
            .store(pos.wrapping_add(self.capacity as u64), Ordering::Release);
        self.header()
            .read_pos
            .store(pos.wrapping_add(1), Ordering::Relaxed);
    }

    /// Try to dequeue one frame into a caller-owned buffer, returning the
    /// frame's `traffic_id`. Allocation-free across calls when `dst` is reused.
    ///
    /// The producer-written `len` is treated as untrusted and clamped to the
    /// slot's payload capacity so a hostile producer can never make the
    /// consumer read out of the slot.
    pub fn try_pop_into(&self, dst: &mut Vec<u8>) -> Option<u32> {
        let (pos, idx, seg, len, traffic_id) = self.next_ready()?;

        dst.clear();
        dst.reserve(len);
        // SAFETY: `len <= max_payload()` so `FRAME_HEADER_LEN + len <= segment_size`,
        // keeping the read inside this owned slot; `dst.reserve(len)` guarantees `len`
        // bytes of capacity at `dst.as_mut_ptr()`, and `set_len(len)` only exposes the
        // bytes just written; source and destination buffers are disjoint allocations.
        unsafe {
            std::ptr::copy_nonoverlapping(seg.add(FRAME_HEADER_LEN), dst.as_mut_ptr(), len);
            dst.set_len(len);
        }

        self.release_slot(pos, idx);
        Some(traffic_id)
    }

    /// Try to dequeue one frame's payload directly into a caller-owned slice,
    /// returning `(traffic_id, copied_len)`.
    ///
    /// This is the single-copy, allocation-free sibling of
    /// [`try_pop_into`](Self::try_pop_into) for callers that already own a
    /// destination buffer (e.g. a strided batch buffer): the payload is copied
    /// straight from the slot into `out` with no intermediate `Vec`. The copy
    /// is clamped to `out.len()`, so an over-large frame is truncated to what
    /// the caller can hold; the returned length is the number of bytes actually
    /// written. The same untrusted-producer clamp as `try_pop_into` applies.
    pub fn try_pop_into_slice(&self, out: &mut [u8]) -> Option<(u32, usize)> {
        let (pos, idx, seg, len, traffic_id) = self.next_ready()?;

        // The clamped frame length is further clamped to what the caller's
        // buffer can hold.
        let n = len.min(out.len());
        // SAFETY: `n <= max_payload()` so `FRAME_HEADER_LEN + n <= segment_size`, keeping
        // the read inside this owned slot; `n <= out.len()` so the write stays within the
        // caller's slice; the slice and the shared segment are disjoint regions.
        unsafe {
            std::ptr::copy_nonoverlapping(seg.add(FRAME_HEADER_LEN), out.as_mut_ptr(), n);
        }

        self.release_slot(pos, idx);
        Some((traffic_id, n))
    }

    /// Peek the next READY frame's full on-wire bytes (`[len|traffic_id|payload]`)
    /// without dequeuing, for zero-copy forwarding straight to the upstream.
    ///
    /// Returns `None` when the ring is empty. The returned slice borrows the
    /// shared data segment and is valid until the matching [`advance`](Self::advance)
    /// call (the slot stays owned by this consumer until then, so an *honest*
    /// producer cannot overwrite it — see the residual-risk note below). A
    /// hostile/garbled `len` is clamped to the slot's payload capacity,
    /// mirroring [`try_pop_into`](Self::try_pop_into).
    ///
    /// # Untrusted-peer caveat (TRA #71)
    ///
    /// For a direction whose data region is writable by the peer (the
    /// gateway's c2g side — only g2c is sealed), a protocol-violating peer can
    /// rewrite the slot while the borrow is live, so the bytes may tear. This
    /// is consciously accepted: the contents are peer-controlled data either
    /// way, and every length/bound is derived from a header copied out before
    /// use, never re-read from shared memory. Callers must treat the bytes as
    /// untrusted and must not rely on them being stable across the borrow.
    pub fn peek_frame(&self) -> Option<&[u8]> {
        let (_pos, _idx, seg, len, _traffic_id) = self.next_ready()?;
        let total = FRAME_HEADER_LEN + len;
        // SAFETY (bounds): `len <= max_payload()` so `total <= segment_size`,
        // keeping the slice inside this slot, and the slot outlives `&self`.
        // Concurrency: the seq protocol keeps an honest producer off the slot
        // until `advance()`; a protocol-violating peer with a writable mapping
        // can still mutate the bytes behind this `&[u8]` — an accepted residual
        // documented on the method (TRA #71), safe-Rust-observable only as
        // torn peer-controlled payload bytes because no length or offset is
        // ever derived from the borrowed region itself.
        Some(unsafe { std::slice::from_raw_parts(seg, total) })
    }

    /// Release the slot observed by the most recent
    /// [`peek_frame`](Self::peek_frame) and advance the read position. Call
    /// exactly once per consumed `peek_frame`.
    ///
    /// Calling without a preceding successful `peek_frame` (e.g. on an empty
    /// ring) is a caller bug: it is a `debug_assert!` failure in debug builds
    /// and a no-op in release builds. Silently releasing a non-READY slot
    /// would store a future lap into a seq word the producer still owns,
    /// wedging the ring permanently (`try_push` full forever).
    pub fn advance(&self) {
        let hdr = self.header();
        let pos = hdr.read_pos.load(Ordering::Relaxed);
        let idx = (pos & self.mask) as usize;
        let seq = self.seq_at(idx).load(Ordering::Acquire);
        if seq.wrapping_sub(pos.wrapping_add(1)) as i64 != 0 {
            debug_assert!(
                false,
                "SlotConsumer::advance() without a READY slot (no matching peek_frame)"
            );
            return;
        }
        self.release_slot(pos, idx);
    }

    /// Payload capacity of one slot.
    #[inline]
    pub fn max_payload(&self) -> usize {
        self.segment_size - FRAME_HEADER_LEN
    }
}

/// Initialise one ring's control region in place: header + seq array.
///
/// # Safety
/// `base` must point at a writable control mapping of at least
/// [`ring_control_bytes`] bytes for `capacity`, not concurrently accessed.
unsafe fn init_ring_control(base: *mut u8, capacity: usize, segment_size: usize, flags: u32) {
    let hdr = base as *mut SlotRingHeader;
    std::ptr::write(
        hdr,
        SlotRingHeader {
            magic: SLOT_MAGIC,
            version: SLOT_VERSION,
            flags,
            capacity: capacity as u32,
            segment_size: segment_size as u32,
            header_size: SLOT_HEADER_SIZE as u32,
            _rsv_cfg: [0; 10],
            write_pos: AtomicU64::new(0),
            _pad1: [0; 7],
            read_pos: AtomicU64::new(0),
            _pad2: [0; 7],
            futex_word: AtomicU32::new(0),
            _pad3: [0; 15],
        },
    );
    // seq[i] = i so that slot i is free for the producer at position i.
    let seq = base.add(SLOT_HEADER_SIZE) as *mut AtomicU64;
    for i in 0..capacity {
        std::ptr::write(seq.add(i), AtomicU64::new(i as u64));
    }
}

/// Initialise an endpoint's slot-ring control page (both `c2g` and `g2c`).
///
/// # Safety
/// `ptr` must point at a writable mapping of at least
/// [`slot_control_size`]`(capacity)` bytes that is not concurrently accessed.
pub unsafe fn init_slot_control(
    ptr: *mut u8,
    capacity: usize,
    segment_size: usize,
    flags: u32,
) -> Result<(), ShmError> {
    validate_geometry(capacity, segment_size)?;
    let stride = ring_control_bytes(capacity);
    init_ring_control(ptr, capacity, segment_size, flags); // c2g
    init_ring_control(ptr.add(stride), capacity, segment_size, flags); // g2c
    Ok(())
}

/// Validate and borrow one ring's header from a control mapping.
///
/// # Safety
/// `base` must point at a readable control mapping of at least
/// [`ring_control_bytes`] bytes valid for `'a`.
unsafe fn attach_ring_header<'a>(base: *const u8) -> Result<&'a SlotRingHeader, ShmError> {
    let hdr = &*(base as *const SlotRingHeader);
    if std::ptr::read_volatile(&hdr.magic) != SLOT_MAGIC {
        return Err(ShmError::BadMagic);
    }
    if std::ptr::read_volatile(&hdr.version) != SLOT_VERSION {
        return Err(ShmError::BadVersion);
    }
    Ok(hdr)
}

/// Gateway-side slot rings: consume from the client (`c2g`), produce to the
/// client (`g2c`).
///
/// # Safety
/// All pointers must reference live mappings of at least the stated lengths.
/// `data_c2g` may be read-only; `data_g2c` must be writable.
#[allow(clippy::too_many_arguments)]
pub unsafe fn gateway_slot_rings(
    control: *mut u8,
    control_len: usize,
    capacity: usize,
    segment_size: usize,
    data_c2g: *const u8,
    data_c2g_len: usize,
    data_g2c: *mut u8,
    data_g2c_len: usize,
) -> Result<(SlotConsumer, SlotProducer), ShmError> {
    validate_geometry(capacity, segment_size)?;
    if control_len < slot_control_size(capacity) {
        return Err(ShmError::TooSmall);
    }
    let need = ring_data_bytes(capacity, segment_size);
    if data_c2g_len < need || data_g2c_len < need {
        return Err(ShmError::BadGeometry);
    }
    let stride = ring_control_bytes(capacity);
    let c2g = control as *const u8;
    let g2c = control.add(stride) as *const u8;
    attach_ring_header(c2g)?;
    attach_ring_header(g2c)?;
    let seq_c2g = c2g.add(SLOT_HEADER_SIZE) as *const AtomicU64;
    let seq_g2c = g2c.add(SLOT_HEADER_SIZE) as *const AtomicU64;
    let from_client = SlotConsumer::new(
        c2g as *const SlotRingHeader,
        seq_c2g,
        data_c2g,
        capacity,
        segment_size,
    );
    let to_client = SlotProducer::new(
        g2c as *const SlotRingHeader,
        seq_g2c,
        data_g2c,
        capacity,
        segment_size,
    );
    Ok((from_client, to_client))
}

/// Client-side slot rings: produce to the gateway (`c2g`), consume from the
/// gateway (`g2c`).
///
/// # Safety
/// All pointers must reference live mappings of at least the stated lengths.
/// `data_c2g` must be writable; `data_g2c` may be read-only.
#[allow(clippy::too_many_arguments)]
pub unsafe fn client_slot_rings(
    control: *mut u8,
    control_len: usize,
    capacity: usize,
    segment_size: usize,
    data_c2g: *mut u8,
    data_c2g_len: usize,
    data_g2c: *const u8,
    data_g2c_len: usize,
) -> Result<(SlotProducer, SlotConsumer), ShmError> {
    validate_geometry(capacity, segment_size)?;
    if control_len < slot_control_size(capacity) {
        return Err(ShmError::TooSmall);
    }
    let need = ring_data_bytes(capacity, segment_size);
    if data_c2g_len < need || data_g2c_len < need {
        return Err(ShmError::BadGeometry);
    }
    let stride = ring_control_bytes(capacity);
    let c2g = control as *const u8;
    let g2c = control.add(stride) as *const u8;
    attach_ring_header(c2g)?;
    attach_ring_header(g2c)?;
    let seq_c2g = c2g.add(SLOT_HEADER_SIZE) as *const AtomicU64;
    let seq_g2c = g2c.add(SLOT_HEADER_SIZE) as *const AtomicU64;
    let to_gateway = SlotProducer::new(
        c2g as *const SlotRingHeader,
        seq_c2g,
        data_c2g,
        capacity,
        segment_size,
    );
    let from_gateway = SlotConsumer::new(
        g2c as *const SlotRingHeader,
        seq_g2c,
        data_g2c,
        capacity,
        segment_size,
    );
    Ok((to_gateway, from_gateway))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 64-byte-aligned zeroed allocation standing in for an `mmap` in tests.
    struct Aligned {
        ptr: *mut u8,
        layout: std::alloc::Layout,
        len: usize,
    }
    impl Aligned {
        fn new(len: usize) -> Aligned {
            let layout = std::alloc::Layout::from_size_align(len.max(1), 64).unwrap();
            // SAFETY: `layout` has a non-zero size (`len.max(1)`), satisfying the
            // `alloc_zeroed` contract; the returned pointer is null-checked below.
            let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
            assert!(!ptr.is_null());
            Aligned { ptr, layout, len }
        }
    }
    impl Drop for Aligned {
        fn drop(&mut self) {
            // SAFETY: `self.ptr` was returned by `alloc_zeroed` with `self.layout`
            // in `new` and has not been freed before; this runs once at drop.
            unsafe { std::alloc::dealloc(self.ptr, self.layout) };
        }
    }

    fn make(
        capacity: usize,
        segment_size: usize,
    ) -> (Aligned, Aligned, SlotProducer, SlotConsumer) {
        let control = Aligned::new(slot_control_size(capacity));
        let data = Aligned::new(ring_data_bytes(capacity, segment_size));
        // SAFETY: `control.ptr` is a fresh, exclusively-owned, 64-byte-aligned
        // allocation of `slot_control_size(capacity)` bytes, not yet shared.
        unsafe {
            init_slot_control(control.ptr, capacity, segment_size, 0).unwrap();
        }
        // Use only the c2g ring for single-ring tests.
        let hdr = control.ptr as *const SlotRingHeader;
        // SAFETY: the seq array begins at `SLOT_HEADER_SIZE` within the control
        // allocation, which is large enough to hold the header plus the seq array.
        let seq = unsafe { control.ptr.add(SLOT_HEADER_SIZE) } as *const AtomicU64;
        // SAFETY: `hdr`/`seq` point into the live, initialised control allocation and
        // `data.ptr` maps `capacity * segment_size` writable bytes, all outliving the
        // returned handle; this test is the sole producer.
        let producer = unsafe { SlotProducer::new(hdr, seq, data.ptr, capacity, segment_size) };
        // SAFETY: `hdr`/`seq` point into the live, initialised control allocation and
        // `data.ptr` maps `capacity * segment_size` readable bytes, all outliving the
        // returned handle; this test is the sole consumer.
        let consumer =
            unsafe { SlotConsumer::new(hdr, seq, data.ptr as *const u8, capacity, segment_size) };
        let _ = control.len;
        let _ = data.len;
        (control, data, producer, consumer)
    }

    #[test]
    fn header_is_four_cache_lines() {
        assert_eq!(SLOT_HEADER_SIZE, 256);
        assert_eq!(std::mem::align_of::<SlotRingHeader>(), 64);
    }

    #[test]
    fn write_and_read_positions_on_separate_lines() {
        let off_w = std::mem::offset_of!(SlotRingHeader, write_pos);
        let off_r = std::mem::offset_of!(SlotRingHeader, read_pos);
        let off_f = std::mem::offset_of!(SlotRingHeader, futex_word);
        assert_ne!(off_w / CACHE_LINE, off_r / CACHE_LINE);
        assert_ne!(off_r / CACHE_LINE, off_f / CACHE_LINE);
    }

    #[test]
    fn spsc_roundtrip() {
        let (_c, _d, producer, consumer) = make(8, segment_size_for(64));
        assert!(consumer.try_pop().is_none());
        assert_eq!(
            producer.try_push(11, b"abc").unwrap(),
            PushOutcome::Pushed { was_empty: true }
        );
        // Second push: ring is no longer empty.
        assert_eq!(
            producer.try_push(22, b"defgh").unwrap(),
            PushOutcome::Pushed { was_empty: false }
        );
        assert_eq!(consumer.try_pop().unwrap(), (11, b"abc".to_vec()));
        assert_eq!(consumer.try_pop().unwrap(), (22, b"defgh".to_vec()));
        assert!(consumer.try_pop().is_none());
    }

    #[test]
    fn full_ring_reports_full() {
        let (_c, _d, producer, _consumer) = make(2, segment_size_for(16));
        assert!(matches!(
            producer.try_push(1, &[1u8; 16]).unwrap(),
            PushOutcome::Pushed { .. }
        ));
        assert!(matches!(
            producer.try_push(2, &[2u8; 16]).unwrap(),
            PushOutcome::Pushed { .. }
        ));
        // Both slots occupied.
        assert_eq!(producer.try_push(3, &[3u8; 16]).unwrap(), PushOutcome::Full);
    }

    // DP-11: a hostile consumer that writes a `seq` outside the {free, full}
    // window must yield RingCorrupt (so the endpoint tears down) rather than a
    // false Full (which would wedge the producer forever).
    #[test]
    fn corrupt_seq_yields_ring_corrupt_not_full() {
        let (control, _d, producer, _consumer) = make(8, segment_size_for(64));
        // Next write position is 0 (slot 0). Legal seq at pos 0 is 0 (free) or
        // 1 - capacity (full). Inject a value in neither state.
        let seq0 = unsafe { control.ptr.add(SLOT_HEADER_SIZE) } as *const AtomicU64;
        // SAFETY: `seq0` points at the first seq entry of the live control page.
        unsafe { (*seq0).store(7, Ordering::Release) };
        assert_eq!(producer.try_push(1, b"x"), Err(ShmError::RingCorrupt));

        // A wildly large seq is corrupt too (would otherwise read as diff != 0).
        // SAFETY: same live control-page entry.
        unsafe { (*seq0).store(u64::MAX, Ordering::Release) };
        assert_eq!(producer.try_push(1, b"x"), Err(ShmError::RingCorrupt));

        // Restoring the legal "free" value (== pos) lets the push proceed again.
        // SAFETY: same live control-page entry.
        unsafe { (*seq0).store(0, Ordering::Release) };
        assert!(matches!(
            producer.try_push(1, b"x").unwrap(),
            PushOutcome::Pushed { .. }
        ));
    }

    // --- Zero-copy producer: reserve / commit (in-place production) ---

    #[test]
    fn reserve_commit_roundtrips_like_try_push() {
        let (_c, _d, producer, consumer) = make(4, segment_size_for(64));
        for i in 0..5_000u32 {
            let len = 1 + (i as usize % 50);
            let byte = (i & 0xff) as u8;
            // Reserve, fill the payload straight into the ring, publish.
            let mut slot = producer.reserve().unwrap().expect("slot free");
            slot.payload_mut()[..len].fill(byte);
            assert_eq!(
                slot.commit(i, len).unwrap(),
                PushOutcome::Pushed { was_empty: true }
            );
            // Consumer sees exactly the bytes written in place, same as try_push.
            let (tid, payload) = consumer.try_pop().unwrap();
            assert_eq!(tid, i);
            assert_eq!(payload, vec![byte; len]);
            assert!(consumer.try_pop().is_none());
        }
    }

    #[test]
    fn reserve_without_commit_abandons_slot() {
        let (_c, _d, producer, consumer) = make(4, segment_size_for(64));
        // Reserve then drop without committing: nothing is published and
        // `write_pos` never moved, so the slot is reused untouched.
        {
            let mut slot = producer.reserve().unwrap().expect("slot free");
            slot.payload_mut()[..3].copy_from_slice(b"xyz");
        } // dropped, not committed
        assert!(consumer.try_pop().is_none());
        assert_eq!(
            producer.try_push(9, b"abc").unwrap(),
            PushOutcome::Pushed { was_empty: true }
        );
        assert_eq!(consumer.try_pop().unwrap(), (9, b"abc".to_vec()));
    }

    #[test]
    fn commit_oversized_len_rejected_and_publishes_nothing() {
        let (_c, _d, producer, consumer) = make(4, segment_size_for(16));
        let max = producer.max_payload();
        let slot = producer.reserve().unwrap().expect("slot free");
        assert_eq!(slot.commit(1, max + 1), Err(ShmError::FrameTooLarge));
        assert!(consumer.try_pop().is_none());
    }

    #[test]
    fn reserve_full_ring_returns_none() {
        let (_c, _d, producer, _consumer) = make(2, segment_size_for(16));
        assert!(producer.reserve().unwrap().unwrap().commit(1, 4).is_ok());
        assert!(producer.reserve().unwrap().unwrap().commit(2, 4).is_ok());
        // Both slots occupied → reserve reports full.
        assert!(producer.reserve().unwrap().is_none());
    }

    #[test]
    fn reserve_corrupt_seq_yields_ring_corrupt() {
        let (control, _d, producer, _consumer) = make(8, segment_size_for(64));
        // Inject a `seq` in neither the free (== pos) nor full state at slot 0.
        let seq0 = unsafe { control.ptr.add(SLOT_HEADER_SIZE) } as *const AtomicU64;
        // SAFETY: `seq0` points at the first seq entry of the live control page.
        unsafe { (*seq0).store(7, Ordering::Release) };
        assert_eq!(producer.reserve().err(), Some(ShmError::RingCorrupt));
    }

    #[test]
    fn reserve_commit_was_empty_semantics() {
        let (_c, _d, producer, consumer) = make(8, segment_size_for(32));
        let s1 = producer.reserve().unwrap().unwrap();
        assert_eq!(
            s1.commit(1, 0).unwrap(),
            PushOutcome::Pushed { was_empty: true }
        );
        let s2 = producer.reserve().unwrap().unwrap();
        assert_eq!(
            s2.commit(2, 0).unwrap(),
            PushOutcome::Pushed { was_empty: false }
        );
        consumer.try_pop().unwrap();
        consumer.try_pop().unwrap();
    }

    #[test]
    fn oversized_frame_rejected() {
        let (_c, _d, producer, _consumer) = make(4, segment_size_for(16));
        let max = producer.max_payload();
        assert!(producer.try_push(1, &vec![0u8; max]).is_ok());
        assert_eq!(
            producer.try_push(1, &vec![0u8; max + 1]),
            Err(ShmError::FrameTooLarge)
        );
    }

    #[test]
    fn wrap_around_many_frames() {
        let (_c, _d, producer, consumer) = make(4, segment_size_for(64));
        let mut buf = Vec::new();
        for i in 0..10_000u32 {
            let len = 1 + (i as usize % 50);
            let payload = vec![(i & 0xff) as u8; len];
            assert!(matches!(
                producer.try_push(i, &payload).unwrap(),
                PushOutcome::Pushed { .. }
            ));
            let tid = consumer.try_pop_into(&mut buf).unwrap();
            assert_eq!(tid, i);
            assert_eq!(&buf[..], &payload[..]);
        }
        assert!(consumer.try_pop_into(&mut buf).is_none());
    }

    #[test]
    fn peek_frame_yields_on_wire_bytes_and_advances() {
        let (_c, _d, producer, consumer) = make(4, segment_size_for(64));
        // Empty ring → nothing to peek.
        assert!(consumer.peek_frame().is_none());

        for i in 0..5_000u32 {
            let len = 1 + (i as usize % 50);
            let payload = vec![(i & 0xff) as u8; len];
            assert!(matches!(
                producer.try_push(i, &payload).unwrap(),
                PushOutcome::Pushed { .. }
            ));
            // Peek must return the exact `[len|traffic_id|payload]` on-wire frame.
            let frame = consumer.peek_frame().expect("frame ready");
            let mut expect = encode_header(len as u32, i).to_vec();
            expect.extend_from_slice(&payload);
            assert_eq!(frame, &expect[..]);
            // Peeking again (before advance) returns the same frame.
            assert_eq!(consumer.peek_frame().unwrap(), &expect[..]);
            consumer.advance();
            assert!(consumer.peek_frame().is_none());
        }
    }

    #[test]
    fn advance_without_ready_slot_is_rejected_and_ring_survives() {
        let (_c, _d, producer, consumer) = make(4, segment_size_for(64));
        // Empty ring: advance() must not release anything. Debug builds trip
        // the misuse debug_assert; release builds no-op. Either way the ring
        // must remain functional (a silent release would wedge it: the
        // producer would see Full forever).
        let misuse = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| consumer.advance()));
        if cfg!(debug_assertions) {
            assert!(misuse.is_err(), "debug build must assert on misuse");
        } else {
            assert!(misuse.is_ok(), "release build must no-op on misuse");
        }
        assert_eq!(
            producer.try_push(7, b"abc").unwrap(),
            PushOutcome::Pushed { was_empty: true }
        );
        assert_eq!(consumer.try_pop().unwrap(), (7, b"abc".to_vec()));
        assert!(consumer.try_pop().is_none());
    }

    #[test]
    fn advance_after_peek_consumes_exactly_one() {
        let (_c, _d, producer, consumer) = make(8, segment_size_for(64));
        assert_eq!(
            producer.try_push(1, b"first").unwrap(),
            PushOutcome::Pushed { was_empty: true }
        );
        assert_eq!(
            producer.try_push(2, b"second").unwrap(),
            PushOutcome::Pushed { was_empty: false }
        );
        assert!(consumer.peek_frame().is_some());
        consumer.advance();
        // Exactly one frame consumed: the second is still there.
        assert_eq!(consumer.try_pop().unwrap(), (2, b"second".to_vec()));
        assert!(consumer.try_pop().is_none());
    }

    #[test]
    fn try_pop_into_slice_matches_try_pop() {
        let (_c, _d, producer, consumer) = make(4, segment_size_for(64));
        // Empty ring → None.
        let mut out = [0u8; 64];
        assert!(consumer.try_pop_into_slice(&mut out).is_none());

        for i in 0..5_000u32 {
            let len = 1 + (i as usize % 50);
            let payload = vec![(i & 0xff) as u8; len];
            assert!(matches!(
                producer.try_push(i, &payload).unwrap(),
                PushOutcome::Pushed { .. }
            ));
            let (tid, n) = consumer.try_pop_into_slice(&mut out).expect("frame ready");
            assert_eq!(tid, i);
            assert_eq!(n, len);
            assert_eq!(&out[..n], &payload[..]);
            assert!(consumer.try_pop_into_slice(&mut out).is_none());
        }
    }

    #[test]
    fn was_empty_only_on_empty_to_nonempty() {
        let (_c, _d, producer, consumer) = make(8, segment_size_for(32));
        // First push onto empty ring → was_empty.
        assert_eq!(
            producer.try_push(1, b"x").unwrap(),
            PushOutcome::Pushed { was_empty: true }
        );
        // Backlog grows → not empty.
        assert_eq!(
            producer.try_push(2, b"y").unwrap(),
            PushOutcome::Pushed { was_empty: false }
        );
        // Drain fully.
        consumer.try_pop().unwrap();
        consumer.try_pop().unwrap();
        // Next push onto a drained ring → was_empty again.
        assert_eq!(
            producer.try_push(3, b"z").unwrap(),
            PushOutcome::Pushed { was_empty: true }
        );
    }

    #[test]
    fn two_ring_endpoint_independent() {
        let capacity = 4;
        let segment_size = segment_size_for(32);
        let control = Aligned::new(slot_control_size(capacity));
        let data_c2g = Aligned::new(ring_data_bytes(capacity, segment_size));
        let data_g2c = Aligned::new(ring_data_bytes(capacity, segment_size));
        // SAFETY: `control.ptr` is a fresh, exclusively-owned, 64-byte-aligned
        // allocation of `slot_control_size(capacity)` bytes, not yet shared.
        unsafe {
            init_slot_control(control.ptr, capacity, segment_size, 0).unwrap();
        }
        // SAFETY: `control`, `data_c2g` and `data_g2c` are live allocations of the
        // exact lengths passed (control page and two `capacity * segment_size` data
        // regions) that outlive the returned ring handles.
        let (gw_rx, gw_tx) = unsafe {
            gateway_slot_rings(
                control.ptr,
                slot_control_size(capacity),
                capacity,
                segment_size,
                data_c2g.ptr,
                ring_data_bytes(capacity, segment_size),
                data_g2c.ptr,
                ring_data_bytes(capacity, segment_size),
            )
            .unwrap()
        };
        // SAFETY: `control`, `data_c2g` and `data_g2c` are the same live allocations of
        // the exact lengths passed, shared with the gateway handles above under the
        // SPSC discipline, and outlive the returned ring handles.
        let (cl_tx, cl_rx) = unsafe {
            client_slot_rings(
                control.ptr,
                slot_control_size(capacity),
                capacity,
                segment_size,
                data_c2g.ptr,
                ring_data_bytes(capacity, segment_size),
                data_g2c.ptr,
                ring_data_bytes(capacity, segment_size),
            )
            .unwrap()
        };

        // client → gateway
        cl_tx.try_push(7, b"ping").unwrap();
        assert_eq!(gw_rx.try_pop().unwrap(), (7, b"ping".to_vec()));
        // gateway → client
        gw_tx.try_push(9, b"pong").unwrap();
        assert_eq!(cl_rx.try_pop().unwrap(), (9, b"pong".to_vec()));
    }

    #[test]
    fn rejects_bad_geometry() {
        // Non-power-of-two capacity.
        let control = Aligned::new(4096);
        assert_eq!(
            // SAFETY: `control.ptr` is a fresh 4096-byte exclusively-owned allocation;
            // the call rejects the bad geometry before touching the mapping.
            unsafe { init_slot_control(control.ptr, 3, segment_size_for(16), 0) },
            Err(ShmError::BadGeometry)
        );
        // segment_size not a cache-line multiple.
        assert_eq!(
            // SAFETY: same fresh 4096-byte allocation; the call rejects the bad
            // geometry before touching the mapping.
            unsafe { init_slot_control(control.ptr, 4, 100, 0) },
            Err(ShmError::BadGeometry)
        );
    }
}
