//! `scg-ipc` — shared IPC primitives for the Secure Communication Gateway.
//!
//! This crate is the single source of truth for the on-the-wire and
//! in-shared-memory formats used by the gateway's local interfaces (UDS and
//! shared memory) and by the client libraries. Keeping it transport-agnostic
//! lets the gateway and every client (Rust/C/C++) agree byte-for-byte.
//!
//! Modules:
//! * [`frame`] — the `[len][traffic_id][data]` packet codec.
//! * [`handshake`] — the capability-token HELLO that opens a data-plane link.
//! * [`token`] — single-use 256-bit capability tokens (constant-time compare).
//! * [`shm`] — the sealed two-ring shared-memory channel.
//! * [`notify`] — `eventfd` and futex wakeup primitives.
//! * [`os`] — audited Linux IPC syscall wrappers (memfd, sealing, SCM_RIGHTS,
//!   SO_PEERCRED, …).
//!
//! The crate targets Linux only; it relies on `memfd_create`, file sealing,
//! `eventfd`, futexes and `SCM_RIGHTS` fd passing.

#![cfg(target_os = "linux")]

pub mod frame;
pub mod handshake;
pub mod notify;
pub mod os;
pub mod shm;
pub mod shm_slot;
pub mod token;

pub use frame::{
    decode_header, encode_header, read_frame, write_frame, FrameDecoder, FrameError, FRAME_HEADER_LEN,
};
pub use handshake::{
    Hello, HelloError, Role, ShmOffer, HELLO_LEN, SHM_FD_CONTROL, SHM_FD_DATA_C2G, SHM_FD_DATA_G2C,
    SHM_FD_EVT_C2G, SHM_FD_EVT_G2C, SHM_NOTIFY_EVENTFD, SHM_NOTIFY_FUTEX, SHM_OFFER_LEN,
    SHM_RING_BYTESTREAM, SHM_RING_SLOT,
};
pub use notify::{EventFd, WakeMechanism};
pub use shm::{RingConsumer, RingProducer, ShmControl, ShmError, SHM_CONTROL_SIZE};
pub use shm_slot::{
    client_slot_rings, gateway_slot_rings, init_slot_control, ring_control_bytes, ring_data_bytes,
    segment_size_for, slot_control_size, PushOutcome, SlotConsumer, SlotProducer, SlotRingHeader,
    SLOT_HEADER_SIZE, SLOT_MAGIC, SLOT_VERSION,
};
pub use token::{CapabilityToken, TOKEN_LEN};
