//! Data-plane handshake.
//!
//! The first message a client sends after connecting to a UDS endpoint (or on
//! the SHM control socket) is a fixed-size HELLO that carries the capability
//! token issued by the management API. The gateway validates the token in
//! constant time, checks it against the endpoint it was issued for, and only
//! then begins relaying framed traffic.
//!
//! Layout (fixed [`HELLO_LEN`] bytes):
//!
//! ```text
//! ┌──────────┬─────────┬───────┬──────────┬──────────────┐
//! │ magic[4] │ ver: u8 │ role  │ rsv: u8  │ token[32]    │
//! └──────────┴─────────┴───────┴──────────┴──────────────┘
//! ```

use crate::token::{CapabilityToken, TOKEN_LEN};

/// HELLO magic: ASCII "SCGH" (SCG Hello).
pub const HELLO_MAGIC: [u8; 4] = *b"SCGH";

/// Current handshake protocol version.
pub const HELLO_VERSION: u8 = 1;

/// Total size of the HELLO message.
pub const HELLO_LEN: usize = 4 + 1 + 1 + 1 + 1 + TOKEN_LEN; // = 40

/// The role a client takes on an endpoint, i.e. which direction of traffic it
/// drives. Matches the gateway rule `Direction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// Client sends plaintext to be encrypted and forwarded upstream.
    Producer = 1,
    /// Client receives decrypted plaintext delivered by the gateway.
    Consumer = 2,
}

impl Role {
    fn from_u8(v: u8) -> Option<Role> {
        match v {
            1 => Some(Role::Producer),
            2 => Some(Role::Consumer),
            _ => None,
        }
    }
}

/// A decoded HELLO message.
#[derive(Debug, Clone)]
pub struct Hello {
    /// Handshake protocol version advertised by the client.
    pub version: u8,
    /// Direction/role the client is taking on the endpoint.
    pub role: Role,
    /// Capability token presented by the client.
    pub token: CapabilityToken,
}

impl Hello {
    /// Build a HELLO for the given role and token.
    pub fn new(role: Role, token: CapabilityToken) -> Self {
        Hello {
            version: HELLO_VERSION,
            role,
            token,
        }
    }

    /// Serialize to the fixed-size wire form.
    pub fn encode(&self) -> [u8; HELLO_LEN] {
        let mut buf = [0u8; HELLO_LEN];
        buf[0..4].copy_from_slice(&HELLO_MAGIC);
        buf[4] = self.version;
        buf[5] = self.role as u8;
        buf[6] = 0; // reserved
        buf[7] = 0; // reserved (keeps the token 8-byte aligned)
        buf[8..8 + TOKEN_LEN].copy_from_slice(self.token.as_bytes());
        buf
    }

    /// Parse a HELLO from its fixed-size wire form, validating magic, version
    /// and role.
    pub fn decode(buf: &[u8; HELLO_LEN]) -> Result<Hello, HelloError> {
        if buf[0..4] != HELLO_MAGIC {
            return Err(HelloError::BadMagic);
        }
        let version = buf[4];
        if version != HELLO_VERSION {
            return Err(HelloError::UnsupportedVersion(version));
        }
        let role = Role::from_u8(buf[5]).ok_or(HelloError::BadRole(buf[5]))?;
        let mut token = [0u8; TOKEN_LEN];
        token.copy_from_slice(&buf[8..8 + TOKEN_LEN]);
        Ok(Hello {
            version,
            role,
            token: CapabilityToken::from_bytes(token),
        })
    }
}

/// Errors produced while decoding a HELLO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloError {
    /// The leading magic bytes did not match [`HELLO_MAGIC`].
    BadMagic,
    /// The advertised version is not supported.
    UnsupportedVersion(u8),
    /// The role byte did not map to a known [`Role`].
    BadRole(u8),
}

impl std::fmt::Display for HelloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelloError::BadMagic => write!(f, "bad HELLO magic"),
            HelloError::UnsupportedVersion(v) => write!(f, "unsupported HELLO version {v}"),
            HelloError::BadRole(r) => write!(f, "invalid HELLO role byte {r}"),
        }
    }
}

impl std::error::Error for HelloError {}

/// Offer magic: ASCII "SCGO" (SCG Offer).
pub const SHM_OFFER_MAGIC: [u8; 4] = *b"SCGO";

/// Size of the SHM offer payload sent alongside the descriptors.
pub const SHM_OFFER_LEN: usize = 4 + 1 + 1 + 1 + 1 + 8 + 8 + 4 + 4; // = 32

/// Notify byte: pollable `eventfd` pair (mirrors proto `NOTIFY_EVENTFD`).
pub const SHM_NOTIFY_EVENTFD: u8 = 0;
/// Notify byte: futex on the control-page notify word (proto `NOTIFY_FUTEX`).
pub const SHM_NOTIFY_FUTEX: u8 = 1;

/// Ring kind byte: variable-length byte-stream ring ([`crate::shm`]).
pub const SHM_RING_BYTESTREAM: u8 = 0;
/// Ring kind byte: fixed-slot Vyukov ring ([`crate::shm_slot`]).
pub const SHM_RING_SLOT: u8 = 1;

/// Index of the control-page memfd in the `SCM_RIGHTS` descriptor array.
pub const SHM_FD_CONTROL: usize = 0;
/// Index of the client→gateway data memfd.
pub const SHM_FD_DATA_C2G: usize = 1;
/// Index of the gateway→client data memfd.
pub const SHM_FD_DATA_G2C: usize = 2;
/// Index of the client→gateway eventfd (only when `notify == eventfd`).
pub const SHM_FD_EVT_C2G: usize = 3;
/// Index of the gateway→client eventfd (only when `notify == eventfd`).
pub const SHM_FD_EVT_G2C: usize = 4;

/// Descriptor-passing offer the gateway sends on the SHM control socket after a
/// valid HELLO.
///
/// The payload travels in the `sendmsg` data buffer; the memfd (and, for the
/// eventfd mechanism, eventfd) descriptors travel in the accompanying
/// `SCM_RIGHTS` control message in the order given by the `SHM_FD_*` indices.
///
/// Layout (fixed [`SHM_OFFER_LEN`] bytes):
///
/// ```text
/// ┌──────────┬─────────┬─────────┬─────────┬───────────┬───────────┬───────────┬───────────┬──────────────┐
/// │ magic[4] │ ver: u8 │ notify  │ n_fds   │ ring_kind │ cap_c2g:8 │ cap_g2c:8 │ capacity:4│ segment_sz:4 │
/// └──────────┴─────────┴─────────┴─────────┴───────────┴───────────┴───────────┴───────────┴──────────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmOffer {
    /// Handshake protocol version (matches [`HELLO_VERSION`]).
    pub version: u8,
    /// Notify mechanism: [`SHM_NOTIFY_EVENTFD`] or [`SHM_NOTIFY_FUTEX`].
    /// Selects the gateway→client (consumer-side) wakeup; the client→gateway
    /// direction always uses an eventfd so the gateway can multiplex it.
    pub notify: u8,
    /// Number of descriptors passed in the control message (3 or 5).
    pub n_fds: u8,
    /// Ring kind: [`SHM_RING_BYTESTREAM`] or [`SHM_RING_SLOT`].
    pub ring_kind: u8,
    /// Capacity in bytes of the client→gateway data region.
    pub cap_c2g: u64,
    /// Capacity in bytes of the gateway→client data region.
    pub cap_g2c: u64,
    /// Slot ring only: number of segments per ring (power of two). Zero for the
    /// byte-stream ring.
    pub capacity: u32,
    /// Slot ring only: bytes per segment slot (multiple of 64). Zero for the
    /// byte-stream ring.
    pub segment_size: u32,
}

impl ShmOffer {
    /// Serialize to the fixed-size wire form.
    pub fn encode(&self) -> [u8; SHM_OFFER_LEN] {
        let mut buf = [0u8; SHM_OFFER_LEN];
        buf[0..4].copy_from_slice(&SHM_OFFER_MAGIC);
        buf[4] = self.version;
        buf[5] = self.notify;
        buf[6] = self.n_fds;
        buf[7] = self.ring_kind;
        buf[8..16].copy_from_slice(&self.cap_c2g.to_le_bytes());
        buf[16..24].copy_from_slice(&self.cap_g2c.to_le_bytes());
        buf[24..28].copy_from_slice(&self.capacity.to_le_bytes());
        buf[28..32].copy_from_slice(&self.segment_size.to_le_bytes());
        buf
    }

    /// Parse an offer from its fixed-size wire form, validating magic/version.
    pub fn decode(buf: &[u8; SHM_OFFER_LEN]) -> Result<ShmOffer, HelloError> {
        if buf[0..4] != SHM_OFFER_MAGIC {
            return Err(HelloError::BadMagic);
        }
        let version = buf[4];
        if version != HELLO_VERSION {
            return Err(HelloError::UnsupportedVersion(version));
        }
        let cap_c2g = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let cap_g2c = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let capacity = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        let segment_size = u32::from_le_bytes(buf[28..32].try_into().unwrap());
        Ok(ShmOffer {
            version,
            notify: buf[5],
            n_fds: buf[6],
            ring_kind: buf[7],
            cap_c2g,
            cap_g2c,
            capacity,
            segment_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip() {
        let token = CapabilityToken::from_bytes([0x5Au8; TOKEN_LEN]);
        let hello = Hello::new(Role::Producer, token);
        let wire = hello.encode();
        assert_eq!(wire.len(), HELLO_LEN);

        let decoded = Hello::decode(&wire).unwrap();
        assert_eq!(decoded.version, HELLO_VERSION);
        assert_eq!(decoded.role, Role::Producer);
        assert!(decoded.token.ct_eq(&[0x5Au8; TOKEN_LEN]));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut wire =
            Hello::new(Role::Consumer, CapabilityToken::from_bytes([0; TOKEN_LEN])).encode();
        wire[0] = b'X';
        assert!(matches!(Hello::decode(&wire), Err(HelloError::BadMagic)));
    }

    #[test]
    fn rejects_bad_role() {
        let mut wire =
            Hello::new(Role::Consumer, CapabilityToken::from_bytes([0; TOKEN_LEN])).encode();
        wire[5] = 99;
        assert!(matches!(Hello::decode(&wire), Err(HelloError::BadRole(99))));
    }

    #[test]
    fn shm_offer_roundtrip() {
        let offer = ShmOffer {
            version: HELLO_VERSION,
            notify: SHM_NOTIFY_EVENTFD,
            n_fds: 5,
            ring_kind: SHM_RING_BYTESTREAM,
            cap_c2g: 0x0011_2233_4455_6677,
            cap_g2c: 0x8899_aabb_ccdd_eeff,
            capacity: 0,
            segment_size: 0,
        };
        let wire = offer.encode();
        assert_eq!(wire.len(), SHM_OFFER_LEN);
        assert_eq!(ShmOffer::decode(&wire).unwrap(), offer);
    }

    #[test]
    fn shm_offer_slot_roundtrip() {
        let offer = ShmOffer {
            version: HELLO_VERSION,
            notify: SHM_NOTIFY_FUTEX,
            n_fds: 5,
            ring_kind: SHM_RING_SLOT,
            cap_c2g: 256 * 1024,
            cap_g2c: 256 * 1024,
            capacity: 256,
            segment_size: 1024,
        };
        let wire = offer.encode();
        assert_eq!(ShmOffer::decode(&wire).unwrap(), offer);
    }

    #[test]
    fn shm_offer_rejects_bad_magic() {
        let mut wire = ShmOffer {
            version: HELLO_VERSION,
            notify: SHM_NOTIFY_FUTEX,
            n_fds: 3,
            ring_kind: SHM_RING_BYTESTREAM,
            cap_c2g: 4096,
            cap_g2c: 4096,
            capacity: 0,
            segment_size: 0,
        }
        .encode();
        wire[0] = b'X';
        assert!(matches!(ShmOffer::decode(&wire), Err(HelloError::BadMagic)));
    }
}
