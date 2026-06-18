//! Single-use capability tokens that bind a data-plane connection to a
//! gRPC-authenticated request.
//!
//! When a client asks the management API to create a UDS/SHM endpoint, the
//! gateway issues a fresh 256-bit token and returns it over the (already
//! peer-authenticated) gRPC channel. The client must present that exact token
//! as the first bytes it sends on the data plane. The gateway validates it in
//! constant time and immediately consumes it, so a token is worthless to any
//! process that races onto the socket later.

use crate::os;
use std::io;

/// Length of a capability token in bytes (256 bits).
pub const TOKEN_LEN: usize = 32;

/// A 256-bit capability token.
#[derive(Clone)]
pub struct CapabilityToken([u8; TOKEN_LEN]);

impl CapabilityToken {
    /// Generate a fresh random token from the system CSPRNG.
    pub fn random() -> io::Result<Self> {
        let mut bytes = [0u8; TOKEN_LEN];
        os::fill_random(&mut bytes)?;
        Ok(CapabilityToken(bytes))
    }

    /// Construct a token from raw bytes (e.g. received over the wire).
    pub fn from_bytes(bytes: [u8; TOKEN_LEN]) -> Self {
        CapabilityToken(bytes)
    }

    /// Borrow the raw token bytes.
    pub fn as_bytes(&self) -> &[u8; TOKEN_LEN] {
        &self.0
    }

    /// Constant-time equality against a candidate slice.
    ///
    /// Returns `false` for any slice whose length differs from [`TOKEN_LEN`].
    /// The comparison time does not depend on *where* a mismatch occurs, which
    /// prevents timing side channels from leaking the token byte-by-byte.
    pub fn ct_eq(&self, candidate: &[u8]) -> bool {
        if candidate.len() != TOKEN_LEN {
            return false;
        }
        let mut diff: u8 = 0;
        for i in 0..TOKEN_LEN {
            diff |= self.0[i] ^ candidate[i];
        }
        // `diff == 0` iff every byte matched; the subtraction/shift keeps the
        // result branch-free.
        diff == 0
    }
}

impl std::fmt::Debug for CapabilityToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the token material; it is a secret.
        write!(f, "CapabilityToken(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_tokens_differ() {
        let a = CapabilityToken::random().unwrap();
        let b = CapabilityToken::random().unwrap();
        assert!(!a.ct_eq(b.as_bytes()));
    }

    #[test]
    fn ct_eq_matches_self() {
        let a = CapabilityToken::random().unwrap();
        assert!(a.ct_eq(a.as_bytes()));
    }

    #[test]
    fn ct_eq_rejects_wrong_length() {
        let a = CapabilityToken::from_bytes([7u8; TOKEN_LEN]);
        assert!(!a.ct_eq(&[7u8; TOKEN_LEN - 1]));
        assert!(!a.ct_eq(&[7u8; TOKEN_LEN + 1]));
    }

    #[test]
    fn ct_eq_detects_single_bit_flip() {
        let mut bytes = [0xA5u8; TOKEN_LEN];
        let token = CapabilityToken::from_bytes(bytes);
        bytes[TOKEN_LEN - 1] ^= 0x01;
        assert!(!token.ct_eq(&bytes));
    }
}
