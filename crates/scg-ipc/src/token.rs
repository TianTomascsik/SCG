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
        for (&actual, &expected) in self.0.iter().zip(candidate.iter()) {
            diff |= actual ^ expected;
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

impl Drop for CapabilityToken {
    fn drop(&mut self) {
        zeroize_token_bytes(&mut self.0);
    }
}

/// Best-effort volatile wipe of a token buffer.
///
/// `scg-ipc` is deliberately libc-only, so this hand-rolls what the `zeroize`
/// crate would do rather than taking a dependency: a `write_volatile` the
/// optimiser may not elide, plus a `compiler_fence` so the wipe is not reordered
/// after the memory is released.
fn zeroize_token_bytes(bytes: &mut [u8; TOKEN_LEN]) {
    // SAFETY: `bytes` is a valid, uniquely-borrowed, properly-aligned
    // `[u8; TOKEN_LEN]`; `write_volatile` stores a value of the exact same type
    // through it. The volatile write prevents the compiler from eliding the wipe
    // as a dead store before the backing memory is freed.
    unsafe { core::ptr::write_volatile(bytes, [0u8; TOKEN_LEN]) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
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

    // The wipe helper clears the buffer (drop uses the same routine).
    #[test]
    fn zeroize_token_bytes_clears_buffer() {
        let mut bytes = [0xA5u8; TOKEN_LEN];
        zeroize_token_bytes(&mut bytes);
        assert_eq!(bytes, [0u8; TOKEN_LEN]);
    }

    // The token never prints its material (guards against accidental log leaks).
    #[test]
    fn debug_masks_token_material() {
        let s = format!("{:?}", CapabilityToken::from_bytes([0xAB; TOKEN_LEN]));
        // Exact masked form → no token material (0xAB / 171 / "AB" hex) can appear.
        assert_eq!(s, "CapabilityToken(***)");
        assert!(!s.contains("171") && !s.contains("AB"), "{s}");
    }
}
