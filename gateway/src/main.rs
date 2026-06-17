//! Secure Communication Gateway — default (open) binary.
//!
//! Registers only the built-in, non-proprietary providers (TLS, kTLS, DTLS,
//! ALE, Raw). Downstream/internal binaries reuse [`gateway::run`] to register
//! additional providers.

fn main() {
    gateway::run(Vec::new(), Vec::new());
}
