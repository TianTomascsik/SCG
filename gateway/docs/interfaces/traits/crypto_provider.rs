//! Crypto Provider interface — REFERENCE STUB (not compiled).
//!
//! Status: AS-BUILT. This mirrors the authoritative definition in
//! `gateway/src/security/provider.rs`. Kept here so the interface set is
//! self-contained; the version in `src/` is the source of truth.
//!
//! A crypto provider is a swappable security engine that owns the encrypt or
//! decrypt loop for a rule, blocking its thread until shutdown.

// Shared types (defined in the gateway crate):
//   Direction    -> crate::management::config::Direction  (Encrypt | Decrypt)
//   Proto        -> crate::management::config::Proto       (Tcp | Udp)
//   RuleContext  -> crate::processing::RuleContext         (per-rule context)

/// A supported (direction, listen_proto) combination for a crypto provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMode {
    pub direction: Direction,
    pub listen_proto: Proto,
}

/// A crypto provider implements one method of encrypting/decrypting traffic.
///
/// Providers are synchronous and block the calling thread for the lifetime of
/// the rule (matching the gateway's thread-per-rule architecture).
pub trait CryptoProvider: Send + Sync {
    /// Unique string identifier used in config (e.g., "tls", "ktls", "dtls").
    fn name(&self) -> &str;

    /// Human-readable description for logging.
    fn description(&self) -> &str;

    /// Which (direction, listen_proto) combinations this provider supports.
    fn supported_modes(&self) -> Vec<ProviderMode>;

    /// Run the encrypt direction for this provider. Blocks until shutdown.
    fn run_encrypt(&self, ctx: &RuleContext) -> Result<(), String>;

    /// Run the decrypt direction for this provider. Blocks until shutdown.
    fn run_decrypt(&self, ctx: &RuleContext) -> Result<(), String>;
}
