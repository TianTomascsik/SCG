//! Crypto provider trait for extensible security engines.
//!
//! Each crypto provider implements one method of encrypting/decrypting traffic.
//! Built-in providers: TLS, kTLS, DTLS, WireGuard, routing.
//! New providers can be added by implementing `CryptoProvider` and registering
//! them in the `ProviderRegistry`.

use crate::management::config::{Direction, Proto};
use crate::processing::RuleContext;

/// A supported (direction, listen_proto) combination for a crypto provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMode {
    pub direction: Direction,
    pub listen_proto: Proto,
}

/// A crypto provider implements one method of encrypting/decrypting traffic.
///
/// Providers are synchronous and block the calling thread for the lifetime
/// of the rule (matching the gateway's thread-per-rule architecture).
///
/// # Adding a new provider
///
/// 1. Create a struct implementing this trait
/// 2. Register it in `lib.rs::run` via `registry.register_crypto(Box::new(MyProvider))`
///    (or inject it out-of-tree via `gateway::run(extra_crypto, extra_app)`)
/// 3. Use the provider's `name()` as the `"security_provider"` value in config
pub trait CryptoProvider: Send + Sync {
    /// Unique string identifier used in config (e.g., "tls", "ktls", "dtls").
    fn name(&self) -> &str;

    /// Human-readable description for logging.
    fn description(&self) -> &str;

    /// Which (direction, listen_proto) combinations this provider supports.
    ///
    /// Advisory metadata: the dispatcher does not consult it yet; per-provider
    /// validation still rejects unsupported combinations at config load.
    fn supported_modes(&self) -> Vec<ProviderMode>;

    /// Run the encrypt direction for this provider. Blocks until shutdown.
    fn run_encrypt(&self, ctx: &RuleContext) -> Result<(), String>;

    /// Run the decrypt direction for this provider. Blocks until shutdown.
    fn run_decrypt(&self, ctx: &RuleContext) -> Result<(), String>;
}
