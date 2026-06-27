//! Provider registry for crypto and application-level protocol providers.
//!
//! Built at startup in `main.rs`, shared (read-only) across all rule threads.

use crate::app_protocols::provider::AppProtocolProvider;
use crate::security::provider::CryptoProvider;
use std::sync::Arc;

/// Registry of all crypto and app-protocol providers.
///
/// Populated once at startup with built-in providers, then shared immutably
/// across all rule threads via `Arc<ProviderRegistry>`.
pub struct ProviderRegistry {
    crypto: Vec<Box<dyn CryptoProvider>>,
    app_protocols: Vec<Box<dyn AppProtocolProvider>>,
}

#[allow(dead_code)]
impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            crypto: Vec::new(),
            app_protocols: Vec::new(),
        }
    }

    /// Register a crypto provider (e.g., TLS, kTLS, DTLS).
    pub fn register_crypto(&mut self, provider: Box<dyn CryptoProvider>) {
        self.crypto.push(provider);
    }

    /// Register an app-level protocol provider (e.g., ALE, Raw).
    pub fn register_app_protocol(&mut self, provider: Box<dyn AppProtocolProvider>) {
        self.app_protocols.push(provider);
    }

    /// Look up a crypto provider by name.
    pub fn find_crypto(&self, name: &str) -> Option<&dyn CryptoProvider> {
        self.crypto
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }

    /// Look up an app-protocol provider by name.
    pub fn find_app_protocol(&self, name: &str) -> Option<&dyn AppProtocolProvider> {
        self.app_protocols
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }

    /// List all registered crypto provider names.
    pub fn crypto_names(&self) -> Vec<&str> {
        self.crypto.iter().map(|p| p.name()).collect()
    }

    /// List all registered app-protocol provider names.
    pub fn app_protocol_names(&self) -> Vec<&str> {
        self.app_protocols.iter().map(|p| p.name()).collect()
    }

    /// Wrap into an Arc for sharing across threads.
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}
