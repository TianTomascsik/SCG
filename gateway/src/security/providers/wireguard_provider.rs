//! Kernel WireGuard crypto provider.
//!
//! Offloads the WireGuard data plane (Noise_IKpsk2 handshake +
//! ChaCha20-Poly1305 transport) to the in-kernel `wireguard` module, the same
//! way [`KtlsProvider`](super::ktls_provider::KtlsProvider) offloads TLS. The
//! provider provisions a `wg` interface and relays plaintext UDP through it; the
//! kernel performs all cryptography. UDP-only, like DTLS.

use crate::management::config::{Direction, Proto};
use crate::processing::RuleContext;
use crate::security::provider::{CryptoProvider, ProviderMode};
use crate::security::wireguard_engine;

/// WireGuard — kernel-offloaded UDP datagram encryption.
pub struct WireguardProvider;

/// WireGuard is a datagram protocol; reject any non-UDP listen protocol with a
/// descriptive error rather than failing deep in the relay.
fn require_udp(listen_proto: Proto) -> Result<(), String> {
    if listen_proto == Proto::Udp {
        Ok(())
    } else {
        Err(format!(
            "WireGuard requires listen_proto = \"udp\", got \"{listen_proto}\""
        ))
    }
}

impl CryptoProvider for WireguardProvider {
    fn name(&self) -> &str {
        "wireguard"
    }

    fn description(&self) -> &str {
        "Kernel WireGuard offload (Noise_IKpsk2 + ChaCha20-Poly1305) — UDP datagram encryption \
         via an in-kernel wg interface (requires CAP_NET_ADMIN, the wireguard module, and `wg`)"
    }

    fn supported_modes(&self) -> Vec<ProviderMode> {
        vec![
            ProviderMode {
                direction: Direction::Encrypt,
                listen_proto: Proto::Udp,
            },
            ProviderMode {
                direction: Direction::Decrypt,
                listen_proto: Proto::Udp,
            },
        ]
    }

    fn run_encrypt(&self, ctx: &RuleContext) -> Result<(), String> {
        require_udp(ctx.listen_proto)?;
        wireguard_engine::run_wireguard_encrypt_relay(ctx)
    }

    fn run_decrypt(&self, ctx: &RuleContext) -> Result<(), String> {
        require_udp(ctx.listen_proto)?;
        wireguard_engine::run_wireguard_decrypt_relay(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_wireguard() {
        assert_eq!(WireguardProvider.name(), "wireguard");
    }

    #[test]
    fn modes_are_udp_only() {
        let modes = WireguardProvider.supported_modes();
        assert_eq!(modes.len(), 2);
        assert!(modes.iter().all(|m| m.listen_proto == Proto::Udp));
        assert!(modes.iter().any(|m| m.direction == Direction::Encrypt));
        assert!(modes.iter().any(|m| m.direction == Direction::Decrypt));
    }

    #[test]
    fn rejects_non_udp_listen_proto() {
        assert!(require_udp(Proto::Udp).is_ok());
        assert!(require_udp(Proto::Tcp).is_err());
        assert!(require_udp(Proto::Uds).is_err());
        assert!(require_udp(Proto::Shm).is_err());
    }
}
