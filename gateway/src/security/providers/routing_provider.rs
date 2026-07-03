//! Routing-only crypto provider: plaintext L4 TCP passthrough (no encryption).
//!
//! Selected with `"security_provider": "routing"`. Both directions perform the
//! same plaintext forwarding (there is no encrypt/decrypt asymmetry without
//! crypto), so the provider simply runs the routing listener.

use crate::management::config::{Direction, Proto};
use crate::processing::RuleContext;
use crate::security::provider::{CryptoProvider, ProviderMode};
use crate::security::routing_engine;

/// Plaintext L4 passthrough — no TLS on either leg.
pub struct RoutingProvider;

impl CryptoProvider for RoutingProvider {
    fn name(&self) -> &str {
        "routing"
    }

    fn description(&self) -> &str {
        "Routing-only — plaintext L4 TCP passthrough (no encryption)"
    }

    fn supported_modes(&self) -> Vec<ProviderMode> {
        vec![
            ProviderMode {
                direction: Direction::Encrypt,
                listen_proto: Proto::Tcp,
            },
            ProviderMode {
                direction: Direction::Decrypt,
                listen_proto: Proto::Tcp,
            },
        ]
    }

    fn run_encrypt(&self, ctx: &RuleContext) -> Result<(), String> {
        route_tcp(ctx)
    }

    fn run_decrypt(&self, ctx: &RuleContext) -> Result<(), String> {
        route_tcp(ctx)
    }
}

fn route_tcp(ctx: &RuleContext) -> Result<(), String> {
    match ctx.listen_proto {
        Proto::Tcp => {
            routing_engine::run_tcp_routing_listener(ctx);
            Ok(())
        }
        other => Err(format!(
            "routing provider supports listen_proto = tcp only, not {}",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_description() {
        assert_eq!(RoutingProvider.name(), "routing");
        assert!(RoutingProvider.description().contains("plaintext"));
    }

    #[test]
    fn modes_are_tcp_only() {
        let modes = RoutingProvider.supported_modes();
        assert_eq!(modes.len(), 2);
        assert!(modes.iter().all(|m| m.listen_proto == Proto::Tcp));
        assert!(modes.iter().any(|m| m.direction == Direction::Encrypt));
        assert!(modes.iter().any(|m| m.direction == Direction::Decrypt));
    }
}
