//! Routing-only crypto provider: plaintext L4 passthrough (no encryption) over
//! TCP (byte stream) or UDP (datagram).
//!
//! Selected with `"security_provider": "routing"`. Both directions perform the
//! same plaintext forwarding (there is no encrypt/decrypt asymmetry without
//! crypto), so the provider simply runs the routing listener for the rule's
//! `listen_proto`: [`routing_engine::run_tcp_routing_listener`] for TCP,
//! [`routing_engine::run_udp_routing_listener`] for UDP.

use crate::management::config::{Direction, Proto};
use crate::processing::RuleContext;
use crate::security::provider::{CryptoProvider, ProviderMode};
use crate::security::routing_engine;

/// Plaintext L4 passthrough — no TLS on either leg (TCP stream or UDP datagram).
pub struct RoutingProvider;

impl CryptoProvider for RoutingProvider {
    fn name(&self) -> &str {
        "routing"
    }

    fn description(&self) -> &str {
        "Routing-only — plaintext L4 passthrough (no encryption), tcp or udp"
    }

    fn supported_modes(&self) -> Vec<ProviderMode> {
        // Advisory (not enforced by config validation — the runtime `route`
        // dispatch and `config::validate` are load-bearing); kept accurate.
        [Proto::Tcp, Proto::Udp]
            .into_iter()
            .flat_map(|proto| {
                [Direction::Encrypt, Direction::Decrypt].map(|direction| ProviderMode {
                    direction,
                    listen_proto: proto,
                })
            })
            .collect()
    }

    fn run_encrypt(&self, ctx: &RuleContext) -> Result<(), String> {
        route(ctx)
    }

    fn run_decrypt(&self, ctx: &RuleContext) -> Result<(), String> {
        route(ctx)
    }
}

/// Dispatch to the plaintext listener for the rule's `listen_proto`.
fn route(ctx: &RuleContext) -> Result<(), String> {
    match ctx.listen_proto {
        Proto::Tcp => {
            routing_engine::run_tcp_routing_listener(ctx);
            Ok(())
        }
        Proto::Udp => {
            routing_engine::run_udp_routing_listener(ctx);
            Ok(())
        }
        other => Err(format!(
            "routing provider supports listen_proto = tcp | udp, not {}",
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
    fn modes_cover_tcp_and_udp_both_directions() {
        let modes = RoutingProvider.supported_modes();
        assert_eq!(modes.len(), 4);
        for proto in [Proto::Tcp, Proto::Udp] {
            assert!(modes
                .iter()
                .any(|m| m.listen_proto == proto && m.direction == Direction::Encrypt));
            assert!(modes
                .iter()
                .any(|m| m.listen_proto == proto && m.direction == Direction::Decrypt));
        }
        // UDS/SHM are never routing modes (those go through the InterfaceManager).
        assert!(modes
            .iter()
            .all(|m| matches!(m.listen_proto, Proto::Tcp | Proto::Udp)));
    }
}
