//! DTLS (Datagram TLS) crypto provider.

use crate::management::config::{Direction, Proto};
use crate::processing::RuleContext;
use crate::security::dtls_engine;
use crate::security::provider::{CryptoProvider, ProviderMode};

/// DTLS — native UDP encryption preserving datagram semantics.
pub struct DtlsProvider;

impl CryptoProvider for DtlsProvider {
    fn name(&self) -> &str {
        "dtls"
    }

    fn description(&self) -> &str {
        "DTLS (Datagram TLS) — native UDP encryption"
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
        if ctx.listen_proto != Proto::Udp {
            return Err("DTLS requires UDP listen_proto".to_string());
        }
        dtls_engine::run_dtls_encrypt_relay(ctx);
        Ok(())
    }

    fn run_decrypt(&self, ctx: &RuleContext) -> Result<(), String> {
        if ctx.listen_proto != Proto::Udp {
            return Err("DTLS requires UDP listen_proto".to_string());
        }
        dtls_engine::run_dtls_decrypt_relay(ctx);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_description() {
        assert_eq!(DtlsProvider.name(), "dtls");
        assert!(DtlsProvider.description().contains("DTLS"));
    }

    #[test]
    fn modes_are_udp_only() {
        let modes = DtlsProvider.supported_modes();
        assert_eq!(modes.len(), 2);
        assert!(modes.iter().all(|m| m.listen_proto == Proto::Udp));
        assert!(modes.iter().any(|m| m.direction == Direction::Encrypt));
        assert!(modes.iter().any(|m| m.direction == Direction::Decrypt));
    }
}
