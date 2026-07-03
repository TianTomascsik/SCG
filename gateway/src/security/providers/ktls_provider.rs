//! kTLS (kernel TLS offload) crypto provider.

use crate::management::config::{Direction, Proto};
use crate::processing::RuleContext;
use crate::security::provider::{CryptoProvider, ProviderMode};
use crate::security::tls_engine::{decrypt, encrypt};

/// Kernel TLS offload (kTLS). Same code paths as TLS, branching on `ctx.tls_mode`
/// internally. Higher throughput than userspace TLS — requires CAP_NET_ADMIN.
pub struct KtlsProvider;

impl CryptoProvider for KtlsProvider {
    fn name(&self) -> &str {
        "ktls"
    }

    fn description(&self) -> &str {
        "Kernel TLS offload (kTLS) — TCP and UDP-over-TLS tunnel"
    }

    fn supported_modes(&self) -> Vec<ProviderMode> {
        vec![
            ProviderMode {
                direction: Direction::Encrypt,
                listen_proto: Proto::Tcp,
            },
            ProviderMode {
                direction: Direction::Encrypt,
                listen_proto: Proto::Udp,
            },
            ProviderMode {
                direction: Direction::Decrypt,
                listen_proto: Proto::Tcp,
            },
            ProviderMode {
                direction: Direction::Decrypt,
                listen_proto: Proto::Udp,
            },
        ]
    }

    fn run_encrypt(&self, ctx: &RuleContext) -> Result<(), String> {
        match ctx.listen_proto {
            Proto::Tcp => encrypt::run_tcp_encrypt_listener(ctx),
            Proto::Udp => encrypt::run_udp_encrypt_relay(ctx),
            Proto::Uds | Proto::Shm => {
                return Err(format!(
                    "security provider cannot listen on {} directly; UDS/SHM endpoints \
                     are driven by the interface manager",
                    ctx.listen_proto
                ));
            }
        }
        Ok(())
    }

    fn run_decrypt(&self, ctx: &RuleContext) -> Result<(), String> {
        decrypt::run_tcp_decrypt_listener(ctx);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_description() {
        assert_eq!(KtlsProvider.name(), "ktls");
        assert!(KtlsProvider.description().contains("kTLS"));
    }

    #[test]
    fn supports_tcp_and_udp_both_directions() {
        let modes = KtlsProvider.supported_modes();
        assert_eq!(modes.len(), 4);
        for proto in [Proto::Tcp, Proto::Udp] {
            assert!(modes
                .iter()
                .any(|m| m.direction == Direction::Encrypt && m.listen_proto == proto));
            assert!(modes
                .iter()
                .any(|m| m.direction == Direction::Decrypt && m.listen_proto == proto));
        }
    }
}
