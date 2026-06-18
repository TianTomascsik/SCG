//! TLS (userspace OpenSSL) crypto provider.

use crate::management::config::{Direction, Proto};
use crate::processing::RuleContext;
use crate::security::provider::{CryptoProvider, ProviderMode};
use crate::security::tls_engine::{decrypt, encrypt};

/// Userspace TLS via OpenSSL. Supports TCP encrypt/decrypt and UDP-over-TLS tunneling.
pub struct TlsProvider;

impl CryptoProvider for TlsProvider {
    fn name(&self) -> &str {
        "tls"
    }

    fn description(&self) -> &str {
        "Userspace TLS (OpenSSL) — TCP and UDP-over-TLS tunnel"
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
        // Both TCP and UDP decrypt go through the TCP decrypt listener
        // (UDP-over-TLS still arrives as TCP+TLS, then gets relayed to UDP upstream)
        decrypt::run_tcp_decrypt_listener(ctx);
        Ok(())
    }
}
