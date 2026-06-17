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
