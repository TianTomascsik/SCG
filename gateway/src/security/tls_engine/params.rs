//! Resolved TLS/DTLS security parameters parsed from a rule's `provider_params`.
//!
//! The built-in `tls`/`ktls`/`dtls` providers historically hardcoded a
//! self-signed certificate and `SslVerifyMode::NONE`. This module turns the
//! generic, untyped `provider_params` map on a rule into a typed, validated
//! [`TlsSecurityParams`] that the engine builders consume to configure
//! certificates, peer verification, cipher policy, PSK and SNI.
//!
//! ## Recognised `provider_params` keys
//!
//! | Key | Type | Meaning |
//! |-----|------|---------|
//! | `profile` | string | `default` (back-compat), `subset146-pki`, `subset146-psk`, `integrity-only` |
//! | `verify` | string | `none`, `server`, `mutual` |
//! | `cert_path` | string | PEM identity certificate (server cert, or client cert for mutual) |
//! | `key_path` | string | PEM private key for `cert_path` |
//! | `ca_path` | string | PEM CA bundle used to verify the peer |
//! | `server_name` | string | SNI / hostname verified on the connector (defaults to the upstream host) |
//! | `psk_identity` | string | PSK identity (for `subset146-psk`) |
//! | `psk_hex` | string | PSK key as hex (for `subset146-psk`) |
//! | `cipher_list` | string | Advanced override for TLS ≤ 1.2 cipher list |
//! | `ciphersuites` | string | Advanced override for TLS 1.3 ciphersuites |
//! | `max_sessions` | integer | DTLS only: max concurrent peer sessions (admission control) |
//! | `idle_ttl_secs` | integer | DTLS only: idle session eviction timeout (seconds) |
//!
//! `protocol_version` (a first-class rule field) selects the protocol version
//! (`tls1.2`/`tls1.3`/`dtls1.0`/`dtls1.2`).

use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

/// Default ceiling on concurrent DTLS sessions for a DTLS encrypt relay. Bounds
/// memory/socket/handshake-CPU growth under a source-address-spoofing flood.
pub const DEFAULT_DTLS_MAX_SESSIONS: usize = 1024;

/// Default idle timeout (seconds) after which a DTLS session is evicted so a
/// flood of short-lived peers cannot pin resources indefinitely.
pub const DEFAULT_DTLS_IDLE_TTL_SECS: u64 = 60;

/// Peer-verification policy for a TLS/DTLS rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// No peer verification (legacy default — `SslVerifyMode::NONE`).
    None,
    /// The connector verifies the upstream server certificate + hostname.
    Server,
    /// Both sides authenticate with X.509 certificates (mTLS).
    Mutual,
}

/// A named bundle of verify-mode + cipher-policy + version presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsProfile {
    /// Back-compatible default (self-signed, verify none, RSA-GCM).
    Default,
    /// UNISIG Subset-146 TLS PKI: mutual X.509, ECDHE/ECDSA-GCM.
    Subset146Pki,
    /// UNISIG Subset-146 TLS PSK: DHE-PSK-GCM, TLS 1.2 only.
    Subset146Psk,
    /// Authenticated-but-not-encrypted TLS (NULL-encryption cipher suites).
    IntegrityOnly,
}

impl TlsProfile {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "default" => Ok(TlsProfile::Default),
            "subset146-pki" | "s146-pki" | "pki" => Ok(TlsProfile::Subset146Pki),
            "subset146-psk" | "s146-psk" | "psk" => Ok(TlsProfile::Subset146Psk),
            "integrity-only" | "integrity" | "null" => Ok(TlsProfile::IntegrityOnly),
            other => Err(format!(
                "unknown profile '{}' (expected: default, subset146-pki, subset146-psk, integrity-only)",
                other
            )),
        }
    }

    /// Human-readable name for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            TlsProfile::Default => "default",
            TlsProfile::Subset146Pki => "subset146-pki",
            TlsProfile::Subset146Psk => "subset146-psk",
            TlsProfile::IntegrityOnly => "integrity-only",
        }
    }
}

/// Resolved, validated security parameters for a TLS/DTLS rule.
///
/// `Debug` is implemented by hand (not derived) so that PSK secret material is
/// never printed: a derived `Debug` would emit `psk_key`/`psk_identity`
/// verbatim if this struct is ever logged with `{:?}`. See the manual `Debug`
/// impl below, which mirrors the `***`-masking convention used by
/// `scg_ipc::CapabilityToken`.
#[derive(Clone)]
pub struct TlsSecurityParams {
    /// Protocol version string (`tls1.2`/`tls1.3`/`dtls1.0`/`dtls1.2`), if any.
    pub version: Option<String>,
    /// Selected profile preset.
    pub profile: TlsProfile,
    /// Peer-verification policy.
    pub verify: VerifyMode,
    /// PEM identity certificate path (server cert, or client cert for mutual).
    pub cert_path: Option<PathBuf>,
    /// PEM private key path for `cert_path`.
    pub key_path: Option<PathBuf>,
    /// PEM CA bundle path used to verify the peer.
    pub ca_path: Option<PathBuf>,
    /// SNI / hostname verified on the connector (defaults to the upstream host).
    pub server_name: Option<String>,
    /// PSK identity (for `subset146-psk`).
    pub psk_identity: Option<String>,
    /// PSK key bytes, decoded from `psk_hex` (for `subset146-psk`).
    pub psk_key: Option<Vec<u8>>,
    /// Advanced override for the TLS ≤ 1.2 cipher list.
    pub cipher_list: Option<String>,
    /// Advanced override for the TLS 1.3 ciphersuites.
    pub ciphersuites: Option<String>,
    /// Whether TLS session resumption (TLS 1.3 tickets / TLS 1.2 session cache)
    /// is enabled for this rule. Resumption amortises the handshake cost across
    /// reconnects; leaving it `false` forces a full handshake on every
    /// connection. Default: `false` (opt-in).
    pub resumption: bool,
    /// Maximum concurrent DTLS sessions (distinct peer addresses) a DTLS encrypt
    /// relay will hold. Admission control against source-spoofing floods; the
    /// userspace TLS path ignores it. Default: [`DEFAULT_DTLS_MAX_SESSIONS`].
    pub max_sessions: usize,
    /// Idle time (seconds) after which an inactive DTLS session is evicted to
    /// reclaim its socket/buffers. Default: [`DEFAULT_DTLS_IDLE_TTL_SECS`].
    pub idle_ttl_secs: u64,
}

impl std::fmt::Debug for TlsSecurityParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // PSK material is redacted; presence (`Some`/`None`) is preserved so the
        // output remains useful for diagnosing configuration without leaking
        // secrets into logs.
        f.debug_struct("TlsSecurityParams")
            .field("version", &self.version)
            .field("profile", &self.profile)
            .field("verify", &self.verify)
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("ca_path", &self.ca_path)
            .field("server_name", &self.server_name)
            .field(
                "psk_identity",
                &self.psk_identity.as_ref().map(|_| "[REDACTED]"),
            )
            .field("psk_key", &self.psk_key.as_ref().map(|_| "[REDACTED]"))
            .field("cipher_list", &self.cipher_list)
            .field("ciphersuites", &self.ciphersuites)
            .field("resumption", &self.resumption)
            .field("max_sessions", &self.max_sessions)
            .field("idle_ttl_secs", &self.idle_ttl_secs)
            .finish()
    }
}

impl Default for TlsSecurityParams {
    fn default() -> Self {
        TlsSecurityParams {
            version: None,
            profile: TlsProfile::Default,
            verify: VerifyMode::None,
            cert_path: None,
            key_path: None,
            ca_path: None,
            server_name: None,
            psk_identity: None,
            psk_key: None,
            cipher_list: None,
            ciphersuites: None,
            resumption: false,
            max_sessions: DEFAULT_DTLS_MAX_SESSIONS,
            idle_ttl_secs: DEFAULT_DTLS_IDLE_TTL_SECS,
        }
    }
}

impl TlsSecurityParams {
    /// Parse and validate security parameters from a rule's generic
    /// `provider_params` map plus its `protocol_version`.
    ///
    /// Returns `Err` with a human-readable message for invalid combinations
    /// (e.g. a PSK profile without a key, or an unpaired cert/key).
    pub fn from_params(
        params: &HashMap<String, Value>,
        protocol_version: Option<&str>,
    ) -> Result<Self, String> {
        let get_str = |key: &str| -> Option<String> {
            params.get(key).and_then(|v| v.as_str()).map(str::to_string)
        };

        let profile = match get_str("profile") {
            Some(s) => TlsProfile::parse(&s)?,
            None => TlsProfile::Default,
        };

        // Verify mode: an explicit `verify` always wins. Profiles that imply a
        // safe posture (PKI ⇒ mutual, integrity-only ⇒ server) keep their
        // default, but the `default` and `subset146-psk` profiles have no safe
        // implicit default — silently falling back to `none` would disable peer
        // verification and enable MITM. Require an explicit choice instead
        // (fail-secure).
        let verify = match get_str("verify") {
            Some(s) => match s.as_str() {
                "none" => VerifyMode::None,
                "server" => VerifyMode::Server,
                "mutual" | "mtls" => VerifyMode::Mutual,
                other => {
                    return Err(format!(
                        "unknown verify mode '{}' (expected: none, server, mutual)",
                        other
                    ))
                }
            },
            None => match profile {
                TlsProfile::Subset146Pki => VerifyMode::Mutual,
                TlsProfile::IntegrityOnly => VerifyMode::Server,
                TlsProfile::Subset146Psk | TlsProfile::Default => {
                    return Err(
                        "verify mode must be set explicitly (expected: none, server, mutual); \
                         omitting it would silently disable peer verification"
                            .to_string(),
                    )
                }
            },
        };

        let cert_path = get_str("cert_path").map(PathBuf::from);
        let key_path = get_str("key_path").map(PathBuf::from);
        let ca_path = get_str("ca_path").map(PathBuf::from);
        let server_name = get_str("server_name");
        let psk_identity = get_str("psk_identity");
        let psk_key = match get_str("psk_hex") {
            Some(h) => Some(decode_hex(&h)?),
            None => None,
        };
        let cipher_list = get_str("cipher_list");
        let ciphersuites = get_str("ciphersuites");

        // Session resumption defaults off (opt-in); accept a JSON bool or a
        // "true"/"false" string so it can be supplied via the generic
        // provider-params map.
        let resumption = match params.get("resumption") {
            Some(v) => v
                .as_bool()
                .or_else(|| v.as_str().and_then(|s| s.parse::<bool>().ok()))
                .ok_or_else(|| "resumption must be a boolean (true/false)".to_string())?,
            None => false,
        };

        // DTLS admission-control knobs (ignored by the userspace TLS path).
        // Accept a JSON number or a numeric string, like `resumption`.
        let max_sessions = match params.get("max_sessions") {
            Some(v) => {
                let n = v
                    .as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                    .filter(|&n| n > 0)
                    .ok_or_else(|| "max_sessions must be a positive integer".to_string())?;
                usize::try_from(n).map_err(|_| "max_sessions is too large".to_string())?
            }
            None => DEFAULT_DTLS_MAX_SESSIONS,
        };
        let idle_ttl_secs = match params.get("idle_ttl_secs") {
            Some(v) => v
                .as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                .filter(|&n| n > 0)
                .ok_or_else(|| "idle_ttl_secs must be a positive integer".to_string())?,
            None => DEFAULT_DTLS_IDLE_TTL_SECS,
        };

        let parsed = TlsSecurityParams {
            version: protocol_version.map(str::to_string),
            profile,
            verify,
            cert_path,
            key_path,
            ca_path,
            server_name,
            psk_identity,
            psk_key,
            cipher_list,
            ciphersuites,
            resumption,
            max_sessions,
            idle_ttl_secs,
        };
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), String> {
        // cert and key must be supplied together.
        match (&self.cert_path, &self.key_path) {
            (Some(_), None) => return Err("cert_path requires key_path".to_string()),
            (None, Some(_)) => return Err("key_path requires cert_path".to_string()),
            _ => {}
        }

        match self.profile {
            TlsProfile::Subset146Psk => {
                if self.psk_identity.is_none() || self.psk_key.is_none() {
                    return Err(
                        "subset146-psk profile requires both psk_identity and psk_hex".to_string(),
                    );
                }
                if self.is_tls13() {
                    return Err(
                        "subset146-psk requires TLS 1.2 (PSK-only handshakes were removed in TLS 1.3)"
                            .to_string(),
                    );
                }
            }
            TlsProfile::Subset146Pki
                // PKI mandates mutual authentication.
                if self.verify != VerifyMode::Mutual => {
                    return Err("subset146-pki profile requires verify = mutual".to_string());
                }
            _ => {}
        }

        // psk_hex without the psk profile is a likely misconfiguration.
        if self.psk_key.is_some() && self.profile != TlsProfile::Subset146Psk {
            return Err(
                "psk_hex/psk_identity are only valid with profile = subset146-psk".to_string(),
            );
        }

        Ok(())
    }

    /// Whether the selected version is TLS 1.3.
    pub fn is_tls13(&self) -> bool {
        self.version.as_deref() == Some("tls1.3")
    }

    /// Whether this configuration can be offloaded to kernel TLS.
    ///
    /// kTLS offloads only the post-handshake AES-GCM record layer, which is
    /// independent of *how* the peer was authenticated: `build_acceptor` /
    /// `build_connector` apply the same `apply_*_verify` (CA trust, mutual client
    /// cert) to the kTLS context as to userspace, and peer auth completes during
    /// the handshake *before* kTLS activates. So server- and mutual-verified TLS
    /// are offloadable; only a non-`Default` profile (subset146 — non-GCM / PSK
    /// cipher policy) or a PSK handshake (no AES-GCM record path) is not.
    ///
    /// This is *static* eligibility only. The relay must still gate the zero-copy
    /// splice path on **runtime** activation (`ktls_active`), never on this flag,
    /// or a silent kTLS-enable failure would relay cleartext — see
    /// `tls_engine::{decrypt,encrypt}` and TRA register #56.
    pub fn is_ktls_offloadable(&self) -> bool {
        self.profile == TlsProfile::Default && self.psk_key.is_none()
    }

    /// The SNI / verification hostname to present on the connector. Falls back
    /// to the host portion of `upstream_addr`, then to the legacy `"gateway"`.
    pub fn sni_name(&self, upstream_addr: &str) -> String {
        if let Some(name) = &self.server_name {
            return name.clone();
        }
        host_of(upstream_addr).unwrap_or_else(|| "gateway".to_string())
    }

    /// Resolve the (cipher_list for ≤ 1.2, ciphersuites for 1.3) pair to apply,
    /// honouring explicit overrides before profile presets.
    pub fn cipher_policy(&self) -> (Option<String>, Option<String>) {
        let (default_list, default_suites): (Option<&str>, Option<&str>) = match self.profile {
            TlsProfile::Default => (
                Some(
                    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                     ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
                ),
                Some("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"),
            ),
            TlsProfile::Subset146Pki => (
                Some("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"),
                Some("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"),
            ),
            TlsProfile::Subset146Psk => (Some("DHE-PSK-AES256-GCM-SHA384:@SECLEVEL=0"), None),
            TlsProfile::IntegrityOnly => (
                Some("ECDHE-ECDSA-NULL-SHA:ECDHE-RSA-NULL-SHA:NULL-SHA256:NULL-SHA:@SECLEVEL=0"),
                Some("TLS_SHA384_SHA384:TLS_SHA256_SHA256"),
            ),
        };

        let list = self
            .cipher_list
            .clone()
            .or_else(|| default_list.map(str::to_string));
        let suites = self
            .ciphersuites
            .clone()
            .or_else(|| default_suites.map(str::to_string));
        (list, suites)
    }
}

/// Extract the host portion of a `HOST:PORT` string (handles IPv6 `[::1]:port`).
pub(crate) fn host_of(addr: &str) -> Option<String> {
    let addr = addr.trim();
    if addr.is_empty() || addr == "auto" {
        return None;
    }
    if let Some(end) = addr.strip_prefix('[') {
        // IPv6 literal: [host]:port
        if let Some(idx) = end.find(']') {
            return Some(end[..idx].to_string());
        }
    }
    match addr.rsplit_once(':') {
        Some((host, _port)) if !host.is_empty() => Some(host.to_string()),
        _ => Some(addr.to_string()),
    }
}

/// Decode a hex string (optionally with `0x` prefix or whitespace) into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .trim()
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.is_empty() {
        return Err("psk_hex is empty".to_string());
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err("psk_hex must have an even number of hex digits".to_string());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!("invalid hex digit '{}'", other as char)),
    }
}

/// Best-effort probe: does the linked OpenSSL expose NULL-encryption ciphers?
///
/// Distribution builds frequently disable `eNULL`. WP5's integrity-only test
/// uses this to skip gracefully instead of failing on an unsupported platform.
pub fn openssl_supports_null_cipher() -> bool {
    use openssl::ssl::{SslContext, SslMethod};
    let mut builder = match SslContext::builder(SslMethod::tls()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    builder
        .set_cipher_list("ECDHE-RSA-NULL-SHA:NULL-SHA256:NULL-SHA:@SECLEVEL=0")
        .is_ok()
}

#[cfg(test)]
mod secret_redaction_tests {
    use super::*;

    #[test]
    fn debug_redacts_psk_material() {
        let p = TlsSecurityParams {
            psk_identity: Some("super-secret-identity".to_string()),
            psk_key: Some(vec![0xde, 0xad, 0xbe, 0xef]),
            ..TlsSecurityParams::default()
        };
        let s = format!("{p:?}");
        assert!(
            !s.contains("super-secret-identity"),
            "psk_identity leaked into Debug output: {s}"
        );
        // 0xde == 222 decimal — the byte rendering a derived Debug would emit.
        assert!(
            !s.contains("222"),
            "psk_key bytes leaked into Debug output: {s}"
        );
        assert!(s.contains("REDACTED"), "expected redaction marker: {s}");
        // Presence is still conveyed.
        assert!(
            s.contains("psk_key: Some"),
            "presence should be visible: {s}"
        );
    }

    #[test]
    fn debug_shows_none_for_absent_psk() {
        let s = format!("{:?}", TlsSecurityParams::default());
        assert!(s.contains("psk_key: None"), "{s}");
        assert!(!s.contains("REDACTED"), "{s}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;

    fn params_from(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn default_profile_requires_explicit_verify() {
        // Fail-secure: the `default` profile must not silently default to
        // verify = none. An empty params map is rejected.
        assert!(TlsSecurityParams::from_params(&HashMap::new(), None).is_err());
    }

    #[test]
    fn default_profile_with_explicit_none() {
        let m = params_from(&[("verify", json!("none"))]);
        let p = TlsSecurityParams::from_params(&m, None).unwrap();
        assert_eq!(p.profile, TlsProfile::Default);
        assert_eq!(p.verify, VerifyMode::None);
        assert!(p.is_ktls_offloadable());
    }

    #[test]
    fn selected_identity_does_not_disable_ktls_offload() {
        let m = params_from(&[
            ("verify", json!("none")),
            ("cert_path", json!("/certs/server.pem")),
            ("key_path", json!("/certs/server.key")),
        ]);
        let p = TlsSecurityParams::from_params(&m, Some("tls1.3")).unwrap();
        assert!(p.is_ktls_offloadable());
        assert_eq!(p.cert_path.as_deref(), Some(Path::new("/certs/server.pem")));
        assert_eq!(p.key_path.as_deref(), Some(Path::new("/certs/server.key")));
    }

    #[test]
    fn default_profile_server_verify_is_ktls_offloadable() {
        // Server verification only adds CA trust to the handshake; the AES-GCM
        // record layer is still kTLS-offloadable (verification runs on the kTLS
        // context too). The relay guards the splice path on runtime activation
        // separately — see TRA #56.
        let m = params_from(&[("verify", json!("server"))]);
        let p = TlsSecurityParams::from_params(&m, None).unwrap();
        assert_eq!(p.verify, VerifyMode::Server);
        assert!(p.is_ktls_offloadable());
    }

    #[test]
    fn default_profile_mutual_verify_is_ktls_offloadable() {
        // Mutual TLS on the Default profile (the mTLS benchmark path): client-cert
        // auth is a handshake concern, so kTLS still offloads the record layer.
        // Only subset146-pki (a non-Default profile) stays on the userspace engine.
        let m = params_from(&[
            ("verify", json!("mutual")),
            ("cert_path", json!("/certs/client.pem")),
            ("key_path", json!("/certs/client.key")),
            ("ca_path", json!("/certs/ca.pem")),
        ]);
        let p = TlsSecurityParams::from_params(&m, Some("tls1.3")).unwrap();
        assert_eq!(p.verify, VerifyMode::Mutual);
        assert!(p.is_ktls_offloadable());
    }

    #[test]
    fn resumption_defaults_off() {
        let m = params_from(&[("verify", json!("none"))]);
        let p = TlsSecurityParams::from_params(&m, None).unwrap();
        assert!(!p.resumption);
        assert!(!TlsSecurityParams::default().resumption);
    }

    #[test]
    fn resumption_accepts_bool_and_string() {
        let m = params_from(&[("verify", json!("none")), ("resumption", json!(true))]);
        assert!(TlsSecurityParams::from_params(&m, None).unwrap().resumption);

        let m = params_from(&[("verify", json!("none")), ("resumption", json!(false))]);
        assert!(!TlsSecurityParams::from_params(&m, None).unwrap().resumption);

        let m = params_from(&[("verify", json!("none")), ("resumption", json!("true"))]);
        assert!(TlsSecurityParams::from_params(&m, None).unwrap().resumption);
    }

    #[test]
    fn resumption_rejects_non_boolean() {
        let m = params_from(&[("verify", json!("none")), ("resumption", json!("maybe"))]);
        assert!(TlsSecurityParams::from_params(&m, None).is_err());
    }

    #[test]
    fn session_limits_default_when_absent() {
        let m = params_from(&[("verify", json!("none"))]);
        let p = TlsSecurityParams::from_params(&m, None).unwrap();
        assert_eq!(p.max_sessions, DEFAULT_DTLS_MAX_SESSIONS);
        assert_eq!(p.idle_ttl_secs, DEFAULT_DTLS_IDLE_TTL_SECS);
    }

    #[test]
    fn session_limits_accept_number_and_string() {
        let m = params_from(&[
            ("verify", json!("none")),
            ("max_sessions", json!(32)),
            ("idle_ttl_secs", json!("90")),
        ]);
        let p = TlsSecurityParams::from_params(&m, None).unwrap();
        assert_eq!(p.max_sessions, 32);
        assert_eq!(p.idle_ttl_secs, 90);
    }

    #[test]
    fn session_limits_reject_zero_and_junk() {
        let zero = params_from(&[("verify", json!("none")), ("max_sessions", json!(0))]);
        assert!(TlsSecurityParams::from_params(&zero, None).is_err());

        let junk = params_from(&[("verify", json!("none")), ("idle_ttl_secs", json!("soon"))]);
        assert!(TlsSecurityParams::from_params(&junk, None).is_err());
    }

    #[test]
    fn pki_profile_defaults_to_mutual() {
        let m = params_from(&[("profile", json!("subset146-pki"))]);
        let p = TlsSecurityParams::from_params(&m, Some("tls1.2")).unwrap();
        assert_eq!(p.profile, TlsProfile::Subset146Pki);
        assert_eq!(p.verify, VerifyMode::Mutual);
        assert!(!p.is_ktls_offloadable());
        let (list, suites) = p.cipher_policy();
        assert!(list.unwrap().contains("ECDHE-ECDSA-AES256-GCM-SHA384"));
        assert!(suites.unwrap().contains("TLS_AES_256_GCM_SHA384"));
    }

    #[test]
    fn psk_requires_identity_and_key() {
        let m = params_from(&[
            ("profile", json!("subset146-psk")),
            ("verify", json!("none")),
        ]);
        assert!(TlsSecurityParams::from_params(&m, Some("tls1.2")).is_err());

        let m = params_from(&[
            ("profile", json!("subset146-psk")),
            ("verify", json!("none")),
            ("psk_identity", json!("client1")),
            ("psk_hex", json!("00112233445566778899aabbccddeeff")),
        ]);
        let p = TlsSecurityParams::from_params(&m, Some("tls1.2")).unwrap();
        assert_eq!(p.psk_key.as_ref().unwrap().len(), 16);
        assert!(!p.is_ktls_offloadable());
    }

    #[test]
    fn psk_requires_explicit_verify() {
        // subset146-psk has no safe implicit verify default either.
        let m = params_from(&[
            ("profile", json!("subset146-psk")),
            ("psk_identity", json!("client1")),
            ("psk_hex", json!("00112233445566778899aabbccddeeff")),
        ]);
        assert!(TlsSecurityParams::from_params(&m, Some("tls1.2")).is_err());
    }

    #[test]
    fn psk_rejects_tls13() {
        let m = params_from(&[
            ("profile", json!("subset146-psk")),
            ("verify", json!("none")),
            ("psk_identity", json!("c")),
            ("psk_hex", json!("aabb")),
        ]);
        assert!(TlsSecurityParams::from_params(&m, Some("tls1.3")).is_err());
    }

    #[test]
    fn unpaired_cert_key_rejected() {
        let m = params_from(&[("verify", json!("none")), ("cert_path", json!("/x.pem"))]);
        assert!(TlsSecurityParams::from_params(&m, None).is_err());
    }

    #[test]
    fn psk_hex_only_with_psk_profile() {
        let m = params_from(&[
            ("verify", json!("none")),
            ("psk_hex", json!("aabb")),
            ("psk_identity", json!("c")),
        ]);
        assert!(TlsSecurityParams::from_params(&m, None).is_err());
    }

    #[test]
    fn bad_hex_rejected() {
        let m = params_from(&[
            ("profile", json!("subset146-psk")),
            ("psk_identity", json!("c")),
            ("psk_hex", json!("zz")),
        ]);
        assert!(TlsSecurityParams::from_params(&m, Some("tls1.2")).is_err());
    }

    #[test]
    fn integrity_only_defaults_to_server_verify() {
        let m = params_from(&[("profile", json!("integrity-only"))]);
        let p = TlsSecurityParams::from_params(&m, Some("tls1.2")).unwrap();
        assert_eq!(p.verify, VerifyMode::Server);
        let (list, _) = p.cipher_policy();
        assert!(list.unwrap().contains("NULL"));
    }

    #[test]
    fn sni_falls_back_to_upstream_host() {
        let p = TlsSecurityParams::default();
        assert_eq!(p.sni_name("backend.example:443"), "backend.example");
        assert_eq!(p.sni_name("[2001:db8::1]:443"), "2001:db8::1");
        let m = params_from(&[
            ("verify", json!("none")),
            ("server_name", json!("frontend.local")),
        ]);
        let p = TlsSecurityParams::from_params(&m, None).unwrap();
        assert_eq!(p.sni_name("backend:443"), "frontend.local");
    }

    #[test]
    fn hex_decoder_handles_prefix_and_whitespace() {
        assert_eq!(decode_hex("0x00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(decode_hex("aa bb cc").unwrap(), vec![0xaa, 0xbb, 0xcc]);
        assert!(decode_hex("abc").is_err());
    }
}
