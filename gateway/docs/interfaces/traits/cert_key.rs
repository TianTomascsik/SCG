//! Certificate & Key Management interface — REFERENCE STUB (not compiled).
//!
//! Status: PROPOSED. Replaces the global `get_or_init_cert()` and bespoke
//! per-provider key fields with injected providers, and adds a PSK store.
//! Enables swapping the trust source (self-signed / files / PKI / HSM) and
//! adding key rotation without touching the security engines.

pub enum HandshakeRole {
    Server,
    Client,
}

pub enum TlsProtocol {
    Tls12,
    Tls13,
    Dtls10,
    Dtls12,
}

pub enum KeyError {
    NotFound,
    Expired,
    Revoked,
    Backend(String),
    Io,
}

/// DER-encoded certificate.
pub struct CertificateDer(pub Vec<u8>);
/// DER-encoded private key. Zeroized on drop in a real implementation.
pub struct PrivateKeyDer(pub Vec<u8>);

/// Opaque symmetric secret. Real impl: zeroize on drop, no Debug/Display.
pub struct SecretKey(Vec<u8>);

/// Stable identifier for a named key, e.g. "psk:peerA" or "mac:rule1".
pub struct KeyId(pub String);

pub struct CertKeyPair {
    pub cert_chain: Vec<CertificateDer>, // leaf first
    pub private_key: PrivateKeyDer,
}

pub struct IdentityRequest<'a> {
    pub role: HandshakeRole,
    pub server_name: Option<&'a str>,
    pub protocol: TlsProtocol,
    pub rule: &'a str,
}

pub struct VerifyRequest<'a> {
    pub expected_name: Option<&'a str>,
    pub require_revocation_check: bool,
}

/// X.509 identities + trust anchors + peer verification.
pub trait CertificateProvider: Send + Sync {
    fn identity(&self, req: &IdentityRequest<'_>) -> Result<CertKeyPair, KeyError>;
    fn ca_bundle(&self) -> Result<Vec<CertificateDer>, KeyError>;
    fn verify_peer(&self, chain: &[CertificateDer], req: &VerifyRequest<'_>) -> Result<(), KeyError>;
    fn reload(&self) -> Result<(), KeyError>;
}

/// Pre-shared keys for TLS-PSK / DTLS-PSK and keyed-MAC schemes.
pub trait PreSharedKeyStore: Send + Sync {
    fn psk_by_identity(&self, identity: &[u8]) -> Option<SecretKey>;
    fn client_identity(&self) -> Option<(Vec<u8>, SecretKey)>;
    fn identity_hint(&self) -> Option<Vec<u8>>;
    fn rotate(&self) -> Result<KeyId, KeyError>;
}

/// Generic named secret material (e.g. a keyed-MAC provider's key).
pub trait KeyMaterialProvider: Send + Sync {
    fn key(&self, id: &KeyId) -> Result<SecretKey, KeyError>;
    fn rotate(&self, id: &KeyId) -> Result<KeyId, KeyError>;
}
