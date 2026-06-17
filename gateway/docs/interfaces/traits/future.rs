//! Forward-looking interfaces — REFERENCE STUB (not compiled).
//!
//! Status: FUTURE. Contracts for planned modules (TODO stubs in
//! `security/stubs.rs`, `management/stubs.rs`, `api/mod.rs`). Where possible a
//! future module REUSES an existing interface (e.g. IPSec/WireGuard/GDOI are new
//! `CryptoProvider`s, OCSP extends `CertificateProvider`, HSM implements the
//! interface-05 providers). Only genuinely new seams are defined below.

// Shared types referenced from interface 05:
//   CertificateDer, SecretKey, KeyId, KeyError

// ─── B. Identity & Access Management (gates the Admin API, interface 10) ───────

pub struct Principal {
    pub subject: String,
    pub roles: Vec<String>,
}

pub enum Credential<'a> {
    MutualTls { cert: &'a [u8] },
    Token(&'a str),
}

pub enum AdminAction {
    ViewStatus,
    ApplyConfig,
    RotateKeys,
    ReloadPolicy,
    FetchAudit,
}

pub enum AuthError {
    Unauthenticated,
    Forbidden,
    Backend(String),
}

pub trait AuthProvider: Send + Sync {
    fn authenticate(&self, credential: &Credential<'_>) -> Result<Principal, AuthError>;
    fn authorize(&self, principal: &Principal, action: AdminAction) -> Result<(), AuthError>;
}

// ─── C. Crypto Policy & Algorithm Manager ──────────────────────────────────────

pub enum ProtocolFamily {
    Tls,
    Dtls,
}

pub enum ProtocolVersion {
    Tls12,
    Tls13,
    Dtls10,
    Dtls12,
}

pub enum CryptoPolicyError {
    Disallowed(String),
}

pub trait CryptoPolicy: Send + Sync {
    fn cipher_allowed(&self, suite: &str) -> bool;
    fn min_protocol(&self, family: ProtocolFamily) -> ProtocolVersion;
    fn fips_mode(&self) -> bool;
    fn validate_rule(
        &self,
        rule: &str,
        provider: &str,
        version: Option<&str>,
    ) -> Result<(), CryptoPolicyError>;
}

// ─── D. Network Namespace & Firewall Manager ───────────────────────────────────

pub enum NetError {
    Command(String),
    Permission,
    Io(String),
}

pub trait NetworkManager: Send + Sync {
    fn ensure_chains(&self) -> Result<(), NetError>;
    fn ensure_routing(&self) -> Result<(), NetError>;
    fn teardown(&self) -> Result<(), NetError>;
}

// ─── E. Certificate Revocation / OCSP (extends interface 05) ────────────────────

pub enum RevocationStatus {
    Good,
    Revoked,
    Unknown,
}

pub trait RevocationChecker: Send + Sync {
    fn status(&self, cert: &CertificateDer) -> Result<RevocationStatus, KeyError>;
}

// ─── F. Storage Manager / HSM (backend for interface 05 providers) ─────────────

pub trait SecretStore: Send + Sync {
    fn get(&self, id: &KeyId) -> Result<SecretKey, KeyError>;
    fn put(&self, id: &KeyId, secret: SecretKey) -> Result<(), KeyError>;
    fn delete(&self, id: &KeyId) -> Result<(), KeyError>;
}
