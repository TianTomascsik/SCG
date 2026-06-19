//! Certificate & Key Store.
//!
//! Currently provides a self-signed RSA-2048 certificate cached for the
//! gateway's lifetime. Future: persistent cert/key storage, PKI integration,
//! and key rotation.

use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::X509;

use std::path::Path;
use std::sync::OnceLock;

// ─── Cached self-signed certificate ──────────────────────────────────────────

type CachedCert = (PKey<openssl::pkey::Private>, X509);
static CACHED_CERT: OnceLock<CachedCert> = OnceLock::new();

pub fn get_or_init_cert() -> Result<&'static CachedCert, openssl::error::ErrorStack> {
    if let Some(cached) = CACHED_CERT.get() {
        return Ok(cached);
    }
    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;
    let mut name = openssl::x509::X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "gateway")?;
    let name = name.build();
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    builder.set_not_before(not_before.as_ref())?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_after(not_after.as_ref())?;
    builder.sign(&pkey, MessageDigest::sha256())?;
    let cert = (pkey, builder.build());
    let _ = CACHED_CERT.set(cert);
    Ok(CACHED_CERT.get().unwrap())
}

// ─── PEM identity loading ────────────────────────────────────────────────────

/// Load a PEM identity (certificate + private key) from disk.
///
/// The certificate file may contain a single leaf certificate (additional
/// chain certificates are ignored here; the peer's CA bundle handles trust).
/// The key file must hold the matching PEM-encoded private key.
pub fn load_identity_pem(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(PKey<Private>, X509), String> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| format!("failed to read cert_path '{}': {}", cert_path.display(), e))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| format!("failed to read key_path '{}': {}", key_path.display(), e))?;

    let cert = X509::from_pem(&cert_pem)
        .map_err(|e| format!("invalid certificate in '{}': {}", cert_path.display(), e))?;
    let pkey = PKey::private_key_from_pem(&key_pem)
        .map_err(|e| format!("invalid private key in '{}': {}", key_path.display(), e))?;

    Ok((pkey, cert))
}

/// Generate a self-signed ECDSA (secp256r1 / P-256) certificate.
///
/// Used by integrity-only and ECDSA test fixtures where an EC key pair is
/// required (e.g. `ECDHE-ECDSA-*` cipher suites).
pub fn generate_self_signed_ecdsa(
    common_name: &str,
) -> Result<(PKey<Private>, X509), openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec)?;

    let mut name = openssl::x509::X509NameBuilder::new()?;
    name.append_entry_by_text("CN", common_name)?;
    let name = name.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
    builder.sign(&pkey, MessageDigest::sha256())?;

    Ok((pkey, builder.build()))
}
