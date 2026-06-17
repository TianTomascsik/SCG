//! Certificate & Key Store.
//!
//! Currently provides a self-signed RSA-2048 certificate cached for the
//! gateway's lifetime. Future: persistent cert/key storage, PKI integration,
//! and key rotation.

use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::X509;

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
