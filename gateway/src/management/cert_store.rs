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

/// Describe an over-permissive **private key** file mode (KC-01).
///
/// Returns a warning string when the key is readable or writable by group/other
/// (`st_mode & 0o077 != 0`), so a mode-0644 operator key does not load silently
/// readable by a co-located process. Returns `None` for a correctly-restricted
/// key (e.g. `0600`, mirroring the WireGuard key-dir discipline). Never includes
/// the key contents — only the path and the permission bits. Pure for testing.
pub(crate) fn key_perm_warning(path: &Path, mode: u32) -> Option<String> {
    (mode & 0o077 != 0).then(|| {
        format!(
            "private key '{}' is readable/writable by group/other (mode {:o}); \
             restrict it to 0600",
            path.display(),
            mode & 0o7777
        )
    })
}

/// Load a PEM identity (certificate + private key) from disk.
///
/// The certificate file may contain a single leaf certificate (additional
/// chain certificates are ignored here; the peer's CA bundle handles trust).
/// The key file must hold the matching PEM-encoded private key.
pub fn load_identity_pem(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(PKey<Private>, X509), String> {
    // KC-01: warn (never fail) on an over-permissive key file, mirroring the
    // WireGuard 0600 discipline. Externally-provisioned keys must not brick
    // startup, so this is advisory only.
    if let Ok(md) = std::fs::metadata(key_path) {
        use std::os::unix::fs::MetadataExt;
        if let Some(w) = key_perm_warning(key_path, md.mode()) {
            log::warn!("{w}");
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    // KC-01: flag a group/other-readable or -writable key file; stay silent on 0600.
    #[test]
    fn key_perm_warning_flags_over_permissive_modes() {
        let p = Path::new("/tmp/k.pem");
        assert!(key_perm_warning(p, 0o100644).is_some(), "0644 must warn");
        assert!(key_perm_warning(p, 0o100640).is_some(), "0640 must warn");
        assert!(key_perm_warning(p, 0o100604).is_some(), "0604 must warn");
        let w = key_perm_warning(p, 0o100644).unwrap();
        assert!(w.contains("private key"), "{w}");
        assert!(w.contains("644"), "{w}");
    }

    #[test]
    fn key_perm_warning_silent_on_0600() {
        assert!(key_perm_warning(Path::new("/tmp/k.pem"), 0o100600).is_none());
        assert!(key_perm_warning(Path::new("/tmp/k.pem"), 0o100400).is_none());
    }
}
