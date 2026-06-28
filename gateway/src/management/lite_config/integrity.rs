//! Config integrity primitives: detached Ed25519 signatures and the pinned
//! schema SHA-256, implemented on top of the `openssl` crate already used by
//! the gateway (no extra dependencies).
//!
//! These checks are *fail-closed*: the loader refuses to proceed unless every
//! signed file verifies against the pinned public key and the on-disk schema
//! hashes to the value embedded in the (signed) configuration.

use openssl::base64;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{Id, PKey, Public};
use openssl::sign::Verifier;
use std::fs;
use std::path::{Path, PathBuf};

/// Default suffix for a detached signature file (`scg.user.json` ->
/// `scg.user.json.sig`). Matches `runtime.config_signing.signature_suffix`.
pub const DEFAULT_SIG_SUFFIX: &str = ".sig";

/// Path of the detached signature that accompanies `path`.
pub fn sig_path_for(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Load a PEM-encoded Ed25519 public key, rejecting any other key type.
pub fn load_ed25519_public_pem(pem: &[u8]) -> Result<PKey<Public>, String> {
    let pkey =
        PKey::public_key_from_pem(pem).map_err(|e| format!("cannot load public key: {e}"))?;
    if pkey.id() != Id::ED25519 {
        return Err("public key is not an Ed25519 key".to_string());
    }
    Ok(pkey)
}

/// Verify a detached Ed25519 signature over `msg`.
pub fn verify_ed25519(pubkey: &PKey<Public>, msg: &[u8], sig: &[u8]) -> Result<(), String> {
    // Ed25519 is a "one-shot, no pre-hash" scheme: the verifier is created
    // without a digest and the whole message is passed to `verify_oneshot`.
    let mut verifier =
        Verifier::new_without_digest(pubkey).map_err(|e| format!("verifier init failed: {e}"))?;
    let ok = verifier
        .verify_oneshot(sig, msg)
        .map_err(|e| format!("verify error: {e}"))?;
    if ok {
        Ok(())
    } else {
        Err("signature check FAILED".to_string())
    }
}

/// Verify the detached signature next to `file` against `pubkey`.
///
/// Returns `Ok(())` on success or a human-readable error describing the first
/// problem (missing signature, malformed base64, or a failed check).
pub fn verify_signature(file: &Path, suffix: &str, pubkey: &PKey<Public>) -> Result<(), String> {
    let data = fs::read(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let sig_file = sig_path_for(file, suffix);
    let sig_text = fs::read_to_string(&sig_file)
        .map_err(|e| format!("signature file not found: {}: {e}", sig_file.display()))?;
    let sig = base64::decode_block(sig_text.trim())
        .map_err(|e| format!("signature {} is not valid base64: {e}", sig_file.display()))?;
    verify_ed25519(pubkey, &data, &sig).map_err(|e| {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.display().to_string());
        format!("{e} for {name}")
    })
}

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> Result<String, String> {
    let digest = hash(MessageDigest::sha256(), data).map_err(|e| format!("sha256 failed: {e}"))?;
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::sign::Signer;

    fn sign(pkey: &PKey<openssl::pkey::Private>, msg: &[u8]) -> Vec<u8> {
        let mut signer = Signer::new_without_digest(pkey).unwrap();
        signer.sign_oneshot_to_vec(msg).unwrap()
    }

    #[test]
    fn sha256_matches_known_vector() {
        // SHA-256("abc")
        assert_eq!(
            sha256_hex(b"abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn ed25519_roundtrip_accepts_good_and_rejects_tampered() {
        let key = PKey::generate_ed25519().unwrap();
        let pub_pem = key.public_key_to_pem().unwrap();
        let pubkey = load_ed25519_public_pem(&pub_pem).unwrap();

        let msg = b"the quick brown fox";
        let sig = sign(&key, msg);
        assert!(verify_ed25519(&pubkey, msg, &sig).is_ok());

        // Tampered message must fail.
        assert!(verify_ed25519(&pubkey, b"the quick brown FOX", &sig).is_err());
        // Tampered signature must fail.
        let mut bad = sig.clone();
        bad[0] ^= 0xff;
        assert!(verify_ed25519(&pubkey, msg, &bad).is_err());
    }

    #[test]
    fn non_ed25519_key_is_rejected() {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let pem = pkey.public_key_to_pem().unwrap();
        assert!(load_ed25519_public_pem(&pem).is_err());
    }
}
