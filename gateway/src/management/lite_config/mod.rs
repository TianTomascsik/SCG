//! "Lite" layered-configuration loader.
//!
//! Loads the split `scg.defaults.json` + `scg.user.json` model, enforces
//! integrity (detached Ed25519 signatures + a pinned schema SHA-256),
//! deep-merges the two layers, applies the per-connection template, and maps
//! the result onto the gateway's flat [`GatewayConfig`] / `RuleConfig` model.
//!
//! Integrity is **fail-closed**: the loader returns an error (and the gateway
//! refuses to start) unless both config files verify against the pinned public
//! key and the on-disk schema matches the hash embedded in the signed config.
//!
//! The trust anchor (the signing public key) is supplied *out of band* — via
//! `--config-pubkey` or `<dir>/trust/config-signing.pub.pem` — and never taken
//! from the configuration it is used to verify.

mod integrity;
mod mapping;
mod merge;

use crate::management::config::GatewayConfig;
use log::warn;
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub use mapping::MappedRules;

/// Default file names inside a lite config directory.
pub const DEFAULTS_FILE: &str = "scg.defaults.json";
pub const USER_FILE: &str = "scg.user.json";
pub const SCHEMA_FILE: &str = "scg.lite.schema.json";

/// Pointer to the public-key trust anchor co-located with a config directory.
const TRUST_PUBKEY_REL: &str = "trust/config-signing.pub.pem";

/// Where a lite configuration lives, so a hot-reload can re-run the full
/// verify → merge → map pipeline.
#[derive(Debug, Clone)]
pub struct LiteSource {
    /// Directory holding `scg.defaults.json`, `scg.user.json` and the schema.
    pub dir: PathBuf,
    /// Explicit signing public key (trust anchor); falls back to
    /// `<dir>/trust/config-signing.pub.pem` when `None`.
    pub pubkey: Option<PathBuf>,
}

impl LiteSource {
    /// The file whose mtime the hot-reload watcher polls. Editing the user file
    /// is the common reload trigger; SIGHUP forces a reload regardless.
    pub fn watch_path(&self) -> PathBuf {
        self.dir.join(USER_FILE)
    }
}

/// Load, verify and map a lite configuration directory into a validated
/// [`GatewayConfig`]. Warnings about deferred behaviour are logged.
pub fn load(dir: &Path, pubkey_override: Option<&Path>) -> Result<GatewayConfig, String> {
    let (config, warnings) = load_with_warnings(dir, pubkey_override)?;
    for w in &warnings {
        warn!("[lite-config] {w}");
    }
    Ok(config)
}

/// Like [`load`] but returns the warnings instead of logging them, so the
/// caller can surface them after the logger is initialised.
pub fn load_with_warnings(
    dir: &Path,
    pubkey_override: Option<&Path>,
) -> Result<(GatewayConfig, Vec<String>), String> {
    let defaults_path = dir.join(DEFAULTS_FILE);
    let user_path = dir.join(USER_FILE);
    let schema_path = dir.join(SCHEMA_FILE);

    // ── Parse both layers ───────────────────────────────────────────────────
    // Each file is read from disk exactly once; the raw bytes are kept so the
    // signatures below are verified over the very bytes that were parsed —
    // never a re-read a concurrent writer could race (TOCTOU, TRA #70).
    let (defaults_bytes, defaults) = read_json(&defaults_path)?;
    let (user_bytes, user) = read_json(&user_path)?;

    // Merge + template now; the merged document carries the integrity metadata
    // (schema hash) we need below. Template warnings flag user-set values in
    // fields the data plane does not consume yet (M17).
    let mut merged = merge::deep_merge(defaults, user);
    let template_warnings = merge::apply_templates(&mut merged);

    // ── Integrity (fail-closed, before trusting any mapped content) ──────────
    verify_integrity(
        dir,
        (&defaults_path, &defaults_bytes),
        (&user_path, &user_bytes),
        &schema_path,
        &merged,
        pubkey_override,
    )?;

    // ── Trust-anchor posture advisories (CP-07) ─────────────────────────────
    // Signature verification passed; still surface the weak-default posture so a
    // loud operator can move the anchor out of the writable config dir.
    let mut integrity_warnings = Vec::new();
    if pubkey_override.is_none() {
        integrity_warnings.push(format!(
            "[integrity] config signing key resolved to the co-located fallback '{}' \
             — it lives inside the config directory it authenticates, so an actor who \
             can write that directory can also replace the key and re-sign a tampered \
             config. Prefer an anchor outside the config dir via --config-pubkey.",
            dir.join(TRUST_PUBKEY_REL).display()
        ));
    }
    if let Ok(pubkey_path) = resolve_pubkey(dir, pubkey_override) {
        if let Some(w) = crate::management::config::world_or_group_writable_warning(
            &pubkey_path,
            "config signing public key",
        ) {
            integrity_warnings.push(w);
        }
    }

    // ── Map connections → rules ─────────────────────────────────────────────
    let MappedRules { rules, warnings } = mapping::map_connections_to_rules(&merged)?;
    if rules.is_empty() {
        return Err(
            "no connections could be mapped to data-plane rules (see warnings above)".to_string(),
        );
    }

    // Render the flat classic-config document and validate it through the
    // existing GatewayConfig path.
    let mut root = Map::new();
    root.insert("rules".to_string(), Value::Array(rules));

    // Pass through the policy section so the PolicyManager sees it.
    if let Some(policy) = merged.get("policy") {
        root.insert("policy".to_string(), policy.clone());
    }

    let config = GatewayConfig::from_value(Value::Object(root))?;

    // Surface the trust-anchor advisories first, then template (unconsumed
    // field) warnings, then the mapping warnings.
    integrity_warnings.extend(template_warnings);
    integrity_warnings.extend(warnings);
    Ok((config, integrity_warnings))
}

/// Read and parse a JSON file, returning the raw bytes alongside the parsed
/// value so signature verification can run over exactly what was parsed.
fn read_json(path: &Path) -> Result<(Vec<u8>, Value), String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
    Ok((bytes, value))
}

/// Resolve the signing public key: explicit override first, otherwise the
/// trust anchor co-located with the config directory.
fn resolve_pubkey(dir: &Path, override_: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(p) = override_ {
        if p.exists() {
            return Ok(p.to_path_buf());
        }
        return Err(format!(
            "[integrity] config public key not found: {}",
            p.display()
        ));
    }
    let candidate = dir.join(TRUST_PUBKEY_REL);
    if candidate.exists() {
        return Ok(candidate);
    }
    Err(format!(
        "[integrity] no signing public key: pass --config-pubkey or place {} in the config dir",
        TRUST_PUBKEY_REL
    ))
}

/// Verify detached signatures on both config files (over the already-parsed
/// bytes) and the pinned schema hash.
fn verify_integrity(
    dir: &Path,
    defaults: (&Path, &[u8]),
    user: (&Path, &[u8]),
    schema_path: &Path,
    merged: &Value,
    pubkey_override: Option<&Path>,
) -> Result<(), String> {
    let pubkey_path = resolve_pubkey(dir, pubkey_override)?;
    let pubkey_pem = fs::read(&pubkey_path).map_err(|e| {
        format!(
            "[integrity] cannot read public key {}: {e}",
            pubkey_path.display()
        )
    })?;
    let pubkey =
        integrity::load_ed25519_public_pem(&pubkey_pem).map_err(|e| format!("[integrity] {e}"))?;

    // The signature-file suffix is fixed (L2): honoring
    // `runtime.config_signing.signature_suffix` from the not-yet-verified
    // merged document would let the very input under verification choose
    // where its signatures come from — a bootstrapping inversion. The field
    // is still accepted in configs for schema compatibility but ignored;
    // every in-tree config uses the default.
    for (path, bytes) in [defaults, user] {
        integrity::verify_signature_bytes(bytes, path, integrity::DEFAULT_SIG_SUFFIX, &pubkey)
            .map_err(|e| format!("[integrity] {e}"))?;
    }

    // Pinned schema hash binds the config to a specific schema version.
    let pinned = merged
        .pointer("/runtime/config_manager/schema_sha256")
        .and_then(|v| v.as_str())
        .ok_or("[integrity] runtime.config_manager.schema_sha256 is missing")?;
    let schema_bytes = fs::read(schema_path).map_err(|e| {
        format!(
            "[integrity] cannot read schema {}: {e}",
            schema_path.display()
        )
    })?;
    let actual = integrity::sha256_hex(&schema_bytes).map_err(|e| format!("[integrity] {e}"))?;
    if !pinned.eq_ignore_ascii_case(&actual) {
        return Err(format!(
            "[integrity] schema hash mismatch: pinned {pinned} != actual {actual}"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::pkey::{PKey, Private};
    use openssl::sign::Signer;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_DIR_SEQ: AtomicU32 = AtomicU32::new(0);

    struct Fixture {
        dir: PathBuf,
        pubkey: PathBuf,
        key: PKey<Private>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn write_sig(path: &Path, key: &PKey<Private>) {
        let data = fs::read(path).unwrap();
        let mut signer = Signer::new_without_digest(key).unwrap();
        let sig = signer.sign_oneshot_to_vec(&data).unwrap();
        let b64 = openssl::base64::encode_block(&sig);
        fs::write(
            integrity::sig_path_for(path, integrity::DEFAULT_SIG_SUFFIX),
            b64,
        )
        .unwrap();
    }

    /// A minimal, self-consistent signed fixture: schema, defaults (with the
    /// schema's real hash pinned), user, and detached signatures.
    fn make_fixture() -> Fixture {
        let id = TEST_DIR_SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("scg-lite-test-{}-{}", std::process::id(), id));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Schema content is opaque to the Rust loader (only its hash matters).
        let schema =
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#;
        let schema_path = dir.join(SCHEMA_FILE);
        fs::write(&schema_path, schema).unwrap();
        let schema_hash = integrity::sha256_hex(schema.as_bytes()).unwrap();

        let defaults = serde_json::json!({
            "schema_version": "1.0",
            "defaults": {
                "connection": {
                    "enabled": true,
                    "transparent": false,
                    "default_egress_source": { "ip": "auto", "port": "auto" },
                    "default_out_interface": "eth0"
                },
                "protection": { "default_mode": "full" }
            },
            "runtime": {
                "config_manager": { "schema_sha256": schema_hash },
                "config_signing": { "algorithm": "ed25519", "signature_suffix": ".sig" }
            },
            "crypto": {
                "profiles": [
                    { "profile_id": "tls_client", "protocol": "TLS", "role": "client",
                      "min_version": "1.2", "max_version": "1.3" },
                    { "profile_id": "dtls_server", "protocol": "DTLS", "role": "server",
                      "min_version": "1.2", "max_version": "1.2" },
                    { "profile_id": "routing_only", "protocol": "NONE" }
                ]
            }
        });

        let user = serde_json::json!({
            "apps": [
                { "app_id": "app-a", "default_traffic_class": "safety" },
                { "app_id": "app-b", "default_traffic_class": "normal" }
            ],
            "connections": [
                {
                    "connection_id": "c-tls",
                    "app_id": "app-a",
                    "protection": { "profile_ref": "tls_client", "role": "client", "sni": "peer.example" },
                    "transport": { "protocol": "tcp" },
                    "ingress": { "endpoint": { "ip": "127.0.10.10", "port": 15000, "protocol": "tcp" } },
                    "paths": [ { "path_id": "p", "egress": { "endpoint": { "host": "peer.example", "port": 443, "protocol": "tcp" } } } ]
                },
                {
                    "connection_id": "c-transparent",
                    "app_id": "app-a",
                    "transparent": true,
                    "protection": { "profile_ref": "tls_client", "role": "client" },
                    "transport": { "protocol": "tcp" },
                    "ingress": { "endpoint": { "ip": "127.0.30.10", "port": 30000, "protocol": "tcp" } },
                    "paths": [ { "path_id": "p", "egress": { "endpoint": "auto" } } ]
                },
                {
                    "connection_id": "c-routing",
                    "app_id": "app-b",
                    "protection": { "mode": "routing_only", "profile_ref": "routing_only", "role": "none" },
                    "transport": { "protocol": "tcp" },
                    "ingress": { "endpoint": { "ip": "127.0.10.10", "port": 16000, "protocol": "tcp" } },
                    "paths": [ { "path_id": "p", "egress": { "endpoint": { "host": "plain.example", "port": 8080, "protocol": "tcp" } } } ]
                }
            ]
        });

        let defaults_path = dir.join(DEFAULTS_FILE);
        let user_path = dir.join(USER_FILE);
        fs::write(
            &defaults_path,
            serde_json::to_vec_pretty(&defaults).unwrap(),
        )
        .unwrap();
        fs::write(&user_path, serde_json::to_vec_pretty(&user).unwrap()).unwrap();

        let key = PKey::generate_ed25519().unwrap();
        let pubkey = dir.join("config-signing.pub.pem");
        fs::write(&pubkey, key.public_key_to_pem().unwrap()).unwrap();

        write_sig(&defaults_path, &key);
        write_sig(&user_path, &key);

        Fixture { dir, pubkey, key }
    }

    #[test]
    fn good_signed_config_loads_and_maps() {
        let fx = make_fixture();
        let (config, warnings) = load_with_warnings(&fx.dir, Some(&fx.pubkey)).unwrap();

        // Three enabled connections → three rules.
        assert_eq!(config.rules.len(), 3);

        let tls = config.rules.iter().find(|r| r.name == "c-tls").unwrap();
        assert_eq!(tls.direction.to_string(), "encrypt");
        assert_eq!(tls.listen_addr, "127.0.10.10:15000");
        assert_eq!(tls.upstream_addr, "peer.example:443");
        assert_eq!(tls.effective_security_provider(), "tls");
        assert_eq!(tls.traffic_class.to_string(), "safety");
        assert_eq!(tls.protocol_version.as_deref(), Some("tls1.3"));
        // SNI was carried into provider_params via serde(flatten).
        assert_eq!(
            tls.provider_params.get("sni").and_then(|v| v.as_str()),
            Some("peer.example")
        );

        let transp = config
            .rules
            .iter()
            .find(|r| r.name == "c-transparent")
            .unwrap();
        assert!(transp.transparent);
        assert_eq!(transp.upstream_addr, "auto");

        let routing = config.rules.iter().find(|r| r.name == "c-routing").unwrap();
        assert_eq!(routing.effective_security_provider(), "routing");

        // No deferred features in this fixture → no warnings.
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    // CP-07: resolving the signing key via the co-located fallback (no
    // --config-pubkey) emits a posture advisory; an explicit anchor does not.
    #[test]
    fn colocated_anchor_warns_but_explicit_does_not() {
        let fx = make_fixture();
        // Place the anchor at the co-located default path and load with no override.
        let trust_dir = fx.dir.join("trust");
        fs::create_dir_all(&trust_dir).unwrap();
        fs::copy(&fx.pubkey, trust_dir.join("config-signing.pub.pem")).unwrap();

        let (_cfg, warnings) = load_with_warnings(&fx.dir, None).unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("co-located fallback")),
            "expected a co-located-anchor advisory: {warnings:?}"
        );

        // Explicit anchor → no co-located advisory.
        let (_cfg, warnings) = load_with_warnings(&fx.dir, Some(&fx.pubkey)).unwrap();
        assert!(
            !warnings.iter().any(|w| w.contains("co-located fallback")),
            "explicit anchor must not warn: {warnings:?}"
        );
    }

    #[test]
    fn tampered_user_file_is_rejected() {
        let fx = make_fixture();
        // Mutate the user file *after* signing → signature must fail.
        let user_path = fx.dir.join(USER_FILE);
        let mut content = fs::read_to_string(&user_path).unwrap();
        content.push(' ');
        fs::write(&user_path, content).unwrap();

        let err = load_with_warnings(&fx.dir, Some(&fx.pubkey)).unwrap_err();
        assert!(err.contains("[integrity]"), "got: {err}");
        assert!(err.contains("signature"), "got: {err}");
    }

    #[test]
    fn wrong_public_key_is_rejected() {
        let fx = make_fixture();
        // A different key that never signed these files.
        let other = PKey::generate_ed25519().unwrap();
        let other_pub = fx.dir.join("other.pub.pem");
        fs::write(&other_pub, other.public_key_to_pem().unwrap()).unwrap();

        let err = load_with_warnings(&fx.dir, Some(&other_pub)).unwrap_err();
        assert!(err.contains("[integrity]"), "got: {err}");
    }

    #[test]
    fn schema_hash_mismatch_is_rejected() {
        let fx = make_fixture();
        // Change the schema content (its hash no longer matches the pinned one)
        // and *re-sign nothing* — but we must re-sign defaults/user only if we
        // changed them. Here only the schema file changes, so signatures stay
        // valid and the hash check is what fires.
        let schema_path = fx.dir.join(SCHEMA_FILE);
        fs::write(&schema_path, r#"{"type":"object","changed":true}"#).unwrap();

        let err = load_with_warnings(&fx.dir, Some(&fx.pubkey)).unwrap_err();
        assert!(err.contains("schema hash mismatch"), "got: {err}");
    }

    #[test]
    fn deferred_features_warn_but_do_not_fail() {
        let fx = make_fixture();
        // Append a connection that uses integrity-only + multi-path, then
        // re-sign the user file so integrity still passes.
        let user_path = fx.dir.join(USER_FILE);
        let (_, mut user): (Vec<u8>, Value) = read_json(&user_path).unwrap();
        let conns = user.get_mut("connections").unwrap().as_array_mut().unwrap();
        conns.push(serde_json::json!({
            "connection_id": "c-integrity",
            "app_id": "app-a",
            "protection": { "mode": "integrity_only", "profile_ref": "tls_client", "role": "client" },
            "transport": { "protocol": "tcp" },
            "ingress": { "endpoint": { "ip": "127.0.10.10", "port": 15010, "protocol": "tcp" } },
            "paths": [
                { "path_id": "a", "role": "primary", "priority": 10,
                  "egress": { "endpoint": { "host": "h1.example", "port": 443, "protocol": "tcp" } } },
                { "path_id": "b", "role": "standby", "priority": 20,
                  "egress": { "endpoint": { "host": "h2.example", "port": 443, "protocol": "tcp" } } }
            ]
        }));
        fs::write(&user_path, serde_json::to_vec_pretty(&user).unwrap()).unwrap();
        write_sig(&user_path, &fx.key);

        let (config, warnings) = load_with_warnings(&fx.dir, Some(&fx.pubkey)).unwrap();
        assert_eq!(config.rules.len(), 4);
        assert!(
            warnings.iter().any(|w| w.contains("integrity-only")),
            "expected an integrity-only warning, got: {warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("multi-path")),
            "expected a multi-path warning, got: {warnings:?}"
        );
        // The integrity-only connection maps its primary (lowest-priority) path.
        let integ = config
            .rules
            .iter()
            .find(|r| r.name == "c-integrity")
            .unwrap();
        assert_eq!(integ.upstream_addr, "h1.example:443");
    }

    #[test]
    fn missing_signature_is_rejected() {
        let fx = make_fixture();
        let sig = integrity::sig_path_for(&fx.dir.join(USER_FILE), integrity::DEFAULT_SIG_SUFFIX);
        fs::remove_file(&sig).unwrap();
        let err = load_with_warnings(&fx.dir, Some(&fx.pubkey)).unwrap_err();
        assert!(err.contains("signature file not found"), "got: {err}");
    }

    // H1 / TRA #70: signatures are verified over the exact bytes the loader
    // parsed — never a re-read of the file — so a writer racing the loader
    // cannot swap content between the parse and the verification.
    #[test]
    fn signature_verified_over_parsed_bytes_not_a_reread() {
        let fx = make_fixture();
        let user_path = fx.dir.join(USER_FILE);
        let (parsed_bytes, _value) = read_json(&user_path).unwrap();
        let pubkey_pem = fs::read(&fx.pubkey).unwrap();
        let pubkey = integrity::load_ed25519_public_pem(&pubkey_pem).unwrap();

        // Simulate the TOCTOU race: after the loader read+parsed the bytes,
        // an attacker swaps the on-disk file. Verification runs over the
        // parsed bytes and still passes — proving there is no second read.
        fs::write(&user_path, b"{\"tampered\":true}").unwrap();
        integrity::verify_signature_bytes(
            &parsed_bytes,
            &user_path,
            integrity::DEFAULT_SIG_SUFFIX,
            &pubkey,
        )
        .expect("parsed bytes must verify regardless of on-disk content");

        // Inverse: tampered in-memory bytes fail against the intact
        // signature, whatever the disk says.
        let mut tampered = parsed_bytes.clone();
        tampered[0] ^= 0x01;
        assert!(integrity::verify_signature_bytes(
            &tampered,
            &user_path,
            integrity::DEFAULT_SIG_SUFFIX,
            &pubkey,
        )
        .is_err());
    }
}
