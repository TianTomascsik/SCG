//! Every shipped example config must parse and validate.
//!
//! Guards the documented example configurations (the per-capability files in
//! `examples/configs/` plus the top-level `gateway.example.json`) against schema
//! drift: each one is run through the real `GatewayConfig::load`, so a renamed
//! field or a newly-rejected combination fails CI instead of a deployment.

use std::path::{Path, PathBuf};

use gateway::management::config::GatewayConfig;

/// Absolute path to the gateway crate root (`SCG/gateway`).
fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Load + validate one config file, attaching the path to any failure.
fn assert_loads(path: &Path) {
    let cfg = GatewayConfig::load(path.to_str().unwrap())
        .unwrap_or_else(|e| panic!("example config {} failed to load: {e}", path.display()));
    assert!(
        !cfg.rules.is_empty(),
        "example config {} has no rules",
        path.display()
    );
}

#[test]
fn all_example_configs_load() {
    let dir = manifest_dir().join("examples/configs");
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).expect("examples/configs directory exists") {
        let path = entry.expect("read dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            assert_loads(&path);
            count += 1;
        }
    }
    assert!(
        count >= 8,
        "expected at least 8 example configs in {}, found {count}",
        dir.display()
    );
}

#[test]
fn top_level_gateway_example_loads() {
    let path = manifest_dir().join("gateway.example.json");
    assert_loads(&path);
}
