//! Configuration Source interface — REFERENCE STUB (not compiled).
//!
//! Status: PROPOSED. Abstracts config acquisition + change detection (today:
//! `GatewayConfig::load` + `SharedConfig`/`spawn_config_watcher` over a JSON
//! file) so the source (file / env / etcd / control-plane push) is swappable.
//! The consumption types (GatewayConfig, ConfigDiff) are reused unchanged.

// Shared types (gateway crate):
//   GatewayConfig -> crate::management::config::GatewayConfig
//   ConfigDiff    -> crate::management::config::ConfigDiff { added, removed, unchanged }

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub enum ConfigError {
    Io(String),
    Parse(String),
    Validation(String),
    Unavailable(String),
}

/// Dropping this handle stops the associated watcher.
pub struct WatchHandle;

/// Swappable configuration source + change watcher.
pub trait ConfigSource: Send + Sync {
    /// Human-readable identity (e.g. "file:/etc/scg.json").
    fn describe(&self) -> String;

    /// Load and VALIDATE the full configuration now.
    fn load(&self) -> Result<GatewayConfig, ConfigError>;

    /// Watch for changes; invoke `on_change` with a diff vs. the last served
    /// config. Invalid new config must be rejected (keep last good). Honours
    /// `shutdown`; dropping the returned handle stops watching.
    fn watch(
        &self,
        shutdown: Arc<AtomicBool>,
        on_change: Box<dyn Fn(ConfigDiff) + Send>,
    ) -> Result<WatchHandle, ConfigError>;
}
