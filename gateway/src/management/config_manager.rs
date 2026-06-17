//! Hot-reload configuration manager.
//!
//! Provides `SharedConfig` for atomic config swaps and `spawn_config_watcher`
//! for background file-watching and SIGHUP-based reload.

use crate::management::config::{ConfigDiff, GatewayConfig};
use log::{debug, error, info, warn};

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

// ─── Hot-reload support ──────────────────────────────────────────────────────

/// Shared config handle that supports atomic swaps for hot-reload.
/// Existing connections keep running with their original parameters;
/// new connections and new rules use the latest config.
#[derive(Clone)]
pub struct SharedConfig {
    inner: Arc<RwLock<GatewayConfig>>,
    pub config_path: PathBuf,
    last_modified: Arc<RwLock<SystemTime>>,
}

impl SharedConfig {
    /// Create a new SharedConfig from an initial config and its file path.
    pub fn new(config: GatewayConfig, path: &str) -> Self {
        let mtime = fs::metadata(path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        Self {
            inner: Arc::new(RwLock::new(config)),
            config_path: PathBuf::from(path),
            last_modified: Arc::new(RwLock::new(mtime)),
        }
    }

    /// Read the current configuration (snapshot).
    pub fn read(&self) -> GatewayConfig {
        self.inner.read().unwrap().clone()
    }

    /// Check if the config file has been modified since last load.
    pub fn has_changed(&self) -> bool {
        let current_mtime = match fs::metadata(&self.config_path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => return false,
        };
        let last = *self.last_modified.read().unwrap();
        current_mtime > last
    }

    /// Reload config from disk. Returns the diff, or an error string.
    pub fn reload(&self) -> Result<ConfigDiff, String> {
        let path_str = self.config_path.to_string_lossy().to_string();
        let new_config = GatewayConfig::load(&path_str)?;
        let old_config = self.read();
        let diff = old_config.diff(&new_config);

        // Update stored mtime
        if let Ok(mtime) = fs::metadata(&self.config_path).and_then(|m| m.modified()) {
            *self.last_modified.write().unwrap() = mtime;
        }

        // Swap config atomically
        *self.inner.write().unwrap() = new_config;

        Ok(diff)
    }
}

/// Spawn a background thread that watches for config changes via file mtime
/// polling and SIGHUP signal. Calls `on_reload` when changes are detected.
/// Existing connections are NOT affected — only new connections use new rules.
pub fn spawn_config_watcher<F>(
    shared: SharedConfig,
    shutdown: Arc<AtomicBool>,
    on_reload: F,
) -> std::thread::JoinHandle<()>
where
    F: Fn(ConfigDiff) + Send + 'static,
{
    // Register SIGHUP handler
    static SIGHUP_RECEIVED: AtomicBool = AtomicBool::new(false);

    unsafe {
        libc::signal(
            libc::SIGHUP,
            sighup_handler as *const () as libc::sighandler_t,
        );
    }

    extern "C" fn sighup_handler(_sig: libc::c_int) {
        SIGHUP_RECEIVED.store(true, Ordering::SeqCst);
        info!("[gateway] SIGHUP received — reloading configuration...");
    }

    std::thread::Builder::new()
        .name("config-watcher".into())
        .spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(2));

                let should_reload =
                    SIGHUP_RECEIVED.swap(false, Ordering::SeqCst) || shared.has_changed();

                if should_reload {
                    match shared.reload() {
                        Ok(diff) => {
                            if !diff.added.is_empty() || !diff.removed.is_empty() {
                                info!(
                                    "[gateway] Config reloaded: {} added, {} removed, {} unchanged",
                                    diff.added.len(),
                                    diff.removed.len(),
                                    diff.unchanged.len()
                                );
                                for r in &diff.added {
                                    debug!("[gateway]   + rule: \"{}\"", r.name);
                                }
                                for name in &diff.removed {
                                    debug!("[gateway]   - rule: \"{}\"", name);
                                }
                                on_reload(diff);
                            } else {
                                debug!("[gateway] Config reloaded: no rule changes");
                            }
                        }
                        Err(e) => {
                            error!("[gateway] Config reload ERROR: {}", e);
                            warn!("[gateway] Keeping current configuration");
                        }
                    }
                }
            }
        })
        .expect("Failed to spawn config watcher thread")
}
