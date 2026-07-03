//! Hot-reload configuration manager.
//!
//! Provides `SharedConfig` for atomic config swaps and `spawn_config_watcher`
//! for background file-watching and SIGHUP-based reload.

use crate::management::config::{ConfigDiff, GatewayConfig};
use crate::management::lite_config::{self, LiteSource};
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
    /// When set, reloads go through the layered lite-config pipeline (re-running
    /// signature + schema-hash verification) instead of reading a single JSON
    /// file. `config_path` then points at the watched user file.
    lite: Option<LiteSource>,
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
            lite: None,
            last_modified: Arc::new(RwLock::new(mtime)),
        }
    }

    /// Create a SharedConfig backed by a layered lite-config directory. The
    /// watcher polls `source.watch_path()` (the user file) for changes, and
    /// each reload re-runs the full verify → merge → map pipeline.
    pub fn new_lite(config: GatewayConfig, source: LiteSource) -> Self {
        let watch = source.watch_path();
        let mtime = fs::metadata(&watch)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        Self {
            inner: Arc::new(RwLock::new(config)),
            config_path: watch,
            lite: Some(source),
            last_modified: Arc::new(RwLock::new(mtime)),
        }
    }

    /// Read the current configuration (snapshot).
    pub fn read(&self) -> GatewayConfig {
        // Recover the guard even if a previous holder panicked (poison): the
        // config snapshot itself is still consistent, and we must not turn a
        // poisoned lock into a hard panic on the read path.
        self.inner.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Check if the config file has been modified since last load.
    pub fn has_changed(&self) -> bool {
        let current_mtime = match fs::metadata(&self.config_path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => return false,
        };
        let last = *self.last_modified.read().unwrap_or_else(|e| e.into_inner());
        current_mtime > last
    }

    /// Reload config from disk. Returns the diff, or an error string.
    pub fn reload(&self) -> Result<ConfigDiff, String> {
        let new_config = match &self.lite {
            Some(source) => {
                // Re-run the full layered pipeline (signatures + schema hash are
                // re-verified; a tampered or unsigned edit is rejected and the
                // current config is kept).
                lite_config::load(&source.dir, source.pubkey.as_deref())?
            }
            None => {
                let path_str = self.config_path.to_string_lossy().to_string();
                GatewayConfig::load(&path_str)?
            }
        };
        let old_config = self.read();
        let diff = old_config.diff(&new_config);

        // Advisory-only (M-6/CP-08): surface preflight findings *introduced by
        // this reload*. Diffing against the pre-reload advisories suppresses
        // steady-state noise and false positives from live-system probes — e.g.
        // the port-conflict check binds each running rule's port, so without the
        // diff every reload would spam "port in use". A loosening reload is thus
        // recorded, but the reload itself is never blocked.
        let (old_w, old_e) = old_config.preflight_check();
        let (new_w, new_e) = new_config.preflight_check();
        for w in new_advisories(&old_w, &new_w) {
            warn!("[reload advisory] {w}");
        }
        for e in new_advisories(&old_e, &new_e) {
            error!("[reload advisory (error-severity)] {e}");
        }

        // Update stored mtime
        if let Ok(mtime) = fs::metadata(&self.config_path).and_then(|m| m.modified()) {
            *self
                .last_modified
                .write()
                .unwrap_or_else(|e| e.into_inner()) = mtime;
        }

        // Swap config atomically
        *self.inner.write().unwrap_or_else(|e| e.into_inner()) = new_config;

        Ok(diff)
    }
}

/// Advisories present in `new` but not in `old` (order-preserving set difference).
/// Used to log only the preflight findings a reload newly introduces (CP-08).
fn new_advisories(old: &[String], new: &[String]) -> Vec<String> {
    new.iter().filter(|w| !old.contains(w)).cloned().collect()
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

    // SAFETY: `libc::signal` is an FFI call; `libc::SIGHUP` is a valid signal
    // number and `sighup_handler` is a real `extern "C"` function with the
    // required `fn(c_int)` ABI, cast to the `sighandler_t` the call expects. The
    // handler has `'static` lifetime (a top-level `fn`) so it stays valid for the
    // whole process, and it only touches the `'static` `SIGHUP_RECEIVED` atomic,
    // so installing it introduces no dangling pointer or data race.
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
                            if !diff.added.is_empty()
                                || !diff.removed.is_empty()
                                || !diff.changed.is_empty()
                            {
                                info!(
                                    "[gateway] Config reloaded: {} added, {} removed, {} changed, {} unchanged",
                                    diff.added.len(),
                                    diff.removed.len(),
                                    diff.changed.len(),
                                    diff.unchanged.len()
                                );
                                for r in &diff.added {
                                    debug!("[gateway]   + rule: \"{}\"", r.name);
                                }
                                for name in &diff.removed {
                                    debug!("[gateway]   - rule: \"{}\"", name);
                                }
                                for r in &diff.changed {
                                    debug!("[gateway]   ~ rule: \"{}\"", r.name);
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

#[cfg(test)]
mod tests {
    use super::new_advisories;

    // CP-08: only advisories the reload *introduces* are reported.
    #[test]
    fn new_advisories_reports_only_introduced() {
        let old = vec!["a".to_string(), "b".to_string()];
        let new = vec!["b".to_string(), "c".to_string(), "d".to_string()];
        assert_eq!(
            new_advisories(&old, &new),
            vec!["c".to_string(), "d".to_string()]
        );
    }

    #[test]
    fn new_advisories_empty_when_unchanged() {
        let same = vec!["x".to_string(), "y".to_string()];
        assert!(new_advisories(&same, &same).is_empty());
        // A reload that *removes* an advisory introduces nothing new.
        assert!(new_advisories(&same, &["x".to_string()]).is_empty());
    }
}
