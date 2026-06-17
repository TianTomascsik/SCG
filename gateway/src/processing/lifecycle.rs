//! Lifecycle orchestrator — handles rekey, cache clearing, config-change events.
//!
//! Receives events from the config watcher and other subsystems,
//! coordinates cache invalidation and policy reloads.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, RwLock};

use super::cache::TrafficCache;
use super::policy::PolicyManager;
use crate::management::config::{ConfigDiff, PolicyConfig};

/// Events sent to the lifecycle orchestrator.
pub enum LifecycleEvent {
    /// Configuration changed — clear caches, reload policies.
    ConfigChanged {
        diff: ConfigDiff,
        new_policy: Option<PolicyConfig>,
    },
}

/// Sender half for lifecycle events.
pub type LifecycleEventSender = mpsc::Sender<LifecycleEvent>;

/// Lifecycle orchestrator — runs in its own thread.
pub struct LifecycleOrchestrator {
    event_rx: mpsc::Receiver<LifecycleEvent>,
    cache: Arc<TrafficCache>,
    policy: Arc<RwLock<PolicyManager>>,
    shutdown: Arc<AtomicBool>,
}

impl LifecycleOrchestrator {
    /// Create a new orchestrator and return it along with the event sender.
    pub fn new(
        cache: Arc<TrafficCache>,
        policy: Arc<RwLock<PolicyManager>>,
        shutdown: Arc<AtomicBool>,
    ) -> (Self, LifecycleEventSender) {
        let (tx, rx) = mpsc::channel();
        let orchestrator = Self {
            event_rx: rx,
            cache,
            policy,
            shutdown,
        };
        (orchestrator, tx)
    }

    /// Run the event loop (blocking). Call from a dedicated thread.
    pub fn run(self) {
        eprintln!("[lifecycle] Orchestrator started");

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Block for up to 500ms waiting for an event
            match self
                .event_rx
                .recv_timeout(std::time::Duration::from_millis(500))
            {
                Ok(event) => match event {
                    LifecycleEvent::ConfigChanged { diff, new_policy } => {
                        eprintln!(
                            "[lifecycle] Config changed: {} added, {} removed",
                            diff.added.len(),
                            diff.removed.len()
                        );
                        // Clear traffic cache — classification may have changed
                        self.cache.clear();
                        eprintln!("[lifecycle] Traffic cache cleared");

                        // Reload policy
                        self.policy.write().unwrap().reload(new_policy.as_ref());
                        eprintln!("[lifecycle] Policy reloaded");
                    }
                },
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    eprintln!("[lifecycle] All senders disconnected, shutting down");
                    break;
                }
            }
        }

        eprintln!("[lifecycle] Orchestrator stopped");
    }
}
