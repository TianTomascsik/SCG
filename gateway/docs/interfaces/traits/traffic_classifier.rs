//! Traffic Classification interface — REFERENCE STUB (not compiled).
//!
//! Status: PROPOSED. Abstracts `processing/traffic_analyzer.rs` (TrafficAnalyzer)
//! and its `processing/cache.rs` backing so the classification strategy
//! (rule-match today; DPI / identity-based later) is swappable. Output feeds the
//! PolicyEngine and the metrics labels.

// Shared types (gateway crate):
//   TrafficClass -> crate::management::config::TrafficClass (Normal | Safety)

use std::net::SocketAddr;

pub struct Classification {
    pub traffic_id: u64,
    pub app_id: String,
    pub traffic_class: TrafficClass,
}

/// Swappable flow classifier. Constructed from the configured traffic rules.
pub trait TrafficClassifier: Send + Sync {
    /// Classify a flow; `None` => no match (caller keeps the rule default class).
    /// Must be fast and deterministic for a fixed rule set (first-match-wins).
    fn classify(&self, src: &SocketAddr, dst: &SocketAddr) -> Option<Classification>;

    /// Drop cached classifications (config change / rekey).
    fn invalidate(&self);
}
