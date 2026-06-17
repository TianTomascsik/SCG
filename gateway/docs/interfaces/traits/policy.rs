//! Policy / Authorization interface — REFERENCE STUB (not compiled).
//!
//! Status: PROPOSED. Abstracts `processing/policy.rs` (PolicyManager) so the
//! authorization model (whitelist today; ABAC / external authz later) is
//! swappable while the enforcement point stays in
//! `RuleContext::classify_and_check_policy`.

// Shared types (gateway crate):
//   TrafficClass -> crate::management::config::TrafficClass (Normal | Safety)
//   PolicyConfig -> crate::management::config::PolicyConfig

use std::net::SocketAddr;

pub struct FlowContext<'a> {
    pub src: &'a SocketAddr,
    pub dst: &'a SocketAddr,
    pub traffic_class: TrafficClass,
    pub rule: &'a str,
    pub app_id: Option<&'a str>,
}

pub enum PolicyDecision {
    Allow,
    Deny { reason: &'static str },
}

pub enum PolicyError {
    InvalidConfig(String),
}

/// Swappable authorization decision engine.
///
/// Invariants every implementation MUST preserve:
///  * TrafficClass::Safety is always allowed.
///  * With no configuration, Normal traffic is denied (fail closed).
pub trait PolicyEngine: Send + Sync {
    /// Decide whether a classified flow may be forwarded. Must be fast and
    /// side-effect free (called per connection / per datagram).
    fn check(&self, flow: &FlowContext<'_>) -> PolicyDecision;

    /// Atomically reload from new configuration.
    fn reload(&self, config: Option<&PolicyConfig>) -> Result<(), PolicyError>;
}
