//! Policy manager — whitelist-based allow/deny enforcement.
//!
//! Checks whether a traffic flow is permitted based on configured
//! whitelist rules. Default action is configurable (allow or deny).

use std::net::SocketAddr;

use crate::management::config::{AddressPattern, PolicyAction, PolicyConfig, TrafficClass};

/// Compiled whitelist entry with pre-parsed address patterns.
struct CompiledWhitelistEntry {
    source: AddressPattern,
    destination: AddressPattern,
}

/// Policy enforcement manager.
pub struct PolicyManager {
    default_action: PolicyAction,
    entries: Vec<CompiledWhitelistEntry>,
    /// When true, Safety traffic is also subject to the whitelist/default-deny
    /// instead of being unconditionally allowed (opt-in; default false).
    enforce_policy_on_safety: bool,
}

impl PolicyManager {
    /// Create a new policy manager from config. If config is None, denies all
    /// (except Safety traffic which always passes).
    pub fn new(config: Option<&PolicyConfig>) -> Self {
        match config {
            Some(cfg) => {
                let entries: Vec<CompiledWhitelistEntry> = cfg
                    .whitelist
                    .iter()
                    .filter_map(|entry| {
                        let source = AddressPattern::parse(&entry.source).ok()?;
                        let destination = AddressPattern::parse(&entry.destination).ok()?;
                        Some(CompiledWhitelistEntry {
                            source,
                            destination,
                        })
                    })
                    .collect();
                Self {
                    default_action: cfg.default_action,
                    entries,
                    enforce_policy_on_safety: cfg.enforce_policy_on_safety,
                }
            }
            None => Self {
                default_action: PolicyAction::Deny,
                entries: Vec::new(),
                enforce_policy_on_safety: false,
            },
        }
    }

    /// Check if a flow is allowed by the policy.
    ///
    /// Safety traffic is allowed unconditionally by default (fail-open for
    /// railway availability); set `enforce_policy_on_safety` to also subject it
    /// to the whitelist/default-deny.
    pub fn check_allowed(
        &self,
        src: &SocketAddr,
        dst: &SocketAddr,
        traffic_class: TrafficClass,
    ) -> bool {
        // Safety traffic passes unconditionally unless enforcement is opted in.
        if traffic_class == TrafficClass::Safety && !self.enforce_policy_on_safety {
            return true;
        }

        // If no whitelist entries exist, use default action
        if self.entries.is_empty() {
            return self.default_action == PolicyAction::Allow;
        }

        // Check whitelist: if any entry matches, allow
        for entry in &self.entries {
            if entry.source.matches(src) && entry.destination.matches(dst) {
                return true;
            }
        }

        // No match — use default action
        self.default_action == PolicyAction::Allow
    }

    /// Reload policy from new config.
    pub fn reload(&mut self, config: Option<&PolicyConfig>) {
        let new = PolicyManager::new(config);
        self.default_action = new.default_action;
        self.entries = new.entries;
        self.enforce_policy_on_safety = new.enforce_policy_on_safety;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::config::{PolicyAction, PolicyConfig, WhitelistEntry};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_no_policy_denies_all() {
        let pm = PolicyManager::new(None);
        assert!(!pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Normal
        ));
        // Safety traffic still passes
        assert!(pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Safety
        ));
    }

    /// Build a `PolicyConfig` for tests with the safety-enforcement opt-in off.
    fn policy(default_action: PolicyAction, whitelist: Vec<WhitelistEntry>) -> PolicyConfig {
        PolicyConfig {
            default_action,
            whitelist,
            enforce_policy_on_safety: false,
        }
    }

    #[test]
    fn test_safety_always_allowed() {
        let cfg = policy(PolicyAction::Deny, vec![]);
        let pm = PolicyManager::new(Some(&cfg));
        // Normal traffic denied
        assert!(!pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Normal
        ));
        // Safety always allowed
        assert!(pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Safety
        ));
    }

    #[test]
    fn safety_enforced_when_opted_in() {
        // With the opt-in, Safety traffic is subject to the whitelist/default-deny.
        let cfg = PolicyConfig {
            default_action: PolicyAction::Deny,
            whitelist: vec![],
            enforce_policy_on_safety: true,
        };
        let pm = PolicyManager::new(Some(&cfg));
        // Safety is now DENIED by default-deny.
        assert!(!pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Safety
        ));

        // A whitelisted safety flow still passes under enforcement.
        let cfg = PolicyConfig {
            default_action: PolicyAction::Deny,
            whitelist: vec![WhitelistEntry {
                source: "10.0.0.0/8".into(),
                destination: "any".into(),
            }],
            enforce_policy_on_safety: true,
        };
        let pm = PolicyManager::new(Some(&cfg));
        assert!(pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Safety
        ));
    }

    #[test]
    fn test_whitelist_match() {
        let cfg = policy(
            PolicyAction::Deny,
            vec![WhitelistEntry {
                source: "127.0.0.0/8".into(),
                destination: "any".into(),
            }],
        );
        let pm = PolicyManager::new(Some(&cfg));
        assert!(pm.check_allowed(
            &addr("127.0.0.1:5000"),
            &addr("10.0.0.1:443"),
            TrafficClass::Normal
        ));
        assert!(!pm.check_allowed(
            &addr("192.168.1.1:5000"),
            &addr("10.0.0.1:443"),
            TrafficClass::Normal
        ));
    }

    #[test]
    fn test_deny_default_no_match() {
        let cfg = policy(
            PolicyAction::Deny,
            vec![WhitelistEntry {
                source: "192.168.0.0/16".into(),
                destination: "any".into(),
            }],
        );
        let pm = PolicyManager::new(Some(&cfg));
        assert!(!pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Normal
        ));
    }

    #[test]
    fn test_allow_default_empty_whitelist() {
        let cfg = policy(PolicyAction::Allow, vec![]);
        let pm = PolicyManager::new(Some(&cfg));
        assert!(pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Normal
        ));
    }

    #[test]
    fn test_reload() {
        let cfg1 = policy(PolicyAction::Allow, vec![]);
        let mut pm = PolicyManager::new(Some(&cfg1));
        assert!(pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Normal
        ));

        let cfg2 = policy(PolicyAction::Deny, vec![]);
        pm.reload(Some(&cfg2));
        assert!(!pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Normal
        ));
    }
}
