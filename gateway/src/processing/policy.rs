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
                }
            }
            None => Self {
                default_action: PolicyAction::Deny,
                entries: Vec::new(),
            },
        }
    }

    /// Check if a flow is allowed by the policy.
    /// Safety traffic is always allowed regardless of policy.
    pub fn check_allowed(
        &self,
        src: &SocketAddr,
        dst: &SocketAddr,
        traffic_class: TrafficClass,
    ) -> bool {
        // Safety traffic always passes
        if traffic_class == TrafficClass::Safety {
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

    #[test]
    fn test_safety_always_allowed() {
        let cfg = PolicyConfig {
            default_action: PolicyAction::Deny,
            whitelist: vec![],
        };
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
    fn test_whitelist_match() {
        let cfg = PolicyConfig {
            default_action: PolicyAction::Deny,
            whitelist: vec![WhitelistEntry {
                source: "127.0.0.0/8".into(),
                destination: "any".into(),
            }],
        };
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
        let cfg = PolicyConfig {
            default_action: PolicyAction::Deny,
            whitelist: vec![WhitelistEntry {
                source: "192.168.0.0/16".into(),
                destination: "any".into(),
            }],
        };
        let pm = PolicyManager::new(Some(&cfg));
        assert!(!pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Normal
        ));
    }

    #[test]
    fn test_allow_default_empty_whitelist() {
        let cfg = PolicyConfig {
            default_action: PolicyAction::Allow,
            whitelist: vec![],
        };
        let pm = PolicyManager::new(Some(&cfg));
        assert!(pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Normal
        ));
    }

    #[test]
    fn test_reload() {
        let cfg1 = PolicyConfig {
            default_action: PolicyAction::Allow,
            whitelist: vec![],
        };
        let mut pm = PolicyManager::new(Some(&cfg1));
        assert!(pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Normal
        ));

        let cfg2 = PolicyConfig {
            default_action: PolicyAction::Deny,
            whitelist: vec![],
        };
        pm.reload(Some(&cfg2));
        assert!(!pm.check_allowed(
            &addr("10.0.0.1:1234"),
            &addr("10.0.0.2:443"),
            TrafficClass::Normal
        ));
    }
}
