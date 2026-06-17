//! Traffic analyzer — classifies connections/datagrams by source/destination.
//!
//! Assigns a traffic class to each flow based on configured traffic rules,
//! using the cache for fast repeated lookups.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::cache::{CacheKey, TrafficCache, TrafficId};
use crate::management::config::{AddressPattern, TrafficClass, TrafficRuleConfig};

/// Result of classifying a traffic flow.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub traffic_id: TrafficId,
    pub app_id: String,
    pub traffic_class: TrafficClass,
}

/// Compiled traffic rule (pre-parsed address patterns).
struct CompiledTrafficRule {
    source: AddressPattern,
    destination: AddressPattern,
    app_id: String,
    traffic_class: TrafficClass,
}

/// Traffic analyzer: classifies source/destination pairs against configured rules.
pub struct TrafficAnalyzer {
    cache: Arc<TrafficCache>,
    compiled_rules: Vec<CompiledTrafficRule>,
    next_id: AtomicU64,
}

impl TrafficAnalyzer {
    /// Create a new analyzer from traffic rule configs and a shared cache.
    pub fn new(rules: &[TrafficRuleConfig], cache: Arc<TrafficCache>) -> Self {
        let compiled_rules: Vec<CompiledTrafficRule> = rules
            .iter()
            .filter_map(|r| {
                let source = AddressPattern::parse(&r.source).ok()?;
                let destination = AddressPattern::parse(&r.destination).ok()?;
                Some(CompiledTrafficRule {
                    source,
                    destination,
                    app_id: r.app_id.clone(),
                    traffic_class: r.traffic_class,
                })
            })
            .collect();

        Self {
            cache,
            compiled_rules,
            next_id: AtomicU64::new(1),
        }
    }

    /// Classify a flow by source and destination address.
    /// Checks cache first; on miss, matches rules and inserts into cache.
    pub fn classify(&self, src: &SocketAddr, dst: &SocketAddr) -> Option<ClassificationResult> {
        let key = CacheKey {
            src: *src,
            dst: *dst,
        };

        // Cache hit
        if let Some(entry) = self.cache.get(&key) {
            return Some(ClassificationResult {
                traffic_id: entry.traffic_id,
                app_id: entry.app_id.clone(),
                traffic_class: entry.traffic_class,
            });
        }

        // Cache miss — match against compiled rules (first match wins)
        for rule in &self.compiled_rules {
            if rule.source.matches(src) && rule.destination.matches(dst) {
                let tid = TrafficId(self.next_id.fetch_add(1, Ordering::Relaxed));
                let result = ClassificationResult {
                    traffic_id: tid,
                    app_id: rule.app_id.clone(),
                    traffic_class: rule.traffic_class,
                };
                self.cache
                    .insert(key, tid, rule.app_id.clone(), rule.traffic_class);
                return Some(result);
            }
        }

        None // No matching rule
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::config::{TrafficClass, TrafficRuleConfig};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_exact_match() {
        let cache = Arc::new(TrafficCache::new(100, 300));
        let rules = vec![TrafficRuleConfig {
            source: "127.0.0.2:5000".into(),
            destination: "any".into(),
            app_id: "etcs_safety".into(),
            traffic_class: TrafficClass::Safety,
        }];
        let analyzer = TrafficAnalyzer::new(&rules, cache);
        let result = analyzer.classify(&addr("127.0.0.2:5000"), &addr("10.0.0.1:443"));
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.app_id, "etcs_safety");
        assert_eq!(r.traffic_class, TrafficClass::Safety);
    }

    #[test]
    fn test_cidr_match() {
        let cache = Arc::new(TrafficCache::new(100, 300));
        let rules = vec![TrafficRuleConfig {
            source: "127.0.0.0/8".into(),
            destination: "any".into(),
            app_id: "local_apps".into(),
            traffic_class: TrafficClass::Normal,
        }];
        let analyzer = TrafficAnalyzer::new(&rules, cache);
        let result = analyzer.classify(&addr("127.0.0.99:1234"), &addr("10.0.0.1:443"));
        assert!(result.is_some());
        assert_eq!(result.unwrap().app_id, "local_apps");
    }

    #[test]
    fn test_no_match() {
        let cache = Arc::new(TrafficCache::new(100, 300));
        let rules = vec![TrafficRuleConfig {
            source: "192.168.1.0/24".into(),
            destination: "any".into(),
            app_id: "lan".into(),
            traffic_class: TrafficClass::Normal,
        }];
        let analyzer = TrafficAnalyzer::new(&rules, cache);
        let result = analyzer.classify(&addr("10.0.0.1:5000"), &addr("10.0.0.2:443"));
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_hit() {
        let cache = Arc::new(TrafficCache::new(100, 300));
        let rules = vec![TrafficRuleConfig {
            source: "any".into(),
            destination: "any".into(),
            app_id: "all".into(),
            traffic_class: TrafficClass::Normal,
        }];
        let analyzer = TrafficAnalyzer::new(&rules, cache);
        let src = addr("127.0.0.1:5000");
        let dst = addr("10.0.0.1:443");
        let r1 = analyzer.classify(&src, &dst).unwrap();
        let r2 = analyzer.classify(&src, &dst).unwrap();
        // Same flow should get same traffic_id (cache hit)
        assert_eq!(r1.traffic_id, r2.traffic_id);
    }

    #[test]
    fn test_first_rule_wins() {
        let cache = Arc::new(TrafficCache::new(100, 300));
        let rules = vec![
            TrafficRuleConfig {
                source: "127.0.0.2:5000".into(),
                destination: "any".into(),
                app_id: "safety_app".into(),
                traffic_class: TrafficClass::Safety,
            },
            TrafficRuleConfig {
                source: "any".into(),
                destination: "any".into(),
                app_id: "catch_all".into(),
                traffic_class: TrafficClass::Normal,
            },
        ];
        let analyzer = TrafficAnalyzer::new(&rules, cache);
        let result = analyzer.classify(&addr("127.0.0.2:5000"), &addr("10.0.0.1:443"));
        assert_eq!(result.unwrap().app_id, "safety_app");
    }
}
