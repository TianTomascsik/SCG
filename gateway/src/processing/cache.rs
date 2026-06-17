//! Traffic classification cache.
//!
//! Maps (source, destination) address pairs to classification results,
//! avoiding repeated rule matching for known flows. Uses RwLock for
//! concurrent read access and TTL-based expiry.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::Instant;

use crate::management::config::TrafficClass;

/// Unique traffic identifier (hash of source+destination key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrafficId(pub u64);

/// Cache key: a (source, destination) address pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// Cached classification entry.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub traffic_id: TrafficId,
    pub app_id: String,
    pub traffic_class: TrafficClass,
    inserted_at: Instant,
}

/// Thread-safe traffic classification cache with TTL-based expiry.
pub struct TrafficCache {
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
    max_entries: usize,
    ttl: std::time::Duration,
}

impl TrafficCache {
    /// Create a new cache with the given capacity and TTL.
    pub fn new(max_entries: usize, ttl_secs: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries,
            ttl: std::time::Duration::from_secs(ttl_secs),
        }
    }

    /// Look up a cached classification. Returns `None` if not found or expired.
    pub fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        let entries = self.entries.read().unwrap();
        if let Some(entry) = entries.get(key) {
            if entry.inserted_at.elapsed() < self.ttl {
                return Some(entry.clone());
            }
        }
        None
    }

    /// Insert a classification result into the cache.
    pub fn insert(
        &self,
        key: CacheKey,
        traffic_id: TrafficId,
        app_id: String,
        traffic_class: TrafficClass,
    ) {
        let mut entries = self.entries.write().unwrap();
        // Evict expired entries if at capacity
        if entries.len() >= self.max_entries {
            let now = Instant::now();
            entries.retain(|_, v| now.duration_since(v.inserted_at) < self.ttl);
        }
        // If still at capacity after eviction, drop oldest
        if entries.len() >= self.max_entries {
            if let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, v)| v.inserted_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
            }
        }
        entries.insert(
            key,
            CacheEntry {
                traffic_id,
                app_id,
                traffic_class,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Clear all entries (called by lifecycle orchestrator on rekey/config-change).
    pub fn clear(&self) {
        self.entries.write().unwrap().clear();
    }

    /// Number of entries currently in the cache.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_insert_and_get() {
        let cache = TrafficCache::new(100, 300);
        let key = CacheKey {
            src: addr("127.0.0.1:5000"),
            dst: addr("10.0.0.1:443"),
        };
        cache.insert(
            key.clone(),
            TrafficId(1),
            "app1".into(),
            TrafficClass::Safety,
        );

        let entry = cache.get(&key).unwrap();
        assert_eq!(entry.traffic_id, TrafficId(1));
        assert_eq!(entry.app_id, "app1");
        assert_eq!(entry.traffic_class, TrafficClass::Safety);
    }

    #[test]
    fn test_miss_returns_none() {
        let cache = TrafficCache::new(100, 300);
        let key = CacheKey {
            src: addr("127.0.0.1:5000"),
            dst: addr("10.0.0.1:443"),
        };
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_ttl_expiry() {
        let cache = TrafficCache::new(100, 0); // 0-second TTL = immediate expiry
        let key = CacheKey {
            src: addr("127.0.0.1:5000"),
            dst: addr("10.0.0.1:443"),
        };
        cache.insert(
            key.clone(),
            TrafficId(1),
            "app1".into(),
            TrafficClass::Normal,
        );
        // With 0s TTL, entry is expired immediately
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_clear() {
        let cache = TrafficCache::new(100, 300);
        let key = CacheKey {
            src: addr("127.0.0.1:5000"),
            dst: addr("10.0.0.1:443"),
        };
        cache.insert(key, TrafficId(1), "app1".into(), TrafficClass::Normal);
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_capacity_eviction() {
        let cache = TrafficCache::new(2, 300);
        let k1 = CacheKey {
            src: addr("127.0.0.1:1001"),
            dst: addr("10.0.0.1:443"),
        };
        let k2 = CacheKey {
            src: addr("127.0.0.1:1002"),
            dst: addr("10.0.0.1:443"),
        };
        let k3 = CacheKey {
            src: addr("127.0.0.1:1003"),
            dst: addr("10.0.0.1:443"),
        };
        cache.insert(k1.clone(), TrafficId(1), "a".into(), TrafficClass::Normal);
        cache.insert(k2.clone(), TrafficId(2), "b".into(), TrafficClass::Normal);
        cache.insert(k3.clone(), TrafficId(3), "c".into(), TrafficClass::Normal);
        // Cache has capacity 2, so one entry was evicted
        assert!(cache.len() <= 2);
        // k3 should be present since it was just inserted
        assert!(cache.get(&k3).is_some());
    }
}
