//! Traffic classification cache.
//!
//! Maps (source, destination) address pairs to classification results,
//! avoiding repeated rule matching for known flows. Uses RwLock for
//! concurrent read access and TTL-based expiry.

use std::collections::{HashMap, VecDeque};
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

/// Cache state behind the lock: the entry map plus an insertion-ordered queue
/// used for amortized-O(1) oldest-first eviction.
struct CacheInner {
    map: HashMap<CacheKey, CacheEntry>,
    /// Keys in insertion order. May contain stale entries after a key is
    /// re-inserted (its old queue entry lingers); those are skipped lazily by
    /// comparing the queued `Instant` against the live entry's `inserted_at`.
    order: VecDeque<(CacheKey, Instant)>,
}

/// Thread-safe traffic classification cache with TTL-based expiry.
pub struct TrafficCache {
    inner: RwLock<CacheInner>,
    max_entries: usize,
    ttl: std::time::Duration,
}

impl TrafficCache {
    /// Create a new cache with the given capacity and TTL.
    pub fn new(max_entries: usize, ttl_secs: u64) -> Self {
        Self {
            inner: RwLock::new(CacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
            max_entries,
            ttl: std::time::Duration::from_secs(ttl_secs),
        }
    }

    /// Look up a cached classification. Returns `None` if not found or expired.
    pub fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        let inner = self.inner.read().unwrap();
        if let Some(entry) = inner.map.get(key) {
            if entry.inserted_at.elapsed() < self.ttl {
                return Some(entry.clone());
            }
        }
        None
    }

    /// Insert a classification result into the cache.
    ///
    /// Eviction is amortized O(1): when at capacity, the oldest live entry is
    /// popped from the insertion queue (stale queue records — left behind by a
    /// re-insert of the same key — are skipped without touching the map). The
    /// TTL check in [`get`](Self::get) still filters out expired-but-present
    /// entries, so the queue never needs a full O(n) expiry sweep.
    pub fn insert(
        &self,
        key: CacheKey,
        traffic_id: TrafficId,
        app_id: String,
        traffic_class: TrafficClass,
    ) {
        let now = Instant::now();
        let mut inner = self.inner.write().unwrap();

        // Evict oldest-first until below capacity (unless we are replacing an
        // existing key, which does not grow the map).
        if !inner.map.contains_key(&key) {
            while inner.map.len() >= self.max_entries {
                match inner.order.pop_front() {
                    Some((k, queued_at)) => {
                        // Only remove if this queue record is the live one for k;
                        // a later re-insert would have pushed a newer record.
                        if inner.map.get(&k).map(|e| e.inserted_at) == Some(queued_at) {
                            inner.map.remove(&k);
                        }
                        // else: stale record, already superseded — skip it.
                    }
                    None => break, // queue drained (map and queue diverged) — stop
                }
            }
        }

        inner.map.insert(
            key.clone(),
            CacheEntry {
                traffic_id,
                app_id,
                traffic_class,
                inserted_at: now,
            },
        );
        inner.order.push_back((key, now));
    }

    /// Clear all entries (called by lifecycle orchestrator on rekey/config-change).
    pub fn clear(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.map.clear();
        inner.order.clear();
    }

    /// Number of entries currently in the cache.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().map.len()
    }

    /// Whether the cache currently holds no entries.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().map.is_empty()
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

    fn key(port: u16) -> CacheKey {
        CacheKey {
            src: addr(&format!("127.0.0.1:{port}")),
            dst: addr("10.0.0.1:443"),
        }
    }

    #[test]
    fn test_capacity_eviction() {
        let cache = TrafficCache::new(2, 300);
        let (k1, k2, k3) = (key(1001), key(1002), key(1003));
        cache.insert(k1.clone(), TrafficId(1), "a".into(), TrafficClass::Normal);
        cache.insert(k2.clone(), TrafficId(2), "b".into(), TrafficClass::Normal);
        cache.insert(k3.clone(), TrafficId(3), "c".into(), TrafficClass::Normal);
        // Cache has capacity 2, so one entry was evicted
        assert!(cache.len() <= 2);
        // k3 should be present since it was just inserted
        assert!(cache.get(&k3).is_some());
    }

    // DoS-06: eviction drops the oldest-inserted entry first.
    #[test]
    fn eviction_is_oldest_first() {
        let cache = TrafficCache::new(2, 300);
        let (k1, k2, k3) = (key(1), key(2), key(3));
        cache.insert(k1.clone(), TrafficId(1), "a".into(), TrafficClass::Normal);
        cache.insert(k2.clone(), TrafficId(2), "b".into(), TrafficClass::Normal);
        cache.insert(k3.clone(), TrafficId(3), "c".into(), TrafficClass::Normal);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&k1).is_none(), "oldest (k1) must be evicted");
        assert!(cache.get(&k2).is_some());
        assert!(cache.get(&k3).is_some());
    }

    // DoS-06: capacity is never exceeded under a unique-key flood.
    #[test]
    fn capacity_never_exceeded_under_churn() {
        let cache = TrafficCache::new(8, 300);
        for i in 0..80u16 {
            cache.insert(
                key(i),
                TrafficId(i as u64),
                "x".into(),
                TrafficClass::Normal,
            );
            assert!(cache.len() <= 8, "capacity exceeded at insert {i}");
        }
        assert_eq!(cache.len(), 8);
    }

    // DoS-06: a re-inserted key survives eviction even though its earlier queue
    // record is now stale (it must not be double-evicted).
    #[test]
    fn reinserted_key_survives_stale_queue_entry() {
        let cache = TrafficCache::new(3, 300);
        let (a, b, c, d) = (key(1), key(2), key(3), key(4));
        cache.insert(a.clone(), TrafficId(1), "a".into(), TrafficClass::Normal);
        cache.insert(b.clone(), TrafficId(2), "b".into(), TrafficClass::Normal);
        cache.insert(c.clone(), TrafficId(3), "c".into(), TrafficClass::Normal);
        // Ensure the re-insert gets a distinct Instant from a's first insert.
        std::thread::sleep(std::time::Duration::from_millis(2));
        // Re-insert a → a is now the newest; its old queue record is stale.
        cache.insert(a.clone(), TrafficId(9), "a2".into(), TrafficClass::Normal);
        // Insert d at capacity → the stale a-record is skipped, b (true oldest) evicted.
        cache.insert(d.clone(), TrafficId(4), "d".into(), TrafficClass::Normal);

        assert_eq!(cache.len(), 3);
        assert!(cache.get(&a).is_some(), "re-inserted key a must survive");
        assert!(cache.get(&b).is_none(), "true-oldest key b must be evicted");
        assert!(cache.get(&c).is_some());
        assert!(cache.get(&d).is_some());
    }
}
