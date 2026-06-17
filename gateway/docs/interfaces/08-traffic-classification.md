# 08 — Traffic Classification Interface

> **Status:** 🟡 Proposed · **Trait:** `TrafficClassifier` ·
> **Abstracts:** [processing/traffic_analyzer.rs](../../src/processing/traffic_analyzer.rs)
> (`TrafficAnalyzer`) + [processing/cache.rs](../../src/processing/cache.rs) ·
> **Stub:** [traits/traffic_classifier.rs](traits/traffic_classifier.rs)

## Purpose

Map a flow (source/destination, and potentially more) to a **classification** —
an application identity and a traffic class (`Normal`/`Safety`) — that downstream
policy and metrics use. Abstracting this allows richer classifiers (DPI, port/CIDR
rules, identity-based) to replace the current rule-matching analyzer without
touching policy or the engines.

## Why an interface is needed

Today [`TrafficAnalyzer`](../../src/processing/traffic_analyzer.rs) is a concrete
struct that matches `(src, dst)` against compiled rules (first match wins) and
caches results in a [`TrafficCache`](../../src/processing/cache.rs) with TTL +
capacity eviction. It is invoked from `RuleContext::classify_and_check_policy`.
The classification *signal* feeds both policy and the safety/normal split, so
making it an interface lets the classification strategy evolve independently.

## Trait

```rust
pub trait TrafficClassifier: Send + Sync {
    /// Classify a flow. `None` means "no rule matched" (caller falls back to the
    /// rule-level default class).
    fn classify(&self, src: &SocketAddr, dst: &SocketAddr) -> Option<Classification>;

    /// Drop any cached classifications (called on config change / rekey).
    fn invalidate(&self);
}
```

## Method contracts

| Method | Contract |
|--------|----------|
| `classify(src, dst)` | Fast; safe to call per connection and per datagram. May cache internally (today: `TrafficCache`). Returns `None` when nothing matches so the caller keeps the rule's default `traffic_class`. |
| `invalidate()` | Clears internal caches. Called by the lifecycle orchestrator on config reload so stale classifications do not persist across a rekey. |

**Determinism.** For a fixed rule set, classification of the same `(src, dst)`
must be stable (first-match-wins ordering is part of the contract today).

## Data types

```rust
pub struct Classification {
    pub traffic_id: u64,           // unique id assigned to the flow
    pub app_id: String,            // application identity
    pub traffic_class: TrafficClass, // Normal | Safety
}
```

`TrafficClass` is defined in [config.rs](../../src/management/config.rs). The
classifier is constructed from `&[TrafficRuleConfig]`.

## Lifecycle & threading

- **Construct:** from traffic rules + a shared cache handle.
- **Inject:** `GatewayServices.classifier`; reachable from engines via
  `RuleContext` (today `traffic_analyzer: Option<Arc<TrafficAnalyzer>>`).
- **Run:** `classify` from every connection thread → `Send + Sync`.
- **Reload:** `invalidate()` on config change
  ([processing/lifecycle.rs](../../src/processing/lifecycle.rs) calls
  `TrafficCache::clear`).

## Relationship to other interfaces

```text
classify(src,dst) ─▶ Classification ─▶ PolicyEngine.check(FlowContext{class, app_id})
                                   └──▶ MetricsSink labels (traffic_class)
```

Classification is the **input** to [policy](07-policy.md) and a **label source**
for [telemetry](04-telemetry-diagnostics.md).

## Mapping from current code

| Today | Interface |
|-------|-----------|
| `TrafficAnalyzer::classify(src, dst) -> Option<ClassificationResult>` | `classify(src, dst) -> Option<Classification>` |
| `ClassificationResult { traffic_id, app_id, traffic_class }` | `Classification { … }` (same fields) |
| `TrafficCache::clear()` on lifecycle event | `invalidate()` |

## Example implementor (skeleton)

```rust
pub struct RuleClassifier { /* compiled rules + cache */ }

impl TrafficClassifier for RuleClassifier {
    fn classify(&self, src: &SocketAddr, dst: &SocketAddr) -> Option<Classification> {
        // cache lookup; on miss, first-match-wins over compiled rules; insert
        None
    }
    fn invalidate(&self) { /* clear cache */ }
}
```

## Selection

```json
{ "traffic_rules": [
    { "match": { "source": "10.0.0.0/8", "destination": "10.9.0.0/16" },
      "app_id": "etcs", "traffic_class": "safety" } ],
  "cache": { "max_entries": 100000, "ttl_s": 300 } }
```

## Conformance checklist

- [ ] `classify` is fast and safe to call per datagram.
- [ ] `None` is returned on no-match (caller keeps rule default class).
- [ ] First-match-wins (or a documented, deterministic) ordering is used.
- [ ] `invalidate()` fully clears cached results on reload/rekey.
- [ ] Output feeds policy and metrics labels consistently.
- [ ] Trait is `Send + Sync`.
