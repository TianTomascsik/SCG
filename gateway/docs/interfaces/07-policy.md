# 07 — Policy / Authorization Interface

> **Status:** 🟡 Proposed · **Trait:** `PolicyEngine` ·
> **Abstracts:** [processing/policy.rs](../../src/processing/policy.rs)
> (`PolicyManager`) · **Stub:** [traits/policy.rs](traits/policy.rs)

## Purpose

Decide whether a given traffic flow is **allowed to be forwarded**. Abstracting
this lets the authorization model be swapped — the current whitelist, or a future
ABAC/label-based engine, or an external authorization service — without changing
where the gateway enforces the decision.

## Why an interface is needed

Today [`PolicyManager`](../../src/processing/policy.rs) is a concrete struct with
a fixed whitelist model (`check_allowed(src, dst, traffic_class) -> bool`,
`reload(config)`), wrapped in `Arc<RwLock<PolicyManager>>` and consulted via
`RuleContext::classify_and_check_policy`. The **enforcement points are already
correct**; only the *decision logic* is fixed. An interface keeps the enforcement
points and makes the decision pluggable.

## Trait

```rust
pub trait PolicyEngine: Send + Sync {
    /// Decide whether a classified flow may be forwarded.
    fn check(&self, flow: &FlowContext<'_>) -> PolicyDecision;
    /// Atomically reload the policy from new configuration.
    fn reload(&self, config: Option<&PolicyConfig>) -> Result<(), PolicyError>;
}
```

## Method contracts

| Method | Contract |
|--------|----------|
| `check(flow)` | Pure and fast (called per new connection / per datagram). No blocking I/O. Must be deterministic for a given policy version. |
| `reload(config)` | Swap policy atomically; concurrent `check` calls see either the old or new policy, never a partial state (today: `Arc<RwLock<…>>`). |

**Safety invariant (must be preserved).** `TrafficClass::Safety` flows are
**always allowed**, independent of policy — matching the current
`PolicyManager::check_allowed`. Any replacement engine must honour this.

**Fail-closed default.** With no configuration, the default is **deny** for
`Normal` traffic (today `PolicyManager::new(None)` denies all non-safety flows).

## Data types

```rust
pub struct FlowContext<'a> {
    pub src: &'a std::net::SocketAddr,
    pub dst: &'a std::net::SocketAddr,
    pub traffic_class: TrafficClass,   // Normal | Safety
    pub rule: &'a str,
    pub app_id: Option<&'a str>,       // from classification, when available
}

pub enum PolicyDecision {
    Allow,
    Deny { reason: &'static str },
}

pub enum PolicyError { InvalidConfig(String) }
```

`TrafficClass` and `PolicyConfig` are defined in
[config.rs](../../src/management/config.rs).

## Lifecycle & threading

- **Construct:** from `Option<&PolicyConfig>`.
- **Inject:** `GatewayServices.policy`; reachable from engines through
  `RuleContext` (today `policy_manager: Option<Arc<RwLock<PolicyManager>>>`).
- **Run:** `check` from every connection thread → `Send + Sync`.
- **Reload:** driven by the lifecycle orchestrator on config change
  ([processing/lifecycle.rs](../../src/processing/lifecycle.rs)).

## Relationship to enforcement

The gateway calls the policy engine from one place —
`RuleContext::classify_and_check_policy` — after classification and before
forwarding. A denied decision drops the flow and should emit a
`PolicyDenied` [audit event](03-logging.md) and increment the `PolicyDenied`
[metric](04-telemetry-diagnostics.md).

## Mapping from current code

| Today | Interface |
|-------|-----------|
| `PolicyManager::check_allowed(src, dst, class) -> bool` | `check(FlowContext) -> PolicyDecision` |
| `PolicyManager::reload(Option<&PolicyConfig>)` | `reload(Option<&PolicyConfig>) -> Result<(), PolicyError>` |
| Safety always passes; empty ⇒ default action | preserved as invariants above |

## Example implementor (skeleton)

```rust
pub struct WhitelistPolicy { /* compiled entries + default action */ }

impl PolicyEngine for WhitelistPolicy {
    fn check(&self, flow: &FlowContext<'_>) -> PolicyDecision {
        if flow.traffic_class == TrafficClass::Safety { return PolicyDecision::Allow; }
        // match src/dst against whitelist; else default action
        PolicyDecision::Deny { reason: "not in whitelist" }
    }
    fn reload(&self, _config: Option<&PolicyConfig>) -> Result<(), PolicyError> { Ok(()) }
}
```

## Selection

```json
{ "policy": { "engine": "whitelist", "default_action": "deny",
              "whitelist": [ { "source": "10.0.0.0/8", "destination": "10.1.0.0/16:443" } ] } }
```

## Conformance checklist

- [ ] `Safety` traffic is always allowed.
- [ ] No configuration ⇒ deny `Normal` traffic (fail closed).
- [ ] `check` is non-blocking, deterministic, and side-effect free.
- [ ] `reload` is atomic w.r.t. concurrent `check` calls.
- [ ] Denials emit an audit event and a metric.
- [ ] Trait is `Send + Sync`.
