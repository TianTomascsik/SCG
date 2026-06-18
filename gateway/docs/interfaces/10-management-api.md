# 10 — Management & Admin API Interface

> **Status:** 🟡 Proposed · **Traits:** `ManagementApi`, `AdminApi`,
> `HealthCheck` · **Abstracts:** [api/mod.rs](../../src/api/mod.rs) (TODO stub) ·
> **Stub:** [traits/management_api.rs](traits/management_api.rs)

## Purpose

Provide a stable, **transport-agnostic** surface for runtime observability and
control of a running gateway — status queries, rule management, health, and
privileged admin actions (certificate/key rotation, policy updates, audit
retrieval) — so the *wire protocol* (gRPC, REST, a Unix-socket CLI) can be swapped
without changing the gateway core, and so access can be gated by authentication.

## Why an interface is needed

[api/mod.rs](../../src/api/mod.rs) is currently a set of TODO comments describing
a planned gRPC API and gRPC Admin API. Defining the interface now (a) pins down
the contract the core must satisfy, (b) lets the management surface be exposed
over different transports, and (c) separates **read/operate** (`ManagementApi`)
from **privileged admin** (`AdminApi`) so the latter can require authentication.

This interface is a **consumer** of the other interfaces — it reads
[diagnostics](04-telemetry-diagnostics.md), drives
[config](09-configuration.md)/[policy](07-policy.md) reloads, and triggers
[key/cert](05-cert-key-management.md) rotation — rather than implementing them.

## Traits

```rust
pub trait ManagementApi: Send + Sync {
    fn status(&self) -> GatewayStatus;
    fn list_rules(&self) -> Vec<RuleStatus>;
    fn get_rule(&self, name: &str) -> Option<RuleStatus>;
    fn metrics_snapshot(&self) -> DiagnosticsSnapshot;   // from interface 04
}

pub trait AdminApi: Send + Sync {
    fn apply_config(&self, cfg: &str) -> Result<ApplyOutcome, AdminError>;
    fn reload(&self) -> Result<ApplyOutcome, AdminError>;
    fn rotate_keys(&self, scope: KeyScope) -> Result<(), AdminError>;
    fn reload_policy(&self) -> Result<(), AdminError>;
    fn fetch_audit(&self, since_ns: u64, limit: usize) -> Result<Vec<AuditRecord>, AdminError>;
}

pub trait HealthCheck: Send + Sync {
    fn liveness(&self) -> HealthStatus;     // process is running
    fn readiness(&self) -> HealthReport;    // ready to serve (from interface 04)
}
```

## Method contracts

| Method | Contract |
|--------|----------|
| `status` / `list_rules` / `get_rule` | Read-only, cheap, non-blocking. Reflect current runtime state (active rules, connection counts, throughput) derived from [diagnostics](04-telemetry-diagnostics.md). |
| `metrics_snapshot` | Delegates to `DiagnosticsProvider::snapshot()`. |
| `apply_config(cfg)` | Validate first (same rules as [config](09-configuration.md)); on success compute a diff and apply via the normal hot-reload path. Atomic: either fully applied or rejected. |
| `reload` | Re-read the active `ConfigSource` and apply. |
| `rotate_keys(scope)` | Trigger [cert/key](05-cert-key-management.md) rotation for the given scope; overlap epochs so live handshakes are unaffected. |
| `reload_policy` | Reload the [policy engine](07-policy.md). |
| `fetch_audit(since, limit)` | Page audit records from the [audit sink](03-logging.md). |
| `liveness` / `readiness` | Standard health probes for orchestrators. Liveness = process alive; readiness = listeners bound and dependencies healthy. |

**Authentication & authorization.** Every `AdminApi` call is privileged and MUST
be authenticated/authorized (the planned IAM, see
[11 — Future interfaces](11-future-interfaces.md)). `ManagementApi` read methods
may be exposed read-only. The trait layer is transport-agnostic; the binding
layer (gRPC/REST) enforces authN/authZ before dispatching.

## Data types

```rust
pub struct GatewayStatus {
    pub version: String,
    pub uptime_secs: u64,
    pub rule_count: usize,
    pub active_connections: u64,
    pub health: HealthStatus,        // from interface 04
}

pub struct RuleStatus {
    pub name: String,
    pub direction: String,
    pub provider: String,
    pub listen_addr: String,
    pub upstream_addr: String,
    pub active_connections: u64,
    pub total_connections: u64,
}

pub struct ApplyOutcome { pub added: Vec<String>, pub removed: Vec<String>, pub unchanged: Vec<String> }
pub enum KeyScope { All, Certificates, Psk, Material(String) }
pub struct AuditRecord { pub timestamp_ns: u64, pub kind: String, pub detail: String }
pub enum AdminError { Unauthorized, InvalidConfig(String), Unavailable(String), Io(String) }
```

`DiagnosticsSnapshot`, `HealthReport`, `HealthStatus` come from
[04 — Telemetry & Diagnostics](04-telemetry-diagnostics.md).

## Lifecycle & threading

- **Construct:** a binding (gRPC server, REST server, UDS CLI) is given handles to
  the management/admin/health implementations.
- **Inject:** the implementations are thin adapters over `GatewayServices`
  (diagnostics, config source, policy, key providers).
- **Run:** served on a dedicated listener thread/runtime, separate from data-plane
  rule threads. `Send + Sync`.
- **Shutdown:** the binding stops with the gateway.

## Mapping from the planned stub

| [api/mod.rs](../../src/api/mod.rs) TODO | Interface |
|------|-----------|
| "Runtime status queries (active rules, connection counts, throughput)" | `ManagementApi::status` / `list_rules` / `metrics_snapshot` |
| "Rule management (add/remove/modify without config file)" | `AdminApi::apply_config` |
| "Health check endpoint for orchestration" | `HealthCheck` |
| "Certificate management (upload, rotate, revoke)" | `AdminApi::rotate_keys` (+ cert provider) |
| "Security policy updates" | `AdminApi::reload_policy` |
| "Audit log retrieval" | `AdminApi::fetch_audit` |
| "Integration with IAM for authenticated access" | authN/authZ at the binding layer |

## Example implementor (skeleton)

```rust
pub struct CoreManagement { services: Arc<GatewayServices> }

impl ManagementApi for CoreManagement {
    fn status(&self) -> GatewayStatus { /* derive from diagnostics */ todo!() }
    fn list_rules(&self) -> Vec<RuleStatus> { todo!() }
    fn get_rule(&self, _name: &str) -> Option<RuleStatus> { None }
    fn metrics_snapshot(&self) -> DiagnosticsSnapshot { self.services.diagnostics.snapshot() }
}
```

## Selection

```json
{ "api": { "bind": "127.0.0.1:50051", "protocol": "grpc",
           "admin": { "enabled": true, "auth": "mtls" } } }
```

## Conformance checklist

- [ ] Read methods are non-blocking and reflect live state.
- [ ] `apply_config` validates before applying and is atomic (reuses hot-reload).
- [ ] Every `AdminApi` method is authenticated/authorized at the binding layer.
- [ ] `rotate_keys` overlaps epochs so live handshakes are unaffected.
- [ ] Health probes distinguish liveness from readiness.
- [ ] Served off the data path (separate listener) and is `Send + Sync`.

---

## Implemented — Local-interface provisioning (gRPC over UDS)

The shipped management surface is the **`scg.management.v1.ManagementApi`** gRPC
service ([crates/scg-proto](../../../crates/scg-proto)), served on a dedicated
thread off the data path ([src/api/grpc.rs](../../src/api/grpc.rs)). It is the
control plane through which co-located apps obtain **per-app, per-traffic-class**
UDS/SHM endpoints (see [Architecture.md](../../Architecture.md) → *Local
Interfaces*).

### Transport & caller identity

- **Default:** gRPC-over-UDS at `api.uds_path` (`/run/scg/management.sock`). The
  Unix socket gives a kernel-verified `SO_PEERCRED` → `CallerCred { uid, gid,
  pid }` with no network exposure.
- **Optional:** `api.tcp_addr` enables a TCP listener for remote admin.

### RPCs

| RPC | Contract |
|---|---|
| `CreateUdsEndpoint(app_id, traffic_class, direction)` | Authorize the caller against the matching uds rule template, enforce the per-uid quota + rate limit, mint a **single-use 256-bit token**, spawn the endpoint, and return `{ socket_path, token, endpoint_id }`. |
| `CreateShmEndpoint(app_id, traffic_class, direction, ring_capacity)` | As above but returns `{ control_socket_path, token, endpoint_id, cap_c2g, cap_g2c, notify }`; the client connects the control socket, presents the token, and receives the memfd + eventfd descriptors via `SCM_RIGHTS`. |
| `CloseEndpoint(endpoint_id)` | Only the owning uid may close; tears the endpoint down (create-or-replace also tears down the previous endpoint for the same slot). |
| `Health()` | `{ healthy, version }`. |
| `ListRules()` | Snapshot of the configured pipeline rules. |

### Token / HELLO flow

The token returned by a `Create*` RPC is presented as the **first data-plane
frame** (`HELLO`) on the endpoint/control socket. `authenticate_peer`
re-checks `SO_PEERCRED` (peer uid must equal the endpoint owner and be in
`allowed_uids`; pid checked when `allowed_pids` is set), compares the token in
**constant time**, and **consumes it under a lock** so a racing connection cannot
reuse it. Tokens never appear in logs (Debug masks them as `***`).

### Errors & audit

| Condition | gRPC status |
|---|---|
| Unknown `app_id`/class/direction | `NOT_FOUND` |
| uid/pid not authorized | `PERMISSION_DENIED` |
| Per-uid quota or rate limit exceeded | `RESOURCE_EXHAUSTED` |
| `decrypt` direction (v1) | `UNIMPLEMENTED` |

Every denial emits one greppable audit line:
`AUDIT deny op=… uid=… pid=… app_id=…: reason`. Resource guards are configured
via `api.max_endpoints_per_uid` and `api.create_rate_per_min` (see
[09 — Configuration](09-configuration.md)).
