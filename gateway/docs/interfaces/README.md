# SCG Module Interface Specifications

This folder defines and documents the **module interfaces** of the Secure
Communication Gateway (SCG). The goal of these interfaces is to let modules be
**interchanged, updated, and upgraded with minimal development overhead**: a
module is anything that can be swapped behind a stable contract (a security
engine, a framing protocol, a logger, a metrics sink, a key source, a transport,
a policy engine, a config source, a management API, etc.).

> **Status of this document set.** Two interfaces (`CryptoProvider` and
> `AppProtocolProvider`/`FramingSession`) already exist in the codebase and are
> documented **as-built**. The remaining interfaces are **proposed** contracts
> that capture today's concrete implementations behind a trait so they become
> swappable. Each spec is explicitly labelled with its status.

---

## How these specs are organized

| # | Interface | Category | Status | Current implementation | Selector |
|---|-----------|----------|--------|------------------------|----------|
| [01](01-crypto-provider.md) | **Crypto Provider** | Security engine | ✅ As-built | [security/provider.rs](../../src/security/provider.rs) | `security_provider` |
| [02](02-protocol-provider.md) | **Protocol Provider** (+ Framing Session) | App framing | ✅ As-built | [app_protocols/provider.rs](../../src/app_protocols/provider.rs) | `app_protocol` |
| [03](03-logging.md) | **Logging / Audit** | Observability | 🟡 Proposed | `log` + `env_logger` ([main.rs](../../src/main.rs)) | `log_sink` (new) |
| [04](04-telemetry-diagnostics.md) | **Telemetry / Diagnostics** | Observability | 🟡 Proposed | [management/telemetry.rs](../../src/management/telemetry.rs) | `metrics_sink` (new) |
| [05](05-cert-key-management.md) | **Certificate & Key Management** (incl. PSK) | Security material | 🟡 Proposed | [management/cert_store.rs](../../src/management/cert_store.rs) | `cert_provider` / `psk_store` (new) |
| [06](06-transport.md) | **Transport** (TCP/UDP/UDS/SHM) | Networking | 🟡 Proposed | [networking/](../../src/networking/) + [interfaces/tproxy.rs](../../src/interfaces/tproxy.rs) | `listen_proto` / `transport` |
| [07](07-policy.md) | **Policy / Authorization** | Control plane | 🟡 Proposed | [processing/policy.rs](../../src/processing/policy.rs) | `policy.engine` (new) |
| [08](08-traffic-classification.md) | **Traffic Classification** | Control plane | 🟡 Proposed | [processing/traffic_analyzer.rs](../../src/processing/traffic_analyzer.rs) | `classifier` (new) |
| [09](09-configuration.md) | **Configuration Source** | Control plane | 🟡 Proposed | [management/config.rs](../../src/management/config.rs) + [config_manager.rs](../../src/management/config_manager.rs) | `config_source` (new) |
| [10](10-management-api.md) | **Management / Admin API** (+ Health) | Control plane | 🟡 Proposed | [api/grpc.rs](../../src/api/grpc.rs) — endpoint provisioning **built**; broader admin surface proposed | `api` |
| [11](11-future-interfaces.md) | **Forward-looking interfaces** | Mixed | 🔵 Future | — | — |

**Status legend:** ✅ As-built (trait exists today) · 🟡 Proposed (contract for an
existing concrete implementation) · 🔵 Future (planned module, no implementation yet).

Reference Rust trait stubs for every interface live in [`traits/`](traits/).
**They are illustrative and are not part of the cargo build** (see
[below](#about-the-trait-stubs)).

---

## Design principles

Every SCG module interface follows the same set of rules so that implementations
stay interchangeable:

1. **Trait-based contracts.** An interface is a Rust `trait`. Implementations are
   structs that `impl` the trait. Callers depend on `&dyn Trait` /
   `Box<dyn Trait>` / `Arc<dyn Trait>`, never on a concrete type.
2. **`Send + Sync`.** The gateway is multi-threaded (thread-per-rule plus an
   elastic connection pool). Shared interfaces require `Send + Sync` so a single
   instance can be shared across threads via `Arc`. Per-connection *session*
   objects (e.g. `FramingSession`) require only `Send`.
3. **Synchronous, blocking model.** The gateway uses blocking I/O with a
   thread-per-rule architecture (no async runtime). Interfaces are synchronous to
   match. "Run" methods may block for the lifetime of a rule; short methods must
   not block unexpectedly. (If an async variant is ever needed, it should be a
   separate trait, not a breaking change to these.)
4. **Registration by name (factory pattern).** Swappable engines are registered
   in a registry and selected at runtime by a string `name()` that matches a
   config field. This is the existing [`ProviderRegistry`](../../src/processing/registry.rs)
   pattern; new interface categories generalize it (see
   [Composition root](#composition-root--dependency-injection)).
5. **Dependency injection, not ownership.** Modules receive their dependencies;
   they do not reach out for global singletons. For example a security engine is
   *given* its certificate/key material through a `CertificateProvider` rather
   than calling a global `get_or_init_cert()`. This is what makes the key source
   (file, generated, PKI, HSM) swappable without touching the engine.
6. **Explicit, typed error contracts.** Each interface declares its error type.
   Existing code uses `Result<(), String>` (crypto run methods) and
   `io::Result<...>` (framing); new interfaces define dedicated error enums so a
   failing module degrades predictably.
7. **Stability & versioning.** Interfaces are versioned (see
   [Stability policy](#stability--versioning-policy)). Backwards-compatible
   growth uses default methods or new traits; breaking changes bump the major
   version of the interface set.
8. **Conformance is testable.** Each spec ends with a **conformance checklist**
   an implementor can verify against. The intent is that a new module can be
   dropped in and validated independently of the rest of the gateway.

---

## Shared types glossary

These types appear across multiple interfaces. They are defined in the gateway
crate today; the interface specs reference them by name.

| Type | Defined in | Meaning |
|------|-----------|---------|
| `Direction` | [config.rs](../../src/management/config.rs) | `Encrypt` (plain→encrypted) or `Decrypt` (encrypted→plain). |
| `Proto` | [config.rs](../../src/management/config.rs) | Transport selector: `Tcp` or `Udp`. |
| `TlsMode` | [config.rs](../../src/management/config.rs) | Legacy security selector (`Tls`/`Ktls`/`Dtls`); superseded by `security_provider`. |
| `TrafficClass` | [config.rs](../../src/management/config.rs) | `Normal` or `Safety`; `Safety` always bypasses policy denial. |
| `ProviderMode` | [security/provider.rs](../../src/security/provider.rs) | A supported `(Direction, Proto)` pair for a crypto provider. |
| `RuleConfig` | [config.rs](../../src/management/config.rs) | One forwarding rule from `gateway.json`. |
| `GatewayConfig` | [config.rs](../../src/management/config.rs) | Whole parsed configuration (globals + rules + policy + traffic rules). |
| `ConfigDiff` | [config.rs](../../src/management/config.rs) | `{ added, removed, unchanged }` rule sets produced on hot-reload. |
| `PolicyConfig` | [config.rs](../../src/management/config.rs) | Whitelist + default action for the policy engine. |
| `RuleContext` | [processing/mod.rs](../../src/processing/mod.rs) | The fully-resolved per-rule context handed to a crypto provider. Bundles addresses, protocols, security settings, metrics, the shutdown flag, the connection pool, and optional policy/classifier handles. |
| `RuleMetrics` / `ConnectionMetrics` | [telemetry.rs](../../src/management/telemetry.rs) | Aggregate (per-rule) and per-connection counters. |
| `ConnectionPool` | [security/conn_pool.rs](../../src/security/conn_pool.rs) | Elastic worker pool used to run per-connection handlers. |

`RuleContext` is the **primary data carrier** between the gateway core and a
security engine. When a new dependency must reach engines (a metrics sink, a key
provider, a transport factory), the recommended path is to add an
`Arc<dyn Trait>` field to `RuleContext` rather than a global.

---

## Composition root & dependency injection

Today the gateway wires modules together in [`lib.rs::run`](../../src/lib.rs)
(`main.rs` is a thin wrapper): it
builds a [`ProviderRegistry`](../../src/processing/registry.rs), registers the
built-in crypto and protocol providers, freezes it with `into_arc()`, and passes
the `Arc<ProviderRegistry>` to the rule runner.

```text
gateway.json ──load & validate──▶ lib.rs::run ──register──▶ ProviderRegistry
                                                              │ into_arc() (freeze)
                                                              ▼
                                                   Arc<ProviderRegistry>  ──▶ each rule thread
```

To make **all** module categories swappable (not just crypto/protocol), the
specs propose generalizing this into a single **composition root** assembled in
`lib.rs::run` and carried alongside the registry:

```rust
// PROPOSED — see individual specs for each trait.
pub struct GatewayServices {
    pub providers:   Arc<ProviderRegistry>,        // crypto + app-protocol (exists today)
    pub log_sink:    Arc<dyn LogSink>,             // 03
    pub audit_sink:  Arc<dyn AuditSink>,           // 03
    pub metrics:     Arc<dyn MetricsSink>,         // 04
    pub diagnostics: Arc<dyn DiagnosticsProvider>, // 04
    pub certs:       Arc<dyn CertificateProvider>, // 05
    pub psk:         Arc<dyn PreSharedKeyStore>,   // 05
    pub transport:   Arc<dyn TransportFactory>,    // 06
    pub policy:      Arc<dyn PolicyEngine>,         // 07
    pub classifier:  Arc<dyn TrafficClassifier>,    // 08
    pub config_src:  Arc<dyn ConfigSource>,         // 09
}
```

The composition root is the **only** place that names concrete implementations.
Swapping a module = changing one line where its `Arc::new(...)` is constructed.
Everything downstream depends on the trait object.

---

## Lifecycle model

Interfaces distinguish four lifecycle phases. Not every interface uses all four;
each spec states which apply.

| Phase | Meaning | Typical method shape |
|-------|---------|----------------------|
| **Construct** | Build the implementation from its own config. Cheap, no I/O side effects beyond opening handles. | `fn new(cfg) -> Result<Self, E>` (concrete; not on the trait) |
| **Register / inject** | Hand the instance to the composition root / registry. | `registry.register_*` / `Arc::new` into `GatewayServices` |
| **Run / serve** | Do the work. May block for the rule lifetime (`run_encrypt`) or be invoked per event (`record`, `check_allowed`, `classify`). | `fn run_*(&self, ctx)` / `fn <verb>(&self, ...)` |
| **Reload / shutdown** | React to hot-reload (`reload(new_cfg)`) and cooperative shutdown (observe `ctx.shutdown: Arc<AtomicBool>`). | `fn reload(&self, cfg)` / observe shutdown flag |

**Cooperative shutdown** is uniform across the gateway: long-running methods poll
an `Arc<AtomicBool>` shutdown flag (carried in `RuleContext`) and return when it
is set. New blocking interfaces must honour the same flag.

---

## Error handling conventions

- **Engine "run" methods** return `Result<(), String>` today (human-readable,
  logged once per rule). New blocking run-style methods should follow suit or use
  a dedicated error enum that implements `Display`.
- **Per-datagram / per-call methods** return `io::Result<...>` when they wrap I/O
  (framing, transport), or a dedicated error enum otherwise.
- **Control-plane lookups** (find a provider, classify a flow, check a policy)
  return `Option<...>` or `bool` for "no match / denied" and reserve `Result` for
  genuine faults.
- A module must **fail safe**: on internal error it should refuse traffic
  (drop/deny) rather than forwarding unprotected data. Safety-class traffic
  handling is governed by the [policy spec](07-policy.md).

---

## Stability & versioning policy

- The interface set is versioned as a whole: **`scg-interfaces` v0.1** (initial).
- **Additive** changes (new default method, new optional trait) are minor bumps.
- **Breaking** changes (method signature change, removed method) are major bumps
  and require updating all implementors.
- An implementation declares the interface version it targets in its docs/header.
  The composition root may refuse to load a module built against an incompatible
  major version.

---

## How to add or swap a module

The generic recipe (each spec has interface-specific steps):

1. **Implement the trait** in a new module under the relevant `src/` subtree
   (e.g. a new crypto engine under `src/security/providers/`).
2. **Honour the contract** in the spec: thread-safety bounds, lifecycle, error
   behaviour, and the conformance checklist.
3. **Register / inject** it at the composition root in `lib.rs::run` (add a
   `register_*` call, or set the corresponding `GatewayServices` field).
4. **Select it** via the config selector named in the catalog table (e.g.
   `"security_provider": "my-engine"`).
5. **Validate** against the conformance checklist and the gateway's existing
   tests/benches.

No other module needs to change — that is the point of the interface boundary.

---

## About the trait stubs

The [`traits/`](traits/) subfolder contains one Rust file per interface with the
proposed trait definitions and supporting types.

- They are **reference material**, not compiled. Cargo only builds `src/` for the
  `gateway` crate, so files under `docs/` are ignored by the build.
- For interfaces marked **As-built**, the stub mirrors the real trait in `src/`
  (the real definition is authoritative).
- For **Proposed**/**Future** interfaces, the stub is a design proposal. Some
  reference gateway-internal types (e.g. `RuleContext`) via comments and may not
  compile standalone; that is intentional — they document the contract.

When a proposed interface is adopted, move its stub into `src/`, wire it into the
composition root, and flip its status here to **As-built**.
