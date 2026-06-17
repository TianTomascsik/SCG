# 03 — Logging & Audit Interface

> **Status:** 🟡 Proposed · **Traits:** `LogSink`, `AuditSink` ·
> **Abstracts:** `log` + `env_logger` ([main.rs](../../src/main.rs)) ·
> **Stub:** [traits/logging.rs](traits/logging.rs)

## Purpose

Decouple the gateway from a specific logging backend so the **log destination
and format** (stderr, journald, syslog, JSON-to-file, remote collector) can be
swapped without changing call sites, and so **security-relevant audit events**
(policy denials, config changes, handshake failures, key rotations) can be routed
to a separate, tamper-evident sink independent of diagnostic logging.

Two distinct concerns, two interfaces:

- **`LogSink`** — operational/diagnostic logging (the `info!/warn!/error!/debug!`
  stream today).
- **`AuditSink`** — structured security audit events with stronger delivery and
  retention expectations.

## Why an interface is needed

Today logging is direct `log`-crate macros initialized with `env_logger` in
[main.rs](../../src/main.rs). That is fine for a single deployment but is **not
swappable**: there is no audit trail separate from debug logs, no structured
output for SIEM ingestion, and the format/destination are fixed at compile time.
An interface keeps the ergonomic macro call sites while making the backend a
runtime choice.

## Traits

```rust
pub trait LogSink: Send + Sync {
    /// Emit one structured log record. Must be non-blocking in the common path.
    fn log(&self, record: &LogRecord<'_>);
    /// Is a level enabled for a target? Lets call sites skip building records.
    fn enabled(&self, level: LogLevel, target: &str) -> bool { true }
    /// Flush buffered records (called on shutdown and periodically).
    fn flush(&self);
}

pub trait AuditSink: Send + Sync {
    /// Record a security-relevant event. Returns Err if it could not be durably
    /// accepted (caller decides whether to fail closed).
    fn record(&self, event: &AuditEvent<'_>) -> Result<(), AuditError>;
    /// Flush/commit buffered audit events.
    fn flush(&self) -> Result<(), AuditError>;
}
```

## Method contracts

| Method | Contract |
|--------|----------|
| `LogSink::log` | Best-effort, non-blocking in the hot path. Never panics. Dropping under backpressure is acceptable for diagnostic logs (must be counted). |
| `LogSink::enabled` | Cheap; lets the caller avoid formatting when a level is filtered. Default `true`. |
| `LogSink::flush` | Idempotent; called on graceful shutdown. |
| `AuditSink::record` | Should be **durable** before returning `Ok`. On `Err`, the caller decides whether to deny the related action (fail-closed for high-severity events). Must preserve ordering per source where feasible. |
| `AuditSink::flush` | Commit/sync buffered events; called on shutdown and on rotation. |

## Data types

```rust
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel { Error, Warn, Info, Debug, Trace }

pub struct LogRecord<'a> {
    pub level: LogLevel,
    pub target: &'a str,              // module/subsystem, e.g. "gateway", rule name
    pub message: &'a str,
    pub fields: &'a [(&'a str, FieldValue<'a>)], // structured key/values
    pub timestamp_ns: u64,            // CLOCK_MONOTONIC or wall clock per impl
}

pub enum FieldValue<'a> { Str(&'a str), I64(i64), U64(u64), F64(f64), Bool(bool) }

pub struct AuditEvent<'a> {
    pub kind: AuditKind,
    pub severity: LogLevel,
    pub rule: Option<&'a str>,
    pub src: Option<std::net::SocketAddr>,
    pub dst: Option<std::net::SocketAddr>,
    pub detail: &'a str,
    pub fields: &'a [(&'a str, FieldValue<'a>)],
    pub timestamp_ns: u64,
}

pub enum AuditKind {
    PolicyDenied, PolicyAllowed, ConfigChanged, HandshakeFailed,
    KeyRotated, CertLoaded, AuthFailure, ModuleLoaded, Shutdown, Other,
}

pub enum AuditError { Backpressure, Io, Unavailable }
```

## Relationship to the `log` crate

The interface is **complementary**, not a replacement for the call-site
ergonomics. Recommended adoption: provide a `LogSink` adapter that implements
`log::Log`, so existing `info!/warn!/error!/debug!` macros continue to work and
are routed through the selected `LogSink`. New structured call sites can target
`LogSink::log` directly. Audit events always go through `AuditSink`, never the
diagnostic macros.

## Lifecycle & threading

- **Construct:** from config (destination, format, level filter, audit path).
- **Inject:** placed in `GatewayServices.log_sink` / `.audit_sink`; for the
  `log`-macro bridge, also installed as the global logger in `main.rs`.
- **Run:** `log`/`record` invoked from every thread → `Send + Sync` required.
- **Reload:** level filter and (optionally) destination updated on config reload.
- **Shutdown:** `flush()` on both sinks.

## Error handling

`LogSink` is infallible (best-effort, drops are counted and surfaced via
[telemetry](04-telemetry-diagnostics.md)). `AuditSink` is fallible; high-severity
audit failures should be treated as operationally significant (fail-closed for
the guarded action where safety requires it).

## Current implementation (to be wrapped)

- Init: `env_logger::Builder::new().filter_level(level).format_timestamp_millis().init()`
  in [main.rs](../../src/main.rs).
- Call sites: `use log::{info, warn, error, debug};` throughout
  ([processing/mod.rs](../../src/processing/mod.rs),
  [management/config_manager.rs](../../src/management/config_manager.rs), engines).
- No audit sink exists today (policy denials are logged via `warn!`).
- Level comes from `--log-level` CLI or `config.log_level`.

## Example implementor (skeleton)

```rust
pub struct StderrJsonSink { min: LogLevel }

impl LogSink for StderrJsonSink {
    fn log(&self, r: &LogRecord<'_>) {
        if r.level > self.min { return; }
        // serialize r to JSON, write to stderr (best-effort)
    }
    fn enabled(&self, level: LogLevel, _t: &str) -> bool { level <= self.min }
    fn flush(&self) { /* stderr is unbuffered */ }
}
```

## Selection

```json
{ "logging": { "sink": "json-stderr", "level": "info",
               "audit": { "sink": "file", "path": "/var/log/scg/audit.jsonl" } } }
```

## Conformance checklist

- [ ] `LogSink::log` is non-blocking in the hot path and never panics.
- [ ] Dropped diagnostic records are counted and exposed as a metric.
- [ ] `AuditSink::record` is durable before `Ok`, or returns a typed `AuditError`.
- [ ] Audit events are structured and independent of the diagnostic stream.
- [ ] A `log::Log` bridge is provided so existing macros keep working.
- [ ] `flush()` is honoured on shutdown.
- [ ] Both sinks are `Send + Sync`.
