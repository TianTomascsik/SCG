# 04 — Telemetry & Diagnostics Interface

> **Status:** 🟡 Proposed · **Traits:** `MetricsSink`, `DiagnosticsProvider` ·
> **Abstracts:** [management/telemetry.rs](../../src/management/telemetry.rs)
> (`ConnectionMetrics`, `RuleMetrics`) · **Stub:** [traits/telemetry.rs](traits/telemetry.rs)

## Purpose

Make the gateway's **diagnostic information** (counters, throughput, latency,
connection state, health) consumable by interchangeable backends — periodic log
summaries today, but also Prometheus, statsd, OpenTelemetry, or a gRPC
health/status endpoint — without changing the code paths that *produce* the
numbers.

Two concerns:

- **`MetricsSink`** — a push target for counters/gauges/histograms recorded in
  the hot path.
- **`DiagnosticsProvider`** — a pull source for point-in-time status/health
  snapshots (for the [Management API](10-management-api.md) and health checks).

## Why an interface is needed

Today metrics live in concrete structs `ConnectionMetrics` (per connection) and
`RuleMetrics` (per rule, atomic counters), and are surfaced only by
`RuleMetrics::print_summary()` writing to the `info!` log every ~10s, plus
optional CSV via `bench_log::CsvLogger`. The collection points are good but the
**export path is hard-coded**. An interface separates "record a measurement" from
"where measurements go," so a deployment can add Prometheus scraping without
editing the engines.

## Traits

```rust
pub trait MetricsSink: Send + Sync {
    fn incr_counter(&self, metric: Metric, by: u64, labels: &Labels<'_>);
    fn set_gauge(&self, metric: Metric, value: f64, labels: &Labels<'_>);
    fn observe(&self, metric: Metric, value: f64, labels: &Labels<'_>); // histogram/summary
    fn flush(&self) {}
}

pub trait DiagnosticsProvider: Send + Sync {
    fn snapshot(&self) -> DiagnosticsSnapshot;
    fn health(&self) -> HealthReport;
}
```

## Method contracts

| Method | Contract |
|--------|----------|
| `incr_counter` | Monotonic add. Lock-free / wait-free in the hot path (back it with atomics, like `RuleMetrics` today). |
| `set_gauge` | Set an instantaneous value (e.g. `active_connections`). |
| `observe` | Record a sample for a distribution (e.g. per-message latency ns, handshake ms). Implementations may downsample. |
| `flush` | Optional; push buffered values to a remote backend. |
| `snapshot` | Cheap, consistent-enough point-in-time view across all rules. Used by the management API and CSV export. |
| `health` | Aggregate readiness/liveness derived from the snapshot and module state. |

**Cardinality.** `Metric` is a closed enum and labels are bounded
(rule, direction, provider, traffic_class) to avoid unbounded metric cardinality.

## Data types

```rust
#[derive(Copy, Clone)]
pub enum Metric {
    BytesIn, BytesOut, MessagesRelayed,
    ConnectionsOpened, ConnectionsClosed, ConnectionsActive,
    HandshakeSeconds, MessageLatencySeconds,
    PolicyDenied, DeframeErrors, LogRecordsDropped,
}

pub struct Labels<'a> {
    pub rule: &'a str,
    pub direction: &'a str,   // "encrypt" | "decrypt"
    pub provider: &'a str,    // security_provider name
    pub traffic_class: &'a str, // "normal" | "safety"
}

pub struct DiagnosticsSnapshot {
    pub rules: Vec<RuleStat>,
    pub uptime_secs: u64,
}

pub struct RuleStat {
    pub rule: String,
    pub direction: String,
    pub provider: String,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_messages: u64,
    pub throughput_in_bps: f64,
    pub throughput_out_bps: f64,
    pub latency_p50_ns: Option<u64>,
    pub latency_p99_ns: Option<u64>,
}

pub struct HealthReport {
    pub status: HealthStatus,       // Healthy | Degraded | Unhealthy
    pub detail: String,
    pub checks: Vec<(String, HealthStatus)>,
}

pub enum HealthStatus { Healthy, Degraded, Unhealthy }
```

## Lifecycle & threading

- **Construct:** from config (exporter type, scrape endpoint, sampling).
- **Inject:** `GatewayServices.metrics` / `.diagnostics`. Reachable from engines
  via an `Arc<dyn MetricsSink>` (carried in `RuleContext` when adopted).
- **Run:** `incr_counter`/`observe` called from every connection thread →
  `Send + Sync`, atomic-backed.
- **Reload:** label sets and exporter targets may change on config reload.
- **Shutdown:** `flush()`.

## Mapping from current code

| Today | Interface call |
|-------|----------------|
| `RuleMetrics.total_bytes_in.fetch_add(n)` | `incr_counter(BytesIn, n, labels)` |
| `RuleMetrics.active_connections` inc/dec | `set_gauge(ConnectionsActive, v, labels)` |
| `ConnectionMetrics.record_relay(bytes, latency_ns)` | `incr_counter(MessagesRelayed,1,..)` + `observe(MessageLatencySeconds, ns/1e9, ..)` |
| `handshake_ms` | `observe(HandshakeSeconds, ms/1e3, ..)` |
| `RuleMetrics::print_summary()` | a `MetricsSink` impl that logs `snapshot()` every 10s |
| `log_connection_csv()` | a `MetricsSink`/exporter impl writing CSV |

`now_ns()`, `format_rate()`, `format_bytes()` remain helper utilities.

## Example implementor (skeleton)

```rust
pub struct LogSummarySink { /* atomics per (rule,direction) */ }

impl MetricsSink for LogSummarySink {
    fn incr_counter(&self, m: Metric, by: u64, l: &Labels<'_>) { /* atomic add */ }
    fn set_gauge(&self, m: Metric, v: f64, l: &Labels<'_>) { /* store */ }
    fn observe(&self, m: Metric, v: f64, l: &Labels<'_>) { /* reservoir sample */ }
}
```

## Selection

```json
{ "telemetry": { "sink": "prometheus", "listen": "127.0.0.1:9100",
                 "summary_log_interval_s": 10, "csv": true } }
```

## Conformance checklist

- [ ] Hot-path methods are wait-free (atomic-backed) and never block.
- [ ] Metric/label cardinality is bounded (closed `Metric` enum, fixed labels).
- [ ] `snapshot()` is consistent enough to drive the management API & CSV export.
- [ ] `health()` reflects real module/transport state, not just "process up."
- [ ] Latency percentiles are derived from `observe(MessageLatencySeconds, …)`.
- [ ] `flush()` is honoured on shutdown.
- [ ] Both traits are `Send + Sync`.
