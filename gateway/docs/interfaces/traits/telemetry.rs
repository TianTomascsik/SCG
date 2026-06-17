//! Telemetry & Diagnostics interface — REFERENCE STUB (not compiled).
//!
//! Status: PROPOSED. Abstracts the concrete metrics in
//! `gateway/src/management/telemetry.rs` (ConnectionMetrics / RuleMetrics) so the
//! export path (log summary, Prometheus, statsd, CSV, gRPC health) is swappable.

/// Closed set of metrics (keeps cardinality bounded).
#[derive(Copy, Clone)]
pub enum Metric {
    BytesIn,
    BytesOut,
    MessagesRelayed,
    ConnectionsOpened,
    ConnectionsClosed,
    ConnectionsActive,
    HandshakeSeconds,
    MessageLatencySeconds,
    PolicyDenied,
    DeframeErrors,
    LogRecordsDropped,
}

/// Bounded label set attached to each measurement.
pub struct Labels<'a> {
    pub rule: &'a str,
    pub direction: &'a str,
    pub provider: &'a str,
    pub traffic_class: &'a str,
}

/// Push target for hot-path measurements. Implementations must be wait-free.
pub trait MetricsSink: Send + Sync {
    fn incr_counter(&self, metric: Metric, by: u64, labels: &Labels<'_>);
    fn set_gauge(&self, metric: Metric, value: f64, labels: &Labels<'_>);
    fn observe(&self, metric: Metric, value: f64, labels: &Labels<'_>);
    fn flush(&self) {}
}

// ─── Diagnostics (pull) ────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
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

pub struct DiagnosticsSnapshot {
    pub rules: Vec<RuleStat>,
    pub uptime_secs: u64,
}

pub struct HealthReport {
    pub status: HealthStatus,
    pub detail: String,
    pub checks: Vec<(String, HealthStatus)>,
}

/// Pull source for point-in-time status/health (management API, health checks).
pub trait DiagnosticsProvider: Send + Sync {
    fn snapshot(&self) -> DiagnosticsSnapshot;
    fn health(&self) -> HealthReport;
}
