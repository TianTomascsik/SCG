//! Metrics collection and reporting for the gateway proxy.
//!
//! Collects per-rule throughput and latency statistics, periodically prints
//! summaries, and flushes CSV logs on shutdown via `bench_log::CsvLogger`.

use bench_log::{compute_latency_stats, CsvLogger, CsvRow};
use log::info;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ─── Per-connection metrics ──────────────────────────────────────────────────

/// Metrics collected for a single proxied connection/session.
///
/// When constructed with a `RuleMetrics` reference, bytes/messages are
/// published to the rule-level atomics in real time so that periodic
/// `print_summary()` reflects live traffic from active connections.
/// Batch size for flushing per-connection metrics to rule-level atomics.
/// Accumulating locally and flushing periodically reduces cache-line bounces
/// on the shared AtomicU64 counters.
const METRICS_FLUSH_INTERVAL: u64 = 1024;

pub struct ConnectionMetrics {
    pub direction: String, // "encrypt" or "decrypt"
    pub tls_mode: String,  // "tls" or "ktls"
    pub start: Instant,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub msgs_relayed: u64,
    pub latency_samples_ns: Vec<u64>,
    pub handshake_ms: f64,
    /// Live link to rule-level aggregates (updated on every record_* call).
    rule_metrics: Option<Arc<RuleMetrics>>,
    /// Pending counters for batched atomic flush.
    pending_bytes_in: u64,
    pending_bytes_out: u64,
    pending_msgs: u64,
}

impl ConnectionMetrics {
    /// Create with a live link to rule-level metrics (updated in real time).
    pub fn with_rule_metrics(
        direction: &str,
        tls_mode: &str,
        rule_metrics: Arc<RuleMetrics>,
    ) -> Self {
        Self {
            direction: direction.to_string(),
            tls_mode: tls_mode.to_string(),
            start: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
            msgs_relayed: 0,
            latency_samples_ns: Vec::new(),
            handshake_ms: 0.0,
            rule_metrics: Some(rule_metrics),
            pending_bytes_in: 0,
            pending_bytes_out: 0,
            pending_msgs: 0,
        }
    }

    /// Record a relay operation (batched atomic flush).
    #[inline]
    pub fn record_relay(&mut self, bytes: usize, latency_ns: Option<u64>) {
        self.bytes_out += bytes as u64;
        self.msgs_relayed += 1;
        self.pending_bytes_out += bytes as u64;
        self.pending_msgs += 1;

        // Flush to shared atomics every METRICS_FLUSH_INTERVAL messages
        if self.pending_msgs >= METRICS_FLUSH_INTERVAL {
            self.flush_pending();
        }

        if let Some(lat) = latency_ns {
            if lat > 0 && lat < 60_000_000_000 {
                self.latency_samples_ns.push(lat);
            }
        }
    }

    #[inline]
    pub fn record_read(&mut self, bytes: usize) {
        self.bytes_in += bytes as u64;
        self.pending_bytes_in += bytes as u64;
    }

    /// Flush pending counters to rule-level atomics.
    #[inline]
    fn flush_pending(&mut self) {
        if let Some(ref rm) = self.rule_metrics {
            rm.total_bytes_out
                .fetch_add(self.pending_bytes_out, Ordering::Relaxed);
            rm.total_bytes_in
                .fetch_add(self.pending_bytes_in, Ordering::Relaxed);
            rm.total_msgs
                .fetch_add(self.pending_msgs, Ordering::Relaxed);
        }
        self.pending_bytes_out = 0;
        self.pending_bytes_in = 0;
        self.pending_msgs = 0;
    }

    pub fn elapsed_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64().max(1e-9)
    }
}

impl Drop for ConnectionMetrics {
    fn drop(&mut self) {
        // Flush any remaining pending counters to rule-level atomics.
        self.flush_pending();
    }
}

// ─── Aggregate rule metrics ──────────────────────────────────────────────────

/// Aggregate metrics for a single proxy rule (across all connections).
pub struct RuleMetrics {
    pub rule_name: String,
    pub direction: String,
    pub tls_mode: String,
    pub total_bytes_in: AtomicU64,
    pub total_bytes_out: AtomicU64,
    pub total_connections: AtomicU64,
    pub active_connections: AtomicU64,
    pub total_msgs: AtomicU64,
    latency_samples: Mutex<Vec<u64>>,
    /// Previous snapshot for interval-based throughput reporting.
    prev_bytes_in: AtomicU64,
    prev_bytes_out: AtomicU64,
}

impl RuleMetrics {
    pub fn new(rule_name: &str, direction: &str, tls_mode: &str) -> Self {
        Self {
            rule_name: rule_name.to_string(),
            direction: direction.to_string(),
            tls_mode: tls_mode.to_string(),
            total_bytes_in: AtomicU64::new(0),
            total_bytes_out: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_msgs: AtomicU64::new(0),
            latency_samples: Mutex::new(Vec::new()),
            prev_bytes_in: AtomicU64::new(0),
            prev_bytes_out: AtomicU64::new(0),
        }
    }

    /// Merge connection latency samples into the rule aggregate.
    pub fn merge_connection(&self, conn: &ConnectionMetrics) {
        if conn.rule_metrics.is_none() {
            self.total_bytes_in
                .fetch_add(conn.bytes_in, Ordering::Relaxed);
            self.total_bytes_out
                .fetch_add(conn.bytes_out, Ordering::Relaxed);
            self.total_msgs
                .fetch_add(conn.msgs_relayed, Ordering::Relaxed);
        }

        if !conn.latency_samples_ns.is_empty() {
            if let Ok(mut samples) = self.latency_samples.lock() {
                samples.extend_from_slice(&conn.latency_samples_ns);
            }
        }
    }

    pub fn connection_opened(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Print a summary line to stderr using interval-based throughput.
    pub fn print_summary(&self, interval_s: f64) {
        let bytes_in = self.total_bytes_in.load(Ordering::Relaxed);
        let bytes_out = self.total_bytes_out.load(Ordering::Relaxed);
        let conns = self.total_connections.load(Ordering::Relaxed);
        let active = self.active_connections.load(Ordering::Relaxed);
        let msgs = self.total_msgs.load(Ordering::Relaxed);

        let prev_in = self.prev_bytes_in.swap(bytes_in, Ordering::Relaxed);
        let prev_out = self.prev_bytes_out.swap(bytes_out, Ordering::Relaxed);

        let delta_in = bytes_in.saturating_sub(prev_in) as f64;
        let delta_out = bytes_out.saturating_sub(prev_out) as f64;

        let interval = if interval_s > 0.0 { interval_s } else { 1.0 };
        let in_bps = delta_in / interval;
        let out_bps = delta_out / interval;

        let line = format!(
            "[{}] {} ({}) | conns: {} (active: {}) | msgs: {} | in: {} ({}) | out: {} ({})",
            self.rule_name,
            self.direction,
            self.tls_mode,
            conns,
            active,
            msgs,
            format_rate(in_bps),
            format_bytes(bytes_in),
            format_rate(out_bps),
            format_bytes(bytes_out),
        );
        info!("{}", line);
    }
}

/// Format a bytes-per-second rate with adaptive units.
pub fn format_rate(bps: f64) -> String {
    if bps >= 1024.0 * 1024.0 {
        format!("{:.1} MiB/s", bps / (1024.0 * 1024.0))
    } else if bps >= 1024.0 {
        format!("{:.1} KiB/s", bps / 1024.0)
    } else if bps > 0.0 {
        format!("{:.0} B/s", bps)
    } else {
        "0 B/s".to_string()
    }
}

/// Format a total byte count with adaptive units.
fn format_bytes(bytes: u64) -> String {
    let b = bytes as f64;
    if b >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} GiB total", b / (1024.0 * 1024.0 * 1024.0))
    } else if b >= 1024.0 * 1024.0 {
        format!("{:.1} MiB total", b / (1024.0 * 1024.0))
    } else if b >= 1024.0 {
        format!("{:.1} KiB total", b / 1024.0)
    } else {
        format!("{} B total", bytes)
    }
}

// ─── CSV log helper ──────────────────────────────────────────────────────────

/// Flush connection metrics to a CSV logger.
pub fn log_connection_csv(logger: &mut CsvLogger, conn: &mut ConnectionMetrics, run_id: &str) {
    let elapsed = conn.elapsed_secs();
    let payload_bps = conn.bytes_out as f64 / elapsed;

    let lat_stats = compute_latency_stats(&mut conn.latency_samples_ns);

    let _ = logger.log_result(&CsvRow {
        run_id,
        benchmark: "gateway",
        variant: &format!("{}-{}", conn.direction, conn.tls_mode),
        payload_size_bytes: 0,
        elapsed_s: elapsed,
        payload_bytes_total: conn.bytes_out,
        overhead_bytes_total: 0,
        msg_count: conn.msgs_relayed,
        payload_bps,
        overhead_bps: 0.0,
        total_bps: payload_bps,
        pipe_mode: &conn.tls_mode,
        pipe_threads: 1,
        pipe_bytes_written: conn.bytes_out,
        pipe_bps: payload_bps,
        pipe_handshake_ms: conn.handshake_ms,
        read_latency: lat_stats.as_ref(),
        pipe_latency: None,
    });
}

// ─── High-resolution clock ───────────────────────────────────────────────────

/// Nanosecond timestamp from `CLOCK_MONOTONIC`.
#[inline]
pub fn now_ns() -> u64 {
    unsafe {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
    }
}
