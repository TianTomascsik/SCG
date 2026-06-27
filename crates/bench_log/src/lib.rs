//! bench_log — Scientific logging and CSV output for benchmark results.
//!
//! Provides:
//! - `LatencyStats` with comprehensive percentiles (P50, P75, P95, P99, P99.9)
//! - `CsvLogger` for raw-data CSV file output (no rounding)
//! - Enhanced console print functions with full precision
//! - CLI helpers for `--log-dir`, `--run-id`, and `--instance` flags

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::time::SystemTime;

// ─── Latency Statistics ──────────────────────────────────────────────────────

/// Comprehensive latency statistics computed from nanosecond samples.
#[derive(Debug, Clone)]
pub struct LatencyStats {
    pub count: usize,
    pub min_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
    pub stddev_ns: f64,
    pub p50_ns: u64,
    pub p75_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
}

/// Compute comprehensive latency statistics from nanosecond samples.
/// The input vector is sorted in-place.  Returns `None` if empty.
pub fn compute_latency_stats(samples: &mut Vec<u64>) -> Option<LatencyStats> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    let n = samples.len();
    let min_ns = samples[0];
    let max_ns = samples[n - 1];

    let sum: f64 = samples.iter().map(|&v| v as f64).sum();
    let mean_ns = sum / n as f64;

    let variance: f64 = samples
        .iter()
        .map(|&v| {
            let d = v as f64 - mean_ns;
            d * d
        })
        .sum::<f64>()
        / n as f64;
    let stddev_ns = variance.sqrt();

    let pct = |p: f64| -> u64 {
        let idx = ((n - 1) as f64 * p / 100.0).round() as usize;
        samples[idx.min(n - 1)]
    };

    Some(LatencyStats {
        count: n,
        min_ns,
        max_ns,
        mean_ns,
        stddev_ns,
        p50_ns: pct(50.0),
        p75_ns: pct(75.0),
        p95_ns: pct(95.0),
        p99_ns: pct(99.0),
        p999_ns: pct(99.9),
    })
}

// ─── CSV Logger ──────────────────────────────────────────────────────────────

const CSV_HEADER: &str = "timestamp_unix_us,run_id,benchmark,variant,\
payload_size_bytes,elapsed_s,\
payload_bytes_total,overhead_bytes_total,msg_count,\
payload_bps,overhead_bps,total_bps,\
pipe_mode,pipe_threads,pipe_bytes_written,pipe_bps,pipe_handshake_ms,\
lat_read_count,lat_read_min_ns,lat_read_max_ns,lat_read_mean_ns,lat_read_stddev_ns,\
lat_read_p50_ns,lat_read_p75_ns,lat_read_p95_ns,lat_read_p99_ns,lat_read_p999_ns,\
lat_pipe_count,lat_pipe_min_ns,lat_pipe_max_ns,lat_pipe_mean_ns,lat_pipe_stddev_ns,\
lat_pipe_p50_ns,lat_pipe_p75_ns,lat_pipe_p95_ns,lat_pipe_p99_ns,lat_pipe_p999_ns";

/// A single row of benchmark results for CSV output.
pub struct CsvRow<'a> {
    pub run_id: &'a str,
    pub benchmark: &'a str,
    pub variant: &'a str,
    pub payload_size_bytes: usize,
    pub elapsed_s: f64,
    pub payload_bytes_total: u64,
    pub overhead_bytes_total: u64,
    pub msg_count: u64,
    pub payload_bps: f64,
    pub overhead_bps: f64,
    pub total_bps: f64,
    pub pipe_mode: &'a str, // "none", "ktls", "tls"
    pub pipe_threads: usize,
    pub pipe_bytes_written: u64,
    pub pipe_bps: f64,
    pub pipe_handshake_ms: f64,
    pub read_latency: Option<&'a LatencyStats>,
    pub pipe_latency: Option<&'a LatencyStats>,
}

/// CSV file writer that produces raw, unrounded data for analysis.
pub struct CsvLogger {
    writer: BufWriter<File>,
    path: String,
}

impl CsvLogger {
    /// Create a new CSV log file in `log_dir`.
    /// Filename: `{benchmark}_{variant}_{run_id}__{unix_us}.csv`
    pub fn new(log_dir: &str, benchmark: &str, variant: &str, run_id: &str) -> io::Result<Self> {
        fs::create_dir_all(log_dir)?;
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_micros())
            .unwrap_or(0);
        let safe_id = run_id.replace(['/', ' '], "_");
        let filename = format!("{}_{}_{}__{}.csv", benchmark, variant, safe_id, ts);
        let path = format!("{}/{}", log_dir, filename);
        let file = File::create(&path)?;
        let mut writer = BufWriter::new(file);
        writeln!(writer, "{}", CSV_HEADER)?;
        writer.flush()?;
        eprintln!("[LOG] CSV → {}", path);
        Ok(CsvLogger { writer, path })
    }

    /// File path of the CSV log.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Append one result row.  All floating-point values are written with
    /// full `f64` precision (no rounding).
    pub fn log_result(&mut self, row: &CsvRow) -> io::Result<()> {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_micros())
            .unwrap_or(0);

        fn lat_fields(lat: Option<&LatencyStats>) -> String {
            match lat {
                Some(l) => format!(
                    "{},{},{},{},{},{},{},{},{},{}",
                    l.count,
                    l.min_ns,
                    l.max_ns,
                    l.mean_ns,
                    l.stddev_ns,
                    l.p50_ns,
                    l.p75_ns,
                    l.p95_ns,
                    l.p99_ns,
                    l.p999_ns
                ),
                None => ",,,,,,,,,".to_string(),
            }
        }

        writeln!(
            self.writer,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            ts,
            row.run_id,
            row.benchmark,
            row.variant,
            row.payload_size_bytes,
            row.elapsed_s,
            row.payload_bytes_total,
            row.overhead_bytes_total,
            row.msg_count,
            row.payload_bps,
            row.overhead_bps,
            row.total_bps,
            row.pipe_mode,
            row.pipe_threads,
            row.pipe_bytes_written,
            row.pipe_bps,
            row.pipe_handshake_ms,
            lat_fields(row.read_latency),
            lat_fields(row.pipe_latency),
        )?;
        self.writer.flush()
    }
}

// ─── Console Output ──────────────────────────────────────────────────────────

fn format_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{} MB", bytes / 1024 / 1024)
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} B", bytes)
    }
}

/// Print the throughput table header.
/// `pipe_label` is `Some("kTLS")` or `Some("TLS")` when a pipe is active.
pub fn print_throughput_header(name: &str, pipe_label: Option<&str>) {
    let pipe_str = match pipe_label {
        Some(l) => format!(" (with {} pipe)", l),
        None => String::new(),
    };
    println!("\n=== BENCHMARK: {}{} ===", name, pipe_str);

    match pipe_label {
        Some(l) => {
            println!(
                "{:<12} | {:<15} | {:<15} | {:<15} | {:<10}",
                "Payload Size",
                "IPC Tput",
                &format!("{} Tput", l),
                "Overhead",
                "Status"
            );
            println!(
                "{:-<12}-+-{:-<15}-+-{:-<15}-+-{:-<15}-+-{:-<10}",
                "", "", "", "", ""
            );
        }
        None => {
            println!(
                "{:<12} | {:<15} | {:<15} | {:<10} | {:<10}",
                "Payload Size", "Total Tput", "Payload Tput", "Overhead", "Status"
            );
            println!(
                "{:-<12}-+-{:-<15}-+-{:-<15}-+-{:-<10}-+-{:-<10}",
                "", "", "", "", ""
            );
        }
    }
}

/// Print one throughput result row.
pub fn print_throughput_row(
    payload_size: usize,
    msg_count: u64,
    elapsed_s: f64,
    payload_bps: f64,
    overhead_bps: f64,
    pipe_bps: Option<f64>,
) {
    let total_bps = payload_bps + overhead_bps;
    let overhead_pct = if total_bps > 0.0 {
        (overhead_bps / total_bps) * 100.0
    } else {
        0.0
    };

    let gib = |bps: f64| bps / (1024.0 * 1024.0 * 1024.0);

    match pipe_bps {
        Some(p) => {
            println!(
                "{:<12} | {:>10.2} GiB/s | {:>10.2} GiB/s | {:>8.2} %      | Completed",
                format_size(payload_size),
                gib(total_bps),
                gib(p),
                overhead_pct,
            );
        }
        None => {
            println!(
                "{:<12} | {:>10.2} GiB/s | {:>10.2} GiB/s | {:>8.2} % | Completed",
                format_size(payload_size),
                gib(total_bps),
                gib(payload_bps),
                overhead_pct
            );
        }
    }
    // Additional detail line with raw numbers (messages, elapsed, exact bytes/s)
    println!(
        "             msgs={:<10} elapsed={:.6}s  payload={:.0} B/s  overhead={:.0} B/s  total={:.0} B/s",
        msg_count,
        elapsed_s,
        payload_bps,
        overhead_bps,
        total_bps,
    );
}

/// Print latency summary in the familiar P50/P99 format, plus extra percentiles.
pub fn print_latency_stats(_payload_size: usize, label: &str, stats: &LatencyStats) {
    let us = |ns: u64| ns as f64 / 1000.0;
    let usf = |ns: f64| ns / 1000.0;
    println!(
        "Latency {} P50/P99: {:.3} us / {:.3} us",
        label,
        us(stats.p50_ns),
        us(stats.p99_ns),
    );
    println!(
        "  (n={} min={:.3} mean={:.3} P75={:.3} P95={:.3} P99.9={:.3} max={:.3} stddev={:.3} us)",
        stats.count,
        us(stats.min_ns),
        usf(stats.mean_ns),
        us(stats.p75_ns),
        us(stats.p95_ns),
        us(stats.p999_ns),
        us(stats.max_ns),
        usf(stats.stddev_ns),
    );
}

// ─── CLI Helpers ─────────────────────────────────────────────────────────────

/// Parse `--log-dir <path>` from command-line args.
pub fn parse_log_dir(args: &[String]) -> Option<String> {
    args.iter()
        .position(|a| a == "--log-dir")
        .and_then(|i| args.get(i + 1).cloned())
}

/// Parse `--run-id <id>` from command-line args (default: `"default"`).
pub fn parse_run_id(args: &[String]) -> String {
    args.iter()
        .position(|a| a == "--run-id")
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| "default".to_string())
}

/// Parse `--instance <N>` from command-line args (default: `0`).
pub fn parse_instance(args: &[String]) -> u16 {
    args.iter()
        .position(|a| a == "--instance")
        .and_then(|i| args.get(i + 1).and_then(|v| v.parse().ok()))
        .unwrap_or(0)
}

/// Parse `--pipe-target <HOST:PORT>` from command-line args.
/// When set, the benchmark pipes data to a remote TLS receiver instead of a local sink.
pub fn parse_pipe_target(args: &[String]) -> Option<String> {
    args.iter()
        .position(|a| a == "--pipe-target")
        .and_then(|i| args.get(i + 1).cloned())
}

/// Parse `--server-addr <HOST>` from command-line args (default: `"127.0.0.1"`).
/// Used in 3-container mode so the client connects to a remote server container.
pub fn parse_server_addr(args: &[String]) -> String {
    args.iter()
        .position(|a| a == "--server-addr")
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

/// Parse `--socket-dir <DIR>` from command-line args (default: `"/tmp"`).
/// Used in container mode so UDS benchmarks can share a socket via a Docker volume.
pub fn parse_socket_dir(args: &[String]) -> String {
    args.iter()
        .position(|a| a == "--socket-dir")
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| "/tmp".to_string())
}
