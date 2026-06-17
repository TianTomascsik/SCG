//! Logging & Audit interface — REFERENCE STUB (not compiled).
//!
//! Status: PROPOSED. Abstracts the current `log` + `env_logger` usage so the log
//! destination/format is swappable, and adds a separate structured audit sink.
//!
//! Recommended adoption: provide a `LogSink` adapter implementing `log::Log` so
//! existing info!/warn!/error!/debug! macros keep working unchanged.

use std::net::SocketAddr;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

pub enum FieldValue<'a> {
    Str(&'a str),
    I64(i64),
    U64(u64),
    F64(f64),
    Bool(bool),
}

/// One structured diagnostic log record.
pub struct LogRecord<'a> {
    pub level: LogLevel,
    pub target: &'a str,
    pub message: &'a str,
    pub fields: &'a [(&'a str, FieldValue<'a>)],
    pub timestamp_ns: u64,
}

/// Swappable diagnostic/operational logging backend.
pub trait LogSink: Send + Sync {
    /// Emit one record. Best-effort and non-blocking in the common path.
    fn log(&self, record: &LogRecord<'_>);

    /// Whether a level is enabled for a target (lets callers skip formatting).
    fn enabled(&self, _level: LogLevel, _target: &str) -> bool {
        true
    }

    /// Flush buffered records (shutdown / periodic).
    fn flush(&self);
}

// ─── Audit ───────────────────────────────────────────────────────────────────

pub enum AuditKind {
    PolicyDenied,
    PolicyAllowed,
    ConfigChanged,
    HandshakeFailed,
    KeyRotated,
    CertLoaded,
    AuthFailure,
    ModuleLoaded,
    Shutdown,
    Other,
}

pub enum AuditError {
    Backpressure,
    Io,
    Unavailable,
}

/// A security-relevant audit event.
pub struct AuditEvent<'a> {
    pub kind: AuditKind,
    pub severity: LogLevel,
    pub rule: Option<&'a str>,
    pub src: Option<SocketAddr>,
    pub dst: Option<SocketAddr>,
    pub detail: &'a str,
    pub fields: &'a [(&'a str, FieldValue<'a>)],
    pub timestamp_ns: u64,
}

/// Swappable, durable audit-event sink (independent of diagnostic logging).
pub trait AuditSink: Send + Sync {
    /// Record an event durably. On Err the caller decides whether to fail closed.
    fn record(&self, event: &AuditEvent<'_>) -> Result<(), AuditError>;

    /// Commit/sync buffered events.
    fn flush(&self) -> Result<(), AuditError>;
}
