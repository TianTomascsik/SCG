//! Management & Admin API interface — REFERENCE STUB (not compiled).
//!
//! Status: PROPOSED. Pins down the contract sketched in `gateway/src/api/mod.rs`
//! (planned gRPC API + Admin API) as a transport-agnostic surface so the wire
//! protocol (gRPC / REST / UDS CLI) is swappable. This is a CONSUMER of the
//! other interfaces (diagnostics, config, policy, keys), not an implementor.

// Shared types (interface 04 — telemetry):
//   DiagnosticsSnapshot, HealthReport, HealthStatus

/// Read / operate surface (may be exposed read-only).
pub trait ManagementApi: Send + Sync {
    fn status(&self) -> GatewayStatus;
    fn list_rules(&self) -> Vec<RuleStatus>;
    fn get_rule(&self, name: &str) -> Option<RuleStatus>;
    fn metrics_snapshot(&self) -> DiagnosticsSnapshot;
}

/// Privileged admin surface. Every call MUST be authenticated/authorized at the
/// binding layer (see interface 11 — IAM).
pub trait AdminApi: Send + Sync {
    fn apply_config(&self, cfg: &str) -> Result<ApplyOutcome, AdminError>;
    fn reload(&self) -> Result<ApplyOutcome, AdminError>;
    fn rotate_keys(&self, scope: KeyScope) -> Result<(), AdminError>;
    fn reload_policy(&self) -> Result<(), AdminError>;
    fn fetch_audit(&self, since_ns: u64, limit: usize) -> Result<Vec<AuditRecord>, AdminError>;
}

/// Liveness/readiness probes for orchestrators.
pub trait HealthCheck: Send + Sync {
    fn liveness(&self) -> HealthStatus;
    fn readiness(&self) -> HealthReport;
}

pub struct GatewayStatus {
    pub version: String,
    pub uptime_secs: u64,
    pub rule_count: usize,
    pub active_connections: u64,
    pub health: HealthStatus,
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

pub struct ApplyOutcome {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub unchanged: Vec<String>,
}

pub enum KeyScope {
    All,
    Certificates,
    Psk,
    Material(String),
}

pub struct AuditRecord {
    pub timestamp_ns: u64,
    pub kind: String,
    pub detail: String,
}

pub enum AdminError {
    Unauthorized,
    InvalidConfig(String),
    Unavailable(String),
    Io(String),
}
