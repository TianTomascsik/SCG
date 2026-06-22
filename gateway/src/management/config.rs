//! Configuration module for the gateway proxy.
//!
//! Parses a JSON configuration file defining proxy rules, where each rule
//! specifies a direction (encrypt or decrypt), listen/upstream addresses,
//! security provider, and optional TPROXY transparency.

use log::info;
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::net::{IpAddr, SocketAddr};

// ─── Top-level config ────────────────────────────────────────────────────────

/// Top-level gateway configuration loaded from JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// Socket buffer size in bytes for tuning (default: 16 MiB).
    #[serde(default = "default_sock_buf_size")]
    pub sock_buf_size: usize,

    /// Proxy rules — at least one required.
    pub rules: Vec<RuleConfig>,

    /// Traffic classification rules (optional — enables pipeline).
    #[serde(default)]
    pub traffic_rules: Vec<TrafficRuleConfig>,

    /// Policy enforcement configuration (optional — default: allow all).
    #[serde(default)]
    pub policy: Option<PolicyConfig>,

    /// Traffic cache configuration (optional).
    #[serde(default)]
    pub cache: Option<CacheConfig>,

    /// Log level: "error", "warn", "info", "debug", "trace" (default: "info").
    /// Can be overridden by --log-level CLI flag.
    #[serde(default)]
    pub log_level: Option<String>,

    /// Management API (gRPC) configuration (optional). When omitted, defaults
    /// to gRPC-over-UDS at `/run/scg/management.sock` with no TCP listener.
    #[serde(default)]
    pub api: Option<ApiConfig>,
}

/// Management API (gRPC) configuration.
///
/// The control plane runs on a dedicated thread off the data path. UDS is the
/// default transport because it yields `SO_PEERCRED`-authenticated caller
/// identity and exposes no network port; TCP is opt-in for remote admin.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiConfig {
    /// Whether the management API is started (default: true).
    #[serde(default = "default_api_enabled")]
    pub enabled: bool,

    /// Path of the gRPC-over-UDS management socket
    /// (default: `/run/scg/management.sock`).
    #[serde(default = "default_mgmt_uds")]
    pub uds_path: String,

    /// Optional TCP bind address for remote admin (e.g. "127.0.0.1:50080").
    /// Disabled when unset.
    #[serde(default)]
    pub tcp_addr: Option<String>,

    /// Directory under which per-endpoint UDS/SHM control sockets are created
    /// (default: `/run/scg`). A per-uid subdirectory is created beneath it.
    #[serde(default = "default_runtime_dir")]
    pub runtime_dir: String,

    /// Default shared-memory ring capacity in bytes, per direction
    /// (default: 1 MiB).
    #[serde(default = "default_shm_ring_capacity")]
    pub shm_ring_capacity: usize,

    /// Maximum number of simultaneously-live local endpoints a single uid may
    /// own. Guards against local resource exhaustion from a buggy or hostile
    /// authorised client (default: 64; `0` disables the quota).
    #[serde(default = "default_max_endpoints_per_uid")]
    pub max_endpoints_per_uid: u32,

    /// Maximum endpoint-creation requests a single uid may issue per minute.
    /// Token-bucket rate limit protecting the control plane (default: 120;
    /// `0` disables the limit).
    #[serde(default = "default_create_rate_per_min")]
    pub create_rate_per_min: u32,
}

impl Default for ApiConfig {
    fn default() -> Self {
        ApiConfig {
            enabled: default_api_enabled(),
            uds_path: default_mgmt_uds(),
            tcp_addr: None,
            runtime_dir: default_runtime_dir(),
            shm_ring_capacity: default_shm_ring_capacity(),
            max_endpoints_per_uid: default_max_endpoints_per_uid(),
            create_rate_per_min: default_create_rate_per_min(),
        }
    }
}

fn default_api_enabled() -> bool {
    true
}

fn default_mgmt_uds() -> String {
    "/run/scg/management.sock".to_string()
}

fn default_runtime_dir() -> String {
    "/run/scg".to_string()
}

fn default_shm_ring_capacity() -> usize {
    1024 * 1024 // 1 MiB
}

fn default_max_endpoints_per_uid() -> u32 {
    64
}

fn default_create_rate_per_min() -> u32 {
    120
}

fn default_sock_buf_size() -> usize {
    16 * 1024 * 1024 // 16 MiB
}

// ─── Rule config ─────────────────────────────────────────────────────────────

/// A single proxy rule defining one forwarding path.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    /// Human-readable name for this rule (used in logs/CSV).
    pub name: String,

    /// Direction: "encrypt" (plain -> encrypted) or "decrypt" (encrypted -> plain).
    pub direction: Direction,

    /// Address to listen on (e.g. "0.0.0.0:8080").
    pub listen_addr: String,

    /// Protocol to listen on: "tcp" or "udp".
    #[serde(default = "default_proto")]
    pub listen_proto: Proto,

    /// Upstream address to forward to.
    ///   - Explicit: "backend:443"
    ///   - Auto (TPROXY): "auto" — uses SO_ORIGINAL_DST to determine real target
    #[serde(default = "default_upstream")]
    pub upstream_addr: String,

    /// Protocol for the upstream side.
    #[serde(default = "default_proto")]
    pub upstream_proto: Proto,

    /// Security provider name: "tls", "ktls", "dtls", or any
    /// registered custom provider. This replaces the former `tls_mode` field.
    #[serde(default = "default_security_provider")]
    pub security_provider: String,

    /// Application-level protocol for UDP-over-TLS framing: "ale", "raw",
    /// or any registered custom provider. Only used for UDP-over-TLS paths.
    /// Defaults to "ale" when not specified.
    #[serde(default)]
    pub app_protocol: Option<String>,

    /// Legacy alias for security_provider (for internal compatibility).
    /// If both are set, security_provider takes precedence.
    #[serde(default = "default_tls_mode")]
    pub tls_mode: TlsMode,

    /// Scheduling priority (lower = higher priority). 0 = default.
    #[serde(default)]
    pub priority: i32,

    /// Enable TPROXY transparent proxying (requires IP_TRANSPARENT + iptables).
    #[serde(default)]
    pub transparent: bool,

    /// Provider-specific parameters, captured generically from the rule object.
    ///
    /// Any config keys that are not recognised by the typed fields above are
    /// collected here via `serde(flatten)`. This lets external/custom security
    /// providers read their own settings without the core gateway needing to
    /// know about them.
    #[serde(flatten)]
    pub provider_params: std::collections::HashMap<String, serde_json::Value>,

    /// Traffic priority class: "safety" or "normal" (default: "normal").
    /// Safety traffic is always processed before normal traffic.
    #[serde(default)]
    pub traffic_class: TrafficClass,

    /// Egress DSCP tag (0..=63) to stamp on packets the gateway sends for this
    /// rule. When set it overwrites any inbound marking. When unset the value is
    /// derived from `preserve_inbound_dscp` and then the traffic class (safety
    /// defaults to EF/46). See [`RuleConfig::egress_dscp`].
    #[serde(default)]
    pub dscp_tag: Option<u8>,

    /// When true (and `dscp_tag` is unset), the gateway samples the inbound DS
    /// field and re-applies it to the egress packets, preserving an upstream
    /// marking end-to-end. For TCP this is sampled once per connection.
    #[serde(default)]
    pub preserve_inbound_dscp: bool,

    /// Application identifier for buffer/queue management (optional).
    #[serde(default)]
    pub app_id: Option<String>,

    /// Number of slots in per-app ring buffer (UDP pipeline only, default: 256).
    #[serde(default = "default_buffer_slots")]
    pub buffer_slots: usize,

    /// Bytes per buffer slot (UDP pipeline only, default: 65536).
    #[serde(default = "default_buffer_slot_size")]
    pub buffer_slot_size: usize,

    /// Simulated network delay in milliseconds, applied before each upstream send.
    /// Useful for geo-location simulation / WAN latency testing. Default: 0 (disabled).
    #[serde(default)]
    pub simulated_delay_ms: u64,

    /// Protocol version for TLS/DTLS. Valid values:
    /// - "tls1.2", "tls1.3" (for tls/ktls security providers)
    /// - "dtls1.0", "dtls1.2" (for dtls security provider)
    /// Default: None (TLS 1.2 for tls/ktls, DTLS 1.2 for dtls).
    #[serde(default)]
    pub protocol_version: Option<String>,

    /// Local-interface access control: uids permitted to open a dynamically
    /// created UDS/SHM endpoint bound to this rule's `app_id`. An empty list
    /// means no local client is authorised (the local interface is disabled
    /// for this rule). Enforced via `SO_PEERCRED` at connect time.
    #[serde(default)]
    pub allowed_uids: Vec<u32>,

    /// Optional stricter access control: when non-empty, the connecting peer's
    /// pid (from `SO_PEERCRED`) must also appear here. Empty disables the pid
    /// check (the uid check still applies).
    #[serde(default)]
    pub allowed_pids: Vec<i32>,
}

impl RuleConfig {
    /// Returns the effective security provider name.
    /// Uses `security_provider` if explicitly set (non-default), otherwise
    /// derives from `tls_mode` for backward compatibility.
    pub fn effective_security_provider(&self) -> &str {
        if self.security_provider != "tls" || self.tls_mode == TlsMode::Tls {
            &self.security_provider
        } else {
            // tls_mode was set to something non-default, use it
            match self.tls_mode {
                TlsMode::Tls => "tls",
                TlsMode::Ktls => "ktls",
                TlsMode::Dtls => "dtls",
            }
        }
    }

    /// Returns the effective app protocol name.
    /// Defaults to "ale" for UDP-over-TLS paths if not specified.
    pub fn effective_app_protocol(&self) -> &str {
        match &self.app_protocol {
            Some(p) => p.as_str(),
            None => "ale",
        }
    }

    /// Resolve the DSCP value (0..=63) to stamp on this rule's egress packets,
    /// or `None` to leave the kernel default. Precedence:
    ///
    /// 1. explicit `dscp_tag` (overwrite / tagging),
    /// 2. else `preserve_inbound_dscp` with a `sampled_inbound` value,
    /// 3. else the traffic-class default: Safety = EF (46), Normal = none.
    pub fn egress_dscp(&self, sampled_inbound: Option<u8>) -> Option<u8> {
        self.qos().egress_dscp(sampled_inbound)
    }

    /// Whether this rule must sample the inbound DSCP (via RECVTOS) at runtime —
    /// i.e. preservation is requested and no explicit tag overrides it.
    pub fn needs_inbound_dscp(&self) -> bool {
        self.qos().needs_inbound_dscp()
    }

    /// The `SO_PRIORITY` value for this rule's sockets, derived from its class.
    pub fn so_priority(&self) -> i32 {
        self.qos().so_priority()
    }

    /// The resolved, `Copy`-able QoS policy for this rule, suitable for handing
    /// to the data path inside a `RuleContext`.
    pub fn qos(&self) -> QosPolicy {
        QosPolicy {
            dscp_tag: self.dscp_tag,
            preserve_inbound_dscp: self.preserve_inbound_dscp,
            traffic_class: self.traffic_class,
        }
    }
}

fn default_security_provider() -> String {
    "tls".to_string()
}

fn default_proto() -> Proto {
    Proto::Tcp
}

fn default_tls_mode() -> TlsMode {
    TlsMode::Tls
}

fn default_upstream() -> String {
    "auto".to_string()
}

fn default_buffer_slots() -> usize {
    256
}

fn default_buffer_slot_size() -> usize {
    65536
}

// ─── Enums ───────────────────────────────────────────────────────────────────

/// Proxy direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Plain TCP/UDP → TLS/kTLS/DTLS (encrypt outbound traffic).
    Encrypt,
    /// TLS/kTLS/DTLS → Plain TCP/UDP (decrypt inbound traffic).
    Decrypt,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Encrypt => write!(f, "encrypt"),
            Direction::Decrypt => write!(f, "decrypt"),
        }
    }
}

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    /// Unix-domain-socket local interface (dynamically created per app/class).
    Uds,
    /// Shared-memory local interface (dynamically created per app/class).
    Shm,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Proto::Tcp => write!(f, "tcp"),
            Proto::Udp => write!(f, "udp"),
            Proto::Uds => write!(f, "uds"),
            Proto::Shm => write!(f, "shm"),
        }
    }
}

/// TLS implementation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Userspace OpenSSL TLS (no kernel offload). Runs over TCP.
    Tls,
    /// Kernel TLS offload (kTLS via SSL_OP_ENABLE_KTLS). Runs over TCP.
    Ktls,
    /// Datagram TLS — TLS adapted for UDP. Runs over UDP natively.
    /// Preserves UDP semantics: no head-of-line blocking, no ordering guarantee.
    /// Note: kTLS does NOT support DTLS (Linux kernel limitation).
    Dtls,
}

impl fmt::Display for TlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsMode::Tls => write!(f, "tls"),
            TlsMode::Ktls => write!(f, "ktls"),
            TlsMode::Dtls => write!(f, "dtls"),
        }
    }
}

/// Traffic priority class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficClass {
    /// Normal priority — default for all traffic.
    Normal,
    /// Safety-critical traffic — always processed first.
    Safety,
}

impl Default for TrafficClass {
    fn default() -> Self {
        TrafficClass::Normal
    }
}

impl fmt::Display for TrafficClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrafficClass::Normal => write!(f, "normal"),
            TrafficClass::Safety => write!(f, "safety"),
        }
    }
}

/// Expedited Forwarding DSCP (RFC 3246) — the default egress mark for safety
/// traffic so downstream routers give it priority queuing.
pub const DSCP_EF: u8 = 46;

/// `SO_PRIORITY` for safety traffic — the highest value settable without
/// `CAP_NET_ADMIN`, selecting the top band of the default `pfifo_fast` qdisc.
pub const SAFETY_SO_PRIORITY: i32 = 6;

/// Thread nice value applied to Safety-class data-path threads (lower = higher
/// priority) so safety relays preempt normal traffic. Negative values require
/// `CAP_SYS_NICE`; applied best-effort.
pub const SAFETY_THREAD_NICE: i32 = -5;

/// Map a traffic class to its `SO_PRIORITY` value (Safety = 6, Normal = 0).
pub fn so_priority_for(class: TrafficClass) -> i32 {
    match class {
        TrafficClass::Safety => SAFETY_SO_PRIORITY,
        TrafficClass::Normal => 0,
    }
}

/// Resolved QoS (DiffServ + scheduling) policy for a rule. `Copy` so it can be
/// embedded in the per-connection data path without allocation.
#[derive(Debug, Clone, Copy)]
pub struct QosPolicy {
    /// Explicit egress DSCP tag (0..=63), overriding preservation and defaults.
    pub dscp_tag: Option<u8>,
    /// Carry the inbound DS field to egress when no explicit tag is set.
    pub preserve_inbound_dscp: bool,
    /// Traffic class driving SO_PRIORITY and the default DSCP.
    pub traffic_class: TrafficClass,
}

impl QosPolicy {
    /// See [`RuleConfig::egress_dscp`].
    pub fn egress_dscp(&self, sampled_inbound: Option<u8>) -> Option<u8> {
        if let Some(tag) = self.dscp_tag {
            return Some(tag & 0x3f);
        }
        if self.preserve_inbound_dscp {
            if let Some(v) = sampled_inbound {
                return Some(v & 0x3f);
            }
        }
        match self.traffic_class {
            TrafficClass::Safety => Some(DSCP_EF),
            TrafficClass::Normal => None,
        }
    }

    /// Whether the inbound DSCP must be sampled (RECVTOS) for preservation.
    pub fn needs_inbound_dscp(&self) -> bool {
        self.preserve_inbound_dscp && self.dscp_tag.is_none()
    }

    /// The `SO_PRIORITY` for this policy's sockets.
    pub fn so_priority(&self) -> i32 {
        so_priority_for(self.traffic_class)
    }
}

/// A traffic classification rule (matches source/destination to app_id + class).
#[derive(Debug, Clone, Deserialize)]
pub struct TrafficRuleConfig {
    /// Source address pattern: "IP:port", "IP", CIDR "IP/prefix", or "any".
    pub source: String,
    /// Destination address pattern: "IP:port", "IP", CIDR "IP/prefix", or "any".
    pub destination: String,
    /// Application identifier (links to RuleConfig.app_id).
    pub app_id: String,
    /// Traffic class for matching flows.
    #[serde(default)]
    pub traffic_class: TrafficClass,
}

/// Policy enforcement configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    /// Default action when no whitelist entry matches.
    #[serde(default = "default_policy_action")]
    pub default_action: PolicyAction,
    /// Whitelist entries — traffic matching any entry is allowed.
    #[serde(default)]
    pub whitelist: Vec<WhitelistEntry>,
}

/// Policy default action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Allow,
    Deny,
}

impl Default for PolicyAction {
    fn default() -> Self {
        PolicyAction::Allow
    }
}

fn default_policy_action() -> PolicyAction {
    PolicyAction::Allow
}

/// A single whitelist entry for the policy manager.
#[derive(Debug, Clone, Deserialize)]
pub struct WhitelistEntry {
    /// Source address pattern: "IP:port", "IP", CIDR "IP/prefix", or "any".
    pub source: String,
    /// Destination address pattern: "IP:port", "IP", CIDR "IP/prefix", or "any".
    pub destination: String,
}

/// Traffic cache configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// Maximum number of cached classification entries (default: 10000).
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: usize,
    /// Time-to-live for cache entries in seconds (default: 300).
    #[serde(default = "default_cache_ttl")]
    pub ttl_secs: u64,
}

fn default_cache_max_entries() -> usize {
    10_000
}

fn default_cache_ttl() -> u64 {
    300
}

/// Compiled address pattern for traffic matching.
#[derive(Debug, Clone)]
pub enum AddressPattern {
    /// Matches any address.
    Any,
    /// Exact socket address match (IP:port).
    Exact(SocketAddr),
    /// IP-only match (any port).
    IpOnly(IpAddr),
    /// CIDR prefix match (IP/prefix_len, any port).
    Cidr { network: IpAddr, prefix_len: u8 },
}

impl AddressPattern {
    /// Parse an address pattern from a config string.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s == "any" {
            return Ok(AddressPattern::Any);
        }
        // Try CIDR: "10.0.0.0/8"
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|e| format!("invalid IP in CIDR '{}': {}", s, e))?;
            let prefix_len: u8 = prefix_str
                .parse()
                .map_err(|e| format!("invalid prefix in CIDR '{}': {}", s, e))?;
            let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
            if prefix_len > max_prefix {
                return Err(format!(
                    "prefix length {} exceeds max {} for '{}'",
                    prefix_len, max_prefix, s
                ));
            }
            return Ok(AddressPattern::Cidr {
                network: ip,
                prefix_len,
            });
        }
        // Try exact socket address: "1.2.3.4:5000"
        if let Ok(sa) = s.parse::<SocketAddr>() {
            return Ok(AddressPattern::Exact(sa));
        }
        // Try IP only: "1.2.3.4"
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(AddressPattern::IpOnly(ip));
        }
        Err(format!("cannot parse address pattern '{}'", s))
    }

    /// Check if a socket address matches this pattern.
    pub fn matches(&self, addr: &SocketAddr) -> bool {
        match self {
            AddressPattern::Any => true,
            AddressPattern::Exact(sa) => addr == sa,
            AddressPattern::IpOnly(ip) => &addr.ip() == ip,
            AddressPattern::Cidr {
                network,
                prefix_len,
            } => cidr_contains(*network, *prefix_len, addr.ip()),
        }
    }
}

/// Check if `addr` is within the CIDR block `network/prefix_len`.
fn cidr_contains(network: IpAddr, prefix_len: u8, addr: IpAddr) -> bool {
    match (network, addr) {
        (IpAddr::V4(net), IpAddr::V4(a)) => {
            if prefix_len == 0 {
                return true;
            }
            let mask = u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0);
            let net_bits = u32::from(net) & mask;
            let addr_bits = u32::from(a) & mask;
            net_bits == addr_bits
        }
        (IpAddr::V6(net), IpAddr::V6(a)) => {
            if prefix_len == 0 {
                return true;
            }
            let mask = u128::MAX.checked_shl(128 - prefix_len as u32).unwrap_or(0);
            let net_bits = u128::from(net) & mask;
            let addr_bits = u128::from(a) & mask;
            net_bits == addr_bits
        }
        _ => false, // v4 vs v6 mismatch
    }
}

// ─── Loading ─────────────────────────────────────────────────────────────────

impl GatewayConfig {
    /// Load configuration from a JSON file.
    pub fn load(path: &str) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file '{}': {}", path, e))?;
        let config: GatewayConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse config file '{}': {}", path, e))?;
        config.validate()?;
        Ok(config)
    }

    /// Build and validate a `GatewayConfig` from an already-rendered classic
    /// configuration `Value`.
    ///
    /// Used by the lite-config loader after it has merged the layered model and
    /// mapped connections into the flat `rules` array. Runs the same structural
    /// and semantic validation as [`GatewayConfig::load`].
    pub fn from_value(value: serde_json::Value) -> Result<Self, String> {
        let config: GatewayConfig = serde_json::from_value(value)
            .map_err(|e| format!("Failed to build gateway config from lite mapping: {}", e))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    fn validate(&self) -> Result<(), String> {
        if self.rules.is_empty() {
            return Err(
                "Configuration must contain at least one rule in \"rules\" array".to_string(),
            );
        }

        let mut seen_names = HashSet::new();
        let mut seen_listen = HashSet::new();

        for (i, rule) in self.rules.iter().enumerate() {
            if rule.name.is_empty() {
                return Err(format!("Rule at index {} has an empty name", i));
            }

            // Duplicate rule names
            if !seen_names.insert(&rule.name) {
                return Err(format!(
                    "Rule '{}' (index {}): duplicate rule name (names must be unique for hot-reload)",
                    rule.name, i
                ));
            }

            // Validate listen address parses
            //
            // UDS/SHM rules are templates for dynamically-created local
            // endpoints (consumed by the InterfaceManager and started on demand
            // via the management API). They have no static TCP/UDP listen
            // address, so validate their local-interface requirements instead.
            if matches!(rule.listen_proto, Proto::Uds | Proto::Shm) {
                if rule.app_id.as_deref().unwrap_or("").is_empty() {
                    return Err(format!(
                        "Rule '{}' (index {}): {} rules require a non-empty \"app_id\"",
                        rule.name, i, rule.listen_proto
                    ));
                }
                if rule.allowed_uids.is_empty() {
                    return Err(format!(
                        "Rule '{}' (index {}): {} rules require at least one uid in \"allowed_uids\" \
                         (an empty list disables the local interface)",
                        rule.name, i, rule.listen_proto
                    ));
                }
            } else {
                let listen_sock: SocketAddr = rule.listen_addr.parse::<SocketAddr>().map_err(|e| {
                    format!(
                        "Rule '{}' (index {}): invalid listen_addr '{}': {}",
                        rule.name, i, rule.listen_addr, e
                    )
                })?;

                // Duplicate listen addresses (same proto+addr = port conflict)
                let listen_key = format!("{}:{}", rule.listen_proto, listen_sock);
                if !seen_listen.insert(listen_key.clone()) {
                    return Err(format!(
                        "Rule '{}' (index {}): listen address {} ({}) conflicts with another rule",
                        rule.name, i, rule.listen_addr, rule.listen_proto
                    ));
                }
            }

            // Validate upstream address (host:port format) unless "auto"
            if rule.upstream_addr != "auto" && !rule.upstream_addr.contains(':') {
                return Err(format!(
                    "Rule '{}' (index {}): upstream_addr '{}' must be 'auto' or HOST:PORT",
                    rule.name, i, rule.upstream_addr
                ));
            }

            // "auto" upstream requires transparent mode
            if rule.upstream_addr == "auto" && !rule.transparent {
                return Err(format!(
                    "Rule '{}' (index {}): upstream_addr 'auto' requires transparent = true",
                    rule.name, i
                ));
            }

            // DTLS validation: DTLS is UDP-only
            if rule.tls_mode == TlsMode::Dtls && rule.listen_proto != Proto::Udp {
                return Err(format!(
                    "Rule '{}' (index {}): DTLS mode requires listen_proto = \"udp\"",
                    rule.name, i
                ));
            }

            // kTLS capability gate: kernel TLS cannot offload NULL-encryption
            // (integrity-only) cipher suites. Reject at load so the error is
            // surfaced early instead of at connection time. Other non-offloadable
            // profiles (PKI/PSK/verify) fall back to userspace TLS at runtime.
            let is_ktls = rule.effective_security_provider() == "ktls"
                || (rule.tls_mode == TlsMode::Ktls
                    && rule.effective_security_provider() == "tls");
            if is_ktls {
                if let Some(profile) =
                    rule.provider_params.get("profile").and_then(|v| v.as_str())
                {
                    if matches!(profile, "integrity-only" | "integrity" | "null") {
                        return Err(format!(
                            "Rule '{}' (index {}): kTLS cannot offload integrity-only (NULL) \
                             cipher suites; use security_provider = \"tls\" instead",
                            rule.name, i
                        ));
                    }
                }
            }

            // Buffer config validation
            if rule.buffer_slots == 0 {
                return Err(format!(
                    "Rule '{}' (index {}): buffer_slots must be > 0",
                    rule.name, i
                ));
            }
            if rule.buffer_slot_size == 0 {
                return Err(format!(
                    "Rule '{}' (index {}): buffer_slot_size must be > 0",
                    rule.name, i
                ));
            }

            // DSCP tag must be a valid 6-bit DiffServ code point (0..=63).
            if let Some(dscp) = rule.dscp_tag {
                if dscp > 63 {
                    return Err(format!(
                        "Rule '{}' (index {}): dscp_tag {} is out of range (valid DSCP is 0..=63)",
                        rule.name, i, dscp
                    ));
                }
            }

            // TLS/kTLS run over TCP, so a UDP upstream is invalid for them.
            // DTLS and custom datagram providers (UDP-native) are exempt.
            let provider = rule.effective_security_provider();
            if rule.direction == Direction::Encrypt
                && (provider == "tls" || provider == "ktls")
                && rule.upstream_proto == Proto::Udp
            {
                return Err(format!(
                    "Rule '{}' (index {}): encrypt with TLS/kTLS requires a TCP upstream (use DTLS or a UDP datagram provider for UDP-to-UDP)",
                    rule.name, i
                ));
            }
        }

        // Validate traffic rules address patterns
        for (i, tr) in self.traffic_rules.iter().enumerate() {
            AddressPattern::parse(&tr.source).map_err(|e| {
                format!(
                    "traffic_rules[{}]: invalid source '{}': {}",
                    i, tr.source, e
                )
            })?;
            AddressPattern::parse(&tr.destination).map_err(|e| {
                format!(
                    "traffic_rules[{}]: invalid destination '{}': {}",
                    i, tr.destination, e
                )
            })?;
        }

        // Validate policy whitelist address patterns
        if let Some(ref policy) = self.policy {
            for (i, entry) in policy.whitelist.iter().enumerate() {
                AddressPattern::parse(&entry.source).map_err(|e| {
                    format!(
                        "policy.whitelist[{}]: invalid source '{}': {}",
                        i, entry.source, e
                    )
                })?;
                AddressPattern::parse(&entry.destination).map_err(|e| {
                    format!(
                        "policy.whitelist[{}]: invalid destination '{}': {}",
                        i, entry.destination, e
                    )
                })?;
            }
        }

        Ok(())
    }

    /// Run deep preflight checks that go beyond JSON parsing.
    /// Returns a list of warnings (non-fatal) and errors (fatal).
    pub fn preflight_check(&self) -> (Vec<String>, Vec<String>) {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // Check for kTLS kernel support
        let has_ktls_rules = self
            .rules
            .iter()
            .any(|r| r.effective_security_provider() == "ktls");
        if has_ktls_rules {
            if fs::metadata("/proc/modules").is_ok() {
                let modules = fs::read_to_string("/proc/modules").unwrap_or_default();
                if !modules.contains("tls ") && !modules.contains("tls\t") {
                    // Also check built-in via /proc/net/
                    if fs::metadata("/proc/sys/net/tls").is_err() {
                        warnings.push(
                            "kTLS rules configured but kernel TLS module not loaded \
                             (try: modprobe tls). kTLS will fall back to userspace TLS."
                                .to_string(),
                        );
                    }
                }
            }
        }

        // Check for transparent/TPROXY requirements
        let has_transparent = self.rules.iter().any(|r| r.transparent);
        if has_transparent {
            // Check CAP_NET_ADMIN via a simple test
            // (trying IP_TRANSPARENT on a throwaway socket)
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd >= 0 {
                let one: libc::c_int = 1;
                let ret = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_IP,
                        19, // IP_TRANSPARENT
                        &one as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                unsafe {
                    libc::close(fd);
                }
                if ret != 0 {
                    errors.push(
                        "Transparent rules require CAP_NET_ADMIN capability. \
                         Run as root or use: setcap cap_net_admin,cap_net_raw+ep <binary>"
                            .to_string(),
                    );
                }
            }

            // Check iptables chains exist
            Self::check_iptables_chain("nat", "SCG_ENCRYPT", &mut warnings);
            Self::check_iptables_chain("mangle", "SCG_DECRYPT", &mut warnings);

            // Check TPROXY routing policy
            if let Ok(rules) = std::process::Command::new("ip")
                .args(["rule", "show"])
                .output()
            {
                let out = String::from_utf8_lossy(&rules.stdout);
                if !out.contains("fwmark") || !out.contains("lookup 100") {
                    warnings.push(
                        "TPROXY routing policy not found (ip rule fwmark 1 lookup 100). \
                         Incoming decrypt via TPROXY will not work without it. \
                         Run setup_gateway.sh or: ip rule add fwmark 1 lookup 100"
                            .to_string(),
                    );
                }
            }
        }

        // Check for port conflicts with system listeners
        for rule in &self.rules {
            if let Ok(_addr) = rule.listen_addr.parse::<SocketAddr>() {
                let port = _addr.port();
                let proto = &rule.listen_proto;
                // Try a quick bind to see if the port is available
                let available = match proto {
                    Proto::Tcp => std::net::TcpListener::bind(&rule.listen_addr).is_ok(),
                    Proto::Udp => std::net::UdpSocket::bind(&rule.listen_addr).is_ok(),
                    // UDS/SHM endpoints are not network ports and are created
                    // dynamically; they never reach this `SocketAddr` branch.
                    Proto::Uds | Proto::Shm => true,
                };
                if !available {
                    warnings.push(format!(
                        "Rule '{}': port {} ({}) is already in use — \
                         the gateway may fail to start this rule or is already running",
                        rule.name, port, proto
                    ));
                }
            }
        }

        // Check for extreme geo-delay values
        for rule in &self.rules {
            if rule.simulated_delay_ms > 10000 {
                warnings.push(format!(
                    "Rule '{}': simulated_delay_ms is {} ms (>10s) — this will severely throttle throughput",
                    rule.name, rule.simulated_delay_ms
                ));
            }
        }

        // Validate protocol_version per rule
        for rule in &self.rules {
            if let Some(ref version) = rule.protocol_version {
                let sp = rule.effective_security_provider();
                match sp {
                    "tls" | "ktls" => {
                        match version.as_str() {
                            "tls1.2" | "tls1.3" => {}
                            _ => {
                                errors.push(format!(
                                    "Rule '{}': invalid protocol_version '{}' for {} provider (expected 'tls1.2' or 'tls1.3')",
                                    rule.name, version, sp
                                ));
                            }
                        }
                        if sp == "ktls" && version == "tls1.3" {
                            warnings.push(format!(
                                "Rule '{}': kTLS + TLS 1.3 is not reliably supported by all kernels — will fall back to TLS 1.2 at runtime",
                                rule.name
                            ));
                        }
                    }
                    "dtls" => match version.as_str() {
                        "dtls1.0" | "dtls1.2" => {}
                        _ => {
                            errors.push(format!(
                                    "Rule '{}': invalid protocol_version '{}' for dtls provider (expected 'dtls1.0' or 'dtls1.2')",
                                    rule.name, version
                                ));
                        }
                    },
                    _ => {}
                }
            }
        }

        (warnings, errors)
    }

    fn check_iptables_chain(table: &str, chain: &str, warnings: &mut Vec<String>) {
        match std::process::Command::new("iptables")
            .args(["-t", table, "-L", chain, "-n"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        {
            Ok(status) if !status.success() => {
                warnings.push(format!(
                    "iptables chain '{}' not found in {} table. \
                     Traffic interception will not work. Run setup_gateway.sh to configure.",
                    chain, table
                ));
            }
            Err(_) => {
                warnings.push(
                    "iptables command not found — cannot verify traffic interception rules."
                        .to_string(),
                );
            }
            _ => {} // chain exists
        }
    }

    /// Print a summary of all rules to stderr.
    pub fn print_summary(&self) {
        info!("=== Gateway Proxy Configuration ===");
        info!("  Sock buf:    {} KiB", self.sock_buf_size / 1024);
        info!("  Rules:       {}", self.rules.len());
        if !self.traffic_rules.is_empty() {
            info!("  Traffic rules: {}", self.traffic_rules.len());
        }
        if let Some(ref policy) = self.policy {
            info!(
                "  Policy:      default={:?}, {} whitelist entries",
                policy.default_action,
                policy.whitelist.len()
            );
        }
        if let Some(ref cache) = self.cache {
            info!(
                "  Cache:       max={}, ttl={}s",
                cache.max_entries, cache.ttl_secs
            );
        }
        info!("");

        for (i, rule) in self.rules.iter().enumerate() {
            let class_tag = if rule.traffic_class != TrafficClass::Normal {
                format!(" [{}]", rule.traffic_class)
            } else {
                String::new()
            };
            info!(
                "  Rule #{}: \"{}\" ({}) [priority={}]{}",
                i, rule.name, rule.direction, rule.priority, class_tag
            );
            let sp = rule.effective_security_provider();
            let upstream = if rule.upstream_addr == "auto" {
                "auto (SO_ORIGINAL_DST)".to_string()
            } else {
                rule.upstream_addr.clone()
            };
            match rule.direction {
                Direction::Encrypt => {
                    info!(
                        "    {} {} -> {} ({})",
                        rule.listen_proto, rule.listen_addr, upstream, sp,
                    );
                }
                Direction::Decrypt => {
                    info!(
                        "    {}/{} {} -> {} {}",
                        sp, rule.listen_proto, rule.listen_addr, rule.upstream_proto, upstream,
                    );
                }
            }
            if rule.transparent {
                info!("    [TPROXY transparent mode]");
            }
            if rule.simulated_delay_ms > 0 {
                info!("    [Geo delay: {} ms per packet]", rule.simulated_delay_ms);
            }
            if let Some(ref version) = rule.protocol_version {
                info!("    [Protocol: {}]", version);
            }
        }
        info!("===================================");
    }

    /// Diff two configs: return (added_rules, removed_rules, unchanged_rules).
    /// Rules are matched by name.
    pub fn diff(&self, new: &GatewayConfig) -> ConfigDiff {
        let old_names: Vec<&str> = self.rules.iter().map(|r| r.name.as_str()).collect();
        let new_names: Vec<&str> = new.rules.iter().map(|r| r.name.as_str()).collect();

        let added: Vec<RuleConfig> = new
            .rules
            .iter()
            .filter(|r| !old_names.contains(&r.name.as_str()))
            .cloned()
            .collect();

        let removed: Vec<String> = self
            .rules
            .iter()
            .filter(|r| !new_names.contains(&r.name.as_str()))
            .map(|r| r.name.clone())
            .collect();

        let unchanged: Vec<String> = self
            .rules
            .iter()
            .filter(|r| new_names.contains(&r.name.as_str()))
            .map(|r| r.name.clone())
            .collect();

        ConfigDiff {
            added,
            removed,
            unchanged,
        }
    }
}

/// Result of diffing two configurations.
#[derive(Debug)]
pub struct ConfigDiff {
    pub added: Vec<RuleConfig>,
    pub removed: Vec<String>,
    pub unchanged: Vec<String>,
}

/// Decode a hex string to bytes. Assumes valid hex (validated by config validation).
pub fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[cfg(test)]
mod dscp_tests {
    use super::*;

    fn rule_from_json(extra: serde_json::Value) -> RuleConfig {
        let mut base = serde_json::json!({
            "name": "r",
            "direction": "encrypt",
            "listen_addr": "127.0.0.1:8080"
        });
        if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                b.insert(k.clone(), v.clone());
            }
        }
        serde_json::from_value(base).expect("deserialize rule")
    }

    #[test]
    fn explicit_tag_overrides_preserve_and_class() {
        let rule = rule_from_json(serde_json::json!({
            "traffic_class": "normal",
            "dscp_tag": 26,
            "preserve_inbound_dscp": true
        }));
        // Explicit tag wins over both preservation and the class default.
        assert_eq!(rule.egress_dscp(Some(10)), Some(26));
        assert!(!rule.needs_inbound_dscp());
    }

    #[test]
    fn safety_defaults_to_ef_and_priority() {
        let rule = rule_from_json(serde_json::json!({ "traffic_class": "safety" }));
        assert_eq!(rule.egress_dscp(None), Some(DSCP_EF));
        assert_eq!(rule.so_priority(), SAFETY_SO_PRIORITY);
    }

    #[test]
    fn normal_defaults_to_none_and_zero_priority() {
        let rule = rule_from_json(serde_json::json!({ "traffic_class": "normal" }));
        assert_eq!(rule.egress_dscp(None), None);
        assert_eq!(rule.so_priority(), 0);
    }

    #[test]
    fn preserve_uses_sampled_then_falls_back() {
        let normal = rule_from_json(serde_json::json!({
            "traffic_class": "normal",
            "preserve_inbound_dscp": true
        }));
        assert!(normal.needs_inbound_dscp());
        assert_eq!(normal.egress_dscp(Some(18)), Some(18));
        assert_eq!(normal.egress_dscp(None), None); // no sample → class default

        let safety = rule_from_json(serde_json::json!({
            "traffic_class": "safety",
            "preserve_inbound_dscp": true
        }));
        assert_eq!(safety.egress_dscp(Some(18)), Some(18)); // preserve sampled
        assert_eq!(safety.egress_dscp(None), Some(DSCP_EF)); // fallback EF
    }

    #[test]
    fn validate_rejects_out_of_range_dscp() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "bad",
                "direction": "encrypt",
                "listen_addr": "127.0.0.1:8081",
                "upstream_addr": "127.0.0.1:9000",
                "dscp_tag": 64
            }]
        }))
        .expect("deserialize config");
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("dscp_tag"), "unexpected error: {err}");
    }

    #[test]
    fn validate_accepts_valid_dscp() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "ok",
                "direction": "encrypt",
                "listen_addr": "127.0.0.1:8082",
                "upstream_addr": "127.0.0.1:9000",
                "dscp_tag": 46
            }]
        }))
        .expect("deserialize config");
        assert!(cfg.validate().is_ok());
    }
}
