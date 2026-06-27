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

    /// Global performance profile controlling how the data plane trades
    /// throughput against latency. Individual rules may override it via their
    /// own `perf_profile`. Default: `balanced` (the historical behaviour).
    #[serde(default)]
    pub perf_profile: PerfProfile,

    /// Prefer kernel TLS (kTLS) over userspace OpenSSL on the encrypted fast
    /// path. When `true` (the default), a rule configured for userspace `tls`
    /// whose crypto parameters are kTLS-offloadable (default profile,
    /// server-authenticated AES-GCM, no PSK) is transparently upgraded to the
    /// zero-copy kTLS engine on hosts that expose the `tls` ULP. Hosts without
    /// kTLS support, and rules that require userspace features (peer
    /// verification, PSK, custom ciphers), stay on userspace TLS automatically.
    #[serde(default = "default_prefer_ktls")]
    pub prefer_ktls: bool,
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
    /// (default: 1 MiB). Enlarging the ring trades queueing latency for
    /// throughput headroom, so it is left to per-deployment config.
    #[serde(default = "default_shm_ring_capacity")]
    pub shm_ring_capacity: usize,

    /// Shared-memory ring data structure to use for new SHM endpoints.
    /// `byte_stream` (default) is the variable-length packed ring; `slot` is
    /// the fixed-slot Vyukov ring (cache-line-separated indices, wake-on-empty).
    #[serde(default)]
    pub shm_ring_kind: ShmRingKind,

    /// Slot ring only: bytes per segment slot, rounded up to a 64-byte multiple
    /// (default: 2048). Must be at least the largest expected frame + 8 bytes.
    #[serde(default = "default_shm_segment_size")]
    pub shm_segment_size: usize,

    /// Slot ring only: number of segments per ring, rounded up to a power of
    /// two (default: 512). Fewer/smaller slots lower queueing latency; more/
    /// larger slots raise throughput headroom.
    #[serde(default = "default_shm_num_segments")]
    pub shm_num_segments: usize,

    /// Slot ring only: the gateway→client (client receive) wakeup mechanism.
    /// `eventfd` (default) is pollable; `futex` has lower wakeup latency and is
    /// paired with a client-side spin-then-park. The client→gateway direction
    /// always uses an eventfd so the gateway relay can multiplex it.
    #[serde(default)]
    pub shm_g2c_notify: ShmNotify,

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
            shm_ring_kind: ShmRingKind::default(),
            shm_segment_size: default_shm_segment_size(),
            shm_num_segments: default_shm_num_segments(),
            shm_g2c_notify: ShmNotify::default(),
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

fn default_shm_segment_size() -> usize {
    2048
}

fn default_shm_num_segments() -> usize {
    512
}

/// Shared-memory ring data structure selected for SHM endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShmRingKind {
    /// Variable-length packed byte-stream ring ([`scg_ipc::shm`]).
    #[default]
    ByteStream,
    /// Fixed-slot Vyukov ring ([`scg_ipc::shm_slot`]).
    Slot,
}

/// Client-receive (gateway→client) wakeup mechanism for the slot ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShmNotify {
    /// Pollable `eventfd` notifier (the default, also used by the byte-stream
    /// ring).
    #[default]
    Eventfd,
    /// Futex on the slot ring's control-page notify word; lower wakeup latency.
    Futex,
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

fn default_prefer_ktls() -> bool {
    true
}

/// Resolve the effective crypto provider name, applying the kTLS preference.
///
/// Two complementary, mutually-exclusive adjustments are made to the
/// `configured` provider so the gateway always runs the best safe engine:
///
/// * a `ktls` rule whose parameters are **not** offloadable (a non-default
///   profile, peer verification, or PSK) is downgraded to userspace `tls`,
/// * a userspace `tls` rule whose parameters **are** offloadable is upgraded to
///   `ktls` when `prefer_ktls` is set and the kernel exposes the `tls` ULP
///   (`kernel_ktls`), making the zero-copy fast path the default.
///
/// Any other provider (`dtls`, `routing`, custom) is returned unchanged.
pub fn resolve_crypto_provider(
    configured: &str,
    offloadable: bool,
    prefer_ktls: bool,
    kernel_ktls: bool,
) -> &str {
    match configured {
        "ktls" if !offloadable => "tls",
        "tls" if prefer_ktls && offloadable && kernel_ktls => "ktls",
        other => other,
    }
}

// ─── Performance profile ─────────────────────────────────────────────────────

/// High-level performance profile selecting how the data plane balances
/// throughput against latency. It maps to a set of low-level relay knobs
/// ([`PerfKnobs`]) resolved per rule: write coalescing via `TCP_CORK` and a
/// short SHM-ring busy-poll window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfProfile {
    /// Maximise throughput: coalesce consecutive writes (`TCP_CORK`) and never
    /// busy-poll.
    Throughput,
    /// Minimise latency: flush each write immediately (no cork) and briefly
    /// busy-poll the SHM ring before blocking on the eventfd.
    Latency,
    /// Balanced default: coalesce writes but do not burn CPU busy-polling.
    #[default]
    Balanced,
}

/// Default SHM ring busy-poll window (microseconds) applied by the `latency`
/// profile when a rule does not set `spin_wait_us` explicitly.
const LATENCY_SPIN_WAIT_US: u64 = 50;

/// Default `SO_BUSY_POLL` / pre-poll spin window (microseconds) applied by the
/// `latency` profile to the TCP data path, trading a little CPU for lower
/// wakeup latency on the relay sockets.
const LATENCY_BUSY_POLL_US: u32 = 50;

// ── Per-profile data-path buffer sizing ─────────────────────────────────────
//
// The `throughput` profile keeps the historical large buffers (16 MiB sockets,
// 16 MiB splice pipes, 4 MiB userspace-TLS relay buffers) for maximum bulk
// bandwidth. `latency` shrinks them aggressively to bound in-flight queueing
// (the dominant source of bufferbloat latency through the proxy); `balanced`
// sits in between. Socket buffers are expressed as caps clamped against the
// configured `sock_buf_size`; pipe and relay buffers are absolute sizes.

/// Splice pipe capacity per profile (bytes).
const THROUGHPUT_PIPE_SIZE: usize = 16 * 1024 * 1024;
const BALANCED_PIPE_SIZE: usize = 8 * 1024 * 1024;
const LATENCY_PIPE_SIZE: usize = 256 * 1024;

/// Userspace-TLS relay buffer size per profile (bytes).
const THROUGHPUT_RELAY_BUF: usize = 4 * 1024 * 1024;
const BALANCED_RELAY_BUF: usize = 2 * 1024 * 1024;
const LATENCY_RELAY_BUF: usize = 256 * 1024;

/// Socket-buffer cap per profile (bytes). The effective `SO_SNDBUF`/`SO_RCVBUF`
/// is `min(configured sock_buf_size, cap)`, so an explicitly small global
/// `sock_buf_size` still wins over the profile default.
const BALANCED_SOCK_BUF_CAP: usize = 8 * 1024 * 1024;
const LATENCY_SOCK_BUF_CAP: usize = 256 * 1024;

/// `TCP_NOTSENT_LOWAT` target per profile (bytes). Bounds the unsent bytes the
/// kernel keeps queued before signalling writability, trimming local queueing
/// latency. `None` leaves the kernel default (the `throughput` profile).
const BALANCED_NOTSENT_LOWAT: usize = 2 * 1024 * 1024;
const LATENCY_NOTSENT_LOWAT: usize = 16 * 1024;

/// Target local queueing budget for opt-in BDP-adaptive latency sizing.
const DEFAULT_BDP_QUEUE_BUDGET_US: u64 = 1_000;

/// Low-level relay knobs resolved from a [`PerfProfile`] together with a rule's
/// explicit overrides. Cheap to copy; carried on the rule's hot path.
#[derive(Debug, Clone, Copy)]
pub struct PerfKnobs {
    /// Coalesce consecutive writes with `TCP_CORK` before flushing.
    pub enable_cork: bool,
    /// Microseconds to busy-poll the SHM ring before blocking on the eventfd.
    pub spin_wait_us: u64,
    /// Effective `SO_SNDBUF`/`SO_RCVBUF` for this rule's TCP sockets (bytes).
    pub sock_buf_size: usize,
    /// Splice pipe capacity for the zero-copy (routing / kTLS) path (bytes).
    pub pipe_size: usize,
    /// Userspace-TLS relay buffer size (bytes).
    pub relay_buf_size: usize,
    /// `TCP_NOTSENT_LOWAT` target, or `None` to leave the kernel default.
    pub notsent_lowat: Option<usize>,
    /// `SO_BUSY_POLL` / pre-poll spin window for the TCP data path (µs).
    pub busy_poll_us: u32,
    /// Re-tune socket/pipe depths from observed bandwidth-delay product.
    pub bdp_adaptive: bool,
    /// Target local queueing budget used by BDP-adaptive sizing (µs).
    pub bdp_queue_budget_us: u64,
}

impl PerfKnobs {
    /// Resolve the effective knobs for a rule. A non-zero `simulated_delay_ms`
    /// forces cork off (geo-delay needs each packet flushed immediately) and an
    /// explicit non-zero `spin_wait_us` always wins over the profile default.
    /// `sock_buf_size` is the configured (global) socket-buffer size, clamped
    /// down per profile so the `latency` profile cannot bufferbloat.
    pub fn resolve(
        profile: PerfProfile,
        simulated_delay_ms: u64,
        spin_wait_us: u64,
        sock_buf_size: usize,
    ) -> Self {
        let enable_cork = simulated_delay_ms == 0 && profile != PerfProfile::Latency;
        let spin_wait_us = if spin_wait_us > 0 {
            spin_wait_us
        } else if profile == PerfProfile::Latency {
            LATENCY_SPIN_WAIT_US
        } else {
            0
        };
        let (pipe_size, relay_buf_size, sock_cap, notsent_lowat, busy_poll_us) = match profile {
            PerfProfile::Throughput => (
                THROUGHPUT_PIPE_SIZE,
                THROUGHPUT_RELAY_BUF,
                usize::MAX,
                None,
                0,
            ),
            PerfProfile::Balanced => (
                BALANCED_PIPE_SIZE,
                BALANCED_RELAY_BUF,
                BALANCED_SOCK_BUF_CAP,
                Some(BALANCED_NOTSENT_LOWAT),
                0,
            ),
            PerfProfile::Latency => (
                LATENCY_PIPE_SIZE,
                LATENCY_RELAY_BUF,
                LATENCY_SOCK_BUF_CAP,
                Some(LATENCY_NOTSENT_LOWAT),
                LATENCY_BUSY_POLL_US,
            ),
        };
        PerfKnobs {
            enable_cork,
            spin_wait_us,
            sock_buf_size: sock_buf_size.min(sock_cap),
            pipe_size,
            relay_buf_size,
            notsent_lowat,
            busy_poll_us,
            bdp_adaptive: false,
            bdp_queue_budget_us: DEFAULT_BDP_QUEUE_BUDGET_US,
        }
    }

    /// Apply explicit rule-level low-level overrides on top of the profile
    /// defaults. `notsent_lowat = Some(0)` deliberately disables the option.
    fn with_rule_overrides(
        mut self,
        sock_buf_size: Option<usize>,
        pipe_size: Option<usize>,
        relay_buf_size: Option<usize>,
        notsent_lowat: Option<usize>,
        busy_poll_us: Option<u32>,
        bdp_adaptive: bool,
        bdp_queue_budget_us: Option<u64>,
    ) -> Self {
        if let Some(value) = sock_buf_size {
            self.sock_buf_size = value;
        }
        if let Some(value) = pipe_size {
            self.pipe_size = value;
        }
        if let Some(value) = relay_buf_size {
            self.relay_buf_size = value;
        }
        if let Some(value) = notsent_lowat {
            self.notsent_lowat = (value != 0).then_some(value);
        }
        if let Some(value) = busy_poll_us {
            self.busy_poll_us = value;
        }
        self.bdp_adaptive = bdp_adaptive;
        if let Some(value) = bdp_queue_budget_us {
            self.bdp_queue_budget_us = value;
        }
        self
    }
}

// ─── Intercept (firewall self-configuration) ────────────────────────────────

/// Firewall interception mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptMode {
    /// nat/PREROUTING REDIRECT (inbound traffic on an interface/port → gateway listen port).
    IngressRedirect,
    /// nat/OUTPUT REDIRECT (outbound traffic to specific destinations → gateway listen port).
    EgressRedirect,
    /// mangle/PREROUTING TPROXY (inbound traffic → gateway transparent listener).
    Tproxy,
}

impl fmt::Display for InterceptMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InterceptMode::IngressRedirect => write!(f, "ingress_redirect"),
            InterceptMode::EgressRedirect => write!(f, "egress_redirect"),
            InterceptMode::Tproxy => write!(f, "tproxy"),
        }
    }
}

/// Per-rule firewall interception configuration.
///
/// When present, the gateway will install iptables rules at startup to redirect
/// matching traffic to this rule's listen port, and tear them down on shutdown.
/// Requires `CAP_NET_ADMIN`.
#[derive(Debug, Clone, Deserialize)]
pub struct InterceptConfig {
    /// Interception mode (determines which iptables table/chain/target is used).
    pub mode: InterceptMode,

    /// Network interface for ingress matching (e.g. "eth0"). Only used with
    /// `ingress_redirect` mode. When omitted, matches on all interfaces.
    #[serde(default)]
    pub in_interface: Option<String>,

    /// Destination ports to intercept (e.g. "8080", "4465:4467", "80,443").
    /// Comma-separated port numbers or ranges. Required for all modes.
    pub match_dports: String,

    /// Destination IP addresses/CIDRs for egress redirect (e.g. ["192.168.1.2", "10.0.0.0/24"]).
    /// Required for `egress_redirect` mode.
    #[serde(default)]
    pub match_dst: Vec<String>,

    /// Source IP addresses/CIDRs for TPROXY (e.g. ["192.168.1.0/24"]).
    /// Required for `tproxy` mode.
    #[serde(default)]
    pub match_src: Vec<String>,

    /// IP protocol to match. Defaults to the rule's `listen_proto` (tcp or udp).
    #[serde(default)]
    pub protocol: Option<String>,
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

    /// Enable zero-copy relay path (splice for routing, sendfile for kTLS).
    /// Only valid when `security_provider` is `"routing"` or `"ktls"`;
    /// userspace TLS cannot be zero-copy. Default: false.
    #[serde(default)]
    pub zero_copy: bool,

    /// Busy-poll microseconds before blocking on the SHM ring eventfd/futex.
    /// Only meaningful for `listen_proto: "shm"` rules. A value of 0 (default)
    /// means block immediately; higher values trade CPU for lower wakeup latency.
    /// When unset, the `latency` perf profile supplies a small default.
    #[serde(default)]
    pub spin_wait_us: u64,

    /// Optional per-rule performance profile override. When unset, the rule
    /// inherits the gateway-level `perf_profile`.
    #[serde(default)]
    pub perf_profile: Option<PerfProfile>,

    /// Optional per-rule `SO_SNDBUF`/`SO_RCVBUF` override in bytes. When unset,
    /// the selected performance profile supplies the socket-buffer size.
    #[serde(default)]
    pub sock_buf_size: Option<usize>,

    /// Optional per-rule splice pipe/chunk override in bytes.
    #[serde(default)]
    pub pipe_size: Option<usize>,

    /// Optional per-rule userspace relay buffer override in bytes.
    #[serde(default)]
    pub relay_buf_size: Option<usize>,

    /// Optional per-rule `TCP_NOTSENT_LOWAT` override in bytes. A value of `0`
    /// disables `TCP_NOTSENT_LOWAT` even when the selected profile would set it.
    #[serde(default)]
    pub notsent_lowat: Option<usize>,

    /// Optional per-rule `SO_BUSY_POLL` / pre-poll spin override in microseconds.
    #[serde(default)]
    pub busy_poll_us: Option<u32>,

    /// Opt in to bandwidth-delay-product adaptive socket/pipe sizing. Currently
    /// active only on the `latency` profile; other profiles keep fixed depths.
    #[serde(default)]
    pub bdp_adaptive: bool,

    /// Target local queueing budget for BDP-adaptive sizing in microseconds.
    /// Default: 1000 µs.
    #[serde(default)]
    pub bdp_queue_budget_us: Option<u64>,

    /// Firewall interception configuration. When present, the gateway will
    /// install iptables rules at startup to redirect matching traffic to this
    /// rule's listen port and tear them down on graceful shutdown.
    /// Requires `CAP_NET_ADMIN`. Mutually exclusive with UDS/SHM listen_proto.
    #[serde(default)]
    pub intercept: Option<InterceptConfig>,
}

impl RuleConfig {
    /// Resolve this rule's performance knobs, inheriting `global` when the rule
    /// does not specify its own `perf_profile`. `sock_buf_size` is the
    /// gateway-level socket-buffer size, clamped down per profile.
    pub fn perf_knobs(&self, global: PerfProfile, sock_buf_size: usize) -> PerfKnobs {
        let profile = self.perf_profile.unwrap_or(global);
        PerfKnobs::resolve(
            profile,
            self.simulated_delay_ms,
            self.spin_wait_us,
            sock_buf_size,
        )
        .with_rule_overrides(
            self.sock_buf_size,
            self.pipe_size,
            self.relay_buf_size,
            self.notsent_lowat,
            self.busy_poll_us,
            self.bdp_adaptive && profile == PerfProfile::Latency,
            self.bdp_queue_budget_us,
        )
    }

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
                let listen_sock: SocketAddr =
                    rule.listen_addr.parse::<SocketAddr>().map_err(|e| {
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
                || (rule.tls_mode == TlsMode::Ktls && rule.effective_security_provider() == "tls");
            if is_ktls {
                if let Some(profile) = rule.provider_params.get("profile").and_then(|v| v.as_str())
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

            // TLS/kTLS security-parameter validation at load time. Parse the
            // rule's provider_params exactly as the runtime engine will, so
            // misconfigurations — an omitted `verify` mode (fail-secure), an
            // unpaired cert/key, or invalid PSK settings — are surfaced at config
            // load instead of at the first connection.
            {
                let provider = rule.effective_security_provider();
                if provider == "tls" || provider == "ktls" {
                    crate::security::tls_engine::params::TlsSecurityParams::from_params(
                        &rule.provider_params,
                        rule.protocol_version.as_deref(),
                    )
                    .map_err(|e| {
                        format!(
                            "Rule '{}' (index {}): invalid TLS parameters: {}",
                            rule.name, i, e
                        )
                    })?;
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

            // zero_copy is only meaningful for routing (splice) and ktls (sendfile).
            // Userspace TLS must decrypt into a buffer — zero-copy is impossible.
            if rule.zero_copy {
                let provider = rule.effective_security_provider();
                if provider != "routing" && provider != "ktls" {
                    return Err(format!(
                        "Rule '{}' (index {}): zero_copy requires security_provider \
                         \"routing\" or \"ktls\" (userspace TLS cannot be zero-copy)",
                        rule.name, i
                    ));
                }
            }

            // spin_wait_us is only meaningful for SHM rules.
            if rule.spin_wait_us > 0 && rule.listen_proto != Proto::Shm {
                return Err(format!(
                    "Rule '{}' (index {}): spin_wait_us > 0 is only valid for \
                     listen_proto = \"shm\" rules",
                    rule.name, i
                ));
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

            // ── Intercept configuration validation ──────────────────────────
            if let Some(ref intercept) = rule.intercept {
                // Intercept is not valid for UDS/SHM local-only rules.
                if matches!(rule.listen_proto, Proto::Uds | Proto::Shm) {
                    return Err(format!(
                        "Rule '{}' (index {}): intercept cannot be used with {} listen_proto",
                        rule.name, i, rule.listen_proto
                    ));
                }

                // TPROXY intercept requires transparent = true on the rule.
                if intercept.mode == InterceptMode::Tproxy && !rule.transparent {
                    return Err(format!(
                        "Rule '{}' (index {}): intercept mode 'tproxy' requires transparent = true",
                        rule.name, i
                    ));
                }

                // match_dports is required for all modes.
                if intercept.match_dports.trim().is_empty() {
                    return Err(format!(
                        "Rule '{}' (index {}): intercept.match_dports must not be empty",
                        rule.name, i
                    ));
                }

                // Validate port spec syntax (comma-separated port numbers or ranges).
                Self::validate_port_spec(&intercept.match_dports).map_err(|e| {
                    format!(
                        "Rule '{}' (index {}): intercept.match_dports: {}",
                        rule.name, i, e
                    )
                })?;

                // egress_redirect requires at least one match_dst.
                if intercept.mode == InterceptMode::EgressRedirect && intercept.match_dst.is_empty()
                {
                    return Err(format!(
                        "Rule '{}' (index {}): intercept mode 'egress_redirect' requires at least one match_dst",
                        rule.name, i
                    ));
                }

                // tproxy requires at least one match_src OR match_dports.
                if intercept.mode == InterceptMode::Tproxy && intercept.match_src.is_empty() {
                    return Err(format!(
                        "Rule '{}' (index {}): intercept mode 'tproxy' requires at least one match_src",
                        rule.name, i
                    ));
                }

                // Validate match_dst entries as IP/CIDR.
                for (j, dst) in intercept.match_dst.iter().enumerate() {
                    Self::validate_ip_or_cidr(dst).map_err(|e| {
                        format!(
                            "Rule '{}' (index {}): intercept.match_dst[{}] '{}': {}",
                            rule.name, i, j, dst, e
                        )
                    })?;
                }

                // Validate match_src entries as IP/CIDR.
                for (j, src) in intercept.match_src.iter().enumerate() {
                    Self::validate_ip_or_cidr(src).map_err(|e| {
                        format!(
                            "Rule '{}' (index {}): intercept.match_src[{}] '{}': {}",
                            rule.name, i, j, src, e
                        )
                    })?;
                }

                // Validate protocol if specified.
                if let Some(ref proto) = intercept.protocol {
                    if proto != "tcp" && proto != "udp" {
                        return Err(format!(
                            "Rule '{}' (index {}): intercept.protocol must be \"tcp\" or \"udp\" (got \"{}\")",
                            rule.name, i, proto
                        ));
                    }
                }
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

        // ── Intercept self-configuration preflight ──────────────────────────
        let has_intercept = self.rules.iter().any(|r| r.intercept.is_some());
        if has_intercept {
            // CAP_NET_ADMIN is mandatory when intercept is configured.
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
                        "Intercept rules configured but CAP_NET_ADMIN is missing. \
                         The gateway cannot install iptables rules without it. \
                         Run as root or use: setcap cap_net_admin,cap_net_raw+ep <binary>"
                            .to_string(),
                    );
                }
            }

            // iptables binary must exist when self-configuring.
            match std::process::Command::new("iptables")
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
            {
                Err(_) => {
                    errors.push(
                        "Intercept rules configured but 'iptables' command not found. \
                         Install iptables or remove the intercept configuration."
                            .to_string(),
                    );
                }
                _ => {}
            }

            // ip command needed for TPROXY routing policy.
            let has_tproxy_intercept = self
                .rules
                .iter()
                .any(|r| matches!(&r.intercept, Some(ic) if ic.mode == InterceptMode::Tproxy));
            if has_tproxy_intercept {
                match std::process::Command::new("ip")
                    .arg("rule")
                    .arg("show")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                {
                    Err(_) => {
                        errors.push(
                            "Intercept mode 'tproxy' configured but 'ip' command not found. \
                             Install iproute2 or remove the tproxy intercept configuration."
                                .to_string(),
                        );
                    }
                    _ => {}
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

    /// Validate a port specification string (comma-separated ports or port ranges).
    /// Examples: "80", "80,443", "4465:4467", "80,443,4465:4467".
    fn validate_port_spec(spec: &str) -> Result<(), String> {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err("empty port segment".to_string());
            }
            if let Some((lo, hi)) = part.split_once(':') {
                let lo: u16 = lo
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid port number '{}'", lo.trim()))?;
                let hi: u16 = hi
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid port number '{}'", hi.trim()))?;
                if lo == 0 || hi == 0 {
                    return Err("port numbers must be >= 1".to_string());
                }
                if lo > hi {
                    return Err(format!("port range {}:{} is inverted", lo, hi));
                }
            } else {
                let port: u16 = part
                    .parse()
                    .map_err(|_| format!("invalid port number '{}'", part))?;
                if port == 0 {
                    return Err("port numbers must be >= 1".to_string());
                }
            }
        }
        Ok(())
    }

    /// Validate that a string is a valid IP address or CIDR notation.
    fn validate_ip_or_cidr(s: &str) -> Result<(), String> {
        let s = s.trim();
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let ip: IpAddr = ip_str.parse().map_err(|e| format!("invalid IP: {}", e))?;
            let prefix_len: u8 = prefix_str
                .parse()
                .map_err(|e| format!("invalid prefix length: {}", e))?;
            let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
            if prefix_len > max_prefix {
                return Err(format!(
                    "prefix length {} exceeds max {}",
                    prefix_len, max_prefix
                ));
            }
        } else {
            let _ip: IpAddr = s
                .parse()
                .map_err(|e| format!("invalid IP address: {}", e))?;
        }
        Ok(())
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
                "verify": "none",
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
                "verify": "none",
                "dscp_tag": 46
            }]
        }))
        .expect("deserialize config");
        assert!(cfg.validate().is_ok());
    }
}

#[cfg(test)]
mod perf_knobs_tests {
    use super::*;

    const MIB: usize = 1024 * 1024;
    const KIB: usize = 1024;

    #[test]
    fn throughput_profile_keeps_large_buffers() {
        let k = PerfKnobs::resolve(PerfProfile::Throughput, 0, 0, 16 * MIB);
        assert_eq!(k.sock_buf_size, 16 * MIB); // unclamped
        assert_eq!(k.pipe_size, 16 * MIB);
        assert_eq!(k.relay_buf_size, 4 * MIB);
        assert!(k.enable_cork);
        assert_eq!(k.spin_wait_us, 0);
        assert_eq!(k.notsent_lowat, None);
        assert_eq!(k.busy_poll_us, 0);
        assert!(!k.bdp_adaptive);
        assert_eq!(k.bdp_queue_budget_us, 1_000);
    }

    #[test]
    fn balanced_profile_uses_medium_buffers() {
        let k = PerfKnobs::resolve(PerfProfile::Balanced, 0, 0, 16 * MIB);
        assert_eq!(k.sock_buf_size, 8 * MIB); // clamped to balanced cap
        assert_eq!(k.pipe_size, 8 * MIB);
        assert_eq!(k.relay_buf_size, 2 * MIB);
        assert!(k.enable_cork);
        assert_eq!(k.spin_wait_us, 0);
        assert_eq!(k.notsent_lowat, Some(2 * MIB));
        assert_eq!(k.busy_poll_us, 0);
        assert!(!k.bdp_adaptive);
        assert_eq!(k.bdp_queue_budget_us, 1_000);
    }

    #[test]
    fn latency_profile_shrinks_buffers_and_enables_polling() {
        let k = PerfKnobs::resolve(PerfProfile::Latency, 0, 0, 16 * MIB);
        assert_eq!(k.sock_buf_size, 256 * KIB); // clamped to latency cap
        assert_eq!(k.pipe_size, 256 * KIB);
        assert_eq!(k.relay_buf_size, 256 * KIB);
        assert!(!k.enable_cork); // latency never corks
        assert_eq!(k.spin_wait_us, 50);
        assert_eq!(k.notsent_lowat, Some(16 * KIB));
        assert_eq!(k.busy_poll_us, 50);
        assert!(!k.bdp_adaptive);
        assert_eq!(k.bdp_queue_budget_us, 1_000);
    }

    #[test]
    fn explicit_small_sock_buf_wins_over_profile_cap() {
        // An explicitly small global sock_buf_size is a cap that no profile may
        // grow past.
        let t = PerfKnobs::resolve(PerfProfile::Throughput, 0, 0, 128 * KIB);
        assert_eq!(t.sock_buf_size, 128 * KIB);
        let b = PerfKnobs::resolve(PerfProfile::Balanced, 0, 0, 128 * KIB);
        assert_eq!(b.sock_buf_size, 128 * KIB);
    }

    #[test]
    fn geo_delay_forces_cork_off() {
        // A non-zero simulated delay flushes every packet immediately.
        let k = PerfKnobs::resolve(PerfProfile::Throughput, 5, 0, 16 * MIB);
        assert!(!k.enable_cork);
    }

    #[test]
    fn explicit_spin_wait_overrides_profile_default() {
        // Non-zero spin_wait_us always wins over the profile default (0 here).
        let k = PerfKnobs::resolve(PerfProfile::Throughput, 0, 123, 16 * MIB);
        assert_eq!(k.spin_wait_us, 123);
    }

    fn rule_with(extra: serde_json::Value) -> RuleConfig {
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
    fn per_rule_profile_override_wins_over_global() {
        // Global is throughput, but the rule pins latency: the rule wins.
        let rule = rule_with(serde_json::json!({ "perf_profile": "latency" }));
        let k = rule.perf_knobs(PerfProfile::Throughput, 16 * MIB);
        assert_eq!(k.pipe_size, 256 * KIB);
        assert_eq!(k.sock_buf_size, 256 * KIB);
        assert!(!k.enable_cork);
    }

    #[test]
    fn rule_without_override_inherits_global_profile() {
        let rule = rule_with(serde_json::json!({}));
        let k = rule.perf_knobs(PerfProfile::Latency, 16 * MIB);
        assert_eq!(k.pipe_size, 256 * KIB); // inherited latency
    }

    #[test]
    fn low_level_rule_overrides_win_over_profile_defaults() {
        let rule = rule_with(serde_json::json!({
            "perf_profile": "latency",
            "sock_buf_size": 3 * MIB,
            "pipe_size": 4 * MIB,
            "relay_buf_size": 512 * KIB,
            "notsent_lowat": 64 * KIB,
            "busy_poll_us": 75,
            "bdp_adaptive": true,
            "bdp_queue_budget_us": 500
        }));
        let k = rule.perf_knobs(PerfProfile::Throughput, 16 * MIB);

        assert_eq!(k.sock_buf_size, 3 * MIB);
        assert_eq!(k.pipe_size, 4 * MIB);
        assert_eq!(k.relay_buf_size, 512 * KIB);
        assert_eq!(k.notsent_lowat, Some(64 * KIB));
        assert_eq!(k.busy_poll_us, 75);
        assert!(k.bdp_adaptive);
        assert_eq!(k.bdp_queue_budget_us, 500);
        assert!(!k.enable_cork);
    }

    #[test]
    fn zero_notsent_lowat_rule_override_disables_profile_default() {
        let rule = rule_with(serde_json::json!({
            "perf_profile": "latency",
            "notsent_lowat": 0,
            "busy_poll_us": 0
        }));
        let k = rule.perf_knobs(PerfProfile::Throughput, 16 * MIB);

        assert_eq!(k.notsent_lowat, None);
        assert_eq!(k.busy_poll_us, 0);
    }

    #[test]
    fn bdp_adaptive_only_applies_to_latency_profile() {
        let rule = rule_with(serde_json::json!({ "bdp_adaptive": true }));

        let throughput = rule.perf_knobs(PerfProfile::Throughput, 16 * MIB);
        assert!(!throughput.bdp_adaptive);

        let latency = rule.perf_knobs(PerfProfile::Latency, 16 * MIB);
        assert!(latency.bdp_adaptive);
    }
}

#[cfg(test)]
mod crypto_provider_tests {
    use super::resolve_crypto_provider;

    #[test]
    fn offloadable_tls_upgrades_to_ktls_when_kernel_supports_it() {
        assert_eq!(resolve_crypto_provider("tls", true, true, true), "ktls");
    }

    #[test]
    fn tls_stays_userspace_without_kernel_support() {
        assert_eq!(resolve_crypto_provider("tls", true, true, false), "tls");
    }

    #[test]
    fn tls_stays_userspace_when_preference_disabled() {
        assert_eq!(resolve_crypto_provider("tls", true, false, true), "tls");
    }

    #[test]
    fn non_offloadable_tls_is_never_upgraded() {
        assert_eq!(resolve_crypto_provider("tls", false, true, true), "tls");
    }

    #[test]
    fn non_offloadable_ktls_downgrades_to_userspace_tls() {
        assert_eq!(resolve_crypto_provider("ktls", false, true, true), "tls");
    }

    #[test]
    fn offloadable_ktls_stays_ktls() {
        assert_eq!(resolve_crypto_provider("ktls", true, false, false), "ktls");
    }

    #[test]
    fn other_providers_pass_through_unchanged() {
        assert_eq!(resolve_crypto_provider("dtls", false, true, true), "dtls");
        assert_eq!(
            resolve_crypto_provider("routing", true, true, true),
            "routing"
        );
    }
}

#[cfg(test)]
mod intercept_tests {
    use super::*;

    #[test]
    fn valid_ingress_redirect() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "web",
                "direction": "decrypt",
                "listen_addr": "0.0.0.0:8443",
                "upstream_addr": "127.0.0.1:80",
                "verify": "none",
                "intercept": {
                    "mode": "ingress_redirect",
                    "in_interface": "eth0",
                    "match_dports": "8080"
                }
            }]
        }))
        .expect("deserialize");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn valid_egress_redirect() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "enc",
                "direction": "encrypt",
                "listen_addr": "0.0.0.0:3128",
                "upstream_addr": "10.0.0.1:443",
                "verify": "none",
                "intercept": {
                    "mode": "egress_redirect",
                    "match_dports": "4465:4467",
                    "match_dst": ["192.168.1.2", "192.168.1.3"]
                }
            }]
        }))
        .expect("deserialize");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn valid_tproxy() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "dec",
                "direction": "decrypt",
                "listen_addr": "0.0.0.0:4000",
                "upstream_addr": "auto",
                "transparent": true,
                "verify": "none",
                "intercept": {
                    "mode": "tproxy",
                    "match_dports": "4465:4467",
                    "match_src": ["192.168.1.1"]
                }
            }]
        }))
        .expect("deserialize");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn tproxy_requires_transparent() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "dec",
                "direction": "decrypt",
                "listen_addr": "0.0.0.0:4000",
                "upstream_addr": "auto",
                "transparent": true,
                "verify": "none",
                "intercept": {
                    "mode": "tproxy",
                    "match_dports": "4465",
                    "match_src": ["10.0.0.1"]
                }
            }]
        }))
        .expect("deserialize");
        // transparent = true should pass.
        assert!(cfg.validate().is_ok());

        // Now test without transparent.
        let cfg2: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "dec",
                "direction": "decrypt",
                "listen_addr": "0.0.0.0:4000",
                "upstream_addr": "127.0.0.1:80",
                "transparent": false,
                "verify": "none",
                "intercept": {
                    "mode": "tproxy",
                    "match_dports": "4465",
                    "match_src": ["10.0.0.1"]
                }
            }]
        }))
        .expect("deserialize");
        let err = cfg2.validate().unwrap_err();
        assert!(
            err.contains("tproxy") && err.contains("transparent"),
            "got: {err}"
        );
    }

    #[test]
    fn egress_redirect_requires_match_dst() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "enc",
                "direction": "encrypt",
                "listen_addr": "0.0.0.0:3128",
                "upstream_addr": "10.0.0.1:443",
                "verify": "none",
                "intercept": {
                    "mode": "egress_redirect",
                    "match_dports": "80"
                }
            }]
        }))
        .expect("deserialize");
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("match_dst"), "got: {err}");
    }

    #[test]
    fn tproxy_requires_match_src() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "dec",
                "direction": "decrypt",
                "listen_addr": "0.0.0.0:4000",
                "upstream_addr": "auto",
                "transparent": true,
                "verify": "none",
                "intercept": {
                    "mode": "tproxy",
                    "match_dports": "4465"
                }
            }]
        }))
        .expect("deserialize");
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("match_src"), "got: {err}");
    }

    #[test]
    fn empty_match_dports_rejected() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "web",
                "direction": "decrypt",
                "listen_addr": "0.0.0.0:8443",
                "upstream_addr": "127.0.0.1:80",
                "verify": "none",
                "intercept": {
                    "mode": "ingress_redirect",
                    "match_dports": ""
                }
            }]
        }))
        .expect("deserialize");
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("match_dports"), "got: {err}");
    }

    #[test]
    fn invalid_port_spec_rejected() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "web",
                "direction": "decrypt",
                "listen_addr": "0.0.0.0:8443",
                "upstream_addr": "127.0.0.1:80",
                "verify": "none",
                "intercept": {
                    "mode": "ingress_redirect",
                    "match_dports": "abc"
                }
            }]
        }))
        .expect("deserialize");
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("match_dports") && err.contains("invalid"),
            "got: {err}"
        );
    }

    #[test]
    fn invalid_dst_cidr_rejected() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "enc",
                "direction": "encrypt",
                "listen_addr": "0.0.0.0:3128",
                "upstream_addr": "10.0.0.1:443",
                "verify": "none",
                "intercept": {
                    "mode": "egress_redirect",
                    "match_dports": "80",
                    "match_dst": ["not-an-ip"]
                }
            }]
        }))
        .expect("deserialize");
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("match_dst"), "got: {err}");
    }

    #[test]
    fn intercept_invalid_on_uds_rules() {
        let result: Result<GatewayConfig, _> = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "local",
                "direction": "encrypt",
                "listen_addr": "0.0.0.0:0",
                "listen_proto": "uds",
                "upstream_addr": "127.0.0.1:443",
                "app_id": "myapp",
                "allowed_uids": [1000],
                "verify": "none",
                "intercept": {
                    "mode": "ingress_redirect",
                    "match_dports": "80"
                }
            }]
        }));
        // It should parse but fail validation.
        let cfg = result.expect("deserialize");
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("intercept") && err.contains("uds"),
            "got: {err}"
        );
    }

    #[test]
    fn valid_port_specs() {
        assert!(GatewayConfig::validate_port_spec("80").is_ok());
        assert!(GatewayConfig::validate_port_spec("80,443").is_ok());
        assert!(GatewayConfig::validate_port_spec("4465:4467").is_ok());
        assert!(GatewayConfig::validate_port_spec("80,443,4465:4467").is_ok());
        assert!(GatewayConfig::validate_port_spec("0").is_err());
        assert!(GatewayConfig::validate_port_spec("99999").is_err());
        assert!(GatewayConfig::validate_port_spec("abc").is_err());
        assert!(GatewayConfig::validate_port_spec("100:50").is_err()); // inverted range
    }
}

#[cfg(test)]
mod tls_validation_tests {
    use super::*;

    #[test]
    fn default_tls_rule_without_verify_is_rejected() {
        // A rule with no explicit security_provider defaults to "tls". Omitting
        // `verify` must be a load-time error (fail-secure) rather than silently
        // disabling peer verification.
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "enc",
                "direction": "encrypt",
                "listen_addr": "127.0.0.1:8443",
                "upstream_addr": "127.0.0.1:9000"
            }]
        }))
        .expect("deserialize");
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("verify") && err.contains("invalid TLS parameters"),
            "got: {err}"
        );
    }

    #[test]
    fn explicit_tls_rule_without_verify_is_rejected() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "enc",
                "direction": "encrypt",
                "listen_addr": "127.0.0.1:8443",
                "upstream_addr": "127.0.0.1:9000",
                "security_provider": "tls"
            }]
        }))
        .expect("deserialize");
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("verify"), "got: {err}");
    }

    #[test]
    fn tls_rule_with_explicit_verify_none_is_accepted() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "enc",
                "direction": "encrypt",
                "listen_addr": "127.0.0.1:8443",
                "upstream_addr": "127.0.0.1:9000",
                "verify": "none"
            }]
        }))
        .expect("deserialize");
        assert!(cfg.validate().is_ok(), "{:?}", cfg.validate());
    }

    #[test]
    fn routing_rule_skips_tls_verify_requirement() {
        // Non-TLS providers must not be subjected to the verify requirement.
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "route",
                "direction": "encrypt",
                "listen_addr": "127.0.0.1:8443",
                "upstream_addr": "127.0.0.1:9000",
                "security_provider": "routing"
            }]
        }))
        .expect("deserialize");
        assert!(cfg.validate().is_ok(), "{:?}", cfg.validate());
    }
}
