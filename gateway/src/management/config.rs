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
use std::path::{Path, PathBuf};

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

    /// Base worker-thread count for every rule's connection pool. When `None`
    /// (the default), each rule uses `ConnectionPool::default_size` (`2×CPU`).
    /// Relay jobs are long-lived (one worker per connection for the connection's
    /// lifetime) and `Normal`-class pools do not overflow, so a host driving more
    /// concurrent connections than `2×CPU` must raise this or excess connections
    /// queue behind the base workers. Validated to a sane range (see
    /// [`MAX_CONN_POOL_SIZE`]): `0` is rejected (a Normal pool with no workers
    /// silently forwards nothing) and oversized values are rejected (eagerly
    /// spawning that many threads per rule is a self-inflicted resource
    /// exhaustion — TRA register #57). `Safety` pools still floor at their
    /// reserved minimum regardless of this value.
    #[serde(default)]
    pub conn_pool_size: Option<usize>,

    /// Downgrade the unverified-transport preflight **errors** back to warnings
    /// `verify: none` to a non-loopback upstream, or a non-mutual decrypt
    /// listener on a non-loopback bind. Default `false` (fail-secure) — an
    /// operator who deliberately runs an unverified posture on a routable endpoint
    /// must opt in, so `--validate` fails the config until they do.
    #[serde(default)]
    pub allow_unverified_transport: bool,

    /// Filesystem path this config was loaded from (classic mode), captured so the
    /// preflight can advise on the file's permissions (CP-06). Not part of the
    /// JSON; `None` for configs built in memory or via the lite path.
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
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
    /// (default: 4 MiB, i.e. 8 MiB per SHM endpoint — one ring per direction).
    /// Enlarging the ring trades queueing latency for throughput headroom, so
    /// it is left to per-deployment config.
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
    // 4 MiB per direction. At ~10 Gib/s a 1 MiB ring drains in <1 ms, so the
    // gateway→client backpressure (`RING_FULL_BACKOFF` spin) throttles large
    // bursts; 4 MiB keeps the ring from filling on a single-connection
    // throughput run while staying bounded (8 MiB per SHM endpoint).
    4 * 1024 * 1024
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

/// Upper bound on a configured `conn_pool_size`. Each rule eagerly spawns this
/// many worker threads, so an unbounded value is a self-inflicted resource
/// exhaustion (TRA register #57). 4096 base workers per rule is far above any
/// realistic single-host concurrency yet bounds the blast radius of a typo.
pub const MAX_CONN_POOL_SIZE: usize = 4096;

/// Resolve the effective crypto provider name, applying the kTLS preference.
///
/// Two complementary, mutually-exclusive adjustments are made to the
/// `configured` provider so the gateway always runs the best safe engine:
///
/// * a `ktls` rule whose parameters are **not** offloadable (the `integrity-only`
///   profile — NULL-encryption ciphers, no AES-GCM record layer) is downgraded to
///   userspace `tls`. Neither peer verification (server/mutual) nor the Subset-146
///   ETCS profiles (PKI mutual / PSK, both AES-256-GCM) downgrade: kTLS offloads the
///   post-handshake record layer regardless of how the peer was authenticated, and
///   the relay guards splice on runtime activation (see `is_ktls_offloadable`, #56),
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
    // Private builder-style setter; the overrides map 1:1 to tuning knobs.
    #[allow(clippy::too_many_arguments)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
    ///
    /// Precedence: serde cannot distinguish an explicit `security_provider:
    /// "tls"` from its default, so a non-default `tls_mode` wins whenever
    /// `security_provider` is (or defaults to) `"tls"`; any other
    /// `security_provider` value wins over `tls_mode`. See
    /// [`RuleConfig::effective_security_provider`].
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
    ///
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
    ///
    /// A non-default `security_provider` is used as-is. When it is `"tls"`
    /// (explicitly or via its serde default — the two are indistinguishable),
    /// the legacy `tls_mode` decides, so old configs that only set `tls_mode`
    /// keep working. See the `tls_mode` field doc for the precedence note.
    pub fn effective_security_provider(&self) -> &str {
        if self.security_provider == "tls" {
            match self.tls_mode {
                TlsMode::Tls => "tls",
                TlsMode::Ktls => "ktls",
                TlsMode::Dtls => "dtls",
            }
        } else {
            &self.security_provider
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

    /// Whether a same-name rule differs from `other` in a way that requires the
    /// listener to be torn down and recreated on hot-reload: security posture,
    /// routing, framing, or QoS marking. Perf-only knobs (buffer/pipe sizes,
    /// spin waits, BDP tuning) are intentionally excluded so a tuning tweak does
    /// not drop live connections. Drives the `changed` bucket in [`GatewayConfig::diff`].
    pub fn reload_differs(&self, other: &RuleConfig) -> bool {
        self.direction != other.direction
            || self.listen_addr != other.listen_addr
            || self.listen_proto != other.listen_proto
            || self.upstream_addr != other.upstream_addr
            || self.upstream_proto != other.upstream_proto
            || self.effective_security_provider() != other.effective_security_provider()
            || self.effective_app_protocol() != other.effective_app_protocol()
            || self.protocol_version != other.protocol_version
            || self.transparent != other.transparent
            || self.traffic_class != other.traffic_class
            || self.dscp_tag != other.dscp_tag
            || self.preserve_inbound_dscp != other.preserve_inbound_dscp
            // provider_params carries verify/cert/CA/PSK/profile and the DTLS
            // session limits — any change there is security-relevant.
            || self.provider_params != other.provider_params
            // Local-IPC authorization (uds/shm allow-lists) and transparent
            // interception are security-relevant: a tightened allow-list or an
            // intercept change must mark the rule "changed" so the reload
            // re-applies it rather than silently keeping the old posture (#42).
            || self.allowed_uids != other.allowed_uids
            || self.allowed_pids != other.allowed_pids
            || self.intercept != other.intercept
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum TrafficClass {
    /// Normal priority — default for all traffic.
    #[default]
    Normal,
    /// Safety-critical traffic — always processed first.
    Safety,
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
    /// When true, Safety-classified traffic must ALSO pass the whitelist /
    /// default-deny instead of being unconditionally allowed. Default `false`
    /// (fail-open) to preserve the railway-availability guarantee — a policy
    /// misconfiguration must never silence safety-critical signalling.
    /// High-security deployments opt in to confine Safety traffic. See the
    /// `dtls`/policy notes in the gateway README.
    #[serde(default)]
    pub enforce_policy_on_safety: bool,
}

/// Policy default action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PolicyAction {
    #[default]
    Allow,
    Deny,
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
        // Canonicalize the peer IP so an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`,
        // as seen on a dual-stack `[::]` listener) matches IPv4 patterns.
        // Exact/IpOnly pattern IPs are canonicalized too, so a pattern *written* in
        // mapped form still matches. Cidr networks are matched literally — a v6
        // prefix over a mapped network does not translate to a v4 prefix.
        let ip = addr.ip().to_canonical();
        match self {
            AddressPattern::Any => true,
            AddressPattern::Exact(sa) => ip == sa.ip().to_canonical() && addr.port() == sa.port(),
            AddressPattern::IpOnly(p) => ip == p.to_canonical(),
            AddressPattern::Cidr {
                network,
                prefix_len,
            } => cidr_contains(*network, *prefix_len, ip),
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
        let mut config: GatewayConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse config file '{}': {}", path, e))?;
        // Remember where we loaded from so the preflight can advise on the file's
        // permissions (CP-06).
        config.source_path = Some(PathBuf::from(path));
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

        // Bound the connection-pool size before any thread is spawned (TRA #57):
        // 0 would leave a Normal pool with no workers (silently forwards
        // nothing); an oversized value eagerly spawns that many threads per rule.
        if let Some(size) = self.conn_pool_size {
            if size == 0 {
                return Err(
                    "\"conn_pool_size\" must be at least 1 (0 leaves the connection pool with no \
                     workers, so the rule would forward no traffic)"
                        .to_string(),
                );
            }
            if size > MAX_CONN_POOL_SIZE {
                return Err(format!(
                    "\"conn_pool_size\" {size} exceeds the maximum {MAX_CONN_POOL_SIZE} \
                     (each rule eagerly spawns this many worker threads)"
                ));
            }
        }

        let mut seen_names = HashSet::new();
        let mut seen_listen = HashSet::new();
        // UDS/SHM rules have no listen address; their runtime identity is the
        // template key (app_id, class, direction, kind) used by the
        // InterfaceManager — colliding keys would silently shadow each other
        // ("last rule wins"), replacing an earlier rule's allow-lists and
        // security posture, so they are a hard error like listen collisions.
        let mut seen_templates: HashSet<(String, TrafficClass, Direction, Proto)> = HashSet::new();

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
                let template = (
                    rule.app_id.clone().unwrap_or_default(),
                    rule.traffic_class,
                    rule.direction,
                    rule.listen_proto,
                );
                if !seen_templates.insert(template) {
                    return Err(format!(
                        "Rule '{}' (index {}): duplicate local-endpoint template (app_id={}, \
                         class={:?}, direction={:?}, kind={}) conflicts with another rule — \
                         at runtime the last rule would silently replace the earlier one's \
                         allow-lists and security posture",
                        rule.name,
                        i,
                        rule.app_id.as_deref().unwrap_or(""),
                        rule.traffic_class,
                        rule.direction,
                        rule.listen_proto
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
            if rule.upstream_addr != "auto" {
                Self::validate_host_port(&rule.upstream_addr).map_err(|e| {
                    format!(
                        "Rule '{}' (index {}): upstream_addr '{}' must be 'auto' or HOST:PORT ({})",
                        rule.name, i, rule.upstream_addr, e
                    )
                })?;
            }

            // "auto" upstream requires transparent mode
            if rule.upstream_addr == "auto" && !rule.transparent {
                return Err(format!(
                    "Rule '{}' (index {}): upstream_addr 'auto' requires transparent = true",
                    rule.name, i
                ));
            }

            // DTLS validation (keyed to the effective provider so both the
            // modern `security_provider: "dtls"` and the legacy
            // `tls_mode: "dtls"` spellings are covered):
            //   - DTLS is UDP-only.
            //   - No original-destination recovery is implemented for DTLS, so
            //     `upstream_addr = "auto"` is rejected like WireGuard's —
            //     running it would reflect decrypted plaintext back toward the
            //     client-facing segment on decrypt and relay nothing on
            //     encrypt (TRA #74).
            if rule.effective_security_provider() == "dtls" {
                if rule.listen_proto != Proto::Udp {
                    return Err(format!(
                        "Rule '{}' (index {}): DTLS requires listen_proto = \"udp\"",
                        rule.name, i
                    ));
                }
                if rule.upstream_addr == "auto" {
                    return Err(format!(
                        "Rule '{}' (index {}): DTLS does not support upstream_addr = \"auto\" \
                         (no original-destination recovery); configure an explicit upstream",
                        rule.name, i
                    ));
                }
            }

            // Plaintext UDP routing: the relay forwards opaque datagrams to a fixed
            // udp upstream (per-peer demux, bounded by max_sessions — TRA #81).
            // Reject the combinations the fixed-upstream relay cannot honour so they
            // fail at load, not at the first datagram.
            if rule.effective_security_provider() == "routing" && rule.listen_proto == Proto::Udp {
                if rule.upstream_proto != Proto::Udp {
                    return Err(format!(
                        "Rule '{}' (index {}): routing over udp requires upstream_proto = \"udp\"",
                        rule.name, i
                    ));
                }
                if rule.upstream_addr == "auto" {
                    return Err(format!(
                        "Rule '{}' (index {}): routing over udp does not support upstream_addr = \
                         \"auto\" (no original-destination recovery); configure an explicit upstream",
                        rule.name, i
                    ));
                }
                // Session bounds, when set explicitly, must be positive: a zero cap
                // admits nothing and a zero TTL evicts everything. Absent ⇒ the
                // shared UDP defaults (`DEFAULT_UDP_{MAX_SESSIONS,IDLE_TTL_SECS}`).
                for key in ["max_sessions", "idle_ttl_secs"] {
                    if let Some(v) = rule.provider_params.get(key) {
                        if v.as_u64().map(|n| n == 0).unwrap_or(true) {
                            return Err(format!(
                                "Rule '{}' (index {}): routing-udp '{}' must be a positive integer",
                                rule.name, i, key
                            ));
                        }
                    }
                }
            }

            // kTLS capability gate: kernel TLS cannot offload NULL-encryption
            // (integrity-only) cipher suites. Reject at load so the error is
            // surfaced early instead of at connection time. Other non-offloadable
            // profiles (PKI/PSK/verify) fall back to userspace TLS at runtime.
            // (`tls_mode == Ktls` needs no separate disjunct:
            // effective_security_provider() already maps it to "ktls".)
            let is_ktls = rule.effective_security_provider() == "ktls";
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
                if provider == "tls" || provider == "ktls" || provider == "dtls" {
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

                // protocol_version syntax is a pure string check, so it is
                // enforced here — on EVERY load path (startup, --validate,
                // hot-reload, lite-config render) — not just in
                // preflight_check(); the engines interpret the string loosely
                // (`is_tls13()` is an equality test), so a typo like "tls13"
                // would otherwise silently run as the TLS 1.2 default.
                // preflight_check() keeps only the kTLS+TLS1.3 kernel-support
                // warning.
                if let Some(ref version) = rule.protocol_version {
                    let (valid, expected) = match provider {
                        "tls" | "ktls" => (
                            matches!(version.as_str(), "tls1.2" | "tls1.3"),
                            "'tls1.2' or 'tls1.3'",
                        ),
                        "dtls" => (
                            matches!(version.as_str(), "dtls1.0" | "dtls1.2"),
                            "'dtls1.0' or 'dtls1.2'",
                        ),
                        // Custom providers interpret protocol_version themselves.
                        _ => (true, ""),
                    };
                    if !valid {
                        return Err(format!(
                            "Rule '{}' (index {}): invalid protocol_version '{}' for {} \
                             provider (expected {})",
                            rule.name, i, version, provider, expected
                        ));
                    }
                }
            }

            // WireGuard validation: UDP-only, no "auto" upstream (a single peer
            // endpoint is configured), and the provider params (keys, ports,
            // tunnel addresses) must be well-formed. Parsing them here surfaces
            // misconfiguration at `--validate` instead of when the kernel
            // interface is provisioned at rule startup. This never touches the
            // kernel and never panics.
            if rule.effective_security_provider() == "wireguard" {
                if rule.listen_proto != Proto::Udp {
                    return Err(format!(
                        "Rule '{}' (index {}): WireGuard requires listen_proto = \"udp\"",
                        rule.name, i
                    ));
                }
                if rule.upstream_addr == "auto" {
                    return Err(format!(
                        "Rule '{}' (index {}): WireGuard does not support upstream_addr = \"auto\"",
                        rule.name, i
                    ));
                }
                crate::security::wireguard_engine::WgProviderConfig::from_params(
                    &rule.provider_params,
                )
                .map_err(|e| format!("Rule '{}' (index {}): {}", rule.name, i, e))?;
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
        if has_ktls_rules && fs::metadata("/proc/modules").is_ok() {
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

        // Check for kernel WireGuard prerequisites (module, `wg`/`ip` tools,
        // CAP_NET_ADMIN). Warn (not fail) so config can be validated on an
        // unprivileged host; the provider fails fast at startup if still unmet.
        let has_wireguard_rules = self
            .rules
            .iter()
            .any(|r| r.effective_security_provider() == "wireguard");
        if has_wireguard_rules && !crate::security::wireguard_engine::wireguard_available() {
            warnings.push(format!(
                "WireGuard rules configured but prerequisites are missing: {}",
                crate::security::wireguard_engine::unavailable_reason()
            ));
        }

        // Check for transparent/TPROXY requirements
        let has_transparent = self.rules.iter().any(|r| r.transparent);
        if has_transparent {
            // CAP_NET_ADMIN check via the shared IP_TRANSPARENT probe.
            if probe_ip_transparent() == Some(false) {
                errors.push(
                    "Transparent rules require CAP_NET_ADMIN capability. \
                     Run as root or use: setcap cap_net_admin,cap_net_raw+ep <binary>"
                        .to_string(),
                );
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
                         Add an `intercept` block to the rule so the gateway configures \
                         policy routing itself at startup, or run manually: \
                         ip rule add fwmark 1 lookup 100 && \
                         ip route add local default dev lo table 100"
                            .to_string(),
                    );
                }
            }
        }

        // ── Intercept self-configuration preflight ──────────────────────────
        let has_intercept = self.rules.iter().any(|r| r.intercept.is_some());
        if has_intercept {
            // CAP_NET_ADMIN is mandatory when intercept is configured; use the
            // shared IP_TRANSPARENT probe.
            if probe_ip_transparent() == Some(false) {
                errors.push(
                    "Intercept rules configured but CAP_NET_ADMIN is missing. \
                     The gateway cannot install iptables rules without it. \
                     Run as root or use: setcap cap_net_admin,cap_net_raw+ep <binary>"
                        .to_string(),
                );
            }

            // iptables binary must exist when self-configuring.
            if std::process::Command::new("iptables")
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_err()
            {
                errors.push(
                    "Intercept rules configured but 'iptables' command not found. \
                     Install iptables or remove the intercept configuration."
                        .to_string(),
                );
            }

            // ip command needed for TPROXY routing policy.
            let has_tproxy_intercept = self
                .rules
                .iter()
                .any(|r| matches!(&r.intercept, Some(ic) if ic.mode == InterceptMode::Tproxy));
            if has_tproxy_intercept
                && std::process::Command::new("ip")
                    .arg("rule")
                    .arg("show")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_err()
            {
                errors.push(
                    "Intercept mode 'tproxy' configured but 'ip' command not found. \
                     Install iproute2 or remove the tproxy intercept configuration."
                        .to_string(),
                );
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

        // Posture: a routing local endpoint (UDS/SHM) relays plaintext on both
        // legs — there is no local-IPC encryption (TRA #58). The local caller is
        // still uid-authenticated, but the data itself is unprotected. Warn so an
        // operator does not deploy it believing the channel is encrypted.
        for rule in &self.rules {
            if matches!(rule.listen_proto, Proto::Uds | Proto::Shm)
                && rule.effective_security_provider() == "routing"
            {
                warnings.push(format!(
                    "Rule '{}': routing over {} relays cleartext with no local-IPC encryption — \
                     the local app's data is unprotected on the endpoint and upstream legs. \
                     Use a tls/ktls provider for an encrypted local channel.",
                    rule.name, rule.listen_proto
                ));
            }
        }

        // Plaintext routing over the network (tcp/udp) forwards application data
        // unencrypted on the wire (CWE-319, TRA #83). Like the verify:none
        // advisories, this is an ERROR on a non-loopback listener unless the
        // operator opts in via `allow_unverified_transport`, in which case it stays
        // a warning; a loopback endpoint always stays a warning. (UDS/SHM routing
        // has its own local-IPC advisory above; this covers the on-wire cleartext.)
        for rule in &self.rules {
            if rule.effective_security_provider() == "routing"
                && matches!(rule.listen_proto, Proto::Tcp | Proto::Udp)
            {
                let msg = format!(
                    "Rule '{}': routing over {} relays cleartext on the wire — application data is \
                     unencrypted and readable/modifiable by an on-path attacker. Use a tls/ktls \
                     provider to encrypt it, or set allow_unverified_transport: true to accept this \
                     risk.",
                    rule.name, rule.listen_proto
                );
                if listen_is_non_loopback(&rule.listen_addr) && !self.allow_unverified_transport {
                    errors.push(msg);
                } else {
                    warnings.push(msg);
                }
            }
        }

        // protocol_version *syntax* is enforced in validate() (every load
        // path); only the kernel-support caveat belongs here.
        for rule in &self.rules {
            if let Some(ref version) = rule.protocol_version {
                if rule.effective_security_provider() == "ktls" && version == "tls1.3" {
                    warnings.push(format!(
                        "Rule '{}': kTLS + TLS 1.3 is not reliably supported by all kernels — will fall back to TLS 1.2 at runtime",
                        rule.name
                    ));
                }
            }
        }

        // ── TLS/DTLS verification-posture advisories ─────────────────────────
        // `verify: none` stays legal for back-compat, but unverified upstreams
        // (MITM, CWE-295) and decrypt listeners that do not authenticate clients
        // (CWE-306) are ERRORS on a non-loopback endpoint unless the
        // operator opts in via `allow_unverified_transport`, in which case they
        // stay warnings. A loopback/local endpoint always stays a warning. The
        // per-rule KEY-file permission advisory (KC-01) is emitted here too, where
        // the TLS params (and thus the key path) are already resolved.
        for rule in &self.rules {
            let provider = rule.effective_security_provider();
            if provider != "tls" && provider != "ktls" && provider != "dtls" {
                continue;
            }
            let params = match crate::security::tls_engine::params::TlsSecurityParams::from_params(
                &rule.provider_params,
                rule.protocol_version.as_deref(),
            ) {
                Ok(p) => p,
                Err(_) => continue, // parse errors are reported by validate()
            };

            // KC-01: over-permissive private-key file mode.
            if let Some(key) = params.key_path.as_ref() {
                if let Ok(md) = std::fs::metadata(key) {
                    use std::os::unix::fs::MetadataExt;
                    if let Some(w) = crate::management::cert_store::key_perm_warning(key, md.mode())
                    {
                        warnings.push(format!("Rule '{}': {w}", rule.name));
                    }
                }
            }

            use crate::security::tls_engine::params::VerifyMode;
            match rule.direction {
                Direction::Encrypt => {
                    if params.verify == VerifyMode::None
                        && !upstream_is_loopback(&rule.upstream_addr)
                    {
                        let msg = format!(
                            "Rule '{}': encrypt upstream '{}' is contacted without peer \
                             verification (verify: none) — an on-path attacker can impersonate \
                             it. Set verify: server (or mutual) with ca_path to authenticate it, \
                             or set allow_unverified_transport: true to accept this risk.",
                            rule.name, rule.upstream_addr
                        );
                        if self.allow_unverified_transport {
                            warnings.push(msg);
                        } else {
                            errors.push(msg);
                        }
                    }
                }
                Direction::Decrypt => {
                    if params.verify != VerifyMode::Mutual {
                        let msg = format!(
                            "Rule '{}': decrypt listener does not require client certificates \
                             (verify != mutual) — the plaintext relayed upstream originates from \
                             unauthenticated peers. Set verify: mutual, or set \
                             allow_unverified_transport: true to accept this risk.",
                            rule.name
                        );
                        if listen_is_non_loopback(&rule.listen_addr)
                            && !self.allow_unverified_transport
                        {
                            errors.push(msg);
                        } else {
                            warnings.push(msg);
                        }
                    }
                }
            }
        }

        // ── Safety-classification scope warning (advisory) ──────────────────
        // Safety traffic bypasses the policy whitelist by default (a railway
        // availability requirement). Binding a `safety` traffic-rule to a wide /
        // non-loopback source lets a spoofed source obtain the bypass, which is
        // also the precondition for the overflow-thread DoS. Flag it so the
        // operator scopes safety classification to trusted sources.
        for (i, tr) in self.traffic_rules.iter().enumerate() {
            if tr.traffic_class == TrafficClass::Safety && is_wide_untrusted_source(&tr.source) {
                warnings.push(format!(
                    "traffic_rules[{}] (app_id '{}'): classifies a wide/non-loopback source '{}' \
                     as safety, which bypasses the policy whitelist by default. Scope safety \
                     classification to trusted sources, or set policy.enforce_policy_on_safety.",
                    i, tr.app_id, tr.source
                ));
            }
        }

        // ── Management-API TCP-bind posture warning (advisory) ──────────────
        // The optional gRPC TCP bind carries no transport auth or encryption,
        // and the read RPCs (Health/ListRules) are reachable unauthenticated
        // over it (#41; ListRules is now gated by #40, but Health and the lack
        // of transport encryption remain). Endpoint creation is still refused
        // over TCP, but an operator should know they are exposing an
        // unauthenticated control surface — especially on a non-loopback bind.
        if let Some(tcp) = self.api.as_ref().and_then(|a| a.tcp_addr.as_ref()) {
            let non_loopback = tcp
                .parse::<std::net::SocketAddr>()
                .map(|a| !a.ip().is_loopback())
                .unwrap_or(true);
            let scope = if non_loopback {
                "a NON-LOOPBACK address, reachable by remote network clients"
            } else {
                "a loopback address"
            };
            warnings.push(format!(
                "Management API TCP bind '{}' is enabled on {} with no transport \
                 authentication or encryption (endpoint creation is still refused \
                 over TCP). Prefer UDS-only, or place the bind behind mTLS/loopback.",
                tcp, scope
            ));
        }

        // ── Unix-socket path-length (SUN_LEN) check ─────────────────────────
        // The management socket and every UDS/SHM endpoint socket are bound as
        // Unix sockets, whose path must fit `sockaddr_un.sun_path` (108 bytes on
        // Linux, incl. the NUL terminator). Catch an over-long path here so the
        // operator gets a clear `--validate` error instead of a confusing runtime
        // "path must be shorter than SUN_LEN" bind failure.
        if let Some(api) = self.api.as_ref() {
            const SUN_MAX: usize = 108; // Linux sockaddr_un.sun_path incl. NUL
            if api.uds_path.len() >= SUN_MAX {
                errors.push(format!(
                    "api.uds_path '{}' is {} bytes, but a Unix socket path must be \
                     under {} (SUN_LEN) — use a shorter management-socket path (e.g. \
                     under /run)",
                    api.uds_path,
                    api.uds_path.len(),
                    SUN_MAX
                ));
            }
            // Endpoint sockets are laid out as
            // `<runtime_dir>/<uid>/<app_id>.<class>.<direction>.<id>.sock`. Estimate
            // the longest (10-digit uid + id, the longest configured local app_id,
            // and the longest class/direction tokens) and warn before it bites at
            // endpoint-create time.
            let longest_app = self
                .rules
                .iter()
                .filter(|r| matches!(r.listen_proto, Proto::Uds | Proto::Shm))
                .filter_map(|r| r.app_id.as_deref().map(str::len))
                .max();
            if let Some(app_len) = longest_app {
                // runtime_dir + '/' + uid(≤10) + '/' + app + '.' + "safety"(6) +
                // '.' + "encrypt"(7) + '.' + id(≤10) + ".sock"(5)
                let est = api.runtime_dir.len() + 1 + 10 + 1 + app_len + 1 + 6 + 1 + 7 + 1 + 10 + 5;
                if est >= SUN_MAX {
                    warnings.push(format!(
                        "api.runtime_dir '{}' plus a UDS/SHM endpoint filename can reach \
                         ~{} bytes, near/over the {}-byte Unix-socket limit — endpoint \
                         creation may fail at runtime; use a shorter runtime_dir",
                        api.runtime_dir, est, SUN_MAX
                    ));
                }
            }
        }

        // ── Config-file writability advisory (CP-06) ────────────────────────
        // The classic config path has no integrity control; at minimum warn if
        // the file itself is group/other-writable, so a co-located actor cannot
        // silently rewrite the running posture on the next reload.
        if let Some(path) = &self.source_path {
            if let Some(w) = world_or_group_writable_warning(path, "config file") {
                warnings.push(w);
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
                     Traffic interception will not work without it. \
                     Add an `intercept` block to the rule so the gateway installs its \
                     netfilter rules itself at startup, or create the chain manually \
                     (iptables -t {} -N {}, a PREROUTING jump, and per-rule \
                     REDIRECT/TPROXY entries).",
                    chain, table, table, chain
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
    /// Validate an intercept match entry: a bare IP literal or an `IP/prefix`
    /// CIDR.
    ///
    /// Delegates to [`AddressPattern::parse`] so the CIDR/IP parsing and
    /// prefix-bound rules exist exactly once; shapes the pattern language
    /// accepts but intercept matching does not (`any`, `IP:port`) are
    /// rejected here.
    fn validate_ip_or_cidr(s: &str) -> Result<(), String> {
        match AddressPattern::parse(s)? {
            AddressPattern::Cidr { .. } | AddressPattern::IpOnly(_) => Ok(()),
            AddressPattern::Any => Err("expected an IP address or CIDR, not 'any'".to_string()),
            AddressPattern::Exact(_) => {
                Err("expected an IP address or CIDR without a port".to_string())
            }
        }
    }

    /// Validate a `HOST:PORT` upstream endpoint: a non-empty host and a
    /// nonzero `u16` port. Accepts bracketed IPv6 (`[::1]:443`) and DNS
    /// hostnames — name resolution is deliberately a runtime concern.
    fn validate_host_port(s: &str) -> Result<(), String> {
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| "missing ':' separator".to_string())?;
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty() {
            return Err("empty host".to_string());
        }
        match port.parse::<u16>() {
            Ok(0) => Err("port must be 1-65535".to_string()),
            Ok(_) => Ok(()),
            Err(_) => Err(format!("invalid port '{}'", port)),
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

    /// Diff two configs into added / removed / changed / unchanged rule buckets.
    ///
    /// Rules are matched by name. A same-name rule whose security-relevant fields
    /// changed (see [`RuleConfig::reload_differs`]) lands in `changed` and is
    /// applied as a remove + add by the reload path, so an edit that switches the
    /// security provider, retargets the upstream, or tightens posture is actually
    /// re-applied (previously such edits were classified `unchanged` and silently
    /// ignored — CWE-693).
    pub fn diff(&self, new: &GatewayConfig) -> ConfigDiff {
        let old_by_name: std::collections::HashMap<&str, &RuleConfig> =
            self.rules.iter().map(|r| (r.name.as_str(), r)).collect();
        let new_names: std::collections::HashSet<&str> =
            new.rules.iter().map(|r| r.name.as_str()).collect();

        let mut added = Vec::new();
        let mut changed = Vec::new();
        let mut unchanged = Vec::new();
        for r in &new.rules {
            match old_by_name.get(r.name.as_str()) {
                None => added.push(r.clone()),
                Some(old) if old.reload_differs(r) => changed.push(r.clone()),
                Some(_) => unchanged.push(r.name.clone()),
            }
        }

        let removed: Vec<String> = self
            .rules
            .iter()
            .filter(|r| !new_names.contains(r.name.as_str()))
            .map(|r| r.name.clone())
            .collect();

        // Whether the set of intercept-bearing rules changed at all (added,
        // removed, or an intercept/listen edit) — drives firewall reconciliation
        // on hot-reload (CP-09). `removed` carries names only, so this is computed
        // here where both full configs are in scope.
        let intercept_changed = Self::intercept_projection(self) != Self::intercept_projection(new);

        ConfigDiff {
            added,
            removed,
            changed,
            unchanged,
            intercept_changed,
        }
    }

    /// Sorted `(name, listen_addr, listen_proto, intercept)` projection of the
    /// intercept-bearing rules, so two configs compare equal iff their firewall
    /// interception posture is identical (CP-09).
    fn intercept_projection(cfg: &GatewayConfig) -> Vec<(String, String, Proto, InterceptConfig)> {
        let mut v: Vec<_> = cfg
            .rules
            .iter()
            .filter_map(|r| {
                r.intercept.as_ref().map(|ic| {
                    (
                        r.name.clone(),
                        r.listen_addr.clone(),
                        r.listen_proto,
                        ic.clone(),
                    )
                })
            })
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }
}

/// Result of diffing two configurations.
#[derive(Debug)]
pub struct ConfigDiff {
    /// Rules present only in the new config (start them).
    pub added: Vec<RuleConfig>,
    /// Names present only in the old config (stop them).
    pub removed: Vec<String>,
    /// Same-name rules whose security-relevant fields changed (restart them).
    pub changed: Vec<RuleConfig>,
    /// Same-name rules with no security-relevant change (leave running).
    pub unchanged: Vec<String>,
    /// Whether the firewall interception posture (the set of intercept-bearing
    /// rules and their intercept/listen fields) changed — drives firewall
    /// reconciliation on hot-reload (CP-09).
    pub intercept_changed: bool,
}

impl ConfigDiff {
    /// One greppable `AUDIT reload …` summary line naming the rules a hot-reload
    /// added / changed / removed, so a posture-loosening reload leaves a positive
    /// audit trail (CP-05), not just the per-rule start/stop `info` lines.
    pub fn format_reload_audit(&self) -> String {
        let names = |rules: &[RuleConfig]| {
            rules
                .iter()
                .map(|r| r.name.clone())
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "AUDIT reload added=[{}] changed=[{}] removed=[{}] unchanged={}",
            names(&self.added),
            names(&self.changed),
            self.removed.join(","),
            self.unchanged.len()
        )
    }
}

/// Best-effort: does this `host:port` upstream point at loopback? Used only to
/// decide whether to *warn* about an unverified upstream, so it is conservative
/// — an unresolved hostname or `"auto"` (transparent, no static host) is treated
/// as non-loopback and thus warned about.
fn upstream_is_loopback(upstream_addr: &str) -> bool {
    if upstream_addr == "auto" {
        return false;
    }
    let host = match crate::security::tls_engine::params::host_of(upstream_addr) {
        Some(h) => h,
        None => return false,
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Whether a decrypt rule's `listen_addr` is a routable (non-loopback) bind, used
/// to decide whether an unauthenticated-decrypt posture is an error. A
/// local UDS/SHM listener (unparseable as `SocketAddr`) is treated as loopback —
/// its callers are already kernel-authenticated, so it never escalates.
fn listen_is_non_loopback(listen_addr: &str) -> bool {
    listen_addr
        .parse::<std::net::SocketAddr>()
        .map(|a| !a.ip().is_loopback())
        .unwrap_or(false)
}

/// Describe a config/anchor file that is group- or other-writable
/// (`st_mode & 0o022 != 0`), so a co-located actor cannot silently rewrite the
/// posture it feeds (CP-06/CP-07). `None` for a correctly-restricted file. Pure
/// (mode read via `MetadataExt`) so the message is testable.
pub(crate) fn world_or_group_writable_warning(path: &Path, what: &str) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let mode = std::fs::metadata(path).ok()?.mode();
    (mode & 0o022 != 0).then(|| {
        format!(
            "{what} '{}' is group/other-writable (mode {:o}) — a co-located actor \
             could rewrite it; restrict it to 0644 or tighter (owner-writable only)",
            path.display(),
            mode & 0o7777
        )
    })
}

/// Heuristic for the safety-classification warning: a source pattern that is
/// `any`, a CIDR wider than a single host, or a non-loopback literal is
/// considered "wide/untrusted" and worth flagging. Loopback and single-host
/// trusted literals are not flagged.
/// Probe whether this process may set `IP_TRANSPARENT` on a socket — the
/// `CAP_NET_ADMIN` capability check behind transparent/TPROXY and intercept
/// preflight. Shared by both preflight call sites so the `unsafe` probe exists
/// exactly once.
///
/// Returns `None` when no probe socket could be created (nothing can be
/// concluded), `Some(true)` when the kernel accepted the option, and
/// `Some(false)` when it was refused (typically `EPERM`: missing
/// `CAP_NET_ADMIN`).
fn probe_ip_transparent() -> Option<bool> {
    // SAFETY: `libc::socket` takes only scalar arguments and has no pointer
    // preconditions; its return value is checked (`fd >= 0`) before `fd` is used.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return None;
    }
    let one: libc::c_int = 1;
    // SAFETY: `fd` is a valid open descriptor (checked `fd >= 0` above); the
    // option pointer/len pair point to a fully-initialised `libc::c_int`
    // (`one`) whose size is passed exactly via `size_of::<c_int>()`; the
    // return value is checked below.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    // SAFETY: `fd` is the valid descriptor returned by `socket` above and is
    // not used after this call, so closing it exactly once is sound.
    unsafe {
        libc::close(fd);
    }
    Some(ret == 0)
}

fn is_wide_untrusted_source(source: &str) -> bool {
    let s = source.trim();
    if s.eq_ignore_ascii_case("any") || s == "*" {
        return true;
    }
    // CIDR: wide unless it is a *family-correct* single-host prefix (/32 for
    // IPv4, /128 for IPv6 — an IPv6 "/32" spans 2^96 addresses). A single-host
    // CIDR is then held to the same trust rule as the equivalent bare literal
    // below: trusted only when loopback.
    if let Some((ip_str, prefix)) = s.split_once('/') {
        return match ip_str.trim().parse::<std::net::IpAddr>() {
            Ok(ip)
                if (ip.is_ipv4() && prefix.trim() == "32")
                    || (ip.is_ipv6() && prefix.trim() == "128") =>
            {
                !ip.is_loopback()
            }
            _ => true,
        };
    }
    // Bare host/IP[:port]: trusted only if it is a loopback literal.
    let host = crate::security::tls_engine::params::host_of(s).unwrap_or_else(|| s.to_string());
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => !ip.is_loopback(),
        // Unresolved hostname: treat as wide/untrusted (conservative).
        Err(_) => true,
    }
}

#[cfg(test)]
mod address_pattern_tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    // An IPv4-mapped IPv6 peer (dual-stack `[::]` listener) matches an
    // IPv4 CIDR / IP-only / exact whitelist entry after canonicalization.
    #[test]
    fn mapped_v4_peer_matches_v4_patterns() {
        let cidr = AddressPattern::parse("10.0.0.0/8").unwrap();
        let ip_only = AddressPattern::parse("10.0.0.5").unwrap();
        let exact = AddressPattern::parse("10.0.0.5:5000").unwrap();

        let mapped = sa("[::ffff:10.0.0.5]:5000");
        assert!(cidr.matches(&mapped), "mapped v4 must match v4 CIDR");
        assert!(ip_only.matches(&mapped), "mapped v4 must match v4 IP-only");
        assert!(exact.matches(&mapped), "mapped v4 must match v4 exact");

        // A native v4 peer still matches (regression guard).
        let native = sa("10.0.0.5:5000");
        assert!(cidr.matches(&native));
        assert!(ip_only.matches(&native));
        assert!(exact.matches(&native));
    }

    // A mapped v4 peer whose address is outside the pattern still does not match.
    #[test]
    fn mapped_v4_peer_respects_pattern_bounds() {
        let cidr = AddressPattern::parse("10.0.0.0/8").unwrap();
        assert!(!cidr.matches(&sa("[::ffff:192.168.1.1]:1")));
        let exact = AddressPattern::parse("10.0.0.5:5000").unwrap();
        // Right IP, wrong port.
        assert!(!exact.matches(&sa("[::ffff:10.0.0.5]:5001")));
    }

    // Native IPv6 matching is unaffected, and a v4 peer never matches a v6 pattern.
    #[test]
    fn native_v6_and_cross_family_unaffected() {
        let v6 = AddressPattern::parse("2001:db8::/32").unwrap();
        assert!(v6.matches(&sa("[2001:db8::1]:443")));
        assert!(!v6.matches(&sa("[2001:dead::1]:443")));
        // A genuine v4 peer must not match a v6 whitelist.
        assert!(!v6.matches(&sa("10.0.0.1:1")));
    }
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
    fn validate_bounds_conn_pool_size() {
        // TRA #57: the configurable base pool size must be range-checked before
        // any thread is spawned — 0 (no workers) and over-cap (thread storm) are
        // rejected at validate()/--validate time; omitting it keeps the default.
        let with_pool = |size: serde_json::Value| -> GatewayConfig {
            serde_json::from_value(serde_json::json!({
                "conn_pool_size": size,
                "rules": [{
                    "name": "r",
                    "direction": "encrypt",
                    "listen_addr": "127.0.0.1:8080",
                    "upstream_addr": "127.0.0.1:9000",
                    "security_provider": "tls",
                    "verify": "none"
                }]
            }))
            .expect("deserialize config")
        };

        let zero_err = with_pool(serde_json::json!(0)).validate().unwrap_err();
        assert!(
            zero_err.contains("conn_pool_size"),
            "unexpected error: {zero_err}"
        );

        let over_err = with_pool(serde_json::json!(MAX_CONN_POOL_SIZE + 1))
            .validate()
            .unwrap_err();
        assert!(
            over_err.contains("conn_pool_size"),
            "unexpected error: {over_err}"
        );

        assert!(with_pool(serde_json::json!(64)).validate().is_ok());
        assert!(with_pool(serde_json::json!(MAX_CONN_POOL_SIZE))
            .validate()
            .is_ok());
        // Omitted → None → ConnectionPool::default_size(); always valid.
        let omitted: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "r",
                "direction": "encrypt",
                "listen_addr": "127.0.0.1:8080",
                "upstream_addr": "127.0.0.1:9000",
                "security_provider": "tls",
                "verify": "none"
            }]
        }))
        .expect("deserialize config");
        assert!(omitted.conn_pool_size.is_none());
        assert!(omitted.validate().is_ok());
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
    fn validate_covers_dtls_provider_params() {
        // DTLS rules are now parsed at validate time (closing a gap where a bad
        // DTLS param only failed at first connection). A zero session cap is
        // rejected here.
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "dtls-bad",
                "direction": "encrypt",
                "listen_addr": "127.0.0.1:6000",
                "listen_proto": "udp",
                "upstream_addr": "127.0.0.1:6001",
                "upstream_proto": "udp",
                "security_provider": "dtls",
                "protocol_version": "dtls1.2",
                "verify": "none",
                "max_sessions": 0
            }]
        }))
        .expect("deserialize config");
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("max_sessions"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_dtls_missing_verify() {
        // Fail-secure: a default-profile DTLS rule must set `verify` explicitly.
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "dtls-noverify",
                "direction": "encrypt",
                "listen_addr": "127.0.0.1:6000",
                "listen_proto": "udp",
                "upstream_addr": "127.0.0.1:6001",
                "upstream_proto": "udp",
                "security_provider": "dtls",
                "protocol_version": "dtls1.2"
            }]
        }))
        .expect("deserialize config");
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("verify"), "unexpected error: {err}");
    }

    fn config_with_rule(extra: serde_json::Value) -> GatewayConfig {
        let mut rule = serde_json::json!({
            "name": "r",
            "direction": "encrypt",
            "listen_addr": "127.0.0.1:8080",
            "upstream_addr": "backend:443",
            "security_provider": "tls",
            "verify": "none"
        });
        if let (Some(b), Some(e)) = (rule.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                b.insert(k.clone(), v.clone());
            }
        }
        serde_json::from_value(serde_json::json!({ "rules": [rule] })).expect("deserialize config")
    }

    #[test]
    fn diff_flags_changed_upstream_and_provider() {
        let base = config_with_rule(serde_json::json!({}));

        // Retargeted upstream → changed (not unchanged).
        let new_upstream = config_with_rule(serde_json::json!({ "upstream_addr": "other:443" }));
        let d = base.diff(&new_upstream);
        assert_eq!(d.changed.len(), 1, "upstream change must be detected");
        assert!(d.unchanged.is_empty() && d.added.is_empty() && d.removed.is_empty());

        // Switched verify mode (provider_params) → changed.
        let new_verify = config_with_rule(serde_json::json!({ "verify": "server" }));
        let d = base.diff(&new_verify);
        assert_eq!(d.changed.len(), 1, "verify-mode change must be detected");
    }

    #[test]
    fn diff_ignores_perf_only_edits() {
        let base = config_with_rule(serde_json::json!({}));
        // A perf-only knob change must NOT restart the listener.
        let tuned = config_with_rule(serde_json::json!({ "sock_buf_size": 1048576 }));
        let d = base.diff(&tuned);
        assert!(
            d.changed.is_empty(),
            "perf-only edit should not be a security-relevant change"
        );
        assert_eq!(d.unchanged, vec!["r".to_string()]);
    }

    #[test]
    fn diff_tracks_added_and_removed() {
        let base = config_with_rule(serde_json::json!({}));
        let empty: GatewayConfig =
            serde_json::from_value(serde_json::json!({ "rules": [] })).unwrap();
        // Rule removed.
        let d = base.diff(&empty);
        assert_eq!(d.removed, vec!["r".to_string()]);
        // Rule added.
        let d = empty.diff(&base);
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].name, "r");
    }

    // CP-09: the diff flags whether the firewall interception posture changed.
    #[test]
    fn diff_sets_intercept_changed() {
        let with_intercept = |mode: &str| -> GatewayConfig {
            serde_json::from_value(serde_json::json!({
                "rules": [{
                    "name": "r",
                    "direction": "decrypt",
                    "listen_addr": "0.0.0.0:9443",
                    "upstream_addr": "auto",
                    "transparent": true,
                    "intercept": { "mode": mode, "match_dports": "443" }
                }]
            }))
            .unwrap()
        };
        let plain = config_with_rule(serde_json::json!({}));
        let tp = with_intercept("tproxy");

        // Add an intercept rule (plain → tproxy) and remove it (tproxy → plain).
        assert!(plain.diff(&tp).intercept_changed, "adding intercept");
        assert!(tp.diff(&plain).intercept_changed, "removing intercept");
        // Edit the intercept mode.
        assert!(
            tp.diff(&with_intercept("ingress_redirect"))
                .intercept_changed,
            "changing intercept mode"
        );
        // A non-intercept edit leaves it unchanged.
        assert!(
            !plain
                .diff(&config_with_rule(serde_json::json!({ "sni": "x" })))
                .intercept_changed,
            "non-intercept edit must not flag intercept_changed"
        );
        // Identical config → no change.
        assert!(!tp.diff(&with_intercept("tproxy")).intercept_changed);
    }

    // CP-05: the reload audit line names the added/changed/removed rules.
    #[test]
    fn reload_audit_line_lists_rule_names() {
        let base = config_with_rule(serde_json::json!({}));
        let empty: GatewayConfig =
            serde_json::from_value(serde_json::json!({ "rules": [] })).unwrap();
        let added = empty.diff(&base).format_reload_audit();
        assert!(added.starts_with("AUDIT reload"), "{added}");
        assert!(added.contains("added=[r]"), "{added}");
        assert!(added.contains("removed=[]"), "{added}");

        let removed = base.diff(&empty).format_reload_audit();
        assert!(removed.contains("removed=[r]"), "{removed}");
        assert!(removed.contains("added=[]"), "{removed}");
    }

    fn warnings_of(cfg: &GatewayConfig) -> Vec<String> {
        cfg.preflight_check().0
    }

    fn errors_of(cfg: &GatewayConfig) -> Vec<String> {
        cfg.preflight_check().1
    }

    // Verify:none to a non-loopback upstream is a preflight ERROR
    // (fails --validate) rather than a warning.
    #[test]
    fn preflight_errors_on_unverified_remote_encrypt() {
        let cfg = config_with_rule(serde_json::json!({ "upstream_addr": "backend:443" }));
        assert!(
            errors_of(&cfg)
                .iter()
                .any(|w| w.contains("without peer verification")),
            "expected an unverified-upstream ERROR"
        );
    }

    // The opt-in downgrades that error back to a warning.
    #[test]
    fn preflight_downgrades_unverified_encrypt_with_opt_in() {
        let cfg = config_with_rule(serde_json::json!({
            "upstream_addr": "backend:443",
        }));
        let cfg = GatewayConfig {
            allow_unverified_transport: true,
            ..cfg
        };
        assert!(
            !errors_of(&cfg)
                .iter()
                .any(|w| w.contains("without peer verification")),
            "opt-in must remove the error"
        );
        assert!(
            warnings_of(&cfg)
                .iter()
                .any(|w| w.contains("without peer verification")),
            "opt-in keeps a warning"
        );
    }

    #[test]
    fn preflight_silent_on_loopback_encrypt() {
        // A loopback upstream is trusted — no MITM warning or error.
        let cfg = config_with_rule(serde_json::json!({ "upstream_addr": "127.0.0.1:9000" }));
        let has = |v: Vec<String>| v.iter().any(|w| w.contains("without peer verification"));
        assert!(!has(warnings_of(&cfg)) && !has(errors_of(&cfg)));
    }

    // ── Plaintext UDP routing (routing provider over a udp listener) ─────────

    /// A valid plaintext `routing`+`udp` rule (loopback) merged with `extra`.
    fn routing_udp_rule(extra: serde_json::Value) -> GatewayConfig {
        let mut base = serde_json::json!({
            "security_provider": "routing",
            "listen_proto": "udp",
            "listen_addr": "127.0.0.1:8080",
            "upstream_addr": "127.0.0.1:9000",
            "upstream_proto": "udp"
        });
        if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                b.insert(k.clone(), v.clone());
            }
        }
        config_with_rule(base)
    }

    #[test]
    fn validate_rejects_routing_udp_non_udp_upstream() {
        let err = routing_udp_rule(serde_json::json!({ "upstream_proto": "tcp" }))
            .validate()
            .unwrap_err();
        assert!(
            err.contains("routing over udp requires upstream_proto"),
            "{err}"
        );
    }

    #[test]
    fn validate_rejects_routing_udp_auto_upstream() {
        let err =
            routing_udp_rule(serde_json::json!({ "upstream_addr": "auto", "transparent": true }))
                .validate()
                .unwrap_err();
        assert!(
            err.contains("does not support upstream_addr = \"auto\""),
            "{err}"
        );
    }

    #[test]
    fn validate_rejects_routing_udp_zero_session_bounds() {
        for key in ["max_sessions", "idle_ttl_secs"] {
            let err = routing_udp_rule(serde_json::json!({ key: 0 }))
                .validate()
                .unwrap_err();
            assert!(err.contains("must be a positive integer"), "{key}: {err}");
        }
    }

    #[test]
    fn validate_accepts_routing_udp() {
        // Explicit bounds, and omitted bounds (shared defaults), both validate.
        assert!(
            routing_udp_rule(serde_json::json!({ "max_sessions": 512, "idle_ttl_secs": 30 }))
                .validate()
                .is_ok()
        );
        assert!(routing_udp_rule(serde_json::json!({})).validate().is_ok());
    }

    // TRA #83: plaintext routing on the *wire* (tcp/udp) is a non-loopback ERROR
    // by default, downgraded to a warning by `allow_unverified_transport`; a
    // loopback listener stays a warning.
    #[test]
    fn preflight_errors_on_wire_routing_non_loopback() {
        let cfg = routing_udp_rule(serde_json::json!({ "listen_addr": "0.0.0.0:8080" }));
        assert!(
            errors_of(&cfg)
                .iter()
                .any(|e| e.contains("cleartext on the wire")),
            "expected a cleartext-on-wire ERROR: {:?}",
            errors_of(&cfg)
        );
    }

    #[test]
    fn preflight_warns_on_wire_routing_loopback() {
        let cfg = routing_udp_rule(serde_json::json!({}));
        assert!(
            warnings_of(&cfg)
                .iter()
                .any(|w| w.contains("cleartext on the wire")),
            "loopback routing → warning"
        );
        assert!(
            !errors_of(&cfg)
                .iter()
                .any(|e| e.contains("cleartext on the wire")),
            "loopback routing → not an error"
        );
    }

    #[test]
    fn preflight_downgrades_wire_routing_with_opt_in() {
        let cfg = routing_udp_rule(serde_json::json!({ "listen_addr": "0.0.0.0:8080" }));
        let cfg = GatewayConfig {
            allow_unverified_transport: true,
            ..cfg
        };
        assert!(
            !errors_of(&cfg)
                .iter()
                .any(|e| e.contains("cleartext on the wire")),
            "opt-in removes the error"
        );
        assert!(
            warnings_of(&cfg)
                .iter()
                .any(|w| w.contains("cleartext on the wire")),
            "opt-in keeps a warning"
        );
    }

    #[test]
    fn preflight_warns_on_unauthenticated_decrypt() {
        // decrypt + non-mutual verify on a LOOPBACK listen → warning (not error).
        let cfg = config_with_rule(serde_json::json!({
            "direction": "decrypt",
            "verify": "server"
        }));
        assert!(
            warnings_of(&cfg)
                .iter()
                .any(|w| w.contains("does not require client certificates")),
            "expected an unauthenticated-decrypt warning"
        );
        assert!(
            !errors_of(&cfg)
                .iter()
                .any(|w| w.contains("does not require client certificates")),
            "loopback decrypt must not escalate to an error"
        );
    }

    // Non-mutual decrypt on a NON-loopback listen is an error.
    #[test]
    fn preflight_errors_on_nonloopback_unauthenticated_decrypt() {
        let cfg = config_with_rule(serde_json::json!({
            "direction": "decrypt",
            "listen_addr": "0.0.0.0:8443",
            "verify": "server"
        }));
        assert!(
            errors_of(&cfg)
                .iter()
                .any(|w| w.contains("does not require client certificates")),
            "expected a non-loopback unauthenticated-decrypt ERROR"
        );
    }

    #[test]
    fn preflight_silent_on_mutual_decrypt() {
        let cfg = config_with_rule(serde_json::json!({
            "direction": "decrypt",
            "verify": "mutual"
        }));
        assert!(
            !warnings_of(&cfg)
                .iter()
                .any(|w| w.contains("does not require client certificates")),
            "mutual decrypt should not warn"
        );
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("scg-cfg-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    // CP-06: a group/other-writable config file is flagged.
    #[test]
    fn preflight_warns_on_group_writable_config_file() {
        let dir = tmp_dir("gwritable");
        let path = dir.join("gw.json");
        std::fs::write(&path, r#"{"rules":[]}"#).unwrap();
        chmod(&path, 0o664);
        let mut cfg: GatewayConfig = serde_json::from_str(r#"{"rules":[]}"#).unwrap();
        cfg.source_path = Some(path);
        assert!(warnings_of(&cfg)
            .iter()
            .any(|w| w.contains("group/other-writable")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn preflight_silent_on_0644_config_file() {
        let dir = tmp_dir("g644");
        let path = dir.join("gw.json");
        std::fs::write(&path, r#"{"rules":[]}"#).unwrap();
        chmod(&path, 0o644);
        let mut cfg: GatewayConfig = serde_json::from_str(r#"{"rules":[]}"#).unwrap();
        cfg.source_path = Some(path);
        assert!(!warnings_of(&cfg)
            .iter()
            .any(|w| w.contains("group/other-writable")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // SUN_LEN: an over-long management socket path is a preflight error, so the
    // operator sees it at --validate rather than as a runtime bind failure.
    #[test]
    fn preflight_errors_on_overlong_mgmt_socket_path() {
        let long_path = format!("/tmp/{}/mgmt.sock", "x".repeat(120));
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [],
            "api": { "enabled": true, "uds_path": long_path, "runtime_dir": "/run/scg" }
        }))
        .unwrap();
        assert!(errors_of(&cfg)
            .iter()
            .any(|e| e.contains("SUN_LEN") && e.contains("uds_path")));
    }

    #[test]
    fn preflight_silent_on_short_mgmt_socket_path() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [],
            "api": { "enabled": true, "uds_path": "/run/scg/mgmt.sock", "runtime_dir": "/run/scg" }
        }))
        .unwrap();
        assert!(!errors_of(&cfg).iter().any(|e| e.contains("SUN_LEN")));
    }

    // KC-01: a world-readable/writable private key file is flagged in preflight.
    #[test]
    fn preflight_warns_on_world_readable_key() {
        let dir = tmp_dir("keyperm");
        let key = dir.join("k.pem");
        let cert = dir.join("c.pem");
        std::fs::write(&key, b"x").unwrap();
        std::fs::write(&cert, b"x").unwrap();
        chmod(&key, 0o644);
        let cfg = config_with_rule(serde_json::json!({
            "verify": "server",
            "upstream_addr": "127.0.0.1:9000",
            // cert_path/key_path are flattened into provider_params.
            "cert_path": cert.to_str().unwrap(),
            "key_path": key.to_str().unwrap(),
        }));
        assert!(warnings_of(&cfg)
            .iter()
            .any(|w| w.contains("private key") && w.contains("644")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn uds_rule(provider: &str) -> GatewayConfig {
        serde_json::from_value(serde_json::json!({
            "rules": [{
                "name": "r",
                "direction": "encrypt",
                "listen_addr": "unused",
                "listen_proto": "uds",
                "upstream_addr": "127.0.0.1:9000",
                "security_provider": provider,
                "app_id": "app",
                "allowed_uids": [0]
            }]
        }))
        .expect("deserialize config")
    }

    #[test]
    fn preflight_warns_on_plaintext_routing_local_endpoint() {
        // A routing UDS/SHM endpoint relays cleartext — the operator must be
        // warned that there is no local-IPC encryption (TRA #58 criterion 3).
        let cfg = uds_rule("routing");
        assert!(
            warnings_of(&cfg)
                .iter()
                .any(|w| w.contains("no local-IPC encryption")),
            "expected a cleartext routing-local-endpoint warning"
        );
    }

    #[test]
    fn preflight_silent_on_tls_local_endpoint() {
        // A tls local endpoint is encrypted — no cleartext warning.
        let cfg = uds_rule("tls");
        assert!(
            !warnings_of(&cfg)
                .iter()
                .any(|w| w.contains("no local-IPC encryption")),
            "tls local endpoint should not warn about cleartext"
        );
    }

    #[test]
    fn enforce_policy_on_safety_defaults_false() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
            "rules": [],
            "policy": { "default_action": "deny" }
        }))
        .expect("deserialize config");
        assert!(!cfg.policy.unwrap().enforce_policy_on_safety);
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

#[cfg(test)]
mod validation_hardening_tests {
    //! Load-time validation hardening from the 2026-07-02 code review:
    //! M12 (duplicate UDS/SHM template keys), M13 (DTLS checks keyed to the
    //! effective provider), M14 (protocol_version enforced on every load
    //! path), L14 (provider precedence), L15 (upstream host:port rigor),
    //! L16 (family-aware wide-source heuristic), L25 (validate_ip_or_cidr
    //! delegates to AddressPattern::parse), and the TRA #74 dtls+auto
    //! rejection.
    use super::*;

    fn cfg(rules: serde_json::Value) -> GatewayConfig {
        serde_json::from_value(serde_json::json!({ "rules": rules })).expect("deserialize config")
    }

    fn tls_rule(name: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut base = serde_json::json!({
            "name": name,
            "direction": "encrypt",
            "listen_addr": format!("127.0.0.1:{}", 18000 + name.len()),
            "upstream_addr": "127.0.0.1:9000",
            "security_provider": "tls",
            "verify": "none"
        });
        if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                b.insert(k.clone(), v.clone());
            }
        }
        base
    }

    // ── TRA #74: dtls + upstream_addr="auto" is rejected fail-closed ────────

    #[test]
    fn validate_rejects_dtls_auto_upstream_modern_key() {
        let c = cfg(serde_json::json!([tls_rule(
            "d",
            serde_json::json!({
                "security_provider": "dtls",
                "listen_proto": "udp",
                "upstream_proto": "udp",
                "upstream_addr": "auto",
                "transparent": true
            })
        )]));
        let err = c.validate().unwrap_err();
        assert!(err.contains("auto"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_dtls_auto_upstream_legacy_tls_mode() {
        let mut rule = tls_rule(
            "d",
            serde_json::json!({
                "listen_proto": "udp",
                "upstream_proto": "udp",
                "upstream_addr": "auto",
                "transparent": true,
                "tls_mode": "dtls"
            }),
        );
        // Legacy spelling: no security_provider key at all.
        rule.as_object_mut().unwrap().remove("security_provider");
        let err = cfg(serde_json::json!([rule])).validate().unwrap_err();
        assert!(err.contains("auto"), "unexpected error: {err}");
    }

    // ── M13: DTLS UDP-only keyed to the effective provider ──────────────────

    #[test]
    fn validate_rejects_dtls_provider_on_tcp() {
        let c = cfg(serde_json::json!([tls_rule(
            "d",
            serde_json::json!({
                "security_provider": "dtls",
                "listen_proto": "tcp"
            })
        )]));
        let err = c.validate().unwrap_err();
        assert!(
            err.contains("udp") || err.contains("UDP"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_rejects_legacy_dtls_on_tcp() {
        let mut rule = tls_rule(
            "d",
            serde_json::json!({
                "listen_proto": "tcp",
                "tls_mode": "dtls"
            }),
        );
        rule.as_object_mut().unwrap().remove("security_provider");
        let err = cfg(serde_json::json!([rule])).validate().unwrap_err();
        assert!(
            err.contains("udp") || err.contains("UDP"),
            "unexpected error: {err}"
        );
    }

    // ── M12: duplicate UDS/SHM template keys ────────────────────────────────

    fn uds_rule(name: &str, app_id: &str, direction: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "direction": direction,
            "listen_proto": "uds",
            "listen_addr": "",
            "upstream_addr": "127.0.0.1:9000",
            "app_id": app_id,
            "allowed_uids": [1000],
            "security_provider": "routing"
        })
    }

    #[test]
    fn validate_rejects_duplicate_uds_template_key() {
        // Same (app_id, class, direction, kind): the second rule would
        // silently shadow the first's allow-lists at runtime.
        let c = cfg(serde_json::json!([
            uds_rule("a", "etcs", "encrypt"),
            uds_rule("b", "etcs", "encrypt"),
        ]));
        let err = c.validate().unwrap_err();
        assert!(
            err.contains("duplicate local-endpoint template"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_accepts_same_app_id_different_direction() {
        let c = cfg(serde_json::json!([
            uds_rule("a", "etcs", "encrypt"),
            uds_rule("b", "etcs", "decrypt"),
        ]));
        assert!(c.validate().is_ok(), "{:?}", c.validate());
    }

    // ── M14: protocol_version enforced by validate() on every load path ─────

    #[test]
    fn validate_rejects_bad_protocol_version_tls() {
        let c = cfg(serde_json::json!([tls_rule(
            "t",
            serde_json::json!({ "protocol_version": "tls1.4" })
        )]));
        let err = c.validate().unwrap_err();
        assert!(err.contains("protocol_version"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_bad_protocol_version_dtls() {
        let c = cfg(serde_json::json!([tls_rule(
            "d",
            serde_json::json!({
                "security_provider": "dtls",
                "listen_proto": "udp",
                "upstream_proto": "udp",
                "protocol_version": "dtls9"
            })
        )]));
        let err = c.validate().unwrap_err();
        assert!(err.contains("protocol_version"), "unexpected error: {err}");
    }

    #[test]
    fn from_value_rejects_bad_protocol_version() {
        // from_value is the hot-reload / lite-config choke point — the same
        // typo that --validate rejects must fail here too (M14: previously it
        // silently ran as the TLS 1.2 default after a hot reload).
        let err = GatewayConfig::from_value(serde_json::json!({
            "rules": [tls_rule("t", serde_json::json!({ "protocol_version": "tls13" }))]
        }))
        .unwrap_err();
        assert!(err.contains("protocol_version"), "unexpected error: {err}");
    }

    #[test]
    fn validate_accepts_valid_protocol_versions() {
        for v in ["tls1.2", "tls1.3"] {
            let c = cfg(serde_json::json!([tls_rule(
                "t",
                serde_json::json!({ "protocol_version": v })
            )]));
            assert!(c.validate().is_ok(), "version {v}: {:?}", c.validate());
        }
    }

    // ── L15: upstream_addr host:port rigor ──────────────────────────────────

    #[test]
    fn validate_rejects_malformed_upstream_addrs() {
        for bad in [
            "backend",
            "host:",
            ":443",
            "host:0",
            "host:99999",
            "host:port",
        ] {
            let c = cfg(serde_json::json!([tls_rule(
                "t",
                serde_json::json!({ "upstream_addr": bad })
            )]));
            let err = c.validate().unwrap_err();
            assert!(
                err.contains("upstream_addr"),
                "'{bad}' should be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn validate_accepts_wellformed_upstream_addrs() {
        for good in ["10.0.0.1:8443", "[::1]:443", "backend.example.com:443"] {
            let c = cfg(serde_json::json!([tls_rule(
                "t",
                serde_json::json!({ "upstream_addr": good })
            )]));
            assert!(c.validate().is_ok(), "'{good}': {:?}", c.validate());
        }
    }

    // ── L14: provider precedence table ──────────────────────────────────────

    #[test]
    fn effective_security_provider_precedence() {
        let rule = |sp: Option<&str>, tm: Option<&str>| -> RuleConfig {
            let mut base = serde_json::json!({
                "name": "r",
                "direction": "encrypt",
                "listen_addr": "127.0.0.1:1",
            });
            let obj = base.as_object_mut().unwrap();
            if let Some(sp) = sp {
                obj.insert("security_provider".into(), serde_json::json!(sp));
            }
            if let Some(tm) = tm {
                obj.insert("tls_mode".into(), serde_json::json!(tm));
            }
            serde_json::from_value(base).expect("deserialize rule")
        };
        // (security_provider, tls_mode) → effective
        let table = [
            (None, None, "tls"),
            (None, Some("ktls"), "ktls"),
            (None, Some("dtls"), "dtls"),
            (Some("tls"), Some("dtls"), "dtls"), // documented: tls_mode wins over (default-indistinguishable) "tls"
            (Some("ktls"), None, "ktls"),
            (Some("ktls"), Some("dtls"), "ktls"), // non-"tls" provider wins over tls_mode
            (Some("wireguard"), Some("dtls"), "wireguard"),
        ];
        for (sp, tm, want) in table {
            assert_eq!(
                rule(sp, tm).effective_security_provider(),
                want,
                "sp={sp:?} tls_mode={tm:?}"
            );
        }
    }

    // ── L16: family-aware wide-source heuristic ─────────────────────────────

    #[test]
    fn wide_source_heuristic_is_family_aware() {
        // Wide shapes.
        assert!(is_wide_untrusted_source("any"));
        assert!(is_wide_untrusted_source("0.0.0.0/0"));
        assert!(is_wide_untrusted_source("10.0.0.0/8"));
        // An IPv6 /32 spans 2^96 addresses — must be wide (was the L16 bug).
        assert!(is_wide_untrusted_source("2001:db8::/32"));
        // Family-correct single-host prefixes follow the bare-literal rule:
        // trusted only when loopback.
        assert!(!is_wide_untrusted_source("127.0.0.1/32"));
        assert!(!is_wide_untrusted_source("::1/128"));
        assert!(is_wide_untrusted_source("10.1.2.3/32"));
        assert!(is_wide_untrusted_source("2001:db8::1/128"));
        // Consistent with the bare literals:
        assert!(is_wide_untrusted_source("10.1.2.3"));
        assert!(!is_wide_untrusted_source("127.0.0.1"));
        // Junk prefixes stay wide (fail-safe for an advisory).
        assert!(is_wide_untrusted_source("nonsense/32"));
    }

    // ── L25: validate_ip_or_cidr delegates to AddressPattern::parse ─────────

    #[test]
    fn validate_ip_or_cidr_matches_address_pattern_semantics() {
        // Accepted: bare IPs and CIDRs of both families.
        for good in [
            "10.0.0.1",
            "10.0.0.0/8",
            "fe80::1",
            "fe80::/10",
            "0.0.0.0/0",
        ] {
            assert!(
                GatewayConfig::validate_ip_or_cidr(good).is_ok(),
                "'{good}' should be accepted"
            );
        }
        // Rejected: out-of-range prefixes, malformed IPs, and pattern shapes
        // that are not address-only.
        for bad in [
            "10.0.0.0/33",
            "fe80::/129",
            "1.2.3/8",
            "not-an-ip",
            "any",
            "1.2.3.4:80",
        ] {
            assert!(
                GatewayConfig::validate_ip_or_cidr(bad).is_err(),
                "'{bad}' should be rejected"
            );
        }
        // Parity with AddressPattern::parse on the shared corpus: everything
        // validate_ip_or_cidr accepts must parse as a pattern too.
        for s in ["10.0.0.1", "10.0.0.0/8", "fe80::/10"] {
            assert!(AddressPattern::parse(s).is_ok());
        }
    }
}
