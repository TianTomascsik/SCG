//! Interface manager: owns the lifecycle of dynamically-created local
//! interfaces (UDS today; SHM in a later work package).
//!
//! `uds`/`shm` rules in the gateway config act as *templates*: they are not
//! started as listeners at boot. Instead, an application asks the management API
//! to create an endpoint for its `(app_id, traffic_class, direction)`; the
//! manager authorises the caller from config, spawns a dedicated endpoint
//! thread, and returns the socket path plus a single-use capability token.

// These methods return `Result<_, tonic::Status>` to mirror the management-API
// surface they back; `Status` is large but is mandated by the tonic service
// trait (see `api::grpc`), so the error cannot be boxed. Allow the lint here.
#![allow(clippy::result_large_err)]

use crate::interfaces::endpoint::upstream_tls_mode;
use crate::interfaces::shm::{resolve_shm_layout, run_shm_endpoint, ShmEndpointTask};
use crate::interfaces::uds::{run_uds_endpoint, UdsEndpointTask};
use crate::management::config::{
    Direction, GatewayConfig, PerfKnobs, Proto, QosPolicy, ShmNotify, ShmRingKind, TlsMode,
    TrafficClass,
};
use crate::processing::policy::PolicyManager;

use scg_ipc::token::CapabilityToken;
use scg_proto::v1::RuleInfo;

use log::{info, warn};
use tonic::Status;

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::Instant;

/// Credentials of a management-API caller, derived from `SO_PEERCRED` on the
/// gRPC UDS connection. Used only to authorise endpoint creation; the data
/// plane re-derives and re-checks peer credentials independently.
#[derive(Debug, Clone, Copy)]
pub struct CallerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

/// Result of a successful UDS endpoint creation.
pub struct UdsCreated {
    pub socket_path: String,
    pub token: Vec<u8>,
    pub endpoint_id: u32,
}

impl std::fmt::Debug for UdsCreated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the capability token; it is a secret.
        f.debug_struct("UdsCreated")
            .field("socket_path", &self.socket_path)
            .field("token", &"***")
            .field("endpoint_id", &self.endpoint_id)
            .finish()
    }
}

/// Result of a successful SHM endpoint creation.
pub struct ShmCreated {
    pub control_socket_path: String,
    pub token: Vec<u8>,
    pub endpoint_id: u32,
    pub cap_c2g: u64,
    pub cap_g2c: u64,
    /// Proto `Notify` integer value negotiated for the rings.
    pub notify: i32,
}

impl std::fmt::Debug for ShmCreated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the capability token; it is a secret.
        f.debug_struct("ShmCreated")
            .field("control_socket_path", &self.control_socket_path)
            .field("token", &"***")
            .field("endpoint_id", &self.endpoint_id)
            .field("cap_c2g", &self.cap_c2g)
            .field("cap_g2c", &self.cap_g2c)
            .field("notify", &self.notify)
            .finish()
    }
}

/// Template derived from a `uds`/`shm` rule in the gateway config.
///
/// `Clone` so a short read-lock can hand a copy to the (potentially I/O-bound)
/// endpoint-creation path without holding the templates lock — letting a
/// hot-reload swap the template set without blocking on in-flight creates (#42).
#[derive(Clone)]
struct EndpointTemplate {
    rule_name: String,
    upstream_addr: String,
    tls_mode: TlsMode,
    /// `true` when the rule is the `routing` provider: the endpoint relays
    /// plaintext on both legs (no TLS), exactly like the TCP routing provider
    /// (TRA #58). The local-caller auth (`SO_PEERCRED`/owner-uid) is unchanged.
    routing: bool,
    protocol_version: Option<String>,
    /// Raw provider params from the rule, used to build the decrypt-direction
    /// TLS server acceptor (cert/key/profile/verify); empty for encrypt rules.
    provider_params: HashMap<String, serde_json::Value>,
    allowed_uids: Arc<Vec<u32>>,
    allowed_pids: Arc<Vec<i32>>,
    /// Resolved egress QoS policy (DSCP + SO_PRIORITY) for the upstream leg.
    qos: QosPolicy,
    /// Default per-direction ring capacity for SHM endpoints (bytes).
    ring_capacity: usize,
    /// Resolved low-level relay knobs (splice pipe size, busy-poll window, SHM
    /// ring spin-wait, …) from the perf profile + rule overrides. Carried so the
    /// UDS endpoint can drive the same zero-copy splice relay as the static TCP
    /// encrypt path when its upstream is kTLS.
    perf: PerfKnobs,
    /// SHM ring data structure (byte-stream or fixed-slot).
    ring_kind: ShmRingKind,
    /// Slot ring only: bytes per segment.
    segment_size: usize,
    /// Slot ring only: number of segments per ring.
    num_segments: usize,
    /// Slot ring only: gateway→client wakeup mechanism.
    g2c_notify: ShmNotify,
}

/// A currently-live endpoint instance.
struct LiveEndpoint {
    socket_path: PathBuf,
    owner_uid: u32,
    owner_key: String,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

/// Mutable registry of live endpoints, guarded by a single mutex.
struct LiveState {
    next_id: u32,
    by_id: HashMap<u32, LiveEndpoint>,
    by_owner: HashMap<String, u32>,
}

/// Per-uid token-bucket rate limiter for endpoint-creation requests. Protects
/// the control plane from a flood of `create` calls by a single authorised uid.
struct RateLimiter {
    buckets: HashMap<u32, (f64, Instant)>,
}

/// Idle time after which a per-uid bucket is evicted (DoS-07). A bucket refills to
/// full in 60 s (`cap / refill_per_s`), so a bucket untouched for 2× that is
/// indistinguishable from a fresh (full) one — dropping it never admits a request
/// the un-evicted bucket would have denied.
const BUCKET_IDLE_EVICT: std::time::Duration = std::time::Duration::from_secs(120);

impl RateLimiter {
    fn new() -> Self {
        RateLimiter {
            buckets: HashMap::new(),
        }
    }

    /// Try to admit one request from `uid` under a `per_min` budget. Returns
    /// `true` if a token was available (request allowed), `false` otherwise.
    /// The bucket starts full so a fresh uid may burst up to `per_min`.
    fn allow(&mut self, uid: u32, per_min: u32) -> bool {
        self.allow_at(uid, per_min, Instant::now())
    }

    /// [`allow`](Self::allow) with an injectable clock, so eviction is testable.
    /// Evicts idle buckets on every call (DoS-07): the map is bounded to uids seen
    /// within `BUCKET_IDLE_EVICT`, and the retain is O(#authorised uids), which is
    /// small by construction (uids come from the rule allow-lists).
    fn allow_at(&mut self, uid: u32, per_min: u32, now: Instant) -> bool {
        self.buckets
            .retain(|_, (_, touched)| now.duration_since(*touched) < BUCKET_IDLE_EVICT);

        let cap = per_min.max(1) as f64;
        let refill_per_s = per_min as f64 / 60.0;
        let entry = self.buckets.entry(uid).or_insert((cap, now));
        let elapsed = now.duration_since(entry.1).as_secs_f64();
        entry.1 = now;
        entry.0 = (entry.0 + elapsed * refill_per_s).min(cap);
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Owns templates and the live-endpoint registry for the local interfaces.
pub struct InterfaceManager {
    /// UDS/SHM authorization templates, swappable on hot-reload (#42).
    templates: RwLock<HashMap<String, EndpointTemplate>>,
    /// Rule snapshot for ListRules, swapped alongside `templates` on reload.
    all_rules: RwLock<Vec<RuleInfo>>,
    runtime_dir: String,
    sock_buf_size: usize,
    version: String,
    /// Maximum simultaneously-live endpoints per uid (`0` = unlimited).
    max_endpoints_per_uid: u32,
    /// Maximum endpoint-creation requests per uid per minute (`0` = unlimited).
    max_create_per_min: u32,
    live: Mutex<LiveState>,
    rate: Mutex<RateLimiter>,
    /// Shared, hot-reloadable policy manager threaded into every endpoint task so
    /// the local-IPC relay carries the same default-deny second gate as the
    /// network paths (DP-08). `None` disables the gate.
    policy: Option<Arc<RwLock<PolicyManager>>>,
}

impl InterfaceManager {
    /// Build the manager from the gateway config, deriving UDS/SHM templates
    /// from rules whose `listen_proto` is `uds` or `shm`. `policy` is the shared
    /// policy manager applied to each endpoint's network leg (DP-08).
    pub fn new(
        config: &GatewayConfig,
        version: impl Into<String>,
        policy: Option<Arc<RwLock<PolicyManager>>>,
    ) -> Arc<Self> {
        let api = config.api.clone().unwrap_or_default();
        let (templates, all_rules) = Self::build_templates(config);

        info!(
            "interface-manager: {} local-interface template(s) registered",
            templates.len()
        );

        Arc::new(InterfaceManager {
            templates: RwLock::new(templates),
            all_rules: RwLock::new(all_rules),
            runtime_dir: api.runtime_dir,
            sock_buf_size: config.sock_buf_size,
            version: version.into(),
            max_endpoints_per_uid: api.max_endpoints_per_uid,
            max_create_per_min: api.create_rate_per_min,
            live: Mutex::new(LiveState {
                next_id: 1,
                by_id: HashMap::new(),
                by_owner: HashMap::new(),
            }),
            rate: Mutex::new(RateLimiter::new()),
            policy,
        })
    }

    /// Lock the live-endpoint registry, recovering the guard if a previous
    /// holder panicked (L29). One consistent no-`unwrap` poison policy across
    /// every internal mutex: a poisoned registry lock does not corrupt the map
    /// (the panic that poisoned it happened between well-formed operations), so
    /// recovering and continuing is safe and never aborts a management RPC.
    fn live(&self) -> std::sync::MutexGuard<'_, LiveState> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Lock the per-uid rate limiter, recovering a poisoned guard (see
    /// [`live`](Self::live)).
    fn rate(&self) -> std::sync::MutexGuard<'_, RateLimiter> {
        self.rate.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Re-derive the UDS/SHM authorization templates (and the ListRules
    /// snapshot) from `config` and swap them in atomically. Called from the
    /// hot-reload path so a tightened (or relaxed) `allowed_uids`/`allowed_pids`
    /// takes effect without a process restart (#42). Live endpoints are not
    /// disturbed; only subsequent `create_uds`/`create_shm` authorization
    /// decisions use the new templates. Startup-only knobs (runtime_dir, rate
    /// limits) are intentionally not changed here.
    pub fn reload_from_config(&self, config: &GatewayConfig) {
        let (templates, all_rules) = Self::build_templates(config);
        let n = templates.len();
        if let Ok(mut guard) = self.templates.write() {
            *guard = templates;
        }
        if let Ok(mut guard) = self.all_rules.write() {
            *guard = all_rules;
        }
        info!("interface-manager: reloaded {n} local-interface template(s) from config");
    }

    /// Derive the UDS/SHM authorization templates and the rule snapshot from a
    /// config. Shared by [`InterfaceManager::new`] and [`reload_from_config`].
    fn build_templates(
        config: &GatewayConfig,
    ) -> (HashMap<String, EndpointTemplate>, Vec<RuleInfo>) {
        let api = config.api.clone().unwrap_or_default();
        let mut templates: HashMap<String, EndpointTemplate> = HashMap::new();
        let mut all_rules = Vec::with_capacity(config.rules.len());

        for rule in &config.rules {
            all_rules.push(RuleInfo {
                name: rule.name.clone(),
                app_id: rule.app_id.clone().unwrap_or_default(),
                traffic_class: traffic_class_to_proto(rule.traffic_class),
                listen_proto: rule.listen_proto.to_string(),
                upstream_proto: rule.upstream_proto.to_string(),
            });

            if !matches!(rule.listen_proto, Proto::Uds | Proto::Shm) {
                continue;
            }
            let app_id = match &rule.app_id {
                Some(a) if !a.is_empty() => a.clone(),
                _ => {
                    warn!(
                        "[{}] uds/shm rule has no app_id; skipping (clients cannot address it)",
                        rule.name
                    );
                    continue;
                }
            };
            if rule.allowed_uids.is_empty() {
                warn!(
                    "[{}] uds/shm rule (app_id={app_id}) has empty allowed_uids; \
                     the local interface will reject all clients",
                    rule.name
                );
            }
            let tls_mode = upstream_tls_mode(
                rule.effective_security_provider(),
                &rule.provider_params,
                rule.protocol_version.as_deref(),
            );
            let routing = rule.effective_security_provider() == "routing";
            let key = template_key(
                &app_id,
                rule.traffic_class,
                rule.direction,
                rule.listen_proto,
            );
            if templates.contains_key(&key) {
                warn!(
                    "duplicate uds/shm template (app_id={app_id}, class={}, direction={}, \
                     kind={}); the last rule wins",
                    rule.traffic_class, rule.direction, rule.listen_proto
                );
            }
            templates.insert(
                key,
                EndpointTemplate {
                    rule_name: rule.name.clone(),
                    upstream_addr: rule.upstream_addr.clone(),
                    tls_mode,
                    routing,
                    protocol_version: rule.protocol_version.clone(),
                    provider_params: rule.provider_params.clone(),
                    allowed_uids: Arc::new(rule.allowed_uids.clone()),
                    allowed_pids: Arc::new(rule.allowed_pids.clone()),
                    qos: rule.qos(),
                    ring_capacity: api.shm_ring_capacity,
                    perf: rule.perf_knobs(config.perf_profile, config.sock_buf_size),
                    ring_kind: api.shm_ring_kind,
                    segment_size: api.shm_segment_size,
                    num_segments: api.shm_num_segments,
                    g2c_notify: api.shm_g2c_notify,
                },
            );
        }

        (templates, all_rules)
    }

    /// Gateway version string (for the Health RPC).
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Snapshot of the configured pipeline rules (for the ListRules RPC).
    pub fn list_rules(&self) -> Vec<RuleInfo> {
        self.all_rules.read().map(|g| g.clone()).unwrap_or_default()
    }

    /// Format one structured audit line. Kept pure so its columnar shape
    /// (`AUDIT <decision> op=… uid=… pid=… app_id=…<detail>`) is unit-testable and
    /// stays greppable across both the deny and allow paths (CP-05).
    fn audit_line(
        decision: &str,
        op: &str,
        caller: CallerCred,
        app_id: &str,
        detail: &str,
    ) -> String {
        format!(
            "AUDIT {decision} op={op} uid={} pid={} app_id={app_id}{detail}",
            caller.uid, caller.pid
        )
    }

    /// Emit a structured audit record for a denied control-plane request. All
    /// denial paths funnel through here so operators get one consistent,
    /// greppable line (`AUDIT deny`) carrying the caller identity and reason.
    fn audit_deny(op: &str, caller: CallerCred, app_id: &str, reason: &str) {
        warn!(
            "{}",
            Self::audit_line("deny", op, caller, app_id, &format!(": {reason}"))
        );
    }

    /// Emit a positive audit record for a successful endpoint create/replace or
    /// close, so provisioning is attributable and not only denials are logged
    /// (CP-05). `op` is `create_uds`/`create_shm`/`close`.
    fn audit_allow(op: &str, caller: CallerCred, app_id: &str, id: u32) {
        info!(
            "{}",
            Self::audit_line("allow", op, caller, app_id, &format!(" id={id}"))
        );
    }

    /// Apply the per-uid rate limit and live-endpoint quota before a new
    /// endpoint is created. `owner_key` identifies the (uid, app, class,
    /// direction, kind) slot: re-creating an existing slot is a replacement and
    /// does not count against the quota. Returns a ready-to-return `Status` on
    /// rejection.
    fn check_admission(
        &self,
        op: &str,
        caller: CallerCred,
        app_id: &str,
        owner_key: &str,
    ) -> Result<(), Status> {
        // Token-bucket rate limit on create requests.
        if self.max_create_per_min > 0 {
            let admitted = self.rate().allow(caller.uid, self.max_create_per_min);
            if !admitted {
                let reason = format!(
                    "endpoint-creation rate limit exceeded ({}/min)",
                    self.max_create_per_min
                );
                Self::audit_deny(op, caller, app_id, &reason);
                return Err(Status::resource_exhausted(reason));
            }
        }

        // Live-endpoint quota per uid (replacements do not increase the count).
        if self.max_endpoints_per_uid > 0 {
            let live = self.live();
            let is_replace = live.by_owner.contains_key(owner_key);
            if !is_replace {
                let owned = live
                    .by_id
                    .values()
                    .filter(|e| e.owner_uid == caller.uid)
                    .count();
                if owned as u32 >= self.max_endpoints_per_uid {
                    let reason = format!(
                        "endpoint quota reached ({} live)",
                        self.max_endpoints_per_uid
                    );
                    Self::audit_deny(op, caller, app_id, &reason);
                    return Err(Status::resource_exhausted(reason));
                }
            }
        }
        Ok(())
    }

    /// Fetch the endpoint template for `(app_id, class, direction, kind)` and
    /// run the full authorization + admission gate for `caller` (M26): template
    /// lookup under a short read lock, the uid/pid allow-list checks with their
    /// audit-deny lines, and the rate-limit + per-uid-quota admission. Returns
    /// the cloned template and the caller's `owner_key` on success. Both
    /// `create_uds` and `create_shm` route through this so the security-critical
    /// checks cannot drift between the two entry points.
    fn authorize_and_admit(
        &self,
        op: &str,
        caller: CallerCred,
        app_id: &str,
        class: TrafficClass,
        direction: Direction,
        kind: Proto,
    ) -> Result<(EndpointTemplate, String), Status> {
        let key = template_key(app_id, class, direction, kind);
        // Clone the template out under a short read lock so a concurrent
        // hot-reload (write) is never blocked by this create's I/O, and so this
        // request sees a consistent snapshot of the authorization fields (#42).
        let template = self
            .templates
            .read()
            .map_err(|_| Status::internal("interface-manager templates lock poisoned"))?
            .get(&key)
            .cloned();
        let template = template.ok_or_else(|| {
            Status::not_found(format!(
                "no {kind} rule for app_id={app_id} class={class} direction={direction}"
            ))
        })?;

        // Authorise the caller against the rule's allow-lists.
        if template.allowed_uids.is_empty() || !template.allowed_uids.contains(&caller.uid) {
            Self::audit_deny(op, caller, app_id, "uid not in allowed_uids");
            return Err(Status::permission_denied(format!(
                "uid {} is not authorised for app_id={app_id}",
                caller.uid
            )));
        }
        if !template.allowed_pids.is_empty() && !template.allowed_pids.contains(&caller.pid) {
            Self::audit_deny(op, caller, app_id, "pid not in allowed_pids");
            return Err(Status::permission_denied(format!(
                "pid {} is not authorised for app_id={app_id}",
                caller.pid
            )));
        }

        // Enforce per-uid rate limit and live-endpoint quota.
        let owner_key = owner_key(caller.uid, app_id, class, direction, kind);
        self.check_admission(op, caller, app_id, &owner_key)?;

        Ok((template, owner_key))
    }

    /// Create (or atomically replace) a UDS endpoint for the caller.
    pub fn create_uds(
        &self,
        caller: CallerCred,
        app_id: &str,
        class: TrafficClass,
        direction: Direction,
        _ring_capacity: usize,
    ) -> Result<UdsCreated, Status> {
        let (template, owner_key) =
            self.authorize_and_admit("create_uds", caller, app_id, class, direction, Proto::Uds)?;

        // Resolve a per-uid runtime directory for the socket.
        let dir = self
            .resolve_runtime_dir(caller.uid)
            .map_err(|e| Status::internal(format!("runtime dir: {e}")))?;

        // Allocate an id, an owner key, and a fresh single-use token.
        let token =
            CapabilityToken::random().map_err(|e| Status::internal(format!("token: {e}")))?;
        let token_bytes = token.as_bytes().to_vec();
        let id = self.alloc_id();

        let file_name = format!("{}.{}.{}.{}.sock", sanitize(app_id), class, direction, id);
        let socket_path = dir.join(file_name);
        let label = format!("{}#{id}", template.rule_name);
        let shutdown = Arc::new(AtomicBool::new(false));

        let task = UdsEndpointTask {
            label: label.clone(),
            socket_path: socket_path.clone(),
            direction,
            upstream_addr: template.upstream_addr.clone(),
            tls_mode: template.tls_mode,
            routing: template.routing,
            protocol_version: template.protocol_version.clone(),
            provider_params: template.provider_params.clone(),
            sock_buf_size: self.sock_buf_size,
            perf: template.perf,
            qos: template.qos,
            allowed_uids: template.allowed_uids.clone(),
            allowed_pids: template.allowed_pids.clone(),
            owner_uid: caller.uid,
            token: Arc::new(Mutex::new(Some(token))),
            policy: self.policy.clone(),
            shutdown: shutdown.clone(),
        };

        let join = std::thread::Builder::new()
            .name(format!("uds-ep-{id}"))
            .spawn(move || run_uds_endpoint(task))
            .map_err(|e| Status::internal(format!("spawn endpoint thread: {e}")))?;

        // Register, replacing any previous endpoint bound to the same owner key.
        // Returns an error (and tears down this endpoint) if the per-uid quota was
        // raced past the pre-check.
        self.register_or_replace(
            id,
            owner_key.clone(),
            LiveEndpoint {
                socket_path: socket_path.clone(),
                owner_uid: caller.uid,
                owner_key,
                shutdown,
                join: Some(join),
            },
            &label,
        )?;

        Self::audit_allow("create_uds", caller, app_id, id);
        info!(
            "[{label}] created UDS endpoint id={id} at {} for uid={}",
            socket_path.display(),
            caller.uid
        );
        Ok(UdsCreated {
            socket_path: socket_path.to_string_lossy().into_owned(),
            token: token_bytes,
            endpoint_id: id,
        })
    }

    /// Create (or atomically replace) a SHM endpoint for the caller.
    ///
    /// Mirrors [`create_uds`](Self::create_uds) but the data plane is a pair of
    /// sealed shared-memory rings reached through a control socket. The returned
    /// `control_socket_path` is where the client connects, presents its token,
    /// and receives the memfd/eventfd descriptors via `SCM_RIGHTS`.
    pub fn create_shm(
        &self,
        caller: CallerCred,
        app_id: &str,
        class: TrafficClass,
        direction: Direction,
        ring_capacity: usize,
    ) -> Result<ShmCreated, Status> {
        // Upper bound on a caller-requested SHM ring capacity (bytes). The value
        // arrives unauthenticated-in-size over the management API and sizes an
        // mmap'd ring, so an unbounded value is a memory-exhaustion DoS. The
        // admin-configured template default is trusted and not subject to this cap.
        const MAX_SHM_RING_CAPACITY: usize = 256 * 1024 * 1024;

        let (template, owner_key) =
            self.authorize_and_admit("create_shm", caller, app_id, class, direction, Proto::Shm)?;

        // Both rings use the same capacity: the request value if given, else the
        // template default. The endpoint thread rounds it up to a page.
        let cap = if ring_capacity > 0 {
            if ring_capacity > MAX_SHM_RING_CAPACITY {
                Self::audit_deny(
                    "create_shm",
                    caller,
                    app_id,
                    "ring_capacity exceeds maximum",
                );
                return Err(Status::invalid_argument(format!(
                    "ring_capacity {ring_capacity} exceeds maximum {MAX_SHM_RING_CAPACITY}"
                )));
            }
            ring_capacity
        } else {
            template.ring_capacity
        };

        // A slot-ring's geometry comes from num_segments/segment_size, so a
        // caller-supplied ring_capacity is not honoured — warn instead of
        // silently discarding it (M7).
        if ring_capacity > 0 && matches!(template.ring_kind, ShmRingKind::Slot) {
            warn!(
                "[{}] create_shm: ring_capacity={ring_capacity} ignored for a slot-ring template \
                 (geometry is set by num_segments × segment_size)",
                template.rule_name
            );
        }

        let dir = self
            .resolve_runtime_dir(caller.uid)
            .map_err(|e| Status::internal(format!("runtime dir: {e}")))?;

        let token =
            CapabilityToken::random().map_err(|e| Status::internal(format!("token: {e}")))?;
        let token_bytes = token.as_bytes().to_vec();
        let id = self.alloc_id();

        let file_name = format!(
            "{}.{}.{}.{}.ctl.sock",
            sanitize(app_id),
            class,
            direction,
            id
        );
        let control_socket_path = dir.join(file_name);
        let label = format!("{}#{id}", template.rule_name);
        let shutdown = Arc::new(AtomicBool::new(false));

        let task = ShmEndpointTask {
            label: label.clone(),
            control_socket_path: control_socket_path.clone(),
            direction,
            upstream_addr: template.upstream_addr.clone(),
            tls_mode: template.tls_mode,
            routing: template.routing,
            protocol_version: template.protocol_version.clone(),
            provider_params: template.provider_params.clone(),
            sock_buf_size: self.sock_buf_size,
            qos: template.qos,
            cap_c2g: cap,
            cap_g2c: cap,
            spin_wait_us: template.perf.spin_wait_us,
            ring_kind: template.ring_kind,
            segment_size: template.segment_size,
            num_segments: template.num_segments,
            g2c_notify: template.g2c_notify,
            allowed_uids: template.allowed_uids.clone(),
            allowed_pids: template.allowed_pids.clone(),
            owner_uid: caller.uid,
            token: Arc::new(Mutex::new(Some(token))),
            policy: self.policy.clone(),
            shutdown: shutdown.clone(),
        };

        // Compute the reported geometry from the SAME resolver the endpoint
        // thread uses to map the segment (M7), before `task` is moved into the
        // thread — so the gRPC reply's caps and notify mode match what the
        // client actually sees on the control page (slot rings and futex mode
        // included), instead of the byte-stream-only `round_up_page(cap)` and a
        // hardcoded eventfd.
        let layout = resolve_shm_layout(&task);

        let join = std::thread::Builder::new()
            .name(format!("shm-ep-{id}"))
            .spawn(move || run_shm_endpoint(task))
            .map_err(|e| Status::internal(format!("spawn endpoint thread: {e}")))?;

        self.register_or_replace(
            id,
            owner_key.clone(),
            LiveEndpoint {
                socket_path: control_socket_path.clone(),
                owner_uid: caller.uid,
                owner_key,
                shutdown,
                join: Some(join),
            },
            &label,
        )?;

        Self::audit_allow("create_shm", caller, app_id, id);
        info!(
            "[{label}] created SHM endpoint id={id} at {} for uid={} (rings {}B c2g / {}B g2c, notify={})",
            control_socket_path.display(),
            caller.uid,
            layout.cap_c2g,
            layout.cap_g2c,
            layout.notify
        );
        Ok(ShmCreated {
            control_socket_path: control_socket_path.to_string_lossy().into_owned(),
            token: token_bytes,
            endpoint_id: id,
            cap_c2g: layout.cap_c2g as u64,
            cap_g2c: layout.cap_g2c as u64,
            notify: layout.notify,
        })
    }

    /// Tear down a previously-created endpoint owned by the caller.
    pub fn close(&self, caller: CallerCred, endpoint_id: u32) -> Result<(), Status> {
        let mut live = self.live();
        // Single lookup+remove: no `.unwrap()` on a second lookup (L29).
        let owner_uid = live
            .by_id
            .get(&endpoint_id)
            .map(|ep| ep.owner_uid)
            .ok_or_else(|| Status::not_found(format!("no endpoint id={endpoint_id}")))?;
        if owner_uid != caller.uid {
            return Err(Status::permission_denied(
                "only the owning uid may close this endpoint",
            ));
        }
        let Some(mut ep) = live.by_id.remove(&endpoint_id) else {
            return Err(Status::not_found(format!("no endpoint id={endpoint_id}")));
        };
        live.by_owner.remove(&ep.owner_key);
        drop(live);

        ep.shutdown.store(true, Ordering::SeqCst);
        // Detach: dropping the handle lets the endpoint thread wind down on its
        // own without blocking the control-plane runtime.
        ep.join.take();
        // `app_id` is not carried on the close RPC; use "-" to keep the columns
        // aligned with the create audit lines.
        Self::audit_allow("close", caller, "-", endpoint_id);
        info!("closed endpoint id={endpoint_id} (uid={})", caller.uid);
        Ok(())
    }

    /// Signal every live endpoint to shut down and wait for its thread to exit
    /// (called on gateway shutdown).
    ///
    /// Flags are stored on *all* endpoints first, then the threads are joined
    /// (L10): signalling and joining one at a time would serialise the
    /// per-endpoint poll latency. Joining (rather than the old detach) lets a
    /// relay finish its in-flight write and send a clean TLS `close_notify`
    /// instead of being killed mid-write by process exit; the lib.rs shutdown
    /// watchdog force-exits if any thread hangs, bounding the wait.
    pub fn shutdown_all(&self) {
        let mut eps: Vec<LiveEndpoint> = {
            let mut live = self.live();
            live.by_owner.clear();
            live.by_id.drain().map(|(_, ep)| ep).collect()
        };
        // Signal every endpoint before joining any, so their poll intervals
        // overlap instead of summing.
        for ep in &eps {
            ep.shutdown.store(true, Ordering::SeqCst);
        }
        for ep in &mut eps {
            if let Some(handle) = ep.join.take() {
                let _ = handle.join();
            }
            let _ = std::fs::remove_file(&ep.socket_path);
        }
    }

    /// Remove and signal an endpoint without joining (used on create/replace).
    fn detach_endpoint(&self, id: u32) {
        let ep = { self.live().by_id.remove(&id) };
        if let Some(mut ep) = ep {
            ep.shutdown.store(true, Ordering::SeqCst);
            ep.join.take();
        }
    }

    /// Allocate the next endpoint id, wrapping past `u32::MAX` back to 1.
    ///
    /// Skips ids currently present in `by_id` while holding the lock (L11): a
    /// wrap-around that reused a still-live id would silently orphan that
    /// endpoint (its `by_owner` entry would then point at another owner's id).
    /// Practically unreachable under the default rate limit, but cheap to close.
    fn alloc_id(&self) -> u32 {
        let mut live = self.live();
        let mut id = live.next_id;
        while live.by_id.contains_key(&id) {
            id = id.checked_add(1).unwrap_or(1).max(1);
        }
        live.next_id = id.checked_add(1).unwrap_or(1).max(1);
        id
    }

    /// Register a live endpoint under `id`, detaching any previous endpoint that
    /// was bound to the same owner key (create-or-replace semantics).
    fn register_or_replace(
        &self,
        id: u32,
        owner_key: String,
        mut ep: LiveEndpoint,
        label: &str,
    ) -> Result<(), Status> {
        let replaced = {
            let mut live = self.live();
            // Atomic quota enforcement: re-check the per-uid live-endpoint quota
            // under the SAME lock that performs the insert. The pre-check in
            // `check_admission` releases the lock before insertion, so two
            // concurrent creates from one uid could otherwise both pass it and
            // exceed the quota (TOCTOU). A replacement (same owner_key in flight)
            // does not increase the count and is always allowed.
            if self.max_endpoints_per_uid > 0 && !live.by_owner.contains_key(&owner_key) {
                let owned = live
                    .by_id
                    .values()
                    .filter(|e| e.owner_uid == ep.owner_uid)
                    .count();
                if owned as u32 >= self.max_endpoints_per_uid {
                    drop(live);
                    // Tear down the endpoint we optimistically built (detach
                    // without joining, mirroring `detach_endpoint`).
                    ep.shutdown.store(true, Ordering::SeqCst);
                    ep.join.take();
                    warn!(
                        "[{label}] endpoint quota ({}) reached for uid={} — rejecting raced create",
                        self.max_endpoints_per_uid, ep.owner_uid
                    );
                    return Err(Status::resource_exhausted(format!(
                        "endpoint quota reached ({} live)",
                        self.max_endpoints_per_uid
                    )));
                }
            }
            let replaced = live.by_owner.insert(owner_key, id);
            live.by_id.insert(id, ep);
            replaced
        };
        if let Some(old_id) = replaced {
            self.detach_endpoint(old_id);
            info!("[{label}] replaced previous endpoint id={old_id} for the same owner");
        }
        Ok(())
    }

    /// Resolve a per-uid runtime directory for endpoint sockets.
    ///
    /// When the gateway is privileged it creates `<runtime_dir>/<uid>` (0700)
    /// and chowns it to the caller; otherwise it falls back to the caller's XDG
    /// runtime directory `/run/user/<uid>/scg`.
    fn resolve_runtime_dir(&self, uid: u32) -> io::Result<PathBuf> {
        // SAFETY: `geteuid` is a nullary POSIX syscall that takes no arguments,
        // touches no memory, and is always defined to succeed (it cannot fail);
        // calling it is sound from any thread at any time.
        let euid = unsafe { libc::geteuid() };
        let base = PathBuf::from(&self.runtime_dir);

        if ensure_dir(&base, 0o755).is_ok() {
            let per_uid = base.join(uid.to_string());
            if let Ok(()) = ensure_per_uid_dir(&per_uid, uid, euid == 0) {
                return Ok(per_uid);
            }
        }

        // Fallback: the caller's XDG runtime directory.
        let xdg = PathBuf::from(format!("/run/user/{uid}")).join("scg");
        ensure_dir(&xdg, 0o700)?;
        info!(
            "interface-manager: using fallback runtime dir {}",
            xdg.display()
        );
        Ok(xdg)
    }
}

/// Create a directory with `mode`, treating "already exists" as success.
fn ensure_dir(path: &std::path::Path, mode: u32) -> io::Result<()> {
    match scg_ipc::os::mkdir_mode(path, mode) {
        Ok(()) => Ok(()),
        Err(e)
            if e.kind() == io::ErrorKind::AlreadyExists
                || e.raw_os_error() == Some(libc::EEXIST) =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Create (or accept) the per-uid runtime directory `<runtime_dir>/<uid>`
/// without following a symlink into a privileged chown/chmod (M3, CWE-59).
///
/// `mkdir_mode` chmods through a pre-existing symlink on `EEXIST`, so if an
/// operator points `runtime_dir` at a world-writable directory a local
/// attacker could pre-plant `<runtime_dir>/<uid>` as a symlink and redirect
/// the root gateway's chown/chmod onto an attacker-chosen target. Here we
/// `create_dir` (which fails `AlreadyExists` instead of chmod-ing through a
/// symlink) and then `lstat`-verify the entry is a real directory owned by
/// root or the target uid *before* any chown/chmod. A narrow swap-after-lstat
/// TOCTOU remains (the fully robust form uses `openat(O_NOFOLLOW)` +
/// `fchownat`); rejecting the planted symlink closes the practical primitive.
fn ensure_per_uid_dir(per_uid: &std::path::Path, uid: u32, privileged: bool) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    match std::fs::create_dir(per_uid) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    // lstat (does not follow symlinks): reject anything that is not a real dir.
    let meta = std::fs::symlink_metadata(per_uid)?;
    if !meta.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "runtime dir '{}' exists but is not a directory (symlink?); refusing",
                per_uid.display()
            ),
        ));
    }
    // A pre-existing dir must be owned by root or the target uid — an
    // unexpected owner means we did not create it and must not chown it.
    let owner = meta.uid();
    if owner != 0 && owner != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "runtime dir '{}' is owned by uid {} (expected root or {}); refusing",
                per_uid.display(),
                owner,
                uid
            ),
        ));
    }
    if privileged {
        let _ = scg_ipc::os::chown(per_uid, uid, uid);
    }
    let _ = scg_ipc::os::chmod(per_uid, 0o700);
    Ok(())
}

/// Map the config traffic class to its proto integer value.
fn traffic_class_to_proto(class: TrafficClass) -> i32 {
    match class {
        TrafficClass::Normal => 0,
        TrafficClass::Safety => 1,
    }
}

/// Template lookup key: `app_id`, class, direction and kind.
fn template_key(app_id: &str, class: TrafficClass, dir: Direction, kind: Proto) -> String {
    format!("{app_id}\u{0}{class}\u{0}{dir}\u{0}{kind}")
}

/// Owner key for create-or-replace: the template key prefixed with the uid.
fn owner_key(uid: u32, app_id: &str, class: TrafficClass, dir: Direction, kind: Proto) -> String {
    format!("{uid}\u{0}{}", template_key(app_id, class, dir, kind))
}

/// Restrict an `app_id` to characters safe for a socket file name.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scg_ipc::handshake::SHM_NOTIFY_EVENTFD;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;
    use tonic::Code;

    // DoS-07: idle buckets are evicted, bounding the per-uid map.
    #[test]
    fn rate_limiter_evicts_idle_buckets() {
        let mut rl = RateLimiter::new();
        let t0 = Instant::now();
        assert!(rl.allow_at(1, 60, t0));
        // uid 2 arrives well after uid 1 went idle → uid 1 is evicted.
        assert!(rl.allow_at(
            2,
            60,
            t0 + BUCKET_IDLE_EVICT + std::time::Duration::from_secs(1)
        ));
        assert_eq!(rl.buckets.len(), 1, "idle uid 1 should be gone");
        assert!(rl.buckets.contains_key(&2));
    }

    // DoS-07: eviction must not reset an *active* bucket that is currently denying.
    #[test]
    fn rate_limiter_eviction_preserves_active_denial() {
        let mut rl = RateLimiter::new();
        let t0 = Instant::now();
        // Drain the bucket to denial (cap = 1/min → first allow, second deny).
        assert!(rl.allow_at(1, 1, t0));
        assert!(!rl.allow_at(1, 1, t0));
        // A moment later (well under the idle window) it is still denied — not a
        // fresh full bucket.
        assert!(!rl.allow_at(1, 1, t0 + std::time::Duration::from_secs(1)));
    }

    // CP-05: the audit line is columnar and stable across the allow/deny paths.
    #[test]
    fn audit_line_format_is_grep_stable() {
        let caller = CallerCred {
            uid: 1000,
            gid: 1000,
            pid: 42,
        };
        assert_eq!(
            InterfaceManager::audit_line("allow", "create_uds", caller, "app-x", " id=7"),
            "AUDIT allow op=create_uds uid=1000 pid=42 app_id=app-x id=7"
        );
        assert_eq!(
            InterfaceManager::audit_line("deny", "create_shm", caller, "app-y", ": quota reached"),
            "AUDIT deny op=create_shm uid=1000 pid=42 app_id=app-y: quota reached"
        );
    }

    fn unique_tmp() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("scg-itest-{}-{}", std::process::id(), nanos));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // M3 (CWE-59): a pre-planted per-uid symlink must be rejected, and its
    // target must be left untouched — never chmod/chown-ed through the link.
    #[test]
    fn ensure_per_uid_dir_rejects_planted_symlink() {
        let base = unique_tmp();
        let uid = unsafe { libc::getuid() };
        // The attacker-controlled target the symlink points at.
        let target = base.join("victim");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let per_uid = base.join(uid.to_string());
        std::os::unix::fs::symlink(&target, &per_uid).unwrap();

        let err = ensure_per_uid_dir(&per_uid, uid, false).unwrap_err();
        assert!(
            err.to_string().contains("not a directory"),
            "planted symlink must be rejected: {err}"
        );
        // The target's mode must be unchanged (not chmod-ed to 0700 through
        // the link).
        let mode = std::fs::symlink_metadata(&target).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o755, "symlink target must be left untouched");
        let _ = std::fs::remove_dir_all(&base);
    }

    // A fresh per-uid dir is created 0700 and accepted.
    #[test]
    fn ensure_per_uid_dir_creates_fresh_dir_0700() {
        let base = unique_tmp();
        let uid = unsafe { libc::getuid() };
        let per_uid = base.join(uid.to_string());
        ensure_per_uid_dir(&per_uid, uid, false).expect("fresh dir accepted");
        let meta = std::fs::symlink_metadata(&per_uid).unwrap();
        assert!(meta.file_type().is_dir());
        assert_eq!(meta.mode() & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&base);
    }

    fn manager_with_uds_rule(allowed_uid: u32, runtime_dir: &Path) -> Arc<InterfaceManager> {
        let json = format!(
            r#"{{
                "rules": [{{
                    "name": "uds-app1",
                    "direction": "encrypt",
                    "listen_addr": "unused",
                    "listen_proto": "uds",
                    "upstream_addr": "127.0.0.1:1",
                    "security_provider": "tls",
                    "app_id": "app1",
                    "traffic_class": "normal",
                    "allowed_uids": [{allowed_uid}]
                }}, {{
                    "name": "uds-app1-dec",
                    "direction": "decrypt",
                    "listen_addr": "unused",
                    "listen_proto": "uds",
                    "upstream_addr": "127.0.0.1:1",
                    "security_provider": "tls",
                    "app_id": "app1",
                    "traffic_class": "normal",
                    "allowed_uids": [{allowed_uid}]
                }}],
                "api": {{ "runtime_dir": "{}", "uds_path": "{}/mgmt.sock" }}
            }}"#,
            runtime_dir.display(),
            runtime_dir.display()
        );
        let config: GatewayConfig = serde_json::from_str(&json).expect("parse test config");
        InterfaceManager::new(&config, "test", None)
    }

    #[test]
    fn sanitize_keeps_safe_chars_only() {
        assert_eq!(sanitize("app1.normal-x_y"), "app1.normal-x_y");
        assert_eq!(sanitize("a/b c:d"), "a_b_c_d");
    }

    #[test]
    fn template_and_owner_keys_are_distinct() {
        let k1 = template_key("app1", TrafficClass::Normal, Direction::Encrypt, Proto::Uds);
        let k2 = template_key("app1", TrafficClass::Safety, Direction::Encrypt, Proto::Uds);
        assert_ne!(k1, k2);
        let o1 = owner_key(
            1000,
            "app1",
            TrafficClass::Normal,
            Direction::Encrypt,
            Proto::Uds,
        );
        let o2 = owner_key(
            1001,
            "app1",
            TrafficClass::Normal,
            Direction::Encrypt,
            Proto::Uds,
        );
        assert_ne!(o1, o2);
    }

    #[test]
    fn create_uds_unknown_app_is_not_found() {
        let tmp = unique_tmp();
        let mgr = manager_with_uds_rule(1000, &tmp);
        let caller = CallerCred {
            uid: 1000,
            gid: 1000,
            pid: 1,
        };
        let err = mgr
            .create_uds(caller, "nope", TrafficClass::Normal, Direction::Encrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_uds_decrypt_returns_token_and_path() {
        let tmp = unique_tmp();
        // SAFETY: `getuid` is a nullary POSIX syscall that takes no arguments,
        // touches no memory, and is always defined to succeed; calling it is
        // sound from any thread at any time.
        let uid = unsafe { libc::getuid() };
        let mgr = manager_with_uds_rule(uid, &tmp);
        let caller = CallerCred {
            uid,
            gid: uid,
            pid: 1,
        };
        // Decrypt-direction endpoints are now supported and create like encrypt.
        let created = mgr
            .create_uds(caller, "app1", TrafficClass::Normal, Direction::Decrypt, 0)
            .expect("decrypt create_uds should succeed for an authorised uid");
        assert_eq!(created.token.len(), 32, "token must be 256-bit");
        assert!(
            created.socket_path.contains("decrypt"),
            "socket path should encode the direction: {}",
            created.socket_path
        );
        mgr.shutdown_all();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_uds_wrong_uid_is_denied() {
        let tmp = unique_tmp();
        // Rule authorises uid 1000; caller is uid 4242.
        let mgr = manager_with_uds_rule(1000, &tmp);
        let caller = CallerCred {
            uid: 4242,
            gid: 4242,
            pid: 1,
        };
        let err = mgr
            .create_uds(caller, "app1", TrafficClass::Normal, Direction::Encrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn reload_from_config_revokes_uid() {
        let tmp = unique_tmp();
        // SAFETY: `getuid` is a nullary POSIX syscall that takes no arguments,
        // touches no memory, and always succeeds.
        let uid = unsafe { libc::getuid() };
        let mgr = manager_with_uds_rule(uid, &tmp);
        let caller = CallerCred {
            uid,
            gid: uid,
            pid: 1,
        };

        // Initially authorised: create succeeds.
        let created = mgr
            .create_uds(caller, "app1", TrafficClass::Normal, Direction::Encrypt, 0)
            .expect("authorised uid should create before revoke");
        let _ = mgr.close(caller, created.endpoint_id);

        // Reload with a config that revokes this uid (authorises a different one).
        let revoke_uid = uid.wrapping_add(1);
        let json = format!(
            r#"{{
                "rules": [{{
                    "name": "uds-app1",
                    "direction": "encrypt",
                    "listen_addr": "unused",
                    "listen_proto": "uds",
                    "upstream_addr": "127.0.0.1:1",
                    "security_provider": "tls",
                    "app_id": "app1",
                    "traffic_class": "normal",
                    "allowed_uids": [{revoke_uid}]
                }}],
                "api": {{ "runtime_dir": "{}", "uds_path": "{}/mgmt.sock" }}
            }}"#,
            tmp.display(),
            tmp.display()
        );
        let new_config: GatewayConfig = serde_json::from_str(&json).expect("parse reload config");
        mgr.reload_from_config(&new_config);

        // After the revoke reload, the previously-authorised uid is denied (#42).
        let err = mgr
            .create_uds(caller, "app1", TrafficClass::Normal, Direction::Encrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);

        mgr.shutdown_all();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_uds_success_returns_token_and_path() {
        let tmp = unique_tmp();
        // SAFETY: `getuid` is a nullary POSIX syscall that takes no arguments,
        // touches no memory, and is always defined to succeed; calling it is
        // sound from any thread at any time.
        let uid = unsafe { libc::getuid() };
        let mgr = manager_with_uds_rule(uid, &tmp);
        let caller = CallerCred {
            uid,
            gid: uid,
            pid: 1,
        };
        let created = mgr
            .create_uds(caller, "app1", TrafficClass::Normal, Direction::Encrypt, 0)
            .expect("create_uds should succeed for an authorised uid");
        assert_eq!(created.token.len(), 32, "token must be 256-bit");
        assert_eq!(created.endpoint_id, 1);
        assert!(
            created.socket_path.contains(&uid.to_string()),
            "socket path should sit in a per-uid dir: {}",
            created.socket_path
        );
        // A second create for the same owner replaces the first (id increments).
        let created2 = mgr
            .create_uds(caller, "app1", TrafficClass::Normal, Direction::Encrypt, 0)
            .expect("second create_uds should succeed");
        assert_eq!(created2.endpoint_id, 2);

        mgr.shutdown_all();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn manager_with_shm_rule(allowed_uid: u32, runtime_dir: &Path) -> Arc<InterfaceManager> {
        let json = format!(
            r#"{{
                "rules": [{{
                    "name": "shm-app1",
                    "direction": "encrypt",
                    "listen_addr": "unused",
                    "listen_proto": "shm",
                    "upstream_addr": "127.0.0.1:1",
                    "security_provider": "tls",
                    "app_id": "app1",
                    "traffic_class": "safety",
                    "allowed_uids": [{allowed_uid}]
                }}, {{
                    "name": "shm-app1-dec",
                    "direction": "decrypt",
                    "listen_addr": "unused",
                    "listen_proto": "shm",
                    "upstream_addr": "127.0.0.1:1",
                    "security_provider": "tls",
                    "app_id": "app1",
                    "traffic_class": "safety",
                    "allowed_uids": [{allowed_uid}]
                }}],
                "api": {{ "runtime_dir": "{}", "uds_path": "{}/mgmt.sock" }}
            }}"#,
            runtime_dir.display(),
            runtime_dir.display()
        );
        let config: GatewayConfig = serde_json::from_str(&json).expect("parse test config");
        InterfaceManager::new(&config, "test", None)
    }

    #[test]
    fn create_shm_unknown_app_is_not_found() {
        let tmp = unique_tmp();
        let mgr = manager_with_shm_rule(1000, &tmp);
        let caller = CallerCred {
            uid: 1000,
            gid: 1000,
            pid: 1,
        };
        let err = mgr
            .create_shm(caller, "nope", TrafficClass::Safety, Direction::Encrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_shm_decrypt_returns_token_and_path() {
        let tmp = unique_tmp();
        // SAFETY: `getuid` is a nullary POSIX syscall that takes no arguments,
        // touches no memory, and is always defined to succeed; calling it is
        // sound from any thread at any time.
        let uid = unsafe { libc::getuid() };
        let mgr = manager_with_shm_rule(uid, &tmp);
        let caller = CallerCred {
            uid,
            gid: uid,
            pid: 1,
        };
        let created = mgr
            .create_shm(
                caller,
                "app1",
                TrafficClass::Safety,
                Direction::Decrypt,
                4096,
            )
            .expect("decrypt create_shm should succeed for an authorised uid");
        assert_eq!(created.token.len(), 32, "token must be 256-bit");
        assert!(
            created.control_socket_path.contains("decrypt"),
            "control socket path should encode the direction: {}",
            created.control_socket_path
        );
        mgr.shutdown_all();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_shm_wrong_uid_is_denied() {
        let tmp = unique_tmp();
        let mgr = manager_with_shm_rule(1000, &tmp);
        let caller = CallerCred {
            uid: 4242,
            gid: 4242,
            pid: 1,
        };
        let err = mgr
            .create_shm(caller, "app1", TrafficClass::Safety, Direction::Encrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_shm_success_returns_token_path_and_geometry() {
        let tmp = unique_tmp();
        // SAFETY: `getuid` is a nullary POSIX syscall that takes no arguments,
        // touches no memory, and is always defined to succeed; calling it is
        // sound from any thread at any time.
        let uid = unsafe { libc::getuid() };
        let mgr = manager_with_shm_rule(uid, &tmp);
        let caller = CallerCred {
            uid,
            gid: uid,
            pid: 1,
        };
        // Request a small ring; it is rounded up to a page.
        let created = mgr
            .create_shm(
                caller,
                "app1",
                TrafficClass::Safety,
                Direction::Encrypt,
                4096,
            )
            .expect("create_shm should succeed for an authorised uid");
        assert_eq!(created.token.len(), 32, "token must be 256-bit");
        assert_eq!(created.endpoint_id, 1);
        assert_eq!(created.notify, SHM_NOTIFY_EVENTFD as i32);
        assert!(created.cap_c2g >= 4096 && created.cap_c2g.is_multiple_of(4096));
        assert_eq!(created.cap_c2g, created.cap_g2c);
        assert!(
            created.control_socket_path.contains(&uid.to_string()),
            "control socket path should sit in a per-uid dir: {}",
            created.control_socket_path
        );
        assert!(created.control_socket_path.ends_with(".ctl.sock"));

        mgr.shutdown_all();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Count the process-wide open file descriptors (Linux `/proc/self/fd`).
    fn count_open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .map(|d| d.count())
            .unwrap_or(0)
    }

    /// Build a manager with two UDS rules (normal + safety, same app/uid) plus
    /// configurable quota and rate-limit knobs. The two distinct traffic classes
    /// give two distinct owner keys so the per-uid quota can actually be reached.
    fn manager_with_limits(
        allowed_uid: u32,
        runtime_dir: &Path,
        max_endpoints_per_uid: u32,
        create_rate_per_min: u32,
    ) -> Arc<InterfaceManager> {
        let json = format!(
            r#"{{
                "rules": [
                    {{
                        "name": "uds-app1-normal",
                        "direction": "encrypt",
                        "listen_addr": "unused",
                        "listen_proto": "uds",
                        "upstream_addr": "127.0.0.1:1",
                        "security_provider": "tls",
                        "app_id": "app1",
                        "traffic_class": "normal",
                        "allowed_uids": [{allowed_uid}]
                    }},
                    {{
                        "name": "uds-app1-safety",
                        "direction": "encrypt",
                        "listen_addr": "unused",
                        "listen_proto": "uds",
                        "upstream_addr": "127.0.0.1:1",
                        "security_provider": "tls",
                        "app_id": "app1",
                        "traffic_class": "safety",
                        "allowed_uids": [{allowed_uid}]
                    }}
                ],
                "api": {{
                    "runtime_dir": "{rd}",
                    "uds_path": "{rd}/mgmt.sock",
                    "max_endpoints_per_uid": {max_endpoints_per_uid},
                    "create_rate_per_min": {create_rate_per_min}
                }}
            }}"#,
            rd = runtime_dir.display()
        );
        let config: GatewayConfig = serde_json::from_str(&json).expect("parse test config");
        InterfaceManager::new(&config, "test", None)
    }

    #[test]
    fn create_rate_limit_denies_burst() {
        let tmp = unique_tmp();
        // SAFETY: `getuid` is a nullary POSIX syscall that takes no arguments,
        // touches no memory, and is always defined to succeed; calling it is
        // sound from any thread at any time.
        let uid = unsafe { libc::getuid() };
        // Quota disabled; allow a single create per minute.
        let mgr = manager_with_limits(uid, &tmp, 0, 1);
        let caller = CallerCred {
            uid,
            gid: uid,
            pid: 1,
        };
        // First create consumes the only token in the bucket.
        mgr.create_uds(caller, "app1", TrafficClass::Normal, Direction::Encrypt, 0)
            .expect("first create should pass the rate limit");
        // Second create in the same window is rejected.
        let err = mgr
            .create_uds(caller, "app1", TrafficClass::Normal, Direction::Encrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::ResourceExhausted);
        mgr.shutdown_all();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_quota_denies_extra_endpoints() {
        let tmp = unique_tmp();
        // SAFETY: `getuid` is a nullary POSIX syscall that takes no arguments,
        // touches no memory, and is always defined to succeed; calling it is
        // sound from any thread at any time.
        let uid = unsafe { libc::getuid() };
        // One live endpoint allowed; rate limit disabled.
        let mgr = manager_with_limits(uid, &tmp, 1, 0);
        let caller = CallerCred {
            uid,
            gid: uid,
            pid: 1,
        };
        // First (normal) endpoint occupies the quota.
        mgr.create_uds(caller, "app1", TrafficClass::Normal, Direction::Encrypt, 0)
            .expect("first endpoint fits the quota");
        // A second, distinct endpoint (safety class) exceeds it.
        let err = mgr
            .create_uds(caller, "app1", TrafficClass::Safety, Direction::Encrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::ResourceExhausted);
        // Re-creating the SAME slot is a replacement and stays allowed.
        mgr.create_uds(caller, "app1", TrafficClass::Normal, Direction::Encrypt, 0)
            .expect("replacing an existing slot must not count against the quota");
        mgr.shutdown_all();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn replace_cycles_do_not_leak_endpoints_or_fds() {
        let tmp = unique_tmp();
        // SAFETY: `getuid` is a nullary POSIX syscall that takes no arguments,
        // touches no memory, and is always defined to succeed; calling it is
        // sound from any thread at any time.
        let uid = unsafe { libc::getuid() };
        // No quota, no rate limit: hammer create-or-replace on one slot.
        let mgr = manager_with_limits(uid, &tmp, 0, 0);
        let caller = CallerCred {
            uid,
            gid: uid,
            pid: 1,
        };

        let baseline_fds = count_open_fds();
        for _ in 0..100 {
            mgr.create_uds(caller, "app1", TrafficClass::Normal, Direction::Encrypt, 0)
                .expect("replace-cycle create should succeed");
        }
        // The registry never accumulates: exactly one live endpoint / owner.
        {
            let live = mgr.live.lock().unwrap();
            assert_eq!(live.by_id.len(), 1, "replaced endpoints must be detached");
            assert_eq!(live.by_owner.len(), 1, "owner map must not accumulate");
        }

        mgr.shutdown_all();
        // The registry is fully drained after shutdown.
        {
            let live = mgr.live.lock().unwrap();
            assert_eq!(live.by_id.len(), 0, "shutdown_all must drain the registry");
            assert_eq!(live.by_owner.len(), 0);
        }

        // Detached endpoint threads release their listener fds asynchronously;
        // poll until the count settles back near the baseline. A real per-cycle
        // leak would add ~100 fds that never close, well beyond the slack.
        let mut settled = count_open_fds();
        for _ in 0..50 {
            if settled <= baseline_fds + 40 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            settled = count_open_fds();
        }
        assert!(
            settled <= baseline_fds + 40,
            "fd count did not return near baseline after 100 replace cycles: \
             baseline={baseline_fds}, settled={settled}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
