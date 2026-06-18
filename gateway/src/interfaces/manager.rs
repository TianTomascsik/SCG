//! Interface manager: owns the lifecycle of dynamically-created local
//! interfaces (UDS today; SHM in a later work package).
//!
//! `uds`/`shm` rules in the gateway config act as *templates*: they are not
//! started as listeners at boot. Instead, an application asks the management API
//! to create an endpoint for its `(app_id, traffic_class, direction)`; the
//! manager authorises the caller from config, spawns a dedicated endpoint
//! thread, and returns the socket path plus a single-use capability token.

use crate::interfaces::endpoint::upstream_tls_mode;
use crate::interfaces::shm::{run_shm_endpoint, ShmEndpointTask};
use crate::interfaces::uds::{run_uds_endpoint, UdsEndpointTask};
use crate::management::config::{Direction, GatewayConfig, Proto, TlsMode, TrafficClass};

use scg_ipc::handshake::SHM_NOTIFY_EVENTFD;
use scg_ipc::token::CapabilityToken;
use scg_proto::v1::RuleInfo;

use log::{info, warn};
use tonic::Status;

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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
struct EndpointTemplate {
    rule_name: String,
    upstream_addr: String,
    tls_mode: TlsMode,
    protocol_version: Option<String>,
    allowed_uids: Arc<Vec<u32>>,
    allowed_pids: Arc<Vec<i32>>,
    /// Default per-direction ring capacity for SHM endpoints (bytes).
    ring_capacity: usize,
}

/// A currently-live endpoint instance.
struct LiveEndpoint {
    kind: Proto,
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
        let cap = per_min.max(1) as f64;
        let refill_per_s = per_min as f64 / 60.0;
        let now = Instant::now();
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
    templates: HashMap<String, EndpointTemplate>,
    all_rules: Vec<RuleInfo>,
    runtime_dir: String,
    sock_buf_size: usize,
    version: String,
    /// Maximum simultaneously-live endpoints per uid (`0` = unlimited).
    max_endpoints_per_uid: u32,
    /// Maximum endpoint-creation requests per uid per minute (`0` = unlimited).
    max_create_per_min: u32,
    live: Mutex<LiveState>,
    rate: Mutex<RateLimiter>,
}

impl InterfaceManager {
    /// Build the manager from the gateway config, deriving UDS/SHM templates
    /// from rules whose `listen_proto` is `uds` or `shm`.
    pub fn new(
        config: &GatewayConfig,
        version: impl Into<String>,
        _global_shutdown: Arc<AtomicBool>,
    ) -> Arc<Self> {
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
            let tls_mode = upstream_tls_mode(rule.effective_security_provider());
            let key = template_key(&app_id, rule.traffic_class, rule.direction, rule.listen_proto);
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
                    protocol_version: rule.protocol_version.clone(),
                    allowed_uids: Arc::new(rule.allowed_uids.clone()),
                    allowed_pids: Arc::new(rule.allowed_pids.clone()),
                    ring_capacity: api.shm_ring_capacity,
                },
            );
        }

        info!(
            "interface-manager: {} local-interface template(s) registered",
            templates.len()
        );

        Arc::new(InterfaceManager {
            templates,
            all_rules,
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
        })
    }

    /// Gateway version string (for the Health RPC).
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Snapshot of the configured pipeline rules (for the ListRules RPC).
    pub fn list_rules(&self) -> Vec<RuleInfo> {
        self.all_rules.clone()
    }

    /// Emit a structured audit record for a denied control-plane request. All
    /// denial paths funnel through here so operators get one consistent,
    /// greppable line (`AUDIT deny`) carrying the caller identity and reason.
    fn audit_deny(op: &str, caller: CallerCred, app_id: &str, reason: &str) {
        warn!(
            "AUDIT deny op={op} uid={} pid={} app_id={app_id}: {reason}",
            caller.uid, caller.pid
        );
    }

    /// Apply the per-uid rate limit and live-endpoint quota before a new
    /// endpoint is created. `owner_key` identifies the (uid, app, class,
    /// direction, kind) slot: re-creating an existing slot is a replacement and
    /// does not count against the quota. Returns a ready-to-return `Status` on
    /// rejection.
    fn check_admission(&self, op: &str, caller: CallerCred, app_id: &str, owner_key: &str) -> Result<(), Status> {
        // Token-bucket rate limit on create requests.
        if self.max_create_per_min > 0 {
            let admitted = self
                .rate
                .lock()
                .unwrap()
                .allow(caller.uid, self.max_create_per_min);
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
            let live = self.live.lock().unwrap();
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

    /// Create (or atomically replace) a UDS endpoint for the caller.
    pub fn create_uds(
        &self,
        caller: CallerCred,
        app_id: &str,
        class: TrafficClass,
        direction: Direction,
        _ring_capacity: usize,
    ) -> Result<UdsCreated, Status> {
        if direction != Direction::Encrypt {
            return Err(Status::unimplemented(
                "decrypt-direction UDS endpoints are not yet supported",
            ));
        }
        let key = template_key(app_id, class, direction, Proto::Uds);
        let template = self.templates.get(&key).ok_or_else(|| {
            Status::not_found(format!(
                "no uds rule for app_id={app_id} class={class} direction={direction}"
            ))
        })?;

        // Authorise the caller against the rule's allow-lists.
        if template.allowed_uids.is_empty() || !template.allowed_uids.contains(&caller.uid) {
            Self::audit_deny("create_uds", caller, app_id, "uid not in allowed_uids");
            return Err(Status::permission_denied(format!(
                "uid {} is not authorised for app_id={app_id}",
                caller.uid
            )));
        }
        if !template.allowed_pids.is_empty() && !template.allowed_pids.contains(&caller.pid) {
            Self::audit_deny("create_uds", caller, app_id, "pid not in allowed_pids");
            return Err(Status::permission_denied(format!(
                "pid {} is not authorised for app_id={app_id}",
                caller.pid
            )));
        }

        // Enforce per-uid rate limit and live-endpoint quota.
        let owner_key = owner_key(caller.uid, app_id, class, direction, Proto::Uds);
        self.check_admission("create_uds", caller, app_id, &owner_key)?;

        // Resolve a per-uid runtime directory for the socket.
        let dir = self
            .resolve_runtime_dir(caller.uid)
            .map_err(|e| Status::internal(format!("runtime dir: {e}")))?;

        // Allocate an id, an owner key, and a fresh single-use token.
        let token = CapabilityToken::random().map_err(|e| Status::internal(format!("token: {e}")))?;
        let token_bytes = token.as_bytes().to_vec();
        let id = self.alloc_id();

        let file_name = format!("{}.{}.{}.{}.sock", sanitize(app_id), class, direction, id);
        let socket_path = dir.join(file_name);
        let label = format!("{}#{id}", template.rule_name);
        let shutdown = Arc::new(AtomicBool::new(false));

        let task = UdsEndpointTask {
            label: label.clone(),
            socket_path: socket_path.clone(),
            upstream_addr: template.upstream_addr.clone(),
            tls_mode: template.tls_mode,
            protocol_version: template.protocol_version.clone(),
            sock_buf_size: self.sock_buf_size,
            allowed_uids: template.allowed_uids.clone(),
            allowed_pids: template.allowed_pids.clone(),
            owner_uid: caller.uid,
            token: Arc::new(Mutex::new(Some(token))),
            shutdown: shutdown.clone(),
        };

        let join = std::thread::Builder::new()
            .name(format!("uds-ep-{id}"))
            .spawn(move || run_uds_endpoint(task))
            .map_err(|e| Status::internal(format!("spawn endpoint thread: {e}")))?;

        // Register, replacing any previous endpoint bound to the same owner key.
        self.register_or_replace(
            id,
            owner_key.clone(),
            LiveEndpoint {
                kind: Proto::Uds,
                socket_path: socket_path.clone(),
                owner_uid: caller.uid,
                owner_key,
                shutdown,
                join: Some(join),
            },
            &label,
        );

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
        if direction != Direction::Encrypt {
            return Err(Status::unimplemented(
                "decrypt-direction SHM endpoints are not yet supported",
            ));
        }
        let key = template_key(app_id, class, direction, Proto::Shm);
        let template = self.templates.get(&key).ok_or_else(|| {
            Status::not_found(format!(
                "no shm rule for app_id={app_id} class={class} direction={direction}"
            ))
        })?;

        // Authorise the caller against the rule's allow-lists.
        if template.allowed_uids.is_empty() || !template.allowed_uids.contains(&caller.uid) {
            Self::audit_deny("create_shm", caller, app_id, "uid not in allowed_uids");
            return Err(Status::permission_denied(format!(
                "uid {} is not authorised for app_id={app_id}",
                caller.uid
            )));
        }
        if !template.allowed_pids.is_empty() && !template.allowed_pids.contains(&caller.pid) {
            Self::audit_deny("create_shm", caller, app_id, "pid not in allowed_pids");
            return Err(Status::permission_denied(format!(
                "pid {} is not authorised for app_id={app_id}",
                caller.pid
            )));
        }

        // Enforce per-uid rate limit and live-endpoint quota.
        let owner_key = owner_key(caller.uid, app_id, class, direction, Proto::Shm);
        self.check_admission("create_shm", caller, app_id, &owner_key)?;

        // Both rings use the same capacity: the request value if given, else the
        // template default. The endpoint thread rounds it up to a page.
        let cap = if ring_capacity > 0 {
            ring_capacity
        } else {
            template.ring_capacity
        };

        let dir = self
            .resolve_runtime_dir(caller.uid)
            .map_err(|e| Status::internal(format!("runtime dir: {e}")))?;

        let token = CapabilityToken::random().map_err(|e| Status::internal(format!("token: {e}")))?;
        let token_bytes = token.as_bytes().to_vec();
        let id = self.alloc_id();

        let file_name = format!("{}.{}.{}.{}.ctl.sock", sanitize(app_id), class, direction, id);
        let control_socket_path = dir.join(file_name);
        let label = format!("{}#{id}", template.rule_name);
        let shutdown = Arc::new(AtomicBool::new(false));

        let task = ShmEndpointTask {
            label: label.clone(),
            control_socket_path: control_socket_path.clone(),
            upstream_addr: template.upstream_addr.clone(),
            tls_mode: template.tls_mode,
            protocol_version: template.protocol_version.clone(),
            sock_buf_size: self.sock_buf_size,
            cap_c2g: cap,
            cap_g2c: cap,
            allowed_uids: template.allowed_uids.clone(),
            allowed_pids: template.allowed_pids.clone(),
            owner_uid: caller.uid,
            token: Arc::new(Mutex::new(Some(token))),
            shutdown: shutdown.clone(),
        };

        let join = std::thread::Builder::new()
            .name(format!("shm-ep-{id}"))
            .spawn(move || run_shm_endpoint(task))
            .map_err(|e| Status::internal(format!("spawn endpoint thread: {e}")))?;

        self.register_or_replace(
            id,
            owner_key.clone(),
            LiveEndpoint {
                kind: Proto::Shm,
                socket_path: control_socket_path.clone(),
                owner_uid: caller.uid,
                owner_key,
                shutdown,
                join: Some(join),
            },
            &label,
        );

        // The endpoint thread rounds the capacity up to a page; report the same
        // value to the client so its ring geometry matches the control page.
        let cap_reported = round_up_page(cap) as u64;
        info!(
            "[{label}] created SHM endpoint id={id} at {} for uid={} (rings {cap_reported}B/dir)",
            control_socket_path.display(),
            caller.uid
        );
        Ok(ShmCreated {
            control_socket_path: control_socket_path.to_string_lossy().into_owned(),
            token: token_bytes,
            endpoint_id: id,
            cap_c2g: cap_reported,
            cap_g2c: cap_reported,
            notify: SHM_NOTIFY_EVENTFD as i32,
        })
    }

    /// Tear down a previously-created endpoint owned by the caller.
    pub fn close(&self, caller: CallerCred, endpoint_id: u32) -> Result<(), Status> {
        let mut live = self.live.lock().unwrap();
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
        let mut ep = live.by_id.remove(&endpoint_id).unwrap();
        live.by_owner.remove(&ep.owner_key);
        drop(live);

        ep.shutdown.store(true, Ordering::SeqCst);
        // Detach: dropping the handle lets the endpoint thread wind down on its
        // own without blocking the control-plane runtime.
        ep.join.take();
        info!("closed endpoint id={endpoint_id} (uid={})", caller.uid);
        Ok(())
    }

    /// Signal every live endpoint to shut down (called on gateway shutdown).
    pub fn shutdown_all(&self) {
        let mut live = self.live.lock().unwrap();
        let ids: Vec<u32> = live.by_id.keys().copied().collect();
        for id in ids {
            if let Some(mut ep) = live.by_id.remove(&id) {
                ep.shutdown.store(true, Ordering::SeqCst);
                ep.join.take();
                let _ = std::fs::remove_file(&ep.socket_path);
                let _ = ep.kind; // kind retained for future per-kind teardown
            }
        }
        live.by_owner.clear();
    }

    /// Remove and signal an endpoint without joining (used on create/replace).
    fn detach_endpoint(&self, id: u32) {
        let ep = { self.live.lock().unwrap().by_id.remove(&id) };
        if let Some(mut ep) = ep {
            ep.shutdown.store(true, Ordering::SeqCst);
            ep.join.take();
        }
    }

    /// Allocate the next endpoint id, wrapping past `u32::MAX` back to 1.
    fn alloc_id(&self) -> u32 {
        let mut live = self.live.lock().unwrap();
        let id = live.next_id;
        live.next_id = live.next_id.checked_add(1).unwrap_or(1).max(1);
        id
    }

    /// Register a live endpoint under `id`, detaching any previous endpoint that
    /// was bound to the same owner key (create-or-replace semantics).
    fn register_or_replace(&self, id: u32, owner_key: String, ep: LiveEndpoint, label: &str) {
        let replaced = {
            let mut live = self.live.lock().unwrap();
            let replaced = live.by_owner.insert(owner_key, id);
            live.by_id.insert(id, ep);
            replaced
        };
        if let Some(old_id) = replaced {
            self.detach_endpoint(old_id);
            info!("[{label}] replaced previous endpoint id={old_id} for the same owner");
        }
    }

    /// Resolve a per-uid runtime directory for endpoint sockets.
    ///
    /// When the gateway is privileged it creates `<runtime_dir>/<uid>` (0700)
    /// and chowns it to the caller; otherwise it falls back to the caller's XDG
    /// runtime directory `/run/user/<uid>/scg`.
    fn resolve_runtime_dir(&self, uid: u32) -> io::Result<PathBuf> {
        let euid = unsafe { libc::geteuid() };
        let base = PathBuf::from(&self.runtime_dir);

        if ensure_dir(&base, 0o755).is_ok() {
            let per_uid = base.join(uid.to_string());
            if ensure_dir(&per_uid, 0o700).is_ok() {
                if euid == 0 {
                    let _ = scg_ipc::os::chown(&per_uid, uid, uid);
                }
                let _ = scg_ipc::os::chmod(&per_uid, 0o700);
                return Ok(per_uid);
            }
        }

        // Fallback: the caller's XDG runtime directory.
        let xdg = PathBuf::from(format!("/run/user/{uid}")).join("scg");
        ensure_dir(&xdg, 0o700)?;
        info!("interface-manager: using fallback runtime dir {}", xdg.display());
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

/// Map the config traffic class to its proto integer value.
fn traffic_class_to_proto(class: TrafficClass) -> i32 {
    match class {
        TrafficClass::Normal => 0,
        TrafficClass::Safety => 1,
    }
}

/// Round a byte count up to the next system page boundary (matches the rounding
/// the SHM endpoint thread applies to its ring capacities).
fn round_up_page(n: usize) -> usize {
    let page = {
        let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if v <= 0 {
            4096usize
        } else {
            v as usize
        }
    };
    let n = n.max(page);
    (n + page - 1) & !(page - 1)
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
    use tonic::Code;

    fn unique_tmp() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("scg-itest-{}-{}", std::process::id(), nanos));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn manager_with_uds_rule(allowed_uid: u32, runtime_dir: &PathBuf) -> Arc<InterfaceManager> {
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
                }}],
                "api": {{ "runtime_dir": "{}", "uds_path": "{}/mgmt.sock" }}
            }}"#,
            runtime_dir.display(),
            runtime_dir.display()
        );
        let config: GatewayConfig = serde_json::from_str(&json).expect("parse test config");
        InterfaceManager::new(&config, "test", Arc::new(AtomicBool::new(false)))
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
        let o1 = owner_key(1000, "app1", TrafficClass::Normal, Direction::Encrypt, Proto::Uds);
        let o2 = owner_key(1001, "app1", TrafficClass::Normal, Direction::Encrypt, Proto::Uds);
        assert_ne!(o1, o2);
    }

    #[test]
    fn create_uds_unknown_app_is_not_found() {
        let tmp = unique_tmp();
        let mgr = manager_with_uds_rule(1000, &tmp);
        let caller = CallerCred { uid: 1000, gid: 1000, pid: 1 };
        let err = mgr
            .create_uds(caller, "nope", TrafficClass::Normal, Direction::Encrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_uds_decrypt_is_unimplemented() {
        let tmp = unique_tmp();
        let mgr = manager_with_uds_rule(1000, &tmp);
        let caller = CallerCred { uid: 1000, gid: 1000, pid: 1 };
        let err = mgr
            .create_uds(caller, "app1", TrafficClass::Normal, Direction::Decrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::Unimplemented);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_uds_wrong_uid_is_denied() {
        let tmp = unique_tmp();
        // Rule authorises uid 1000; caller is uid 4242.
        let mgr = manager_with_uds_rule(1000, &tmp);
        let caller = CallerCred { uid: 4242, gid: 4242, pid: 1 };
        let err = mgr
            .create_uds(caller, "app1", TrafficClass::Normal, Direction::Encrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_uds_success_returns_token_and_path() {
        let tmp = unique_tmp();
        let uid = unsafe { libc::getuid() };
        let mgr = manager_with_uds_rule(uid, &tmp);
        let caller = CallerCred { uid, gid: uid, pid: 1 };
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

    fn manager_with_shm_rule(allowed_uid: u32, runtime_dir: &PathBuf) -> Arc<InterfaceManager> {
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
                }}],
                "api": {{ "runtime_dir": "{}", "uds_path": "{}/mgmt.sock" }}
            }}"#,
            runtime_dir.display(),
            runtime_dir.display()
        );
        let config: GatewayConfig = serde_json::from_str(&json).expect("parse test config");
        InterfaceManager::new(&config, "test", Arc::new(AtomicBool::new(false)))
    }

    #[test]
    fn create_shm_unknown_app_is_not_found() {
        let tmp = unique_tmp();
        let mgr = manager_with_shm_rule(1000, &tmp);
        let caller = CallerCred { uid: 1000, gid: 1000, pid: 1 };
        let err = mgr
            .create_shm(caller, "nope", TrafficClass::Safety, Direction::Encrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_shm_decrypt_is_unimplemented() {
        let tmp = unique_tmp();
        let mgr = manager_with_shm_rule(1000, &tmp);
        let caller = CallerCred { uid: 1000, gid: 1000, pid: 1 };
        let err = mgr
            .create_shm(caller, "app1", TrafficClass::Safety, Direction::Decrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::Unimplemented);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_shm_wrong_uid_is_denied() {
        let tmp = unique_tmp();
        let mgr = manager_with_shm_rule(1000, &tmp);
        let caller = CallerCred { uid: 4242, gid: 4242, pid: 1 };
        let err = mgr
            .create_shm(caller, "app1", TrafficClass::Safety, Direction::Encrypt, 0)
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_shm_success_returns_token_path_and_geometry() {
        let tmp = unique_tmp();
        let uid = unsafe { libc::getuid() };
        let mgr = manager_with_shm_rule(uid, &tmp);
        let caller = CallerCred { uid, gid: uid, pid: 1 };
        // Request a small ring; it is rounded up to a page.
        let created = mgr
            .create_shm(caller, "app1", TrafficClass::Safety, Direction::Encrypt, 4096)
            .expect("create_shm should succeed for an authorised uid");
        assert_eq!(created.token.len(), 32, "token must be 256-bit");
        assert_eq!(created.endpoint_id, 1);
        assert_eq!(created.notify, SHM_NOTIFY_EVENTFD as i32);
        assert!(created.cap_c2g >= 4096 && created.cap_c2g % 4096 == 0);
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
        runtime_dir: &PathBuf,
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
        InterfaceManager::new(&config, "test", Arc::new(AtomicBool::new(false)))
    }

    #[test]
    fn create_rate_limit_denies_burst() {
        let tmp = unique_tmp();
        let uid = unsafe { libc::getuid() };
        // Quota disabled; allow a single create per minute.
        let mgr = manager_with_limits(uid, &tmp, 0, 1);
        let caller = CallerCred { uid, gid: uid, pid: 1 };
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
        let uid = unsafe { libc::getuid() };
        // One live endpoint allowed; rate limit disabled.
        let mgr = manager_with_limits(uid, &tmp, 1, 0);
        let caller = CallerCred { uid, gid: uid, pid: 1 };
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
        let uid = unsafe { libc::getuid() };
        // No quota, no rate limit: hammer create-or-replace on one slot.
        let mgr = manager_with_limits(uid, &tmp, 0, 0);
        let caller = CallerCred { uid, gid: uid, pid: 1 };

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

