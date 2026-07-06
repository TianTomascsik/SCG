# 09 — Configuration Source Interface

> **Status:** 🟡 Proposed · **Trait:** `ConfigSource` ·
> **Abstracts:** [management/config.rs](../../src/management/config.rs)
> (`GatewayConfig::load`) + [management/config_manager.rs](../../src/management/config_manager.rs)
> (`SharedConfig`, `spawn_config_watcher`) · **Stub:** [traits/config_source.rs](traits/config_source.rs)

## Purpose

Abstract **where configuration comes from and how changes are observed**, so the
gateway can be driven by a JSON file (today), or by environment, etcd/Consul, a
Kubernetes ConfigMap, or a control-plane push — without changing how the rest of
the gateway consumes config or performs hot-reload.

## Why an interface is needed

Today configuration is JSON-file specific:

- `GatewayConfig::load(path)` reads + parses + validates a JSON file.
- [`SharedConfig`](../../src/management/config_manager.rs) wraps it in
  `Arc<RwLock<GatewayConfig>>`, tracks file mtime, and `spawn_config_watcher`
  polls every 2s + handles `SIGHUP`, invoking a callback with a `ConfigDiff`.

The **consumption side** (validated `GatewayConfig`, `ConfigDiff` of
added/removed/unchanged rules, atomic swap) is already well-factored. Only the
**acquisition + change-detection** is file-bound. `ConfigSource` captures exactly
that seam.

## Trait

```rust
pub trait ConfigSource: Send + Sync {
    /// Human-readable identity of the source (e.g. "file:/etc/scg.json").
    fn describe(&self) -> String;

    /// Load and validate the full configuration now.
    fn load(&self) -> Result<GatewayConfig, ConfigError>;

    /// Begin watching for changes. On each change, compute the diff against the
    /// previously-served config and invoke `on_change`. Returns a handle whose
    /// drop stops watching. `shutdown` provides cooperative termination.
    fn watch(
        &self,
        shutdown: Arc<AtomicBool>,
        on_change: Box<dyn Fn(ConfigDiff) + Send>,
    ) -> Result<WatchHandle, ConfigError>;
}
```

## Method contracts

| Method | Contract |
|--------|----------|
| `describe()` | Stable, for logs/diagnostics. |
| `load()` | Performs full parse **and validation** (must reject invalid config, as `GatewayConfig::validate` does today). Returns an owned, ready-to-use `GatewayConfig`. |
| `watch(shutdown, on_change)` | Detects changes by whatever mechanism fits the backend (mtime poll, inotify, etcd watch, signal). On each change it reloads, validates, computes a `ConfigDiff` vs. the last good config, and calls `on_change`. Invalid new config is rejected and the previous config remains active. Honours `shutdown`. |

**Validation must precede activation.** A change that fails validation must not be
applied; the gateway keeps running on the last valid config (today's behaviour).

**Existing connections are unaffected** by a reload; only `diff.added` rules start
and `diff.removed` rules signal shutdown — this consumption contract is preserved.

## Data types

```rust
pub enum ConfigError {
    Io(String),
    Parse(String),
    Validation(String),
    Unavailable(String),
}

pub struct WatchHandle; // Drop stops the watcher
```

`GatewayConfig` and `ConfigDiff { added, removed, unchanged }` are defined in
[config.rs](../../src/management/config.rs) and are the shared consumption types.

## Lifecycle & threading

- **Construct:** from a URI/descriptor (`file:…`, `env:`, `etcd:…`).
- **Inject:** `GatewayServices.config_src`; `main.rs` calls `load()` once at
  startup and `watch()` to drive hot-reload.
- **Run:** watcher runs on its own thread (today: the polling/SIGHUP thread).
- **Shutdown:** drop `WatchHandle` or set `shutdown`.

## Mapping from current code

| Today | Interface |
|-------|-----------|
| `GatewayConfig::load(path)` | `ConfigSource::load()` |
| `SharedConfig` mtime cache + `has_changed()` + `reload()` | internal to a `FileConfigSource` |
| `spawn_config_watcher(shared, shutdown, on_reload)` | `ConfigSource::watch(shutdown, on_change)` |
| `ConfigDiff { added, removed, unchanged }` | unchanged shared type |
| `SIGHUP` + 2s poll | one possible `watch()` implementation |

## Example implementor (skeleton)

```rust
pub struct FileConfigSource { path: PathBuf }

impl ConfigSource for FileConfigSource {
    fn describe(&self) -> String { format!("file:{}", self.path.display()) }
    fn load(&self) -> Result<GatewayConfig, ConfigError> {
        GatewayConfig::load(self.path.to_str().unwrap())
            .map_err(ConfigError::Validation)
    }
    fn watch(&self, shutdown: Arc<AtomicBool>, on_change: Box<dyn Fn(ConfigDiff) + Send>)
        -> Result<WatchHandle, ConfigError> {
        // poll mtime every 2s + SIGHUP; on change: load(), diff, on_change()
        Ok(WatchHandle)
    }
}
```

## Selection

```bash
gateway --config /etc/scg/gateway.json          # file source (default)
gateway --config-source etcd://cluster/scg/cfg  # alternative source (proposed)
```

## Conformance checklist

- [ ] `load()` validates and rejects invalid configuration.
- [ ] Invalid reloads are rejected; the last valid config stays active.
- [ ] `watch()` computes a correct `ConfigDiff` against the last served config.
- [ ] Hot-reload leaves existing connections untouched.
- [ ] `watch()` honours the shutdown flag; dropping `WatchHandle` stops it.
- [ ] Trait is `Send + Sync`.

---

## Implemented — Crypto security parameters (`provider_params`)

Rules using the `tls`, `ktls`, or `dtls` provider accept additional security
fields. They are flattened into the rule object (any key that is not a known
top-level field becomes part of `provider_params`) and resolved into a
[`TlsSecurityParams`](../../src/security/tls_engine/params.rs).

| Field | Required | Meaning |
|---|---|---|
| `protocol_version` | no | `"tls1.2"` · `"tls1.3"` · `"dtls1.0"` · `"dtls1.2"`. |
| `profile` | no | `"default"` · `"subset146-pki"` · `"subset146-psk"` · `"integrity-only"`. |
| `verify` | no (default `none`) | `"none"` · `"server"` · `"mutual"`. |
| `cert_path` / `key_path` | when serving an identity | PEM identity; self-signed fallback when omitted. |
| `ca_path` | with `verify` server/mutual | PEM trust anchor for peer verification. |
| `server_name` | no | SNI + verified hostname (defaults to the upstream host). |
| `psk_identity` / `psk_hex` | with `subset146-psk` | TLS-PSK identity + key. |
| `app_protocol` | no (default `ale`) | UDP-over-TLS framing: `"ale"` or `"raw"`. |

`ktls` + `integrity-only` is rejected at load (a NULL cipher cannot be
offloaded); other non-offloadable profiles fall back to userspace `tls` with a
warning. Full reference: [01 — Crypto Provider](01-crypto-provider.md); runnable
configs: [examples/configs/](../../examples/configs/).

## Implemented — DSCP marking & safety prioritization (QoS)

Every rule carries a traffic class and two optional per-rule QoS fields. Safety
traffic is **always** prioritized internally and marked for priority on the wire.
Parsed into a [`QosPolicy`](../../src/management/config.rs) via `RuleConfig::qos`.

| Field | Required | Meaning |
|---|---|---|
| `traffic_class` | no (default `normal`) | `"safety"` or `"normal"`. Selects the class default DSCP/priority — safety defaults to **EF (46)**, normal is left unmarked. |
| `dscp_tag` | no | Explicit egress DSCP `0`–`63`. Overrides the class default and any inbound marking. `> 63` is **rejected at load**. |
| `preserve_inbound_dscp` | no (default `false`) | When `true` and no `dscp_tag`, the gateway samples the inbound DS field (`IP_RECVTOS` / `IPV6_RECVTCLASS`) and re-applies it on egress. |

**Egress DSCP precedence** ([`RuleConfig::egress_dscp`](../../src/management/config.rs)):

1. explicit `dscp_tag` → that value;
2. else `preserve_inbound_dscp` + a sampled inbound DSCP → the sampled value;
3. else the class default: **safety → EF (46)**, normal → unmarked.

**Internal prioritization (always on for safety).** Independent of DSCP, safety
rules raise their workers' scheduling priority via
[`apply_safety_priority`](../../src/networking/socket_manager.rs) (`nice -5` when
the process holds `CAP_SYS_NICE`), set `SO_PRIORITY = 6` on their sockets, and run
on a class-aware [`ConnectionPool`](../../src/security/conn_pool.rs) with a
reserved minimum worker count so a normal-traffic flood cannot starve safety
capacity. Without `CAP_SYS_NICE` the gateway logs a one-time preflight warning and
degrades to DSCP + `SO_PRIORITY` only.

**Preservation scope.** Per-datagram inbound-DSCP preservation works where the
gateway owns the receive (UDP / DTLS). On TLS-terminated and `splice` TCP paths
the gateway cannot sample per-segment marks, so preservation falls back to the
class default (safety still gets EF). IPv4 (`IP_TOS`) and IPv6 (`IPV6_TCLASS`) are
both first-class.

```json
{
  "name": "safety-ef-tag",
  "direction": "encrypt",
  "listen_addr": "0.0.0.0:9200",
  "listen_proto": "tcp",
  "upstream_addr": "safety-backend.example:9200",
  "security_provider": "routing",
  "traffic_class": "safety",
  "dscp_tag": 46
}
```

Runnable example: [examples/configs/dscp_qos.json](../../examples/configs/dscp_qos.json);
end-to-end tests: [tests/dscp.rs](../../tests/dscp.rs).

## Implemented — Local-interface configuration (UDS/SHM + `api`)

Local interfaces are configured through the **same** `GatewayConfig` schema
already validated by `GatewayConfig::load`/`validate`. Two additions are
relevant.

### Local-interface rules

A UDS or SHM endpoint is declared as a normal rule whose `listen_proto` is
`"uds"` or `"shm"`. Such rules are **templates** consumed by the
`InterfaceManager`: they have no static listen socket, so `validate()` skips the
`listen_addr` parse and instead requires a non-empty `app_id` and at least one
`allowed_uids` entry.

| Field | Required | Meaning |
|---|---|---|
| `listen_proto` | yes | `"uds"` or `"shm"`. |
| `app_id` | yes | Identifies the application slot the client requests. |
| `traffic_class` | no (default `normal`) | `"safety"` or `"normal"` — endpoints are provisioned **per app and per class**. |
| `direction` | yes | `"encrypt"` or `"decrypt"` — both are supported. |
| `upstream_addr` | yes | `HOST:PORT` TLS upstream the endpoint relays to. |
| `security_provider` | no | `"tls"` (default) or `"ktls"` for the upstream leg. |
| `allowed_uids` | yes (non-empty) | uids permitted to open the endpoint; enforced via `SO_PEERCRED`. An empty list disables the local interface for the rule. |
| `allowed_pids` | no | When non-empty, the peer pid must also match. |

```json
{
  "name": "local-uds-safety",
  "direction": "encrypt",
  "listen_proto": "uds",
  "listen_addr": "local",
  "upstream_addr": "remote-gw:5443",
  "security_provider": "ktls",
  "traffic_class": "safety",
  "app_id": "etcs_onboard",
  "allowed_uids": [1000],
  "allowed_pids": []
}
```

### The `api` block

Optional; when omitted it defaults to gRPC-over-UDS at
`/run/scg/management.sock` with no TCP listener. It also tunes the per-uid
resource guards added for security hardening.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Start the management API. |
| `uds_path` | `/run/scg/management.sock` | gRPC-over-UDS control socket (`SO_PEERCRED`-authenticated). |
| `tcp_addr` | `null` | Optional TCP bind for remote admin (e.g. `"127.0.0.1:50080"`). |
| `runtime_dir` | `/run/scg` | Base dir for per-uid endpoint sockets (`<dir>/<uid>`, `0700`). |
| `shm_ring_capacity` | `4194304` | Default SHM ring size per direction (bytes, page-rounded). |
| `shm_ring_kind` | `"byte_stream"` | SHM ring flavour: `"byte_stream"` (variable-length) or `"slot"` (fixed Vyukov slots). |
| `shm_segment_size` | `2048` | Slot ring: bytes per segment (an explicit `0` derives from the max frame). |
| `shm_num_segments` | `512` | Slot ring: number of segments (an explicit `0` = derive; rounded to a power of two). |
| `shm_g2c_notify` | `"eventfd"` | Gateway→client wakeup: `"eventfd"` (pollable) or `"futex"` (lowest latency, slot ring). |
| `max_endpoints_per_uid` | `64` | Max simultaneously-live endpoints per uid (`0` = unlimited). Exceeding it returns `RESOURCE_EXHAUSTED`. |
| `create_rate_per_min` | `120` | Per-uid token-bucket limit on create requests (`0` = unlimited). |

```json
"api": {
  "enabled": true,
  "uds_path": "/run/scg/management.sock",
  "tcp_addr": null,
  "runtime_dir": "/run/scg",
  "shm_ring_capacity": 4194304,
  "shm_ring_kind": "byte_stream",
  "shm_g2c_notify": "eventfd",
  "max_endpoints_per_uid": 64,
  "create_rate_per_min": 120
}
```

Validate any config (including the local-interface rules and `api` block) with:

```bash
gateway --config gateway/gateway.example.json --validate
```
