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
| `direction` | yes | v1 supports `"encrypt"` only; `"decrypt"` is rejected at create time (`UNIMPLEMENTED`). |
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
| `shm_ring_capacity` | `1048576` | Default SHM ring size per direction (bytes, page-rounded). |
| `max_endpoints_per_uid` | `64` | Max simultaneously-live endpoints per uid (`0` = unlimited). Exceeding it returns `RESOURCE_EXHAUSTED`. |
| `create_rate_per_min` | `120` | Per-uid token-bucket limit on create requests (`0` = unlimited). |

```json
"api": {
  "enabled": true,
  "uds_path": "/run/scg/management.sock",
  "tcp_addr": null,
  "runtime_dir": "/run/scg",
  "shm_ring_capacity": 1048576,
  "max_endpoints_per_uid": 64,
  "create_rate_per_min": 120
}
```

Validate any config (including the local-interface rules and `api` block) with:

```bash
gateway --config gateway/gateway.example.json --validate
```
