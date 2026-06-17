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
