# 01 — Crypto Provider Interface

> **Status:** ✅ As-built · **Trait:** `CryptoProvider` ·
> **Source of truth:** [security/provider.rs](../../src/security/provider.rs#L29) ·
> **Stub:** [traits/crypto_provider.rs](traits/crypto_provider.rs)

## Purpose

A **Crypto Provider** is a swappable security engine. It owns the entire
encrypt-or-decrypt loop for a forwarding rule: it opens the listener, performs
the handshake (if any), and relays traffic between the plaintext side and the
protected side until shutdown. Selecting a different provider changes *how* a
rule is protected (userspace TLS, kernel TLS, DTLS, MAC-only authentication, …)
without touching dispatch or any other provider.

This is the reference interface that all other SCG interfaces follow.

## Responsibilities

- Declare a unique `name()` used to select it from config (`security_provider`).
- Declare which `(Direction, Proto)` combinations it supports.
- Implement the **encrypt** path (plaintext in → protected out) and the
  **decrypt** path (protected in → plaintext out).
- Drive its own I/O loop, spawn per-connection work on the rule's connection
  pool, update metrics, and stop when the shutdown flag is set.

A provider is **not** responsible for: choosing the rule, parsing config,
classifying traffic, or owning key material (key/cert material is injected — see
[05 — Certificate & Key Management](05-cert-key-management.md)).

## Trait

```rust
pub trait CryptoProvider: Send + Sync {
    /// Unique string identifier used in config (e.g., "tls", "ktls", "dtls").
    fn name(&self) -> &str;

    /// Human-readable description for logging.
    fn description(&self) -> &str;

    /// Which (direction, listen_proto) combinations this provider supports.
    fn supported_modes(&self) -> Vec<ProviderMode>;

    /// Run the encrypt direction for this provider. Blocks until shutdown.
    fn run_encrypt(&self, ctx: &RuleContext) -> Result<(), String>;

    /// Run the decrypt direction for this provider. Blocks until shutdown.
    fn run_decrypt(&self, ctx: &RuleContext) -> Result<(), String>;
}
```

## Method contracts

| Method | Contract |
|--------|----------|
| `name()` | Stable, unique, lowercase string. Matched against the rule's `security_provider`. Must be constant for the life of the process. |
| `description()` | Free-form, for logs/diagnostics only. |
| `supported_modes()` | Returns every `(Direction, Proto)` the engine can serve. The core may consult this to validate config. A provider that is given an unsupported mode must return `Err` from the corresponding run method. |
| `run_encrypt(ctx)` | **Blocking.** Binds `ctx.listen_addr`/`ctx.listen_proto`, accepts/receives plaintext, protects it, and forwards to `ctx.upstream_addr`. Runs until `ctx.shutdown` is set, then returns `Ok(())`. Returns `Err(msg)` on a fatal setup error (e.g. cannot bind, unsupported mode). |
| `run_decrypt(ctx)` | **Blocking.** Mirror of `run_encrypt`: accepts protected traffic, recovers plaintext, forwards to upstream. Same shutdown/return contract. |

**Per-connection work.** For connection-oriented transports, the run method
should accept in a loop and hand each connection to `ctx.conn_pool` (see
[ConnectionPool](../../src/security/conn_pool.rs)) so connections run
concurrently without unbounded thread growth.

**Policy.** Before forwarding a new flow, a provider should call
`ctx.classify_and_check_policy(src, dst)` and drop the flow if it returns
`false` (see [07 — Policy](07-policy.md)).

## Data types

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMode {
    pub direction: Direction,     // Encrypt | Decrypt
    pub listen_proto: Proto,      // Tcp | Udp
}
```

`Direction` and `Proto` are defined in
[config.rs](../../src/management/config.rs). `RuleContext` is defined in
[processing/mod.rs](../../src/processing/mod.rs) — see the
[shared types glossary](README.md#shared-types-glossary).

## Lifecycle & threading

- **Construct:** providers are zero-sized/stateless singletons today
  (`TlsProvider`, `KtlsProvider`, …). Any per-rule state lives in `RuleContext`
  or is created inside the run method.
- **Register:** once, at startup (see below). After `into_arc()` the registry is
  frozen and shared read-only.
- **Run:** one rule = one dedicated thread calling `run_encrypt`/`run_decrypt`,
  which owns that thread until shutdown. `Send + Sync` is required because the
  same provider instance is shared across all rule threads.
- **Shutdown:** cooperative via `ctx.shutdown: Arc<AtomicBool>`.

## Error handling

`Result<(), String>`. The string is logged once when the rule thread exits.
Setup failures (bind error, unsupported mode, missing key material) return
`Err`; normal shutdown returns `Ok(())`. Providers must fail closed — never
forward plaintext on the protected side when protection cannot be established.

## Current implementation

| Provider | `name()` | File | Notes |
|----------|----------|------|-------|
| `TlsProvider` | `"tls"` | [providers/tls_provider.rs](../../src/security/providers/tls_provider.rs) | OpenSSL userspace TLS; TCP + UDP-over-TLS. Honours the security profiles + verify modes below. |
| `KtlsProvider` | `"ktls"` | [providers/ktls_provider.rs](../../src/security/providers/ktls_provider.rs) | Kernel TLS offload; shares the TLS engine. Non-offloadable profiles fall back to userspace `tls`; integrity-only is rejected at config-load. |
| `DtlsProvider` | `"dtls"` | [providers/dtls_provider.rs](../../src/security/providers/dtls_provider.rs) | Datagram TLS; UDP only. DTLS 1.0 (CBC) + DTLS 1.2 (AEAD), verify/CA/identity parity with `tls`. |
| `WireguardProvider` | `"wireguard"` | [providers/wireguard_provider.rs](../../src/security/providers/wireguard_provider.rs) | Kernel WireGuard offload; UDP only. Provisions a `wg` interface ([wireguard_engine/](../../src/security/wireguard_engine.rs)) and relays plaintext through the kernel tunnel. Needs `CAP_NET_ADMIN`, the `wireguard` module, and `wg`; keys via `provider_params`. Interface-lifecycle provider — see also [06-transport.md](06-transport.md). |
| `RoutingProvider` | `"routing"` | [providers/routing_provider.rs](../../src/security/providers/routing_provider.rs) | Plaintext L4 passthrough (no crypto): forward + classify/policy only. TCP **and** multi-client UDP (`run_udp_routing_listener` + `security/udp_session.rs`), encrypt + decrypt. |

Shared engines: [tls_engine/](../../src/security/tls_engine/),
[dtls_engine.rs](../../src/security/dtls_engine.rs).

## Security profiles & provider parameters

The `tls`, `ktls`, and `dtls` providers read their security configuration from
the rule's flattened `provider_params` (any field that is not a known top-level
rule key) plus the typed `protocol_version`. These are resolved into a
[`TlsSecurityParams`](../../src/security/tls_engine/params.rs) value that drives
the OpenSSL acceptor/connector.

| Key | Values | Meaning |
|-----|--------|---------|
| `profile` | `default` · `subset146-pki` · `subset146-psk` · `integrity-only` | Cipher policy + verify + version preset. Explicit keys below override the preset. |
| `verify` | `none` · `server` · `mutual` | Peer-certificate verification. `server` verifies the upstream cert (encrypt); `mutual` additionally requires a peer client cert (decrypt). |
| `cert_path` / `key_path` | PEM file paths | This endpoint's identity (server cert for decrypt, optional client cert for encrypt). Falls back to a self-signed dev identity when omitted. |
| `ca_path` | PEM file path | Trust anchor used to verify the peer when `verify` is `server`/`mutual`. |
| `server_name` | hostname | SNI sent by the connector and the name verified against the upstream cert. Defaults to the upstream host. |
| `psk_identity` / `psk_hex` | string / hex | TLS-PSK identity and key for `profile = subset146-psk` (DHE-PSK, TLS 1.2). |
| `cipher_list` / `ciphersuites` | OpenSSL strings | Advanced override of the TLS 1.2 / TLS 1.3 cipher selection. |
| `protocol_version` | `tls1.2` · `tls1.3` · `dtls1.0` · `dtls1.2` | Pins the (D)TLS version (typed top-level field, not in `provider_params`). |

Profiles map to the railway/Subset-146 use cases:

- **`subset146-pki`** — mandatory mutual X.509 auth, ECDHE-ECDSA/RSA-AES-GCM
  (TLS 1.2) or `TLS_AES_256_GCM` / `TLS_CHACHA20_POLY1305` (TLS 1.3); non-GCM
  suites are refused, failures fail closed.
- **`subset146-psk`** — TLS-PSK (DHE-PSK-AES256-GCM, TLS 1.2) from
  `psk_identity` + `psk_hex`; no certificates required.
- **`integrity-only`** — authenticated-but-not-encrypted TLS using NULL-cipher
  suites (OpenSSL eNULL is probed at runtime; rejected on `ktls`).
- **`default`** — back-compatible self-signed, `verify = none`.

See [05 — Certificate & Key Management](05-cert-key-management.md) for the
loading details and [examples/configs/](../../examples/configs/) for a runnable
config per profile.


## Example implementor (skeleton)

```rust
pub struct MyProvider;

impl CryptoProvider for MyProvider {
    fn name(&self) -> &str { "my-engine" }
    fn description(&self) -> &str { "My custom security engine" }

    fn supported_modes(&self) -> Vec<ProviderMode> {
        vec![
            ProviderMode { direction: Direction::Encrypt, listen_proto: Proto::Tcp },
            ProviderMode { direction: Direction::Decrypt, listen_proto: Proto::Tcp },
        ]
    }

    fn run_encrypt(&self, ctx: &RuleContext) -> Result<(), String> {
        // bind ctx.listen_addr, accept loop on ctx.conn_pool,
        // protect + forward to ctx.upstream_addr, poll ctx.shutdown
        Ok(())
    }

    fn run_decrypt(&self, ctx: &RuleContext) -> Result<(), String> {
        Ok(())
    }
}
```

## Registration & selection

Registered once in [lib.rs::run](../../src/lib.rs) (the composition root, not `main.rs`) on the
[`ProviderRegistry`](../../src/processing/registry.rs):

```rust
registry.register_crypto(Box::new(TlsProvider));
registry.register_crypto(Box::new(KtlsProvider));
registry.register_crypto(Box::new(DtlsProvider));
registry.register_crypto(Box::new(WireguardProvider));
registry.register_crypto(Box::new(RoutingProvider));
// registry.register_crypto(Box::new(MyProvider));   // ← add here
let registry = registry.into_arc();
```

Selected per rule by `registry.find_crypto(&ctx.security_provider)`, then
dispatched to `run_encrypt`/`run_decrypt` by `direction`.

```json
{ "name": "r1", "direction": "encrypt", "listen_addr": "0.0.0.0:8080",
  "upstream_addr": "backend:443", "security_provider": "my-engine" }
```

## Conformance checklist

- [ ] `name()` is unique, stable, lowercase, and documented.
- [ ] `supported_modes()` lists exactly the served `(Direction, Proto)` pairs.
- [ ] `run_encrypt`/`run_decrypt` block until `ctx.shutdown` and then return `Ok(())`.
- [ ] Fatal setup errors return `Err(String)`; the engine fails closed.
- [ ] Per-connection work is dispatched on `ctx.conn_pool` (connection-oriented modes).
- [ ] `ctx.classify_and_check_policy` is consulted before forwarding new flows.
- [ ] Metrics are updated via `ctx.metrics` (see [04](04-telemetry-diagnostics.md)).
- [ ] Key/cert material is obtained via injection, not a global (see [05](05-cert-key-management.md)).
- [ ] Type is `Send + Sync`.
