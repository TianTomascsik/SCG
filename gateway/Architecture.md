# Gateway Provider Architecture

> Companion document for `provider_architecture.drawio` — read both together.

---

## Overview

The gateway uses a **provider architecture** to decouple *what* security is applied from *how* it is applied. Every connection rule in `gateway.json` names a **security provider** (and optionally an **app protocol**); at startup the gateway looks up the matching provider objects and delegates the entire encrypt/decrypt loop to them.

This makes it possible to add new security schemes (or new application-level framings) without touching the dispatch logic or any other provider.

```
gateway.json ──load & validate──▶ main.rs ──register──▶ ProviderRegistry
                                                             │
                                               into_arc() (freeze)
                                                             │
                                                    Arc<ProviderRegistry>
                                                     (shared read-only)
                                                             │
                                             ┌───────────────┴───────────────┐
                                             ▼                               ▼
                                   crypto: Vec<Box<dyn          app_protocols: Vec<Box<dyn
                                     CryptoProvider>>             AppProtocolProvider>>
```

---

## Diagram Walkthrough

The drawio has six visual layers, top to bottom. Each section below matches one layer.

### 1. Config (top — yellow note)

The file `gateway.json` declares rules. Three fields drive provider selection:

| Field | Example | Purpose |
|---|---|---|
| `security_provider` | `"tls"`, `"ktls"`, `"dtls"` | Selects the CryptoProvider |
| `app_protocol` | `"ale"`, `"raw"`, or omitted | Selects the AppProtocolProvider (UDP-over-TLS only) |
| `direction` | `"encrypt"` / `"decrypt"` | Determines which provider method is called |

### 2. main.rs — Startup & Registration (blue box)

`main.rs` builds a `ProviderRegistry`, registers every built-in provider, then freezes it:

```rust
let mut registry = ProviderRegistry::new();

// Crypto providers
registry.register_crypto(Box::new(TlsProvider));
registry.register_crypto(Box::new(KtlsProvider));
registry.register_crypto(Box::new(DtlsProvider));

// App protocol providers
registry.register_app_protocol(Box::new(AleProtocolProvider));
registry.register_app_protocol(Box::new(RawProtocolProvider));

let registry = registry.into_arc();   // Arc<ProviderRegistry>, immutable from here on
```

After `into_arc()` the registry is **frozen** — no more registrations. Every rule thread receives a clone of the same `Arc`, so lookups are lock-free.

### 3. ProviderRegistry (grey dashed box)

The registry holds two `Vec`s:

```
crypto:         Vec<Box<dyn CryptoProvider>>       ← 3 built-in entries
app_protocols:  Vec<Box<dyn AppProtocolProvider>>   ← 2 built-in entries
```

Lookup is by name: `registry.find_crypto("tls")` iterates the `Vec` and returns the first entry whose `name()` matches. The Vec is tiny (3-5 entries) so linear scan is fine.

#### 3a. CryptoProvider implementations (green boxes)

| Struct | `name()` | Protocol | Modes |
|---|---|---|---|
| `TlsProvider` | `"tls"` | OpenSSL userspace TLS | TCP + UDP-over-TLS (encrypt & decrypt) |
| `KtlsProvider` | `"ktls"` | Kernel TLS offload | TCP + UDP-over-TLS (encrypt & decrypt) |
| `DtlsProvider` | `"dtls"` | Datagram TLS | UDP only (encrypt & decrypt) |

**TLS and kTLS share the same engine code.** Both call the same `tls_engine::encrypt` / `tls_engine::decrypt` functions. The kTLS path branches internally on `ctx.tls_mode` to offload symmetric crypto to the kernel.

**DTLS is UDP-only.** It guards on `ctx.listen_proto == Proto::Udp` and returns an error if given TCP.

#### 3b. AppProtocolProvider implementations (purple boxes)

| Struct | `name()` | Framing | Handshake |
|---|---|---|---|
| `AleProtocolProvider` | `"ale"` | ALEPKT frames (DT/DI) | AU1/AU2 EuroRadio handshake |
| `RawProtocolProvider` | `"raw"` | 4-byte LE length prefix | None |

App protocol providers are only used by the **UDP-over-TLS tunnel** (when a UDP application talks through a TLS TCP tunnel). They solve the problem of multiplexing discrete datagrams over a byte stream.

### 4. Trait Definitions (red document shapes, left sidebar)

#### `trait CryptoProvider`

```rust
pub trait CryptoProvider: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn supported_modes(&self) -> Vec<ProviderMode>;
    fn run_encrypt(&self, ctx: RuleContext) -> Result<()>;  // blocks until shutdown
    fn run_decrypt(&self, ctx: RuleContext) -> Result<()>;  // blocks until shutdown
}
```

`run_encrypt` / `run_decrypt` are **blocking** — they own the thread for the lifetime of the rule. Each opens a listener, accepts connections (TCP) or binds a socket (UDP), and relays traffic in a loop until the shutdown flag is set.

#### `trait AppProtocolProvider`

```rust
pub trait AppProtocolProvider: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn create_session(&self) -> Box<dyn FramingSession>;
}
```

`create_session()` is a **factory** — it returns a fresh, stateful session object for each new connection/tunnel.

#### `trait FramingSession`

```rust
pub trait FramingSession: Send {
    fn handshake_initiator(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()>;
    fn handshake_responder(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()>;
    fn frame_datagram(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()>;
    fn deframe(&mut self, data: &[u8]) -> io::Result<DeframeResult>;
    fn write_disconnect(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()>;
}
```

A `FramingSession` has a lifecycle: **handshake** (once per connection) **frame/deframe** (per datagram) **disconnect** (once at end). The TLS engine calls these methods at the right time — the session itself doesn't know about TLS.

### 5. Dispatch — `processing/mod.rs` (yellow dashed box)

This is the **central switchboard**. For each rule in the config, `start_single_rule()` runs on a dedicated thread and performs three steps:

```
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────────┐
│ 1. Build         │        │ 2. find_crypto() │        │ 3. Dispatch          │
│    RuleContext   │───────>│    by name       │───────>│    encrypt/decrypt   │
│    from config + │        │                  │        │    (blocks forever)  │
│    pipeline      │        │                  │        │                      │
└──────────────────┘        └──────────────────┘        └──────────────────────┘
```

**Step 1 — Build `RuleContext`:** Packs everything a provider needs into one struct: listen/upstream addresses, protocols, TLS settings, the app protocol name, metrics, shutdown flag, traffic class, policy manager reference, etc.

**Step 2 — find_crypto():** Looks up `registry.find_crypto(ctx.security_provider)` to get a `&dyn CryptoProvider`.

**Step 3 — Dispatch:** Calls `provider.run_encrypt(ctx)` or `provider.run_decrypt(ctx)` based on the rule's `direction`. This call **blocks until shutdown** — the thread is owned by the provider from this point on.

### 6. Security Engines (blue boxes, bottom)

Each provider delegates to an engine module that contains the actual network I/O loop:

| Engine Module | Functions | Used By |
|---|---|---|
| `tls_engine/encrypt` | `run_tcp_encrypt_listener`, `run_udp_encrypt_relay` | TLS + kTLS |
| `tls_engine/decrypt` | `run_tcp_decrypt_listener`, `run_udp_decrypt_relay` | TLS + kTLS |
| `dtls_engine` | `run_dtls_encrypt_relay`, `run_dtls_decrypt_relay` | DTLS |

The TLS engine's UDP-over-TLS path (`run_udp_encrypt_relay`) calls into the **FramingSession** (bottom-right purple box) to frame/deframe datagrams inside the TCP+TLS byte stream.

### 7. Network I/O (parallelogram shapes, very bottom)

```
Inbound Traffic          Security Engines          Outbound Traffic
(TCP/UDP listeners) ───▶ (encrypt/decrypt) ───▶ (TLS/kTLS/DTLS)
```

Encrypt direction: plaintext in → ciphertext out.
Decrypt direction: ciphertext in → plaintext out.

---

## Thread Model

Each rule gets **one dedicated thread**. The provider's `run_encrypt` or `run_decrypt` method owns that thread and blocks on I/O until the global shutdown flag is set.

For TCP providers, the listening thread spawns **sub-threads per connection** (one for each accepted TCP client).

```
main thread
 ├── rule "safety-encrypt"   → TlsProvider.run_encrypt()  → accept loop → per-connection threads
 ├── rule "normal-decrypt"   → TlsProvider.run_decrypt()  → accept loop → per-connection threads
 └── rule "dtls-encrypt"     → DtlsProvider.run_encrypt() → single relay loop (UDP, no accept)
```

---

## How UDP-over-TLS Works

When a rule has `listen_proto: "udp"` but `security_provider: "tls"`, the TLS provider tunnels UDP datagrams through a TCP+TLS connection. The `app_protocol` field selects how datagrams are framed:

```
UDP app ──datagrams──▶ [encrypt gateway]
                          │
                          ├── FramingSession::handshake_initiator()
                          │
                          ├── recv UDP datagram
                          ├── FramingSession::frame_datagram()  → [header][payload]
                          ├── write framed bytes into TLS stream
                          │       ... repeat ...
                          │
                          └── FramingSession::write_disconnect()
                                    │
                                 TCP+TLS tunnel
                                    │
                       [decrypt gateway]
                          ├── FramingSession::handshake_responder()
                          ├── read from TLS stream
                          ├── FramingSession::deframe()  → Vec<datagram>
                          ├── forward each datagram as UDP to upstream
                          │       ... repeat ...
                          └── (peer disconnect detected via DeframeResult.disconnected)
```

### ALE Framing (`"ale"`)

Used for ETCS railway signaling (UNISIG Subset-037/098):
- **Handshake:** Initiator sends AU1 (calling ETCS-ID, class-of-service), responder replies with AU2 (responding ETCS-ID). Poll-based with ~5 second timeout.
- **Data:** Each datagram wrapped in an ALEPKT DT frame (with CRC).
- **Disconnect:** ALEPKT DI frame sent before closing.

### Raw Framing (`"raw"`)

Minimal overhead for generic UDP tunneling:
- **Handshake:** None.
- **Data:** `[4 bytes LE length][payload]` — simple length-prefix.
- **Disconnect:** None (connection close = disconnect).

---

## Adding a New Provider

### New CryptoProvider (3 steps)

1. Create `gateway/src/security/providers/my_provider.rs` implementing `CryptoProvider`
2. Add `pub mod my_provider;` to `gateway/src/security/providers/mod.rs`
3. Register in `main.rs`: `registry.register_crypto(Box::new(MyProvider))`

Then use `"security_provider": "my_name"` in config.

### New AppProtocolProvider (4 steps)

1. Create `gateway/src/app_protocols/my_protocol.rs` implementing `AppProtocolProvider`
2. Implement `FramingSession` for the per-connection session struct
3. Add `pub mod my_protocol;` to `gateway/src/app_protocols/mod.rs`
4. Register in `main.rs`: `registry.register_app_protocol(Box::new(MyProtocol))`

Then use `"app_protocol": "my_name"` in config.

---

## Diagram Color Legend

| Color | Meaning |
|---|---|
| Green | CryptoProvider implementations |
| Purple | AppProtocolProvider implementations & FramingSession |
| Blue | Security engine modules (the actual I/O code) |
| Yellow | Config & dispatch logic |
| Red (doc shape) | Trait definitions |
| Dashed arrow | "Delegates to" relationship |
