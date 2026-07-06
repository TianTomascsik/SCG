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
| `security_provider` | `"tls"`, `"ktls"`, `"dtls"`, `"wireguard"`, `"routing"` | Selects the CryptoProvider |
| `app_protocol` | `"ale"`, `"raw"`, or omitted | Selects the AppProtocolProvider (UDP-over-TLS only) |
| `direction` | `"encrypt"` / `"decrypt"` | Determines which provider method is called |

### 2. lib.rs::run — Startup & Registration (blue box)

`lib.rs::run` (the composition root — *not* `main.rs`, which is a thin wrapper) builds a `ProviderRegistry`, registers every built-in provider, then freezes it:

```rust
let mut registry = ProviderRegistry::new();

// Crypto providers
registry.register_crypto(Box::new(TlsProvider));
registry.register_crypto(Box::new(KtlsProvider));
registry.register_crypto(Box::new(DtlsProvider));
registry.register_crypto(Box::new(WireguardProvider));
registry.register_crypto(Box::new(RoutingProvider));

// App protocol providers
registry.register_app_protocol(Box::new(AleProtocolProvider));
registry.register_app_protocol(Box::new(RawProtocolProvider));

let registry = registry.into_arc();   // Arc<ProviderRegistry>, immutable from here on
```

After `into_arc()` the registry is **frozen** — no more registrations. Every rule thread receives a clone of the same `Arc`, so lookups are lock-free.

### 3. ProviderRegistry (grey dashed box)

The registry holds two `Vec`s:

```
crypto:         Vec<Box<dyn CryptoProvider>>       ← 5 built-in entries
app_protocols:  Vec<Box<dyn AppProtocolProvider>>   ← 2 built-in entries
```

Lookup is by name: `registry.find_crypto("tls")` iterates the `Vec` and returns the first entry whose `name()` matches. The Vec is tiny (5 crypto / 2 app-protocol) so linear scan is fine.

#### 3a. CryptoProvider implementations (green boxes)

| Struct | `name()` | Protocol | Modes |
|---|---|---|---|
| `TlsProvider` | `"tls"` | OpenSSL userspace TLS | TCP + UDP-over-TLS (encrypt & decrypt) |
| `KtlsProvider` | `"ktls"` | Kernel TLS offload | TCP + UDP-over-TLS (encrypt & decrypt) |
| `DtlsProvider` | `"dtls"` | Datagram TLS | UDP only (encrypt & decrypt) |
| `WireguardProvider` | `"wireguard"` | Kernel WireGuard offload | UDP only (encrypt & decrypt) |
| `RoutingProvider` | `"routing"` | Plaintext L4 passthrough | TCP + UDP (encrypt & decrypt) |

**TLS and kTLS share the same engine code.** Both call the same `tls_engine::encrypt` / `tls_engine::decrypt` functions. The kTLS path branches internally on `ctx.tls_mode` to offload symmetric crypto to the kernel.

**DTLS is UDP-only.** It guards on `ctx.listen_proto == Proto::Udp` and returns an error if given TCP.

**Routing is a plaintext L4 passthrough (no crypto).** It relays both **TCP** (`run_tcp_routing_listener`) and **multi-client UDP** (`run_udp_routing_listener`, with per-peer demux and session eviction in `security/udp_session.rs`); `supported_modes()` returns `{Tcp, Udp} × {Encrypt, Decrypt}`. Admission is enforced by the policy gate rather than a handshake.

**WireGuard is a kernel offload, like kTLS — but at the interface, not the socket.** The provider performs *no* userspace cryptography. At rule startup it provisions an in-kernel `wireguard` interface via the `wg` + `ip` tools (`wireguard_engine::admin`), then runs a plain UDP relay (`wireguard_engine`) that steers datagrams through the tunnel; the kernel performs the Noise_IKpsk2 handshake and ChaCha20-Poly1305 transport. It is UDP-only and requires `CAP_NET_ADMIN`, the `wireguard` module, and `wg`. WireGuard keys and tunnel parameters are read from `provider_params` (`private_key`, `peer_public_key`, `wg_listen_port`, `peer_endpoint`, `tunnel_local_ip`, `peer_allowed_ips`, optional `preshared_key` / `persistent_keepalive`, and `manage_interface` to attach to an externally-provisioned interface instead of creating one). Private keys are passed to `wg` via `0600` files, never on the command line, and are zeroized after use.

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
    fn run_encrypt(&self, ctx: &RuleContext) -> Result<(), String>;  // blocks until shutdown
    fn run_decrypt(&self, ctx: &RuleContext) -> Result<(), String>;  // blocks until shutdown
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

**Step 3 — Dispatch:** Calls `provider.run_encrypt(&ctx)` or `provider.run_decrypt(&ctx)` based on the rule's `direction`. This call **blocks until shutdown** — the thread is owned by the provider from this point on.

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

---

## Local Interfaces (UDS & SHM) and the Management API

In addition to the network listeners (TCP/UDP/TPROXY), the gateway exposes
**local interfaces** so co-located application processes can hand traffic to the
gateway over a Unix domain socket (UDS) or shared memory (SHM) instead of the
loopback network. Local endpoints are **provisioned on demand, per application
and per traffic class** (safety vs. normal) through the gRPC **management API**.

### Components

| Module | Role |
|---|---|
| [crates/scg-ipc](../crates/scg-ipc) | Dependency-light IPC primitives: framing (`[len][traffic_id][data]`), 256-bit capability tokens (constant-time `ct_eq`), HELLO handshake, two-ring SHM layout + seals, eventfd/futex notify, `SO_PEERCRED`/memfd/`SCM_RIGHTS` OS helpers. |
| [crates/scg-proto](../crates/scg-proto) | tonic/prost `scg.management.v1.ManagementApi` service stubs. |
| [src/api/grpc.rs](src/api/grpc.rs) | gRPC server on a **dedicated thread**, off the data path. Default transport is **gRPC-over-UDS** (`SO_PEERCRED`-authenticated caller identity, no network port); optional TCP for remote admin. |
| [src/interfaces/manager.rs](src/interfaces/manager.rs) | `InterfaceManager`: owns rule **templates**, the live-endpoint registry, token issuance, authorization, per-uid quota + rate limiting, and create-or-replace lifecycle. |
| [src/interfaces/uds.rs](src/interfaces/uds.rs) | UDS data endpoint: a transparent byte pipe between the client socket and the TLS upstream leg. |
| [src/interfaces/shm.rs](src/interfaces/shm.rs) | SHM data endpoint: a control socket that authenticates the client and passes memfd + eventfd descriptors via `SCM_RIGHTS`. |
| [crates/scg-client](../crates/scg-client) | One Rust client engine exposed to **Rust, C (cbindgen ABI), and C++ (header-only)**. |

### Provisioning flow

```
app ──gRPC/UDS──▶ ManagementApi.CreateUdsEndpoint(app_id, class, direction)
                        │  (SO_PEERCRED → CallerCred{uid,gid,pid})
                        ▼
                InterfaceManager: look up the matching uds/shm rule template,
                  authorize (uid ∈ allowed_uids ∧ optional pid ∈ allowed_pids),
                  enforce per-uid quota + create rate-limit,
                  mint a single-use 256-bit token, spawn the endpoint thread
                        │
                        ▼
        reply { socket_path | control_socket_path, token, endpoint_id }
                        │
   app connects to the endpoint and sends HELLO[token] as the first data-plane frame
                        │  authenticate_peer: SO_PEERCRED re-check (uid == owner_uid),
                        ▼  constant-time token compare, consume under lock (single-use)
                  gateway relays:  client ⇄ (UDS pipe | SHM rings) ⇄ TLS upstream
```

- **UDS** carries the gateway's TLS byte stream transparently (frames pass
  through untouched).
- **SHM** uses **two unidirectional rings** (client→gateway and gateway→client).
  The gateway-to-client ring is **sealed** (`F_SEAL_WRITE`) so the client maps it
  read-only and cannot tamper with it. Wakeups default to **eventfd** because the
  single-threaded relay must multiplex the upstream fd and the ring notification
  through one `poll`/`epoll`; see the [SHM wakeup benchmark](../../SCG-Interface-benchmarks/bench_shm)
  (`wakeup_bench`) for the data behind that choice (busy-poll / hybrid-futex remain
  available as a dedicated-core low-latency knob).

### Security layers

1. **Transport identity** — gRPC-over-UDS yields a kernel-verified
   `SO_PEERCRED`; the data-plane connection is re-checked the same way at the
   instant of connect.
2. **Authorization** — `allowed_uids` (and optional `allowed_pids`) come from the
   rule; the connecting uid must match **and** equal the endpoint owner.
3. **Capability token** — single-use, 256-bit, presented in the first HELLO
   frame, compared in constant time, and consumed under a lock so a race cannot
   reuse it. Tokens are masked (`***`) in all log/Debug output.
4. **Filesystem** — per-uid runtime directory `0700` (privileged:
   `/run/scg/<uid>` chowned to the caller; unprivileged fallback
   `/run/user/<uid>/scg`); endpoint sockets `0600`.
5. **Memory** — memfds created `MFD_CLOEXEC | MFD_ALLOW_SEALING` and sealed; the
   client-readable ring additionally `F_SEAL_WRITE`.
6. **Resource safety** — per-uid **live-endpoint quota**
   (`api.max_endpoints_per_uid`) and per-uid **create-request rate limit**
   (`api.create_rate_per_min`); atomic create-or-replace tears down the previous
   endpoint with no fd/mapping leak.
7. **Audit** — every denial logs one greppable line
   (`AUDIT deny op=… uid=… pid=… app_id=…: reason`).

### Configuration

A local interface is declared as a normal rule with `listen_proto` `"uds"` or
`"shm"`, an `app_id`, a `traffic_class`, and an `allowed_uids` list; the `api`
block tunes the management transport and the resource guards. See
[09 — Configuration](docs/interfaces/09-configuration.md) and
[10 — Management API](docs/interfaces/10-management-api.md), and
[gateway.example.json](gateway.example.json) for a complete example.

---

## Deployment Hardening (optional)

The defaults above are self-contained and need no external tooling. For
defense-in-depth in production, the following **optional** OS-level measures
compose well with the gateway and are recommended but not required:

- **Mount/PID/user namespaces** — run the gateway and each app group in their own
  namespaces so the per-uid `/run/scg/<uid>` runtime directory and the endpoint
  sockets are only visible to intended processes.
- **SELinux / AppArmor** — confine the gateway and client processes with a policy
  that restricts which uids may `connect()` the management/endpoint sockets and
  which paths are reachable, backstopping the in-process `SO_PEERCRED` checks.
- **seccomp-bpf** — restrict the gateway's syscall surface (e.g. deny `ptrace`,
  unexpected `socket` families) once the steady-state syscall set is profiled.
- **pidfd pinning (future)** — `scg_ipc::os::pidfd_open` is available to pin the
  caller's process identity across the gRPC→data-plane hop. v1 relies on a fresh
  `SO_PEERCRED` check at each connect plus the single-use token, which already
  closes the PID-reuse window; pidfd pinning is documented here as an available
  enhancement rather than a requirement.
- **systemd sandboxing** — `DynamicUser=`, `ProtectSystem=strict`,
  `RuntimeDirectory=scg`, `RestrictAddressFamilies=AF_UNIX AF_INET`, and
  `NoNewPrivileges=yes` give most of the above with minimal configuration.
