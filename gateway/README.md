# Gateway — Transparent Encryption Proxy with Extensible Provider Architecture

A high-performance transparent proxy that encrypts or decrypts network traffic
without requiring any changes to the applications behind it. Uses a pluggable
provider architecture for security engines and application-level protocols.

## Overview

```
Application A                          Application B
     | plain TCP/UDP                       ^ plain TCP/UDP
     v                                     |
+----------+                         +----------+
| Gateway  | -- TLS/kTLS/DTLS/etc -- | Gateway  |
| (encrypt)|     encrypted tunnel    | (decrypt)|
+----------+                         +----------+
```

**Applications are completely unaware** they communicate over an encrypted
channel. The gateway intercepts traffic at the network layer, encrypts it, and
the receiving gateway decrypts it before delivering to the destination
application.

## Features

| Feature | Description |
|---|---|
| **TLS (userspace)** | OpenSSL-based TLS for TCP streams |
| **kTLS (kernel)** | Kernel TLS offload -- higher throughput, lower CPU |
| **DTLS** | Native UDP encryption -- preserves datagram semantics |
| **WireGuard (kernel)** | Kernel WireGuard offload -- provisions a `wg` interface; UDP only (needs `CAP_NET_ADMIN`) |
| **ALE framing** | ALEPKT framing per Subset-098/037 for UDP-over-TLS (EuroRadio) |
| **Raw framing** | Simple length-prefix framing for UDP-over-TLS without ALE overhead |
| **TPROXY** | Transparent proxy via `IP_TRANSPARENT` + `SO_ORIGINAL_DST` |
| **Hot-reload** | SIGHUP or file watch -- add/remove rules without restart |
| **Provider architecture** | Add custom security or protocol providers by implementing a trait |

## Quick Start

```bash
# Build (production: accepts only the signed --config-dir configuration)
cargo build --release --bin gateway

# Build for development (also accepts the unsigned single-file --config)
cargo build --release --bin gateway --features dev

# Run with a signed, layered configuration directory (production)
sudo ./target/release/gateway --config-dir /etc/scg/config

# Run with a single-file config (requires a --features dev build)
sudo ./target/release/gateway --config gateway/gateway.example.json

# Enable hot-reload polling
sudo ./target/release/gateway --config-dir /etc/scg/config --watch

# Validate a configuration without starting
sudo ./target/release/gateway --config-dir /etc/scg/config --validate
```

> **Config integrity.** The unsigned single-file `--config <FILE>` loader is a
> development-only build feature (`--features dev`). A default (production) build
> accepts only the signed, layered `--config-dir` (Ed25519-signed
> `scg.defaults.json` + `scg.user.json` with a pinned schema hash, verified
> fail-closed). See SCG-TRA finding #87.

### CLI Options

| Flag | Description |
|---|---|
| `--config-dir DIR` | Signed, layered config directory **(required in production builds)** |
| `--config-pubkey PATH` | Ed25519 trust anchor for `--config-dir` (defaults to `DIR/trust/config-signing.pub.pem`) |
| `--config PATH` | Single-file JSON config (**`--features dev` builds only**) |
| `--validate` | Validate config and check environment, then exit |
| `--log-level LVL` | Set log level: error, warn, info, debug, trace (default: info) |
| `--watch` | Enable config file polling every 2 seconds |
| `--log-stdout` | Copy log output to stdout (for journald/containers) |
| `--help` | Print usage information |

## Configuration

The gateway is configured via a JSON file. See
[`gateway.example.json`](gateway.example.json) for a full annotated example.

### Global Settings

```json
{
  "log_level": "info",
  "sock_buf_size": 16777216
}
```

### Rules

Each entry in the `"rules"` array defines a forwarding rule:

```json
{
  "name": "web-encrypt-tls",
  "direction": "encrypt",
  "listen_addr": "0.0.0.0:8080",
  "listen_proto": "tcp",
  "upstream_addr": "backend:443",
  "security_provider": "tls",
  "priority": 0,
  "transparent": false
}
```

| Field | Required | Default | Description |
|---|---|---|---|
| `name` | Yes | -- | Unique name (used in logs and hot-reload) |
| `direction` | Yes | -- | `"encrypt"` (plain->encrypted) or `"decrypt"` (encrypted->plain) |
| `listen_addr` | Yes | -- | Address to listen on (e.g., `"0.0.0.0:8080"`) |
| `listen_proto` | No | `"tcp"` | `"tcp"` or `"udp"` |
| `upstream_addr` | No | `"auto"` | Destination address or `"auto"` for TPROXY |
| `upstream_proto` | No | `"tcp"` | Upstream protocol (decrypt direction) |
| `security_provider` | No | `"tls"` | Security engine: `"tls"`, `"ktls"`, `"dtls"`, `"wireguard"`, `"routing"` (plus any custom provider registered at startup) |
| `app_protocol` | No | `"ale"` | App protocol for UDP-over-TLS: `"ale"`, `"raw"` |
| `priority` | No | `0` | Process nice value (0 = normal) |
| `transparent` | No | `false` | Enable TPROXY transparent mode |
| `simulated_delay_ms` | No | `0` | Simulated network delay (ms) before each upstream send — for geo-location / WAN latency simulation |
| `protocol_version` | No | `null` | Protocol version: `"tls1.2"`, `"tls1.3"`, `"dtls1.0"`, `"dtls1.2"` |

### Security Providers

#### `tls` -- Userspace TLS (OpenSSL)

Works with both TCP and UDP. For UDP, datagrams are encapsulated using the configured `app_protocol` and tunneled over a single TCP+TLS connection.

```json
{ "security_provider": "tls" }
```

#### `ktls` -- Kernel TLS Offload

Offloads TLS record encryption/decryption to the Linux kernel. Higher throughput and lower CPU usage. **TCP and UDP-over-TLS.**

```json
{ "security_provider": "ktls" }
```

Requirements:
- Linux kernel >= 4.13 with `CONFIG_TLS=y`
- `CAP_NET_ADMIN` capability (or run as root)
- `modprobe tls` if the TLS ULP module isn't auto-loaded

#### `dtls` -- DTLS (Datagram TLS)

Native encryption for UDP datagrams. Preserves datagram boundary semantics. **UDP only.**

```json
{
  "security_provider": "dtls",
  "listen_proto": "udp"
}
```

#### `wireguard` -- Kernel WireGuard offload

Offloads the WireGuard data plane (Noise_IKpsk2 handshake + ChaCha20-Poly1305
transport) to the in-kernel `wireguard` module, the way `ktls` offloads TLS. At
rule startup the provider provisions a `wg` interface (via `wg` + `ip`) and then
relays plaintext UDP through the tunnel; the kernel does all cryptography.
**UDP only.** Models a single gateway-to-gateway flow.

```json
{
  "security_provider": "wireguard",
  "listen_proto": "udp",
  "upstream_addr": "10.0.0.2:7000",
  "wg_interface": "wg-scg0",
  "wg_listen_port": 51820,
  "private_key": "<base64 X25519 private key>",
  "peer_public_key": "<base64 X25519 public key>",
  "peer_endpoint": "peer-gateway.example:51821",
  "tunnel_local_ip": "10.0.0.1/32",
  "peer_allowed_ips": "10.0.0.2/32",
  "persistent_keepalive": 25
}
```

`provider_params`:

| Field | Required | Meaning |
|---|---|---|
| `wg_interface` | yes | kernel interface name to manage (e.g. `wg-scg0`) |
| `private_key` | yes | this gateway's X25519 private key (base64) |
| `wg_listen_port` | yes | UDP port the kernel WireGuard interface listens on |
| `peer_public_key` | yes | peer gateway's X25519 public key (base64) |
| `peer_endpoint` | yes | peer gateway's WireGuard endpoint (`host:port`) |
| `tunnel_local_ip` | yes | this interface's tunnel address (CIDR), e.g. `10.0.0.1/32` |
| `peer_allowed_ips` | yes | allowed-IPs / route for the peer, e.g. `10.0.0.2/32` |
| `preshared_key` | no | optional Noise_IKpsk2 preshared key (base64) |
| `persistent_keepalive` | no | keepalive interval in seconds |
| `manage_interface` | no (default `true`) | `false` attaches to an externally-provisioned interface instead of creating/destroying it |

Requirements:
- the `wireguard` kernel module (`modprobe wireguard`)
- `wireguard-tools` (`wg`) and `iproute2` (`ip`)
- `CAP_NET_ADMIN` (or run as root)

Private keys are written to `0600` files for `wg` to read (never passed on the
command line, where `/proc/<pid>/cmdline` would expose them) and zeroized after
use. Keys are never logged or `Debug`-printed.

### Security posture (verification, policy, DoS limits)

**Peer verification / mTLS.** The `tls`/`ktls`/`dtls` providers take a `verify`
mode in `provider_params`: `none` (legacy, no verification), `server` (verify the
upstream certificate against `ca_path`), or `mutual` (mTLS — both sides present
X.509). The `default` and `subset146-psk` profiles require `verify` to be set
explicitly (fail-secure); `subset146-pki` implies `mutual`. An encrypt rule that
contacts a **non-loopback** upstream with `verify: none` (MITM exposure), or a
decrypt listener on a **non-loopback** bind that uses a non-`mutual` mode (it
relays traffic from unauthenticated clients), is a **preflight error** — it fails
`--validate` and is logged loudly at startup. Set `verify: server` (or `mutual`)
with a `ca_path` for remote upstreams (see the `web-encrypt-tls-verified` rule in
`gateway.example.json`), or, to deliberately accept an unverified posture, set the
top-level `"allow_unverified_transport": true` opt-in, which downgrades these
errors back to warnings. Loopback and local UDS/SHM endpoints stay warnings
regardless. See *Authenticated upstream identity (TB2)* in
[docs/interfaces/05-cert-key-management.md](docs/interfaces/05-cert-key-management.md)
for which name is actually authenticated. `ktls` rules keep the
zero-copy kernel offload **even with `verify: server`/`mutual`**: verification
runs on the kTLS context exactly as on the userspace path and completes during
the handshake before kTLS activates, so the secure path is also the fast path.
Only a non-`Default` profile (`subset146-pki`/`-psk`, non-GCM/PSK cipher policy)
falls back to userspace TLS. The relay still gates the splice on *runtime* kTLS
activation, falling back to the userspace SSL relay if kTLS does not engage, so a
silent offload failure never relays cleartext (TRA #56).

**Safety traffic and policy (`enforce_policy_on_safety`).** By design,
`safety`-classified traffic bypasses the policy whitelist / default-deny so a
policy misconfiguration can never silence safety-critical signalling
(fail-open for availability). High-security deployments can set
`policy.enforce_policy_on_safety: true` to also subject safety traffic to the
whitelist. Because classification is driven by configured `traffic_rules`
(source/destination), bind a `safety` traffic-rule only to **trusted,
non-spoofable** sources — a wide/non-loopback `safety` source is flagged at
`--validate`, since it lets a spoofed source obtain the bypass.

**DTLS DoS limits.** A DTLS encrypt relay bounds concurrent peer sessions with
`max_sessions` (default 1024) and reclaims idle ones after `idle_ttl_secs`
(default 60), resisting source-address-spoofing floods. DTLS decrypt listeners
perform a stateless HelloVerifyRequest **cookie** exchange (bound to the peer
address) before the expensive handshake, and bound the per-peer handshake wait.

### App Protocols (for UDP-over-TLS)

When using `tls` or `ktls` security providers with UDP listen, an app-level protocol frames the UDP datagrams over the TLS stream:

- **`ale`** (default): ALEPKT framing per UNISIG Subset-098/037 with AU1/AU2 handshake and CRC-CCITT
- **`raw`**: Simple 4-byte length-prefix framing, no handshake

```json
{
  "security_provider": "tls",
  "listen_proto": "udp",
  "app_protocol": "ale"
}
```

### TPROXY Transparent Mode

In transparent mode, the gateway uses Linux TPROXY to intercept traffic
without the source application knowing:

```json
{
  "transparent": true,
  "upstream_addr": "auto"
}
```

Required iptables setup:

```bash
# Mark packets destined for specific ports
iptables -t mangle -A PREROUTING -p tcp --dport 443 \
    -j TPROXY --tproxy-mark 0x1/0x1 --on-port 3128

# Route marked packets to local
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

Required capabilities: `CAP_NET_ADMIN`, `CAP_NET_RAW`

### Geo-Location Delay Simulation

Simulates geographic distance by adding a configurable delay before each
upstream send. Useful for testing application behavior over WAN links
without an actual WAN.

```json
{
  "name": "encrypt-with-delay",
  "direction": "encrypt",
  "listen_addr": "0.0.0.0:8080",
  "listen_proto": "tcp",
  "upstream_addr": "remote:443",
  "security_provider": "tls",
  "simulated_delay_ms": 50
}
```

The delay is applied per packet/datagram in the forward direction. To
simulate symmetric WAN latency (e.g., 100 ms RTT), configure half the
desired RTT on each gateway (50 ms on encrypt, 50 ms on decrypt).

Works with all security providers: TLS, kTLS, and DTLS.

## Protocol Versions

Each rule can specify the TLS/DTLS protocol version. When not set, defaults
to TLS 1.2 (for `tls`/`ktls`) or DTLS 1.2 (for `dtls`).

### TLS 1.2 / 1.3

```json
{
  "name": "encrypt-tls13",
  "direction": "encrypt",
  "listen_addr": "0.0.0.0:8080",
  "listen_proto": "tcp",
  "upstream_addr": "remote:443",
  "security_provider": "tls",
  "protocol_version": "tls1.3"
}
```

### DTLS 1.0 / 1.2

```json
{
  "name": "sensor-encrypt-dtls10",
  "direction": "encrypt",
  "listen_addr": "0.0.0.0:6000",
  "listen_proto": "udp",
  "upstream_addr": "collector:6000",
  "security_provider": "dtls",
  "protocol_version": "dtls1.0"
}
```

### Notes

- **kTLS + TLS 1.3**: Not reliably supported by all Linux kernels. The gateway
  will log a warning and fall back to TLS 1.2 at runtime.
- **DTLS 1.0**: Automatically uses CBC cipher suites (`AES128-SHA`, `AES256-SHA`)
  since GCM is not supported in DTLS 1.0.

## Logging

The gateway uses structured logging with five levels (from most to least verbose):

| Level | Description |
|---|---|
| `error` | Fatal errors, connection failures, I/O errors |
| `warn` | Non-fatal warnings, fallback paths, policy denials |
| `info` | Rule startup/shutdown, connection accepted, config summary (default) |
| `debug` | Per-connection details, handshake parameters, kTLS setup |
| `trace` | Per-packet relay details, buffer operations |

Configure via CLI flag or JSON config:

```bash
# CLI flag (overrides config file)
gateway --config-dir /etc/scg/config --log-level debug

# JSON config
{ "log_level": "debug" }
```

The `RUST_LOG` environment variable is also supported for fine-grained per-module control:

```bash
RUST_LOG=gateway::security=trace gateway --config-dir /etc/scg/config
```

### Data minimization & retention

The gateway sits on a signaling chokepoint, so its logs are themselves a
privacy/linkability surface (a train-movement metadata source). Operate them
accordingly (KC-07):

- **ETCS identifiers** (`calling`/`called` ETCS-IDs) are emitted **only at
  `debug`** and must stay debug-only; do not raise the ALE provider to `debug` in
  production unless you accept logging railway signaling identifiers.
- **`AUDIT` lines** carry caller `uid`/`pid`/`app_id` and peer addresses (endpoint
  create/close/deny and reload deltas). Treat them as operational,
  personal-adjacent data: rotate and retain per site policy (a ≤90-day default is
  a reasonable starting point), and restrict who may read them.
- **Secrets are never logged**: private keys, PSKs and capability tokens are
  masked in `Debug` (`***`) and zeroized on drop; the management-API version
  string is disclosed only to peer-authenticated (UDS) callers, not over the
  optional TCP bind.
- Consider hashing/truncating any identifiers you persist to long-term storage.

## Provider Architecture

The gateway uses a trait-based provider architecture that makes it easy to add new security engines and app-level protocols.

### Adding a Custom Security Provider

1. Create a struct implementing `CryptoProvider` (see `gateway/src/security/provider.rs`):

```rust
use gateway::security::provider::{CryptoProvider, ProviderMode};
use gateway::processing::RuleContext;

pub struct MyProvider;

impl CryptoProvider for MyProvider {
    fn name(&self) -> &str { "my-provider" }
    fn description(&self) -> &str { "My custom security provider" }
    fn supported_modes(&self) -> Vec<ProviderMode> { /* ... */ }
    fn run_encrypt(&self, ctx: &RuleContext) -> Result<(), String> { /* ... */ }
    fn run_decrypt(&self, ctx: &RuleContext) -> Result<(), String> { /* ... */ }
}
```

2. Pass it to the gateway at startup via the library entry point:

```rust
fn main() {
    // Registered alongside the built-in tls/ktls/dtls and ale/raw providers.
    gateway::run(vec![Box::new(MyProvider)], vec![]);
}
```

3. Use it in config:

```json
{ "security_provider": "my-provider" }
```

### Adding a Custom App Protocol

1. Implement `AppProtocolProvider` and `FramingSession` (see `gateway/src/app_protocols/provider.rs`)
2. Pass it to `gateway::run()` as the second argument (the extra app-protocol providers)
3. Use it in config: `"app_protocol": "my-protocol"`

### Built-in Providers

| Type | Name | Module |
|---|---|---|
| Crypto | `tls` | `security/providers/tls_provider.rs` |
| Crypto | `ktls` | `security/providers/ktls_provider.rs` |
| Crypto | `dtls` | `security/providers/dtls_provider.rs` |
| Crypto | `wireguard` | `security/providers/wireguard_provider.rs` |
| Crypto | `routing` | `security/providers/routing_provider.rs` |
| App Protocol | `ale` | `app_protocols/ale_provider.rs` |
| App Protocol | `raw` | `app_protocols/raw_provider.rs` |

## Systemd Deployment

> A ready-to-use unit file ships as `gateway/SecureCommunicationGateway.service`.
> For full deployment tooling (native, container, devcontainer) see the
> `deploy-methods` repository.

### Installation

```bash
# Build release binary
cargo build --release --bin gateway

# Install binary
sudo mkdir -p /opt/scg
sudo cp target/release/gateway /opt/scg/

# Install config
sudo mkdir -p /etc/scg
sudo cp gateway/gateway.example.json /etc/scg/gateway.json
# Edit /etc/scg/gateway.json for your environment

# Install systemd service
sudo cp gateway/SecureCommunicationGateway.service /etc/systemd/system/
sudo systemctl daemon-reload

# Create service user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin scg
sudo mkdir -p /var/log/scg
sudo chown scg:scg /var/log/scg
```

### Management

```bash
# Start/stop/restart
sudo systemctl start SecureCommunicationGateway
sudo systemctl stop SecureCommunicationGateway
sudo systemctl restart SecureCommunicationGateway

# Enable auto-start on boot
sudo systemctl enable SecureCommunicationGateway

# Hot-reload config (sends SIGHUP)
sudo systemctl reload SecureCommunicationGateway

# View status and logs
sudo systemctl status SecureCommunicationGateway
journalctl -u SecureCommunicationGateway -f
```

### Service Features

- Runs as `scg` user with ambient capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`, `CAP_SYS_NICE`)
- Auto-restart on crash (max 5 attempts per 60s)
- Security hardening: `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`
- `systemctl reload` triggers hot-reload via SIGHUP
- Logs captured by journald

### Host QoS

Safety traffic is isolated inside the gateway by class-specific endpoint
templates and elevated Safety workers. To make that priority visible to the
host egress queue, install the host qdisc policy on the interface that carries
gateway traffic:

```bash
sudo ./scripts/scg-host-qos.sh apply --dev eth0 --normal-rate 800mbit
sudo ./scripts/scg-host-qos.sh status --dev eth0
```

The helper maps Safety sockets (`SO_PRIORITY=6`) to the highest strict-priority
band and Normal sockets (`SO_PRIORITY=0`) below it. `--normal-rate` is optional,
but recommended when bulk traffic must be bounded so Safety capacity remains
reserved. Remove the policy with:

```bash
sudo ./scripts/scg-host-qos.sh clear --dev eth0
```

### Override Settings

Create `/etc/scg/environment`:

```bash
CONFIG=/etc/scg/my_custom.json
```

## Hot-Reload

The gateway supports live configuration changes **without interrupting existing connections**.

### SIGHUP (always available)

```bash
kill -HUP $(pidof gateway)
# or with systemd:
sudo systemctl reload SecureCommunicationGateway
```

### File Watch

With `--watch`, the config file is polled every 2 seconds:

```bash
gateway --config-dir /etc/scg/config --watch
```

### What happens on reload

1. The new config is parsed and validated
2. A diff is computed against the running config:
   - **Added rules**: Started immediately in new threads
   - **Removed rules**: Shutdown flag is set; the listener stops accepting new connections
   - **Unchanged rules**: Not affected -- existing connections continue

Rules are identified by `name`. To modify a rule, change its name (which removes the old rule and adds the new one).

## Validation and Preflight Checks

Use `--validate` to verify both the config file and the runtime environment:

```bash
gateway --config-dir /etc/scg/config --validate
```

| Check | Type | Description |
|---|---|---|
| JSON syntax | Error | Configuration file parses correctly |
| Rule consistency | Error | No duplicate names, no listen port conflicts, valid combinations |
| Log directory | Error | Directory exists (or can be created) and is writable |
| `CAP_NET_ADMIN` | Error | Required capability for transparent/TPROXY rules |
| `CAP_SYS_NICE` | Warning | Required for elevated Safety worker scheduling priority |
| iptables chains | Warning | Traffic interception chains exist |
| TPROXY routing | Warning | Routing policy is in place |
| kTLS module | Warning | Kernel TLS module loaded (when kTLS rules are configured) |
| Port availability | Warning | Listen ports are not already bound |

Exit codes: **0** = passed (may have warnings), **1** = failed (has errors).

## Architecture

### Module Structure

```
gateway/src/
  lib.rs                     -- Library entry point: run(extra_crypto, extra_app), provider registration, CLI
  main.rs                    -- Thin binary wrapper: calls gateway::run(...) with no extra providers
  processing/
    mod.rs                   -- Rule dispatch via provider registry
    registry.rs              -- ProviderRegistry (crypto + app protocol)
  security/
    provider.rs              -- CryptoProvider trait
    providers/               -- Built-in: TLS, kTLS, DTLS, WireGuard, routing
    tls_engine/              -- TLS/kTLS encrypt/decrypt implementation
    dtls_engine.rs           -- DTLS encrypt/decrypt implementation
    routing_engine.rs        -- Routing (plaintext L4): TCP + multi-client UDP listeners
    wireguard_engine.rs      -- WireGuard kernel-offload relay (+ wireguard_engine/admin.rs)
    udp_framing.rs           -- UDP-over-TLS framing selector (UdpFraming: ale / raw)
    udp_session.rs           -- Per-peer UDP/DTLS session admission + idle eviction
    relay.rs                 -- Bidirectional relay functions
  app_protocols/
    provider.rs              -- AppProtocolProvider + FramingSession traits
    ale_provider.rs          -- ALE (EuroRadio) implementation
    raw_provider.rs          -- Raw length-prefix implementation
  management/
    config.rs                -- JSON config parsing, validation
    config_manager.rs        -- Hot-reload via SIGHUP / file watch
    cert_store.rs            -- Self-signed certificate generation
    telemetry.rs             -- Metrics and CSV logging
  networking/                -- Socket management, connect with retry
  interfaces/                -- TPROXY support
```

### Thread Model

```
main thread
  +-- rule-{name} thread        (one per rule -- accepts connections)
  |     +-- conn-{peer} thread  (one per TCP connection -- bidirectional relay)
  +-- stats-{name} thread       (one per rule -- periodic metrics printer)
  +-- config-watcher thread     (polls file/SIGHUP for hot-reload)
  +-- shutdown-watchdog thread  (force-exits after 5s on shutdown)
```

## Building

```bash
# Debug build
cargo build --bin gateway

# Release build (optimized)
cargo build --release --bin gateway
```

## Dependencies

| Crate | Purpose |
|---|---|
| `openssl` | TLS and DTLS via OpenSSL |
| `ktls_pipe` | Kernel TLS session management (workspace member) |
| `tls_pipe` | Userspace TLS helpers (workspace member) |
| `ale_pipe` | ALE/ALEPKT framing (workspace member) |
| `serde` + `serde_json` | JSON config deserialization |
| `libc` | Low-level system calls (TPROXY, signals, poll) |
