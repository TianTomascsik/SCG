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
| **ALE framing** | ALEPKT framing per Subset-098/037 for UDP-over-TLS (EuroRadio) |
| **Raw framing** | Simple length-prefix framing for UDP-over-TLS without ALE overhead |
| **TPROXY** | Transparent proxy via `IP_TRANSPARENT` + `SO_ORIGINAL_DST` |
| **Hot-reload** | SIGHUP or file watch -- add/remove rules without restart |
| **Provider architecture** | Add custom security or protocol providers by implementing a trait |

## Quick Start

```bash
# Build
cargo build --release --bin gateway

# Run with config
sudo ./target/release/gateway --config gateway/gateway.example.json

# Run with overrides
sudo ./target/release/gateway \
    --config gateway.json \
    --watch

# Validate config without starting
sudo ./target/release/gateway --config gateway.json --validate
```

### CLI Options

| Flag | Description |
|---|---|
| `--config PATH` | Path to JSON configuration file **(required)** |
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
| `security_provider` | No | `"tls"` | Security engine: `"tls"`, `"ktls"`, `"dtls"` (plus any custom provider registered at startup) |
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
gateway --config gateway.json --log-level debug

# JSON config
{ "log_level": "debug" }
```

The `RUST_LOG` environment variable is also supported for fine-grained per-module control:

```bash
RUST_LOG=gateway::security=trace gateway --config gateway.json
```

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
gateway --config gateway.json --watch
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
gateway --config gateway.json --validate
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
    providers/               -- Built-in: TLS, kTLS, DTLS
    tls_engine/              -- TLS/kTLS encrypt/decrypt implementation
    dtls_engine.rs           -- DTLS encrypt/decrypt implementation
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
