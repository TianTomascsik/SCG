# Secure Communication Gateway (SCG)

Open-source core of the **Secure Communication Gateway** — a high-performance,
transparent encryption proxy that secures network traffic without changes to the
applications behind it. Part of the **SCG** project.

## Layout

| Path | Description |
|---|---|
| `gateway/` | Gateway library + binary (`gateway`). Built-in crypto providers: TLS, kTLS, DTLS, WireGuard (kernel), routing; app protocols: ALE, raw. |
| `crates/ktls_pipe/` | Kernel TLS (kTLS) pipe library |
| `crates/scg-ipc/` | Local-interface IPC primitives (framed packets, SHM rings, capability tokens) |
| `crates/scg-proto/` | gRPC/protobuf definitions for the management API |
| [`crates/scg-client/`](crates/scg-client/README.md) | Client library (Rust core + C/C++ ABI) for the local interfaces |

## Build & run

```bash
# Production build: accepts only the signed --config-dir configuration
cargo build --release --bin gateway

# Development build: additionally accepts the unsigned single-file --config,
# which is what the bundled example configuration uses
cargo build --release --bin gateway --features dev

# Validate the example configuration without opening sockets (dev build).
# Note: the example includes transparent (TPROXY) rules, so without
# CAP_NET_ADMIN this reports one capability error and exits 1.
./target/release/gateway --config gateway/gateway.example.json --validate

# Run (transparent-proxy rules need CAP_NET_ADMIN, e.g. via sudo or the systemd unit)
sudo ./target/release/gateway --config gateway/gateway.example.json
```

The WireGuard keys in `gateway/gateway.example.json` are throwaway example
material — generate your own with `wg genkey` before any real use.

See [gateway/README.md](gateway/README.md) for full configuration, providers,
deployment, and architecture.

## Provider plugin model

The gateway is a **library**. `gateway::run(extra_crypto, extra_app)` accepts
additional `CryptoProvider` / `AppProtocolProvider` implementations that are
registered alongside the built-ins. The default `gateway` binary passes none.
Downstream builds can link this crate and register their own providers — no
fork required.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
