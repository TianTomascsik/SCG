# Secure Communication Gateway (SCG)

Open-source core of the **Secure Communication Gateway** — a high-performance,
transparent encryption proxy that secures network traffic without changes to the
applications behind it. Part of the **SCG** project.

## Layout

| Path | Description |
|---|---|
| `gateway/` | Gateway library + binary (`gateway`). Built-in crypto providers: TLS, kTLS, DTLS; app protocols: ALE, raw. |
| `crates/ktls_pipe/` | Kernel TLS (kTLS) pipe library |
| `crates/tls_pipe/` | Userspace TLS pipe library (OpenSSL) |

## Build & run

```bash
cargo build --release --bin gateway

# Validate a configuration without opening sockets
./target/release/gateway --config gateway/gateway.example.json --validate

# Run (transparent-proxy rules need CAP_NET_ADMIN, e.g. via sudo or the systemd unit)
sudo ./target/release/gateway --config gateway/gateway.example.json
```

See [gateway/README.md](gateway/README.md) for full configuration, providers,
deployment, and architecture.

## Provider plugin model

The gateway is a **library**. `gateway::run(extra_crypto, extra_app)` accepts
additional `CryptoProvider` / `AppProtocolProvider` implementations that are
registered alongside the built-ins. The default `gateway` binary passes none.
Downstream builds (e.g. the internal `scg-downstream`) link this crate and register
their own providers — no fork required.

## License

Apache-2.0 — see [LICENSE](LICENSE).
