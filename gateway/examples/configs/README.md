# Example configurations & capability matrix

Runnable, per-capability gateway configurations. Each file is a complete
`GatewayConfig` (a `log_dir` plus a `rules` array) and is validated in CI by
[`tests/examples_load.rs`](../../tests/examples_load.rs), so a renamed field or a
newly-rejected combination fails the build.

> The certificate/key paths (`/etc/scg/pki/…`) are placeholders for
> documentation. Configs **parse and validate** without the files present; the
> referenced PEMs are only opened when a rule actually starts.

## Example files

| File | Capability |
|------|------------|
| [mtls_web_frontend.json](mtls_web_frontend.json) | TLS 1.3 HTTPS web frontend: mutual-auth termination (decrypt) + server-verified origination (encrypt), L4. |
| [subset146_pki.json](subset146_pki.json) | Subset-146 mutual TLS **PKI** profile (ECDHE-ECDSA-GCM, TLS 1.2). |
| [subset146_psk.json](subset146_psk.json) | Subset-146 TLS-**PSK** profile (DHE-PSK-AES256-GCM, TLS 1.2). |
| [integrity_only.json](integrity_only.json) | Authenticated-but-not-encrypted TLS (NULL cipher / eNULL). |
| [routing_only.json](routing_only.json) | Plaintext L4 passthrough via the `routing` provider (no crypto). |
| [dtls.json](dtls.json) | DTLS 1.2 with server + mutual verification (UDP-native). |
| [udp_ale.json](udp_ale.json) | UDP-over-TLS with ETCS **ALE** framing (`app_protocol = ale`). |
| [udp_raw.json](udp_raw.json) | UDP-over-TLS with **raw** length-prefix framing (`app_protocol = raw`). |

## Capability matrix

Coverage of `provider × version × verify × profile × app_protocol`, each row
mapped to its example and its automated test.

| Capability | provider | version | verify | profile / app_protocol | Example | Test |
|------------|----------|---------|--------|------------------------|---------|------|
| TLS server verify | `tls` | tls1.2 / tls1.3 | server | default | mtls_web_frontend | [tls_verify.rs](../../tests/tls_verify.rs) |
| TLS mutual auth | `tls` | tls1.2 / tls1.3 | mutual | default | mtls_web_frontend | [tls_verify.rs](../../tests/tls_verify.rs) |
| HTTPS frontend (HTTP↔HTTPS, L4) | `tls` | tls1.3 | mutual / server | default | mtls_web_frontend | [tls_verify.rs](../../tests/tls_verify.rs) |
| Subset-146 PKI | `tls` | tls1.2 / tls1.3 | mutual | subset146-pki | subset146_pki | [subset146_pki.rs](../../tests/subset146_pki.rs) |
| Subset-146 PSK | `tls` | tls1.2 | — | subset146-psk | subset146_psk | [subset146_psk.rs](../../tests/subset146_psk.rs) |
| Integrity-only (NULL) | `tls` | tls1.2 | server / none | integrity-only | integrity_only | [integrity_only.rs](../../tests/integrity_only.rs) |
| Routing-only passthrough | `routing` | — | — | — | routing_only | [routing_smoke.rs](../../tests/routing_smoke.rs) |
| DTLS 1.2 | `dtls` | dtls1.2 | server / mutual | default | dtls | [dtls.rs](../../tests/dtls.rs) |
| DTLS 1.0 | `dtls` | dtls1.0 | none | default | — | [dtls.rs](../../tests/dtls.rs) |
| UDP-over-TLS, ALE | `tls` | tls1.2/1.3 | server | ale | udp_ale | [ale_raw.rs](../../tests/ale_raw.rs) |
| UDP-over-TLS, raw | `tls` | tls1.2/1.3 | server | raw | udp_raw | [ale_raw.rs](../../tests/ale_raw.rs) |
| kTLS PSK → userspace fallback | `ktls`→`tls` | tls1.2 | — | subset146-psk | — | [subset146_psk.rs](../../tests/subset146_psk.rs) |
| kTLS + integrity-only rejected | `ktls` | — | — | integrity-only | — | (config-load reject) |
| All examples load | — | — | — | — | * | [examples_load.rs](../../tests/examples_load.rs) |

## Running

```sh
# validate every example config
cargo test -p gateway --test examples_load

# the capability tests (UDP/DTLS tests are timing-sensitive — pin one thread)
cargo test -p gateway --test ale_raw      -- --test-threads=1
cargo test -p gateway --test dtls         -- --test-threads=1
cargo test -p gateway --test tls_verify
cargo test -p gateway --test subset146_pki
cargo test -p gateway --test subset146_psk
cargo test -p gateway --test integrity_only
cargo test -p gateway --test routing_smoke
```

See [docs/interfaces/01-crypto-provider.md](../../docs/interfaces/01-crypto-provider.md)
for the full `provider_params` reference and
[docs/interfaces/05-cert-key-management.md](../../docs/interfaces/05-cert-key-management.md)
for certificate/key loading.
