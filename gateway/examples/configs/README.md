# Example configurations & capability matrix

Runnable, per-capability gateway configurations. Each file is a complete
`GatewayConfig` (a `rules` array) and is validated by
[`tests/examples_load.rs`](../../tests/examples_load.rs) (part of `cargo test`),
so a renamed field or a newly-rejected combination fails the test suite.

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
| [dscp_qos.json](dscp_qos.json) | **DSCP egress marking + preservation**: safety EF tag, DTLS inbound-DSCP preserve, normal AF11 — mixed safety/normal. |

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
| DSCP tag (safety = EF/46, explicit override) | `routing` / `tls` / `dtls` | — | — | `dscp_tag` | dscp_qos | [dscp.rs](../../tests/dscp.rs) |
| DSCP preserve (inbound DS field → egress) | `dtls` | dtls1.2 | — | `preserve_inbound_dscp` | dscp_qos | [dscp.rs](../../tests/dscp.rs) |
| Safety prioritization (nice + `SO_PRIORITY` + reserved pool) | — | — | — | `traffic_class = safety` | dscp_qos | [dscp.rs](../../tests/dscp.rs) |
| All examples load | — | — | — | — | * | [examples_load.rs](../../tests/examples_load.rs) |

## DSCP marking & safety prioritization

Every rule carries a `traffic_class` (`safety` | `normal`, default `normal`) plus
two optional per-rule QoS fields. Safety traffic is **always** prioritized
internally and marked for priority on the wire.

| Field | Type | Meaning |
|-------|------|---------|
| `traffic_class` | `"safety"` \| `"normal"` | Selects the class default DSCP/priority. Safety defaults to **EF (46)**; normal is left unmarked. |
| `dscp_tag` | `0`–`63` | Explicit egress DSCP. Overrides the class default and any inbound marking. Values `> 63` are rejected at config load. |
| `preserve_inbound_dscp` | `bool` | When `true` (and no `dscp_tag`), the gateway samples the inbound DS field and re-applies it on egress. |

**Egress DSCP precedence** (see [`RuleConfig::egress_dscp`](../../src/management/config.rs)):

1. explicit `dscp_tag` → that value;
2. else `preserve_inbound_dscp` + a sampled inbound DSCP → the sampled value;
3. else the class default: **safety → EF (46)**, normal → unmarked.

**Internal prioritization (always on for safety).** Independent of DSCP, safety
rules raise their workers' scheduling priority
([`apply_safety_priority`](../../src/networking/socket_manager.rs), `nice -5`
when the process holds `CAP_SYS_NICE`), set `SO_PRIORITY = 6` on their sockets,
and run on a class-aware connection pool with a reserved minimum worker count so
a flood of normal traffic cannot starve safety capacity. Without `CAP_SYS_NICE`
the gateway logs a one-time preflight warning and degrades to DSCP + `SO_PRIORITY`
only.

**Preservation scope.** Per-datagram inbound-DSCP preservation works where the
gateway owns the receive (UDP / DTLS). On TLS-terminated and `splice` TCP paths
the gateway cannot sample per-segment marks, so preservation falls back to the
class default (safety still gets EF). On the Linux **loopback** interface the
received DS field is only observable for UDP, so the end-to-end DSCP assertions
in [dscp.rs](../../tests/dscp.rs) verify the DTLS/UDP paths; the TCP egress mark
is verified at the syscall layer by the `socket_manager` unit tests.

## Running

```sh
# validate every example config
cargo test -p gateway --test examples_load

# the capability tests (UDP/DTLS tests are timing-sensitive — pin one thread)
cargo test -p gateway --test ale_raw      -- --test-threads=1
cargo test -p gateway --test dtls         -- --test-threads=1
cargo test -p gateway --test dscp         -- --test-threads=1
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
