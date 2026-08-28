# 05 — Certificate & Key Management Interface (incl. PSK)

> **Status:** 🟡 Proposed · **Traits:** `CertificateProvider`,
> `PreSharedKeyStore`, `KeyMaterialProvider` ·
> **Abstracts:** [management/cert_store.rs](../../src/management/cert_store.rs)
> (`get_or_init_cert`), keyed-MAC key injection, and a future dedicated PSK
> registry.
>
> **Stub:** [traits/cert_key.rs](traits/cert_key.rs)

## Purpose

Centralize and abstract **all key and certificate material** so security engines
receive what they need by injection instead of reaching for globals. This is the
key enabler for swapping the *source* of trust — self-signed (today), file-based
PKI, an enrolment service, or an HSM — and for adding **pre-shared keys (PSK)**
for TLS-PSK/DTLS-PSK and for keyed-MAC providers, without modifying any engine.

Three concerns:

- **`CertificateProvider`** — X.509 identities (cert + private key), the trust
  anchor/CA bundle, and peer verification.
- **`PreSharedKeyStore`** — symmetric pre-shared keys addressed by identity, for
  PSK cipher suites and for keyed-MAC schemes.
- **`KeyMaterialProvider`** — generic named secret material (e.g. a keyed-MAC
  provider's key), decoupling engines from "where the bytes came from."

## Why an interface is needed

Today:

- [cert_store.rs](../../src/management/cert_store.rs) exposes a single free
  function `get_or_init_cert()` that **generates a self-signed RSA-2048 cert** and
  caches it in a `static OnceLock` for the process lifetime. The TLS and DTLS
  engines call it directly (a hidden global dependency).
- A **keyed-MAC provider's key** would be parsed from config and pushed into a
  bespoke, per-provider field on `RuleContext`.
- **A dedicated PSK registry is unimplemented** (see [11-future-interfaces.md](11-future-interfaces.md)); PSK material itself is configured per rule today.

There is no rotation, no peer verification policy, no separation between "how a
cert is obtained" and "how it is used." An interface removes the global, unifies
key sources, and creates a place to add rotation/revocation/HSM later (see
[11 — Future interfaces](11-future-interfaces.md)).

## As-built today (incremental, config-driven)

Ahead of the full provider trait layer below, key/cert material is now loaded
**from rule config** (not just the self-signed global). The `tls`, `ktls`, and
`dtls` engines resolve a typed
[`TlsSecurityParams`](../../src/security/tls_engine/params.rs) from the rule's
flattened `provider_params` + `protocol_version`, and the builders consume it:

- **Identity from files** —
  [`load_identity_pem(cert_path, key_path)`](../../src/management/cert_store.rs)
  loads a PEM cert + private key; `get_or_init_cert()` remains the self-signed
  fallback when no `cert_path` is given, so existing configs are unchanged. A
  `generate_self_signed_ecdsa` helper backs the test PKI.
- **Trust + verification** — `ca_path` sets the peer trust store and `verify`
  (`none` | `server` | `mutual`) maps to the OpenSSL verify mode; the connector
  also checks the `server_name`/SNI hostname. Configured in
  [`build_tls_acceptor` / `build_tls_connector`](../../src/security/tls_engine/mod.rs)
  and [`build_dtls_acceptor` / `build_dtls_connector`](../../src/security/dtls_engine.rs).
- **PSK** — `profile = subset146-psk` wires the OpenSSL PSK server/client
  callbacks from `psk_identity` + `psk_hex` (DHE-PSK, TLS 1.2) — the
  concrete per-rule PSK mechanism shipped today.
- **Cipher policy** — selected per `profile` (`subset146-pki`, `integrity-only`,
  …) with optional `cipher_list`/`ciphersuites` overrides.

This covers the **core handshake** material the engines need today; the trait
abstraction below (rotation, revocation/OCSP, HSM, named MAC keys) remains the
forward-looking design. Keys are still read from files at build time — fail-closed
on a missing/invalid file — without the rotation/epoch semantics the traits add.
See the per-profile runnable configs in
[examples/configs/](../../examples/configs/).

## Authenticated upstream identity (gateway→upstream trust boundary)

When the gateway connects to an upstream (the encrypt/connector leg), the
**identity that is cryptographically authenticated is the SNI / verification
name** — `server_name` if set, otherwise the host part of `upstream_addr`,
resolved by
[`TlsSecurityParams::sni_name`](../../src/security/tls_engine/params.rs). Under
`verify = server`/`mutual` the connector checks the upstream certificate chain
against `ca_path` **and** matches this name against the certificate (SAN/CN).

It is deliberately **not**:

- the raw socket connect target (an IP, or for `transparent`/`"auto"` rules the
  `SO_ORIGINAL_DST` address recovered from the kernel); nor
- the policy-whitelist `destination` (`policy.whitelist[].destination`), which is
  an **unauthenticated routing filter** applied before/independent of the
  handshake, not a cryptographic identity.

Operators pinning an upstream identity should therefore set `server_name`
(matching a SAN on the upstream certificate) together with `verify` + `ca_path`,
rather than relying on the connect target or the policy destination. The
key/certificate material never leaks: private keys are masked in `Debug`
(`TlsSecurityParams`), compared/loaded fail-closed, and PSK bytes are zeroized on
drop.

## Traits

```rust
pub trait CertificateProvider: Send + Sync {
    /// Server (and optionally client) identity for a handshake context.
    fn identity(&self, req: &IdentityRequest) -> Result<CertKeyPair, KeyError>;
    /// Trust anchors used to verify peers.
    fn ca_bundle(&self) -> Result<Vec<CertificateDer>, KeyError>;
    /// Verify a presented peer chain against policy (name, validity, revocation).
    fn verify_peer(&self, chain: &[CertificateDer], req: &VerifyRequest) -> Result<(), KeyError>;
    /// Re-read material from the backing source (file change, rotation).
    fn reload(&self) -> Result<(), KeyError>;
}

pub trait PreSharedKeyStore: Send + Sync {
    /// Resolve a PSK by its identity (TLS-PSK/DTLS-PSK server side).
    fn psk_by_identity(&self, identity: &[u8]) -> Option<SecretKey>;
    /// Identity (and key) this gateway presents as a PSK client, if any.
    fn client_identity(&self) -> Option<(Vec<u8>, SecretKey)>;
    /// Optional identity hint to advertise to peers.
    fn identity_hint(&self) -> Option<Vec<u8>>;
    /// Rotate to the next key epoch; returns the new active key id.
    fn rotate(&self) -> Result<KeyId, KeyError>;
}

pub trait KeyMaterialProvider: Send + Sync {
    /// Fetch named secret material (e.g. a keyed-MAC key for a rule).
    fn key(&self, id: &KeyId) -> Result<SecretKey, KeyError>;
    /// Rotate the named key; returns the new epoch id.
    fn rotate(&self, id: &KeyId) -> Result<KeyId, KeyError>;
}
```

## Method contracts

| Method | Contract |
|--------|----------|
| `identity(req)` | Returns a cert+private-key for the requested role/SNI/protocol. May be cached. Must not return an expired identity. |
| `ca_bundle()` | Trust anchors for peer verification. Empty bundle ⇒ verification disabled only if explicitly configured. |
| `verify_peer(chain, req)` | Enforces name match, validity window, and (when configured) revocation/OCSP. `Ok(())` ⇒ accept. Fail closed on any uncertainty unless policy says otherwise. |
| `reload()` | Atomically swap material; in-flight handshakes keep their captured material. |
| `psk_by_identity(id)` | Constant-time identity lookup where feasible; `None` ⇒ unknown identity ⇒ handshake must fail. |
| `client_identity()` | The PSK identity+key this side presents (PSK client). |
| `rotate()` | Introduces a new epoch while keeping the previous one valid for an overlap window (avoid cutting live peers). |
| `KeyMaterialProvider::key(id)` | Returns the active secret for a named key (e.g. `mac:<rule>`). Zeroized on drop. |

**Secret hygiene.** `SecretKey` wraps the bytes, implements `Drop` to zeroize,
and avoids `Debug`/`Display` of the contents. Engines hold it only as long as
needed.

## Data types

```rust
pub struct IdentityRequest<'a> {
    pub role: HandshakeRole,        // Server | Client
    pub server_name: Option<&'a str>,   // SNI
    pub protocol: TlsProtocol,      // Tls12 | Tls13 | Dtls10 | Dtls12
    pub rule: &'a str,
}

pub struct VerifyRequest<'a> {
    pub expected_name: Option<&'a str>,
    pub require_revocation_check: bool,
}

pub struct CertKeyPair {
    pub cert_chain: Vec<CertificateDer>, // leaf first
    pub private_key: PrivateKeyDer,
}

pub struct CertificateDer(pub Vec<u8>);
pub struct PrivateKeyDer(pub Vec<u8>);   // zeroized on drop

pub struct SecretKey(Vec<u8>);           // zeroized on drop; no Debug
pub struct KeyId(pub String);            // e.g. "psk:peerA", "mac:rule1"

pub enum HandshakeRole { Server, Client }
pub enum TlsProtocol { Tls12, Tls13, Dtls10, Dtls12 }

pub enum KeyError { NotFound, Expired, Revoked, Backend(String), Io }
```

## Lifecycle & threading

- **Construct:** from config (source = `self-signed` | `files` | `pki` | `hsm`;
  PSK table; keyed-MAC keys).
- **Inject:** `GatewayServices.certs` / `.psk`. Engines obtain material through
  these instead of `get_or_init_cert()` or a per-provider key field.
- **Run:** called during handshakes from many threads → `Send + Sync`.
- **Reload/rotate:** `reload()` and `rotate()` triggered by config reload, a
  timer, or the [Management API](10-management-api.md).
- **Shutdown:** drop zeroizes secrets.

## Error handling

`Result<_, KeyError>`. Engines **fail closed**: a missing/expired/revoked
identity or an unknown PSK identity aborts the handshake rather than falling back
to no protection.

## Migration from current code

| Today | Interface |
|-------|-----------|
| `get_or_init_cert()` (self-signed RSA-2048, `OnceLock`) | A `SelfSignedCertProvider: CertificateProvider` (default impl preserving current behaviour). |
| `build_tls_acceptor()` / `build_dtls_acceptor()` calling the global | Pass `&dyn CertificateProvider` into the builders. |
| A per-provider key field on `RuleContext` | `KeyMaterialProvider::key(KeyId("mac:<rule>"))`. |
| Per-rule PSK config fields | `PreSharedKeyStore` impl (file/static table, later HSM). |

## Example implementor (skeleton)

```rust
pub struct SelfSignedCertProvider { cached: OnceLock<CertKeyPair> }

impl CertificateProvider for SelfSignedCertProvider {
    fn identity(&self, _req: &IdentityRequest) -> Result<CertKeyPair, KeyError> {
        // generate-once self-signed RSA-2048 (today's behaviour)
        Ok(self.cached.get_or_init(generate_self_signed).clone())
    }
    fn ca_bundle(&self) -> Result<Vec<CertificateDer>, KeyError> { Ok(vec![]) }
    fn verify_peer(&self, _c: &[CertificateDer], _r: &VerifyRequest) -> Result<(), KeyError> { Ok(()) }
    fn reload(&self) -> Result<(), KeyError> { Ok(()) }
}
```

## Selection

```json
{ "keys": {
    "certificates": { "source": "files", "cert": "/etc/scg/gw.pem", "key": "/etc/scg/gw.key", "ca": "/etc/scg/ca.pem" },
    "psk": { "source": "file", "path": "/etc/scg/psk.toml", "rotation_s": 86400 },
    "material": { "mac": { "rule1": { "hex": "0123…" } } }
} }
```

## Conformance checklist

- [ ] Secrets are zeroized on drop and never logged (`SecretKey`/`PrivateKeyDer`).
- [ ] No engine calls a global; all material arrives via injection.
- [ ] `verify_peer` enforces name + validity (+ revocation when configured) and fails closed.
- [ ] `reload()`/`rotate()` keep in-flight handshakes consistent and overlap epochs.
- [ ] Unknown PSK identity ⇒ handshake failure (no silent downgrade).
- [ ] Self-signed default reproduces today's behaviour for compatibility.
- [ ] All three traits are `Send + Sync`.
