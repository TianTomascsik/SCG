# 11 — Forward-Looking Interfaces

> **Status:** 🔵 Future · **Source:** [security/stubs.rs](../../src/security/stubs.rs),
> [management/stubs.rs](../../src/management/stubs.rs), [api/mod.rs](../../src/api/mod.rs) ·
> **Stub:** [traits/future.rs](traits/future.rs)

These modules are **planned but unimplemented** (TODO stubs in the codebase).
They are documented here so that when they are built they slot into the existing
interface boundaries instead of inventing new ad-hoc seams. Wherever possible a
future module **reuses an existing interface** rather than defining a new one.

## A. New security engines — reuse `CryptoProvider` (interface 01)

The stubs in [security/stubs.rs](../../src/security/stubs.rs) describe additional
encryption schemes. None of these need a *new* interface — each is a new
[`CryptoProvider`](01-crypto-provider.md) implementation registered by name.

| Future engine | `name()` | Notes / extra needs |
|---------------|----------|---------------------|
| **IPSec** (IKEv2 + XFRM) | `"ipsec"` | IKEv2 key exchange; Linux XFRM policy/state via netlink; SA lifecycle. Needs cert/PSK material via [interface 05](05-cert-key-management.md). Likely manages kernel state rather than a userspace relay — `run_*` sets up SAs then supervises. |
| **WireGuard** | `"wireguard"` | Tunnel/peer setup; static keys via [interface 05](05-cert-key-management.md) (`KeyMaterialProvider`); interface creation via the future Firewall/Namespace manager (§D). |
| **GDOI** (group key mgmt) | `"gdoi"` | Group SA distribution; key-server/member roles; pairs with IPSec for group SAs; rekey via the key interfaces. |

**Implication for interface 01:** the existing `CryptoProvider` contract is
sufficient. The only gap is that IPSec/WireGuard manage **kernel** tunnels rather
than relaying bytes in userspace; the `run_encrypt`/`run_decrypt` "own the thread
until shutdown" contract still holds (the thread supervises kernel SAs and tears
them down on shutdown). This should be noted in their provider docs.

## B. Identity & Access Management (IAM) — new `AuthProvider`

Backs the privileged [Admin API](10-management-api.md). Authenticates a caller and
authorizes an action.

```rust
pub trait AuthProvider: Send + Sync {
    fn authenticate(&self, credential: &Credential<'_>) -> Result<Principal, AuthError>;
    fn authorize(&self, principal: &Principal, action: AdminAction) -> Result<(), AuthError>;
}
```

The API binding layer calls `authenticate` then `authorize` before dispatching any
`AdminApi` method. Decisions should emit [audit events](03-logging.md).

## C. Crypto Policy & Algorithm Manager — new `CryptoPolicy`

Enforces algorithm allow/deny lists, minimum protocol versions, key lengths, and
FIPS mode, consulted by security engines while building TLS/DTLS contexts.

```rust
pub trait CryptoPolicy: Send + Sync {
    fn cipher_allowed(&self, suite: &str) -> bool;
    fn min_protocol(&self, family: ProtocolFamily) -> ProtocolVersion;
    fn fips_mode(&self) -> bool;
    fn validate_rule(&self, rule: &str, provider: &str, version: Option<&str>) -> Result<(), PolicyError>;
}
```

This complements [interface 05](05-cert-key-management.md): keys/certs decide
*identity*, crypto policy decides *which algorithms are acceptable*.

## D. Network Namespace & Firewall Manager — new `NetworkManager`

Automates what the `setup_gateway.sh` scripts do today: iptables/nftables chains
(`SCG_ENCRYPT`, `SCG_DECRYPT`), TPROXY routing (`ip rule fwmark 1 lookup 100`),
and network-namespace isolation. Consumed at startup and by the
[transport](06-transport.md) layer for transparent mode.

```rust
pub trait NetworkManager: Send + Sync {
    fn ensure_chains(&self) -> Result<(), NetError>;
    fn ensure_routing(&self) -> Result<(), NetError>;
    fn teardown(&self) -> Result<(), NetError>;
}
```

## E. Certificate Revocation & OCSP — extend `CertificateProvider` (interface 05)

No new top-level interface: revocation is realized through
`CertificateProvider::verify_peer` honouring `VerifyRequest.require_revocation_check`,
backed by a CRL/OCSP component. A small helper trait scopes that backend:

```rust
pub trait RevocationChecker: Send + Sync {
    fn status(&self, cert: &CertificateDer) -> Result<RevocationStatus, KeyError>;
}
// RevocationStatus: Good | Revoked | Unknown
```

## F. Storage Manager / HSM — backend for `KeyMaterialProvider` (interface 05)

Persistent, possibly HSM-backed storage for keys and audit archival. This is an
**implementation** of the [interface 05](05-cert-key-management.md) providers
(`CertificateProvider` / `PreSharedKeyStore` / `KeyMaterialProvider`) whose backend
is an HSM/KMS, plus an optional archival sink for the [audit log](03-logging.md).
No new data-plane interface is required.

```rust
pub trait SecretStore: Send + Sync {
    fn get(&self, id: &KeyId) -> Result<SecretKey, KeyError>;
    fn put(&self, id: &KeyId, secret: SecretKey) -> Result<(), KeyError>;
    fn delete(&self, id: &KeyId) -> Result<(), KeyError>;
}
```

## G. Traffic Mirror — new `ObserverTap` (reuse UDS/SHM endpoints, interface 06)

An **observer tap** that mirrors selected, already-decrypted **(plaintext)** flows to a
read-only endpoint for recording / monitoring (IDS/NDR span-port, pcap, audit-of-payload),
plus a reverse **test-injection** variant. It **reuses** the existing UDS/SHM local-interface
machinery ([`interfaces/uds.rs`](../../src/interfaces/uds.rs) /
[`shm.rs`](../../src/interfaces/shm.rs)) rather than adding a new data-plane subsystem: the
relay feeds a **copy** of frames for a config-selected set of `traffic_id`s / rules to a
read-only observer endpoint, carrying the same authenticated-endpoint discipline
(`SO_PEERCRED` + single-use capability token). Status: **planned — no code today.**

```rust
pub trait ObserverTap: Send + Sync {
    /// Should this flow be mirrored? (config-selected traffic_id / rule filter)
    fn selects(&self, traffic_id: u32) -> bool;
    /// Deliver a copy of a plaintext frame to the observer endpoint.
    fn mirror(&self, traffic_id: u32, frame: &[u8]) -> Result<(), TapError>;
}
```

> **⚠ Security.** A mirror exposes **plaintext** on the trusted side — a real trust-boundary
> addition. It must be gated to explicitly-configured flows, reuse `SO_PEERCRED` + capability
> token, and **pass a TRA before implementation**. See the Application Interfaces README
> (`Architecture/Application Interfaces & Workers/README.md`, §10).

## Summary: new vs. reused

| Future module | Interface strategy |
|---------------|--------------------|
| IPSec / WireGuard / GDOI | **Reuse** `CryptoProvider` (01) |
| Certificate Revocation / OCSP | **Extend** `CertificateProvider` (05) via `RevocationChecker` |
| Storage Manager / HSM | **Implement** interface-05 providers via `SecretStore` |
| IAM | **New** `AuthProvider` (gates Admin API, 10) |
| Crypto Policy / Algorithm Manager | **New** `CryptoPolicy` |
| Network Namespace / Firewall Manager | **New** `NetworkManager` |
| Traffic Mirror (observer tap) | **New** `ObserverTap` (reuses UDS/SHM endpoints, 06) |

## Conformance (when implemented)

- [ ] Reused interfaces are not forked — new engines implement the existing trait.
- [ ] New traits follow the [design principles](README.md#design-principles) (`Send + Sync`, injection, typed errors, fail-closed).
- [ ] Privileged actions are authenticated/authorized and audited.
- [ ] Kernel-state engines (IPSec/WireGuard) honour cooperative shutdown.
