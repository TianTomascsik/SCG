# 02 — Protocol Provider Interface

> **Status:** ✅ As-built · **Traits:** `AppProtocolProvider`, `FramingSession` ·
> **Source of truth:** [app_protocols/provider.rs](../../src/app_protocols/provider.rs#L17) ·
> **Stub:** [traits/protocol_provider.rs](traits/protocol_provider.rs)

## Purpose

An **Application Protocol Provider** defines how discrete UDP datagrams are
**framed over a byte stream** when a UDP application is tunnelled through a
TCP+TLS connection (the "UDP-over-TLS" path). It solves datagram-boundary
multiplexing: turning a sequence of datagrams into a framed byte stream and back,
plus any connection handshake/disconnect signalling the framing protocol needs.

Swapping the protocol provider changes the on-the-wire framing (e.g. ETCS/ALE
vs. a minimal length-prefix) without touching the security engine.

## Responsibilities

Two cooperating traits:

- **`AppProtocolProvider`** — a stateless factory selected by `name()`
  (`app_protocol` in config). Produces a fresh session per connection.
- **`FramingSession`** — the **stateful** per-connection worker. Performs the
  handshake, frames outgoing datagrams, deframes incoming bytes into datagrams,
  and writes a disconnect indication.

The provider is **not** responsible for encryption (that is the crypto engine),
for the UDP sockets themselves, or for routing — only for framing semantics.

## Traits

```rust
/// Stateless factory, selected by name.
pub trait AppProtocolProvider: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn create_session(&self) -> Box<dyn FramingSession>;
}

/// Stateful per-connection framing worker.
pub trait FramingSession: Send {
    fn handshake_initiator(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()>;
    fn handshake_responder(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()>;
    fn frame_datagram(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()>;
    fn deframe(&mut self, data: &[u8]) -> io::Result<DeframeResult>;
    fn write_disconnect(&mut self, stream: &mut dyn ReadWrite) -> io::Result<()>;
}
```

## Method contracts

### `AppProtocolProvider`

| Method | Contract |
|--------|----------|
| `name()` | Stable, unique, lowercase. Matched against the rule's `app_protocol`. |
| `description()` | Free-form, for logs. |
| `create_session()` | Returns a **fresh** `Box<dyn FramingSession>` per connection/tunnel. Must not share mutable state between sessions. |

### `FramingSession`

| Method | Contract |
|--------|----------|
| `handshake_initiator(stream)` | Called once on the **encrypt** side after the TLS tunnel is up. Performs the protocol's client handshake. No-op `Ok(())` if the protocol has none. |
| `handshake_responder(stream)` | Called once on the **decrypt** side. Performs the server handshake. No-op `Ok(())` if none. |
| `frame_datagram(payload, out)` | **Append** the framed form of one datagram (header + payload, CRC, etc.) to `out`. Must not assume `out` is empty (it may batch multiple frames). |
| `deframe(data)` | Feed raw stream bytes; return any **complete** datagrams plus a `disconnected` flag. Must buffer partial frames internally across calls and tolerate `data` that contains zero, one, or many frames. |
| `write_disconnect(stream)` | Write the protocol's close indication before the tunnel is torn down. No-op `Ok(())` if none. |

**Statefulness.** A session owns its framing buffers and any handshake state. It
sees only the (already decrypted) byte stream; it must not know about TLS.

## Data types

```rust
pub struct DeframeResult {
    pub datagrams: Vec<Vec<u8>>, // complete payloads (possibly empty)
    pub disconnected: bool,      // peer sent a disconnect indication
}

/// Trait alias for a bidirectional byte stream.
pub trait ReadWrite: io::Read + io::Write {}
impl<T: io::Read + io::Write> ReadWrite for T {}
```

## Lifecycle & threading

- **Construct factory:** stateless singletons (`AleProtocolProvider`,
  `RawProtocolProvider`), `Send + Sync`, registered once.
- **Create session:** one per tunnel; `Send` (moved onto the handling thread) but
  not required to be `Sync`.
- **Run:** handshake once → many `frame_datagram`/`deframe` calls → one
  `write_disconnect`. The crypto engine drives these calls at the right moments.
- **Shutdown:** the owning crypto engine stops calling the session and drops it.

## Error handling

`io::Result<...>`. A handshake error aborts the tunnel. A `deframe` error should
be treated as a protocol violation and close the tunnel (fail closed). Returning
`Ok(DeframeResult { disconnected: true, .. })` is the graceful peer-close signal.

## Current implementation

| Provider | `name()` | File | Framing |
|----------|----------|------|---------|
| `AleProtocolProvider` | `"ale"` | [app_protocols/ale_provider.rs](../../src/app_protocols/ale_provider.rs) | ALEPKT DT/DI frames + AU1/AU2 handshake (UNISIG Subset-037/098), CRC-CCITT. |
| `RawProtocolProvider` | `"raw"` | [app_protocols/raw_provider.rs](../../src/app_protocols/raw_provider.rs) | 4-byte LE length prefix, no handshake. |

Used by the TLS/kTLS engine's UDP-over-TLS path
([tls_engine/](../../src/security/tls_engine/)).

## Example implementor (skeleton)

```rust
pub struct MyProtocolProvider;

impl AppProtocolProvider for MyProtocolProvider {
    fn name(&self) -> &str { "myproto" }
    fn description(&self) -> &str { "My framing" }
    fn create_session(&self) -> Box<dyn FramingSession> {
        Box::new(MySession::default())
    }
}

#[derive(Default)]
struct MySession { pending: Vec<u8> }

impl FramingSession for MySession {
    fn handshake_initiator(&mut self, _s: &mut dyn ReadWrite) -> io::Result<()> { Ok(()) }
    fn handshake_responder(&mut self, _s: &mut dyn ReadWrite) -> io::Result<()> { Ok(()) }
    fn frame_datagram(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        Ok(())
    }
    fn deframe(&mut self, data: &[u8]) -> io::Result<DeframeResult> {
        self.pending.extend_from_slice(data);
        // ... extract complete frames from self.pending ...
        Ok(DeframeResult { datagrams: Vec::new(), disconnected: false })
    }
    fn write_disconnect(&mut self, _s: &mut dyn ReadWrite) -> io::Result<()> { Ok(()) }
}
```

## Registration & selection

```rust
registry.register_app_protocol(Box::new(AleProtocolProvider));
registry.register_app_protocol(Box::new(RawProtocolProvider));
// registry.register_app_protocol(Box::new(MyProtocolProvider));  // ← add here
```

Selected per rule by `registry.find_app_protocol(&rule.app_protocol)` on the
UDP-over-TLS path.

```json
{ "security_provider": "tls", "listen_proto": "udp", "app_protocol": "myproto" }
```

## Conformance checklist

- [ ] `name()` is unique, stable, lowercase, and documented.
- [ ] `create_session()` returns independent sessions (no shared mutable state).
- [ ] `frame_datagram` appends to `out` and tolerates a non-empty `out`.
- [ ] `deframe` buffers partial frames and handles 0/1/N frames per call.
- [ ] Graceful peer close is reported via `DeframeResult.disconnected`.
- [ ] Handshake/disconnect methods are no-ops returning `Ok(())` when unused.
- [ ] Factory is `Send + Sync`; session is `Send`.
