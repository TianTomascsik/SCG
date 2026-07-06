# 06 — Transport Interface

> **Status:** 🟡 Proposed · **Traits:** `TransportFactory`, `TransportListener`,
> `TransportConnector`, `Conn` ·
> **Abstracts:** [networking/connector.rs](../../src/networking/connector.rs),
> [networking/socket_manager.rs](../../src/networking/socket_manager.rs),
> [interfaces/tproxy.rs](../../src/interfaces/tproxy.rs) ·
> **Stub:** [traits/transport.rs](traits/transport.rs)

## Purpose

Abstract the **byte-moving layer** so the same security engine can run over
different transports — TCP, UDP, Unix domain sockets (UDS), or shared memory
(SHM) — selected by configuration. The repository already contains transport
benchmarks for exactly these
([bench_tcp](../../../benches/bench_tcp/), [bench_udp](../../../benches/bench_udp/),
[bench_uds](../../../benches/bench_uds/), [bench_shm](../../../benches/bench_shm/)),
which is strong evidence that transport interchangeability is an intended axis of
extension. This interface makes that axis a first-class, swappable boundary.

## Why an interface is needed

Today transport is a set of free functions and concrete std types:

- TCP connect-with-retry in [connector.rs](../../src/networking/connector.rs).
- Raw socket tuning (`SO_SNDBUF`/`SO_RCVBUF`, `TCP_NODELAY`, quickack, cork) over
  `RawFd` in [socket_manager.rs](../../src/networking/socket_manager.rs).
- TPROXY listeners/sockets in [interfaces/tproxy.rs](../../src/interfaces/tproxy.rs).
- Engines bind `TcpListener`/`UdpSocket` directly.

There is no seam to substitute UDS or SHM, and TPROXY vs. normal sockets is
branched in-line. A `TransportFactory` provides one place to construct listeners
and connectors, so engines depend on `Conn`/`Datagram` traits instead of
`TcpStream`/`UdpSocket`.

## Traits

```rust
pub trait TransportFactory: Send + Sync {
    fn name(&self) -> &str;                 // "tcp" | "udp" | "uds" | "shm"
    fn kind(&self) -> TransportKind;        // Stream | Datagram
    fn listener(&self, ep: &Endpoint, opts: &SocketOptions) -> io::Result<Box<dyn TransportListener>>;
    fn connector(&self) -> Box<dyn TransportConnector>;
}

/// Stream transports (TCP, UDS-stream, SHM-stream).
pub trait TransportListener: Send {
    fn accept(&self) -> io::Result<(Box<dyn Conn>, PeerAddr)>;
    fn local_addr(&self) -> io::Result<PeerAddr>;
    fn set_nonblocking(&self, nb: bool) -> io::Result<()>;
}

pub trait TransportConnector: Send + Sync {
    fn connect(&self, ep: &Endpoint, opts: &SocketOptions, shutdown: &AtomicBool)
        -> io::Result<Box<dyn Conn>>;
}

/// A bidirectional stream connection.
pub trait Conn: io::Read + io::Write + Send {
    fn peer_addr(&self) -> io::Result<PeerAddr>;
    fn original_dst(&self) -> Option<PeerAddr>;   // TPROXY SO_ORIGINAL_DST, if any
    fn raw_fd(&self) -> Option<RawFd>;            // for kTLS/sockopt; None for SHM
    fn shutdown_write(&self) -> io::Result<()>;
}

/// Datagram transports (UDP, UDS-datagram).
pub trait DatagramSocket: Send + Sync {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, PeerAddr, Option<PeerAddr>)>;
    fn send_to(&self, buf: &[u8], dst: &PeerAddr) -> io::Result<usize>;
    fn local_addr(&self) -> io::Result<PeerAddr>;
    fn raw_fd(&self) -> Option<RawFd>;
}
```

## Method contracts

| Method | Contract |
|--------|----------|
| `TransportFactory::kind` | Declares whether the transport is `Stream` or `Datagram`; the core checks this against the rule's needs. |
| `listener(ep, opts)` | Binds and applies `opts` (buffer sizes, nodelay, transparent/TPROXY). For TPROXY, sets `IP_TRANSPARENT` and enables original-dst recovery. |
| `accept()` | Blocking accept; returns a `Conn` and the peer address. Honour `set_nonblocking`. |
| `connect(ep, opts, shutdown)` | Connect with the existing retry/backoff semantics, polling `shutdown` (mirrors `connect_with_retry`). |
| `Conn::raw_fd` | `Some(fd)` for kernel-backed transports (enables kTLS offload and sockopt tuning); `None` for SHM. Engines needing a real fd must check. |
| `Conn::original_dst` | `Some(addr)` only under TPROXY; drives `upstream_addr: "auto"`. |
| `DatagramSocket::recv_from` | Returns payload, source, and (under TPROXY) the original destination. |

## Data types

```rust
pub enum TransportKind { Stream, Datagram }

pub struct Endpoint {
    pub addr: String,        // "0.0.0.0:8080", "/run/scg.sock", "shm:region1"
    pub transparent: bool,   // TPROXY
}

pub struct SocketOptions {
    pub send_buf: Option<usize>,
    pub recv_buf: Option<usize>,
    pub nodelay: bool,
    pub quickack: bool,
    pub reuse_addr: bool,
}

pub enum PeerAddr { Ip(std::net::SocketAddr), Unix(String), Shm(String) }
```

## Lifecycle & threading

- **Construct factory:** one per transport kind, `Send + Sync`, registered by name.
- **Listener:** owned by the rule's run loop (`Send`); per-connection `Conn`
  objects are moved onto pool threads.
- **Connector:** shared (`Send + Sync`); `connect` honours the shutdown flag.
- **Shutdown:** listeners/sockets dropped; `Conn::shutdown_write` for half-close.

## Mapping from current code

| Today | Interface |
|-------|-----------|
| `TcpListener::bind` + `tune_socket_buffers`/`set_nodelay` | `factory.listener(ep, opts)` (tcp factory). |
| `connect_with_retry(addr, …, shutdown)` | `TransportConnector::connect(ep, opts, shutdown)`. |
| `tproxy::create_transparent_tcp_listener` / `create_transparent_udp_socket` | tcp/udp factory with `Endpoint.transparent = true`. |
| `tproxy::get_original_dst` | `Conn::original_dst` / `recv_from`'s original-dst out-param. |
| `ProxyStream::raw_fd()` | `Conn::raw_fd()`. |

## Example implementor (skeleton)

```rust
pub struct TcpTransport;

impl TransportFactory for TcpTransport {
    fn name(&self) -> &str { "tcp" }
    fn kind(&self) -> TransportKind { TransportKind::Stream }
    fn listener(&self, ep: &Endpoint, opts: &SocketOptions) -> io::Result<Box<dyn TransportListener>> {
        // bind (transparent or normal), apply opts, return a TcpListenerAdapter
        todo!()
    }
    fn connector(&self) -> Box<dyn TransportConnector> { Box::new(TcpConnector) }
}
```

## Selection

> **Note — proposed vs as-built.** The `TransportFactory` seam and a `transport`
> selector key below are *proposed*. As-built there is **no `transport` key**:
> all four transports are chosen by **`listen_proto`** (`"tcp"|"udp"|"uds"|"shm"`),
> and — critically — **UDS/SHM are not statically bound at a fixed path**. They are
> **dynamically provisioned per app / traffic class** through the management API
> (see [10 — Management API](10-management-api.md) and
> [09 — Configuration](09-configuration.md)); a `uds`/`shm` rule uses
> `"listen_addr": "local"`, not a socket path.

```json
{ "transport": "uds", "listen_addr": "/run/scg/in.sock", "upstream_addr": "/run/scg/out.sock" }
```

(For IP transports the existing `listen_proto: "tcp"|"udp"` continues to select
the factory; `transport` generalizes it to `uds`/`shm`.)

## Conformance checklist

- [ ] `kind()` correctly classifies Stream vs Datagram.
- [ ] `SocketOptions` (buffers, nodelay, quickack, transparent) are applied.
- [ ] `connect` honours the shutdown flag and uses bounded retry/backoff.
- [ ] `Conn::raw_fd` returns `Some` for kernel-backed transports, `None` for SHM.
- [ ] TPROXY original-destination is exposed for `upstream_addr: "auto"`.
- [ ] Half-close via `shutdown_write` is supported for stream transports.
- [ ] Factory/connector are `Send + Sync`; listeners/conns are `Send`.

---

## Implemented — UDS & SHM local interfaces

The UDS and SHM transports are **implemented today** as on-demand *local
interfaces* rather than statically-bound listeners. They are provisioned per
application and per traffic class through the management API; the wire and
security details live in [Architecture.md](../../Architecture.md) → *Local
Interfaces* and [10 — Management API](10-management-api.md). Transport-relevant
specifics:

- **UDS** ([src/interfaces/uds.rs](../../src/interfaces/uds.rs)) is a **transparent
  byte pipe**: the gateway's TLS byte stream (`[len][traffic_id][data]` frames)
  passes through untouched, so a UDS client and an SHM client interoperate
  end-to-end. The endpoint socket is `0600`, owned by the authorized uid, inside
  a per-uid `0700` directory.
- **SHM** ([src/interfaces/shm.rs](../../src/interfaces/shm.rs)) uses **two
  unidirectional rings** (client→gateway, gateway→client) in a sealed memfd. The
  client-readable ring is `F_SEAL_WRITE` so the client maps it **read-only**
  (`Conn::raw_fd` is `None`, matching the checklist). Descriptors are handed to
  the client over the control socket via `SCM_RIGHTS`.
- **Wakeup** defaults to **eventfd** so the single-threaded relay can multiplex
  the upstream fd and the ring notification through one `poll`/`epoll`. The
  trade-off (eventfd vs. strict/hybrid futex vs. busy-poll) is quantified by the
  `wakeup_bench` micro-benchmark in
  [SCG-Interface-benchmarks/bench_shm](../../../SCG-Interface-benchmarks/bench_shm);
  busy-poll/hybrid remain available as a dedicated-core low-latency knob.
