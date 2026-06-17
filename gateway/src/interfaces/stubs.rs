//! Stub modules for unimplemented Application Interfaces & Workers.

// TODO: Sender per App
// - Dedicated outbound sender per application/rule
// - Traffic shaping and rate limiting per sender
// - Connection pooling for persistent upstreams

// TODO: Traffic Mirror
// - Tap/mirror traffic to a secondary destination for monitoring
// - Configurable mirror targets per rule
// - Selective mirroring (e.g., only first N bytes, only metadata)

// TODO: UDS Reader/Writer (Unix Domain Socket)
// - Accept connections on Unix domain sockets
// - Forward to/from TLS-protected channels
// - Used for local inter-process communication protection

// TODO: Shared Memory Reader/Writer
// - Read/write via POSIX shared memory segments
// - Zero-copy data transfer for co-located processes
// - Integration with Traffic Scheduler for ordering
