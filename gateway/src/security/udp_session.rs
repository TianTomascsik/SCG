//! Shared per-peer UDP session helpers used by the DTLS engine and the plaintext
//! UDP routing relay.
//!
//! Because UDP is connectionless and source-address-spoofable, any relay that maps
//! each new source `SocketAddr` to its own session (a connected upstream socket)
//! must bound that state or a spoofed-source flood exhausts file descriptors /
//! memory (TRA #37 for DTLS, #81 for routing). These helpers centralise the
//! admission cap and idle-session selection so both engines bound spoofed-source
//! state identically:
//!
//! * [`session_admitted`] — refuse a *new* peer once the cap is reached
//!   (call **before** any policy/classify work — admission-before-classify).
//! * [`stale_peers`] — select peers idle for at least `ttl`, for eviction.
//!
//! Both are pure so they are unit-testable without sockets; callers apply the
//! selection plus their own per-session-type teardown.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Default maximum concurrent per-peer UDP sessions (admission cap). Matches the
/// DTLS engine's `DEFAULT_DTLS_MAX_SESSIONS` so the plaintext routing path and the
/// DTLS path bound spoofed-source state the same way.
pub(crate) const DEFAULT_UDP_MAX_SESSIONS: usize = 1024;

/// Default idle-session eviction timeout, in seconds.
pub(crate) const DEFAULT_UDP_IDLE_TTL_SECS: u64 = 60;

/// Whether a *new* peer session may be admitted given the current count and the
/// configured maximum. Pure (testable without sockets).
pub(crate) fn session_admitted(current: usize, max: usize) -> bool {
    current < max
}

/// Peers whose last activity is at least `ttl` in the past, relative to `now`.
/// Pure (testable without sockets); callers apply the result plus their own
/// per-session teardown (e.g. `ssl.shutdown()` for DTLS, socket drop for routing).
pub(crate) fn stale_peers(
    last_activity: &[(SocketAddr, Instant)],
    ttl: Duration,
    now: Instant,
) -> Vec<SocketAddr> {
    last_activity
        .iter()
        .filter(|(_, last)| now.saturating_duration_since(*last) >= ttl)
        .map(|(peer, _)| *peer)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_respects_cap() {
        assert!(session_admitted(0, 2));
        assert!(session_admitted(1, 2));
        assert!(!session_admitted(2, 2), "at the cap, a new peer is refused");
        assert!(!session_admitted(3, 2));
        // A zero cap admits nothing.
        assert!(!session_admitted(0, 0));
    }

    #[test]
    fn stale_peers_selects_only_the_idle() {
        let now = Instant::now();
        let ttl = Duration::from_secs(10);
        let fresh = now; // 0s idle
        let idle = now
            .checked_sub(Duration::from_secs(20))
            .expect("test clock supports 20s in the past");
        let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let selected = stale_peers(&[(a, fresh), (b, idle)], ttl, now);
        assert_eq!(selected, vec![b], "only the >=ttl-idle peer is evicted");
        // Exactly-at-ttl counts as stale (>=).
        let at = now.checked_sub(ttl).unwrap_or(now);
        assert_eq!(stale_peers(&[(a, at)], ttl, now), vec![a]);
    }
}
