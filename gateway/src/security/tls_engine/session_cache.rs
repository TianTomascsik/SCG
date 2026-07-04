//! Client-side (gateway→upstream) TLS session cache for resumption (task S2).
//!
//! The gateway previously never resumed to an upstream: `apply_resumption` set only
//! `SslSessionCacheMode::CLIENT` and every per-endpoint `SslConnector` connected once and
//! dropped its cache, so each gateway→upstream handshake was full. This module lets a
//! reconnect to the *same* upstream under the *same* crypto policy resume, amortising the
//! handshake — driven by the rule's `resumption` toggle (default `false`, so behaviour is
//! unchanged unless opted in).
//!
//! Design controls (TRA register #78–#80, TB2):
//!   * **#78 cross-peer / cross-policy reuse** — sessions are keyed by a *full* upstream
//!     identity + crypto-policy fingerprint ([`resumption_key`]): a cached ticket is only
//!     ever presented on a byte-identical reconnect to the same peer under the same posture.
//!   * **#79 resumption across a tightened posture** — the key includes the verify mode and
//!     CA/cert paths, so a hot-reload that tightens verification *misses* the cache and forces
//!     a fresh, fully-verified handshake.
//!   * **#80 unbounded growth** — the store is bounded ([`MAX_CACHED_SESSIONS`]) with FIFO
//!     eviction. Sessions are held as opaque DER bytes (never logged — secret material, A3)
//!     and only `Vec<u8>` crosses threads, so no `SSL_SESSION` is shared between threads.
//!
//! **No 0-RTT:** early_data / TLS 1.3 0-RTT is never enabled, so there is no replay window
//! (a future 0-RTT change would need its own TRA).

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};

use openssl::ex_data::Index;
use openssl::ssl::{Ssl, SslContextBuilder, SslRef, SslSession, SslSessionCacheMode};

use super::params::TlsSecurityParams;

/// Hard cap on distinct (upstream × policy) sessions cached at once — a memory-DoS bound
/// (TRA #80). Distinct upstream targets are normally few and operator-configured.
const MAX_CACHED_SESSIONS: usize = 256;

/// Bounded DER-session store with FIFO eviction. Keyed by [`resumption_key`].
struct SessionStore {
    map: HashMap<String, Vec<u8>>,
    order: VecDeque<String>,
}

impl SessionStore {
    fn insert(&mut self, key: String, der: Vec<u8>) {
        if self.map.insert(key.clone(), der).is_none() {
            self.order.push_back(key);
            while self.order.len() > MAX_CACHED_SESSIONS {
                if let Some(evicted) = self.order.pop_front() {
                    self.map.remove(&evicted);
                }
            }
        }
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.map.get(key).cloned()
    }
}

fn store() -> &'static Mutex<SessionStore> {
    static STORE: OnceLock<Mutex<SessionStore>> = OnceLock::new();
    STORE.get_or_init(|| {
        Mutex::new(SessionStore {
            map: HashMap::new(),
            order: VecDeque::new(),
        })
    })
}

/// The `SSL`-level ex-data slot holding this connection's resumption key, so the
/// new-session callback (fired when the ticket arrives) knows where to file it.
/// Allocation only fails under catastrophic OOM at startup; on failure resumption
/// simply does not engage (a full handshake — fail-safe), never a panic.
fn key_index() -> Option<Index<Ssl, String>> {
    static IDX: OnceLock<Option<Index<Ssl, String>>> = OnceLock::new();
    *IDX.get_or_init(|| Ssl::new_ex_index::<String>().ok())
}

/// Full upstream-identity + crypto-policy fingerprint for the session store.
///
/// Every field that changes the peer identity or the negotiated security posture is folded
/// in, so a cached session is only ever reused on a byte-identical reconnect to the same peer
/// (TRA #78) and a tightened verify/cert posture misses the cache (TRA #79). PSK *key bytes*
/// are deliberately excluded (secret); the PSK identity distinguishes policies.
pub(crate) fn resumption_key(
    params: &TlsSecurityParams,
    upstream_addr: &str,
    ktls: bool,
) -> String {
    let path = |p: &Option<std::path::PathBuf>| {
        p.as_ref()
            .map(|v| v.display().to_string())
            .unwrap_or_default()
    };
    format!(
        "{addr}|sni={sni}|v={ver}|verify={verify:?}|ca={ca}|cert={cert}|psk={psk}|cl={cl}|cs={cs}|ktls={ktls}",
        addr = upstream_addr,
        sni = params.server_name.as_deref().unwrap_or(""),
        ver = params.version.as_deref().unwrap_or(""),
        verify = params.verify,
        ca = path(&params.ca_path),
        cert = path(&params.cert_path),
        psk = params.psk_identity.as_deref().unwrap_or(""),
        cl = params.cipher_list.as_deref().unwrap_or(""),
        cs = params.ciphersuites.as_deref().unwrap_or(""),
        ktls = ktls,
    )
}

/// Install the client session cache on a connector context: enable the OpenSSL client cache
/// and register a new-session callback that files each issued ticket (as DER) under the
/// connection's primed [`resumption_key`]. Called from `apply_resumption` when a client
/// connector has `resumption` enabled. No-ops the capture if the ex-data slot is unavailable.
pub(super) fn install_client_session_cache(builder: &mut SslContextBuilder) {
    builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    let Some(idx) = key_index() else {
        return;
    };
    builder.set_new_session_callback(move |ssl: &mut SslRef, session: SslSession| {
        // Only cache when a key was primed on this SSL (i.e. the resumption path ran) and the
        // ticket is from a completed — therefore fully-verified — handshake.
        if let Some(key) = ssl.ex_data(idx) {
            if let Ok(der) = session.to_der() {
                if let Ok(mut s) = store().lock() {
                    s.insert(key.clone(), der);
                }
            }
        }
    });
}

/// Prime a client SSL/connect-configuration for resumption *before* the handshake: present a
/// cached ticket for this exact upstream+policy if one exists, and record the key so the
/// new-session callback can store the fresh ticket. Called at the upstream connect site when
/// the rule enables `resumption`.
pub(crate) fn prime_resumption(ssl: &mut SslRef, key: String) {
    let Some(idx) = key_index() else {
        return;
    };
    if let Ok(s) = store().lock() {
        if let Some(der) = s.get(&key) {
            if let Ok(session) = SslSession::from_der(&der) {
                // SAFETY: `session` is a freshly-deserialized `SSL_SESSION` owned by this
                // scope and valid for the call; `set_session` copies it into the SSL and does
                // not retain the reference. The session can only have been cached under this
                // exact (upstream + full crypto-policy) key — which includes verify mode and
                // CA/cert (TRA #78/#79) — so it cannot be presented to a different peer or
                // resume across a weaker/looser posture.
                unsafe {
                    let _ = ssl.set_session(&session);
                }
            }
        }
    }
    ssl.set_ex_data(idx, key);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::tls_engine::params::{TlsProfile, VerifyMode};

    fn params(verify: VerifyMode, ca: Option<&str>) -> TlsSecurityParams {
        TlsSecurityParams {
            version: Some("tls1.3".into()),
            profile: TlsProfile::Default,
            verify,
            cert_path: None,
            key_path: None,
            ca_path: ca.map(Into::into),
            server_name: Some("upstream.example".into()),
            psk_identity: None,
            psk_key: None,
            cipher_list: None,
            ciphersuites: None,
            resumption: true,
            max_sessions: 1024,
            idle_ttl_secs: 60,
        }
    }

    #[test]
    fn key_distinguishes_peer_and_posture() {
        let p = params(VerifyMode::Server, Some("/etc/ca.pem"));
        let base = resumption_key(&p, "10.0.0.1:443", false);
        // Same peer + policy → identical key (would resume).
        assert_eq!(base, resumption_key(&p, "10.0.0.1:443", false));
        // Different upstream → different key (TRA #78: no cross-peer reuse).
        assert_ne!(base, resumption_key(&p, "10.0.0.2:443", false));
        // Tightened/loosened verify → different key (TRA #79: no cross-posture resume).
        assert_ne!(
            base,
            resumption_key(
                &params(VerifyMode::None, Some("/etc/ca.pem")),
                "10.0.0.1:443",
                false
            )
        );
        // Different CA → different key (TRA #79).
        assert_ne!(
            base,
            resumption_key(
                &params(VerifyMode::Server, Some("/etc/other.pem")),
                "10.0.0.1:443",
                false
            )
        );
        // kTLS vs userspace → different key.
        assert_ne!(base, resumption_key(&p, "10.0.0.1:443", true));
    }

    #[test]
    fn store_is_bounded_with_fifo_eviction() {
        let mut s = SessionStore {
            map: HashMap::new(),
            order: VecDeque::new(),
        };
        for i in 0..(MAX_CACHED_SESSIONS + 50) {
            s.insert(format!("k{i}"), vec![i as u8]);
        }
        assert_eq!(s.map.len(), MAX_CACHED_SESSIONS); // TRA #80: bounded
        assert!(s.get("k0").is_none()); // oldest evicted
        assert!(s.get(&format!("k{}", MAX_CACHED_SESSIONS + 49)).is_some()); // newest kept
    }

    /// End-to-end: with resumption wired, a second connection to the same upstream under the
    /// same policy actually resumes (`session_reused()`), while a different-policy key does not.
    /// Drives the real `build_tls_connector` + `prime_resumption` + new-session callback path.
    #[test]
    fn second_connection_resumes_same_key_only() {
        use crate::security::tls_engine::{build_tls_acceptor, build_tls_connector};
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        // TLS 1.3 upstream that offers tickets (resumption=true) and echoes one byte.
        let mut server = params(VerifyMode::None, None);
        server.resumption = true;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_s = stop.clone();
        let acceptor = build_tls_acceptor(&server).expect("acceptor");
        let handle = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if stop_s.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(sock) = conn else { break };
                if let Ok(mut tls) = acceptor.accept(sock) {
                    let mut b = [0u8; 1];
                    if tls.read(&mut b).map(|n| n > 0).unwrap_or(false) {
                        let _ = tls.write_all(&b);
                        let _ = tls.flush();
                    }
                }
            }
        });

        // Client with resumption enabled; verify=None accepts the self-signed upstream cert.
        let client = {
            let mut c = params(VerifyMode::None, None);
            c.resumption = true;
            c
        };
        let connector = build_tls_connector(&client).expect("connector");
        let key = resumption_key(&client, &addr, false);

        // One request/echo cycle; returns whether this handshake resumed. The read is what
        // delivers the TLS 1.3 NewSessionTicket, so connection N's ticket is cached for N+1.
        let one = |k: &str| -> bool {
            let tcp = TcpStream::connect(&addr).expect("connect");
            let mut cfg = connector.configure().expect("configure");
            cfg.set_verify_hostname(false);
            prime_resumption(&mut cfg, k.to_string());
            let mut s = cfg.connect("localhost", tcp).expect("tls connect");
            let reused = s.ssl().session_reused();
            s.write_all(b"x").expect("write");
            let mut b = [0u8; 1];
            let _ = s.read(&mut b);
            reused
        };

        assert!(!one(&key), "first handshake must be full");
        assert!(
            one(&key),
            "second handshake to same upstream+policy must resume"
        );
        // A different (upstream×policy) key must NOT resume — no cross-peer/policy reuse (#78).
        let other_key = format!("{key}|different-policy");
        assert!(!one(&other_key), "a different key must not resume");

        stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(&addr); // unblock accept()
        let _ = handle.join();
    }
}
