//! Minimal TLS echo upstream for the local-interface cross-language runner.
//!
//! Binds a TCP port, completes a server-side TLS handshake using the gateway's
//! built-in self-signed certificate, and echoes every byte back. Prints
//! `LISTENING <ip:port>` on stdout once bound so a caller can discover an
//! ephemeral port (pass `127.0.0.1:0`).
//!
//! This exists only to give the example clients a reachable upstream; the
//! gateway connects to it as a TLS client exactly as it would to a real peer.

use std::io::{Read, Write};
use std::net::TcpListener;

use gateway::security::tls_engine::build_tls_acceptor;

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:0".to_string());

    let listener = TcpListener::bind(&addr).expect("bind tls_echo upstream");
    let local = listener.local_addr().expect("local_addr");
    println!("LISTENING {local}");
    let _ = std::io::stdout().flush();

    let acceptor = build_tls_acceptor(None).expect("build tls acceptor");
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        let acc = acceptor.clone();
        std::thread::spawn(move || {
            let mut tls = match acc.accept(stream) {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut buf = [0u8; 16 * 1024];
            loop {
                match tls.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if tls.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let _ = tls.flush();
                    }
                    Err(_) => break,
                }
            }
        });
    }
}
