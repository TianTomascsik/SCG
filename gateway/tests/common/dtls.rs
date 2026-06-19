//! Test-only DTLS (UDP) plumbing for the WP7 DTLS tests.
//!
//! The gateway's own `DtlsUdpStream` / DTLS builders are private, so the
//! integration tests build their own OpenSSL DTLS peers:
//!
//!   * [`UdpStream`]            — a `Read + Write` wrapper over a *connected*
//!     `UdpSocket`, as OpenSSL's DTLS expects.
//!   * [`DtlsEchoServer`]       — a DTLS server that echoes datagrams; used as
//!     the upstream for gateway **encrypt** rules (exercises the connector).
//!   * [`PlainUdpEchoServer`]   — a plain-UDP echo backend behind gateway
//!     **decrypt** rules.
//!   * [`dtls_client_round_trip`] — a raw DTLS client that drives a gateway
//!     **decrypt** rule (exercises the acceptor).

use std::io::{self, Read, Write};
use std::net::UdpSocket;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;

/// `Read + Write` over a connected `UdpSocket` for OpenSSL DTLS.
pub struct UdpStream(pub UdpSocket);

impl Read for UdpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf)
    }
}

impl Write for UdpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.send(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Resolve a DTLS version string to the OpenSSL version + an interoperable
/// cipher list (mirrors the gateway's own DTLS-version cipher policy).
fn version_and_ciphers(version: &str) -> (SslVersion, &'static str) {
    match version {
        "dtls1.0" => (
            SslVersion::DTLS1,
            "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA:AES256-SHA:@SECLEVEL=0",
        ),
        _ => (
            SslVersion::DTLS1_2,
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
             ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
        ),
    }
}

fn pin(builder: &mut SslContextBuilder, v: SslVersion) {
    builder.set_min_proto_version(Some(v)).unwrap();
    builder.set_max_proto_version(Some(v)).unwrap();
}

/// A DTLS echo server: each accepted session reflects datagrams verbatim.
/// Optionally requires + verifies a client certificate (mutual auth).
pub struct DtlsEchoServer {
    pub addr: String,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl DtlsEchoServer {
    /// `client_ca = Some(ca)` makes the server require a client cert that
    /// chains to `ca` (mutual auth); `None` accepts any client.
    pub fn start(
        version: &str,
        cert: &Path,
        key: &Path,
        client_ca: Option<&Path>,
    ) -> DtlsEchoServer {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();

        let (v, ciphers) = version_and_ciphers(version);
        let cert = X509::from_pem(&std::fs::read(cert).unwrap()).unwrap();
        let key = PKey::private_key_from_pem(&std::fs::read(key).unwrap()).unwrap();
        let client_ca = client_ca.map(|p| p.to_path_buf());

        let mut builder = openssl::ssl::SslAcceptor::mozilla_intermediate(SslMethod::dtls()).unwrap();
        builder.set_certificate(&cert).unwrap();
        builder.set_private_key(&key).unwrap();
        builder.check_private_key().unwrap();
        pin(&mut builder, v);
        builder.set_cipher_list(ciphers).unwrap();
        match &client_ca {
            Some(ca) => {
                builder.set_ca_file(ca).unwrap();
                builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            }
            None => builder.set_verify(SslVerifyMode::NONE),
        }
        let acceptor = builder.build();

        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = shutdown.clone();
        let handle = thread::spawn(move || {
            // Discover the first peer without consuming the ClientHello.
            while !sd.load(Ordering::Relaxed) {
                let mut peek = [0u8; 2048];
                let peer = match sock.peek_from(&mut peek) {
                    Ok((_, p)) => p,
                    Err(_) => continue, // timeout → re-check shutdown
                };
                if sock.connect(peer).is_err() {
                    continue;
                }
                let stream = match sock.try_clone() {
                    Ok(s) => UdpStream(s),
                    Err(_) => return,
                };
                match acceptor.accept(stream) {
                    Ok(mut ssl) => {
                        let mut buf = [0u8; 2048];
                        loop {
                            if sd.load(Ordering::Relaxed) {
                                break;
                            }
                            match ssl.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    if ssl.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                    let _ = ssl.flush();
                                }
                                Err(ref e)
                                    if e.kind() == io::ErrorKind::WouldBlock
                                        || e.kind() == io::ErrorKind::TimedOut =>
                                {
                                    continue
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    Err(_) => { /* handshake refused (negative tests) */ }
                }
                return; // one session is enough for the tests
            }
        });

        DtlsEchoServer {
            addr,
            shutdown,
            handle: Some(handle),
        }
    }
}

impl Drop for DtlsEchoServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// A plain-UDP echo backend (no DTLS) sitting behind a gateway decrypt rule.
pub struct PlainUdpEchoServer {
    pub addr: String,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl PlainUdpEchoServer {
    pub fn start() -> PlainUdpEchoServer {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = shutdown.clone();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !sd.load(Ordering::Relaxed) {
                match sock.recv_from(&mut buf) {
                    Ok((n, peer)) => {
                        let _ = sock.send_to(&buf[..n], peer);
                    }
                    Err(_) => continue,
                }
            }
        });
        PlainUdpEchoServer {
            addr,
            shutdown,
            handle: Some(handle),
        }
    }
}

impl Drop for PlainUdpEchoServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Drive a gateway **decrypt** rule as a raw DTLS client: handshake, send
/// `payload`, and return the echoed bytes. `client_identity` presents a client
/// certificate for mutual auth. Returns `Err` when the handshake or I/O fails
/// (asserted by the negative tests). The gateway's own certificate is not
/// verified (we are testing the gateway-as-server direction).
pub fn dtls_client_round_trip(
    gateway_addr: &str,
    version: &str,
    client_identity: Option<(&Path, &Path)>,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    sock.connect(gateway_addr)?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;

    let (v, ciphers) = version_and_ciphers(version);
    let mut builder = SslConnector::builder(SslMethod::dtls())
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_verify(SslVerifyMode::NONE);
    pin(&mut builder, v);
    builder
        .set_cipher_list(ciphers)
        .map_err(|e| io::Error::other(e.to_string()))?;
    if let Some((cert, key)) = client_identity {
        let cert = X509::from_pem(&std::fs::read(cert)?).map_err(|e| io::Error::other(e.to_string()))?;
        let key =
            PKey::private_key_from_pem(&std::fs::read(key)?).map_err(|e| io::Error::other(e.to_string()))?;
        builder.set_certificate(&cert).map_err(|e| io::Error::other(e.to_string()))?;
        builder.set_private_key(&key).map_err(|e| io::Error::other(e.to_string()))?;
    }
    let connector = builder.build();

    let mut ssl = connector
        .configure()
        .map_err(|e| io::Error::other(e.to_string()))?
        .verify_hostname(false)
        .use_server_name_indication(false)
        .connect("gateway", UdpStream(sock))
        .map_err(|_| io::Error::other("dtls handshake failed"))?;

    ssl.write_all(payload)?;
    ssl.flush()?;
    let mut buf = vec![0u8; payload.len()];
    ssl.read_exact(&mut buf)?;
    Ok(buf)
}
