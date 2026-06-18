//! Round-trip demo for the Rust client API.
//!
//! Connects to a running gateway's management socket, opens an endpoint bound
//! to a pipeline rule (`app_id` + traffic class + encrypt direction), sends a
//! payload, waits for the upstream's reply (relayed back through the gateway),
//! and prints it.
//!
//! Usage:
//! ```text
//! cargo run -p scg-client --example rust_roundtrip -- \
//!     --app app-telemetry --transport uds --class safety \
//!     [--mgmt /run/scg/management.sock] [--message "hello"]
//! ```
//!
//! Requires a gateway configured with a matching rule and a reachable upstream;
//! see the management-API docs. Exits non-zero on any error.

use std::process::ExitCode;
use std::time::Duration;

use scg_client::{Direction, ScgClient, TrafficClass, Transport};

struct Args {
    app: String,
    transport: Transport,
    class: TrafficClass,
    mgmt: Option<String>,
    message: String,
}

fn parse_args() -> Result<Args, String> {
    let mut app = None;
    let mut transport = Transport::Uds;
    let mut class = TrafficClass::Safety;
    let mut mgmt = None;
    let mut message = String::from("hello from scg-client");

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--app" => app = Some(it.next().ok_or("--app needs a value")?),
            "--transport" => {
                transport = match it.next().as_deref() {
                    Some("uds") => Transport::Uds,
                    Some("shm") => Transport::Shm,
                    other => return Err(format!("invalid --transport {other:?}")),
                }
            }
            "--class" => {
                class = match it.next().as_deref() {
                    Some("normal") => TrafficClass::Normal,
                    Some("safety") => TrafficClass::Safety,
                    other => return Err(format!("invalid --class {other:?}")),
                }
            }
            "--mgmt" => mgmt = Some(it.next().ok_or("--mgmt needs a value")?),
            "--message" => message = it.next().ok_or("--message needs a value")?,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    Ok(Args {
        app: app.ok_or("--app is required")?,
        transport,
        class,
        mgmt,
        message,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("argument error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mgmt = args.mgmt.as_deref().map(std::path::Path::new);
    let mut client = match ScgClient::connect(
        mgmt,
        &args.app,
        args.transport,
        args.class,
        Direction::Encrypt,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "connected: endpoint_id={} transport={:?}",
        client.endpoint_id(),
        args.transport
    );

    if let Err(e) = client.send(1, args.message.as_bytes()) {
        eprintln!("send failed: {e}");
        return ExitCode::FAILURE;
    }
    println!("sent {} bytes", args.message.len());

    match client.recv_timeout(Some(Duration::from_secs(5))) {
        Ok(Some((traffic_id, payload))) => {
            println!(
                "recv: traffic_id={traffic_id} {} bytes: {:?}",
                payload.len(),
                String::from_utf8_lossy(&payload)
            );
        }
        Ok(None) => {
            eprintln!("recv timed out (no reply within 5s)");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("recv failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    if let Err(e) = client.close() {
        eprintln!("close failed: {e}");
        return ExitCode::FAILURE;
    }
    println!("closed");
    ExitCode::SUCCESS
}
