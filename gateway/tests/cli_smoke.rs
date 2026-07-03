//! CLI smoke tests — exercise the real `gateway` binary end-to-end.
//!
//! Everything else in the suite drives the library API in-process, so the
//! process bootstrap in `lib.rs::run()` (argument handling, config loading,
//! `--validate`, pipeline startup, hot-reload, and graceful shutdown) was
//! previously untested. These tests spawn the actual instrumented binary via
//! `CARGO_BIN_EXE_gateway`; `cargo llvm-cov` attributes the child process's
//! coverage back to the library, so they close the biggest coverage gap while
//! also giving the binary its only end-to-end regression test.
//!
//! Runs unprivileged: the boot configs use loopback + self-signed TLS and carry
//! no `intercept` block, so no firewall/CAP_NET_ADMIN setup is triggered.

mod common;

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::temp_dir;

/// Path to the built `gateway` binary (Cargo sets this for integration tests).
fn gateway_bin() -> &'static str {
    env!("CARGO_BIN_EXE_gateway")
}

/// Grab an ephemeral loopback port, then release it for the gateway to bind.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// A minimal, unprivileged boot config: one loopback TLS encrypt rule (self-
/// signed, `verify=none`, `safety` class so the default deny-all policy passes),
/// the management gRPC API on a temp UDS, and an allow-all policy block so the
/// traffic pipeline (analyzer/policy/lifecycle) is instantiated.
fn boot_config(listen_port: u16, tmp: &Path) -> String {
    let mgmt = tmp.join("mgmt.sock");
    let run = tmp.join("run");
    format!(
        r#"{{
            "rules": [{{
                "name": "boot-encrypt",
                "direction": "encrypt",
                "listen_addr": "127.0.0.1:{listen_port}",
                "listen_proto": "tcp",
                "upstream_addr": "127.0.0.1:{upstream}",
                "upstream_proto": "tcp",
                "security_provider": "tls",
                "verify": "none",
                "traffic_class": "safety"
            }}],
            "policy": {{ "default_action": "allow", "whitelist": [] }},
            "api": {{
                "enabled": true,
                "uds_path": "{mgmt}",
                "runtime_dir": "{run}"
            }}
        }}"#,
        listen_port = listen_port,
        upstream = free_port(),
        mgmt = mgmt.display(),
        run = run.display(),
    )
}

/// Poll until `127.0.0.1:port` accepts a TCP connection or the timeout elapses.
fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let addr = format!("127.0.0.1:{port}");
    while Instant::now() < deadline {
        if TcpStream::connect(&addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

/// Send `signal` to `child` (via `kill(2)`).
fn send_signal(child: &Child, signal: libc::c_int) {
    // SAFETY: `kill(2)` takes no pointers; `child.id()` is this test's own child
    // pid, valid for the lifetime of `child`. The return value is best-effort.
    unsafe {
        libc::kill(child.id() as libc::pid_t, signal);
    }
}

/// Wait up to `timeout` for `child` to exit, returning its exit code. Fails the
/// test (after SIGKILL) if it hangs — a hang means the graceful-shutdown path
/// did not complete (the in-process watchdog would `_exit(1)` after 5 s, which
/// also skips the coverage flush, so we never want to see that here).
fn wait_for_exit(child: &mut Child, timeout: Duration) -> i32 {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait().expect("try_wait on gateway child") {
            Some(status) => return status.code().unwrap_or(-1),
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("gateway did not exit within {timeout:?} after shutdown signal");
}

// ── Argument / validation paths (fast, no boot) ──────────────────────────────

#[test]
fn help_prints_usage_and_exits_zero() {
    let out = Command::new(gateway_bin())
        .arg("--help")
        .output()
        .expect("spawn gateway --help");
    assert!(out.status.success(), "--help should exit 0");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Usage:"),
        "usage text expected on stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("Security providers:"),
        "provider list expected in usage, got: {stderr}"
    );
}

#[test]
fn no_args_prints_usage_and_exits_zero() {
    let out = Command::new(gateway_bin())
        .output()
        .expect("spawn gateway with no args");
    assert!(
        out.status.success(),
        "no-args should print usage and exit 0"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Usage:"),
        "usage text expected, got: {stderr}"
    );
}

#[test]
fn validate_good_config_succeeds() {
    // A simple, unprivileged config (no transparent/intercept rules, so preflight
    // raises no CAP_NET_ADMIN error): `--validate` must load it, run preflight,
    // and exit 0. (The shipped `gateway.example.json` intentionally exercises
    // TPROXY, which hard-fails preflight without CAP_NET_ADMIN — not usable here.)
    let tmp = temp_dir("cli-validate");
    let cfg_path = tmp.join("gw.json");
    let json = format!(
        r#"{{ "rules": [{{
            "name": "validate-me",
            "direction": "encrypt",
            "listen_addr": "127.0.0.1:{port}",
            "listen_proto": "tcp",
            "upstream_addr": "127.0.0.1:9",
            "upstream_proto": "tcp",
            "security_provider": "routing",
            "traffic_class": "normal"
        }}] }}"#,
        port = free_port(),
    );
    std::fs::write(&cfg_path, json).unwrap();

    let out = Command::new(gateway_bin())
        .args(["--validate", "--config", cfg_path.to_str().unwrap()])
        .output()
        .expect("spawn gateway --validate");
    assert!(
        out.status.success(),
        "--validate on a clean config should exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn validate_honours_log_level_flags() {
    // Drives the log-level resolution arms in `run()`: an explicit level and an
    // unknown level (which warns and falls back to "info"); both still validate
    // a clean config and exit 0.
    let tmp = temp_dir("cli-loglvl");
    let cfg_path = tmp.join("gw.json");
    let json = format!(
        r#"{{ "rules": [{{
            "name": "lvl", "direction": "encrypt",
            "listen_addr": "127.0.0.1:{port}", "listen_proto": "tcp",
            "upstream_addr": "127.0.0.1:9", "upstream_proto": "tcp",
            "security_provider": "routing", "traffic_class": "normal"
        }}] }}"#,
        port = free_port(),
    );
    std::fs::write(&cfg_path, json).unwrap();

    for level in ["debug", "totally-bogus-level"] {
        let out = Command::new(gateway_bin())
            .args(["--validate", "--config", cfg_path.to_str().unwrap()])
            .args(["--log-level", level])
            .output()
            .expect("spawn gateway --validate --log-level");
        assert!(
            out.status.success(),
            "--validate with --log-level {level} should exit 0; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn validate_missing_config_fails() {
    let out = Command::new(gateway_bin())
        .args([
            "--validate",
            "--config",
            "/nonexistent/scg-does-not-exist.json",
        ])
        .output()
        .expect("spawn gateway --validate on a bad path");
    assert!(
        !out.status.success(),
        "--validate on a missing config should exit non-zero"
    );
}

#[test]
fn missing_config_flag_errors() {
    // Neither --config nor --config-dir: the `run()` arg resolver must error out.
    let out = Command::new(gateway_bin())
        .arg("--log-level")
        .arg("warn")
        .output()
        .expect("spawn gateway without a config source");
    assert!(
        !out.status.success(),
        "a run without --config/--config-dir should exit non-zero"
    );
}

// ── Full boot + graceful shutdown ────────────────────────────────────────────

#[test]
fn boot_then_sigterm_shuts_down_cleanly() {
    let tmp = temp_dir("cli-boot");
    let port = free_port();
    let cfg_path = tmp.join("gw.json");
    std::fs::write(&cfg_path, boot_config(port, &tmp)).unwrap();

    let mut child = Command::new(gateway_bin())
        .args(["--config", cfg_path.to_str().unwrap(), "--log-stdout"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gateway boot");

    assert!(
        wait_for_port(port, Duration::from_secs(10)),
        "gateway listener never came up"
    );

    // Single SIGTERM → the signal handler flips the shutdown flag and `run()`
    // drains + tears down and returns normally (exit 0). A second signal would
    // force `_exit`, so we send exactly one.
    send_signal(&child, libc::SIGTERM);
    let code = wait_for_exit(&mut child, Duration::from_secs(10));
    assert_eq!(code, 0, "clean SIGTERM shutdown should exit 0");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn boot_then_sighup_reloads_then_sigterm() {
    let tmp = temp_dir("cli-reload");
    let port = free_port();
    let cfg_path = tmp.join("gw.json");
    std::fs::write(&cfg_path, boot_config(port, &tmp)).unwrap();

    let mut child = Command::new(gateway_bin())
        .args(["--config", cfg_path.to_str().unwrap(), "--watch"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gateway boot for reload");

    assert!(
        wait_for_port(port, Duration::from_secs(10)),
        "gateway listener never came up"
    );

    // Rewrite the config with a changed rule (different upstream) plus an added
    // rule, then SIGHUP: this drives the reload closure's `changed`/`added`
    // branches, the audit line, interface-manager re-auth, and the lifecycle
    // event — none of which the in-process tests reach.
    let port2 = free_port();
    let mgmt = tmp.join("mgmt.sock");
    let run = tmp.join("run");
    let reloaded = format!(
        r#"{{
            "rules": [
                {{
                    "name": "boot-encrypt",
                    "direction": "encrypt",
                    "listen_addr": "127.0.0.1:{port}",
                    "listen_proto": "tcp",
                    "upstream_addr": "127.0.0.1:{new_upstream}",
                    "upstream_proto": "tcp",
                    "security_provider": "tls",
                    "verify": "none",
                    "traffic_class": "safety"
                }},
                {{
                    "name": "boot-encrypt-2",
                    "direction": "encrypt",
                    "listen_addr": "127.0.0.1:{port2}",
                    "listen_proto": "tcp",
                    "upstream_addr": "127.0.0.1:{new_upstream}",
                    "upstream_proto": "tcp",
                    "security_provider": "tls",
                    "verify": "none",
                    "traffic_class": "safety"
                }}
            ],
            "policy": {{ "default_action": "allow", "whitelist": [] }},
            "api": {{ "enabled": true, "uds_path": "{mgmt}", "runtime_dir": "{run}" }}
        }}"#,
        port = port,
        port2 = port2,
        new_upstream = free_port(),
        mgmt = mgmt.display(),
        run = run.display(),
    );
    let mut f = std::fs::File::create(&cfg_path).unwrap();
    f.write_all(reloaded.as_bytes()).unwrap();
    f.sync_all().unwrap();
    drop(f);

    send_signal(&child, libc::SIGHUP);
    // The watcher reloads on the SIGHUP flag within its ~2 s poll; give it room
    // to apply the diff and bring up the added rule before we tear down.
    assert!(
        wait_for_port(port2, Duration::from_secs(10)),
        "reloaded (added) rule's listener never came up"
    );

    send_signal(&child, libc::SIGTERM);
    let code = wait_for_exit(&mut child, Duration::from_secs(10));
    assert_eq!(code, 0, "clean SIGTERM shutdown after reload should exit 0");

    let _ = std::fs::remove_dir_all(&tmp);
}
