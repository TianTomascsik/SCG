//! Kernel WireGuard interface lifecycle via the `wg` + `ip` tools.
//!
//! This is control-plane work, run once at rule startup/teardown — never on the
//! per-datagram data path. Provisioning is idempotent: any stale interface of
//! the same name is removed first.
//!
//! ## Secret hygiene
//!
//! Process arguments are world-readable through `/proc/<pid>/cmdline`, so key
//! material is **never** passed to `wg` on the command line. Private and
//! preshared keys are written to `0600` files inside a `0700` per-process
//! directory, handed to `wg set ... private-key <file>`, and removed (with the
//! directory) immediately after `wg` reads them. The in-memory [`Secret`]
//! zeroizes itself on drop.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Write as _;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use log::debug;

use super::{Secret, WgProviderConfig};

/// Run a tool and map a non-zero exit (or spawn failure) to a descriptive
/// error. `args` only ever contains non-secret values (key *files*, not keys),
/// so it is safe to include in the error message.
fn run_tool(tool: &str, args: &[String]) -> Result<(), String> {
    let output = Command::new(tool)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run `{tool}`: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "`{tool} {}` failed: {}",
            args.join(" "),
            stderr.trim()
        ))
    }
}

fn ip_link_add_argv(iface: &str) -> Vec<String> {
    ["link", "add", "dev", iface, "type", "wireguard"]
        .into_iter()
        .map(String::from)
        .collect()
}

fn ip_link_del_argv(iface: &str) -> Vec<String> {
    ["link", "del", "dev", iface]
        .into_iter()
        .map(String::from)
        .collect()
}

fn ip_link_up_argv(iface: &str) -> Vec<String> {
    ["link", "set", iface, "up"]
        .into_iter()
        .map(String::from)
        .collect()
}

fn ip_addr_add_argv(cfg: &WgProviderConfig) -> Vec<String> {
    let ip_part = cfg
        .tunnel_local_ip
        .split('/')
        .next()
        .unwrap_or(cfg.tunnel_local_ip.as_str());
    let family = match ip_part.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(_)) => "-6",
        _ => "-4",
    };
    vec![
        family.to_string(),
        "address".to_string(),
        "add".to_string(),
        cfg.tunnel_local_ip.clone(),
        "dev".to_string(),
        cfg.wg_interface.clone(),
    ]
}

/// Build the `wg set` argv. The private (and optional preshared) key are passed
/// as **file paths**, never as the key bytes themselves.
fn wg_set_argv(cfg: &WgProviderConfig, key_path: &Path, psk_path: Option<&Path>) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "set".to_string(),
        cfg.wg_interface.clone(),
        "private-key".to_string(),
        key_path.to_string_lossy().into_owned(),
        "listen-port".to_string(),
        cfg.wg_listen_port.to_string(),
        "peer".to_string(),
        cfg.peer_public_key.clone(),
    ];
    if let Some(psk) = psk_path {
        a.push("preshared-key".to_string());
        a.push(psk.to_string_lossy().into_owned());
    }
    a.push("endpoint".to_string());
    a.push(cfg.peer_endpoint.clone());
    a.push("allowed-ips".to_string());
    a.push(cfg.peer_allowed_ips.clone());
    if let Some(n) = cfg.persistent_keepalive {
        a.push("persistent-keepalive".to_string());
        a.push(n.to_string());
    }
    a
}

/// A `0700` directory holding `0600` key files; removed on drop so key material
/// never outlives provisioning, even on an early error.
struct KeyDir {
    path: PathBuf,
}

impl KeyDir {
    fn create(iface: &str) -> Result<KeyDir, String> {
        let base = if Path::new("/run").is_dir() {
            PathBuf::from("/run")
        } else {
            std::env::temp_dir()
        };
        // The interface name is config-derived; keep only path-safe characters
        // so the template cannot escape `base`.
        let safe_iface: String = iface
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        // Create the directory atomically with an UNPREDICTABLE random suffix
        // via mkdtemp(3) (mode 0700). On a world-writable fallback base such as
        // /tmp (used only when /run is absent), a co-located uid therefore
        // cannot pre-create or symlink the key directory to interfere with the
        // private key written into it (#44, CWE-377); mkdtemp never reuses an
        // existing path.
        let mut tmpl = base
            .join(format!("scg-wg-{safe_iface}-XXXXXX"))
            .into_os_string()
            .into_vec();
        tmpl.push(0); // NUL terminator required by mkdtemp
                      // SAFETY: `tmpl` is a mutable, NUL-terminated C string ending in the
                      // required `XXXXXX` template; mkdtemp writes the resolved unique path
                      // back into the buffer in place and returns a pointer into it (or null
                      // on failure, checked below). `tmpl` outlives the call.
        let ret = unsafe { libc::mkdtemp(tmpl.as_mut_ptr() as *mut libc::c_char) };
        if ret.is_null() {
            return Err(format!(
                "failed to create key dir under {}: {}",
                base.display(),
                io::Error::last_os_error()
            ));
        }
        tmpl.pop(); // strip the NUL before converting back to a path
        Ok(KeyDir {
            path: PathBuf::from(OsString::from_vec(tmpl)),
        })
    }

    /// Write `secret` to a `0600` file (created exclusively) and return its path.
    fn write_key(&self, name: &str, secret: &Secret) -> Result<PathBuf, String> {
        let path = self.path.join(name);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("failed to create key file: {e}"))?;
        f.write_all(secret.expose().as_bytes())
            .and_then(|_| f.write_all(b"\n"))
            .map_err(|e| format!("failed to write key file: {e}"))?;
        Ok(path)
    }
}

impl Drop for KeyDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Create and configure the kernel WireGuard interface described by `cfg`.
/// Idempotent and self-cleaning: a stale interface is removed first, and a
/// partially-configured interface is torn down on error.
pub(crate) fn provision(cfg: &WgProviderConfig) -> Result<(), String> {
    let iface = cfg.wg_interface.as_str();
    debug!("provisioning WireGuard interface {iface}");

    // Idempotency: drop any leftover interface from a previous run.
    let _ = run_tool("ip", &ip_link_del_argv(iface));

    run_tool("ip", &ip_link_add_argv(iface))?;

    let configured = (|| -> Result<(), String> {
        let keydir = KeyDir::create(iface)?;
        let key_path = keydir.write_key("private.key", &cfg.private_key)?;
        let psk_path = match &cfg.preshared_key {
            Some(psk) => Some(keydir.write_key("psk.key", psk)?),
            None => None,
        };
        let argv = wg_set_argv(cfg, &key_path, psk_path.as_deref());
        let res = run_tool("wg", &argv);
        // `keydir` (and the key files) are removed when it drops at end of scope;
        // do it eagerly so secrets leave disk before the slower `ip` calls.
        drop(keydir);
        res?;
        run_tool("ip", &ip_addr_add_argv(cfg))?;
        run_tool("ip", &ip_link_up_argv(iface))?;
        Ok(())
    })();

    if let Err(e) = configured {
        // Best-effort cleanup so we don't leave a half-configured interface.
        let _ = run_tool("ip", &ip_link_del_argv(iface));
        return Err(e);
    }
    Ok(())
}

/// Remove the kernel WireGuard interface.
pub(crate) fn teardown(iface: &str) -> Result<(), String> {
    run_tool("ip", &ip_link_del_argv(iface))
}

#[cfg(test)]
mod tests {
    use super::super::WgProviderConfig;
    use super::*;
    use serde_json::{json, Value};
    use std::collections::HashMap;

    const KEY_A: &str = "QID5p0yqzAGq2gA1nF3w8H6+6N0eX0K3nG3vJ8h0VFg=";
    const KEY_B: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

    fn cfg_params() -> HashMap<String, Value> {
        let mut p = HashMap::new();
        p.insert("wg_interface".into(), json!("wg-test0"));
        p.insert("private_key".into(), json!(KEY_A));
        p.insert("wg_listen_port".into(), json!(51820));
        p.insert("peer_public_key".into(), json!(KEY_B));
        p.insert("peer_endpoint".into(), json!("192.0.2.2:51820"));
        p.insert("tunnel_local_ip".into(), json!("10.0.0.1/32"));
        p.insert("peer_allowed_ips".into(), json!("10.0.0.2/32"));
        p
    }

    #[test]
    fn wg_set_argv_uses_keyfile_not_key_bytes() {
        let cfg = WgProviderConfig::from_params(&cfg_params()).unwrap();
        let argv = wg_set_argv(&cfg, Path::new("/run/scg-wg/private.key"), None);
        assert!(argv.iter().any(|a| a == "private-key"));
        assert!(argv.iter().any(|a| a == "/run/scg-wg/private.key"));
        // The private key bytes must never reach argv (/proc-visible).
        assert!(
            !argv.iter().any(|a| a.contains("QID5p0yqzAGq2gA1nF3w8H6")),
            "private key must not appear on the wg argv"
        );
        // Public key + endpoint are not secret and are passed inline.
        assert!(argv.iter().any(|a| a == KEY_B));
        assert!(argv.iter().any(|a| a == "192.0.2.2:51820"));
        assert!(argv.iter().any(|a| a == "10.0.0.2/32"));
    }

    #[test]
    fn wg_set_argv_adds_psk_and_keepalive() {
        let mut p = cfg_params();
        p.insert("preshared_key".into(), json!(KEY_B));
        p.insert("persistent_keepalive".into(), json!(25));
        let cfg = WgProviderConfig::from_params(&p).unwrap();
        let argv = wg_set_argv(&cfg, Path::new("/k/priv"), Some(Path::new("/k/psk")));
        assert!(argv.iter().any(|a| a == "preshared-key"));
        assert!(argv.iter().any(|a| a == "/k/psk"));
        assert!(argv.iter().any(|a| a == "persistent-keepalive"));
        assert!(argv.iter().any(|a| a == "25"));
    }

    #[test]
    fn ip_addr_argv_selects_ipv4() {
        let cfg = WgProviderConfig::from_params(&cfg_params()).unwrap();
        let argv = ip_addr_add_argv(&cfg);
        assert_eq!(argv[0], "-4");
        assert!(argv.iter().any(|a| a == "10.0.0.1/32"));
        assert!(argv.iter().any(|a| a == "wg-test0"));
    }

    #[test]
    fn ip_addr_argv_selects_ipv6() {
        let mut p = cfg_params();
        p.insert("tunnel_local_ip".into(), json!("fd00::1/128"));
        let cfg = WgProviderConfig::from_params(&p).unwrap();
        assert_eq!(ip_addr_add_argv(&cfg)[0], "-6");
    }

    #[test]
    fn link_argv_shapes() {
        assert_eq!(
            ip_link_add_argv("wg0"),
            vec!["link", "add", "dev", "wg0", "type", "wireguard"]
        );
        assert_eq!(ip_link_del_argv("wg0"), vec!["link", "del", "dev", "wg0"]);
        assert_eq!(ip_link_up_argv("wg0"), vec!["link", "set", "wg0", "up"]);
    }
}
