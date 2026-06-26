//! Map the high-level, layered "lite" configuration model (apps / connections /
//! crypto profiles) onto the gateway's flat `RuleConfig` data-plane model.
//!
//! Each *enabled* connection becomes one proxy rule. Fields the data plane does
//! not yet implement (multi-path fail-over, UDS/SHM egress, integrity-only,
//! PSK, policy enforcement, …) are surfaced as warnings rather than silently
//! dropped, so an operator always sees what was and was not honoured.

use serde_json::{Map, Value};
use std::collections::HashMap;

/// Result of mapping: the rendered classic-config `rules` array plus any
/// non-fatal warnings describing deferred or downgraded behaviour.
pub struct MappedRules {
    pub rules: Vec<Value>,
    pub warnings: Vec<String>,
}

/// Build a `profile_id -> profile` lookup from `crypto.profiles`.
fn index_profiles(merged: &Value) -> HashMap<String, &Value> {
    let mut index = HashMap::new();
    if let Some(profiles) = merged
        .pointer("/crypto/profiles")
        .and_then(|p| p.as_array())
    {
        for profile in profiles {
            if let Some(id) = profile.get("profile_id").and_then(|v| v.as_str()) {
                index.insert(id.to_string(), profile);
            }
        }
    }
    index
}

/// Map every enabled connection to a rule object.
pub fn map_connections_to_rules(merged: &Value) -> Result<MappedRules, String> {
    let profiles = index_profiles(merged);
    let connections = merged
        .get("connections")
        .and_then(|c| c.as_array())
        .ok_or_else(|| "configuration has no 'connections' array".to_string())?;

    let mut rules = Vec::new();
    let mut warnings = Vec::new();

    for conn in connections {
        let cid = conn
            .get("connection_id")
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>")
            .to_string();

        let enabled = conn.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        if !enabled {
            warnings.push(format!(
                "connection '{cid}': disabled — not mapped to a data-plane rule"
            ));
            continue;
        }

        match map_one(conn, &profiles, &mut warnings) {
            Ok(rule) => rules.push(rule),
            Err(e) => warnings.push(format!("connection '{cid}': skipped — {e}")),
        }
    }

    Ok(MappedRules { rules, warnings })
}

/// Resolved security provider for a connection.
struct Provider {
    security_provider: &'static str,
    app_protocol: Option<&'static str>,
    protocol_version: Option<String>,
}

/// Map a crypto-profile `protocol` (+ protection `mode`) to a gateway security
/// provider, app-protocol and TLS/DTLS version.
fn resolve_provider(
    proto: &str,
    profile: &Value,
    mode: &str,
    profiles: &HashMap<String, &Value>,
    cid: &str,
    warnings: &mut Vec<String>,
) -> Result<Provider, String> {
    // routing_only always means "no crypto, just forward" regardless of the
    // referenced profile.
    if mode == "routing_only" || proto == "NONE" {
        return Ok(Provider {
            security_provider: "routing",
            app_protocol: None,
            protocol_version: None,
        });
    }

    // Integrity-only protection (authenticate without encrypting the payload)
    // is not yet implemented in the data plane. Whether requested via the
    // protection `mode` or a dedicated abstract profile, fall back to full TLS
    // and warn loudly — this is fail-safe (more protection, never less).
    if mode == "integrity_only" || proto == "ABSTRACT_INTEGRITY_ONLY" {
        warnings.push(format!(
            "connection '{cid}': integrity-only protection is not yet implemented in the data plane — using full TLS (payload WILL be encrypted)"
        ));
        return Ok(Provider {
            security_provider: "tls",
            app_protocol: None,
            protocol_version: None,
        });
    }

    let provider = match proto {
        "TLS" => Provider {
            security_provider: "tls",
            app_protocol: None,
            protocol_version: tls_version(profile),
        },
        "TLS_PSK" => {
            warnings.push(format!(
                "connection '{cid}': TLS-PSK mapped to the 'tls' provider — PSK key exchange is only partially wired (deferred)"
            ));
            Provider {
                security_provider: "tls",
                app_protocol: None,
                protocol_version: tls_version(profile),
            }
        }
        "DTLS" => Provider {
            security_provider: "dtls",
            app_protocol: None,
            protocol_version: dtls_version(profile),
        },
        "ALE" | "RAW" => {
            let app_protocol = if proto == "ALE" { "ale" } else { "raw" };
            // The crypto comes from the referenced outer profile.
            let outer = profile
                .get("outer_crypto_profile_ref")
                .and_then(|v| v.as_str())
                .and_then(|r| profiles.get(r).copied());
            let outer_proto = outer
                .and_then(|o| o.get("protocol"))
                .and_then(|v| v.as_str())
                .unwrap_or("TLS");
            let (security_provider, protocol_version) = match outer_proto {
                "DTLS" => ("dtls", outer.and_then(dtls_version)),
                _ => ("tls", outer.and_then(tls_version)),
            };
            Provider {
                security_provider,
                app_protocol: Some(app_protocol),
                protocol_version,
            }
        }
        other => {
            return Err(format!(
                "unsupported crypto profile protocol '{other}'"
            ))
        }
    };

    Ok(provider)
}

fn tls_version(profile: &Value) -> Option<String> {
    match profile.get("max_version").and_then(|v| v.as_str()) {
        Some("1.3") => Some("tls1.3".to_string()),
        Some("1.2") => Some("tls1.2".to_string()),
        _ => None,
    }
}

fn dtls_version(profile: &Value) -> Option<String> {
    match profile.get("max_version").and_then(|v| v.as_str()) {
        Some("1.2") => Some("dtls1.2".to_string()),
        Some("1.0") => Some("dtls1.0".to_string()),
        _ => None,
    }
}

/// Choose the primary path: an explicit `role == "primary"`, else the lowest
/// `priority`, else the first entry.
fn pick_primary(paths: &[Value]) -> &Value {
    paths
        .iter()
        .find(|p| p.get("role").and_then(|v| v.as_str()) == Some("primary"))
        .or_else(|| {
            paths.iter().min_by_key(|p| {
                p.get("priority").and_then(|v| v.as_i64()).unwrap_or(i64::MAX)
            })
        })
        .unwrap_or(&paths[0])
}

fn map_one(
    conn: &Value,
    profiles: &HashMap<String, &Value>,
    warnings: &mut Vec<String>,
) -> Result<Value, String> {
    let cid = conn
        .get("connection_id")
        .and_then(|v| v.as_str())
        .ok_or("missing connection_id")?
        .to_string();

    let transparent = conn.get("transparent").and_then(|v| v.as_bool()).unwrap_or(false);
    let traffic_class = conn
        .get("traffic_class")
        .and_then(|v| v.as_str())
        .unwrap_or("normal")
        .to_string();
    let app_id = conn.get("app_id").and_then(|v| v.as_str()).map(str::to_string);

    // ── protection → direction + provider ───────────────────────────────────
    let prot = conn.get("protection").ok_or("missing 'protection'")?;
    let role = prot.get("role").and_then(|v| v.as_str()).unwrap_or("client");
    let mode = prot.get("mode").and_then(|v| v.as_str()).unwrap_or("full");
    let profile_ref = prot
        .get("profile_ref")
        .and_then(|v| v.as_str())
        .ok_or("missing 'protection.profile_ref'")?;
    let sni = prot.get("sni").and_then(|v| v.as_str()).map(str::to_string);

    let profile = profiles.get(profile_ref).copied().ok_or_else(|| {
        format!("protection.profile_ref '{profile_ref}' does not resolve to a crypto profile")
    })?;
    let proto = profile
        .get("protocol")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("crypto profile '{profile_ref}' has no 'protocol'"))?;

    let direction = match role {
        "client" => "encrypt",
        "server" => "decrypt",
        "none" => "encrypt", // routing_only passthrough; provider ignores direction
        other => {
            warnings.push(format!(
                "connection '{cid}': unknown protection.role '{other}' — defaulting to 'encrypt'"
            ));
            "encrypt"
        }
    };

    let provider = resolve_provider(proto, profile, mode, profiles, &cid, warnings)?;

    // ── ingress → listen_addr / listen_proto ────────────────────────────────
    let endpoint = conn
        .pointer("/ingress/endpoint")
        .ok_or("missing 'ingress.endpoint'")?;
    let ip = endpoint.get("ip").and_then(|v| v.as_str()).ok_or(
        "ingress.endpoint has no 'ip' (UDS/SHM ingress is not yet supported by the data plane)",
    )?;
    let port = endpoint
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or("ingress.endpoint has no numeric 'port'")?;
    let listen_addr = if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    };
    let listen_proto = endpoint
        .get("protocol")
        .and_then(|v| v.as_str())
        .or_else(|| conn.pointer("/transport/protocol").and_then(|v| v.as_str()))
        .unwrap_or("tcp")
        .to_string();

    // ── primary path egress → upstream_addr / upstream_proto ────────────────
    let paths = conn
        .get("paths")
        .and_then(|v| v.as_array())
        .filter(|p| !p.is_empty())
        .ok_or("connection has no 'paths'")?;
    if paths.len() > 1 {
        warnings.push(format!(
            "connection '{cid}': {} paths defined — only the primary path is mapped (multi-path fail-over is deferred)",
            paths.len()
        ));
    }
    let primary = pick_primary(paths);
    let egress_ep = primary
        .pointer("/egress/endpoint")
        .ok_or("primary path has no 'egress.endpoint'")?;

    let (upstream_addr, upstream_proto) = if egress_ep.as_str() == Some("auto") {
        ("auto".to_string(), listen_proto.clone())
    } else if let Some(ep) = egress_ep.as_object() {
        if let Some(host) = ep.get("host").and_then(|v| v.as_str()) {
            let p = ep
                .get("port")
                .and_then(|v| v.as_u64())
                .ok_or("egress endpoint has no numeric 'port'")?;
            let up_proto = ep
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or(&listen_proto)
                .to_string();
            (format!("{host}:{p}"), up_proto)
        } else {
            let kind = ep.get("type").and_then(|v| v.as_str()).unwrap_or("?");
            return Err(format!(
                "egress endpoint kind '{kind}' is not yet supported by the data plane (only host:port or 'auto')"
            ));
        }
    } else {
        return Err("egress endpoint must be 'auto' or an object with host/port".to_string());
    };

    // ── transparent ⇔ auto consistency ──────────────────────────────────────
    if upstream_addr == "auto" && !transparent {
        return Err("egress 'auto' requires transparent = true".to_string());
    }
    if transparent && upstream_addr != "auto" {
        warnings.push(format!(
            "connection '{cid}': transparent = true but egress is an explicit endpoint — the original-destination lookup will be ignored"
        ));
    }

    // ── assemble the rule object ────────────────────────────────────────────
    let mut rule = Map::new();
    rule.insert("name".to_string(), Value::String(cid));
    rule.insert("direction".to_string(), Value::String(direction.to_string()));
    rule.insert("listen_addr".to_string(), Value::String(listen_addr));
    rule.insert("listen_proto".to_string(), Value::String(listen_proto));
    rule.insert("upstream_addr".to_string(), Value::String(upstream_addr));
    rule.insert("upstream_proto".to_string(), Value::String(upstream_proto));
    rule.insert(
        "security_provider".to_string(),
        Value::String(provider.security_provider.to_string()),
    );
    // Fail-secure: emit an explicit peer-verification mode for crypto providers
    // so the generated rule never relies on the (now-rejected) implicit
    // "no verification" default. Abstract lite TLS/DTLS profiles map to
    // certificate verification of the peer ("server"); deployments that need
    // mutual authentication express it through a richer crypto profile.
    if matches!(provider.security_provider, "tls" | "dtls") {
        rule.insert("verify".to_string(), Value::String("server".to_string()));
    }
    if let Some(ap) = provider.app_protocol {
        rule.insert("app_protocol".to_string(), Value::String(ap.to_string()));
    }
    rule.insert("transparent".to_string(), Value::Bool(transparent));
    rule.insert("traffic_class".to_string(), Value::String(traffic_class));
    if let Some(aid) = app_id {
        rule.insert("app_id".to_string(), Value::String(aid));
    }
    if let Some(pv) = provider.protocol_version {
        rule.insert("protocol_version".to_string(), Value::String(pv));
    }
    // Carried through `serde(flatten)` into `provider_params` for the provider.
    if let Some(sni) = sni {
        rule.insert("sni".to_string(), Value::String(sni));
    }

    // ── intercept (firewall self-configuration) ─────────────────────────────
    // Read from `ingress.intercept` on the connection.
    if let Some(intercept_val) = conn.pointer("/ingress/intercept") {
        if let Some(ic) = intercept_val.as_object() {
            let mut intercept = Map::new();
            // mode is required.
            if let Some(mode) = ic.get("mode").and_then(|v| v.as_str()) {
                intercept.insert("mode".to_string(), Value::String(mode.to_string()));
            } else {
                return Err("ingress.intercept has no 'mode'".to_string());
            }
            // Optional fields pass through.
            if let Some(iface) = ic.get("in_interface").and_then(|v| v.as_str()) {
                intercept.insert("in_interface".to_string(), Value::String(iface.to_string()));
            }
            if let Some(dports) = ic.get("match_dports").and_then(|v| v.as_str()) {
                intercept.insert("match_dports".to_string(), Value::String(dports.to_string()));
            }
            if let Some(dst) = ic.get("match_dst") {
                intercept.insert("match_dst".to_string(), dst.clone());
            }
            if let Some(src) = ic.get("match_src") {
                intercept.insert("match_src".to_string(), src.clone());
            }
            if let Some(proto) = ic.get("protocol").and_then(|v| v.as_str()) {
                intercept.insert("protocol".to_string(), Value::String(proto.to_string()));
            }
            rule.insert("intercept".to_string(), Value::Object(intercept));
        }
    }

    Ok(Value::Object(rule))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a merged document with the given connections array and a small set
    /// of crypto profiles, then map it.
    fn map(connections: Value) -> MappedRules {
        let merged = serde_json::json!({
            "crypto": {
                "profiles": [
                    { "profile_id": "tls_c", "protocol": "TLS", "role": "client",
                      "max_version": "1.3" },
                    { "profile_id": "dtls_s", "protocol": "DTLS", "role": "server",
                      "max_version": "1.2" },
                    { "profile_id": "ale_p", "protocol": "ALE",
                      "outer_crypto_profile_ref": "tls_c" }
                ]
            },
            "connections": connections
        });
        map_connections_to_rules(&merged).unwrap()
    }

    fn rule<'a>(m: &'a MappedRules, name: &str) -> &'a Value {
        m.rules
            .iter()
            .find(|r| r["name"] == name)
            .unwrap_or_else(|| panic!("rule '{name}' not mapped: {:?}", m.rules))
    }

    #[test]
    fn dtls_server_maps_to_decrypt_dtls_over_udp() {
        let m = map(serde_json::json!([{
            "connection_id": "c-dtls",
            "app_id": "a",
            "traffic_class": "normal",
            "enabled": true,
            "protection": { "profile_ref": "dtls_s", "role": "server", "mode": "full" },
            "ingress": { "endpoint": { "ip": "127.0.20.20", "port": 5684, "protocol": "udp" } },
            "paths": [ { "egress": { "endpoint": { "host": "app.local", "port": 7000, "protocol": "udp" } } } ]
        }]));
        let r = rule(&m, "c-dtls");
        assert_eq!(r["direction"], "decrypt");
        assert_eq!(r["listen_proto"], "udp");
        assert_eq!(r["upstream_proto"], "udp");
        assert_eq!(r["security_provider"], "dtls");
        assert_eq!(r["upstream_addr"], "app.local:7000");
        assert_eq!(r["protocol_version"], "dtls1.2");
    }

    #[test]
    fn ale_maps_to_tls_with_ale_app_protocol() {
        let m = map(serde_json::json!([{
            "connection_id": "c-ale",
            "app_id": "a",
            "traffic_class": "normal",
            "enabled": true,
            "protection": { "profile_ref": "ale_p", "role": "client", "mode": "full" },
            "ingress": { "endpoint": { "ip": "127.0.20.10", "port": 21000, "protocol": "udp" } },
            "paths": [ { "egress": { "endpoint": { "host": "gw.local", "port": 6514, "protocol": "tcp" } } } ]
        }]));
        let r = rule(&m, "c-ale");
        // UDP datagrams in, TLS-over-TCP out (the ALE app-protocol frames them).
        assert_eq!(r["direction"], "encrypt");
        assert_eq!(r["listen_proto"], "udp");
        assert_eq!(r["upstream_proto"], "tcp");
        assert_eq!(r["security_provider"], "tls");
        assert_eq!(r["app_protocol"], "ale");
    }

    #[test]
    fn uds_egress_is_skipped_with_warning() {
        let m = map(serde_json::json!([{
            "connection_id": "c-uds",
            "app_id": "a",
            "enabled": true,
            "protection": { "profile_ref": "dtls_s", "role": "server", "mode": "full" },
            "ingress": { "endpoint": { "ip": "127.0.20.20", "port": 5684, "protocol": "udp" } },
            "paths": [ { "egress": { "endpoint": { "type": "uds", "path": "/run/x.sock" } } } ]
        }]));
        assert!(m.rules.is_empty());
        assert!(
            m.warnings.iter().any(|w| w.contains("uds") && w.contains("skipped")),
            "got: {:?}",
            m.warnings
        );
    }

    #[test]
    fn auto_egress_without_transparent_is_skipped() {
        let m = map(serde_json::json!([{
            "connection_id": "c-bad-auto",
            "app_id": "a",
            "enabled": true,
            "transparent": false,
            "protection": { "profile_ref": "tls_c", "role": "client", "mode": "full" },
            "ingress": { "endpoint": { "ip": "127.0.0.1", "port": 1234, "protocol": "tcp" } },
            "paths": [ { "egress": { "endpoint": "auto" } } ]
        }]));
        assert!(m.rules.is_empty());
        assert!(
            m.warnings.iter().any(|w| w.contains("requires transparent")),
            "got: {:?}",
            m.warnings
        );
    }

    #[test]
    fn intercept_is_mapped_from_ingress() {
        let m = map(serde_json::json!([{
            "connection_id": "c-intercept",
            "app_id": "a",
            "enabled": true,
            "protection": { "profile_ref": "tls_c", "role": "server", "mode": "full" },
            "ingress": {
                "endpoint": { "ip": "0.0.0.0", "port": 8443, "protocol": "tcp" },
                "intercept": {
                    "mode": "ingress_redirect",
                    "in_interface": "eth0",
                    "match_dports": "8080"
                }
            },
            "paths": [ { "egress": { "endpoint": { "host": "127.0.0.1", "port": 80 } } } ]
        }]));
        let r = rule(&m, "c-intercept");
        let ic = r.get("intercept").expect("rule should have intercept");
        assert_eq!(ic["mode"], "ingress_redirect");
        assert_eq!(ic["in_interface"], "eth0");
        assert_eq!(ic["match_dports"], "8080");
    }

    #[test]
    fn no_intercept_when_absent() {
        let m = map(serde_json::json!([{
            "connection_id": "c-no-ic",
            "app_id": "a",
            "enabled": true,
            "protection": { "profile_ref": "tls_c", "role": "client", "mode": "full" },
            "ingress": { "endpoint": { "ip": "0.0.0.0", "port": 9000, "protocol": "tcp" } },
            "paths": [ { "egress": { "endpoint": { "host": "10.0.0.1", "port": 443 } } } ]
        }]));
        let r = rule(&m, "c-no-ic");
        assert!(r.get("intercept").is_none());
    }
}
