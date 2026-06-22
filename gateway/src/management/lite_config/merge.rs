//! Layered-config assembly: deep-merge of `defaults` + `user`, then the
//! per-connection template fill. This is the Rust mirror of `deep_merge` and
//! `apply_templates` in `tools/validate_config.py`; the two implementations
//! must stay behaviourally identical so the offline validator and the gateway
//! agree on the materialised configuration.

use serde_json::{Map, Value};
use std::collections::HashMap;

/// Deep-merge `override_` onto `base`.
///
/// Objects are merged key by key; any non-object value (including arrays)
/// coming from `override_` replaces the corresponding value in `base`.
pub fn deep_merge(base: Value, override_: Value) -> Value {
    match (base, override_) {
        (Value::Object(mut b), Value::Object(o)) => {
            for (key, value) in o {
                let merged = match b.remove(&key) {
                    Some(existing) => deep_merge(existing, value),
                    None => value,
                };
                b.insert(key, merged);
            }
            Value::Object(b)
        }
        (_, over) => over,
    }
}

fn default_runtime_update() -> Value {
    serde_json::json!({
        "mode": "drain_and_replace",
        "hot_reload_fields": ["paths"],
        "restart_required_fields": ["ingress.endpoint.port", "protection.profile_ref"],
    })
}

fn default_egress_source() -> Value {
    serde_json::json!({ "ip": "auto", "port": "auto" })
}

/// Complete each connection from `defaults.connection` / `defaults.protection`.
///
/// A user file only carries what is unique to a flow; the platform template
/// fills the mechanical fields *before* the document is mapped to data-plane
/// rules. Mirrors `apply_templates` in the Python validator.
pub fn apply_templates(merged: &mut Value) {
    // Snapshot the template values from `defaults` up front (immutable borrow
    // ends before we take the mutable borrow of `connections`).
    let tmpl_enabled;
    let tmpl_transparent;
    let tmpl_runtime_update;
    let tmpl_src;
    let tmpl_out_iface;
    let tmpl_mode;
    let app_class: HashMap<String, Value>;
    {
        let conn_defaults = merged
            .get("defaults")
            .and_then(|d| d.get("connection"));
        let prot_defaults = merged
            .get("defaults")
            .and_then(|d| d.get("protection"));

        tmpl_enabled = conn_defaults
            .and_then(|c| c.get("enabled"))
            .cloned()
            .unwrap_or(Value::Bool(true));
        tmpl_transparent = conn_defaults
            .and_then(|c| c.get("transparent"))
            .cloned()
            .unwrap_or(Value::Bool(false));
        tmpl_runtime_update = conn_defaults
            .and_then(|c| c.get("runtime_update"))
            .cloned()
            .unwrap_or_else(default_runtime_update);
        tmpl_src = conn_defaults
            .and_then(|c| c.get("default_egress_source"))
            .cloned()
            .unwrap_or_else(default_egress_source);
        tmpl_out_iface = conn_defaults
            .and_then(|c| c.get("default_out_interface"))
            .cloned()
            .unwrap_or_else(|| Value::String("eth0".to_string()));
        tmpl_mode = prot_defaults
            .and_then(|p| p.get("default_mode"))
            .cloned()
            .unwrap_or_else(|| Value::String("full".to_string()));

        app_class = merged
            .get("apps")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|app| {
                        let id = app.get("app_id")?.as_str()?.to_string();
                        let class = app.get("default_traffic_class")?.clone();
                        Some((id, class))
                    })
                    .collect()
            })
            .unwrap_or_default();
    }

    let Some(connections) = merged
        .get_mut("connections")
        .and_then(|c| c.as_array_mut())
    else {
        return;
    };

    for conn in connections.iter_mut() {
        let Some(obj) = conn.as_object_mut() else {
            continue;
        };

        obj.entry("enabled").or_insert_with(|| tmpl_enabled.clone());
        obj.entry("transparent")
            .or_insert_with(|| tmpl_transparent.clone());

        if !obj.contains_key("connection_group_id") {
            if let Some(cid) = obj.get("connection_id").cloned() {
                obj.insert("connection_group_id".to_string(), cid);
            }
        }

        if !obj.contains_key("traffic_class") {
            if let Some(app_id) = obj.get("app_id").and_then(|v| v.as_str()) {
                if let Some(class) = app_class.get(app_id) {
                    obj.insert("traffic_class".to_string(), class.clone());
                }
            }
        }

        if !obj.contains_key("runtime_update") {
            obj.insert("runtime_update".to_string(), tmpl_runtime_update.clone());
        }

        if let Some(prot) = obj.get_mut("protection").and_then(|p| p.as_object_mut()) {
            prot.entry("mode").or_insert_with(|| tmpl_mode.clone());
        }

        if let Some(paths) = obj.get_mut("paths").and_then(|p| p.as_array_mut()) {
            let single = paths.len() == 1;
            for path in paths.iter_mut() {
                let Some(p) = path.as_object_mut() else {
                    continue;
                };
                if single {
                    p.entry("role")
                        .or_insert_with(|| Value::String("primary".to_string()));
                    p.entry("priority").or_insert_with(|| Value::from(0));
                }
                if let Some(egress) = p.get_mut("egress").and_then(|e| e.as_object_mut()) {
                    egress
                        .entry("source")
                        .or_insert_with(|| tmpl_src.clone());
                }
                if !p.contains_key("routing") {
                    let mut routing = Map::new();
                    routing.insert("out_interface".to_string(), tmpl_out_iface.clone());
                    p.insert("routing".to_string(), Value::Object(routing));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_merge_objects_recurse_and_scalars_override() {
        let base = serde_json::json!({
            "a": { "x": 1, "y": 2 },
            "list": [1, 2, 3],
            "keep": true
        });
        let over = serde_json::json!({
            "a": { "y": 20, "z": 30 },
            "list": [9],
        });
        let merged = deep_merge(base, over);
        assert_eq!(merged["a"]["x"], 1);
        assert_eq!(merged["a"]["y"], 20);
        assert_eq!(merged["a"]["z"], 30);
        // Arrays replace, not concatenate.
        assert_eq!(merged["list"], serde_json::json!([9]));
        assert_eq!(merged["keep"], true);
    }

    #[test]
    fn templates_fill_connection_defaults() {
        let mut doc = serde_json::json!({
            "defaults": {
                "connection": {
                    "enabled": true,
                    "transparent": false,
                    "default_egress_source": { "ip": "auto", "port": "auto" },
                    "default_out_interface": "eth0"
                },
                "protection": { "default_mode": "full" }
            },
            "apps": [
                { "app_id": "app-a", "default_traffic_class": "safety" }
            ],
            "connections": [
                {
                    "connection_id": "c1",
                    "app_id": "app-a",
                    "protection": { "profile_ref": "p", "role": "client" },
                    "paths": [
                        { "path_id": "only", "egress": { "endpoint": { "host": "h", "port": 1 } } }
                    ]
                }
            ]
        });
        apply_templates(&mut doc);
        let conn = &doc["connections"][0];
        assert_eq!(conn["enabled"], true);
        assert_eq!(conn["transparent"], false);
        assert_eq!(conn["connection_group_id"], "c1");
        // traffic_class inherited from the app.
        assert_eq!(conn["traffic_class"], "safety");
        // protection.mode filled from defaults.
        assert_eq!(conn["protection"]["mode"], "full");
        // single path gets role/priority + egress.source + routing.
        let path = &conn["paths"][0];
        assert_eq!(path["role"], "primary");
        assert_eq!(path["priority"], 0);
        assert_eq!(path["egress"]["source"]["ip"], "auto");
        assert_eq!(path["routing"]["out_interface"], "eth0");
    }
}
