use std::path::Path;

use serde_json::{json, Value};

pub fn read_config(config_path: &Path) -> Result<Value, std::io::Error> {
    match std::fs::read_to_string(config_path) {
        Ok(text) => crate::config_io::parse_strict(config_path, &text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(error) => Err(error),
    }
}

pub fn extension_value(config: &Value, ext_name: &str, key: &str) -> Option<Value> {
    config
        .get("extensions")
        .and_then(Value::as_object)
        .and_then(|extensions| extensions.get(ext_name))
        .and_then(Value::as_object)
        .and_then(|ext| ext.get(key))
        .cloned()
}

pub fn save_extension_value(
    config_path: &Path,
    ext_name: &str,
    key: &str,
    value: Value,
) -> Result<(), std::io::Error> {
    let mut config = read_config(config_path)?;
    if !config.is_object() {
        config = json!({});
    }
    let root = config.as_object_mut().expect("object set above");
    let extensions = root.entry("extensions").or_insert_with(|| json!({}));
    if !extensions.is_object() {
        *extensions = json!({});
    }
    let ext_map = extensions.as_object_mut().expect("object set above");
    let ext = ext_map.entry(ext_name).or_insert_with(|| json!({}));
    if !ext.is_object() {
        *ext = json!({});
    }
    ext.as_object_mut()
        .expect("object set above")
        .insert(key.to_string(), value);
    crate::config_io::write(config_path, &config)
}

/// Resolve an extension's `enabled` flag exactly as Python's manifest loader
/// does (`core/extensions_core/lifecycle/extensions_loader_manifest.py::load_manifest`):
/// a per-extension override recorded in the user's config.json under
/// `extensions.<name>.enabled` wins first; failing that, fall back to the
/// extension's own `extension.json` `config.enabled`; failing that, default
/// to `true`. Shared by `routes::auto_stubs::list_extensions`
/// (GET /api/extensions) and `routes::extensions_admin::extension_detail`
/// (GET /api/extensions/{name}) so the two surfaces cannot silently drift.
pub fn resolve_extension_enabled(config: &Value, name: &str, manifest_json: &Value) -> bool {
    extension_value(config, name, "enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or_else(|| {
            manifest_json
                .get("config")
                .and_then(|c| c.get("enabled"))
                .and_then(Value::as_bool)
                .unwrap_or(true)
        })
}

pub fn string_roots(value: Option<Value>) -> Option<Vec<String>> {
    value.and_then(|value| {
        value.as_array().map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
    })
}

pub fn global_scan_roots(config: &Value) -> Vec<String> {
    config
        .get("scan_roots")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    if let Some(path) = item.as_str() {
                        return Some(path.to_string());
                    }
                    let obj = item.as_object()?;
                    if obj.get("enabled").and_then(Value::as_bool).unwrap_or(true) {
                        obj.get("path").and_then(Value::as_str).map(str::to_string)
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}
