use std::path::Path;

use serde_json::{json, Value};

pub fn read_config(config_path: &Path) -> Result<Value, std::io::Error> {
    match std::fs::read_to_string(config_path) {
        Ok(text) => serde_json::from_str(&text)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(error) => Err(error),
    }
}

pub fn write_config(config_path: &Path, config: &Value) -> Result<(), std::io::Error> {
    let tmp = config_path.with_extension("json.tmp");
    let text = serde_json::to_string_pretty(config)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, config_path)
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
    write_config(config_path, &config)
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
