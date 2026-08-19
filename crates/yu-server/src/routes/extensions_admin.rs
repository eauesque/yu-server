//! `/api/extensions/*` admin surface — git-based lifecycle (Rust native) + forwarders.
//!
//! Git lifecycle (install/update/uninstall) runs Rust-native; no Python compat.
//! Author tools, marketplace, and metadata routes remain Python forwarders.

use std::{collections::HashSet, path::PathBuf};

use axum::{
    body::Bytes,
    extract::{Extension, Path as AxumPath, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use tokio::process::Command as Cmd;

use crate::{
    auth::{scope::require_admin_scope, AuthContext},
    state::SharedState,
};

// ── envelope helpers (mirrors Python core/infra_core/api_errors.py::api_result) ─

/// Success branch: `{"ok": true, "error": null, "data": null, ...payload}`.
fn api_result(payload: Value) -> Response {
    let mut body = match payload {
        Value::Object(map) => map,
        other => return Json(json!({"ok": true, "error": null, "data": other})).into_response(),
    };
    body.insert("ok".to_string(), Value::Bool(true));
    body.insert("error".to_string(), Value::Null);
    body.entry("data".to_string()).or_insert(Value::Null);
    Json(Value::Object(body)).into_response()
}

/// Error branch: `{"ok": false, "error": <message>, ...extra payload keys}` at
/// the given status. Mirrors Python's `api_error`/`api_result` merging every
/// extra payload key onto the top level, not just `error`.
fn api_result_status(payload: Value, status: StatusCode) -> Response {
    let mut body = match payload {
        Value::Object(map) => map,
        other => {
            let mut map = serde_json::Map::new();
            map.insert("error".to_string(), other);
            map
        }
    };
    body.insert("ok".to_string(), Value::Bool(false));
    body.entry("error".to_string()).or_insert(Value::Null);
    (status, Json(Value::Object(body))).into_response()
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn admin_gate(state: &SharedState, auth: Option<&Extension<AuthContext>>) -> Option<Response> {
    require_admin_scope(state.config.pin_auth_enabled, auth.map(|c| &c.0))
}

fn ext_dir(state: &SharedState) -> PathBuf {
    state.config.project_root.join("extensions")
}

/// HTTPS only, must have a non-empty host segment.
fn validate_git_url(url: &str) -> Option<&'static str> {
    if !url.starts_with("https://") {
        return Some("Only HTTPS URLs are allowed");
    }
    let rest = &url["https://".len()..];
    if rest.is_empty() || rest.starts_with('/') {
        return Some("URL must have a valid host");
    }
    None
}

/// Last path segment of a git URL, with .git suffix stripped.
fn repo_name_from_url(url: &str) -> Option<String> {
    let seg = url.trim_end_matches('/').rsplit('/').next()?;
    let name = seg.strip_suffix(".git").unwrap_or(seg);
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Reject names that could escape the extensions directory.
fn safe_ext_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.contains('\\') && !name.starts_with('.')
}

/// Scan the extensions directory for a manifest whose `name` field matches
/// `name`. Python's `ExtensionManager.manifests` is keyed by the manifest's
/// own `name` field (`extensions_loader_manifest.py::load_manifest`,
/// `ext_name = raw["name"]`), not by directory basename, so this scans and
/// matches on the parsed field rather than assuming `ext_dir/name` is the
/// manifest's home directory. Entries are sorted by path before scanning so
/// the result is deterministic regardless of the filesystem's raw readdir
/// order (which is unspecified — e.g. hash-ordered on some filesystems).
fn find_extension_manifest(state: &SharedState, name: &str) -> Option<(PathBuf, Value)> {
    let dir = ext_dir(state);
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    entries.sort();
    for path in entries {
        if !path.is_dir() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path.join("extension.json")) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if v.get("name").and_then(Value::as_str) == Some(name) {
            return Some((path, v));
        }
    }
    None
}

/// Names of all locally-installed extensions (dir scan, keyed by manifest
/// `name` — same rationale as `find_extension_manifest`). Mirrors Python's
/// `set(mgr.manifests.keys())` used to compute marketplace `installed` flags.
fn installed_extension_names(state: &SharedState) -> HashSet<String> {
    let dir = ext_dir(state);
    std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let text = std::fs::read_to_string(e.path().join("extension.json")).ok()?;
            let v: Value = serde_json::from_str(&text).ok()?;
            v.get("name").and_then(Value::as_str).map(str::to_string)
        })
        .collect()
}

/// Only canonical bundled `builtin-*` directories are "trusted" — mirrors
/// Python `extensions_loader_manifest.py::determine_trust_level`. Everything
/// else (including a directory merely *named* `builtin-...`) is "untrusted";
/// Rust has no VERIFIED (L1, signature-based) tier either, matching Python's
/// current state (planned Phase 2+, not implemented there either).
fn trust_level(state: &SharedState, name: &str, found_dir: &std::path::Path) -> &'static str {
    if !name.starts_with("builtin-") {
        return "untrusted";
    }
    let underscored = name.replace('-', "_");
    let dir_name_matches = found_dir
        .file_name()
        .map(|n| n == underscored.as_str())
        .unwrap_or(false);
    let bundled_dir = ext_dir(state).join(&underscored);
    if !dir_name_matches || !bundled_dir.is_dir() {
        return "untrusted";
    }
    let found_canon = std::fs::canonicalize(found_dir).ok();
    let bundled_canon = std::fs::canonicalize(&bundled_dir).ok();
    if found_canon.is_some() && found_canon == bundled_canon {
        "trusted"
    } else {
        "untrusted"
    }
}

fn is_secret_field(field_name: &str) -> bool {
    let lowered = field_name.to_lowercase();
    ["secret", "token", "password", "api_key", "apikey"]
        .iter()
        .any(|t| lowered.contains(t))
}

/// `string`/`boolean`/`number`/`integer` alias to `str`/`bool`/`float`/`int`;
/// any other type name (or empty) passes through / defaults to `str` —
/// mirrors Python's `_CONFIG_TYPE_ALIASES.get(raw_type, raw_type or "str")`.
fn alias_config_type(raw: &str) -> String {
    match raw {
        "string" => "str".to_string(),
        "boolean" => "bool".to_string(),
        "number" => "float".to_string(),
        "integer" => "int".to_string(),
        "" => "str".to_string(),
        other => other.to_string(),
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
    }
}

/// `type(value).__name__` for the JSON types `validate_config_value` cares
/// about — mirrors Python's dynamic type name used in "Expected X, got Y"
/// messages. A JSON integer literal (no fractional part) maps to `int`;
/// anything with a fractional part (or written with a decimal point) maps
/// to `float`, matching how Python's own `json.loads` distinguishes them.
fn python_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                "int"
            } else {
                "float"
            }
        }
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// Python `repr()` for the JSON value types that can appear in a
/// `config_schema` `options`/value slot — used for `Allowed: [...]` enum
/// error messages, which format each option through `repr`.
fn python_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(python_repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(k, v)| format!("'{}': {}", k, python_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Python `str()` — identical to `repr()` except a top-level string value
/// prints unquoted. Used for the `Invalid option '{value}'.` message, which
/// Python builds via an f-string (`str()`), not `repr()`.
fn python_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => python_repr(other),
    }
}

/// Mirrors Python `extensions_core/lifecycle/extensions_admin.py::validate_config_value`.
/// `field_type` must already be alias-normalized (see `alias_config_type`)
/// and lowercased, matching how `cf.type` is resolved once at manifest
/// parse time in Python (`extensions_loader_manifest.py::parse_config_schema`)
/// before `validate_config_value` re-lowercases it.
///
/// Deliberately diverges from CPython here. Because `bool` subclasses `int`
/// in Python, `isinstance(True, int)` is true, so Python's `int`/`number`
/// branches **accept a JSON boolean** and persist `True` into a field the
/// manifest declares numeric. `serde_json::Value::Bool` is a distinct variant
/// from `Value::Number`, so matching on `Number` rejects it.
///
/// The divergence is kept on purpose, not inherited by accident:
/// `routes/settings.rs::coerce_value` already refuses booleans for numeric
/// settings, so accepting one here would be inconsistent within this crate,
/// and storing `true` in an int-typed config field is a latent Python defect
/// rather than a contract anyone depends on. Pinned by
/// `extension_config_post_bool_value_rejected_for_int_field`. If parity with
/// Python is ever required for this case, change both sides together.
fn validate_config_value(
    field_type: &str,
    value: &Value,
    options: &[Value],
    range: Option<&(Value, Value)>,
) -> Option<String> {
    let check_range = |v: &Value| -> Option<String> {
        let (lo, hi) = range?;
        let lo_f = lo.as_f64().unwrap_or(f64::NEG_INFINITY);
        let hi_f = hi.as_f64().unwrap_or(f64::INFINITY);
        let v_f = v.as_f64().unwrap_or(0.0);
        if v_f < lo_f || v_f > hi_f {
            Some(format!("Out of range [{}, {}]", lo, hi))
        } else {
            None
        }
    };
    match field_type {
        "bool" | "boolean" if !matches!(value, Value::Bool(_)) => {
            return Some(format!("Expected bool, got {}", python_type_name(value)));
        }
        "bool" | "boolean" => {}
        "enum" => {
            if !options.iter().any(|o| o == value) {
                return Some(format!(
                    "Invalid option '{}'. Allowed: [{}]",
                    python_str(value),
                    options
                        .iter()
                        .map(python_repr)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        "int" | "integer" => {
            if !matches!(value, Value::Number(n) if n.is_i64() || n.is_u64()) {
                return Some(format!("Expected int, got {}", python_type_name(value)));
            }
            if let Some(err) = check_range(value) {
                return Some(err);
            }
        }
        "float" | "number" => {
            if !matches!(value, Value::Number(_)) {
                return Some(format!("Expected number, got {}", python_type_name(value)));
            }
            if let Some(err) = check_range(value) {
                return Some(err);
            }
        }
        "str" | "string" if !matches!(value, Value::String(_)) => {
            return Some(format!("Expected str, got {}", python_type_name(value)));
        }
        "str" | "string" => {}
        _ => {}
    }
    None
}

/// `manifest_to_dict`-equivalent config_schema: `type`/`default`/`label`/
/// `cli_flag` always present; `options`/`range`/`description` only when
/// truthy (matches Python's conditional `if cf.options: ...` etc).
fn build_manifest_config_schema(schema_raw: &Value) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(obj) = schema_raw.as_object() {
        for (field_name, spec) in obj {
            let empty = serde_json::Map::new();
            let spec_obj = spec.as_object().unwrap_or(&empty);
            let raw_type = spec_obj
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("str")
                .trim()
                .to_lowercase();
            let default = spec_obj.get("default").cloned().unwrap_or(Value::Null);
            let label = spec_obj
                .get("label")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| field_name.clone());
            let cli_flag = spec_obj
                .get("cli_flag")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let mut field = json!({
                "type": alias_config_type(&raw_type),
                "default": default,
                "label": label,
                "cli_flag": cli_flag,
            });
            if let Some(options) = spec_obj.get("options") {
                if truthy(options) {
                    field["options"] = options.clone();
                }
            }
            if let Some(range) = spec_obj.get("range") {
                if truthy(range) {
                    field["range"] = range.clone();
                }
            }
            if let Some(description) = spec_obj.get("description") {
                if truthy(description) {
                    field["description"] = description.clone();
                }
            }
            out.insert(field_name.clone(), field);
        }
    }
    Value::Object(out)
}

/// `build_config_schema`-equivalent config_schema: every key unconditional,
/// plus a resolved `value` (config.json override → schema default), with
/// secret-named fields masked to `null` regardless of stored value — mirrors
/// `extensions_api_config_ops.py::build_config_schema` + `_is_secret_field`.
fn build_config_schema_with_values(config: &Value, ext_name: &str, schema_raw: &Value) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(obj) = schema_raw.as_object() {
        for (field_name, spec) in obj {
            let empty = serde_json::Map::new();
            let spec_obj = spec.as_object().unwrap_or(&empty);
            let raw_type = spec_obj
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("str")
                .trim()
                .to_lowercase();
            let default = spec_obj.get("default").cloned().unwrap_or(Value::Null);
            let label = spec_obj
                .get("label")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| field_name.clone());
            let cli_flag = spec_obj
                .get("cli_flag")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let options = spec_obj.get("options").cloned().unwrap_or(json!([]));
            let range = spec_obj.get("range").cloned().unwrap_or(Value::Null);
            let description = spec_obj
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let value = if is_secret_field(field_name) {
                Value::Null
            } else {
                crate::ext_config::extension_value(config, ext_name, field_name)
                    .unwrap_or_else(|| default.clone())
            };
            out.insert(
                field_name.clone(),
                json!({
                    "type": alias_config_type(&raw_type),
                    "default": default,
                    "label": label,
                    "cli_flag": cli_flag,
                    "options": options,
                    "range": range,
                    "description": description,
                    "value": value,
                }),
            );
        }
    }
    Value::Object(out)
}

// ── Python forwarder plumbing (author/marketplace/metadata routes) ────────────

fn extensions_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"ok": false, "error": "extensions_unavailable"})),
    )
        .into_response()
}

async fn fwd_get(state: &SharedState, path: &str) -> Response {
    if state.config.python_url.is_empty() {
        return extensions_unavailable();
    }
    let url = format!("{}{}", state.config.python_url.trim_end_matches('/'), path);
    match state
        .python_client
        .get(&url)
        .header("X-Remote-User", "yu-proxy-auth")
        .send()
        .await
    {
        Ok(r) => {
            let s = r.status();
            r.bytes().await.map_or_else(
                |_| StatusCode::BAD_GATEWAY.into_response(),
                |b| (s, b).into_response(),
            )
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

async fn fwd_post(state: &SharedState, path: &str, body: Bytes) -> Response {
    if state.config.python_url.is_empty() {
        return extensions_unavailable();
    }
    let url = format!("{}{}", state.config.python_url.trim_end_matches('/'), path);
    match state
        .python_client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Remote-User", "yu-proxy-auth")
        .header("X-Requested-With", "XMLHttpRequest")
        .body(body)
        .send()
        .await
    {
        Ok(r) => {
            let s = r.status();
            r.bytes().await.map_or_else(
                |_| StatusCode::BAD_GATEWAY.into_response(),
                |b| (s, b).into_response(),
            )
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

// ── Git lifecycle — Rust native ───────────────────────────────────────────────

/// POST /api/extensions/install — git clone --depth 1
pub async fn install(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    body: Bytes,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }

    let data: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid JSON"})),
            )
                .into_response()
        }
    };
    let url = match data
        .get("url")
        .or_else(|| data.get("git"))
        .or_else(|| data.get("repo"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(u) => u.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "url is required"})),
            )
                .into_response()
        }
    };

    if let Some(err) = validate_git_url(&url) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": err}))).into_response();
    }
    let repo_name = match repo_name_from_url(&url) {
        Some(n) => n,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "cannot extract repository name from URL"})),
            )
                .into_response()
        }
    };

    let extensions_dir = ext_dir(&state);
    let target = extensions_dir.join(&repo_name);
    if target.components().any(|c| c.as_os_str() == "..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid repository name (path traversal blocked)"})),
        )
            .into_response();
    }
    if target.exists() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": format!("Extension '{}' already exists", repo_name)})),
        )
            .into_response();
    }
    if let Err(e) = tokio::fs::create_dir_all(&extensions_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to create extensions directory: {}", e)})),
        )
            .into_response();
    }

    match Cmd::new("git").args(["clone", "--depth", "1", &url, target.to_str().unwrap_or("")]).output().await {
        Ok(out) if out.status.success() =>
            (StatusCode::OK, Json(json!({"message": format!("Extension '{}' installed successfully", repo_name), "name": repo_name}))).into_response(),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            (StatusCode::BAD_GATEWAY, Json(json!({"error": format!("git clone failed: {}", stderr.trim())}))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("Failed to run git: {}", e)}))).into_response(),
    }
}

/// POST /api/extensions/{name}/update — git pull --ff-only
pub async fn update_git(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    if !safe_ext_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid extension name"})),
        )
            .into_response();
    }
    let ext_path = ext_dir(&state).join(&name);
    if !ext_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Extension '{}' not found", name)})),
        )
            .into_response();
    }
    if !ext_path.join(".git").exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Extension '{}' is not a git repository", name)})),
        )
            .into_response();
    }

    match Cmd::new("git")
        .args(["-C", ext_path.to_str().unwrap_or(""), "pull", "--ff-only"])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let status = if stdout.contains("Already up to date") {
                "unchanged"
            } else {
                "updated"
            };
            (StatusCode::OK, Json(json!({"message": format!("Extension '{}' {}", name, status), "name": name, "status": status}))).into_response()
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("git pull failed: {}", stderr.trim())})),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to run git: {}", e)})),
        )
            .into_response(),
    }
}

/// POST /api/extensions/update-all — git pull --ff-only for each git extension
pub async fn update_all_git(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }

    let extensions_dir = ext_dir(&state);
    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut updated_count = 0usize;
    let mut total = 0usize;

    if let Ok(mut entries) = tokio::fs::read_dir(&extensions_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.starts_with('.') {
                continue;
            }
            total += 1;

            if !path.join(".git").exists() {
                results.push(
                    json!({"name": name, "status": "skipped", "message": "not a git repository"}),
                );
                continue;
            }

            match Cmd::new("git")
                .args(["-C", path.to_str().unwrap_or(""), "pull", "--ff-only"])
                .output()
                .await
            {
                Ok(out) if out.status.success() => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let already = stdout.contains("Already up to date");
                    if !already {
                        updated_count += 1;
                    }
                    results.push(json!({"name": name, "status": if already { "unchanged" } else { "updated" }}));
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    results
                        .push(json!({"name": name, "status": "error", "message": stderr.trim()}));
                }
                Err(e) => {
                    results.push(json!({"name": name, "status": "error", "message": e.to_string()}))
                }
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "message": format!("{} extension(s) updated", updated_count),
            "total": total,
            "updated": updated_count,
            "results": results,
        })),
    )
        .into_response()
}

/// DELETE /api/extensions/{name}/uninstall — remove extension directory
pub async fn uninstall_ext(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    if !safe_ext_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid extension name"})),
        )
            .into_response();
    }
    let ext_path = ext_dir(&state).join(&name);
    if !ext_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Extension '{}' not found", name)})),
        )
            .into_response();
    }
    match tokio::fs::remove_dir_all(&ext_path).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"message": format!("Extension '{}' uninstalled", name)})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to remove extension: {}", e)})),
        )
            .into_response(),
    }
}

// ── Python forwarder routes ───────────────────────────────────────────────────

/// GET /api/extensions/hooks
pub async fn hooks(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::OK,
        Json(json!({"ok": true, "hooks": [], "definitions": {}})),
    )
        .into_response()
}

/// GET /api/extensions/isolation
///
/// Mirrors Python `core/extensions_api/handlers_security.py::get_isolation_status`,
/// which reports on Python's in-process extension sandbox
/// (`core.extensions_core.sandbox.process_isolation`). Rust standalone runs no
/// Python interpreter and has no equivalent in-process sandbox to report on,
/// so `available` is honestly `false` and `processes` is empty — the same
/// explicit "not available" answer as the `os_isolation` handler above,
/// rather than fabricating a positive status.
pub async fn isolation(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    api_result(json!({"available": false, "processes": {}}))
}

/// POST /api/extensions/author/create
pub async fn author_create(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// GET /api/extensions/author/:name/files
pub async fn author_files(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// GET /api/extensions/author/:name/read
pub async fn author_read(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// POST /api/extensions/author/:name/validate
pub async fn author_validate(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// POST /api/extensions/author/:name/write
pub async fn author_write(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// GET /api/tauri-shell/tabs
pub async fn tauri_shell_tabs(State(_state): State<SharedState>) -> Response {
    extensions_unavailable()
}

#[derive(serde::Deserialize)]
pub struct MarketplaceQuery {
    #[serde(default)]
    q: String,
}

/// GET /api/extensions/marketplace
///
/// Mirrors Python `handlers.py::marketplace_search` /
/// `_marketplace_search_sync` and `extensions_marketplace.py::search_index`.
/// The index URL comes from config's `extension_index_url`; when unset (the
/// default) no network fetch is attempted and the result is an empty list,
/// matching Python's `fetch_index` early-return on empty `get_index_url()`.
/// `total` is `results.len()` (not the extension-count pattern used elsewhere
/// in this codebase for the installed-extensions list), matching Python's
/// `len(results)` in `_marketplace_search_sync`.
pub async fn marketplace(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    Query(q): Query<MarketplaceQuery>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    let config = crate::ext_config::read_config(&state.config.config_path).unwrap_or(json!({}));
    let index_url = config
        .get("extension_index_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut extensions: Vec<Value> = if index_url.is_empty() {
        Vec::new()
    } else {
        match state.python_client.get(&index_url).send().await {
            Ok(resp) => match resp.json::<Value>().await {
                Ok(Value::Array(items)) => items,
                Ok(Value::Object(map)) => map
                    .get("extensions")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default(),
                _ => Vec::new(),
            },
            Err(_) => Vec::new(),
        }
    };
    let installed = installed_extension_names(&state);
    let extensions = filter_and_annotate_marketplace(extensions, &q.q, &installed);
    let total = extensions.len();
    api_result(json!({"extensions": extensions, "total": total}))
}

/// Pure marketplace post-processing, extracted from [`marketplace`] so it is
/// testable without a network fetch: case-insensitive substring filter over
/// name/description/author (mirrors `search_index`), then `installed`
/// annotation — only added at all when `installed` is non-empty, matching
/// Python's behavior of never emitting the key when nothing is installed
/// locally rather than emitting it as `false`.
fn filter_and_annotate_marketplace(
    mut extensions: Vec<Value>,
    query: &str,
    installed: &HashSet<String>,
) -> Vec<Value> {
    if !query.is_empty() {
        let needle = query.to_lowercase();
        extensions.retain(|ext| {
            let name = ext
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            let desc = ext
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            let author = ext
                .get("author")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            name.contains(&needle) || desc.contains(&needle) || author.contains(&needle)
        });
    }
    if !installed.is_empty() {
        for ext in extensions.iter_mut() {
            let name = ext
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if let Some(obj) = ext.as_object_mut() {
                obj.insert(
                    "installed".to_string(),
                    Value::Bool(installed.contains(&name)),
                );
            }
        }
    }
    extensions
}

/// POST /api/extensions/marketplace/refresh
pub async fn marketplace_refresh(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// GET /api/extensions/os-isolation
pub async fn os_isolation(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "os_isolation": {"available": false},
            "config": {
                "enabled": false, "apparmor": false,
                "macos_sandbox_exec": false, "macos_user_isolation": false,
                "windows_restricted_token": false, "windows_job_object": false
            },
            "processes": {}
        })),
    )
        .into_response()
}

/// GET /api/extensions/{name}
///
/// Mirrors Python `handlers.py::get_extension` → `ExtensionManagerView.get_extension_info`
/// → `extensions_manifest_view.py::manifest_to_dict`. `status`/`status_message`
/// are always the manifest's load-time defaults (`"loaded"`/`""`) and `health`
/// is always `null`: Rust standalone has no module-loading pipeline and no
/// health-probe capability (Python's `compute_health` never runs here), so
/// reporting anything else would be dishonest — same rationale as the
/// `isolation`/`os_isolation` handlers' explicit "not available" answers.
pub async fn extension_detail(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    let Some((dir, manifest)) = find_extension_manifest(&state, &name) else {
        return api_result_status(
            json!({"error": format!("Extension '{}' not found", name)}),
            StatusCode::NOT_FOUND,
        );
    };
    let config = crate::ext_config::read_config(&state.config.config_path).unwrap_or(json!({}));
    let enabled = crate::ext_config::resolve_extension_enabled(&config, &name, &manifest);
    let priority = crate::ext_config::extension_value(&config, &name, "priority")
        .and_then(|v| v.as_i64())
        .unwrap_or_else(|| {
            manifest
                .get("config")
                .and_then(|c| c.get("priority"))
                .and_then(Value::as_i64)
                .unwrap_or(100)
        });
    let empty_schema = json!({});
    let config_schema =
        build_manifest_config_schema(manifest.get("config_schema").unwrap_or(&empty_schema));
    let trust = trust_level(&state, &name, &dir);
    let version = manifest
        .get("version")
        .map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_else(|| "0.0.0".to_string());
    let blueprint_prefix = manifest
        .get("blueprint_prefix")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    api_result(json!({
        "name": name,
        "version": version,
        "description": manifest.get("description").and_then(Value::as_str).unwrap_or(""),
        "type": manifest.get("type").and_then(Value::as_str).unwrap_or("general"),
        "category": manifest.get("category").and_then(Value::as_str).unwrap_or(""),
        "entry": manifest.get("entry").and_then(Value::as_str).unwrap_or(""),
        "hooks": manifest.get("hooks").cloned().unwrap_or(json!([])),
        "enabled": enabled,
        "priority": priority,
        "config_schema": config_schema,
        "source": "local",
        "has_blueprint": manifest.get("has_blueprint").and_then(Value::as_bool).unwrap_or(false),
        "blueprint_prefix": blueprint_prefix,
        "nav": manifest.get("nav").cloned().unwrap_or(json!({})),
        "status": "loaded",
        "status_message": "",
        "trust_level": trust,
        "health": Value::Null,
    }))
}

/// GET /api/extensions/{name}/scan-results
pub async fn extension_scan_results(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// GET /api/extensions/{name}/tokens
pub async fn extension_tokens(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// GET /api/extensions/{name}/integrity
pub async fn extension_integrity(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// GET /api/extensions/{name}/permissions
pub async fn extension_permissions_get(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// POST /api/extensions/{name}/permissions
pub async fn extension_permissions_post(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// POST /api/extensions/{name}/toggle
///
/// Mirrors Python `handlers.py::toggle_extension` (56-70 行) +
/// `extensions_admin.py::persist_extension_state`. Python's version also
/// flips a live in-process `ExtensionManager` (hook registry, isolated
/// process stop) — this server has no such in-process extension runtime, so
/// only the persistence-layer effect (`config.extensions.<name>.enabled`) is
/// reproduced, matching what the already-native GET routes
/// (`extension_detail`, `extension_config_get`) already read back via
/// `ext_config::resolve_extension_enabled`.
///
/// Python checks manifest existence lazily (only on the "key absent" branch
/// directly, and via `mgr.set_enabled` returning `False` on the "key
/// present" branch); both branches 404 identically, so this checks once
/// up front for the same externally-observable result.
pub async fn extension_toggle(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    AxumPath(name): AxumPath<String>,
    body: Bytes,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }

    // Mirrors Python `require_json_dict` (core/infra_core/api_request.py).
    let data: Value = match serde_json::from_slice::<Value>(&body) {
        Ok(v) if v.is_object() => v,
        Ok(_) => {
            return api_result_status(
                json!({"error": "JSON object body is required", "code": "invalid_json_object"}),
                StatusCode::BAD_REQUEST,
            )
        }
        Err(_) => {
            return api_result_status(
                json!({"error": "Invalid JSON body", "code": "invalid_json"}),
                StatusCode::BAD_REQUEST,
            )
        }
    };

    let Some((_, manifest)) = find_extension_manifest(&state, &name) else {
        return api_result_status(
            json!({"error": format!("Extension '{}' not found", name)}),
            StatusCode::NOT_FOUND,
        );
    };

    // `get_arg(data, ("enabled", "on"), None)`: first key whose value is not
    // JSON null wins; both absent/null falls through to "invert current".
    let requested = data
        .get("enabled")
        .filter(|v| !v.is_null())
        .or_else(|| data.get("on").filter(|v| !v.is_null()));

    let enabled = match requested {
        // `bool(enabled)` in Python is a truthiness coercion, not a type
        // check — any JSON value (string/number/etc) is accepted.
        Some(v) => truthy(v),
        None => {
            let config =
                crate::ext_config::read_config(&state.config.config_path).unwrap_or(json!({}));
            !crate::ext_config::resolve_extension_enabled(&config, &name, &manifest)
        }
    };

    let _guard = state.settings_lock.lock().await;
    if let Err(e) = crate::ext_config::save_extension_value(
        &state.config.config_path,
        &name,
        "enabled",
        Value::Bool(enabled),
    ) {
        return api_result_status(
            json!({"error": format!("failed to save extension state: {}", e)}),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    api_result(json!({
        "name": name,
        "enabled": enabled,
        "message": format!(
            "Extension '{}' {}",
            name,
            if enabled { "enabled" } else { "disabled" }
        ),
    }))
}

/// POST /api/extensions/{name}/rescan
pub async fn extension_rescan(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// GET /api/extensions/{name}/config
///
/// Mirrors Python `handlers.py::extension_config` (GET branch) →
/// `extensions_api_config_ops.py::build_config_schema`: every schema field is
/// included unconditionally (unlike `manifest_to_dict`'s conditional
/// `options`/`range`/`description`), plus a resolved `value` (config.json
/// override → schema default), with secret-named fields
/// (`secret`/`token`/`password`/`api_key`/`apikey` substring) masked to
/// `null` regardless of their stored value.
pub async fn extension_config_get(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }
    let Some((_, manifest)) = find_extension_manifest(&state, &name) else {
        return api_result_status(
            json!({"error": format!("Extension '{}' not found", name)}),
            StatusCode::NOT_FOUND,
        );
    };
    let config = crate::ext_config::read_config(&state.config.config_path).unwrap_or(json!({}));
    let empty_schema = json!({});
    let schema_raw = manifest.get("config_schema").unwrap_or(&empty_schema);
    let config_schema = build_config_schema_with_values(&config, &name, schema_raw);
    api_result(json!({"name": name, "config_schema": config_schema}))
}

/// POST /api/extensions/{name}/config
///
/// Mirrors Python `handlers.py::extension_config` (POST branch) →
/// `extensions_api_config_ops.py::validate_and_save_config` →
/// `extensions_admin.py::validate_config_value` / `save_extension_config_values`
/// (secret-field encryption in `save_extension_config_values` is not
/// reproduced — out of scope for this route pair and would need a new crate
/// dependency; values are persisted as given, matching the response shape
/// `{"saved": values}` which always echoes the raw request payload anyway,
/// never the encrypted-at-rest form).
pub async fn extension_config_post(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    AxumPath(name): AxumPath<String>,
    body: Bytes,
) -> Response {
    if let Some(r) = admin_gate(&state, auth.as_ref()) {
        return r;
    }

    let Some((_, manifest)) = find_extension_manifest(&state, &name) else {
        return api_result_status(
            json!({"error": format!("Extension '{}' not found", name)}),
            StatusCode::NOT_FOUND,
        );
    };

    // Mirrors Python `require_json_dict`.
    let data: Value = match serde_json::from_slice::<Value>(&body) {
        Ok(v) if v.is_object() => v,
        Ok(_) => {
            return api_result_status(
                json!({"error": "JSON object body is required", "code": "invalid_json_object"}),
                StatusCode::BAD_REQUEST,
            )
        }
        Err(_) => {
            return api_result_status(
                json!({"error": "Invalid JSON body", "code": "invalid_json"}),
                StatusCode::BAD_REQUEST,
            )
        }
    };
    let values: serde_json::Map<String, Value> = data
        .get("values")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let empty_schema = json!({});
    let schema_raw = manifest.get("config_schema").unwrap_or(&empty_schema);
    let schema_obj = schema_raw.as_object();

    let mut errors: Vec<String> = Vec::new();
    for (field_name, value) in &values {
        let Some(spec) = schema_obj.and_then(|o| o.get(field_name)) else {
            errors.push(format!("Unknown config field: {}", field_name));
            continue;
        };
        let empty = serde_json::Map::new();
        let spec_obj = spec.as_object().unwrap_or(&empty);
        let raw_type = spec_obj
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("str")
            .trim()
            .to_lowercase();
        let field_type = alias_config_type(&raw_type).to_lowercase();
        let options: Vec<Value> = spec_obj
            .get("options")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let range_arr = spec_obj.get("range").and_then(Value::as_array);
        let range = range_arr
            .filter(|a| a.len() == 2)
            .map(|a| (a[0].clone(), a[1].clone()));

        if let Some(err) = validate_config_value(&field_type, value, &options, range.as_ref()) {
            errors.push(format!("{}: {}", field_name, err));
        }
    }

    if !errors.is_empty() {
        return api_result_status(
            json!({"error": "Validation failed", "details": errors}),
            StatusCode::BAD_REQUEST,
        );
    }

    let _guard = state.settings_lock.lock().await;
    for (field_name, value) in &values {
        if let Err(e) = crate::ext_config::save_extension_value(
            &state.config.config_path,
            &name,
            field_name,
            value.clone(),
        ) {
            return api_result_status(
                json!({"error": format!("failed to save config: {}", e)}),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    }

    api_result(json!({"name": name, "saved": Value::Object(values)}))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr, sync::Arc};

    use axum::body::to_bytes;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use tempfile::TempDir;

    use super::*;
    use crate::state::{AppState, Config};

    fn write_file(path: &std::path::Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    async fn test_state(project_root: PathBuf, config_body: &str) -> SharedState {
        write_file(&project_root.join("config.json"), config_body);
        let pool = SqlitePoolOptions::new()
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:").unwrap())
            .await
            .unwrap();
        Arc::new(
            AppState::new(
                Config {
                    db_path: "sqlite::memory:".to_string(),
                    pin_hash: String::new(),
                    valid_token: String::new(),
                    secret: String::new(),
                    trusted_proxy_enabled: false,
                    pin_boss_login_ui: false,
                    trusted_ips: HashSet::new(),
                    trusted_peer_ips: HashSet::new(),
                    quick_lock_enabled: true,
                    pin_auth_enabled: false,
                    min_pin_length: 4,
                    python_url: String::new(),
                    config_path: project_root.join("config.json"),
                    project_root,
                    app_config: json!({}),
                    cache_dir: PathBuf::from("."),
                    server_mode: "full".to_string(),
                    headless: false,
                    safe_mode: false,
                    mcp_native: false,
                    standalone: false,
                    infer_standalone: true,
                    active_profile: None,
                    python_executable: String::new(),
                },
                pool.clone(),
                pool,
                Arc::new(crate::logs::ring::LogRingBuffer::new(64)),
            )
            .await,
        )
    }

    async fn json_body(response: Response) -> Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn write_extension(root: &std::path::Path, dir_name: &str, manifest: &str) {
        write_file(
            &root
                .join("extensions")
                .join(dir_name)
                .join("extension.json"),
            manifest,
        );
    }

    // ── extension_detail ────────────────────────────────────────────────────

    #[tokio::test]
    async fn extension_detail_404_when_manifest_missing() {
        let temp = TempDir::new().unwrap();
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let resp = extension_detail(
            State(Arc::clone(&state)),
            None,
            AxumPath("nonexistent-ext".to_string()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = json_body(resp).await;
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"], "Extension 'nonexistent-ext' not found");
    }

    #[tokio::test]
    async fn extension_detail_config_json_override_wins_over_manifest_default() {
        // Pins the resolve_extension_enabled precedence: a config.json
        // per-extension override must beat the extension.json manifest's
        // own config.enabled, not the other way around.
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config": {"enabled": true}}"#,
        );
        let state = test_state(
            temp.path().to_path_buf(),
            r#"{"extensions": {"sample": {"enabled": false}}}"#,
        )
        .await;

        let resp = extension_detail(
            State(Arc::clone(&state)),
            None,
            AxumPath("sample".to_string()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["enabled"], false);
    }

    #[tokio::test]
    async fn extension_detail_falls_back_to_manifest_default_without_override() {
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config": {"enabled": false}}"#,
        );
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(
            extension_detail(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
            )
            .await,
        )
        .await;
        assert_eq!(body["enabled"], false);
        assert_eq!(body["trust_level"], "untrusted");
        assert_eq!(body["health"], Value::Null);
        assert_eq!(body["status"], "loaded");
    }

    #[tokio::test]
    async fn extension_detail_scan_survives_unreadable_manifest_in_earlier_directory() {
        // Regression test for a bug caught in self-review: find_extension_manifest
        // originally used `.ok()?` inside the scan loop, which aborted the ENTIRE
        // directory scan (returning None early) the moment it hit any directory
        // without a readable/parseable extension.json — not just skipped that one
        // entry. A decoy directory ("aaa-decoy" sorts before "sample" on most
        // filesystems) with no extension.json at all must not prevent the target
        // extension, scanned later, from being found.
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path().join("extensions").join("aaa-decoy")).unwrap();
        write_extension(temp.path(), "sample", r#"{"name": "sample"}"#);
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let resp = extension_detail(
            State(Arc::clone(&state)),
            None,
            AxumPath("sample".to_string()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["name"], "sample");
    }

    // ── extension_config_get ────────────────────────────────────────────────

    #[tokio::test]
    async fn extension_config_get_404_when_manifest_missing() {
        let temp = TempDir::new().unwrap();
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let resp = extension_config_get(
            State(Arc::clone(&state)),
            None,
            AxumPath("nonexistent-ext".to_string()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn extension_config_get_masks_secret_fields_and_resolves_value() {
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config_schema": {
                "api_key": {"type": "string", "default": "unset"},
                "threshold": {"type": "number", "default": 5}
            }}"#,
        );
        let state = test_state(
            temp.path().to_path_buf(),
            r#"{"extensions": {"sample": {"api_key": "real-secret", "threshold": 9}}}"#,
        )
        .await;

        let body = json_body(
            extension_config_get(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
            )
            .await,
        )
        .await;
        let schema = &body["config_schema"];
        // Secret-named field: value masked to null even though config.json has a stored value.
        assert_eq!(schema["api_key"]["value"], Value::Null);
        assert_eq!(schema["api_key"]["type"], "str");
        // Non-secret field: value resolves from config.json override.
        assert_eq!(schema["threshold"]["value"], 9);
        assert_eq!(schema["threshold"]["type"], "float");
    }

    // ── extension_toggle ────────────────────────────────────────────────────

    fn body_json(v: Value) -> Bytes {
        Bytes::from(serde_json::to_vec(&v).unwrap())
    }

    #[tokio::test]
    async fn extension_toggle_404_when_manifest_missing() {
        let temp = TempDir::new().unwrap();
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let resp = extension_toggle(
            State(Arc::clone(&state)),
            None,
            AxumPath("nonexistent-ext".to_string()),
            body_json(json!({})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = json_body(resp).await;
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"], "Extension 'nonexistent-ext' not found");
    }

    #[tokio::test]
    async fn extension_toggle_inverts_current_value_when_key_absent() {
        // Manifest defaults enabled=true (no config override) — an empty
        // body must invert it to false and persist that inversion, not
        // default to any fixed value.
        let temp = TempDir::new().unwrap();
        write_extension(temp.path(), "sample", r#"{"name": "sample"}"#);
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(
            extension_toggle(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
                body_json(json!({})),
            )
            .await,
        )
        .await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["enabled"], false);
        assert_eq!(body["message"], "Extension 'sample' disabled");

        // Persisted: re-reading config.json directly must reflect the flip.
        let config = crate::ext_config::read_config(&state.config.config_path).unwrap();
        assert_eq!(config["extensions"]["sample"]["enabled"], false);
    }

    #[tokio::test]
    async fn extension_toggle_explicit_enabled_key_overrides_current_value() {
        let temp = TempDir::new().unwrap();
        write_extension(temp.path(), "sample", r#"{"name": "sample"}"#);
        // Already enabled=true; an explicit {"enabled": true} must still be
        // honored (not treated as "absent" and inverted).
        let state = test_state(
            temp.path().to_path_buf(),
            r#"{"extensions": {"sample": {"enabled": true}}}"#,
        )
        .await;

        let body = json_body(
            extension_toggle(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
                body_json(json!({"enabled": true})),
            )
            .await,
        )
        .await;
        assert_eq!(body["enabled"], true);
        assert_eq!(body["message"], "Extension 'sample' enabled");
    }

    #[tokio::test]
    async fn extension_toggle_accepts_on_alias_key() {
        let temp = TempDir::new().unwrap();
        write_extension(temp.path(), "sample", r#"{"name": "sample"}"#);
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(
            extension_toggle(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
                body_json(json!({"on": false})),
            )
            .await,
        )
        .await;
        assert_eq!(body["enabled"], false);
    }

    #[tokio::test]
    async fn extension_toggle_coerces_truthy_non_bool_values() {
        // Python's `bool(enabled)` is truthiness coercion, not a type
        // check — a non-empty string is truthy.
        let temp = TempDir::new().unwrap();
        write_extension(temp.path(), "sample", r#"{"name": "sample"}"#);
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(
            extension_toggle(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
                body_json(json!({"enabled": ""})),
            )
            .await,
        )
        .await;
        // Empty string is falsy.
        assert_eq!(body["enabled"], false);
    }

    // ── extension_config_post ───────────────────────────────────────────────

    #[tokio::test]
    async fn extension_config_post_404_when_manifest_missing() {
        let temp = TempDir::new().unwrap();
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let resp = extension_config_post(
            State(Arc::clone(&state)),
            None,
            AxumPath("nonexistent-ext".to_string()),
            body_json(json!({"values": {}})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn extension_config_post_unknown_field_400_details_and_no_save() {
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config_schema": {
                "threshold": {"type": "number", "default": 5}
            }}"#,
        );
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let resp = extension_config_post(
            State(Arc::clone(&state)),
            None,
            AxumPath("sample".to_string()),
            body_json(json!({"values": {"nope": 1}})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_body(resp).await;
        assert_eq!(body["error"], "Validation failed");
        assert_eq!(body["details"], json!(["Unknown config field: nope"]));

        // Nothing saved.
        let config = crate::ext_config::read_config(&state.config.config_path).unwrap();
        assert_eq!(config.get("extensions"), None);
    }

    #[tokio::test]
    async fn extension_config_post_bool_type_mismatch_message() {
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config_schema": {
                "flag": {"type": "bool", "default": false}
            }}"#,
        );
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(
            extension_config_post(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
                body_json(json!({"values": {"flag": 1}})),
            )
            .await,
        )
        .await;
        assert_eq!(body["details"], json!(["flag: Expected bool, got int"]));
    }

    #[tokio::test]
    async fn extension_config_post_bool_value_rejected_for_int_field() {
        // Deliberate divergence from CPython's isinstance(bool, int)
        // subclassing quirk — see `validate_config_value` doc comment.
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config_schema": {
                "count": {"type": "int", "default": 1}
            }}"#,
        );
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(
            extension_config_post(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
                body_json(json!({"values": {"count": true}})),
            )
            .await,
        )
        .await;
        assert_eq!(body["details"], json!(["count: Expected int, got bool"]));
    }

    #[tokio::test]
    async fn extension_config_post_int_out_of_range_message() {
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config_schema": {
                "count": {"type": "int", "default": 1, "range": [0, 10]}
            }}"#,
        );
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(
            extension_config_post(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
                body_json(json!({"values": {"count": 42}})),
            )
            .await,
        )
        .await;
        assert_eq!(body["details"], json!(["count: Out of range [0, 10]"]));
    }

    #[tokio::test]
    async fn extension_config_post_float_type_mismatch_message() {
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config_schema": {
                "ratio": {"type": "float", "default": 0.5}
            }}"#,
        );
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(
            extension_config_post(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
                body_json(json!({"values": {"ratio": "nope"}})),
            )
            .await,
        )
        .await;
        assert_eq!(body["details"], json!(["ratio: Expected number, got str"]));
    }

    #[tokio::test]
    async fn extension_config_post_str_type_mismatch_message() {
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config_schema": {
                "label": {"type": "str", "default": "x"}
            }}"#,
        );
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(
            extension_config_post(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
                body_json(json!({"values": {"label": 5}})),
            )
            .await,
        )
        .await;
        assert_eq!(body["details"], json!(["label: Expected str, got int"]));
    }

    /// `type(value).__name__` must render Python's names, not Rust/JSON ones.
    /// Verified 2026-08-13: swapping `list`/`dict` for `array`/`object` left all
    /// 25 tests green, so the array/object/null arms were entirely unpinned —
    /// a silent divergence in a message this port matches word for word.
    #[tokio::test]
    async fn extension_config_post_reports_python_type_names_for_every_json_kind() {
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config_schema": {
                "label": {"type": "str", "default": "x"}
            }}"#,
        );
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        for (value, python_name) in [
            (json!(null), "NoneType"),
            (json!(true), "bool"),
            (json!(5), "int"),
            (json!(1.5), "float"),
            (json!([1, 2]), "list"),
            (json!({"k": 1}), "dict"),
        ] {
            let body = json_body(
                extension_config_post(
                    State(Arc::clone(&state)),
                    None,
                    AxumPath("sample".to_string()),
                    body_json(json!({"values": {"label": value}})),
                )
                .await,
            )
            .await;
            assert_eq!(
                body["details"],
                json!([format!("label: Expected str, got {python_name}")]),
                "value {value}"
            );
        }
    }

    #[tokio::test]
    async fn extension_config_post_enum_invalid_option_message() {
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config_schema": {
                "mode": {"type": "enum", "default": "a", "options": ["a", "b"]}
            }}"#,
        );
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(
            extension_config_post(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
                body_json(json!({"values": {"mode": "c"}})),
            )
            .await,
        )
        .await;
        assert_eq!(
            body["details"],
            json!(["mode: Invalid option 'c'. Allowed: ['a', 'b']"])
        );
    }

    #[tokio::test]
    async fn extension_config_post_saves_on_success_and_echoes_values() {
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config_schema": {
                "threshold": {"type": "int", "default": 1},
                "label": {"type": "str", "default": "x"}
            }}"#,
        );
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(
            extension_config_post(
                State(Arc::clone(&state)),
                None,
                AxumPath("sample".to_string()),
                body_json(json!({"values": {"threshold": 7, "label": "hi"}})),
            )
            .await,
        )
        .await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["name"], "sample");
        assert_eq!(body["saved"], json!({"threshold": 7, "label": "hi"}));

        let config = crate::ext_config::read_config(&state.config.config_path).unwrap();
        assert_eq!(config["extensions"]["sample"]["threshold"], 7);
        assert_eq!(config["extensions"]["sample"]["label"], "hi");
    }

    #[tokio::test]
    async fn extension_config_post_partial_failure_saves_nothing() {
        // One valid field alongside one invalid field: Python's
        // validate_and_save_config never calls save_extension_config_values
        // when `errors` is non-empty, so even the valid field must not be
        // persisted.
        let temp = TempDir::new().unwrap();
        write_extension(
            temp.path(),
            "sample",
            r#"{"name": "sample", "config_schema": {
                "threshold": {"type": "int", "default": 1},
                "flag": {"type": "bool", "default": false}
            }}"#,
        );
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let resp = extension_config_post(
            State(Arc::clone(&state)),
            None,
            AxumPath("sample".to_string()),
            body_json(json!({"values": {"threshold": 7, "flag": "not-a-bool"}})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let config = crate::ext_config::read_config(&state.config.config_path).unwrap();
        assert_eq!(config.get("extensions"), None);
    }

    // ── marketplace ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn marketplace_empty_index_url_returns_empty_no_network() {
        // No extension_index_url configured — must not attempt a fetch.
        let temp = TempDir::new().unwrap();
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(
            marketplace(
                State(Arc::clone(&state)),
                None,
                Query(MarketplaceQuery { q: String::new() }),
            )
            .await,
        )
        .await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["extensions"], json!([]));
        assert_eq!(body["total"], 0);
    }

    #[tokio::test]
    async fn marketplace_installed_flag_reflects_local_extension_dir() {
        // Pins the `installed` flag computation through the same pure helper
        // marketplace() calls: a result whose name matches a locally
        // installed extension is flagged true, a non-match false.
        let mut installed = HashSet::new();
        installed.insert("sample".to_string());
        let extensions = vec![json!({"name": "sample"}), json!({"name": "other"})];
        let out = filter_and_annotate_marketplace(extensions, "", &installed);
        assert_eq!(out[0]["installed"], true);
        assert_eq!(out[1]["installed"], false);
    }

    #[tokio::test]
    async fn marketplace_installed_key_absent_when_nothing_installed_locally() {
        // Python only adds the "installed" key at all when the local
        // installed-set is non-empty; with zero local extensions no result
        // gets an "installed" key, not even `false`.
        let extensions = vec![json!({"name": "sample"})];
        let out = filter_and_annotate_marketplace(extensions, "", &HashSet::new());
        assert!(out[0].get("installed").is_none());
    }

    // ── isolation ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn isolation_reports_unavailable_honestly() {
        let temp = TempDir::new().unwrap();
        let state = test_state(temp.path().to_path_buf(), "{}").await;

        let body = json_body(isolation(State(Arc::clone(&state)), None).await).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["available"], false);
        assert_eq!(body["processes"], json!({}));
    }
}
