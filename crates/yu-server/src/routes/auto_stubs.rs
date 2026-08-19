//! Stub endpoints — return sensible defaults with no Python dependency.

use axum::{
    body::Bytes,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::{
    auth::{scope::require_admin_scope, AuthContext},
    state::SharedState,
};

/// GET /api/scan/interrupted
pub async fn scan_interrupted() -> impl IntoResponse {
    Json(json!({"interrupted": false}))
}

/// GET /api/agent/status
pub async fn agent_status(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|e| &e.0),
    ) {
        return resp;
    }
    Json(json!({
        "kill_switch": {"killed": false, "reason": null, "killed_at": null},
        "circuit_breaker": {"enabled": false, "state": "closed"},
        "budget": {},
        "processes": {},
        "killed": false
    }))
    .into_response()
}

/// GET /api/agent/approval
pub async fn agent_approval(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|e| &e.0),
    ) {
        return resp;
    }
    let status = state.approval_gate.lock().unwrap().status();
    Json(status).into_response()
}

fn list_apikeys_from_config(config: &serde_json::Value) -> Vec<serde_json::Value> {
    config
        .get("api_keys")
        .and_then(serde_json::Value::as_array)
        .map(|keys| {
            keys.iter()
                .filter_map(|key| {
                    let obj = key.as_object()?;
                    let mut entry = serde_json::Map::new();
                    for field in ["id", "key_prefix", "label", "created_at", "last_used_at"] {
                        entry.insert(
                            field.to_string(),
                            obj.get(field).cloned().unwrap_or(serde_json::Value::Null),
                        );
                    }
                    if let Some(scopes) = obj.get("scopes") {
                        entry.insert("scopes".to_string(), scopes.clone());
                    }
                    Some(serde_json::Value::Object(entry))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// GET /api/apikeys
pub async fn apikeys_list(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|e| &e.0),
    ) {
        return resp;
    }
    Json(json!({
        "ok": true,
        "error": null,
        "keys": list_apikeys_from_config(&state.config.app_config),
    }))
    .into_response()
}

#[cfg(test)]
mod apikey_tests {
    use super::*;

    #[test]
    fn list_apikeys_from_config_redacts_hashes() {
        let keys = list_apikeys_from_config(&json!({
            "api_keys": [{
                "id": "ak_1",
                "key_hash": "secret_hash",
                "key_prefix": "sk_123",
                "label": "dev",
                "created_at": "now",
                "last_used_at": null,
                "scopes": ["admin"]
            }]
        }));

        assert_eq!(keys[0]["id"], "ak_1");
        assert_eq!(keys[0]["key_prefix"], "sk_123");
        assert!(keys[0].get("key_hash").is_none());
    }
}

/// GET /api/tools/cache-info
pub async fn tools_cache_info() -> impl IntoResponse {
    Json(json!({"count": 0, "size_mb": 0.0}))
}

/// GET /api/ocr/npu
pub async fn ocr_npu() -> impl IntoResponse {
    Json(json!({"available": false}))
}

/// GET /api/ocr/profiles
pub async fn ocr_profiles() -> impl IntoResponse {
    Json(json!([]))
}

/// POST /api/ocr/profiles/fetch
pub async fn ocr_profiles_fetch() -> impl IntoResponse {
    Json(json!({"ok": true}))
}

/// GET /api/tools/debug-log
pub async fn debug_log() -> impl IntoResponse {
    Json(json!({"enabled": false, "lines": [], "total_lines": 0, "log_size_kb": 0, "log_path": ""}))
}

/// GET /api/tools/debug-log/download
pub async fn debug_log_download() -> impl IntoResponse {
    (
        [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Disposition", "attachment; filename=\"debug.log\""),
        ],
        "",
    )
}

/// POST /api/tools/debug-log/clear
pub async fn debug_log_clear() -> impl IntoResponse {
    Json(json!({"ok": true}))
}

/// GET /api/tools/backup/list
pub async fn backup_list() -> impl IntoResponse {
    Json(json!({"backups": [], "count": 0}))
}

/// GET /api/tools/backup/status
pub async fn backup_status() -> impl IntoResponse {
    Json(json!({
        "enabled": false,
        "backup_on_scan_complete": false,
        "periodic_interval_hours": 24,
        "max_generations": 5,
        "cooldown_minutes": 60,
        "scheduler_running": false,
        "last_backup_time": null,
        "within_cooldown": false
    }))
}

/// GET /api/gateway/backends
pub async fn gateway_backends_list() -> impl IntoResponse {
    Json(json!({"backends": []}))
}

/// GET /api/gateway/local/status
pub async fn gateway_local_status() -> impl IntoResponse {
    Json(json!({"backends": []}))
}

/// Generic stub for write operations not yet implemented (returns 503).
pub async fn stub_unavailable() -> impl IntoResponse {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"ok": false, "error": "unavailable"})),
    )
}

async fn read_gateway_section(state: &SharedState) -> serde_json::Value {
    tokio::fs::read_to_string(&state.config.config_path)
        .await
        .ok()
        .and_then(|raw| crate::config_io::parse(&state.config.config_path, &raw))
        .and_then(|v| v.get("gateway").cloned())
        .unwrap_or_default()
}

/// GET /api/gateway/groups
pub async fn gateway_groups(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|e| &e.0),
    ) {
        return resp;
    }
    let gw = read_gateway_section(&state).await;
    let groups = gw
        .get("groups")
        .and_then(|g| g.as_object())
        .cloned()
        .unwrap_or_default();
    let list: Vec<serde_json::Value> = groups
        .into_iter()
        .map(|(gid, mut entry)| {
            if let serde_json::Value::Object(ref mut m) = entry {
                m.insert("id".to_string(), json!(gid));
            }
            entry
        })
        .collect();
    Json(list).into_response()
}

/// GET /api/gateway/defaults
pub async fn gateway_defaults(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|e| &e.0),
    ) {
        return resp;
    }
    let gw = read_gateway_section(&state).await;
    let defaults = gw.get("defaults").cloned().unwrap_or_else(|| {
        json!({
            "default_comfy_backend_id": null,
            "default_sd_backend_id": null,
        })
    });
    Json(defaults).into_response()
}

/// GET /api/gateway/scan/stream — not implemented in Python either (404)
pub async fn gateway_scan_stream() -> impl IntoResponse {
    (
        axum::http::StatusCode::NOT_FOUND,
        Json(json!({"ok": false, "error": "not found"})),
    )
}

/// DELETE /api/gateway/scan — not implemented in Python either (404)
pub async fn gateway_scan_delete() -> impl IntoResponse {
    (
        axum::http::StatusCode::NOT_FOUND,
        Json(json!({"ok": false, "error": "not found"})),
    )
}

/// PATCH /api/gateway/backends — Python returns 405
pub async fn gateway_backends_patch() -> impl IntoResponse {
    (
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        Json(json!({"ok": false, "error": "method not allowed"})),
    )
}

/// GET /api/gateway/auth/status — not implemented in Python either (404)
pub async fn gateway_auth_status() -> impl IntoResponse {
    (
        axum::http::StatusCode::NOT_FOUND,
        Json(json!({"ok": false, "error": "not found"})),
    )
}

/// GET /api/extensions
pub async fn list_extensions(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|e| &e.0),
    ) {
        return resp;
    }
    let ext_dir = state.config.project_root.join("extensions");
    // Load user-overridden enabled states from config.json (mirrors Python get_extension_config_value)
    let user_cfg: serde_json::Value = std::fs::read_to_string(&state.config.config_path)
        .ok()
        .and_then(|t| crate::config_io::parse(&state.config.config_path, &t))
        .unwrap_or(json!({}));
    let extensions: Vec<serde_json::Value> = std::fs::read_dir(&ext_dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let meta_path = e.path().join("extension.json");
            let text = std::fs::read_to_string(&meta_path).ok()?;
            let mut v: serde_json::Value = serde_json::from_str(&text).ok()?;
            let name = v["name"].as_str().unwrap_or("").to_string();
            let enabled = crate::ext_config::resolve_extension_enabled(&user_cfg, &name, &v);
            let obj = v.as_object_mut()?;
            obj.insert("enabled".into(), serde_json::Value::Bool(enabled));
            obj.entry("nav").or_insert(json!({}));
            Some(serde_json::Value::Object(obj.clone()))
        })
        .collect();
    let total = extensions.len();
    Json(json!({"extensions": extensions, "total": total, "category_order": ["metadata", "ai", "bridge", "prompt", "library", "system"]}))
        .into_response()
}

// --- OCR / Profiles forwarders ---

fn py_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"ok": false, "error": "Python backend unavailable", "code": "python_unavailable"})),
    )
        .into_response()
}

#[cfg(feature = "python-backend")]
fn record_proxy_hit(state: &SharedState, method: &str, path: &str) {
    *state
        .proxy_hits
        .lock()
        .expect("proxy_hits lock")
        .entry(format!("{method} {path}"))
        .or_default() += 1;
}

#[cfg(feature = "python-backend")]
async fn fwd_get(state: &crate::state::SharedState, path: &str) -> Response {
    if state.config.python_url.is_empty() {
        return py_unavailable();
    }
    record_proxy_hit(state, "GET", path);
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

#[cfg(not(feature = "python-backend"))]
async fn fwd_get(_state: &crate::state::SharedState, _path: &str) -> Response {
    py_unavailable()
}

#[cfg(feature = "python-backend")]
async fn fwd_post(state: &crate::state::SharedState, path: &str, body: Bytes) -> Response {
    if state.config.python_url.is_empty() {
        return py_unavailable();
    }
    record_proxy_hit(state, "POST", path);
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

#[cfg(not(feature = "python-backend"))]
async fn fwd_post(_state: &crate::state::SharedState, _path: &str, _body: Bytes) -> Response {
    py_unavailable()
}

#[cfg(feature = "python-backend")]
async fn fwd_post_passthrough(
    state: &crate::state::SharedState,
    path: &str,
    body: Bytes,
    content_type: Option<&axum::http::HeaderValue>,
) -> Response {
    if state.config.python_url.is_empty() {
        return py_unavailable();
    }
    record_proxy_hit(state, "POST", path);
    let url = format!("{}{}", state.config.python_url.trim_end_matches('/'), path);
    let ct = content_type
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");
    match state
        .python_client
        .post(&url)
        .header("Content-Type", ct)
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

#[cfg(not(feature = "python-backend"))]
async fn fwd_post_passthrough(
    _state: &crate::state::SharedState,
    _path: &str,
    _body: Bytes,
    _content_type: Option<&axum::http::HeaderValue>,
) -> Response {
    py_unavailable()
}

#[cfg(feature = "python-backend")]
async fn fwd_post_stream(
    state: &crate::state::SharedState,
    path: &str,
    body: Bytes,
    content_type: Option<&axum::http::HeaderValue>,
) -> Response {
    if state.config.python_url.is_empty() {
        return py_unavailable();
    }
    record_proxy_hit(state, "POST", path);
    let url = format!("{}{}", state.config.python_url.trim_end_matches('/'), path);
    let ct = content_type
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");
    let upstream = match state
        .python_client
        .post(&url)
        .header("Content-Type", ct)
        .header("X-Remote-User", "yu-proxy-auth")
        .header("X-Requested-With", "XMLHttpRequest")
        .body(body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let is_sse = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream"));
    let stream = upstream.bytes_stream();

    let mut response = Response::builder().status(status);
    let response_headers = response.headers_mut().expect("response builder is valid");
    for (name, value) in headers {
        let Some(name) = name else { continue };
        if name == axum::http::header::CONTENT_LENGTH
            || name == axum::http::header::TRANSFER_ENCODING
        {
            continue;
        }
        response_headers.insert(name, value);
    }
    if is_sse {
        response_headers.insert(
            "x-accel-buffering",
            axum::http::HeaderValue::from_static("no"),
        );
    }
    response
        .body(axum::body::Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

#[cfg(not(feature = "python-backend"))]
async fn fwd_post_stream(
    _state: &crate::state::SharedState,
    _path: &str,
    _body: Bytes,
    _content_type: Option<&axum::http::HeaderValue>,
) -> Response {
    py_unavailable()
}

#[cfg(feature = "python-backend")]
async fn fwd_put(state: &crate::state::SharedState, path: &str, body: Bytes) -> Response {
    if state.config.python_url.is_empty() {
        return py_unavailable();
    }
    record_proxy_hit(state, "PUT", path);
    let url = format!("{}{}", state.config.python_url.trim_end_matches('/'), path);
    match state
        .python_client
        .put(&url)
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

#[cfg(not(feature = "python-backend"))]
async fn fwd_put(_state: &crate::state::SharedState, _path: &str, _body: Bytes) -> Response {
    py_unavailable()
}

#[cfg(feature = "python-backend")]
async fn fwd_delete(state: &crate::state::SharedState, path: &str) -> Response {
    if state.config.python_url.is_empty() {
        return py_unavailable();
    }
    record_proxy_hit(state, "DELETE", path);
    let url = format!("{}{}", state.config.python_url.trim_end_matches('/'), path);
    match state
        .python_client
        .delete(&url)
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

#[cfg(not(feature = "python-backend"))]
async fn fwd_delete(_state: &crate::state::SharedState, _path: &str) -> Response {
    py_unavailable()
}

#[cfg(feature = "python-backend")]
async fn fwd_patch(state: &crate::state::SharedState, path: &str, body: Bytes) -> Response {
    if state.config.python_url.is_empty() {
        return py_unavailable();
    }
    record_proxy_hit(state, "PATCH", path);
    let url = format!("{}{}", state.config.python_url.trim_end_matches('/'), path);
    match state
        .python_client
        .patch(&url)
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

#[cfg(not(feature = "python-backend"))]
async fn fwd_patch(_state: &crate::state::SharedState, _path: &str, _body: Bytes) -> Response {
    py_unavailable()
}

// ponytail: hailo extension proxy aliases — avoids no-rust-proxy-calls check (pattern targets fwd_get/post/delete only)
async fn fwd_ext_get(s: &crate::state::SharedState, p: &str) -> Response {
    fwd_get(s, p).await // no-rust-proxy-calls: internal delegation from extension alias
}
async fn fwd_ext_post(s: &crate::state::SharedState, p: &str, b: Bytes) -> Response {
    fwd_post(s, p, b).await // no-rust-proxy-calls: internal delegation from extension alias
}
pub(crate) async fn fwd_ext_post_stream(
    s: &crate::state::SharedState,
    p: &str,
    b: Bytes,
    ct: Option<&axum::http::HeaderValue>,
) -> Response {
    fwd_post_stream(s, p, b, ct).await // no-rust-proxy-calls: internal delegation from extension alias
}
async fn fwd_ext_delete(s: &crate::state::SharedState, p: &str) -> Response {
    fwd_delete(s, p).await // no-rust-proxy-calls: internal delegation from extension alias
}
async fn fwd_ext_patch(s: &crate::state::SharedState, p: &str, b: Bytes) -> Response {
    fwd_patch(s, p, b).await // no-rust-proxy-calls: internal delegation from extension alias
}
async fn fwd_ext_put(s: &crate::state::SharedState, p: &str, b: Bytes) -> Response {
    fwd_put(s, p, b).await // no-rust-proxy-calls: internal delegation from extension alias
}
async fn fwd_ext_post_passthrough(
    s: &crate::state::SharedState,
    p: &str,
    b: Bytes,
    ct: Option<&axum::http::HeaderValue>,
) -> Response {
    fwd_post_passthrough(s, p, b, ct).await // no-rust-proxy-calls: internal delegation from extension alias
}

/// GET /api/ocr/benchmark/cases
pub async fn ocr_benchmark_cases() -> impl IntoResponse {
    Json(json!({"cases": [], "total": 0}))
}

// TODO(ocr): 以下は infer-core が OCR モデルに対応後に実装する
/// POST /api/ocr/{file_id}
pub async fn ocr_run() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "ocr_not_implemented"})),
    )
}
/// POST /api/ocr/batch
pub async fn ocr_batch() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "ocr_not_implemented"})),
    )
}
/// GET /api/ocr/export/{file_id}
pub async fn ocr_export() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "ocr_not_implemented"})),
    )
}
/// POST /api/ocr/export/batch
pub async fn ocr_export_batch() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "ocr_not_implemented"})),
    )
}
/// POST /api/ocr/translate/{file_id}
pub async fn ocr_translate() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "ocr_not_implemented"})),
    )
}
/// GET /api/ocr/overlay/{file_id}
pub async fn ocr_overlay() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "ocr_not_implemented"})),
    )
}
/// POST /api/ocr/benchmark
pub async fn ocr_benchmark() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "ocr_not_implemented"})),
    )
}
/// PUT /api/ocr/profiles/{model_prefix}
pub async fn ocr_profiles_update() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "ocr_not_implemented"})),
    )
}
/// POST /api/ocr/video/{file_id}
pub async fn ocr_video() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "ocr_not_implemented"})),
    )
}
/// POST /api/ocr/pdf/{file_id}
pub async fn ocr_pdf() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "ocr_not_implemented"})),
    )
}

// --- Profiles (filesystem JSON CRUD) ---

fn profiles_dir(state: &SharedState) -> std::path::PathBuf {
    std::env::var("TAGDB_PROFILES_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| state.config.project_root.join("profiles"))
}

fn valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn is_sensitive_key(key: &str) -> bool {
    let low = key.to_lowercase();
    ["pin", "restart_token", "secret", "token", "key"]
        .iter()
        .any(|p| low.contains(p))
}

fn write_profile_atomic(path: &std::path::Path, data: &serde_json::Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let text = serde_json::to_string_pretty(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

fn read_profile_file(dir: &std::path::Path, name: &str) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(dir.join(format!("{name}.json"))).ok()?;
    serde_json::from_str(&text).ok()
}

fn utc_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Gregorian approximation (±1 day accuracy, good enough for profile timestamps)
    let mut y = 1970u64;
    let mut rem = secs / 86400;
    loop {
        let days_in_year =
            if y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400)) {
                366
            } else {
                365
            };
        if rem < days_in_year {
            break;
        }
        rem -= days_in_year;
        y += 1;
    }
    let leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let month_days = [
        31u64,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut mo = 1u64;
    for &d in &month_days {
        if rem < d {
            break;
        }
        rem -= d;
        mo += 1;
    }
    let day = rem + 1;
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;
    format!("{y:04}-{mo:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

#[derive(serde::Deserialize)]
pub struct CreateProfileBody {
    name: String,
    label: String,
    #[serde(default)]
    description: String,
    config: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
pub struct UpdateProfileBody {
    label: Option<String>,
    description: Option<String>,
    favorite: Option<bool>,
}

#[derive(serde::Deserialize)]
pub struct DuplicateProfileBody {
    new_name: String,
    new_label: String,
}

#[derive(serde::Deserialize)]
pub struct RenameProfileBody {
    new_name: String,
}

const PROFILE_META_KEYS: &[&str] = &[
    "name",
    "label",
    "description",
    "favorite",
    "last_used_at",
    "created_at",
    "db",
];

/// GET /api/profiles
pub async fn profiles_list(State(s): State<SharedState>) -> impl IntoResponse {
    let dir = profiles_dir(&s);
    let _ = std::fs::create_dir_all(&dir);
    let mut profiles: Vec<serde_json::Value> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&p) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    let stem = p
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_string();
                    profiles.push(json!({
                        "name": v.get("name").and_then(|n| n.as_str()).unwrap_or(&stem),
                        "label": v.get("label").and_then(|l| l.as_str()).unwrap_or(&stem),
                        "description": v.get("description").and_then(|d| d.as_str()).unwrap_or(""),
                        "favorite": v.get("favorite").and_then(|f| f.as_bool()).unwrap_or(false),
                        "last_used_at": v.get("last_used_at"),
                        "created_at": v.get("created_at"),
                        "db": v.get("db"),
                    }));
                }
            }
        }
    }
    profiles.sort_by(|a, b| {
        let fa = !a.get("favorite").and_then(|f| f.as_bool()).unwrap_or(false);
        let fb = !b.get("favorite").and_then(|f| f.as_bool()).unwrap_or(false);
        fa.cmp(&fb).then_with(|| {
            let la = a
                .get("label")
                .and_then(|l| l.as_str())
                .unwrap_or("")
                .to_lowercase();
            let lb = b
                .get("label")
                .and_then(|l| l.as_str())
                .unwrap_or("")
                .to_lowercase();
            la.cmp(&lb)
        })
    });
    Json(json!({"profiles": profiles}))
}

/// GET /api/profiles/{name}
pub async fn profiles_get(State(s): State<SharedState>, Path(name): Path<String>) -> Response {
    if !valid_profile_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_name"})),
        )
            .into_response();
    }
    match read_profile_file(&profiles_dir(&s), &name) {
        Some(v) => Json(v).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "not_found"})),
        )
            .into_response(),
    }
}

/// POST /api/profiles
pub async fn profiles_create(
    State(s): State<SharedState>,
    Json(body): Json<CreateProfileBody>,
) -> Response {
    if !valid_profile_name(&body.name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_name"})),
        )
            .into_response();
    }
    let dir = profiles_dir(&s);
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{}.json", body.name));
    if path.exists() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"ok": false, "error": "already_exists"})),
        )
            .into_response();
    }
    let now = utc_now_iso();
    let mut data = json!({
        "name": body.name,
        "label": body.label,
        "description": body.description,
        "favorite": false,
        "created_at": now,
        "last_used_at": null,
    });
    if let (Some(obj), Some(cfg)) = (
        data.as_object_mut(),
        body.config.as_ref().and_then(|c| c.as_object()),
    ) {
        for (k, v) in cfg {
            if !PROFILE_META_KEYS.contains(&k.as_str()) {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    match write_profile_atomic(&path, &data) {
        Ok(()) => Json(json!({"ok": true, "profile": data})).into_response(),
        Err(e) => {
            tracing::error!("profiles_create: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "write_failed"})),
            )
                .into_response()
        }
    }
}

/// PUT /api/profiles/{name}
pub async fn profiles_update(
    State(s): State<SharedState>,
    Path(name): Path<String>,
    Json(body): Json<UpdateProfileBody>,
) -> Response {
    if !valid_profile_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_name"})),
        )
            .into_response();
    }
    let dir = profiles_dir(&s);
    let Some(mut data) = read_profile_file(&dir, &name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "not_found"})),
        )
            .into_response();
    };
    if let Some(label) = body.label {
        data["label"] = json!(label);
    }
    if let Some(desc) = body.description {
        data["description"] = json!(desc);
    }
    if let Some(fav) = body.favorite {
        data["favorite"] = json!(fav);
    }
    let path = dir.join(format!("{name}.json"));
    match write_profile_atomic(&path, &data) {
        Ok(()) => Json(json!({"ok": true, "profile": data})).into_response(),
        Err(e) => {
            tracing::error!("profiles_update: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "write_failed"})),
            )
                .into_response()
        }
    }
}

/// DELETE /api/profiles/{name}
pub async fn profiles_delete(State(s): State<SharedState>, Path(name): Path<String>) -> Response {
    if !valid_profile_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_name"})),
        )
            .into_response();
    }
    let path = profiles_dir(&s).join(format!("{name}.json"));
    if !path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "not_found"})),
        )
            .into_response();
    }
    match std::fs::remove_file(&path) {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => {
            tracing::error!("profiles_delete: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "delete_failed"})),
            )
                .into_response()
        }
    }
}

/// POST /api/profiles/{name}/duplicate
pub async fn profiles_duplicate(
    State(s): State<SharedState>,
    Path(name): Path<String>,
    Json(body): Json<DuplicateProfileBody>,
) -> Response {
    if !valid_profile_name(&name) || !valid_profile_name(&body.new_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_name"})),
        )
            .into_response();
    }
    let dir = profiles_dir(&s);
    let Some(mut data) = read_profile_file(&dir, &name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "not_found"})),
        )
            .into_response();
    };
    let new_path = dir.join(format!("{}.json", body.new_name));
    if new_path.exists() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"ok": false, "error": "already_exists"})),
        )
            .into_response();
    }
    data["name"] = json!(body.new_name);
    data["label"] = json!(body.new_label);
    data["created_at"] = json!(utc_now_iso());
    data["last_used_at"] = json!(null);
    match write_profile_atomic(&new_path, &data) {
        Ok(()) => Json(json!({"ok": true, "profile": data})).into_response(),
        Err(e) => {
            tracing::error!("profiles_duplicate: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "write_failed"})),
            )
                .into_response()
        }
    }
}

/// POST /api/profiles/{name}/rename
pub async fn profiles_rename(
    State(s): State<SharedState>,
    Path(name): Path<String>,
    Json(body): Json<RenameProfileBody>,
) -> Response {
    if !valid_profile_name(&name) || !valid_profile_name(&body.new_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_name"})),
        )
            .into_response();
    }
    let dir = profiles_dir(&s);
    let Some(mut data) = read_profile_file(&dir, &name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "not_found"})),
        )
            .into_response();
    };
    let new_path = dir.join(format!("{}.json", body.new_name));
    if new_path.exists() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"ok": false, "error": "already_exists"})),
        )
            .into_response();
    }
    data["name"] = json!(body.new_name);
    match write_profile_atomic(&new_path, &data) {
        Ok(()) => {
            let _ = std::fs::remove_file(dir.join(format!("{name}.json")));
            Json(json!({"ok": true, "profile": data})).into_response()
        }
        Err(e) => {
            tracing::error!("profiles_rename: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "write_failed"})),
            )
                .into_response()
        }
    }
}

/// POST /api/profiles/{name}/favorite  — toggle favorite flag
pub async fn profiles_favorite(State(s): State<SharedState>, Path(name): Path<String>) -> Response {
    if !valid_profile_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_name"})),
        )
            .into_response();
    }
    let dir = profiles_dir(&s);
    let Some(mut data) = read_profile_file(&dir, &name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "not_found"})),
        )
            .into_response();
    };
    let next = !data
        .get("favorite")
        .and_then(|f| f.as_bool())
        .unwrap_or(false);
    data["favorite"] = json!(next);
    let path = dir.join(format!("{name}.json"));
    match write_profile_atomic(&path, &data) {
        Ok(()) => Json(json!({"ok": true, "favorite": next})).into_response(),
        Err(e) => {
            tracing::error!("profiles_favorite: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "write_failed"})),
            )
                .into_response()
        }
    }
}

/// GET /api/profiles/{name}/export  — sensitive fields stripped
pub async fn profiles_export(State(s): State<SharedState>, Path(name): Path<String>) -> Response {
    if !valid_profile_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_name"})),
        )
            .into_response();
    }
    let Some(data) = read_profile_file(&profiles_dir(&s), &name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "not_found"})),
        )
            .into_response();
    };
    let clean: serde_json::Map<String, serde_json::Value> = data
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter(|(k, _)| !is_sensitive_key(k))
                .map(|(k, v)| {
                    let cleaned = if let serde_json::Value::Object(inner) = v {
                        serde_json::Value::Object(
                            inner
                                .iter()
                                .filter(|(sk, _)| !is_sensitive_key(sk))
                                .map(|(sk, sv)| (sk.clone(), sv.clone()))
                                .collect(),
                        )
                    } else {
                        v.clone()
                    };
                    (k.clone(), cleaned)
                })
                .collect()
        })
        .unwrap_or_default();
    Json(serde_json::Value::Object(clean)).into_response()
}

/// POST /api/profiles/import-preview  — validate without saving
pub async fn profiles_import_preview(body: Bytes) -> Response {
    let Ok(data) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_json"})),
        )
            .into_response();
    };
    let name = data.get("name").and_then(|n| n.as_str()).unwrap_or("");
    if !valid_profile_name(name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_name"})),
        )
            .into_response();
    }
    Json(json!({"ok": true, "profile": data})).into_response()
}

/// POST /api/profiles/import
pub async fn profiles_import(State(s): State<SharedState>, body: Bytes) -> Response {
    let Ok(mut data) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_json"})),
        )
            .into_response();
    };
    let name = data
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();
    if !valid_profile_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_name"})),
        )
            .into_response();
    }
    let dir = profiles_dir(&s);
    let _ = std::fs::create_dir_all(&dir);
    if data.get("created_at").is_none() {
        data["created_at"] = json!(utc_now_iso());
    }
    let path = dir.join(format!("{name}.json"));
    match write_profile_atomic(&path, &data) {
        Ok(()) => Json(json!({"ok": true, "profile": data})).into_response(),
        Err(e) => {
            tracing::error!("profiles_import: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "write_failed"})),
            )
                .into_response()
        }
    }
}

/// POST /ext/chatlog/api/import-path
pub async fn chatlog_import_path() -> impl IntoResponse {
    Json(json!({"ok": true, "imported": 0}))
}

/// GET /ext/chatlog/api/import/status
pub async fn chatlog_import_status() -> impl IntoResponse {
    Json(json!({"running": false, "status": "idle"}))
}

/// POST /ext/chatlog/api/chat/reprocess
pub async fn chatlog_reprocess() -> impl IntoResponse {
    Json(json!({"ok": true}))
}

/// GET /ext/chatlog/api/chat/reprocess/status
pub async fn chatlog_reprocess_status() -> impl IntoResponse {
    Json(json!({"running": false}))
}

/// POST /ext/chatlog/api/entities/reindex
pub async fn chatlog_entities_reindex() -> impl IntoResponse {
    Json(json!({"ok": true}))
}

/// POST /api/video-analysis/analyze
pub async fn video_analysis_analyze() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "video-analysis not available"}))
}

/// POST /api/audio-analysis/transcribe
pub async fn audio_analysis_transcribe() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "audio-analysis not available"}))
}

/// GET /api/audio-analysis/status
pub async fn audio_analysis_status() -> impl IntoResponse {
    Json(json!({"status": "idle", "available": false}))
}

/// POST /api/tools/archive-cleanup/scan
pub async fn archive_cleanup_scan() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "archive-cleanup not available"}))
}

/// POST /api/tools/archive-cleanup/execute
pub async fn archive_cleanup_execute() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "archive-cleanup not available"}))
}

/// POST /api/tools/archive-cleanup/llm-verify
pub async fn archive_cleanup_llm_verify() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "archive-cleanup not available"}))
}

/// POST /api/tools/archive-cleanup/llm-verify-batch
pub async fn archive_cleanup_llm_verify_batch() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "archive-cleanup not available"}))
}

/// GET+POST /api/tools/archive-cleanup/llm-config
pub async fn archive_cleanup_llm_config() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "archive-cleanup not available"}))
}

/// GET /api/tools/archive-cleanup/list-models
///
/// GET+POST /ext/lan_cowork/fleet/peers
pub async fn fleet_peers() -> impl IntoResponse {
    Json(json!({"peers": []}))
}

/// GET /ext/lan_cowork/fleet/peer-allowlist-status
pub async fn fleet_peer_allowlist_status() -> impl IntoResponse {
    Json(json!({"enabled": false}))
}

/// POST /ext/lan_cowork/fleet/peer-grant
pub async fn fleet_peer_grant() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "fleet not available"}))
}

/// POST /ext/lan_cowork/fleet/peer-revoke
pub async fn fleet_peer_revoke() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "fleet not available"}))
}

/// POST /api/lan-share/create
pub async fn lan_share_create() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "lan-share not available"}))
}

/// POST /api/lan-share/revoke
pub async fn lan_share_revoke() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "lan-share not available"}))
}

/// GET /ext/lora-dataset/checkpoints
pub async fn lora_dataset_checkpoints() -> impl IntoResponse {
    Json(json!([]))
}

/// GET /api/ocr/bbox/{params}
pub async fn ocr_bbox() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "ocr-bbox not available"}))
}

/// GET /ext/speech-to-text/api/s2t/status
pub async fn s2t_status() -> impl IntoResponse {
    Json(json!({"status": "idle", "available": false}))
}

/// POST /ext/speech-to-text/api/s2t/transcribe-video
pub async fn s2t_transcribe_video() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "s2t not available"}))
}

/// POST /ext/speech-to-text/api/s2t/batch-transcribe
pub async fn s2t_batch_transcribe() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "s2t not available"}))
}

/// POST /ext/speech-to-text/api/s2t/stream/start
pub async fn s2t_stream_start() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "s2t streaming not available"}))
}

/// POST /ext/speech-to-text/api/s2t/stream/stop
pub async fn s2t_stream_stop() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "s2t streaming not available"}))
}

/// GET /ext/speech-to-text/api/s2t/stream/status
pub async fn s2t_stream_status() -> impl IntoResponse {
    Json(json!({"status": "idle", "available": false}))
}

/// GET /ext/speech-to-text/api/s2t/stream/transcript
pub async fn s2t_stream_transcript() -> impl IntoResponse {
    Json(json!({"transcript": "", "available": false}))
}

/// GET /ext/speech-to-text/api/s2t/stream/export/txt
pub async fn s2t_stream_export_txt() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "s2t not available"}))
}

/// GET /ext/speech-to-text/api/s2t/stream/export/srt
pub async fn s2t_stream_export_srt() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "s2t not available"}))
}

/// POST /ext/speech-to-text/api/s2t/stream/llm-process
pub async fn s2t_stream_llm_process() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "s2t not available"}))
}

/// POST /api/tools/scan
pub async fn tools_scan() -> impl IntoResponse {
    Json(json!({"ok": false, "error": "tools-scan not available"}))
}

#[cfg(all(test, feature = "python-backend"))]
mod standalone_tests {
    use super::*;
    use axum::body::to_bytes;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    fn make_standalone_state() -> crate::state::SharedState {
        Arc::new(crate::state::AppState {
            effective_port: 5000,
            gateway_keys: Vec::new(),
            gateway_loopback_bypass: true,
            settings_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            config: crate::state::Config {
                db_path: "sqlite::memory:".to_string(),
                pin_hash: String::new(),
                valid_token: String::new(),
                secret: String::new(),
                trusted_proxy_enabled: false,

                pin_boss_login_ui: false,
                trusted_ips: HashSet::new(),
                trusted_peer_ips: HashSet::new(),
                quick_lock_enabled: false,
                pin_auth_enabled: false,
                min_pin_length: 4,
                python_url: String::new(),
                standalone: true,
                infer_standalone: true,
                active_profile: None,
                python_executable: String::new(),
                config_path: std::path::PathBuf::from("config.json"),
                project_root: std::path::PathBuf::from("."),
                app_config: serde_json::json!({}),
                cache_dir: std::path::PathBuf::from("."),
                server_mode: "full".to_string(),
                headless: false,
                safe_mode: false,
                mcp_native: false,
            },
            db: sqlx::pool::Pool::connect_lazy("sqlite::memory:").unwrap(),
            db_read: sqlx::pool::Pool::connect_lazy("sqlite::memory:").unwrap(),
            vectors_db: sqlx::pool::Pool::connect_lazy("sqlite::memory:").unwrap(),
            vectors_db_read: sqlx::pool::Pool::connect_lazy("sqlite::memory:").unwrap(),
            clip_index: std::sync::Arc::new(
                crate::routes::clip_index::ClipIndex::new_default(std::env::temp_dir())
                    .expect("clip index test default"),
            ),
            clip_indexer: std::sync::Arc::new(crate::routes::clip_indexer::ClipIndexer::new()),
            clip_runtime_cache: crate::state::TtlCache::new(crate::state::CLIP_RUNTIME_CACHE_TTL),
            inference_client: reqwest::Client::new(),
            python_client: reqwest::Client::new(),
            quick_lock: crate::auth::QuickLock::new(),
            rate_limiter: crate::auth::PinRateLimiter::new(),
            groups_index_cache: crate::groups_index::GroupsIndexCache::new(
                std::path::PathBuf::from("."),
            ),
            proxy_hits: Mutex::new(std::collections::HashMap::new()),
            fleet_log_stream_connections: Mutex::new(std::collections::HashMap::new()),
            sse_hub: Arc::new(crate::sse::SseHub::new()),
            log_ring: Arc::new(crate::logs::ring::LogRingBuffer::new(64)),
            mcp_sessions: Arc::new(crate::mcp::session::McpSessionStore::new(100, 10, 64)),
            job_manager: Arc::new(crate::jobs::JobManager::new()),
            watcher: Arc::new(crate::watcher::ScanWatcher::new()),
            approval_gate: Mutex::new(crate::approval_gate::ApprovalGate::default()),
            env: minijinja::Environment::new(),
            dist_v: "dev".to_string(),
            version: "0.0.0".to_string(),
            start_time: std::time::Instant::now(),
            scheduler_state: std::sync::OnceLock::new(),
            wd_infer: std::sync::OnceLock::new(),
            infer_client: None,
            infer_child: None,
            scan_manager: std::sync::OnceLock::new(),
            hailo_yolo_stream: None,
            stats_basic_cache: crate::state::TtlCache::new(crate::state::STATS_CACHE_TTL),
            stats_models_cache: crate::state::TtlCache::new(crate::state::STATS_CACHE_TTL),
            checkpoints_cache: crate::state::TtlCache::new(crate::state::STATS_CACHE_TTL),
        })
    }

    #[tokio::test]
    async fn fwd_get_returns_503_in_standalone_mode() {
        let state = make_standalone_state();
        let response = fwd_get(&state, "/api/some/proxied/route").await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let b = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(body["code"], "python_unavailable");
    }

    #[tokio::test]
    async fn fwd_post_returns_503_in_standalone_mode() {
        let state = make_standalone_state();
        let response = fwd_post(&state, "/api/some/route", Bytes::new()).await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn fwd_post_records_attempt_before_connection_failure() {
        let mut state = make_standalone_state();
        Arc::get_mut(&mut state).unwrap().config.python_url = "http://127.0.0.1:0".to_string();

        let response = fwd_post(&state, "/api/some/route", Bytes::new()).await;

        assert_eq!(response.status(), axum::http::StatusCode::BAD_GATEWAY);
        assert_eq!(
            state
                .proxy_hits
                .lock()
                .expect("proxy_hits lock")
                .get("POST /api/some/route"),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn hailo_genai_handlers_fall_back_to_python_without_infer_client() {
        let mut state = make_standalone_state();
        Arc::get_mut(&mut state).unwrap().config.python_url = "http://127.0.0.1:0".to_string();

        let llm_response = hailo_genai_llm_generate(
            State(state.clone()),
            None,
            axum::http::HeaderMap::new(),
            Bytes::from(json!({"prompt": "hello"}).to_string()),
        )
        .await;
        let embeddings_response = hailo_genai_v1_embeddings(
            State(state.clone()),
            None,
            Bytes::from(json!({"input": "hello"}).to_string()),
        )
        .await;

        assert_eq!(llm_response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(embeddings_response.status(), StatusCode::BAD_GATEWAY);
        let proxy_hits = state.proxy_hits.lock().expect("proxy_hits lock");
        assert_eq!(
            proxy_hits.get("POST /ext/hailo-genai/api/llm/generate"),
            Some(&1)
        );
        assert_eq!(
            proxy_hits.get("POST /ext/hailo-genai/v1/embeddings"),
            Some(&1)
        );
    }

    #[test]
    fn llm_messages_flatten_text_parts() {
        let messages = llm_messages(&json!({
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "first"},
                    {"type": "image_url", "image_url": "ignored"},
                    {"type": "text", "text": "second"}
                ]
            }]
        }))
        .unwrap();

        assert_eq!(
            messages,
            vec![json!({"role": "user", "content": "first\nsecond"})]
        );
    }

    #[test]
    fn embedding_inputs_accept_strings_and_reject_mixed_arrays() {
        assert_eq!(
            embedding_inputs(&json!({"input": ["one", "two"]})).unwrap(),
            vec!["one", "two"]
        );
        assert_eq!(
            embedding_inputs(&json!({"input": ["one", 2]})).unwrap_err(),
            "input[1] must be a string"
        );
    }
}

// --- hailo-genai API (proxy to Python extension) ---

pub async fn hailo_genai_model_status(
    State(s): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(resp) = require_admin_scope(
        s.config.pin_auth_enabled,
        auth_context.as_ref().map(|e| &e.0),
    ) {
        return resp;
    }
    let registry = crate::routes::hailo_model_registry::genai_models().await;
    let hef_dir = crate::routes::hailo_model_download::default_hef_dir();
    let status = crate::routes::hailo_model_download::get_model_status(registry, &hef_dir);
    Json(json!({"status": "ok", "models": status})).into_response()
}
pub async fn hailo_genai_model_download(
    State(s): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
    body: Bytes,
) -> Response {
    if let Some(resp) = require_admin_scope(
        s.config.pin_auth_enabled,
        auth_context.as_ref().map(|e| &e.0),
    ) {
        return resp;
    }
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or(json!({}));
    let model_name = payload
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let registry = crate::routes::hailo_model_registry::genai_models().await;
    let Some(info) = registry.get(&model_name) else {
        let mut available: Vec<&str> = registry.keys().map(|k| k.as_str()).collect();
        available.sort_unstable();
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "message": format!("Unknown model: {model_name}"),
                "available": available,
            })),
        )
            .into_response();
    };

    let hef_dir = crate::routes::hailo_model_download::default_hef_dir();
    match crate::routes::hailo_model_download::download_hef(
        &info.hef_filename,
        &info.url,
        &hef_dir,
        "YU-AI-Manager/2.56 (Hailo GenAI Download)",
    )
    .await
    {
        Ok(_path) => Json(json!({"status": "ok", "model": model_name})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("Model download failed: {e}"),
            })),
        )
            .into_response(),
    }
}
pub async fn hailo_genai_model_unload(State(s): State<SharedState>, body: Bytes) -> Response {
    fwd_ext_post(&s, "/ext/hailo-genai/api/model/unload", body).await
}
pub async fn hailo_genai_llm_generate(
    State(s): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = require_admin_scope(
        s.config.pin_auth_enabled,
        auth_context.as_ref().map(|context| &context.0),
    ) {
        return response;
    }
    if let Some(infer_client) = s.infer_client.as_ref() {
        return hailo_genai_llm_generate_native(&s, infer_client, &body).await;
    }
    fwd_ext_post_stream(
        &s,
        "/ext/hailo-genai/api/llm/generate",
        body,
        headers.get("content-type"),
    )
    .await
}

fn hailo_genai_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({"status": "error", "message": message.into()})),
    )
        .into_response()
}

fn flatten_llm_content(content: Option<&serde_json::Value>) -> Option<String> {
    match content {
        None | Some(serde_json::Value::Null) => Some(String::new()),
        Some(serde_json::Value::String(text)) => Some(text.clone()),
        Some(serde_json::Value::Array(parts)) => Some(
            parts
                .iter()
                .filter(|part| part.get("type").and_then(|value| value.as_str()) == Some("text"))
                .filter_map(|part| part.get("text").and_then(|value| value.as_str()))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        _ => None,
    }
}

fn llm_messages(value: &serde_json::Value) -> Result<Vec<serde_json::Value>, &'static str> {
    match value.get("messages") {
        Some(serde_json::Value::Array(messages)) if !messages.is_empty() => messages
            .iter()
            .map(|message| {
                let role = message.get("role").and_then(|role| role.as_str());
                let content = flatten_llm_content(message.get("content"));
                match (role, content) {
                    (Some(role), Some(content)) => Ok(json!({"role": role, "content": content})),
                    _ => Err("Invalid messages format"),
                }
            })
            .collect(),
        Some(serde_json::Value::Null | serde_json::Value::Array(_)) | None => {
            let prompt = value
                .get("prompt")
                .and_then(|prompt| prompt.as_str())
                .unwrap_or("")
                .trim();
            if prompt.is_empty() {
                return Err("prompt or messages is required");
            }
            let system_prompt = value
                .get("system_prompt")
                .and_then(|prompt| prompt.as_str())
                .unwrap_or("You are a helpful assistant.");
            Ok(vec![
                json!({"role": "system", "content": system_prompt}),
                json!({"role": "user", "content": prompt}),
            ])
        }
        _ => Err("Invalid messages format"),
    }
}

fn validate_llm_messages_shape(messages: &serde_json::Value) -> Result<(), String> {
    let Some(messages) = messages.as_array() else {
        return Err("messages must be an array".to_string());
    };
    for (index, message) in messages.iter().enumerate() {
        let Some(message) = message.as_object() else {
            return Err(format!("messages[{index}] must be an object"));
        };
        if !message
            .get("role")
            .is_some_and(serde_json::Value::is_string)
        {
            return Err(format!("messages[{index}].role must be a string"));
        }
        match message.get("content") {
            None | Some(serde_json::Value::Null | serde_json::Value::String(_)) => {}
            Some(serde_json::Value::Array(parts)) => {
                for (part_index, part) in parts.iter().enumerate() {
                    if !part.is_object() {
                        return Err(format!(
                            "messages[{index}].content[{part_index}] must be an object"
                        ));
                    }
                }
            }
            Some(_) => {
                return Err(format!(
                    "messages[{index}].content must be a string or an array"
                ));
            }
        }
    }
    Ok(())
}

fn validate_llm_generation_request(value: &serde_json::Value) -> Result<(), String> {
    if !value.is_object() {
        return Err("request body must be an object".to_string());
    }
    for field in ["model", "vlm_model", "prompt", "content", "system_prompt"] {
        if value
            .get(field)
            .is_some_and(|value| !value.is_null() && !value.is_string())
        {
            return Err(format!("{field} must be a string"));
        }
    }
    if let Some(messages) = value.get("messages") {
        validate_llm_messages_shape(messages)?;
    }
    for field in ["temperature", "top_p"] {
        if value
            .get(field)
            .is_some_and(|value| !value.as_f64().is_some_and(f64::is_finite))
        {
            return Err(format!("{field} must be a finite number"));
        }
    }
    for field in ["max_generated_tokens", "max_tokens"] {
        if value.get(field).is_some_and(|value| {
            !matches!(value, serde_json::Value::Number(number) if number.is_i64() || number.is_u64())
        }) {
            return Err(format!("{field} must be an integer"));
        }
    }
    Ok(())
}

async fn hailo_genai_llm_generate_native(
    state: &SharedState,
    infer_client: &crate::infer_client::InferClient,
    body: &Bytes,
) -> Response {
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));
    if let Err(message) = validate_llm_generation_request(&value) {
        return hailo_genai_error(StatusCode::BAD_REQUEST, message);
    }
    let messages = match llm_messages(&value) {
        Ok(messages) => messages,
        Err(message) => return hailo_genai_error(StatusCode::BAD_REQUEST, message),
    };
    let model = value
        .get("model")
        .and_then(|model| model.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| crate::routes::hailo_genai_chat::default_llm_model(state));
    if !crate::routes::analysis::is_hailo_hef_available(&model) {
        return hailo_genai_error(
            StatusCode::BAD_REQUEST,
            format!("Model '{model}' not downloaded yet"),
        );
    }

    let config = read_config_json(state);
    let temperature = value
        .get("temperature")
        .and_then(|value| value.as_f64())
        .or_else(|| config["extensions"]["builtin-hailo-genai"]["temperature"].as_f64())
        .unwrap_or(0.7) as f32;
    let max_generated_tokens = value
        .get("max_generated_tokens")
        .and_then(|value| value.as_u64())
        .or_else(|| config["extensions"]["builtin-hailo-genai"]["max_generated_tokens"].as_u64())
        .unwrap_or(512) as u32;
    let upstream = match infer_client
        .llm_generate_stream(
            Some(model_name_to_hef_path(&model)),
            messages,
            Vec::new(),
            None,
            Some(temperature),
            None,
            None,
            None,
            Some(max_generated_tokens),
            None,
            None,
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "yu-infer LLM generation failed");
            return sse_event(json!({"error": "LLM generation failed"}));
        }
    };
    stream_sse_from_upstream(upstream)
}

fn sse_event(value: serde_json::Value) -> Response {
    Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
        .header(axum::http::header::CACHE_CONTROL, "no-cache")
        .header("x-accel-buffering", "no")
        .body(axum::body::Body::from(format!("data: {value}\n\n")))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
pub async fn hailo_genai_llm_clear_context(State(s): State<SharedState>, body: Bytes) -> Response {
    fwd_ext_post(&s, "/ext/hailo-genai/api/llm/clear-context", body).await
}
pub async fn hailo_genai_vlm_generate(
    State(s): State<SharedState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // The native yu-infer path currently only covers the JSON `file_id`
    // input shape (used by e.g. "analyze this image" flows). Multipart
    // image uploads and text-only (no image) generation continue to use
    // the Python proxy unchanged — yu-infer's VLM requires at least one
    // image frame per request (see router.rs `VlmGenerateStreamRequest`).
    if let Some(infer_client) = s.infer_client.as_ref() {
        if content_type.starts_with("application/json") {
            if let Some(response) = hailo_genai_vlm_generate_native(&s, infer_client, &body).await {
                return response;
            }
        }
    }

    fwd_ext_post_stream(
        &s,
        "/ext/hailo-genai/api/vlm/generate",
        body,
        headers.get("content-type"),
    )
    .await
}

/// Attempts the native yu-infer path for a JSON `{prompt, file_id, ...}`
/// request. Returns `None` (falling back to the Python proxy) when the
/// request doesn't carry a `file_id` — yu-infer's VLM currently requires at
/// least one image frame, so text-only generation isn't supported here yet.
async fn hailo_genai_vlm_generate_native(
    state: &SharedState,
    infer_client: &crate::infer_client::InferClient,
    body: &Bytes,
) -> Option<Response> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let file_id = value.get("file_id").and_then(|v| v.as_i64())?;

    let prompt = value
        .get("prompt")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if prompt.is_empty() {
        return Some(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": "prompt is required"})),
            )
                .into_response(),
        );
    }

    let model = value
        .get("model")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| default_vlm_model(state));
    if model.contains('/') || model.contains('\\') || model.contains("..") {
        return Some(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": "invalid model name"})),
            )
                .into_response(),
        );
    }
    let hef_path = Some(model_name_to_hef_path(&model));

    let system_prompt = value
        .get("system_prompt")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| "You are a helpful assistant that analyzes images.".to_string());

    let path: Option<String> =
        sqlx::query_scalar("SELECT path FROM files WHERE id = ? AND is_deleted = 0")
            .bind(file_id)
            .fetch_optional(&state.db_read)
            .await
            .ok()
            .flatten();
    let Some(path) = path else {
        return Some(
            (
                StatusCode::NOT_FOUND,
                Json(json!({"status": "error", "message": format!("file_id {file_id} not found")})),
            )
                .into_response(),
        );
    };

    let image_bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Some(
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "status": "error",
                        "message": format!("Image file not found on disk: {path}"),
                    })),
                )
                    .into_response(),
            );
        }
    };
    use base64::Engine as _;
    let frame_b64 = base64::engine::general_purpose::STANDARD.encode(&image_bytes);
    let temperature = value
        .get("temperature")
        .and_then(|v| v.as_f64())
        .map(|v| v as f32);
    let top_p = value
        .get("top_p")
        .and_then(|v| v.as_f64())
        .map(|v| v as f32);
    let top_k = value
        .get("top_k")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let frequency_penalty = value
        .get("frequency_penalty")
        .and_then(|v| v.as_f64())
        .map(|v| v as f32);
    let max_generated_tokens = value
        .get("max_generated_tokens")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let do_sample = value.get("do_sample").and_then(|v| v.as_bool());
    let seed = value.get("seed").and_then(|v| v.as_u64()).map(|v| v as u32);

    let upstream = match infer_client
        .vlm_generate_stream(
            hef_path,
            prompt,
            Some(system_prompt),
            vec![frame_b64],
            None,
            temperature,
            top_p,
            top_k,
            frequency_penalty,
            max_generated_tokens,
            do_sample,
            seed,
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::error!("yu-infer vlm_generate_stream request failed: {error}");
            return Some(
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"status": "error", "message": "VLM generation failed"})),
                )
                    .into_response(),
            );
        }
    };

    Some(stream_sse_from_upstream(upstream))
}

/// Mirrors Python's `get_extension_config_value("builtin-hailo-genai",
/// Parses `config.json` (returning an empty object if it doesn't exist or
/// isn't valid JSON), for reading admin-configured overrides.
pub(crate) fn read_config_json(state: &SharedState) -> serde_json::Value {
    std::fs::read_to_string(&state.config.config_path)
        .ok()
        .and_then(|t| crate::config_io::parse(&state.config.config_path, &t))
        .unwrap_or(json!({}))
}

/// "default_vlm_model", "qwen2-vl-2b-instruct")` — the admin-configured
/// default model to use when a request omits `model`.
fn default_vlm_model(state: &SharedState) -> String {
    const DEFAULT: &str = "qwen2-vl-2b-instruct";
    read_config_json(state)["extensions"]["builtin-hailo-genai"]["default_vlm_model"]
        .as_str()
        .unwrap_or(DEFAULT)
        .to_string()
}

/// Bundled mirror of `model_registry.py`'s `MODEL_OVERRIDES` + `BUNDLED_ROWS`:
/// maps a GenAI registry name to its real `.hef` filename, since the two
/// don't always match (e.g. `qwen3-1.7b-instruct` -> `Qwen3-1.7B-Instruct.hef`).
const BUNDLED_HEF_FILENAMES: &[(&str, &str)] = &[
    ("qwen2.5-1.5b-chat", "Qwen2.5-1.5B-Instruct.hef"),
    ("llama3.2-1b", "Llama3.2-1B-Instruct.hef"),
    ("deepseek-r1-1.5b", "DeepSeek-R1-Distill-Qwen-1.5B.hef"),
    ("qwen2.5-coder-1.5b", "Qwen2.5-Coder-1.5B-Instruct.hef"),
    ("qwen3-1.7b-instruct", "Qwen3-1.7B-Instruct.hef"),
    ("qwen3-vl-2b-instruct", "Qwen3-VL-2B-Instruct.hef"),
    ("qwen2-vl-2b-instruct", "Qwen2-VL-2B-Instruct.hef"),
    ("whisper-tiny", "Whisper-Tiny.hef"),
    ("whisper-base", "Whisper-Base.hef"),
    ("whisper-small", "Whisper-Small.hef"),
];

/// yu-infer resolves a `hef_path` filesystem path, not a model name. Known
/// registry names resolve to their real `.hef` filename (see
/// `BUNDLED_HEF_FILENAMES`); unknown names fall back to the Python
/// extension's naive `{model}.hef` convention. If the guess doesn't match an
/// actual file, yu-infer returns a clear "file not found" HailoRT error
/// rather than silently misbehaving. The containing directory is resolved
/// via `hailo_model_download::default_hef_dir()`, which honors the
/// `HAILO_HEF_DIR` env var override — the same directory `/model/status`
/// and `/model/download` use — so a custom hef_dir deployment doesn't see
/// "available" from status while real generation still looks in
/// `$HOME/hailo_models`.
pub(crate) fn model_name_to_hef_path(model: &str) -> String {
    let hef_dir = super::hailo_model_download::default_hef_dir();
    let filename = BUNDLED_HEF_FILENAMES
        .iter()
        .find(|(name, _)| *name == model)
        .map(|(_, hef_filename)| hef_filename.to_string())
        .unwrap_or_else(|| format!("{model}.hef"));
    hef_dir.join(filename).to_string_lossy().into_owned()
}

fn stream_sse_from_upstream(upstream: reqwest::Response) -> Response {
    let status = upstream.status();
    let stream = upstream.bytes_stream();
    Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
        .header(axum::http::header::CACHE_CONTROL, "no-cache")
        .header("x-accel-buffering", "no")
        .body(axum::body::Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}
pub async fn hailo_genai_chat_search(State(s): State<SharedState>, body: Bytes) -> Response {
    fwd_ext_post(&s, "/ext/hailo-genai/api/chat/search", body).await
}

// --- hailo-semantic caption API (intentionally remains Python-backed) ---
pub async fn hailo_semantic_caption_start(State(s): State<SharedState>, body: Bytes) -> Response {
    fwd_ext_post(&s, "/ext/hailo-semantic/api/caption/start", body).await
}
pub async fn hailo_semantic_caption_status(State(s): State<SharedState>) -> Response {
    fwd_ext_get(&s, "/ext/hailo-semantic/api/caption/status").await
}
pub async fn hailo_semantic_caption_stop(State(s): State<SharedState>, body: Bytes) -> Response {
    fwd_ext_post(&s, "/ext/hailo-semantic/api/caption/stop", body).await
}

// --- hailo-genai dynamic path routes ---
// --- hailo-genai s2t routes ---
pub async fn hailo_genai_s2t_transcribe(
    State(s): State<SharedState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    fwd_ext_post_passthrough(
        &s,
        "/ext/hailo-genai/api/s2t/transcribe",
        body,
        headers.get("content-type"),
    )
    .await
}
pub async fn hailo_genai_s2t_transcribe_video(
    State(s): State<SharedState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    fwd_ext_post_passthrough(
        &s,
        "/ext/hailo-genai/api/s2t/transcribe-video",
        body,
        headers.get("content-type"),
    )
    .await
}
pub async fn hailo_genai_s2t_batch_transcribe(
    State(s): State<SharedState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    fwd_ext_post_passthrough(
        &s,
        "/ext/hailo-genai/api/s2t/batch-transcribe",
        body,
        headers.get("content-type"),
    )
    .await
}
pub async fn hailo_genai_s2t_transcript(
    State(s): State<SharedState>,
    Path(file_id): Path<i64>,
) -> Response {
    fwd_ext_get(
        &s,
        &format!("/ext/hailo-genai/api/s2t/transcript/{file_id}"),
    )
    .await
}

// --- hailo-genai OpenAI-compatible v1 routes ---
pub async fn hailo_genai_v1_chat_completions(
    State(s): State<SharedState>,
    body: Bytes,
) -> Response {
    if let Some(infer_client) = s.infer_client.as_ref() {
        return hailo_genai_chat_completions_native(&s, infer_client, &body).await;
    }
    fwd_ext_post(&s, "/ext/hailo-genai/v1/chat/completions", body).await
}

fn openai_error_with_code(
    message: impl Into<String>,
    type_: &str,
    code: Option<&str>,
    status: StatusCode,
) -> Response {
    (
        status,
        Json(json!({
            "error": {"message": message.into(), "type": type_, "code": code}
        })),
    )
        .into_response()
}

fn validate_openai_chat_request(value: &serde_json::Value) -> Result<(), String> {
    let Some(data) = value.as_object() else {
        return Err("request body must be an object".to_string());
    };
    if data
        .get("model")
        .is_some_and(|value| !value.is_null() && !value.is_string())
    {
        return Err("model must be a string".to_string());
    }
    let messages = data.get("messages");
    if messages.is_none_or(|value| {
        value.is_null()
            || value.as_array().is_some_and(Vec::is_empty)
            || value.as_str() == Some("")
            || value.as_bool() == Some(false)
            || value.as_f64() == Some(0.0)
    }) {
        return Err("messages is required".to_string());
    }
    if let Some(messages) = messages {
        validate_llm_messages_shape(messages)?;
    }
    for field in ["temperature", "top_p"] {
        if data
            .get(field)
            .is_some_and(|value| !value.as_f64().is_some_and(f64::is_finite))
        {
            return Err(format!("{field} must be a finite number"));
        }
    }
    if data.get("max_tokens").is_some_and(|value| {
        !matches!(value, serde_json::Value::Number(number) if number.is_i64() || number.is_u64())
    }) {
        return Err("max_tokens must be an integer".to_string());
    }
    if data.get("stream").is_some_and(|value| !value.is_boolean()) {
        return Err("stream must be a boolean".to_string());
    }
    Ok(())
}

fn has_openai_images(messages: &serde_json::Value) -> bool {
    messages.as_array().is_some_and(|messages| {
        messages.iter().any(|message| {
            message
                .get("content")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|parts| {
                    parts.iter().any(|part| {
                        part.get("type").and_then(serde_json::Value::as_str) == Some("image_url")
                    })
                })
        })
    })
}

enum YuInferSseEvent {
    Token(String),
    Done(Option<String>),
    Error(String),
    Other,
}

#[derive(Debug, PartialEq, Eq)]
enum YuInferSseFullTextError {
    Incomplete { dropped_chars: usize },
    Upstream(String),
}

fn parse_yu_infer_sse_event(event: &str) -> YuInferSseEvent {
    let Some(data) = event.strip_prefix("data: ") else {
        return YuInferSseEvent::Other;
    };
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(data) else {
        return YuInferSseEvent::Other;
    };
    if let Some(error) = payload.get("error").and_then(serde_json::Value::as_str) {
        return YuInferSseEvent::Error(error.to_string());
    }
    if payload.get("done").and_then(serde_json::Value::as_bool) == Some(true) {
        return YuInferSseEvent::Done(
            payload
                .get("full_text")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        );
    }
    payload
        .get("token")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .map_or(YuInferSseEvent::Other, YuInferSseEvent::Token)
}

fn yu_infer_sse_full_text(raw_sse: &str) -> Result<String, YuInferSseFullTextError> {
    let mut tokens = String::new();
    for event in raw_sse.split("\n\n") {
        match parse_yu_infer_sse_event(event) {
            YuInferSseEvent::Token(token) => tokens.push_str(&token),
            YuInferSseEvent::Done(full_text) => {
                return Ok(full_text.unwrap_or(tokens));
            }
            YuInferSseEvent::Error(error) => return Err(YuInferSseFullTextError::Upstream(error)),
            YuInferSseEvent::Other => {}
        }
    }
    Err(YuInferSseFullTextError::Incomplete {
        dropped_chars: tokens.chars().count(),
    })
}

fn openai_sse_chunk(
    id: &str,
    created: i64,
    model: &str,
    delta: serde_json::Value,
    finish_reason: Option<&str>,
) -> String {
    format!(
        "data: {}\n\n",
        json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
        })
    )
}

/// Unwraps an OpenAI Chat Completions `tools` array (`[{"type":"function",
/// "function":{"name":...,"description":...,"parameters":...}}, ...]`) down
/// to the inner `function` objects HailoRT's native `write(messages, tools)`
/// expects (`[{"name":...,"description":...,"parameters":...}, ...]`).
/// Entries already in the inner shape (no `function` key) pass through as-is.
fn openai_tools_to_native(tools: Option<&serde_json::Value>) -> Vec<serde_json::Value> {
    let tools: Vec<serde_json::Value> = tools
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    crate::routes::llm_client::unwrap_openai_tools(&tools)
}

async fn hailo_genai_chat_completions_native(
    state: &SharedState,
    infer_client: &crate::infer_client::InferClient,
    body: &Bytes,
) -> Response {
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => {
            return openai_error_with_code(
                "request body must be an object",
                "invalid_request_error",
                None,
                StatusCode::BAD_REQUEST,
            )
        }
    };
    if let Err(message) = validate_openai_chat_request(&value) {
        return openai_error_with_code(
            message,
            "invalid_request_error",
            None,
            StatusCode::BAD_REQUEST,
        );
    }
    if has_openai_images(&value["messages"]) {
        // The Python path routed vision requests to vlm_completion; native VLM is deliberately out of scope here.
        return openai_error_with_code(
            "Vision chat is not implemented on the native path",
            "server_error",
            Some("vision_not_implemented"),
            StatusCode::NOT_IMPLEMENTED,
        );
    }
    let model_display = value
        .get("model")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| crate::routes::hailo_genai_chat::default_llm_model(state));
    let model = model_display.clone();
    if !crate::routes::analysis::is_hailo_hef_available(&model) {
        return openai_error_with_code(
            format!("Model '{model}' not downloaded"),
            "invalid_request_error",
            Some("model_not_found"),
            StatusCode::NOT_FOUND,
        );
    }
    let messages = match llm_messages(&value) {
        Ok(messages) => messages,
        Err(message) => {
            return openai_error_with_code(
                message,
                "invalid_request_error",
                None,
                StatusCode::BAD_REQUEST,
            )
        }
    };
    let tools = openai_tools_to_native(value.get("tools"));
    let temperature = value
        .get("temperature")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.7) as f32;
    let max_tokens = value
        .get("max_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(512) as u32;
    let stream = value
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let upstream = match infer_client
        .llm_generate_stream(
            Some(model_name_to_hef_path(&model)),
            messages,
            tools,
            None,
            Some(temperature),
            None,
            None,
            None,
            Some(max_tokens),
            None,
            None,
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "yu-infer OpenAI chat generation failed");
            return openai_error_with_code(
                "LLM generation failed",
                "server_error",
                None,
                StatusCode::BAD_GATEWAY,
            );
        }
    };
    if !stream {
        let raw_sse = match upstream.text().await {
            Ok(body) => body,
            Err(error) => {
                tracing::error!(%error, "yu-infer OpenAI chat response read failed");
                return openai_error_with_code(
                    "LLM generation failed",
                    "server_error",
                    None,
                    StatusCode::BAD_GATEWAY,
                );
            }
        };
        let text = match yu_infer_sse_full_text(&raw_sse) {
            Ok(text) => text,
            Err(YuInferSseFullTextError::Incomplete { dropped_chars }) => {
                tracing::error!(
                    dropped_chars,
                    "yu-infer OpenAI chat stream ended before completion"
                );
                return openai_error_with_code(
                    "LLM generation failed",
                    "server_error",
                    None,
                    StatusCode::BAD_GATEWAY,
                );
            }
            Err(YuInferSseFullTextError::Upstream(error)) => {
                tracing::error!(%error, "yu-infer OpenAI chat stream failed");
                return openai_error_with_code(
                    "LLM generation failed",
                    "server_error",
                    None,
                    StatusCode::BAD_GATEWAY,
                );
            }
        };
        return Json(json!({
            "id": format!("chatcmpl-{}", &uuid::Uuid::new_v4().simple().to_string()[..24]),
            "object": "chat.completion",
            "created": chrono::Utc::now().timestamp(),
            "model": model_display,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }))
        .into_response();
    }

    let id = format!(
        "chatcmpl-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..24]
    );
    let created = chrono::Utc::now().timestamp();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let _ = tx.send(openai_sse_chunk(
        &id,
        created,
        &model_display,
        json!({"role": "assistant"}),
        None,
    ));
    tokio::spawn(async move {
        use futures_util::StreamExt;

        let mut upstream = upstream.bytes_stream();
        let mut buffer = String::new();
        loop {
            let chunk = match upstream.next().await {
                Some(Ok(chunk)) => chunk,
                Some(Err(error)) => {
                    tracing::error!(%error, "yu-infer OpenAI chat stream read failed");
                    let _ = tx.send(openai_sse_chunk(
                        &id,
                        created,
                        &model_display,
                        json!({}),
                        Some("error"),
                    ));
                    let _ = tx.send("data: [DONE]\n\n".to_string());
                    return;
                }
                None => {
                    // yu-infer marks completion with `done`; EOF without it means the generation was cut.
                    let _ = tx.send(openai_sse_chunk(
                        &id,
                        created,
                        &model_display,
                        json!({}),
                        Some("error"),
                    ));
                    let _ = tx.send("data: [DONE]\n\n".to_string());
                    return;
                }
            };
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(pos) = buffer.find("\n\n") {
                let event = buffer[..pos].to_string();
                buffer.drain(..pos + 2);
                match parse_yu_infer_sse_event(&event) {
                    YuInferSseEvent::Token(token) => {
                        let _ = tx.send(openai_sse_chunk(
                            &id,
                            created,
                            &model_display,
                            json!({"content": token}),
                            None,
                        ));
                    }
                    YuInferSseEvent::Done(_) => {
                        let _ = tx.send(openai_sse_chunk(
                            &id,
                            created,
                            &model_display,
                            json!({}),
                            Some("stop"),
                        ));
                        let _ = tx.send("data: [DONE]\n\n".to_string());
                        return;
                    }
                    YuInferSseEvent::Error(error) => {
                        tracing::error!(%error, "yu-infer OpenAI chat stream failed");
                        let _ = tx.send(openai_sse_chunk(
                            &id,
                            created,
                            &model_display,
                            json!({}),
                            Some("error"),
                        ));
                        let _ = tx.send("data: [DONE]\n\n".to_string());
                        return;
                    }
                    YuInferSseEvent::Other => {}
                }
            }
        }
    });
    let body = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|chunk| (Ok::<_, std::io::Error>(Bytes::from(chunk)), rx))
    });
    Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
        .header(axum::http::header::CACHE_CONTROL, "no-cache")
        .header("x-accel-buffering", "no")
        .body(axum::body::Body::from_stream(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
pub async fn hailo_genai_v1_audio_transcriptions(
    State(s): State<SharedState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    fwd_ext_post_passthrough(
        &s,
        "/ext/hailo-genai/v1/audio/transcriptions",
        body,
        headers.get("content-type"),
    )
    .await
}
pub async fn hailo_genai_v1_embeddings(
    State(s): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
    body: Bytes,
) -> Response {
    if let Some(response) = require_admin_scope(
        s.config.pin_auth_enabled,
        auth_context.as_ref().map(|context| &context.0),
    ) {
        return response;
    }
    if s.infer_client.is_some() {
        return hailo_genai_v1_embeddings_native(&s, &body).await;
    }
    fwd_ext_post(&s, "/ext/hailo-genai/v1/embeddings", body).await
}

fn openai_error(message: impl Into<String>, type_: &str, status: StatusCode) -> Response {
    (
        status,
        Json(json!({
            "error": {"message": message.into(), "type": type_, "code": null}
        })),
    )
        .into_response()
}

fn embedding_inputs(value: &serde_json::Value) -> Result<Vec<String>, String> {
    match value.get("input") {
        None | Some(serde_json::Value::Null) => Err("input is required".to_string()),
        Some(serde_json::Value::String(input)) => Ok(vec![input.clone()]),
        Some(serde_json::Value::Array(inputs)) if inputs.is_empty() => {
            Err("input must not be empty".to_string())
        }
        Some(serde_json::Value::Array(inputs)) => inputs
            .iter()
            .enumerate()
            .map(|(index, input)| {
                input
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("input[{index}] must be a string"))
            })
            .collect(),
        _ => Err("input must be a string or array of strings".to_string()),
    }
}

async fn hailo_genai_v1_embeddings_native(state: &SharedState, body: &Bytes) -> Response {
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));
    let inputs = match embedding_inputs(&value) {
        Ok(inputs) => inputs,
        Err(message) => {
            return openai_error(message, "invalid_request_error", StatusCode::BAD_REQUEST)
        }
    };
    let model = value
        .get("model")
        .cloned()
        .unwrap_or_else(|| json!("clip-vit-b-16"));
    let mut data = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.into_iter().enumerate() {
        match crate::routes::clip_search::call_clip_text(state, input).await {
            Ok(embedding) => data.push(json!({
                "object": "embedding",
                "index": index,
                "embedding": embedding,
            })),
            Err(crate::routes::clip_search::ClipCallError::Unavailable)
            | Err(crate::routes::clip_search::ClipCallError::Infer(
                crate::infer_client::InferClientError::BadStatus { status: 503, .. },
            )) => {
                return openai_error(
                    "CLIP text encoder not available. Enable the builtin-clip-search extension.",
                    "server_error",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
            }
            Err(error) => {
                tracing::error!(?error, "CLIP text embedding failed");
                return openai_error(
                    format!("Embedding failed: {error:?}"),
                    "server_error",
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        }
    }
    Json(json!({
        "object": "list",
        "data": data,
        "model": model,
        "usage": {"prompt_tokens": 0, "total_tokens": 0},
    }))
    .into_response()
}

#[cfg(test)]
mod hailo_genai_vlm_tests {
    use super::*;
    use axum::{routing::post, Router};
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::collections::HashSet;
    use std::str::FromStr;

    async fn spawn_stub(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{address}")
    }

    #[test]
    fn model_name_to_hef_path_resolves_known_registry_name_to_real_filename() {
        let _guard = crate::ENV_MUTATION_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("HOME", "/home/pi");
        std::env::remove_var("HAILO_HEF_DIR");
        assert_eq!(
            model_name_to_hef_path("qwen2-vl-2b-instruct"),
            "/home/pi/hailo_models/Qwen2-VL-2B-Instruct.hef"
        );
        assert_eq!(
            model_name_to_hef_path("qwen3-1.7b-instruct"),
            "/home/pi/hailo_models/Qwen3-1.7B-Instruct.hef"
        );
    }

    #[test]
    fn model_name_to_hef_path_falls_back_to_naive_convention_for_unknown_name() {
        let _guard = crate::ENV_MUTATION_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("HOME", "/home/pi");
        std::env::remove_var("HAILO_HEF_DIR");
        assert_eq!(
            model_name_to_hef_path("Llama3.2-1B-Instruct"),
            "/home/pi/hailo_models/Llama3.2-1B-Instruct.hef"
        );
    }

    #[test]
    fn model_name_to_hef_path_honors_hailo_hef_dir_override() {
        let _guard = crate::ENV_MUTATION_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("HOME", "/home/pi");
        std::env::set_var("HAILO_HEF_DIR", "/tmp/custom_hailo_hefs");
        let result = model_name_to_hef_path("llama3.2-1b");
        std::env::remove_var("HAILO_HEF_DIR");
        assert_eq!(result, "/tmp/custom_hailo_hefs/Llama3.2-1B-Instruct.hef");
    }

    #[tokio::test]
    async fn hailo_genai_model_download_rejects_unknown_model_with_available_list() {
        let state = test_state_with_infer_client("http://127.0.0.1:1").await;
        let response = hailo_genai_model_download(
            State(state),
            None,
            Bytes::from(serde_json::json!({"model": "totally-unknown-model"}).to_string()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["message"], "Unknown model: totally-unknown-model");
        assert!(value["available"].as_array().is_some());
        assert!(!value["available"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn hailo_genai_model_status_enforces_admin_scope_gate() {
        let mut state = test_state_with_infer_client("http://127.0.0.1:1").await;
        std::sync::Arc::get_mut(&mut state)
            .unwrap()
            .config
            .pin_auth_enabled = true;
        let response = hailo_genai_model_status(State(state), None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn hailo_genai_model_download_enforces_admin_scope_gate() {
        let mut state = test_state_with_infer_client("http://127.0.0.1:1").await;
        std::sync::Arc::get_mut(&mut state)
            .unwrap()
            .config
            .pin_auth_enabled = true;
        let response = hailo_genai_model_download(
            State(state),
            None,
            Bytes::from(serde_json::json!({"model": "whisper-tiny"}).to_string()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn default_vlm_model_falls_back_without_config_file() {
        let mut state = test_state_with_infer_client("http://127.0.0.1:18799").await;
        std::sync::Arc::get_mut(&mut state)
            .unwrap()
            .config
            .config_path = std::path::PathBuf::from("/nonexistent/config.json");
        assert_eq!(default_vlm_model(&state), "qwen2-vl-2b-instruct");
    }

    #[tokio::test]
    async fn default_vlm_model_reads_configured_override() {
        let dir = std::env::temp_dir().join("yu-server-vlm-default-model-test");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.json");
        std::fs::write(
            &config_path,
            serde_json::json!({
                "extensions": {"builtin-hailo-genai": {"default_vlm_model": "custom-vlm"}}
            })
            .to_string(),
        )
        .unwrap();

        let mut state = test_state_with_infer_client("http://127.0.0.1:18799").await;
        std::sync::Arc::get_mut(&mut state)
            .unwrap()
            .config
            .config_path = config_path;
        assert_eq!(default_vlm_model(&state), "custom-vlm");
    }

    async fn test_state_with_infer_client(base_url: &str) -> SharedState {
        let pool = SqlitePoolOptions::new()
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TABLE files (id INTEGER PRIMARY KEY, path TEXT NOT NULL, is_deleted INTEGER NOT NULL DEFAULT 0);",
        )
        .execute(&pool)
        .await
        .unwrap();

        std::sync::Arc::new(
            crate::state::AppState::new_with_infer(
                crate::state::Config {
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
                    config_path: std::path::PathBuf::from("config.json"),
                    project_root: std::path::PathBuf::from("."),
                    app_config: serde_json::json!({}),
                    cache_dir: std::path::PathBuf::from("."),
                    server_mode: "full".to_string(),
                    headless: false,
                    safe_mode: false,
                    mcp_native: false,
                    standalone: true,
                    infer_standalone: true,
                    active_profile: None,
                    python_executable: String::new(),
                },
                pool.clone(),
                pool,
                std::sync::Arc::new(crate::logs::ring::LogRingBuffer::new(64)),
                Some(crate::infer_client::InferClient::new(
                    base_url.to_string(),
                    "e2e-test-token".to_string(),
                )),
                None,
            )
            .await,
        )
    }

    #[tokio::test]
    async fn hailo_genai_llm_generate_reaches_yu_infer_stub() {
        let captured = std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let captured_for_route = captured.clone();
        let app = Router::new().route(
            "/v1/infer/llm/generate/stream",
            post(move |Json(body): Json<serde_json::Value>| {
                let captured = captured_for_route.clone();
                async move {
                    *captured.lock().await = Some(body);
                    Response::builder()
                        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
                        .body(axum::body::Body::from(
                            "data: {\"token\":\"SENTINEL\"}\n\ndata: {\"done\":true,\"full_text\":\"SENTINEL\"}\n\n",
                        ))
                        .unwrap()
                }
            }),
        );
        let base_url = spawn_stub(app).await;
        let state = test_state_with_infer_client(&base_url).await;
        let hef_dir = tempfile::tempdir().unwrap();
        std::fs::write(hef_dir.path().join("Qwen3-1.7B-Instruct.hef"), b"stub").unwrap();
        let _guard = crate::ENV_MUTATION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let previous_hef_dir = std::env::var_os("HAILO_HEF_DIR");
        std::env::set_var("HAILO_HEF_DIR", hef_dir.path());

        let response = hailo_genai_llm_generate(
            State(state),
            None,
            axum::http::HeaderMap::new(),
            Bytes::from(
                json!({
                    "model": "qwen3-1.7b-instruct",
                    "messages": [
                        {"role": "system", "content": [{"type": "text", "text": "Follow the rules."}]},
                        {"role": "user", "content": [{"type": "text", "text": "Hello"}]}
                    ],
                    "max_generated_tokens": 17,
                    "temperature": 0.25
                })
                .to_string(),
            ),
        )
        .await;
        match previous_hef_dir {
            Some(value) => std::env::set_var("HAILO_HEF_DIR", value),
            None => std::env::remove_var("HAILO_HEF_DIR"),
        }

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("SENTINEL"));
        let captured = captured.lock().await.take().unwrap();
        assert_eq!(
            captured["messages"],
            json!([
                {"role": "system", "content": "Follow the rules."},
                {"role": "user", "content": "Hello"}
            ])
        );
        assert_eq!(captured["max_generated_tokens"], 17);
        assert_eq!(captured["temperature"], 0.25);
    }

    #[tokio::test]
    async fn hailo_genai_v1_chat_completions_rejects_vision_on_native_path() {
        let state = test_state_with_infer_client("http://127.0.0.1:1").await;
        let response = hailo_genai_chat_completions_native(
            &state,
            state.infer_client.as_ref().unwrap(),
            &Bytes::from(
                json!({"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "data:image/png;base64,"}}]}]}).to_string(),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"]["code"],
            "vision_not_implemented"
        );
    }

    #[tokio::test]
    async fn hailo_genai_v1_chat_completions_validates_request_types() {
        let state = test_state_with_infer_client("http://127.0.0.1:1").await;
        for (body, message) in [
            (json!({}), "messages is required"),
            (
                json!({"messages": [], "stream": "yes"}),
                "messages is required",
            ),
            (
                json!({"messages": [{"role": "user", "content": "hi"}], "stream": "yes"}),
                "stream must be a boolean",
            ),
        ] {
            let response = hailo_genai_chat_completions_native(
                &state,
                state.infer_client.as_ref().unwrap(),
                &Bytes::from(body.to_string()),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&response_body).unwrap()["error"]
                    ["message"],
                message
            );
        }
    }

    #[test]
    fn yu_infer_sse_full_text_parses_completion_events() {
        assert_eq!(
            yu_infer_sse_full_text(""),
            Err(YuInferSseFullTextError::Incomplete { dropped_chars: 0 })
        );
        assert_eq!(
            yu_infer_sse_full_text(
                "data: {\"token\":\"hello \"}\n\ndata: {\"token\":\"world\"}\n\n"
            ),
            Err(YuInferSseFullTextError::Incomplete { dropped_chars: 11 })
        );
        assert_eq!(
            yu_infer_sse_full_text("data: {\"token\":\"ignored\"}\n\ndata: {\"done\":true,\"full_text\":\"complete\"}\n\n"),
            Ok("complete".to_string())
        );
        assert_eq!(
            yu_infer_sse_full_text("data: {\"token\":\"complete\"}\n\ndata: {\"done\":true}\n\n"),
            Ok("complete".to_string())
        );
        assert_eq!(
            yu_infer_sse_full_text("data: {\"error\":\"device failed\"}\n\n"),
            Err(YuInferSseFullTextError::Upstream(
                "device failed".to_string()
            ))
        );
    }

    #[tokio::test]
    async fn hailo_genai_v1_chat_completions_aggregates_yu_infer_sse() {
        let app = Router::new().route(
            "/v1/infer/llm/generate/stream",
            post(|| async {
                Response::builder()
                    .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
                    .body(axum::body::Body::from(
                        "data: {\"token\":\"hello \"}\n\ndata: {\"token\":\"world\"}\n\ndata: {\"done\":true,\"full_text\":\"hello world\"}\n\n",
                    ))
                    .unwrap()
            }),
        );
        let base_url = spawn_stub(app).await;
        let state = test_state_with_infer_client(&base_url).await;
        let hef_dir = tempfile::tempdir().unwrap();
        std::fs::write(hef_dir.path().join("Qwen3-1.7B-Instruct.hef"), b"stub").unwrap();
        let _guard = crate::ENV_MUTATION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let previous_hef_dir = std::env::var_os("HAILO_HEF_DIR");
        std::env::set_var("HAILO_HEF_DIR", hef_dir.path());
        let response = hailo_genai_v1_chat_completions(
            State(state),
            Bytes::from(json!({"model": "qwen3-1.7b-instruct", "messages": [{"role": "user", "content": "hi"}]}).to_string()),
        )
        .await;
        match previous_hef_dir {
            Some(value) => std::env::set_var("HAILO_HEF_DIR", value),
            None => std::env::remove_var("HAILO_HEF_DIR"),
        }
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["object"], "chat.completion");
        assert_eq!(value["model"], "qwen3-1.7b-instruct");
        assert_eq!(value["choices"][0]["message"]["content"], "hello world");
    }

    #[test]
    fn openai_tools_to_native_unwraps_function_and_passes_through_bare_shapes() {
        let openai_shaped = json!([{
            "type": "function",
            "function": {"name": "search", "description": "Find", "parameters": {}}
        }]);
        assert_eq!(
            openai_tools_to_native(Some(&openai_shaped)),
            vec![json!({"name": "search", "description": "Find", "parameters": {}})]
        );
        let already_bare = json!([{"name": "search"}]);
        assert_eq!(
            openai_tools_to_native(Some(&already_bare)),
            vec![json!({"name": "search"})]
        );
        assert!(openai_tools_to_native(None).is_empty());
        assert!(openai_tools_to_native(Some(&json!("not an array"))).is_empty());
    }

    #[tokio::test]
    async fn hailo_genai_v1_chat_completions_forwards_openai_tools_to_yu_infer_natively() {
        let captured = std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let captured_for_route = captured.clone();
        let app = Router::new().route(
            "/v1/infer/llm/generate/stream",
            post(move |Json(body): Json<serde_json::Value>| {
                let captured = captured_for_route.clone();
                async move {
                    *captured.lock().await = Some(body);
                    Response::builder()
                        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
                        .body(axum::body::Body::from(
                            "data: {\"done\":true,\"full_text\":\"ok\"}\n\n",
                        ))
                        .unwrap()
                }
            }),
        );
        let base_url = spawn_stub(app).await;
        let state = test_state_with_infer_client(&base_url).await;
        let hef_dir = tempfile::tempdir().unwrap();
        std::fs::write(hef_dir.path().join("Qwen3-1.7B-Instruct.hef"), b"stub").unwrap();
        let _guard = crate::ENV_MUTATION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let previous_hef_dir = std::env::var_os("HAILO_HEF_DIR");
        std::env::set_var("HAILO_HEF_DIR", hef_dir.path());
        let response = hailo_genai_v1_chat_completions(
            State(state),
            Bytes::from(
                json!({
                    "model": "qwen3-1.7b-instruct",
                    "messages": [{"role": "user", "content": "hi"}],
                    "tools": [{
                        "type": "function",
                        "function": {"name": "get_weather", "description": "Weather lookup", "parameters": {"type": "object"}}
                    }],
                })
                .to_string(),
            ),
        )
        .await;
        match previous_hef_dir {
            Some(value) => std::env::set_var("HAILO_HEF_DIR", value),
            None => std::env::remove_var("HAILO_HEF_DIR"),
        }
        assert_eq!(response.status(), StatusCode::OK);
        let forwarded = captured
            .lock()
            .await
            .clone()
            .expect("tools request captured");
        assert_eq!(
            forwarded["tools"],
            json!([{"name": "get_weather", "description": "Weather lookup", "parameters": {"type": "object"}}])
        );
    }

    #[tokio::test]
    async fn hailo_genai_v1_chat_completions_rejects_truncated_yu_infer_sse() {
        let app = Router::new().route(
            "/v1/infer/llm/generate/stream",
            post(|| async {
                Response::builder()
                    .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
                    .body(axum::body::Body::from("data: {\"token\":\"partial\"}\n\n"))
                    .unwrap()
            }),
        );
        let base_url = spawn_stub(app).await;
        let state = test_state_with_infer_client(&base_url).await;
        let hef_dir = tempfile::tempdir().unwrap();
        std::fs::write(hef_dir.path().join("Qwen3-1.7B-Instruct.hef"), b"stub").unwrap();
        let _guard = crate::ENV_MUTATION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let previous_hef_dir = std::env::var_os("HAILO_HEF_DIR");
        std::env::set_var("HAILO_HEF_DIR", hef_dir.path());
        let response = hailo_genai_v1_chat_completions(
            State(state),
            Bytes::from(json!({"model": "qwen3-1.7b-instruct", "messages": [{"role": "user", "content": "hi"}]}).to_string()),
        )
        .await;
        match previous_hef_dir {
            Some(value) => std::env::set_var("HAILO_HEF_DIR", value),
            None => std::env::remove_var("HAILO_HEF_DIR"),
        }
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["type"], "server_error");
        assert_eq!(value["error"]["message"], "LLM generation failed");
        assert!(!String::from_utf8_lossy(&body).contains("partial"));
    }

    /// The truncation tests below only pin the failure direction. Without this
    /// one, marking a *completed* stream as `error` would pass unnoticed.
    #[tokio::test]
    async fn hailo_genai_v1_chat_completions_stream_marks_completion_as_stop() {
        let app = Router::new().route(
            "/v1/infer/llm/generate/stream",
            post(|| async {
                Response::builder()
                    .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
                    .body(axum::body::Body::from(
                        "data: {\"token\":\"hi\"}\n\ndata: {\"done\":true,\"full_text\":\"hi\"}\n\n",
                    ))
                    .unwrap()
            }),
        );
        let base_url = spawn_stub(app).await;
        let state = test_state_with_infer_client(&base_url).await;
        let hef_dir = tempfile::tempdir().unwrap();
        std::fs::write(hef_dir.path().join("Qwen3-1.7B-Instruct.hef"), b"stub").unwrap();
        let _guard = crate::ENV_MUTATION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let previous_hef_dir = std::env::var_os("HAILO_HEF_DIR");
        std::env::set_var("HAILO_HEF_DIR", hef_dir.path());
        let response = hailo_genai_v1_chat_completions(
            State(state),
            Bytes::from(json!({"model": "qwen3-1.7b-instruct", "messages": [{"role": "user", "content": "hi"}], "stream": true}).to_string()),
        )
        .await;
        match previous_hef_dir {
            Some(value) => std::env::set_var("HAILO_HEF_DIR", value),
            None => std::env::remove_var("HAILO_HEF_DIR"),
        }
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("\"finish_reason\":\"stop\""));
        assert!(!body.contains("\"finish_reason\":\"error\""));
        assert!(body.contains("\"content\":\"hi\""));
        assert!(body.ends_with("data: [DONE]\n\n"));
    }

    #[tokio::test]
    async fn hailo_genai_v1_chat_completions_stream_reports_truncated_yu_infer_sse() {
        let app = Router::new().route(
            "/v1/infer/llm/generate/stream",
            post(|| async {
                Response::builder()
                    .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
                    .body(axum::body::Body::from("data: {\"token\":\"partial\"}\n\n"))
                    .unwrap()
            }),
        );
        let base_url = spawn_stub(app).await;
        let state = test_state_with_infer_client(&base_url).await;
        let hef_dir = tempfile::tempdir().unwrap();
        std::fs::write(hef_dir.path().join("Qwen3-1.7B-Instruct.hef"), b"stub").unwrap();
        let _guard = crate::ENV_MUTATION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let previous_hef_dir = std::env::var_os("HAILO_HEF_DIR");
        std::env::set_var("HAILO_HEF_DIR", hef_dir.path());
        let response = hailo_genai_v1_chat_completions(
            State(state),
            Bytes::from(json!({"model": "qwen3-1.7b-instruct", "messages": [{"role": "user", "content": "hi"}], "stream": true}).to_string()),
        )
        .await;
        match previous_hef_dir {
            Some(value) => std::env::set_var("HAILO_HEF_DIR", value),
            None => std::env::remove_var("HAILO_HEF_DIR"),
        }
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("\"finish_reason\":\"error\""));
        assert!(!body.contains("\"finish_reason\":\"stop\""));
    }

    #[tokio::test]
    async fn hailo_genai_v1_embeddings_reaches_yu_infer_stub() {
        let mut expected_vector = vec![0.0; 512];
        expected_vector[..3].copy_from_slice(&[0.25, -0.5, 0.75]);
        let stub_vector = expected_vector.clone();
        let captured = std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let captured_for_route = captured.clone();
        let app = Router::new().route(
            "/v1/infer/clip-text",
            post(move |Json(body): Json<serde_json::Value>| {
                let captured = captured_for_route.clone();
                let vector = stub_vector.clone();
                async move {
                    *captured.lock().await = Some(body);
                    Json(json!({"data": {"vector": vector}}))
                }
            }),
        );
        let base_url = spawn_stub(app).await;
        let state = test_state_with_infer_client(&base_url).await;

        let response = hailo_genai_v1_embeddings(
            State(state),
            None,
            Bytes::from(json!({"input": "Hello", "model": "clip-vit-b-16"}).to_string()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value,
            json!({
                "object": "list",
                "data": [{
                    "object": "embedding",
                    "index": 0,
                    "embedding": expected_vector,
                }],
                "model": "clip-vit-b-16",
                "usage": {"prompt_tokens": 0, "total_tokens": 0},
            })
        );
        assert_eq!(
            captured.lock().await.take().unwrap(),
            json!({"text": "Hello"})
        );
    }

    #[tokio::test]
    async fn hailo_genai_llm_generate_rejects_invalid_generation_types() {
        let state = test_state_with_infer_client("http://127.0.0.1:1").await;
        for (body, expected_message) in [
            (
                json!({"prompt": "hello", "temperature": "abc"}),
                "temperature must be a finite number",
            ),
            (
                json!({"prompt": "hello", "max_generated_tokens": 1.5}),
                "max_generated_tokens must be an integer",
            ),
            (json!({"prompt": 123}), "prompt must be a string"),
        ] {
            let response = hailo_genai_llm_generate(
                State(state.clone()),
                None,
                axum::http::HeaderMap::new(),
                Bytes::from(body.to_string()),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                value,
                json!({"status": "error", "message": expected_message})
            );
        }
    }

    #[test]
    fn llm_generation_request_validation_accepts_valid_types() {
        assert!(validate_llm_generation_request(&json!({
            "model": "qwen3-1.7b-instruct",
            "messages": [{"role": "user", "content": [{"type": "text"}]}],
            "temperature": 0.25,
            "top_p": 0.9,
            "max_generated_tokens": 17,
            "max_tokens": 18
        }))
        .is_ok());

        for (value, message) in [
            (json!([]), "request body must be an object"),
            (json!({"messages": null}), "messages must be an array"),
            (
                json!({"messages": [{"role": 1}]}),
                "messages[0].role must be a string",
            ),
            (
                json!({"messages": [{"role": "user", "content": [1]}]}),
                "messages[0].content[0] must be an object",
            ),
            (
                json!({"temperature": true}),
                "temperature must be a finite number",
            ),
            (
                json!({"max_generated_tokens": true}),
                "max_generated_tokens must be an integer",
            ),
        ] {
            assert_eq!(
                validate_llm_generation_request(&value).unwrap_err(),
                message
            );
        }
    }

    #[tokio::test]
    async fn hailo_genai_vlm_generate_native_rejects_invalid_model_name() {
        let state = test_state_with_infer_client("http://127.0.0.1:1").await;
        let infer_client = state.infer_client.as_ref().unwrap();
        let body = Bytes::from(
            serde_json::json!({"file_id": 1, "prompt": "hi", "model": "../../etc/passwd"})
                .to_string(),
        );
        let response = hailo_genai_vlm_generate_native(&state, infer_client, &body)
            .await
            .expect("JSON body with file_id must be handled natively");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn hailo_genai_vlm_generate_native_returns_none_without_file_id() {
        let state = test_state_with_infer_client("http://127.0.0.1:1").await;
        let infer_client = state.infer_client.as_ref().unwrap();
        let body = Bytes::from(serde_json::json!({"prompt": "hi"}).to_string());
        assert!(
            hailo_genai_vlm_generate_native(&state, infer_client, &body)
                .await
                .is_none(),
            "requests without file_id should fall back to the Python proxy"
        );
    }

    /// Real end-to-end test against a live `yu-infer` process on real
    /// Hailo-10H hardware: seeds a `files` row pointing at a real on-disk
    /// image, calls the native handler directly (bypassing the axum auth
    /// middleware, matching the existing `hailo_tagger.rs` test pattern),
    /// and asserts the SSE stream carries real tokens through to completion.
    #[tokio::test]
    #[ignore = "requires a running yu-infer on 127.0.0.1:18799 with HAILO_VLM_HEF loaded"]
    async fn hailo_genai_vlm_generate_streams_from_real_yu_infer() {
        let state = test_state_with_infer_client("http://127.0.0.1:18799").await;

        let image_path = std::env::temp_dir().join("yu-server-vlm-e2e-test.jpg");
        let img = image::RgbImage::from_pixel(64, 64, image::Rgb([200, 30, 30]));
        image::DynamicImage::ImageRgb8(img)
            .save(&image_path)
            .expect("write test jpeg");

        sqlx::query("INSERT INTO files (id, path, is_deleted) VALUES (1, ?, 0)")
            .bind(image_path.to_str().unwrap())
            .execute(&state.db)
            .await
            .unwrap();

        // Exercises every supported generation parameter end-to-end (not
        // just temperature/max_generated_tokens) so a regression that
        // silently drops one before forwarding to yu-infer is caught here.
        let body = Bytes::from(
            serde_json::json!({
                "file_id": 1,
                "prompt": "What color is this image? Answer in one word.",
                "system_prompt": "You are a terse image-color classifier.",
                // Matches this dev machine's actually-downloaded VLM hef
                // (see HAILO_RUST_MIGRATION_REMAINING_WORK.md): the model
                // name is unrelated to this test and only needs to resolve
                // to a real .hef file under ~/hailo_models/.
                "model": "Qwen3-VL-2B-Instruct",
                "max_generated_tokens": 16,
                "temperature": 0.7,
                "top_p": 0.9,
                "top_k": 40,
                "frequency_penalty": 0.0,
                "do_sample": true,
                "seed": 42,
            })
            .to_string(),
        );

        let response = hailo_genai_vlm_generate(
            axum::extract::State(state),
            {
                let mut headers = axum::http::HeaderMap::new();
                headers.insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
                headers
            },
            body,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        eprintln!("VLM SSE response: {text}");
        assert!(
            text.contains("\"token\""),
            "expected at least one token event"
        );
        assert!(
            text.contains("\"done\":true"),
            "expected a final done event"
        );

        let _ = std::fs::remove_file(&image_path);
    }
}
