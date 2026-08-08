//! `/api/extensions/*` admin surface — git-based lifecycle (Rust native) + forwarders.
//!
//! Git lifecycle (install/update/uninstall) runs Rust-native; no Python compat.
//! Author tools, marketplace, and metadata routes remain Python forwarders.

use std::path::PathBuf;

use axum::{
    body::Bytes,
    extract::{Extension, Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tokio::process::Command as Cmd;

use crate::{
    auth::{scope::require_admin_scope, AuthContext},
    state::SharedState,
};

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
pub async fn isolation(
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

/// GET /api/extensions/marketplace
pub async fn marketplace(
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
pub async fn extension_detail(
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
pub async fn extension_toggle(
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
pub async fn extension_config_get(
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

/// POST /api/extensions/{name}/config
pub async fn extension_config_post(
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
