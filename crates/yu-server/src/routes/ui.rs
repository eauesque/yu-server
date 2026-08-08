use std::path::{Path, PathBuf};

use axum::{
    body::Bytes,
    extract::{Extension, Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::{
    auth::{scope::require_admin_scope, AuthContext},
    state::SharedState,
};

async fn fwd_post(state: &SharedState, path: &str, body: Bytes) -> Response {
    if state.config.python_url.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok":false,"error":"unavailable"})),
        )
            .into_response();
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

async fn fwd_delete(state: &SharedState, path: &str) -> Response {
    if state.config.python_url.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok":false,"error":"unavailable"})),
        )
            .into_response();
    }
    let url = format!("{}{}", state.config.python_url.trim_end_matches('/'), path);
    match state
        .python_client
        .delete(&url)
        .header("X-Remote-User", "yu-proxy-auth")
        .header("X-Requested-With", "XMLHttpRequest")
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

/// POST /api/ui/switch — no auth (Python also requires none)
pub async fn ui_switch() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
}

pub async fn install(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = require_admin_scope(state.config.pin_auth_enabled, auth.as_ref().map(|c| &c.0))
    {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

pub async fn uninstall(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = require_admin_scope(state.config.pin_auth_enabled, auth.as_ref().map(|c| &c.0))
    {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

pub async fn ui_list(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(response) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|c| &c.0),
    ) {
        return response;
    }
    match list_uis(&state.config.project_root, &state.config.config_path) {
        Ok(uis) => api_result(json!({"data": {"uis": uis}})),
        Err(error) => internal_error(error, "failed to list UIs"),
    }
}

fn list_uis(project_root: &Path, config_path: &Path) -> std::io::Result<Vec<Value>> {
    let active = resolve_active_ui(project_root, &load_config_json(config_path));
    let ui_root = project_root.join("ui");
    if !ui_root.is_dir() {
        return Ok(vec![]);
    }
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(ui_root)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir() && path.join("manifest.json").is_file())
        .collect();
    dirs.sort();

    let mut result = Vec::new();
    for ui_dir in dirs {
        let Some(manifest) = load_ui_manifest(&ui_dir) else {
            continue;
        };
        let name = ui_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        result.push(json!({
            "name": name,
            "active": name == active,
            "manifest": manifest,
            "has_templates": ui_dir.join("templates").is_dir(),
            "has_static": ui_dir.join("static").is_dir(),
        }));
    }
    Ok(result)
}

pub(crate) fn load_config_json(config_path: &Path) -> Value {
    let mut paths = vec![config_path.to_path_buf()];
    paths.push(PathBuf::from("config.json"));
    paths.push(PathBuf::from("tagdb_config.json"));
    for path in paths {
        if path.exists() {
            return std::fs::read_to_string(path)
                .ok()
                .and_then(|raw| serde_json::from_str(&raw).ok())
                .unwrap_or_else(|| json!({"scan_roots": []}));
        }
    }
    json!({"scan_roots": []})
}

pub(crate) fn resolve_active_ui(project_root: &Path, config: &Value) -> String {
    if let Some(explicit) = config
        .get("ui")
        .and_then(Value::as_str)
        .filter(|s| is_safe_ui_name(s))
    {
        let ui_dir = project_root.join("ui").join(explicit);
        if ui_dir.is_dir() && load_ui_manifest(&ui_dir).is_some() {
            return explicit.to_string();
        }
    }
    let custom_dir = project_root.join("ui").join("custom");
    if custom_dir.is_dir() && load_ui_manifest(&custom_dir).is_some() {
        return "custom".to_string();
    }
    "default".to_string()
}

pub(crate) fn is_safe_ui_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn load_ui_manifest(ui_dir: &Path) -> Option<Value> {
    let raw = std::fs::read_to_string(ui_dir.join("manifest.json")).ok()?;
    let data: Value = serde_json::from_str(&raw).ok()?;
    let map = data.as_object()?;
    for field in ["name", "version"] {
        if map
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|s| s.trim().is_empty())
        {
            return None;
        }
    }
    if let Some(ui_type) = map.get("type").and_then(Value::as_str) {
        if !matches!(ui_type, "full" | "theme") {
            return None;
        }
    }
    Some(data)
}

pub(crate) fn api_result(payload: Value) -> Response {
    let mut body = match payload {
        Value::Object(map) => map,
        other => {
            return Json(json!({"ok": true, "error": null, "data": other})).into_response();
        }
    };
    body.insert("ok".to_string(), Value::Bool(true));
    body.insert("error".to_string(), Value::Null);
    body.entry("data".to_string()).or_insert(Value::Null);
    Json(Value::Object(body)).into_response()
}

pub(crate) fn internal_error(error: impl std::fmt::Debug, message: &'static str) -> Response {
    tracing::error!(?error, "{}", message);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"ok": false, "error": "internal_server_error"})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        fs,
        path::{Path, PathBuf},
        str::FromStr,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use axum::body::to_bytes;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use crate::state::{AppState, Config};

    fn temp_root(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("yu-server-{name}-{unique}"))
    }

    fn write_file(path: &Path, body: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
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

    async fn json_body(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn ui_list_returns_valid_ui_manifests_in_directory_order() {
        let root = temp_root("ui-list");
        write_file(
            &root.join("ui/default/manifest.json"),
            r#"{"name":"default","version":"1.0","label":"Default"}"#,
        );
        fs::create_dir_all(root.join("ui/default/templates")).unwrap();
        fs::create_dir_all(root.join("ui/default/static")).unwrap();
        write_file(
            &root.join("ui/sample/manifest.json"),
            r#"{"name":"sample","version":"2.0","type":"full","is_sample":true}"#,
        );
        fs::create_dir_all(root.join("ui/sample/static")).unwrap();
        write_file(&root.join("ui/broken/manifest.json"), r#"{"name":""}"#);

        let response = ui_list(
            State(test_state(root.clone(), r#"{"ui":"sample"}"#).await),
            None,
        )
        .await;
        let _ = fs::remove_dir_all(root);
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(value["ok"], true);
        assert_eq!(value["error"], serde_json::Value::Null);
        assert_eq!(value["data"]["uis"][0]["name"], "default");
        assert_eq!(value["data"]["uis"][0]["active"], false);
        assert_eq!(value["data"]["uis"][0]["has_templates"], true);
        assert_eq!(value["data"]["uis"][0]["has_static"], true);
        assert_eq!(value["data"]["uis"][1]["name"], "sample");
        assert_eq!(value["data"]["uis"][1]["active"], true);
        assert_eq!(value["data"]["uis"][1]["has_templates"], false);
        assert_eq!(value["data"]["uis"][1]["has_static"], true);
    }

    #[tokio::test]
    async fn ui_list_rejects_path_traversal_active_ui_names() {
        let root = temp_root("ui-list-traversal");
        write_file(
            &root.join("ui/default/manifest.json"),
            r#"{"name":"default","version":"1.0"}"#,
        );
        write_file(
            &root.join("evil/manifest.json"),
            r#"{"name":"evil","version":"1.0"}"#,
        );

        let response = ui_list(
            State(test_state(root.clone(), r#"{"ui":"../evil"}"#).await),
            None,
        )
        .await;
        let _ = fs::remove_dir_all(root);
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(value["data"]["uis"][0]["name"], "default");
        assert_eq!(value["data"]["uis"][0]["active"], true);
    }
}
