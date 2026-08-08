use axum::{
    body::Bytes,
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use sqlx::Row;

use crate::{
    auth::{scope::require_admin_scope, AuthContext},
    routes::peer_identity::{derive_peer_id_from_seed, local_peer_id},
    state::SharedState,
};

fn api_result(payload: Value) -> Response {
    let mut body = match payload {
        Value::Object(map) => map,
        other => return Json(json!({"ok": true, "error": null, "data": other})).into_response(),
    };
    body.entry("ok".to_string()).or_insert(Value::Bool(true));
    body.entry("error".to_string()).or_insert(Value::Null);
    body.entry("data".to_string()).or_insert(Value::Null);
    Json(Value::Object(body)).into_response()
}

fn api_error(message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"ok": false, "error": message})),
    )
        .into_response()
}

fn admin_scope_error(
    state: &SharedState,
    auth_context: Option<&Extension<AuthContext>>,
) -> Option<Response> {
    require_admin_scope(state.config.pin_auth_enabled, auth_context.map(|c| &c.0))
}

async fn online_peer_rows(
    state: &SharedState,
) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    // The Python mesh registry owns live mDNS/runtime capability updates. Rust
    // reads the persisted table only, so liveness is as fresh as last_reached_at.
    sqlx::query(
        "SELECT peer_id, name
         FROM peers
         WHERE last_reached_at IS NOT NULL
         ORDER BY peer_id",
    )
    .fetch_all(&state.db_read)
    .await
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "localhost".to_string())
}

fn configured_peer_name(state: &SharedState) -> String {
    let configured = state
        .config
        .app_config
        .get("extensions")
        .and_then(|extensions| extensions.get("builtin-lan-cowork"))
        .and_then(|cowork| cowork.get("peer_name"))
        .and_then(Value::as_str)
        .unwrap_or("auto");
    if configured == "auto" {
        hostname()
    } else {
        configured.to_string()
    }
}

fn has_local_tagger_capability(state: &SharedState) -> bool {
    let mut roots = vec![state.config.project_root.join("cache").join("wd_tagger")];
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(
            std::path::PathBuf::from(home)
                .join(".cache")
                .join("yu_ai_manager")
                .join("wd_tagger"),
        );
    }
    roots.into_iter().any(|root| {
        let Ok(entries) = std::fs::read_dir(root) else {
            return false;
        };
        entries.flatten().any(|entry| {
            let path = entry.path();
            path.is_dir() && (path.join("model.hef").exists() || path.join("model.onnx").exists())
        })
    })
}

async fn local_tagger_peer(state: &SharedState) -> Option<Value> {
    if !has_local_tagger_capability(state) {
        return None;
    }
    let peer_id = local_peer_id(&**state).await?;
    Some(json!({
        "peer_id": peer_id,
        "name": configured_peer_name(state),
        "status": "online",
        "is_local": true,
    }))
}

pub async fn list(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(response) = admin_scope_error(&state, auth_context.as_ref()) {
        return response;
    }
    match online_peer_rows(&state).await {
        Ok(rows) => {
            let mut servers = Vec::new();
            if let Some(local) = local_tagger_peer(&state).await {
                servers.push(json!({
                    "id": local.get("peer_id").and_then(Value::as_str).unwrap_or(""),
                    "name": local.get("name").and_then(Value::as_str).unwrap_or(""),
                    "type": "mesh",
                    "priority": 0,
                    "enabled": true,
                    "status": "online",
                }));
            }
            servers.extend(
                rows.into_iter()
                    .map(|row| {
                        json!({
                            "id": row.try_get::<String, _>("peer_id").unwrap_or_default(),
                            "name": row.try_get::<String, _>("name").unwrap_or_default(),
                            "type": "mesh",
                            "priority": 0,
                            "enabled": true,
                            "status": "online",
                        })
                    })
                    .collect::<Vec<_>>(),
            );
            api_result(json!({"mode": "mesh", "servers": servers}))
        }
        Err(error) => {
            tracing::error!(?error, "failed to list tagger peers");
            api_error("Failed to list tagger servers")
        }
    }
}

pub async fn health(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(response) = admin_scope_error(&state, auth_context.as_ref()) {
        return response;
    }
    match online_peer_rows(&state).await {
        Ok(rows) => {
            let mut peers = Vec::new();
            if let Some(local) = local_tagger_peer(&state).await {
                peers.push(local);
            }
            peers.extend(
                rows.into_iter()
                    .map(|row| {
                        json!({
                            "peer_id": row.try_get::<String, _>("peer_id").unwrap_or_default(),
                            "name": row.try_get::<String, _>("name").unwrap_or_default(),
                            "status": "online",
                            "is_local": false,
                        })
                    })
                    .collect::<Vec<_>>(),
            );
            api_result(json!({"peers": peers}))
        }
        Err(error) => {
            tracing::error!(?error, "failed to list tagger peer health");
            api_error("Failed to get tagger server health")
        }
    }
}

pub async fn stats(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(response) = admin_scope_error(&state, auth_context.as_ref()) {
        return response;
    }
    match sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
         FROM files f
         WHERE f.is_deleted = 0
           AND NOT EXISTS (
             SELECT 1 FROM file_hailo_tags h WHERE h.file_id = f.id
           )",
    )
    .fetch_one(&state.db_read)
    .await
    {
        Ok(count) => api_result(json!({"untagged_count": count})),
        Err(error) => {
            tracing::error!(?error, "failed to count untagged files");
            api_error("Failed to get tagger server stats")
        }
    }
}

// ── tagger-servers batch forwarders (no admin scope — mirrors Python) ─────────

async fn fwd_post_ts(state: &SharedState, path: &str, body: Bytes) -> Response {
    if state.config.python_url.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"ok": false, "error": "unavailable"})),
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

pub async fn batch_tag(State(s): State<SharedState>, body: Bytes) -> Response {
    fwd_post_ts(&s, "/api/tagger-servers/batch", body).await
}

pub async fn batch_cancel(State(s): State<SharedState>, body: Bytes) -> Response {
    fwd_post_ts(&s, "/api/tagger-servers/batch/cancel", body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashSet, path::PathBuf, str::FromStr, sync::Arc};

    use axum::{body::to_bytes, extract::State};
    use serde_json::json;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use crate::state::{AppState, Config, SharedState};

    async fn test_state() -> SharedState {
        let pool = SqlitePoolOptions::new()
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TABLE peers (
               peer_id TEXT PRIMARY KEY,
               name TEXT,
               api_host TEXT,
               api_port INTEGER,
               token TEXT,
               token_expires_at INTEGER,
               token_issued_at INTEGER,
               allow_legacy_auth INTEGER NOT NULL DEFAULT 0,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL,
               last_reached_at INTEGER,
               last_attempted_at INTEGER
             );
             CREATE TABLE files (id INTEGER PRIMARY KEY, is_deleted INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE file_hailo_tags (
               id INTEGER PRIMARY KEY,
               file_id INTEGER NOT NULL,
               tag_name TEXT NOT NULL,
               confidence REAL NOT NULL,
               source TEXT NOT NULL DEFAULT 'hailo_remote',
               created_at INTEGER NOT NULL DEFAULT 0,
               UNIQUE(file_id, tag_name)
             );
             INSERT INTO peers(peer_id, name, api_host, api_port, created_at, updated_at, last_reached_at)
             VALUES ('peer-a', 'Peer A', '127.0.0.1', 5000, 100, 200, 200),
                    ('peer-b', 'Peer B', '127.0.0.2', 5001, 100, 200, NULL);
             INSERT INTO files(id, is_deleted) VALUES (1, 0), (2, 0), (3, 1);
             INSERT INTO file_hailo_tags(file_id, tag_name, confidence, source, created_at)
             VALUES (1, 'cat', 0.9, 'mesh', 200);",
        )
        .execute(&pool)
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
                    config_path: PathBuf::from("config.json"),
                    project_root: PathBuf::from("."),
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

    async fn test_state_with_local_tagger() -> (SharedState, String) {
        let pool = SqlitePoolOptions::new()
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:").unwrap())
            .await
            .unwrap();
        let seed = vec![7_u8; 32];
        let expected_peer_id = derive_peer_id_from_seed(&seed).unwrap();
        sqlx::raw_sql(
            "CREATE TABLE peers (
               peer_id TEXT PRIMARY KEY,
               name TEXT,
               api_host TEXT,
               api_port INTEGER,
               token TEXT,
               token_expires_at INTEGER,
               token_issued_at INTEGER,
               allow_legacy_auth INTEGER NOT NULL DEFAULT 0,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL,
               last_reached_at INTEGER,
               last_attempted_at INTEGER
             );
             CREATE TABLE lan_cowork_identity (
               key TEXT PRIMARY KEY,
               value BLOB NOT NULL
             );
             INSERT INTO lan_cowork_identity(key, value) VALUES ('ed25519_seed', X'0707070707070707070707070707070707070707070707070707070707070707');
             INSERT INTO peers(peer_id, name, api_host, api_port, created_at, updated_at, last_reached_at)
             VALUES ('peer-a', 'Peer A', '127.0.0.1', 5000, 100, 200, 200);",
        )
        .execute(&pool)
        .await
        .unwrap();
        let project_root =
            std::env::temp_dir().join(format!("yu-server-local-peer-test-{}", std::process::id()));
        let model_dir = project_root
            .join("cache")
            .join("wd_tagger")
            .join("SmilingWolf_wd-swinv2-tagger-v3");
        std::fs::create_dir_all(&model_dir).unwrap();
        std::fs::write(model_dir.join("model.onnx"), b"").unwrap();
        let cache_dir = project_root.join("cache");

        let state = Arc::new(
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
                    cache_dir,
                    server_mode: "full".to_string(),
                    headless: false,
                    safe_mode: false,
                    mcp_native: false,
                    standalone: false,
                    infer_standalone: true,
                    active_profile: None,
                    python_executable: String::new(),
                    app_config: json!({
                        "extensions": {
                            "builtin-lan-cowork": {
                                "peer_name": "local-node"
                            }
                        }
                    }),
                },
                pool.clone(),
                pool,
                Arc::new(crate::logs::ring::LogRingBuffer::new(64)),
            )
            .await,
        );
        (state, expected_peer_id)
    }

    async fn json_body(response: axum::response::Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn list_reads_tagger_peers_from_persisted_registry() {
        let value = json_body(list(State(test_state().await), None).await).await;

        assert_eq!(value["ok"], true);
        assert_eq!(value["mode"], "mesh");
        assert_eq!(value["servers"][0]["id"], "peer-a");
        assert_eq!(value["servers"][0]["type"], "mesh");
        assert_eq!(value["servers"][0]["status"], "online");
    }

    #[tokio::test]
    async fn health_returns_online_tagger_peers_from_persisted_registry() {
        let value = json_body(health(State(test_state().await), None).await).await;

        assert_eq!(value["ok"], true);
        assert_eq!(value["peers"][0]["peer_id"], "peer-a");
        assert_eq!(value["peers"][0]["status"], "online");
        assert_eq!(value["peers"][0]["is_local"], false);
    }

    #[tokio::test]
    async fn list_and_health_prepend_local_tagger_peer_from_identity_and_cache() {
        let (state, expected_peer_id) = test_state_with_local_tagger().await;

        let list_value = json_body(list(State(Arc::clone(&state)), None).await).await;
        let health_value = json_body(health(State(state), None).await).await;

        assert_eq!(list_value["servers"][0]["id"], expected_peer_id);
        assert_eq!(list_value["servers"][0]["name"], "local-node");
        assert_eq!(list_value["servers"][0]["status"], "online");
        assert_eq!(health_value["peers"][0]["peer_id"], expected_peer_id);
        assert_eq!(health_value["peers"][0]["name"], "local-node");
        assert_eq!(health_value["peers"][0]["status"], "online");
        assert_eq!(health_value["peers"][0]["is_local"], true);
        assert_eq!(health_value["peers"][1]["peer_id"], "peer-a");
    }

    #[tokio::test]
    async fn stats_counts_files_without_tagger_rows() {
        let value = json_body(stats(State(test_state().await), None).await).await;

        assert_eq!(value["ok"], true);
        assert_eq!(value["untagged_count"], 1);
    }
}
