use std::cmp::Ordering;

use axum::{
    body::Bytes,
    extract::{Extension, Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use sqlx::{Row, SqlitePool};

use crate::{
    auth::{scope::require_admin_scope, AuthContext},
    state::SharedState,
};

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

fn api_result_status(payload: Value, status: StatusCode) -> Response {
    if status.is_client_error() || status.is_server_error() {
        let message = payload
            .get("error")
            .or_else(|| payload.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("Request failed");
        let code = payload.get("code").cloned().unwrap_or(Value::Null);
        return (
            status,
            Json(json!({
                "ok": false,
                "error": message,
                "code": code,
            })),
        )
            .into_response();
    }
    let mut body = match payload {
        Value::Object(map) => map,
        other => {
            return (
                status,
                Json(json!({"ok": true, "error": null, "data": other})),
            )
                .into_response();
        }
    };
    body.insert("ok".to_string(), Value::Bool(true));
    body.insert("error".to_string(), Value::Null);
    body.entry("data".to_string()).or_insert(Value::Null);
    (status, Json(Value::Object(body))).into_response()
}

fn api_error(message: &str, code: &str, status: StatusCode) -> Response {
    (
        status,
        Json(json!({
            "ok": false,
            "error": message,
            "code": code,
        })),
    )
        .into_response()
}

fn admin_scope_error(
    state: &SharedState,
    auth_context: Option<&Extension<AuthContext>>,
) -> Option<Response> {
    require_admin_scope(state.config.pin_auth_enabled, auth_context.map(|c| &c.0))
}

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

/// POST /api/extract-from-zip — admin scope required
pub async fn extract_from_zip(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_scope_error(&state, auth_context.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

async fn build_file_info(pool: &SqlitePool, file_id: i64) -> Result<Option<Value>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT path, is_zip_member, extracted_from_zip, extracted_from_internal,
                extraction_date, extracted_to_file_id
         FROM files WHERE id=?",
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        json!({
            "path": row.get::<String, _>("path"),
            "is_zip_member": row
                .try_get::<Option<i64>, _>("is_zip_member")
                .ok()
                .flatten()
                .unwrap_or(0) != 0,
            "extracted_from_zip": row.try_get::<Option<String>, _>("extracted_from_zip").ok().flatten(),
            "extracted_from_internal": row.try_get::<Option<String>, _>("extracted_from_internal").ok().flatten(),
            "extraction_date": row.try_get::<Option<i64>, _>("extraction_date").ok().flatten(),
            "extracted_to_file_id": row.try_get::<Option<i64>, _>("extracted_to_file_id").ok().flatten(),
        })
    }))
}

pub async fn open_folder(
    State(state): State<SharedState>,
    AxumPath(file_id): AxumPath<i64>,
) -> Response {
    let row: Option<String> =
        sqlx::query_scalar("SELECT path FROM files WHERE id=? AND is_deleted=0")
            .bind(file_id)
            .fetch_optional(&state.db_read)
            .await
            .unwrap_or(None);
    let path_str = match row {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"ok":false,"error":"file_not_found","detail":"File not found"})),
            )
                .into_response();
        }
    };

    // Strip archive member suffix (e.g. "foo.zip!member.png" → "foo.zip")
    let fs_path = if let Some(idx) = path_str.find('!') {
        path_str[..idx].to_string()
    } else {
        path_str.clone()
    };
    let abs_path = std::path::Path::new(&fs_path)
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(&fs_path));
    let dir = abs_path.parent().unwrap_or(&abs_path).to_path_buf();

    let dir_str = dir.to_string_lossy().to_string();

    #[cfg(target_os = "linux")]
    let cmd = std::process::Command::new("xdg-open").arg(&dir_str).spawn();
    #[cfg(target_os = "macos")]
    let cmd = std::process::Command::new("open")
        .arg("-R")
        .arg(&abs_path)
        .spawn();
    #[cfg(target_os = "windows")]
    let cmd = std::process::Command::new("explorer").arg(&dir_str).spawn();
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let cmd: Result<_, std::io::Error> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unsupported",
    ));

    if let Err(e) = cmd {
        tracing::warn!(?e, "open_folder: failed to launch file manager");
    }

    Json(json!({"ok":true,"error":null,"data":{"success":true,"path":dir_str}})).into_response()
}

pub async fn file_info(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
    AxumPath(file_id): AxumPath<i64>,
) -> Response {
    if let Some(response) = admin_scope_error(&state, auth_context.as_ref()) {
        return response;
    }
    match build_file_info(&state.db_read, file_id).await {
        Ok(Some(value)) => api_result(value),
        Ok(None) => api_result_status(
            json!({"error": "File not found", "code": "file_not_found"}),
            StatusCode::NOT_FOUND,
        ),
        Err(error) => {
            tracing::error!(?error, file_id, "file info failed");
            api_error(
                "Failed to get file info",
                "file_info_error",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

fn archive_part(path: &str) -> String {
    let lower = path.to_lowercase();
    let mut first: Option<(usize, usize)> = None;
    for ext in [".zip!", ".7z!", ".rar!"] {
        if let Some(idx) = lower.find(ext) {
            if first.is_none_or(|(first_idx, _)| idx < first_idx) {
                first = Some((idx, ext.len()));
            }
        }
    }
    if let Some((idx, ext_len)) = first {
        let sep = idx + ext_len - 1;
        return path[..sep].to_string();
    }
    path.to_string()
}

fn container_path(path: &str) -> String {
    let path = path.to_string();
    if path.contains('!') {
        return archive_part(&path);
    }
    let lower = path.to_lowercase();
    if lower.ends_with(".zip") || lower.ends_with(".7z") || lower.ends_with(".rar") {
        return path;
    }
    String::new()
}

fn member_name(path: &str) -> &str {
    path.split_once('!').map_or(path, |(_, name)| name)
}

#[derive(Debug, Eq, PartialEq)]
enum NaturalPart {
    Number(String),
    Text(String),
}

fn natural_parts(path: &str) -> Vec<NaturalPart> {
    let name = member_name(path).replace('\\', "/");
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_digit: Option<bool> = None;
    for (idx, ch) in name.char_indices() {
        let digit = ch.is_ascii_digit();
        match in_digit {
            None => in_digit = Some(digit),
            Some(current) if current != digit => {
                let part = &name[start..idx];
                if current {
                    parts.push(NaturalPart::Number(part.to_string()));
                } else {
                    parts.push(NaturalPart::Text(part.to_lowercase()));
                }
                start = idx;
                in_digit = Some(digit);
            }
            Some(_) => {}
        }
    }
    if let Some(current) = in_digit {
        let part = &name[start..];
        if current {
            parts.push(NaturalPart::Number(part.to_string()));
        } else {
            parts.push(NaturalPart::Text(part.to_lowercase()));
        }
    }
    parts
}

fn compare_number_text(left: &str, right: &str) -> Ordering {
    let left_trimmed = left.trim_start_matches('0');
    let right_trimmed = right.trim_start_matches('0');
    let left_norm = if left_trimmed.is_empty() {
        "0"
    } else {
        left_trimmed
    };
    let right_norm = if right_trimmed.is_empty() {
        "0"
    } else {
        right_trimmed
    };
    left_norm
        .len()
        .cmp(&right_norm.len())
        .then_with(|| left_norm.cmp(right_norm))
}

fn natural_cmp(left: &str, right: &str) -> Ordering {
    let left_parts = natural_parts(left);
    let right_parts = natural_parts(right);
    for (left_part, right_part) in left_parts.iter().zip(right_parts.iter()) {
        let order = match (left_part, right_part) {
            (NaturalPart::Number(a), NaturalPart::Number(b)) => compare_number_text(a, b),
            (NaturalPart::Number(_), NaturalPart::Text(_)) => Ordering::Less,
            (NaturalPart::Text(_), NaturalPart::Number(_)) => Ordering::Greater,
            (NaturalPart::Text(a), NaturalPart::Text(b)) => a.cmp(b),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    left_parts.len().cmp(&right_parts.len()).then_with(|| {
        member_name(left)
            .to_lowercase()
            .cmp(&member_name(right).to_lowercase())
    })
}

async fn build_container_members(
    pool: &SqlitePool,
    file_id: i64,
) -> Result<Result<Value, (Value, StatusCode)>, sqlx::Error> {
    let row = sqlx::query("SELECT id, path FROM files WHERE id=?")
        .bind(file_id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(Err((
            json!({"error": "File not found", "code": "file_not_found"}),
            StatusCode::NOT_FOUND,
        )));
    };
    let row_id = row.get::<i64, _>("id");
    let path = row.get::<String, _>("path");
    let container_path = container_path(&path);
    if container_path.is_empty() {
        return Ok(Err((
            json!({"error": "Container not found for file", "code": "container_not_found"}),
            StatusCode::BAD_REQUEST,
        )));
    }
    let like = format!("{container_path}!%");
    let rows = sqlx::query(
        "SELECT id, path
         FROM files
         WHERE is_deleted=0
           AND path LIKE ?
         ORDER BY path",
    )
    .bind(like)
    .fetch_all(pool)
    .await?;
    let mut members = rows
        .into_iter()
        .map(|row| (row.get::<i64, _>("id"), row.get::<String, _>("path")))
        .collect::<Vec<_>>();
    members.sort_by(|left, right| natural_cmp(&left.1, &right.1));
    let member_ids = members.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    let representatives = member_ids.iter().copied().take(4).collect::<Vec<_>>();
    let focus_id = if member_ids.contains(&row_id) {
        Some(row_id)
    } else {
        member_ids.first().copied()
    };
    Ok(Ok(json!({
        "success": true,
        "container_path": container_path,
        "member_count": member_ids.len(),
        "member_ids": member_ids,
        "representatives": representatives,
        "focus_id": focus_id,
    })))
}

pub async fn container_members(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
    AxumPath(file_id): AxumPath<i64>,
) -> Response {
    if let Some(response) = admin_scope_error(&state, auth_context.as_ref()) {
        return response;
    }
    match build_container_members(&state.db_read, file_id).await {
        Ok(Ok(value)) => api_result(value),
        Ok(Err((payload, status))) => api_result_status(payload, status),
        Err(error) => {
            tracing::error!(?error, file_id, "container members failed");
            api_error(
                "Failed to get container members",
                "container_members_error",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, path::PathBuf, str::FromStr, sync::Arc};

    use axum::{
        body::to_bytes,
        extract::{Path as AxumPath, State},
        response::Response,
    };
    use serde_json::{json, Value};
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use crate::state::{AppState, Config, SharedState};

    async fn test_state(seed: &str) -> SharedState {
        let pool = SqlitePoolOptions::new()
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TABLE files (
               id INTEGER PRIMARY KEY,
               path TEXT NOT NULL,
               is_deleted INTEGER NOT NULL DEFAULT 0,
               is_zip_member INTEGER,
               extracted_from_zip TEXT,
               extracted_from_internal TEXT,
               extraction_date INTEGER,
               extracted_to_file_id INTEGER
             );",
        )
        .execute(&pool)
        .await
        .unwrap();
        if !seed.is_empty() {
            sqlx::raw_sql(seed).execute(&pool).await.unwrap();
        }
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

    async fn json_body(response: Response) -> Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn file_info_returns_zip_metadata_and_404_payload() {
        let state = test_state(
            "INSERT INTO files(id, path, is_zip_member, extracted_from_zip,
                               extracted_from_internal, extraction_date, extracted_to_file_id)
             VALUES(1, '/tmp/archive.zip!dir/a.png', 1, '/tmp/archive.zip',
                    'dir/a.png', 1234, 9);",
        )
        .await;

        let value =
            json_body(super::file_info(State(state.clone()), None, AxumPath(1)).await).await;
        assert_eq!(value["path"], "/tmp/archive.zip!dir/a.png");
        assert_eq!(value["is_zip_member"], true);
        assert_eq!(value["extracted_from_zip"], "/tmp/archive.zip");
        assert_eq!(value["extracted_from_internal"], "dir/a.png");
        assert_eq!(value["extraction_date"], 1234);
        assert_eq!(value["extracted_to_file_id"], 9);

        let missing = json_body(super::file_info(State(state), None, AxumPath(99)).await).await;
        assert_eq!(
            missing,
            json!({"ok": false, "error": "File not found", "code": "file_not_found"})
        );
    }

    #[tokio::test]
    async fn container_members_resolves_archive_and_natural_sorts_members() {
        let state = test_state(
            "INSERT INTO files(id, path, is_deleted) VALUES
               (1, '/tmp/archive.zip', 0),
               (2, '/tmp/archive.zip!img10.png', 0),
               (3, '/tmp/archive.zip!img2.png', 0),
               (4, '/tmp/archive.zip!dir/img1.png', 0),
               (5, '/tmp/archive.zip!img1.png', 1),
               (6, '/tmp/other.zip!img1.png', 0);",
        )
        .await;

        let value =
            json_body(super::container_members(State(state), None, AxumPath(2)).await).await;

        assert_eq!(value["success"], true);
        assert_eq!(value["container_path"], "/tmp/archive.zip");
        assert_eq!(value["member_count"], 3);
        assert_eq!(value["member_ids"], json!([4, 3, 2]));
        assert_eq!(value["representatives"], json!([4, 3, 2]));
        assert_eq!(value["focus_id"], 2);
    }

    #[tokio::test]
    async fn container_members_rejects_non_archive_files() {
        let state =
            test_state("INSERT INTO files(id, path, is_deleted) VALUES(1, '/tmp/a.png', 0);").await;

        let value =
            json_body(super::container_members(State(state), None, AxumPath(1)).await).await;

        assert_eq!(
            value,
            json!({
                "ok": false,
                "error": "Container not found for file",
                "code": "container_not_found",
            })
        );
    }
}
