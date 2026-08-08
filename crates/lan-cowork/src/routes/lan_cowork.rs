use std::path::Path;

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    routes::lan_cowork_host::{LanCoworkHost, LanCoworkState},
    routes::peer_identity::local_peer_id,
};

const EXT_NAME: &str = "builtin-lan-cowork";

pub fn load_config_json(config_path: &Path) -> Value {
    if config_path.exists() {
        return std::fs::read_to_string(config_path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_else(|| json!({}));
    }
    json!({})
}

pub fn write_config_json(config_path: &Path, config: &Value) -> Result<(), std::io::Error> {
    let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".lan_cowork_cfg_{}_{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let text = serde_json::to_string_pretty(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, format!("{text}\n"))?;
    std::fs::rename(&tmp, config_path)?;
    Ok(())
}

pub fn ext_config(config: &Value) -> Value {
    config
        .get("extensions")
        .and_then(|e| e.get(EXT_NAME))
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn cfg_bool(cfg: &Value, key: &str, default: bool) -> bool {
    cfg.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn cfg_i64(cfg: &Value, key: &str, default: i64) -> i64 {
    cfg.get(key).and_then(Value::as_i64).unwrap_or(default)
}

fn normalize_allowlist(entries: &[Value]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for entry in entries.iter().take(256) {
        let candidate = match entry {
            Value::String(s) => Some(s.trim().to_string()),
            Value::Object(map) => map
                .get("peer_id")
                .and_then(Value::as_str)
                .map(|s| s.trim().to_string()),
            _ => None,
        };
        if let Some(pid) = candidate {
            if !pid.is_empty() && seen.insert(pid.clone()) {
                out.push(pid);
            }
        }
    }
    out
}

fn api_ok(data: Value) -> Response {
    Json(data).into_response()
}

pub fn api_err(message: &str, code: &str, status: StatusCode) -> Response {
    (
        status,
        Json(json!({"ok": false, "error": message, "code": code})),
    )
        .into_response()
}

pub async fn session_guard(
    state: &dyn LanCoworkHost,
    session: Option<&tower_sessions::Session>,
) -> Option<Response> {
    state.require_session(session).await
}

pub async fn notify_fleet_allowlists_changed(state: &dyn LanCoworkHost) -> bool {
    if state.python_url().is_empty() {
        return true;
    }
    let url = format!(
        "{}/_internal/lan_cowork/fleet-allowlists-changed",
        state.python_url().trim_end_matches('/')
    );
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state.python_client().post(url).send(),
    )
    .await
    {
        Ok(Ok(response)) => response.status().is_success(),
        _ => false,
    }
}

async fn notify_fleet_chief_changed(state: &dyn LanCoworkHost) -> bool {
    if state.python_url().is_empty() {
        return true;
    }
    let url = format!(
        "{}/_internal/lan_cowork/fleet-chief-changed",
        state.python_url().trim_end_matches('/')
    );
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state.python_client().post(url).send(),
    )
    .await
    {
        Ok(Ok(response)) => response.status().is_success(),
        _ => false,
    }
}

/// Notify the Python `CoworkManager` that a peer's registry state changed so the
/// in-memory registry (which discovery/heartbeat keep live) stays in sync.
///
/// `action` is a discriminator understood by the Python `/_internal` endpoint:
/// - `"token_cleared"` — clear the peer's token fields (UI freshness after revoke)
/// - `"removed"` — evict the peer entirely (`registry.remove`, hybrid delete path)
///
/// Standalone (`python_url` empty) has no Python registry, so this skips and
/// reports success — the caller is authoritative there (design 2026-07-19 M3/M6).
async fn notify_registry_peer_changed(
    state: &dyn LanCoworkHost,
    peer_id: &str,
    action: &str,
) -> bool {
    if state.python_url().is_empty() {
        return true;
    }
    let url = format!(
        "{}/_internal/lan_cowork/registry-peer-changed",
        state.python_url().trim_end_matches('/')
    );
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state
            .python_client()
            .post(url)
            .json(&json!({"peer_id": peer_id, "action": action}))
            .send(),
    )
    .await
    {
        Ok(Ok(response)) => response.status().is_success(),
        _ => false,
    }
}

/// Remove a peer's `peers` row (standalone: direct DELETE) or delegate to the
/// Python in-memory registry (hybrid: `registry.remove` via notify, which also
/// deletes the row — a direct Rust DELETE would be revived by discovery in ~10s).
/// Returns whether the live registry is in sync; `Err` carries a 500 on DB error.
/// Shared by session-authed `peer_admin_delete` and peer-authed `peer_self_delete`
/// (design 2026-07-19 MF-6).
async fn evict_peer_row(state: &dyn LanCoworkHost, peer_id: &str) -> Result<bool, Response> {
    if state.python_url().is_empty() {
        match sqlx::query("DELETE FROM peers WHERE peer_id = ?1")
            .bind(peer_id)
            .execute(state.db())
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                tracing::warn!("evict_peer_row peers delete failed: {e}");
                Err(api_err(
                    "internal error",
                    "db_error",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            }
        }
    } else {
        Ok(notify_registry_peer_changed(state, peer_id, "removed").await)
    }
}

async fn get_peer_auth_settings(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    if let Some(r) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return r;
    }
    let cfg = ext_config(&load_config_json(state.config_path()));
    api_ok(
        json!({"ok": true, "protect_heartbeat": cfg_bool(&cfg, "protect_heartbeat", true), "protect_events": cfg_bool(&cfg, "protect_events", true), "allowed_cidr": cfg_i64(&cfg, "allowed_cidr", 24)}),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerAuthSettingsUpdateReq {
    protect_heartbeat: Option<bool>,
    protect_events: Option<bool>,
    allowed_cidr: Option<i64>,
}

async fn update_peer_auth_settings(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Some(r) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return r;
    }
    let content_type_ok = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim() == "application/json")
        .unwrap_or(false);
    if !content_type_ok {
        return api_err(
            "JSON body is required",
            "invalid_content_type",
            StatusCode::BAD_REQUEST,
        );
    }
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return api_err("Invalid JSON body", "invalid_json", StatusCode::BAD_REQUEST),
    };
    if !parsed.is_object() {
        return api_err(
            "JSON object body is required",
            "invalid_json_object",
            StatusCode::BAD_REQUEST,
        );
    }
    let req: PeerAuthSettingsUpdateReq = match serde_json::from_value(parsed) {
        Ok(r) => r,
        Err(e) => {
            return api_err(
                &format!("body: {e}"),
                "validation_error",
                StatusCode::BAD_REQUEST,
            )
        }
    };
    if req.protect_heartbeat.is_none() && req.protect_events.is_none() && req.allowed_cidr.is_none()
    {
        return api_err(
            "no valid fields provided",
            "validation_error",
            StatusCode::BAD_REQUEST,
        );
    }
    if let Some(cidr) = req.allowed_cidr {
        if !(8..=32).contains(&cidr) {
            return api_err(
                "allowed_cidr: input should be between 8 and 32",
                "validation_error",
                StatusCode::BAD_REQUEST,
            );
        }
    }
    let _guard = state.settings_lock.lock().await;
    let mut full = load_config_json(state.config_path());
    if !full.is_object() {
        full = json!({});
    }
    let root = full.as_object_mut().expect("object set above");
    let extensions = root.entry("extensions").or_insert_with(|| json!({}));
    if !extensions.is_object() {
        *extensions = json!({});
    }
    let ext = extensions
        .as_object_mut()
        .expect("object set above")
        .entry(EXT_NAME)
        .or_insert_with(|| json!({}));
    if !ext.is_object() {
        *ext = json!({});
    }
    let ext_obj = ext.as_object_mut().expect("object set above");
    if let Some(v) = req.protect_heartbeat {
        ext_obj.insert("protect_heartbeat".to_string(), json!(v));
    }
    if let Some(v) = req.protect_events {
        ext_obj.insert("protect_events".to_string(), json!(v));
    }
    if let Some(v) = req.allowed_cidr {
        ext_obj.insert("allowed_cidr".to_string(), json!(v));
    }
    if let Err(e) = write_config_json(state.config_path(), &full) {
        return api_err(
            &format!("failed to write config: {e}"),
            "write_failed",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }
    api_ok(json!({"ok": true}))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetAllowlistsUpdateReq {
    allow_log_stream_from: Option<Vec<Value>>,
    allow_update_from: Option<Vec<Value>>,
    allow_restart_from: Option<Vec<Value>>,
    allow_remote_update: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetSettingsUpdateReq {
    chief: bool,
}

async fn get_fleet_settings(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    if let Some(r) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return r;
    }
    let fleet = ext_config(&load_config_json(state.config_path()))
        .get("fleet")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let chief = fleet.get("chief").and_then(Value::as_bool).unwrap_or(false);
    api_ok(json!({"ok": true, "chief": chief}))
}

async fn update_fleet_settings(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Some(r) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return r;
    }
    let json_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(';').next().unwrap_or("").trim() == "application/json");
    if !json_type {
        return api_err(
            "JSON body is required",
            "invalid_content_type",
            StatusCode::BAD_REQUEST,
        );
    }
    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return api_err("Invalid JSON body", "invalid_json", StatusCode::BAD_REQUEST),
    };
    if !value.is_object() {
        return api_err(
            "JSON object body is required",
            "invalid_json_object",
            StatusCode::BAD_REQUEST,
        );
    }
    let req: FleetSettingsUpdateReq = match serde_json::from_value(value) {
        Ok(v) => v,
        Err(e) => {
            return api_err(
                &format!("body: {e}"),
                "validation_error",
                StatusCode::BAD_REQUEST,
            )
        }
    };

    let guard = state.settings_lock.lock().await;
    let mut full = load_config_json(state.config_path());
    if !full.is_object() {
        full = json!({});
    }
    let root = full.as_object_mut().unwrap();
    let exts = root.entry("extensions").or_insert_with(|| json!({}));
    if !exts.is_object() {
        *exts = json!({});
    }
    let ext = exts
        .as_object_mut()
        .unwrap()
        .entry(EXT_NAME)
        .or_insert_with(|| json!({}));
    if !ext.is_object() {
        *ext = json!({});
    }
    let fleet = ext
        .as_object_mut()
        .unwrap()
        .entry("fleet")
        .or_insert_with(|| json!({}));
    if !fleet.is_object() {
        *fleet = json!({});
    }
    fleet
        .as_object_mut()
        .unwrap()
        .insert("chief".into(), json!(req.chief));
    if let Err(e) = write_config_json(state.config_path(), &full) {
        return api_err(
            &format!("failed to write config: {e}"),
            "write_failed",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }
    drop(guard);

    super::lan_cowork_fleet_manager::sync_fleet_manager(&state, req.chief).await;
    let live_sync = notify_fleet_chief_changed(&*state).await;
    api_ok(json!({"ok": true, "chief": req.chief, "live_sync": live_sync}))
}

async fn get_fleet_allowlists(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    if let Some(r) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return r;
    }
    let fleet = ext_config(&load_config_json(state.config_path()))
        .get("fleet")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let list = |key| {
        normalize_allowlist(
            fleet
                .get(key)
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        )
    };
    api_ok(
        json!({"ok":true,"allow_log_stream_from":list("allow_log_stream_from"),"allow_update_from":list("allow_update_from"),"allow_restart_from":list("allow_restart_from"),"allow_remote_update":fleet.get("allow_remote_update").and_then(Value::as_bool).unwrap_or(true)}),
    )
}

async fn update_fleet_allowlists(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Some(r) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return r;
    }
    let json_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(';').next().unwrap_or("").trim() == "application/json");
    if !json_type {
        return api_err(
            "JSON body is required",
            "invalid_content_type",
            StatusCode::BAD_REQUEST,
        );
    }
    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return api_err("Invalid JSON body", "invalid_json", StatusCode::BAD_REQUEST),
    };
    if !value.is_object() {
        return api_err(
            "JSON object body is required",
            "invalid_json_object",
            StatusCode::BAD_REQUEST,
        );
    }
    let req: FleetAllowlistsUpdateReq = match serde_json::from_value(value) {
        Ok(v) => v,
        Err(e) => {
            return api_err(
                &format!("body: {e}"),
                "validation_error",
                StatusCode::BAD_REQUEST,
            )
        }
    };
    if req.allow_log_stream_from.is_none()
        && req.allow_update_from.is_none()
        && req.allow_restart_from.is_none()
        && req.allow_remote_update.is_none()
    {
        return api_err(
            "no valid fields provided",
            "validation_error",
            StatusCode::BAD_REQUEST,
        );
    }
    for v in [
        &req.allow_log_stream_from,
        &req.allow_update_from,
        &req.allow_restart_from,
    ] {
        if v.as_ref().is_some_and(|v| v.len() > 256) {
            return api_err(
                "allowlist array exceeds 256 elements",
                "validation_error",
                StatusCode::BAD_REQUEST,
            );
        }
    }
    let guard = state.settings_lock.lock().await;
    let mut full = load_config_json(state.config_path());
    if !full.is_object() {
        full = json!({});
    }
    let root = full.as_object_mut().unwrap();
    let exts = root.entry("extensions").or_insert_with(|| json!({}));
    if !exts.is_object() {
        *exts = json!({});
    }
    let ext = exts
        .as_object_mut()
        .unwrap()
        .entry(EXT_NAME)
        .or_insert_with(|| json!({}));
    if !ext.is_object() {
        *ext = json!({});
    }
    let fleet = ext
        .as_object_mut()
        .unwrap()
        .entry("fleet")
        .or_insert_with(|| json!({}));
    if !fleet.is_object() {
        *fleet = json!({});
    }
    let fleet = fleet.as_object_mut().unwrap();
    let old = |k| {
        fleet
            .get(k)
            .and_then(Value::as_array)
            .map(|v| {
                normalize_allowlist(v)
                    .into_iter()
                    .collect::<std::collections::HashSet<_>>()
            })
            .unwrap_or_default()
    };
    let mut shrinking = false;
    let mut changed = std::collections::HashSet::new();
    for (key, input, previous) in [
        (
            "allow_log_stream_from",
            &req.allow_log_stream_from,
            old("allow_log_stream_from"),
        ),
        (
            "allow_update_from",
            &req.allow_update_from,
            old("allow_update_from"),
        ),
        (
            "allow_restart_from",
            &req.allow_restart_from,
            old("allow_restart_from"),
        ),
    ] {
        if let Some(input) = input {
            let normalized = normalize_allowlist(input);
            let next: std::collections::HashSet<_> = normalized.iter().cloned().collect();
            shrinking |= previous.difference(&next).next().is_some();
            changed.extend(previous.symmetric_difference(&next).cloned());
            fleet.insert(key.to_string(), json!(normalized));
        }
    }
    let old_remote = fleet
        .get("allow_remote_update")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut master_changed = false;
    if let Some(v) = req.allow_remote_update {
        shrinking |= old_remote && !v;
        master_changed = old_remote != v;
        fleet.insert("allow_remote_update".into(), json!(v));
    }
    let log = fleet
        .get("allow_log_stream_from")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let update = fleet
        .get("allow_update_from")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let restart = fleet
        .get("allow_restart_from")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let remote = fleet
        .get("allow_remote_update")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if let Err(e) = write_config_json(state.config_path(), &full) {
        return api_err(
            &format!("failed to write config: {e}"),
            "write_failed",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }
    drop(guard);
    let id = session
        .as_ref()
        .and_then(|Extension(s)| s.id())
        .map(|id| id.to_string())
        .unwrap_or_else(|| "unknown".into());
    if master_changed {
        state
            .record_journal_action(
                &id,
                "fleet.permissions.master_switch",
                "success",
                0,
                &format!("fleet master switch set to {remote}"),
            )
            .await;
    }
    for peer in changed {
        state
            .record_journal_action(
                &id,
                "fleet.permissions.update",
                "success",
                0,
                &format!("fleet permissions updated for {peer}"),
            )
            .await;
    }
    let live_sync = notify_fleet_allowlists_changed(&*state).await;
    if shrinking && !live_sync {
        return api_err(
            "permission change saved but live sync failed",
            "live_sync_failed",
            StatusCode::BAD_GATEWAY,
        );
    }
    api_ok(
        json!({"ok":true,"allow_log_stream_from":log,"allow_update_from":update,"allow_restart_from":restart,"allow_remote_update":remote,"live_sync":live_sync}),
    )
}

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
struct TokenRow {
    peer_id: String,
    issued_at: i64,
    expires_at: i64,
    source: String,
    note: Option<String>,
}

async fn list_tokens(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    if let Some(r) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return r;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let rows: Result<Vec<TokenRow>, sqlx::Error> = sqlx::query_as(
        "SELECT peer_id, issued_at, expires_at, source, note \
         FROM peer_tokens WHERE revoked_at IS NULL AND expires_at > ?1 \
         ORDER BY issued_at DESC",
    )
    .bind(now)
    .fetch_all(state.db_read())
    .await;
    match rows {
        Ok(tokens) => api_ok(json!({"ok": true, "tokens": tokens})),
        Err(e) => {
            tracing::warn!("list_tokens query failed: {e}");
            api_err(
                "internal error",
                "db_error",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

async fn revoke_token(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    axum::extract::Path(peer_id): axum::extract::Path<String>,
) -> Response {
    if let Some(r) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return r;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut tx = match state.db().begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!("revoke_token begin failed: {e}");
            return api_err(
                "internal error",
                "db_error",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let r1 = sqlx::query(
        "UPDATE peer_tokens SET revoked_at = ?1 WHERE peer_id = ?2 AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(&peer_id)
    .execute(&mut *tx)
    .await;
    if let Err(e) = r1 {
        tracing::warn!("revoke_token peer_tokens update failed: {e}");
        return api_err(
            "internal error",
            "db_error",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    let r2 = sqlx::query(
        "UPDATE peers SET token = NULL, token_expires_at = NULL, token_issued_at = NULL WHERE peer_id = ?1",
    )
    .bind(&peer_id)
    .execute(&mut *tx)
    .await;
    if let Err(e) = r2 {
        tracing::warn!("revoke_token peers update failed: {e}");
        return api_err(
            "internal error",
            "db_error",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    if let Err(e) = tx.commit().await {
        tracing::warn!("revoke_token commit failed: {e}");
        return api_err(
            "internal error",
            "db_error",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    state.sse_send(
        "lan_cowork",
        "peer.token_revoked",
        now as f64,
        json!({"peer_id": peer_id}),
    );

    // Fire-and-forget: nudge the Python registry to drop the stale token so the
    // discover UI stops showing the peer as paired. The DB revoke above is
    // already authoritative (token_store.verify reads peer_tokens.revoked_at), so
    // a failed notify is only a cosmetic hybrid-UI lag — never fail the revoke
    // (design 2026-07-19 M2/M4).
    let _ = notify_registry_peer_changed(&*state, &peer_id, "token_cleared").await;

    api_ok(json!({"ok": true}))
}

/// Session-authenticated peer removal (LAN Cowork admin UI).
///
/// Mirrors Python `peer_admin_delete` but inverts its ordering: the fleet
/// allowlist removal (security-relevant, persisted to config.json) happens
/// BEFORE the peers-row/registry eviction, so a partial failure never leaves a
/// removed peer still holding fleet permissions (design 2026-07-19 M5; the
/// Python order leaves exactly that window). The peer's inbound *token* is not
/// revoked here (Python parity) — permanent lockout still requires
/// `revoke_token` (design S2).
async fn peer_admin_delete(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    axum::extract::Path(peer_id): axum::extract::Path<String>,
) -> Response {
    if let Some(r) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return r;
    }

    // Self-delete rejection (M6). When no local identity seed is stored,
    // local_peer_id is None: there is no "self" to protect, so deletion proceeds.
    if let Some(local) = local_peer_id(&*state).await {
        if peer_id == local {
            return api_err(
                "cannot remove self",
                "cannot_remove_self",
                StatusCode::BAD_REQUEST,
            );
        }
    }

    // Step 1 (M5): remove the peer from all fleet allowlists and persist to
    // config.json FIRST, under the shared settings lock.
    let guard = state.settings_lock.lock().await;
    let mut full = load_config_json(state.config_path());
    let mut allowlist_changed = false;
    if let Some(fleet) = full
        .get_mut("extensions")
        .and_then(|e| e.get_mut(EXT_NAME))
        .and_then(|e| e.get_mut("fleet"))
        .and_then(Value::as_object_mut)
    {
        for key in [
            "allow_log_stream_from",
            "allow_update_from",
            "allow_restart_from",
        ] {
            // Scope the immutable borrow so the mutable insert below is legal.
            let kept = match fleet.get(key).and_then(Value::as_array) {
                Some(arr) => {
                    let normalized = normalize_allowlist(arr);
                    if normalized.iter().any(|p| p == &peer_id) {
                        Some(
                            normalized
                                .into_iter()
                                .filter(|p| p != &peer_id)
                                .collect::<Vec<_>>(),
                        )
                    } else {
                        None
                    }
                }
                None => None,
            };
            if let Some(kept) = kept {
                fleet.insert(key.to_string(), json!(kept));
                allowlist_changed = true;
            }
        }
    }
    if allowlist_changed {
        if let Err(e) = write_config_json(state.config_path(), &full) {
            drop(guard);
            return api_err(
                &format!("failed to write config: {e}"),
                "write_failed",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    }
    drop(guard);

    // Live-sync the allowlist change to the running peer (reuse the existing
    // fleet-allowlists notify + its shrink-502 semantics). No-op in standalone.
    let allowlist_synced = if allowlist_changed {
        notify_fleet_allowlists_changed(&*state).await
    } else {
        true
    };

    // Step 2 (M5): peers row + in-memory registry eviction, branched by mode.
    let registry_synced = match evict_peer_row(&*state, &peer_id).await {
        Ok(synced) => synced,
        Err(resp) => return resp,
    };

    if !allowlist_synced || !registry_synced {
        // The allowlist config is already persisted and never rolled back (M2);
        // signal that live propagation to the running peer did not complete.
        return api_err(
            "peer removed but live sync failed",
            "live_sync_failed",
            StatusCode::BAD_GATEWAY,
        );
    }

    api_ok(json!({"ok": true}))
}

/// Peer-authenticated self removal: `DELETE /ext/lan_cowork/api/peer/{peer_id}`.
///
/// Unlike `peer_admin_delete` (session auth, admin UI), this is authenticated by
/// the peer transport chain (Ed25519 signature + Bearer token) and a peer may
/// remove ONLY itself (MF-7). It does not touch fleet allowlists (Python
/// `peer_delete` only calls `registry.remove`). Removal reuses the shared
/// mode-branch helper (MF-6).
async fn peer_self_delete(
    State(state): State<LanCoworkState>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    axum::extract::Path(peer_id): axum::extract::Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let authed_peer_id = match crate::auth::peer_transport::require_peer_auth(
        &*state,
        "DELETE",
        uri.path(),
        uri.query().unwrap_or(""),
        &headers,
        &body,
    )
    .await
    {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MF-7: a peer may only remove itself.
    if authed_peer_id != peer_id {
        return api_err("can only remove self", "forbidden", StatusCode::FORBIDDEN);
    }
    match evict_peer_row(&*state, &peer_id).await {
        Ok(true) => api_ok(json!({"ok": true})),
        Ok(false) => api_err(
            "peer removed but live sync failed",
            "live_sync_failed",
            StatusCode::BAD_GATEWAY,
        ),
        Err(resp) => resp,
    }
}

pub fn routes() -> Router<LanCoworkState> {
    Router::new()
        .route(
            "/ext/lan_cowork/api/settings/peer-auth",
            get(get_peer_auth_settings).post(update_peer_auth_settings),
        )
        .route(
            "/ext/lan_cowork/api/settings/fleet/allowlists",
            get(get_fleet_allowlists).post(update_fleet_allowlists),
        )
        .route(
            "/ext/lan_cowork/api/settings/fleet",
            get(get_fleet_settings).post(update_fleet_settings),
        )
        .route("/ext/lan_cowork/api/peer/tokens", get(list_tokens))
        .route(
            "/ext/lan_cowork/api/peer/tokens/{peer_id}/revoke",
            axum::routing::post(revoke_token),
        )
        .route(
            "/ext/lan_cowork/api/peer/admin/{peer_id}",
            axum::routing::delete(peer_admin_delete),
        )
        .route(
            "/ext/lan_cowork/api/peer/{peer_id}",
            axum::routing::delete(peer_self_delete),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::state::SharedState;

    async fn test_state(config_path: std::path::PathBuf) -> SharedState {
        let mut host = crate::test_support::TestHost::new(
            false,
            false,
            String::new(),
            std::path::PathBuf::from("."),
        );
        host.config.config_path = config_path;
        Arc::new(host)
    }
    async fn seed_token_tables(state: &SharedState) {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS peer_tokens (
               peer_id TEXT PRIMARY KEY,
               token_hash TEXT NOT NULL,
               issued_at INTEGER NOT NULL,
               expires_at INTEGER NOT NULL,
               revoked_at INTEGER,
               source TEXT NOT NULL DEFAULT 'pairing',
               note TEXT
             );
             CREATE TABLE IF NOT EXISTS peers (
               peer_id TEXT PRIMARY KEY,
               name TEXT,
               api_host TEXT,
               api_port INTEGER,
               token TEXT,
               token_expires_at INTEGER,
               token_issued_at INTEGER,
               allow_legacy_auth INTEGER NOT NULL DEFAULT 0,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );",
        )
        .execute(&state.db)
        .await
        .unwrap();
    }
    async fn json_body(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }
    async fn request(
        app: Router,
        method: &str,
        body: &str,
        content_type: Option<&str>,
    ) -> Response {
        let mut b = axum::http::Request::builder()
            .method(method)
            .uri("/ext/lan_cowork/api/settings/peer-auth");
        if let Some(v) = content_type {
            b = b.header("content-type", v);
        }
        app.oneshot(b.body(axum::body::Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }
    async fn request_at(
        app: Router,
        method: &str,
        path: &str,
        body: &str,
        content_type: Option<&str>,
    ) -> Response {
        let mut b = axum::http::Request::builder().method(method).uri(path);
        if let Some(v) = content_type {
            b = b.header("content-type", v);
        }
        app.oneshot(b.body(axum::body::Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }
    const FLEET_ALLOWLISTS_PATH: &str = "/ext/lan_cowork/api/settings/fleet/allowlists";
    const FLEET_SETTINGS_PATH: &str = "/ext/lan_cowork/api/settings/fleet";
    #[tokio::test]
    async fn get_returns_defaults_when_unconfigured() {
        let tmp = tempfile::tempdir().unwrap();
        let response = request(
            routes().with_state(LanCoworkState::from_shared(
                &test_state(tmp.path().join("config.json")).await,
            )),
            "GET",
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(
            value,
            json!({"ok":true,"protect_heartbeat":true,"protect_events":true,"allowed_cidr":24})
        );
    }
    #[tokio::test]
    async fn post_all_none_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let response = request(
            routes().with_state(LanCoworkState::from_shared(
                &test_state(tmp.path().join("config.json")).await,
            )),
            "POST",
            "{}",
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["code"], "validation_error");
    }
    #[tokio::test]
    async fn post_partial_update_then_get_reflects_it() {
        let tmp = tempfile::tempdir().unwrap();
        let app = routes().with_state(LanCoworkState::from_shared(
            &test_state(tmp.path().join("config.json")).await,
        ));
        assert_eq!(
            request(
                app.clone(),
                "POST",
                r#"{"allowed_cidr":16}"#,
                Some("application/json")
            )
            .await
            .status(),
            StatusCode::OK
        );
        let value = json_body(request(app, "GET", "", None).await).await;
        assert_eq!(value["allowed_cidr"], 16);
        assert_eq!(value["protect_heartbeat"], true);
    }
    #[tokio::test]
    async fn post_out_of_range_cidr_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            request(
                routes().with_state(LanCoworkState::from_shared(
                    &test_state(tmp.path().join("config.json")).await
                )),
                "POST",
                r#"{"allowed_cidr":7}"#,
                Some("application/json")
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    #[tokio::test]
    async fn post_unknown_field_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let response = request(
            routes().with_state(LanCoworkState::from_shared(
                &test_state(tmp.path().join("config.json")).await,
            )),
            "POST",
            r#"{"bogus_field":true}"#,
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["code"], "validation_error");
    }
    #[tokio::test]
    async fn post_malformed_json_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let response = request(
            routes().with_state(LanCoworkState::from_shared(
                &test_state(tmp.path().join("config.json")).await,
            )),
            "POST",
            "{not json",
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["code"], "invalid_json");
    }
    #[tokio::test]
    async fn post_wrong_content_type_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let response = request(
            routes().with_state(LanCoworkState::from_shared(
                &test_state(tmp.path().join("config.json")).await,
            )),
            "POST",
            r#"{"allowed_cidr":16}"#,
            Some("text/plain"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["code"], "invalid_content_type");
    }
    #[tokio::test]
    async fn post_json_array_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let response = request(
            routes().with_state(LanCoworkState::from_shared(
                &test_state(tmp.path().join("config.json")).await,
            )),
            "POST",
            "[1,2,3]",
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["code"], "invalid_json_object");
    }
    #[tokio::test]
    async fn requires_session_when_pin_auth_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path().join("config.json")).await;
        Arc::get_mut(&mut state).unwrap().config.pin_auth_enabled = true;
        assert_eq!(
            request(
                routes().with_state(LanCoworkState::from_shared(&state)),
                "GET",
                "",
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn normalize_allowlist_dedups_across_string_and_object_forms() {
        let input = vec![
            json!("peer-a"),
            json!({"peer_id": "peer-a"}),
            json!("  peer-b  "),
            json!({"peer_id": "peer-b"}),
            json!({"role": "chief"}),
            json!(123),
            json!("   "),
        ];
        let result = normalize_allowlist(&input);
        assert_eq!(result, vec!["peer-a".to_string(), "peer-b".to_string()]);
    }

    #[test]
    fn normalize_allowlist_preserves_first_seen_order() {
        let input = vec![json!("c"), json!("a"), json!("b"), json!("a")];
        let result = normalize_allowlist(&input);
        assert_eq!(
            result,
            vec!["c".to_string(), "a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn normalize_allowlist_empty_for_non_string_non_object() {
        let input = vec![json!(null), json!([1, 2]), json!(true)];
        assert!(normalize_allowlist(&input).is_empty());
    }

    #[tokio::test]
    async fn notify_fleet_allowlists_changed_returns_true_when_python_url_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        assert!(notify_fleet_allowlists_changed(&*state).await);
    }

    #[tokio::test]
    async fn notify_fleet_allowlists_changed_returns_true_on_2xx() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = Router::new().route(
            "/_internal/lan_cowork/fleet-allowlists-changed",
            axum::routing::post(|| async { StatusCode::OK }),
        );
        tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });

        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path().join("config.json")).await;
        Arc::get_mut(&mut state).unwrap().config.python_url = format!("http://{addr}");
        assert!(notify_fleet_allowlists_changed(&*state).await);
    }

    #[tokio::test]
    async fn notify_fleet_allowlists_changed_returns_false_on_unreachable() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path().join("config.json")).await;
        Arc::get_mut(&mut state).unwrap().config.python_url = "http://127.0.0.1:1".to_string();
        assert!(!notify_fleet_allowlists_changed(&*state).await);
    }

    #[tokio::test]
    async fn notify_fleet_allowlists_changed_returns_false_on_5xx() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = Router::new().route(
            "/_internal/lan_cowork/fleet-allowlists-changed",
            axum::routing::post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        );
        tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });

        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path().join("config.json")).await;
        Arc::get_mut(&mut state).unwrap().config.python_url = format!("http://{addr}");
        assert!(!notify_fleet_allowlists_changed(&*state).await);
    }

    #[tokio::test]
    async fn notify_fleet_chief_changed_returns_true_when_python_url_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        assert!(notify_fleet_chief_changed(&*state).await);
    }

    #[tokio::test]
    async fn notify_fleet_chief_changed_returns_true_on_2xx() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = Router::new().route(
            "/_internal/lan_cowork/fleet-chief-changed",
            axum::routing::post(|| async { StatusCode::OK }),
        );
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path().join("config.json")).await;
        Arc::get_mut(&mut state).unwrap().config.python_url = format!("http://{addr}");
        assert!(notify_fleet_chief_changed(&*state).await);
    }

    #[tokio::test]
    async fn notify_fleet_chief_changed_returns_false_on_unreachable() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path().join("config.json")).await;
        Arc::get_mut(&mut state).unwrap().config.python_url = "http://127.0.0.1:1".to_string();
        assert!(!notify_fleet_chief_changed(&*state).await);
    }

    #[tokio::test]
    async fn notify_fleet_chief_changed_returns_false_on_5xx() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = Router::new().route(
            "/_internal/lan_cowork/fleet-chief-changed",
            axum::routing::post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        );
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path().join("config.json")).await;
        Arc::get_mut(&mut state).unwrap().config.python_url = format!("http://{addr}");
        assert!(!notify_fleet_chief_changed(&*state).await);
    }

    #[tokio::test]
    async fn fleet_settings_get_returns_default_false_when_unconfigured() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "GET",
            FLEET_SETTINGS_PATH,
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await,
            json!({"ok": true, "chief": false})
        );
    }

    #[tokio::test]
    async fn fleet_settings_requires_session_when_pin_auth_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path().join("config.json")).await;
        Arc::get_mut(&mut state).unwrap().config.pin_auth_enabled = true;
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "GET",
            FLEET_SETTINGS_PATH,
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn fleet_settings_post_unknown_field_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            FLEET_SETTINGS_PATH,
            r#"{"chief":true,"unknown":1}"#,
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["code"], "validation_error");
    }

    #[tokio::test]
    async fn fleet_settings_post_missing_chief_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            FLEET_SETTINGS_PATH,
            "{}",
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn fleet_settings_post_non_bool_chief_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            FLEET_SETTINGS_PATH,
            r#"{"chief":"true"}"#,
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn fleet_settings_post_then_get_reflects_it() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        let response = request_at(
            app.clone(),
            "POST",
            FLEET_SETTINGS_PATH,
            r#"{"chief":true}"#,
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await,
            json!({"ok": true, "chief": true, "live_sync": true})
        );
        assert_eq!(
            json_body(request_at(app, "GET", FLEET_SETTINGS_PATH, "", None).await).await,
            json!({"ok": true, "chief": true})
        );
    }

    #[tokio::test]
    async fn fleet_settings_toggle_stops_and_restarts_polling() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        crate::schema::apply_standalone_schema(&state.db)
            .await
            .unwrap();
        let lc = LanCoworkState::from_shared(&state);
        lc.peer_registry
            .set(Arc::new(
                crate::routes::lan_cowork_registry::PeerRegistry::new(
                    state.db.clone(),
                    std::time::Duration::from_secs(30),
                    "local".to_owned(),
                ),
            ))
            .ok();
        let app = routes().with_state(lc.clone());

        assert_eq!(
            request_at(
                app.clone(),
                "POST",
                FLEET_SETTINGS_PATH,
                r#"{"chief":true}"#,
                Some("application/json"),
            )
            .await
            .status(),
            StatusCode::OK
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while lc.fleet_manager.test_poll_ticks() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(lc.fleet_manager.is_running().await);

        assert_eq!(
            request_at(
                app.clone(),
                "POST",
                FLEET_SETTINGS_PATH,
                r#"{"chief":false}"#,
                Some("application/json"),
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert!(!lc.fleet_manager.is_running().await);
        let stopped_ticks = lc.fleet_manager.test_poll_ticks();

        assert_eq!(
            request_at(
                app,
                "POST",
                FLEET_SETTINGS_PATH,
                r#"{"chief":true}"#,
                Some("application/json"),
            )
            .await
            .status(),
            StatusCode::OK
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while lc.fleet_manager.test_poll_ticks() <= stopped_ticks {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        lc.fleet_manager.stop().await;
    }

    #[tokio::test]
    async fn fleet_settings_post_preserves_sibling_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        request_at(
            app.clone(),
            "POST",
            FLEET_ALLOWLISTS_PATH,
            r#"{"allow_update_from":["1.2.3.4"]}"#,
            Some("application/json"),
        )
        .await;
        let response = request_at(
            app,
            "POST",
            FLEET_SETTINGS_PATH,
            r#"{"chief":true}"#,
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let fleet = ext_config(&load_config_json(&state.config.config_path))["fleet"].clone();
        assert_eq!(fleet["chief"], true);
        assert_eq!(fleet["allow_update_from"][0], "1.2.3.4");
    }

    #[tokio::test]
    async fn fleet_allowlists_get_returns_defaults_when_unconfigured() {
        let tmp = tempfile::tempdir().unwrap();
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(
                &test_state(tmp.path().join("config.json")).await,
            )),
            "GET",
            FLEET_ALLOWLISTS_PATH,
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(
            value,
            json!({"ok":true,"allow_log_stream_from":[],"allow_update_from":[],"allow_restart_from":[],"allow_remote_update":true})
        );
    }

    #[tokio::test]
    async fn fleet_allowlists_post_all_none_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(
                &test_state(tmp.path().join("config.json")).await,
            )),
            "POST",
            FLEET_ALLOWLISTS_PATH,
            "{}",
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["code"], "validation_error");
    }

    #[tokio::test]
    async fn fleet_allowlists_post_mixed_array_normalizes() {
        let tmp = tempfile::tempdir().unwrap();
        let app = routes().with_state(LanCoworkState::from_shared(
            &test_state(tmp.path().join("config.json")).await,
        ));
        let response = request_at(
            app.clone(),
            "POST",
            FLEET_ALLOWLISTS_PATH,
            r#"{"allow_update_from": ["a", {"peer_id": "b"}, "a"]}"#,
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(value["allow_update_from"], json!(["a", "b"]));

        let value = json_body(request_at(app, "GET", FLEET_ALLOWLISTS_PATH, "", None).await).await;
        assert_eq!(value["allow_update_from"], json!(["a", "b"]));
    }

    #[tokio::test]
    async fn fleet_allowlists_post_preserves_untouched_sibling_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        let seed = json!({
            "extensions": {
                "builtin-lan-cowork": {
                    "fleet": {"chief": true, "allow_restart_from": ["z"]}
                }
            }
        });
        std::fs::write(&config_path, serde_json::to_string(&seed).unwrap()).unwrap();
        let app = routes().with_state(LanCoworkState::from_shared(
            &test_state(config_path.clone()).await,
        ));
        let response = request_at(
            app,
            "POST",
            FLEET_ALLOWLISTS_PATH,
            r#"{"allow_update_from": ["a"]}"#,
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let on_disk: Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let fleet = &on_disk["extensions"]["builtin-lan-cowork"]["fleet"];
        assert_eq!(fleet["chief"], true);
        assert_eq!(fleet["allow_restart_from"], json!(["z"]));
        assert_eq!(fleet["allow_update_from"], json!(["a"]));
    }

    #[tokio::test]
    async fn fleet_allowlists_post_preserves_peer_auth_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        let app = routes().with_state(LanCoworkState::from_shared(
            &test_state(config_path.clone()).await,
        ));
        assert_eq!(
            request_at(
                app.clone(),
                "POST",
                "/ext/lan_cowork/api/settings/peer-auth",
                r#"{"allowed_cidr":16}"#,
                Some("application/json"),
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            request_at(
                app.clone(),
                "POST",
                FLEET_ALLOWLISTS_PATH,
                r#"{"allow_update_from": ["a"]}"#,
                Some("application/json"),
            )
            .await
            .status(),
            StatusCode::OK
        );
        let value = json_body(
            request_at(
                app,
                "GET",
                "/ext/lan_cowork/api/settings/peer-auth",
                "",
                None,
            )
            .await,
        )
        .await;
        assert_eq!(value["allowed_cidr"], 16);
    }

    #[tokio::test]
    async fn fleet_allowlists_post_over_256_elements_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let entries: Vec<String> = (0..257).map(|i| format!("\"p{i}\"")).collect();
        let body = format!(r#"{{"allow_update_from": [{}]}}"#, entries.join(","));
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(
                &test_state(tmp.path().join("config.json")).await,
            )),
            "POST",
            FLEET_ALLOWLISTS_PATH,
            &body,
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn fleet_allowlists_post_unknown_field_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(
                &test_state(tmp.path().join("config.json")).await,
            )),
            "POST",
            FLEET_ALLOWLISTS_PATH,
            r#"{"bogus_field": true}"#,
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["code"], "validation_error");
    }

    #[tokio::test]
    async fn fleet_allowlists_requires_session_when_pin_auth_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path().join("config.json")).await;
        Arc::get_mut(&mut state).unwrap().config.pin_auth_enabled = true;
        assert_eq!(
            request_at(
                routes().with_state(LanCoworkState::from_shared(&state)),
                "GET",
                FLEET_ALLOWLISTS_PATH,
                "",
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn fleet_allowlists_post_shrink_returns_502_when_notify_unreachable() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        let seed = json!({
            "extensions": {
                "builtin-lan-cowork": {"fleet": {"allow_update_from": ["a"]}}
            }
        });
        std::fs::write(&config_path, serde_json::to_string(&seed).unwrap()).unwrap();
        let mut state = test_state(config_path).await;
        Arc::get_mut(&mut state).unwrap().config.python_url = "http://127.0.0.1:1".to_string();
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            FLEET_ALLOWLISTS_PATH,
            r#"{"allow_update_from": []}"#,
            Some("application/json"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(json_body(response).await["code"], "live_sync_failed");
    }

    async fn insert_token(
        state: &SharedState,
        peer_id: &str,
        issued_at: i64,
        expires_at: i64,
        revoked_at: Option<i64>,
        source: &str,
        note: Option<&str>,
    ) {
        sqlx::query("INSERT INTO peer_tokens (peer_id, token_hash, issued_at, expires_at, revoked_at, source, note) VALUES (?1, 'dummy_hash', ?2, ?3, ?4, ?5, ?6)")
            .bind(peer_id).bind(issued_at).bind(expires_at).bind(revoked_at).bind(source).bind(note).execute(&state.db).await.unwrap();
    }
    async fn insert_peer_with_token(state: &SharedState, peer_id: &str) {
        sqlx::query("INSERT INTO peers (peer_id, name, api_host, api_port, token, token_expires_at, token_issued_at, created_at, updated_at) VALUES (?1, 'test', '127.0.0.1', 5000, 'outbound_token', 99999999999, 1, 100, 100)")
            .bind(peer_id).execute(&state.db).await.unwrap();
    }

    #[tokio::test]
    async fn tokens_get_returns_empty_when_unconfigured() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_token_tables(&state).await;
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "GET",
            "/ext/lan_cowork/api/peer/tokens",
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await, json!({"ok": true, "tokens": []}));
    }
    #[tokio::test]
    async fn tokens_get_excludes_revoked_and_expired() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_token_tables(&state).await;
        let now = 1_000_000_000_i64;
        insert_token(
            &state,
            "active",
            now - 100,
            99999999999,
            None,
            "pairing",
            None,
        )
        .await;
        insert_token(
            &state,
            "revoked",
            now - 100,
            now + 1000,
            Some(now),
            "pairing",
            None,
        )
        .await;
        insert_token(
            &state,
            "expired",
            now - 2000,
            now - 1000,
            None,
            "pairing",
            None,
        )
        .await;
        let value = json_body(
            request_at(
                routes().with_state(LanCoworkState::from_shared(&state)),
                "GET",
                "/ext/lan_cowork/api/peer/tokens",
                "",
                None,
            )
            .await,
        )
        .await;
        let tokens = value["tokens"].as_array().unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0]["peer_id"], "active");
    }
    #[tokio::test]
    async fn tokens_get_note_null_key_present_source_not_null() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_token_tables(&state).await;
        insert_token(&state, "p1", 100, 99999999999, None, "pairing", None).await;
        let value = json_body(
            request_at(
                routes().with_state(LanCoworkState::from_shared(&state)),
                "GET",
                "/ext/lan_cowork/api/peer/tokens",
                "",
                None,
            )
            .await,
        )
        .await;
        let token = &value["tokens"][0];
        assert!(token.as_object().unwrap().contains_key("note"));
        assert!(token["note"].is_null());
        assert_eq!(token["source"], "pairing");
        assert!(token.get("token_hash").is_none());
        assert!(token.get("revoked_at").is_none());
    }
    #[tokio::test]
    async fn tokens_get_ordered_by_issued_at_desc() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_token_tables(&state).await;
        insert_token(&state, "older", 100, 99999999999, None, "pairing", None).await;
        insert_token(&state, "newer", 200, 99999999999, None, "pairing", None).await;
        let value = json_body(
            request_at(
                routes().with_state(LanCoworkState::from_shared(&state)),
                "GET",
                "/ext/lan_cowork/api/peer/tokens",
                "",
                None,
            )
            .await,
        )
        .await;
        let tokens = value["tokens"].as_array().unwrap();
        assert_eq!(tokens[0]["peer_id"], "newer");
        assert_eq!(tokens[1]["peer_id"], "older");
    }
    #[tokio::test]
    async fn tokens_revoke_sets_revoked_at_and_clears_peers_token() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_token_tables(&state).await;
        insert_token(&state, "p1", 100, 99999999999, None, "pairing", None).await;
        insert_peer_with_token(&state, "p1").await;
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        let response = request_at(
            app.clone(),
            "POST",
            "/ext/lan_cowork/api/peer/tokens/p1/revoke",
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let value =
            json_body(request_at(app, "GET", "/ext/lan_cowork/api/peer/tokens", "", None).await)
                .await;
        assert_eq!(value["tokens"].as_array().unwrap().len(), 0);
        let peer_row: (Option<String>,) =
            sqlx::query_as("SELECT token FROM peers WHERE peer_id = 'p1'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(peer_row.0, None);
    }
    #[tokio::test]
    async fn tokens_revoke_nonexistent_peer_returns_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_token_tables(&state).await;
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            "/ext/lan_cowork/api/peer/tokens/nonexistent/revoke",
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    #[tokio::test]
    async fn tokens_revoke_twice_preserves_first_revoked_at() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_token_tables(&state).await;
        insert_token(&state, "p1", 100, 99999999999, None, "pairing", None).await;
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        request_at(
            app.clone(),
            "POST",
            "/ext/lan_cowork/api/peer/tokens/p1/revoke",
            "",
            None,
        )
        .await;
        let first: (Option<i64>,) =
            sqlx::query_as("SELECT revoked_at FROM peer_tokens WHERE peer_id = 'p1'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        request_at(
            app,
            "POST",
            "/ext/lan_cowork/api/peer/tokens/p1/revoke",
            "",
            None,
        )
        .await;
        let second: (Option<i64>,) =
            sqlx::query_as("SELECT revoked_at FROM peer_tokens WHERE peer_id = 'p1'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(first.0, second.0);
    }
    #[tokio::test]
    async fn tokens_revoke_emits_sse_event() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_token_tables(&state).await;
        insert_token(&state, "p1", 100, 99999999999, None, "pairing", None).await;
        let mut rx = state.sse_hub.subscribe();
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            "/ext/lan_cowork/api/peer/tokens/p1/revoke",
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let event = rx.try_recv().expect("sse event should be sent");
        assert_eq!(event.event_type, "peer.token_revoked");
        assert_eq!(event.data["peer_id"], "p1");
    }
    #[tokio::test]
    async fn tokens_requires_session_when_pin_auth_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path().join("config.json")).await;
        seed_token_tables(&state).await;
        Arc::get_mut(&mut state).unwrap().config.pin_auth_enabled = true;
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "GET",
            "/ext/lan_cowork/api/peer/tokens",
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    #[tokio::test]
    async fn tokens_get_db_error_returns_generic_message() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "GET",
            "/ext/lan_cowork/api/peer/tokens",
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let value = json_body(response).await;
        assert_eq!(value["ok"], false);
        assert_eq!(value["code"], "db_error");
        let message = value["error"].as_str().unwrap();
        assert!(
            !message.to_lowercase().contains("sql")
                && !message.to_lowercase().contains("sqlite")
                && !message.contains("peer_tokens"),
            "error message must not leak raw sqlx/sqlite details: {message}"
        );
    }

    // ── Increment 1a: revoke → registry notify helper ────────────────────────
    #[tokio::test]
    async fn notify_registry_peer_changed_returns_true_when_python_url_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        assert!(notify_registry_peer_changed(&*state, "peer1", "token_cleared").await);
    }

    #[tokio::test]
    async fn notify_registry_peer_changed_returns_false_on_unreachable() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path().join("config.json")).await;
        Arc::get_mut(&mut state).unwrap().config.python_url = "http://127.0.0.1:1".to_string();
        assert!(!notify_registry_peer_changed(&*state, "peer1", "removed").await);
    }

    // ── Increment 1b: peer_admin_delete ──────────────────────────────────────
    const PEER_ADMIN_PATH: &str = "/ext/lan_cowork/api/peer/admin/";

    async fn seed_identity(state: &SharedState, seed: &[u8]) {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS lan_cowork_identity (key TEXT PRIMARY KEY, value BLOB);",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO lan_cowork_identity (key, value) VALUES ('ed25519_seed', ?1)")
            .bind(seed)
            .execute(&state.db)
            .await
            .unwrap();
    }

    async fn peer_row_count(state: &SharedState, peer_id: &str) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM peers WHERE peer_id = ?1")
            .bind(peer_id)
            .fetch_one(&state.db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn peer_admin_delete_standalone_removes_row_and_allowlist() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        let seed = json!({
            "extensions": {
                "builtin-lan-cowork": {"fleet": {
                    "allow_update_from": ["victim", "keep"],
                    "allow_restart_from": ["victim"]
                }}
            }
        });
        std::fs::write(&config_path, serde_json::to_string(&seed).unwrap()).unwrap();
        let state = test_state(config_path.clone()).await;
        seed_token_tables(&state).await;
        insert_peer_with_token(&state, "victim").await;
        insert_peer_with_token(&state, "keep").await;

        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "DELETE",
            &format!("{PEER_ADMIN_PATH}victim"),
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["ok"], true);

        assert_eq!(peer_row_count(&state, "victim").await, 0);
        assert_eq!(peer_row_count(&state, "keep").await, 1);

        let cfg: Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let fleet = &cfg["extensions"]["builtin-lan-cowork"]["fleet"];
        assert_eq!(fleet["allow_update_from"], json!(["keep"]));
        assert_eq!(fleet["allow_restart_from"], json!([]));
    }

    #[tokio::test]
    async fn peer_admin_delete_rejects_self() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_token_tables(&state).await;
        let seed = [7u8; 32];
        seed_identity(&state, &seed).await;
        let self_id = crate::routes::peer_identity::derive_peer_id_from_seed(&seed).unwrap();

        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "DELETE",
            &format!("{PEER_ADMIN_PATH}{self_id}"),
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["code"], "cannot_remove_self");
    }

    #[tokio::test]
    async fn peer_admin_delete_proceeds_when_no_local_identity() {
        // No lan_cowork_identity table/seed → local_peer_id None → deletion proceeds.
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_token_tables(&state).await;
        insert_peer_with_token(&state, "somepeer").await;

        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "DELETE",
            &format!("{PEER_ADMIN_PATH}somepeer"),
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(peer_row_count(&state, "somepeer").await, 0);
    }

    #[tokio::test]
    async fn peer_admin_delete_idempotent_for_absent_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_token_tables(&state).await;

        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "DELETE",
            &format!("{PEER_ADMIN_PATH}ghost"),
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["ok"], true);
    }

    #[tokio::test]
    async fn peer_admin_delete_requires_session_when_pin_auth_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path().join("config.json")).await;
        Arc::get_mut(&mut state).unwrap().config.pin_auth_enabled = true;
        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "DELETE",
            &format!("{PEER_ADMIN_PATH}anyone"),
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn peer_admin_delete_hybrid_returns_502_when_notify_unreachable() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        let state = test_state(config_path).await;
        seed_token_tables(&state).await;
        insert_peer_with_token(&state, "victim").await;
        let mut state = state;
        Arc::get_mut(&mut state).unwrap().config.python_url = "http://127.0.0.1:1".to_string();

        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "DELETE",
            &format!("{PEER_ADMIN_PATH}victim"),
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(json_body(response).await["code"], "live_sync_failed");
        // Hybrid must NOT delete the peers row itself (discovery would resurrect it).
        assert_eq!(peer_row_count(&state, "victim").await, 1);
    }

    #[tokio::test]
    async fn peer_admin_delete_hybrid_502_still_persists_allowlist_removal() {
        // M2: the allowlist removal is persisted to config.json BEFORE the notify
        // and is never rolled back, even when the delete returns 502.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        let seed = json!({
            "extensions": {
                "builtin-lan-cowork": {"fleet": {"allow_update_from": ["victim", "keep"]}}
            }
        });
        std::fs::write(&config_path, serde_json::to_string(&seed).unwrap()).unwrap();
        let state = test_state(config_path.clone()).await;
        seed_token_tables(&state).await;
        insert_peer_with_token(&state, "victim").await;
        let mut state = state;
        Arc::get_mut(&mut state).unwrap().config.python_url = "http://127.0.0.1:1".to_string();

        let response = request_at(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "DELETE",
            &format!("{PEER_ADMIN_PATH}victim"),
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        // Allowlist removal is persisted despite the 502...
        let cfg: Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(
            cfg["extensions"]["builtin-lan-cowork"]["fleet"]["allow_update_from"],
            json!(["keep"])
        );
        // ...and the peers row is untouched (hybrid delegates row deletion to Python).
        assert_eq!(peer_row_count(&state, "victim").await, 1);
    }

    // ── Increment A: peer-authenticated self delete ──────────────────────────
    fn b64url(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE.encode(bytes)
    }

    fn now_secs_i64() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    async fn seed_transport_tables(state: &SharedState) {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS peers (
               peer_id TEXT PRIMARY KEY, pubkey BLOB, created_at INTEGER, updated_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS peer_tokens (
               peer_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, issued_at INTEGER,
               expires_at INTEGER, revoked_at INTEGER, source TEXT
             );",
        )
        .execute(&state.db)
        .await
        .unwrap();
    }

    /// Insert a paired peer (peer_id derived from the seed) plus a live token.
    /// Returns (peer_id, seed).
    async fn insert_paired_peer(state: &SharedState, token_raw: &str) -> (String, Vec<u8>) {
        use openssl::pkey::{Id, PKey};
        let seed: Vec<u8> = (1u8..=32).collect();
        let pk = PKey::private_key_from_raw_bytes(&seed, Id::ED25519).unwrap();
        let pubkey = pk.raw_public_key().unwrap();
        let peer_id = crate::routes::peer_identity::derive_peer_id_from_seed(&seed).unwrap();
        sqlx::query(
            "INSERT INTO peers (peer_id, pubkey, created_at, updated_at) VALUES (?1, ?2, 100, 100)",
        )
        .bind(&peer_id)
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .unwrap();
        let hash = crate::auth::peer_transport::hash_token(token_raw);
        sqlx::query("INSERT INTO peer_tokens (peer_id, token_hash, issued_at, expires_at, revoked_at, source) VALUES (?1, ?2, 100, ?3, NULL, 'pairing')")
            .bind(&peer_id)
            .bind(&hash)
            .bind(now_secs_i64() + 86_400)
            .execute(&state.db)
            .await
            .unwrap();
        (peer_id, seed)
    }

    /// Build signed peer-transport headers for `DELETE <path>` (empty body).
    fn signed_delete_headers(
        seed: &[u8],
        peer_id: &str,
        path: &str,
        token: &str,
    ) -> Vec<(String, String)> {
        use openssl::pkey::{Id, PKey};
        let ts = now_secs_i64().to_string();
        let canonical =
            crate::auth::peer_transport::build_canonical_message("DELETE", path, "", &ts, b"");
        let pk = PKey::private_key_from_raw_bytes(seed, Id::ED25519).unwrap();
        let mut signer = openssl::sign::Signer::new_without_digest(&pk).unwrap();
        let sig = signer.sign_oneshot_to_vec(&canonical).unwrap();
        vec![
            ("X-Peer-Id".into(), peer_id.into()),
            ("X-Peer-Ts".into(), ts),
            ("X-Peer-Sig".into(), b64url(&sig)),
            ("Authorization".into(), format!("Bearer {token}")),
        ]
    }

    async fn delete_with_headers(
        app: Router,
        path: &str,
        headers: Vec<(String, String)>,
    ) -> Response {
        let mut b = axum::http::Request::builder().method("DELETE").uri(path);
        for (k, v) in headers {
            b = b.header(k, v);
        }
        app.oneshot(b.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn peer_self_delete_standalone_removes_own_row() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_transport_tables(&state).await;
        let (peer_id, seed) = insert_paired_peer(&state, "tok-secret").await;
        let path = format!("/ext/lan_cowork/api/peer/{peer_id}");
        let headers = signed_delete_headers(&seed, &peer_id, &path, "tok-secret");

        let response = delete_with_headers(
            routes().with_state(LanCoworkState::from_shared(&state)),
            &path,
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["ok"], true);
        assert_eq!(peer_row_count(&state, &peer_id).await, 0);
    }

    #[tokio::test]
    async fn peer_self_delete_rejects_other_peer() {
        // Authenticated as peer A, but the path targets peer B → 403 (MF-7).
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_transport_tables(&state).await;
        let (peer_id_a, seed) = insert_paired_peer(&state, "tok-secret").await;
        let other = "some_other_peer_id";
        let path = format!("/ext/lan_cowork/api/peer/{other}");
        // A signs the request for the B path (valid signature, wrong target).
        let headers = signed_delete_headers(&seed, &peer_id_a, &path, "tok-secret");

        let response = delete_with_headers(
            routes().with_state(LanCoworkState::from_shared(&state)),
            &path,
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(response).await["code"], "forbidden");
    }

    #[tokio::test]
    async fn peer_self_delete_rejects_bad_token() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_transport_tables(&state).await;
        let (peer_id, seed) = insert_paired_peer(&state, "tok-secret").await;
        let path = format!("/ext/lan_cowork/api/peer/{peer_id}");
        // Valid signature, wrong bearer token → 401.
        let headers = signed_delete_headers(&seed, &peer_id, &path, "wrong-token");

        let response = delete_with_headers(
            routes().with_state(LanCoworkState::from_shared(&state)),
            &path,
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(peer_row_count(&state, &peer_id).await, 1);
    }

    #[tokio::test]
    async fn peer_self_delete_rejects_unknown_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_transport_tables(&state).await;
        let path = "/ext/lan_cowork/api/peer/ghostpeer";
        let headers = vec![
            ("X-Peer-Id".to_string(), "ghostpeer".to_string()),
            ("X-Peer-Ts".to_string(), now_secs_i64().to_string()),
            ("X-Peer-Sig".to_string(), "AAAA".to_string()),
            ("Authorization".to_string(), "Bearer x".to_string()),
        ];
        let response = delete_with_headers(
            routes().with_state(LanCoworkState::from_shared(&state)),
            path,
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn peer_self_delete_hybrid_returns_502_when_notify_unreachable() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().join("config.json")).await;
        seed_transport_tables(&state).await;
        let (peer_id, seed) = insert_paired_peer(&state, "tok-secret").await;
        let mut state = state;
        Arc::get_mut(&mut state).unwrap().config.python_url = "http://127.0.0.1:1".to_string();
        let path = format!("/ext/lan_cowork/api/peer/{peer_id}");
        let headers = signed_delete_headers(&seed, &peer_id, &path, "tok-secret");

        let response = delete_with_headers(
            routes().with_state(LanCoworkState::from_shared(&state)),
            &path,
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(json_body(response).await["code"], "live_sync_failed");
        // Hybrid must not delete the peers row itself (discovery would revive it).
        assert_eq!(peer_row_count(&state, &peer_id).await, 1);
    }
}
