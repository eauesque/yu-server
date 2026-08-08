//! Miscellaneous admin routes.

use axum::{
    extract::{Extension, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use std::time::{SystemTime, UNIX_EPOCH};
use std::{path::Path as FsPath, sync::OnceLock};
use tokio::sync::Mutex as TokioMutex;

use crate::{
    auth::{client_ip::ClientIp, scope::require_admin_scope, AuthContext},
    routes::{
        settings::{
            load_config_json as load_cfg, validate_base_url, write_config_json as write_cfg,
        },
        update_status::detect_install_type,
    },
    security::CspNonce,
    state::SharedState,
};

struct UpdateCache {
    data: Option<(u64, serde_json::Value)>,
}
static CHECK_CACHE: OnceLock<TokioMutex<UpdateCache>> = OnceLock::new();
static UNIFIED_CACHE: OnceLock<TokioMutex<UpdateCache>> = OnceLock::new();
static AI_CONTEXT_VERSION: OnceLock<String> = OnceLock::new();

const SETTINGS_SCHEMA_JSON: &str = include_str!("../../../../config/settings_schema.json");
const WD_TAGGER_MANIFEST_JSON: &str =
    include_str!("../../../../extensions/builtin_wd_tagger/extension.json");
const CSRF_NOTE: &str = "POST/PUT/PATCH/DELETE リクエストには X-Requested-With: XMLHttpRequest ヘッダが必要。Bearer API Key 認証時は不要。安全メソッド (GET, HEAD, OPTIONS) は CSRF チェック対象外。除外パスプレフィックス: /api/events/, /api/webhooks/receive/, /v1/。/ext/<name>/v1/* も除外（^/ext/[A-Za-z0-9][\\w\\-]*/v1/）。";

fn parse_version(v: &str) -> Vec<u64> {
    v.trim_start_matches('v')
        .split('.')
        .map(|s| s.parse::<u64>().unwrap_or(0))
        .collect()
}

async fn fetch_update_check(s: &SharedState) -> serde_json::Value {
    let current = tokio::fs::read_to_string(s.config.project_root.join("VERSION"))
        .await
        .unwrap_or_else(|_| "0.0.0\n".to_string());
    let current = current.trim().to_string();
    let install_type = detect_install_type(&s.config.project_root);
    let mut result = json!({
        "current": current,
        "latest": current,
        "update_available": false,
        "release_url": "",
        "release_notes": "",
        "published_at": "",
        "install_type": install_type,
    });
    let url = "https://api.github.com/repos/eauesque/yu_ai_manager/releases/latest";
    match s
        .python_client
        .get(url)
        .header("User-Agent", format!("YU-AI-Manager/{}", current))
        .header("Accept", "application/vnd.github+json")
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(data) => {
                let latest = data["tag_name"].as_str().unwrap_or("").to_string();
                result["update_available"] =
                    json!(parse_version(&latest) > parse_version(&current));
                result["latest"] = json!(latest);
                result["release_url"] = json!(data["html_url"].as_str().unwrap_or(""));
                result["release_notes"] = json!(data["body"].as_str().unwrap_or(""));
                result["published_at"] = json!(data["published_at"].as_str().unwrap_or(""));
            }
            Err(e) => {
                result["error"] = json!(e.to_string());
            }
        },
        Ok(resp) => {
            result["error"] = json!(format!("HTTP {}", resp.status()));
        }
        Err(e) => {
            result["error"] = json!(e.to_string());
        }
    }
    result
}

fn gate(state: &SharedState, auth: Option<&Extension<AuthContext>>) -> Option<Response> {
    require_admin_scope(state.config.pin_auth_enabled, auth.map(|c| &c.0))
}

fn read_version_cached<'a>(cache: &'a OnceLock<String>, project_root: &FsPath) -> &'a str {
    cache
        .get_or_init(|| {
            std::fs::read_to_string(project_root.join("VERSION"))
                .map(|version| version.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        })
        .as_str()
}

fn json_truthy(value: Option<&serde_json::Value>) -> bool {
    match value {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(value)) => *value,
        Some(serde_json::Value::Number(value)) => value.as_f64() != Some(0.0),
        Some(serde_json::Value::String(value)) => !value.is_empty(),
        Some(serde_json::Value::Array(value)) => !value.is_empty(),
        Some(serde_json::Value::Object(value)) => !value.is_empty(),
    }
}

fn resolve_dotted_key<'a>(
    config: &'a serde_json::Value,
    key: &str,
) -> Option<&'a serde_json::Value> {
    key.split('.')
        .try_fold(config, |value, part| value.get(part))
}

fn get_config_hints(config: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut hints = Vec::new();
    let server = config.get("server");
    if json_truthy(server.and_then(|value| value.get("lan")))
        && !json_truthy(server.and_then(|value| value.get("pin")))
    {
        hints.push(json!({
            "key": "server.pin",
            "severity": "warning",
            "message": "PIN 未設定で LAN アクセスが有効です。PIN を設定することを推奨します",
        }));
    }

    let ai = config.get("ai_analysis");
    if !json_truthy(ai.and_then(|value| value.get("api_key"))) {
        hints.push(json!({
            "key": "ai_analysis.api_key",
            "severity": "info",
            "message": "Claude API キー未設定。AI 分析機能が無効になっています",
        }));
    }

    let schema: serde_json::Value = serde_json::from_str(SETTINGS_SCHEMA_JSON).unwrap_or_default();
    for setting in schema.as_array().into_iter().flatten() {
        let key = setting["key"].as_str().unwrap_or("");
        if !setting["secret"].as_bool().unwrap_or(false)
            || !setting["default"].is_null()
            || matches!(key, "server.pin" | "ai_analysis.api_key")
        {
            continue;
        }
        let value = resolve_dotted_key(config, key);
        if value.is_none()
            || value == Some(&serde_json::Value::Null)
            || value
                .and_then(serde_json::Value::as_str)
                .is_some_and(|s| s.trim().is_empty())
        {
            hints.push(json!({
                "key": key,
                "severity": "info",
                "message": format!(
                    "未設定のシークレット項目（ヒューリスティック）: {}",
                    setting["description"].as_str().unwrap_or("")
                ),
            }));
        }
    }
    hints
}

fn capabilities(config: &serde_json::Value, native_daemon: bool) -> Vec<&'static str> {
    let mut capabilities = vec!["llm_router"];
    if native_daemon {
        capabilities.push("lan_cowork");
    }
    let hailo = config.get("hailo_tagger");
    if hailo
        .and_then(|value| value.get("enabled"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        && hailo
            .and_then(|value| value.get("endpoint_url"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|url| !url.trim().is_empty())
    {
        capabilities.push("hailo");
    }
    let wd_default = serde_json::from_str::<serde_json::Value>(WD_TAGGER_MANIFEST_JSON)
        .ok()
        .and_then(|manifest| manifest["config"]["enabled"].as_bool())
        .unwrap_or(true);
    if config["extensions"]["builtin-wd-tagger"]["enabled"]
        .as_bool()
        .unwrap_or(wd_default)
    {
        capabilities.push("wd_tagger");
    }
    capabilities.extend(["image_analysis", "gateway", "scheduler"]);
    capabilities
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"ok": false, "error": "unavailable"})),
    )
        .into_response()
}

fn sns_config_value(config: &serde_json::Value) -> serde_json::Value {
    let mut value = json!({
        "bluesky": {
            "handle": "",
            "app_password": "",
        },
        "post_template": "{title}\n{url}",
    });
    if let Some(sns) = config.get("sns").and_then(serde_json::Value::as_object) {
        if let Some(bluesky) = sns.get("bluesky").and_then(serde_json::Value::as_object) {
            for (key, val) in bluesky {
                value["bluesky"][key] = val.clone();
            }
        }
        if let Some(template) = sns.get("post_template") {
            value["post_template"] = template.clone();
        }
    }
    value
}

fn bsky_monitor_config_value(config: &serde_json::Value) -> serde_json::Value {
    config
        .get("sns")
        .and_then(|v| v.get("bsky_monitor"))
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "poll_interval_minutes": 30,
                "auto_dismiss_follow": true,
                "auto_dismiss_like": true,
                "auto_dismiss_repost": true,
                "auto_respond_enabled": false,
                "notify_on_connect": true,
            })
        })
}

fn bsky_triage_prompts_value(config: &serde_json::Value) -> serde_json::Value {
    config
        .get("sns")
        .and_then(|v| v.get("bsky_triage"))
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "triage_prompts": {
                    "mention": "",
                    "reply": "",
                    "quote": "",
                },
                "auto_responses": {
                    "mention": "",
                    "reply": "",
                },
            })
        })
}

#[cfg(test)]
mod sns_tests {
    use super::*;

    #[test]
    fn sns_config_value_merges_defaults() {
        let cfg = sns_config_value(&json!({
            "sns": {
                "bluesky": {"handle": "alice.test"},
                "post_template": "hello"
            }
        }));

        assert_eq!(cfg["bluesky"]["handle"], "alice.test");
        assert_eq!(cfg["bluesky"]["app_password"], "");
        assert_eq!(cfg["post_template"], "hello");
    }
}

#[cfg(test)]
mod ai_context_tests {
    use super::*;
    use axum::body::to_bytes;
    use tempfile::TempDir;

    async fn test_state() -> (TempDir, SharedState) {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("config.json"), "{}\n").unwrap();
        let state = crate::state::semantic_test_state_with_root(
            true,
            String::new(),
            root.path().to_path_buf(),
        )
        .await;
        (root, state)
    }

    fn api_key(scopes: &[&str]) -> Extension<AuthContext> {
        Extension(AuthContext {
            reason: "api_key".to_string(),
            scopes: Some(scopes.iter().map(|scope| (*scope).to_string()).collect()),
        })
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn ai_context_requires_admin_scope() {
        let (_root, state) = test_state().await;
        let read_response = ai_context(
            State(state.clone()),
            Extension(false),
            Some(api_key(&["read"])),
        )
        .await;
        assert_eq!(read_response.status(), StatusCode::FORBIDDEN);

        let admin_response =
            ai_context(State(state), Extension(false), Some(api_key(&["admin"]))).await;
        assert_eq!(admin_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ai_context_matches_python_metadata_and_unmounted_capabilities() {
        let (_root, state) = test_state().await;
        let response = ai_context(State(state), Extension(false), Some(api_key(&["admin"]))).await;
        let value = response_json(response).await;
        let data = &value["data"];

        assert_eq!(data["software"]["name"], "YU AI Manager");
        assert_eq!(
            data["software"]["description"],
            "ローカルファースト AI 画像メタデータ管理ツール"
        );
        assert_eq!(
            data["urls"],
            json!({
                "settings_schema": "/api/settings/schema",
                "current_settings": "/api/settings/all",
                "openapi": "/api/openapi.json",
            })
        );
        assert_eq!(
            data["diagnostics"],
            json!({
                "doctor_start": {"method": "POST", "url": "/api/diagnostics/doctor"},
                "doctor_poll": {"method": "GET", "url": "/api/diagnostics/doctor/{job_id}"},
                "note": "POST で job を起動し、返された job_id を GET で polling して完了を確認する",
            })
        );
        assert!(!data["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability == "lan_cowork"));
    }

    #[test]
    fn ai_context_version_falls_back_and_caches_unknown() {
        let root = tempfile::tempdir().unwrap();
        let cache = OnceLock::new();
        assert_eq!(read_version_cached(&cache, root.path()), "unknown");
        std::fs::write(root.path().join("VERSION"), "9.9.9\n").unwrap();
        assert_eq!(read_version_cached(&cache, root.path()), "unknown");
    }

    #[test]
    fn ai_context_capabilities_follow_actual_configuration() {
        let config = json!({
            "hailo_tagger": {"enabled": true, "endpoint_url": "http://hailo.test"},
            "extensions": {"builtin-wd-tagger": {"enabled": false}},
        });
        assert_eq!(
            capabilities(&config, false),
            [
                "llm_router",
                "hailo",
                "image_analysis",
                "gateway",
                "scheduler"
            ]
        );
        assert!(capabilities(&config, true).contains(&"lan_cowork"));
    }

    #[test]
    fn ai_context_config_hints_match_python_rules() {
        let keys: Vec<_> = get_config_hints(&json!({
            "server": {"lan": true},
            "ai_analysis": {"api_key": ""},
        }))
        .into_iter()
        .map(|hint| hint["key"].as_str().unwrap().to_string())
        .collect();
        assert_eq!(
            keys,
            [
                "server.pin",
                "ai_analysis.api_key",
                "server.restart_token",
                "webhook_secret",
            ]
        );
    }
}

/// GET /api/ai-context
pub async fn ai_context(
    State(s): State<SharedState>,
    Extension(native_daemon): Extension<bool>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    let config = load_cfg(&s.config.config_path);
    Json(json!({
        "data": {
            "software": {
                "name": "YU AI Manager",
                "version": read_version_cached(&AI_CONTEXT_VERSION, &s.config.project_root),
                "description": "ローカルファースト AI 画像メタデータ管理ツール",
            },
            "capabilities": capabilities(&config, native_daemon),
            "urls": {
                "settings_schema": "/api/settings/schema",
                "current_settings": "/api/settings/all",
                "openapi": "/api/openapi.json",
            },
            "diagnostics": {
                "doctor_start": {"method": "POST", "url": "/api/diagnostics/doctor"},
                "doctor_poll": {"method": "GET", "url": "/api/diagnostics/doctor/{job_id}"},
                "note": "POST で job を起動し、返された job_id を GET で polling して完了を確認する",
            },
            "csrf_note": CSRF_NOTE,
            "config_hints": get_config_hints(&config),
        }
    }))
    .into_response()
}

/// GET /api/system/update/check
pub async fn update_check(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let cache = CHECK_CACHE.get_or_init(|| TokioMutex::new(UpdateCache { data: None }));
    let cached = {
        let guard = cache.lock().await;
        guard.data.as_ref().and_then(|(ts, v)| {
            if now.saturating_sub(*ts) < 600 {
                Some(v.clone())
            } else {
                None
            }
        })
    };
    let result = if let Some(v) = cached {
        v
    } else {
        let v = fetch_update_check(&s).await;
        let mut guard = cache.lock().await;
        guard.data = Some((now, v.clone()));
        v
    };
    Json(result).into_response()
}

/// GET /api/system/update/unified-check
pub async fn update_unified_check(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let cache = UNIFIED_CACHE.get_or_init(|| TokioMutex::new(UpdateCache { data: None }));
    let cached = {
        let guard = cache.lock().await;
        guard.data.as_ref().and_then(|(ts, v)| {
            if now.saturating_sub(*ts) < 600 {
                Some(v.clone())
            } else {
                None
            }
        })
    };
    let result = if let Some(v) = cached {
        v
    } else {
        let system = fetch_update_check(&s).await;
        let v = json!({
            "system": system,
            "extensions": [],
            "summary": {
                "total": 0,
                "up_to_date": 0,
                "update_available": 0,
                "unknown": 0,
                "builtin": 0,
            }
        });
        let mut guard = cache.lock().await;
        guard.data = Some((now, v.clone()));
        v
    };
    Json(result).into_response()
}

/// POST /api/search-union
pub async fn search_union(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// POST /api/debug/query
pub async fn debug_query(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// GET /api/workflow-gen-params/{file_id}
pub async fn workflow_gen_params(
    State(_s): State<SharedState>,
    Path(_file_id): Path<i64>,
) -> Response {
    unavailable()
}

/// GET /api/sns/preview
pub async fn sns_preview(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// GET /api/sns/x/intent
pub async fn sns_x_intent(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// POST /api/sns/bluesky/post
pub async fn sns_bluesky_post(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// POST /api/sns/bluesky/test
pub async fn sns_bluesky_test(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// GET /api/sns/bsky/queue
pub async fn sns_bsky_queue(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// GET /api/sns/bsky/queue/pending
pub async fn sns_bsky_queue_pending(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// GET /api/sns/bsky/monitor/config
pub async fn sns_bsky_monitor_config(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    Json(
        json!({"ok": true, "error": null, "data": bsky_monitor_config_value(&s.config.app_config)}),
    )
    .into_response()
}

/// GET /api/sns/bsky/monitor/triage-prompts
pub async fn sns_bsky_triage_prompts(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    Json(
        json!({"ok": true, "error": null, "data": bsky_triage_prompts_value(&s.config.app_config)}),
    )
    .into_response()
}

/// GET /api/sns/config
pub async fn sns_config_get(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    Json(json!({"ok": true, "error": null, "data": sns_config_value(&s.config.app_config)}))
        .into_response()
}

/// POST /api/sns/config
pub async fn sns_config_post(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// GET /api/mesh-inference/state
pub async fn mesh_state(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    Json(
        json!({"ok": true, "data": {"enabled": false, "backends": [], "status": "not_configured"}}),
    )
    .into_response()
}

/// POST /api/mesh-inference/toggle
pub async fn mesh_toggle(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// POST /api/mesh-inference/bulk
pub async fn mesh_bulk(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// POST /api/mesh-inference/refresh
pub async fn mesh_refresh(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// GET /api/collections/{id}/export
pub async fn collections_export(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    Path(id): Path<i64>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM collections WHERE id = ?")
        .bind(id)
        .fetch_optional(&s.db_read)
        .await
        .unwrap_or(None);
    let Some(cname) = name else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "collection_not_found"})),
        )
            .into_response();
    };
    let rows = sqlx::query_as::<
        _,
        (
            i64,
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT f.id, f.path, f.meta_source, f.mtime, t.raw_prompt, t.raw_negative \
         FROM favorites fav \
         JOIN files f ON f.id = fav.file_id AND f.is_deleted = 0 \
         LEFT JOIN templates t ON t.file_id = f.id \
         WHERE fav.collection_id = ? ORDER BY fav.added_at DESC",
    )
    .bind(id)
    .fetch_all(&s.db_read)
    .await
    .unwrap_or_default();
    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(fid, path, meta_source, mtime, positive, negative)| {
            let p = path.as_deref().unwrap_or("");
            let fname = p.rsplit('/').next().unwrap_or(p);
            let folder = if let Some(idx) = p.rfind('/') {
                &p[..idx]
            } else {
                ""
            };
            let mtime_iso = mtime
                .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_default();
            json!({
                "id": fid,
                "filename": fname,
                "folder": folder,
                "path": p,
                "meta_source": meta_source.unwrap_or_default(),
                "mtime": mtime_iso,
                "positive": positive.unwrap_or_default(),
                "negative": negative.unwrap_or_default(),
            })
        })
        .collect();
    Json(json!({"ok": true, "collection": {"id": id, "name": cname}, "items": items}))
        .into_response()
}

/// GET /api/collections/{id}/export/csv
pub async fn collections_export_csv(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    Path(id): Path<i64>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM collections WHERE id = ?")
        .bind(id)
        .fetch_optional(&s.db_read)
        .await
        .unwrap_or(None);
    let Some(cname) = name else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "collection_not_found"})),
        )
            .into_response();
    };
    let rows = sqlx::query_as::<
        _,
        (
            i64,
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT f.id, f.path, f.meta_source, f.mtime, t.raw_prompt, t.raw_negative \
         FROM favorites fav \
         JOIN files f ON f.id = fav.file_id AND f.is_deleted = 0 \
         LEFT JOIN templates t ON t.file_id = f.id \
         WHERE fav.collection_id = ? ORDER BY fav.added_at DESC",
    )
    .bind(id)
    .fetch_all(&s.db_read)
    .await
    .unwrap_or_default();

    let mut csv = String::from("\u{FEFF}"); // UTF-8 BOM
    csv.push_str("id,filename,folder,path,meta_source,mtime,positive,negative\n");
    for (fid, path, meta_source, mtime, positive, negative) in rows {
        let p = path.as_deref().unwrap_or("").to_string();
        let fname = p.rsplit('/').next().unwrap_or(&p).to_string();
        let folder = if let Some(idx) = p.rfind('/') {
            p[..idx].to_string()
        } else {
            String::new()
        };
        let mtime_iso = mtime
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_default();
        fn csv_field(s: &str) -> String {
            if s.contains([',', '"', '\n']) {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        }
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            fid,
            csv_field(&fname),
            csv_field(&folder),
            csv_field(&p),
            csv_field(meta_source.as_deref().unwrap_or("")),
            mtime_iso,
            csv_field(positive.as_deref().unwrap_or("")),
            csv_field(negative.as_deref().unwrap_or("")),
        ));
    }
    let safe_name: String = cname
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let disposition = format!("attachment; filename=\"{safe_name}.csv\"");
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (header::CONTENT_DISPOSITION, &disposition),
        ],
        csv,
    )
        .into_response()
}

/// POST /api/llm/agent
pub async fn llm_agent(State(_s): State<SharedState>) -> Response {
    unavailable()
}

/// POST /api/llm/chat
pub async fn llm_chat(State(_s): State<SharedState>) -> Response {
    unavailable()
}

/// GET /share
pub async fn page_share(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// GET /crypto-tools
pub async fn page_crypto_tools(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    Extension(CspNonce(nonce)): Extension<CspNonce>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    crate::frontend::render(
        &s,
        "crypto_tools.html",
        serde_json::json!({"csp_nonce": nonce, "dist_v": s.dist_v, "active": "crypto_tools"}),
    )
    .into_response()
}

/// GET /tauri-shell
pub async fn page_tauri_shell(State(_s): State<SharedState>) -> Response {
    unavailable()
}

/// GET /help
pub async fn page_help(
    State(s): State<SharedState>,
    Extension(CspNonce(nonce)): Extension<CspNonce>,
) -> Response {
    crate::frontend::render(
        &s,
        "help.html",
        serde_json::json!({"csp_nonce": nonce, "dist_v": s.dist_v, "active": "help"}),
    )
    .into_response()
}

/// GET /backends
pub async fn page_backends(State(_s): State<SharedState>) -> Response {
    unavailable()
}

/// GET /local/status
pub async fn page_local_status(State(_s): State<SharedState>) -> Response {
    unavailable()
}

/// GET /groups
pub async fn page_groups(State(_s): State<SharedState>) -> Response {
    unavailable()
}

/// GET /defaults
pub async fn page_defaults(State(_s): State<SharedState>) -> Response {
    unavailable()
}

// --- native gateway / SD handlers ---

async fn read_config_json(state: &SharedState) -> serde_json::Value {
    tokio::fs::read_to_string(&state.config.config_path)
        .await
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| serde_json::json!({}))
}

fn sd_backend_url(gw: &serde_json::Value) -> String {
    let id = gw["defaults"]["default_sd_backend_id"]
        .as_str()
        .unwrap_or("");
    if !id.is_empty() {
        if let Some(url) = gw["backends"][id]["base_url"].as_str() {
            if !url.is_empty() {
                return url.to_owned();
            }
        }
    }
    "http://127.0.0.1:7860".to_owned()
}

async fn fwd_get_sd(state: &SharedState, path: &str) -> Response {
    let gw = read_config_json(state).await["gateway"].clone();
    let url = format!("{}{}", sd_backend_url(&gw).trim_end_matches('/'), path);
    match state.python_client.get(&url).send().await {
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

/// GET /api/gateway/keys — admin scope, returns key list without secrets
pub async fn gateway_keys(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    let cfg = read_config_json(&s).await;
    let keys = cfg["gateway"]["auth"]["api_keys"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let safe: Vec<serde_json::Value> = keys
        .iter()
        .map(|k| {
            json!({
                "id": k["id"],
                "scopes": k["scopes"],
                "allowed_models": k["allowed_models"],
            })
        })
        .collect();
    Json(json!({"ok": true, "keys": safe})).into_response()
}

/// GET /agentmemory/livez — proxy to configured AgentMemory base_url/livez
pub async fn agentmemory_livez(State(s): State<SharedState>) -> Response {
    let cfg = read_config_json(&s).await;
    let base_url = cfg["gateway"]["backends"]["agentmemory"]["base_url"]
        .as_str()
        .unwrap_or("http://127.0.0.1:3111")
        .trim_end_matches('/')
        .to_owned();
    let livez_url = format!("{base_url}/livez");
    match s.python_client.get(&livez_url).send().await {
        Ok(resp) => {
            let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let body = resp.text().await.unwrap_or_default();
            (status, body).into_response()
        }
        Err(_) => Json(json!({"ok": false, "status": "unreachable"})).into_response(),
    }
}

/// GET /api/agentmemory-dash/health
pub async fn agentmemory_dash_health(State(s): State<SharedState>) -> Response {
    let cfg = read_config_json(&s).await;
    let base_url = cfg["gateway"]["backends"]["agentmemory"]["base_url"]
        .as_str()
        .unwrap_or("")
        .trim_end_matches('/')
        .to_owned();
    if base_url.is_empty() {
        return Json(json!({"ok": false, "status": "not_configured"})).into_response();
    }
    match s
        .python_client
        .get(format!("{base_url}/health"))
        .send()
        .await
    {
        Ok(r) => {
            let st = axum::http::StatusCode::from_u16(r.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            (st, r.text().await.unwrap_or_default()).into_response()
        }
        Err(_) => Json(json!({"ok": false, "status": "unreachable"})).into_response(),
    }
}

/// GET /api/agentmemory-dash/profile
pub async fn agentmemory_dash_profile(State(s): State<SharedState>) -> Response {
    let cfg = read_config_json(&s).await;
    let base_url = cfg["gateway"]["backends"]["agentmemory"]["base_url"]
        .as_str()
        .unwrap_or("")
        .trim_end_matches('/')
        .to_owned();
    if base_url.is_empty() {
        return Json(json!({"ok": false, "status": "not_configured", "profile": null}))
            .into_response();
    }
    match s
        .python_client
        .get(format!("{base_url}/profile"))
        .send()
        .await
    {
        Ok(r) => {
            let st = axum::http::StatusCode::from_u16(r.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            (st, r.text().await.unwrap_or_default()).into_response()
        }
        Err(_) => {
            Json(json!({"ok": false, "status": "unreachable", "profile": null})).into_response()
        }
    }
}

/// GET /api/gateway/agentmemory/config — admin scope
pub async fn agentmemory_config(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    let cfg = read_config_json(&s).await;
    let base_url = cfg["gateway"]["backends"]["agentmemory"]["base_url"]
        .as_str()
        .unwrap_or("http://127.0.0.1:3111")
        .to_owned();
    Json(json!({"base_url": base_url})).into_response()
}

/// PUT /api/gateway/agentmemory/config — admin scope
pub async fn gateway_agentmemory_config_put(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    let body = body.map(|Json(v)| v).unwrap_or_default();
    let base_url_raw = body["base_url"].as_str().unwrap_or("").to_string();

    let base_url = match validate_base_url(&base_url_raw) {
        Ok(u) => u,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response(),
    };

    let mut config = load_cfg(&s.config.config_path);
    config["gateway"]["backends"]["agentmemory"]["base_url"] = json!(base_url);
    if let Err(e) = write_cfg(&s.config.config_path, &config) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }

    Json(json!({"base_url": base_url})).into_response()
}

/// GET /api/gateway/headroom/config — admin scope
pub async fn headroom_config(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    let cfg = read_config_json(&s).await;
    let h = &cfg["gateway"]["backends"]["headroom"];
    Json(json!({"ok": true, "base_url": h["base_url"], "auth_key": h["auth_key"]})).into_response()
}

/// GET /api/gateway/admin-token — native: loopback-only, reads/creates gateway_admin_token
pub async fn admin_token(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    if !matches!(ip.as_str(), "127.0.0.1" | "::1" | "localhost") {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "Forbidden"}))).into_response();
    }
    if let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        let h = host.split(':').next().unwrap_or("").trim_start_matches('[');
        if !h.is_empty() && !matches!(h, "127.0.0.1" | "::1" | "localhost") {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "Forbidden"}))).into_response();
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let h = origin
            .split("://")
            .nth(1)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.split(':').next())
            .unwrap_or("");
        if !h.is_empty() && !matches!(h, "127.0.0.1" | "::1" | "localhost") {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "Forbidden"}))).into_response();
        }
    }
    let mut cfg = read_config_json(&s).await;
    let token = match cfg["gateway"]["gateway_admin_token"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        Some(t) => t.to_owned(),
        None => {
            let t = uuid::Uuid::new_v4().simple().to_string();
            cfg["gateway"]["gateway_admin_token"] = json!(t.clone());
            let _ = write_cfg(&s.config.config_path, &cfg);
            t
        }
    };
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"token": token})),
    )
        .into_response()
}

/// GET /sd/config — admin scope, proxies to SD backend
pub async fn sd_config(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    fwd_get_sd(&s, "/config").await
}

/// GET /sd/info — admin scope
pub async fn sd_info(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    fwd_get_sd(&s, "/info").await
}

/// GET /sd/internal/ping — admin scope
pub async fn sd_ping(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    fwd_get_sd(&s, "/internal/ping").await
}

/// GET /v1/models
pub async fn llm_models(State(_s): State<SharedState>) -> Response {
    unavailable()
}

/// GET /v1/router/health
pub async fn router_health(State(_s): State<SharedState>) -> Response {
    unavailable()
}

/// POST /v1/router/refresh — stub (Python LLM router unavailable in standalone)
pub async fn router_refresh(State(_s): State<SharedState>) -> Response {
    unavailable()
}

/// POST /v1/router/estimate — stub
pub async fn router_estimate(State(_s): State<SharedState>) -> Response {
    unavailable()
}

/// GET /v1/router/capabilities/{target} — stub
pub async fn router_capabilities_target(
    State(_s): State<SharedState>,
    Path(_target): Path<String>,
) -> Response {
    unavailable()
}

/// POST /api/system/update/apply — admin scope
pub async fn system_update_apply(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// POST /api/system/update/unified-apply — admin scope
pub async fn system_update_unified_apply(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// POST /api/update/verify — admin scope
pub async fn update_verify(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// POST /api/update/apply — admin scope
pub async fn update_apply(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// POST /api/update/rollback — admin scope
pub async fn update_rollback(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }
    unavailable()
}

/// POST /api/inspect — native multipart upload inspection (Rust implementation)
pub async fn inspect_upload(
    State(s): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    mut multipart: axum::extract::Multipart,
) -> Response {
    if let Some(r) = gate(&s, auth.as_ref()) {
        return r;
    }

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut filename = String::new();
    let mut zip_entry = String::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name() {
            Some("file") => {
                filename = field.file_name().unwrap_or("upload").to_string();
                match field.bytes().await {
                    Ok(b) => file_bytes = Some(b.to_vec()),
                    Err(_) => {
                        return Json(json!({"error": "Failed to read uploaded file"}))
                            .into_response()
                    }
                }
            }
            Some("zip_entry") => {
                zip_entry = field.text().await.unwrap_or_default();
            }
            _ => {}
        }
    }

    let bytes = match file_bytes {
        Some(b) if !b.is_empty() => b,
        Some(_) => return Json(json!({"error": "Uploaded file is empty"})).into_response(),
        None => return Json(json!({"error": "No file uploaded"})).into_response(),
    };
    if filename.is_empty() {
        return Json(json!({"error": "Empty filename"})).into_response();
    }

    let ext = std::path::Path::new(&filename)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e.to_lowercase()))
        .unwrap_or_default();

    let payload = if ext == ".zip" {
        inspect_zip(bytes, filename, &zip_entry)
    } else {
        inspect_image(bytes, filename, &ext)
    };
    Json(payload).into_response()
}

const _IMAGE_EXTS: &[&str] = &[".png", ".jpg", ".jpeg", ".webp"];
const _MAX_IMAGE_BYTES: usize = 50 * 1024 * 1024;
const _MAX_ZIP_BYTES: usize = 200 * 1024 * 1024;

fn inspect_image(bytes: Vec<u8>, filename: String, ext: &str) -> serde_json::Value {
    use std::io::Write as _;
    if !_IMAGE_EXTS.contains(&ext) {
        return json!({"error": format!("Unsupported file type: {:?}. Allowed: .png, .jpg, .jpeg, .webp", ext)});
    }
    if bytes.len() > _MAX_IMAGE_BYTES {
        return json!({"error": "Uploaded file is too large (max 50 MB)"});
    }
    let mut tmp = match tempfile::Builder::new().suffix(ext).tempfile() {
        Ok(f) => f,
        Err(_) => return json!({"error": "Failed to create temp file"}),
    };
    if tmp.write_all(&bytes).is_err() {
        return json!({"error": "Failed to write temp file"});
    }
    scan_to_json(tmp.path(), &filename, ext, bytes.len())
}

fn inspect_zip(bytes: Vec<u8>, filename: String, zip_entry: &str) -> serde_json::Value {
    use std::io::{Read as _, Write as _};
    if bytes.len() > _MAX_ZIP_BYTES {
        return json!({"error": "Uploaded ZIP is too large (max 200 MB)"});
    }
    if !zip_entry.is_empty()
        && (zip_entry.contains('\0') || zip_entry.split('/').any(|p| p == ".."))
    {
        return json!({"error": "Invalid zip entry path"});
    }
    let cursor = std::io::Cursor::new(&bytes);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return json!({"error": "Failed to open ZIP"}),
    };
    let mut images = Vec::new();
    for i in 0..archive.len() {
        if let Ok(f) = archive.by_index(i) {
            if !f.is_dir() {
                let name = f.name().to_string();
                let lower = name.to_lowercase();
                if _IMAGE_EXTS.iter().any(|e| lower.ends_with(e)) {
                    images.push(name);
                }
            }
        }
    }
    if images.is_empty() {
        return json!({"error": "No image files found in ZIP"});
    }
    let target = if !zip_entry.is_empty() && images.contains(&zip_entry.to_string()) {
        zip_entry.to_string()
    } else {
        images[0].clone()
    };
    let target_ext = std::path::Path::new(&target)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e.to_lowercase()))
        .unwrap_or_default();
    let mut entry = match archive.by_name(&target) {
        Ok(e) => e,
        Err(_) => return json!({"error": "Failed to extract ZIP entry"}),
    };
    if entry.size() > _MAX_IMAGE_BYTES as u64 {
        return json!({"error": "Image in ZIP is too large (max 50 MB)"});
    }
    let mut entry_bytes = Vec::new();
    if entry.read_to_end(&mut entry_bytes).is_err() {
        return json!({"error": "Failed to read ZIP entry"});
    }
    let mut tmp = match tempfile::Builder::new().suffix(&target_ext).tempfile() {
        Ok(f) => f,
        Err(_) => return json!({"error": "Failed to create temp file"}),
    };
    if tmp.write_all(&entry_bytes).is_err() {
        return json!({"error": "Failed to write temp file"});
    }
    let entry_name = format!("{}!{}", filename, target);
    let mut result = scan_to_json(tmp.path(), &entry_name, &target_ext, entry_bytes.len());
    if result.get("error").is_none() {
        result["zip_images"] =
            serde_json::Value::Array(images.into_iter().map(serde_json::Value::String).collect());
        result["zip_current"] = serde_json::Value::String(target);
    }
    result
}

fn scan_to_json(
    path: &std::path::Path,
    filename: &str,
    ext: &str,
    size: usize,
) -> serde_json::Value {
    use meta_extract::{
        models::PngTextChunks, parse_metadata, read_exif_tags, read_png_text_chunks,
    };

    let (chunks, raw_metadata) = if ext == ".png" {
        let chunks = read_png_text_chunks(path);
        let raw: serde_json::Map<String, serde_json::Value> = chunks
            .entries
            .iter()
            .map(|(k, v)| (k.clone(), json!(v.chars().take(2000).collect::<String>())))
            .collect();
        (chunks, serde_json::Value::Object(raw))
    } else {
        let exif = read_exif_tags(path);
        let raw: serde_json::Map<String, serde_json::Value> = exif
            .iter()
            .map(|(k, v)| (k.clone(), json!(v.chars().take(500).collect::<String>())))
            .collect();
        let mut chunks = PngTextChunks::default();
        for (k, v) in &exif {
            chunks.entries.insert(format!("exif:{k}"), v.clone());
        }
        (chunks, serde_json::Value::Object(raw))
    };

    let meta = parse_metadata(&chunks);
    let parsed = meta.format != "unknown";
    let meta_source = match meta.format.as_str() {
        "comfy" => {
            if ext == ".webp" {
                "comfy_webp"
            } else {
                "comfy_png"
            }
        }
        "nai_v4" => {
            if ext == ".webp" {
                "novelai_v4_webp"
            } else {
                "novelai_v4_png"
            }
        }
        other => other,
    };

    use crate::routes::file_detail::resolve_detail_fields;
    let detail = resolve_detail_fields(
        meta_source,
        meta.positive.as_deref().unwrap_or(""),
        meta.negative.as_deref().unwrap_or(""),
        meta.raw_meta.as_deref(),
        None,
    );

    let mut result = json!({
        "filename": filename,
        "size": size,
        "parsed": parsed,
        "meta_source": meta_source,
        "positive": detail.positive,
        "negative": detail.negative,
        "format": meta.format,
        "resolution": detail.resolution,
        "model": detail.model,
        "parameters": detail.parameters,
        "raw_metadata": raw_metadata,
        "raw_meta_json": meta.raw_meta,
        "tags": [],
    });
    if let Some(nai) = detail.novelai_v4 {
        result["novelai_v4"] = nai;
    }
    result
}
