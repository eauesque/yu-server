use axum::{
    body::Bytes,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use sqlx::Row;

use crate::{
    auth::{scope::require_admin_scope, AuthContext},
    state::SharedState,
};

const SCHEMA: &str = "yu://recipe/1";

const NAI_SOURCES: &[&str] = &[
    "novelai_v4_png",
    "novelai_png",
    "novelai_v4_webp",
    "novelai_webp",
    "novelai_v4",
    "nai_webp",
];
const COMFY_SOURCES: &[&str] = &[
    "comfyui",
    "comfy_png",
    "comfy_webp",
    "comfy_webm",
    "comfy_flac",
];

fn meta_source_to_bridge_id(meta_source: &str) -> Option<&'static str> {
    if NAI_SOURCES.contains(&meta_source) {
        return Some("nai");
    }
    if meta_source.starts_with("a1111_") || meta_source == "tensor_art" {
        return Some("sd-webui");
    }
    if COMFY_SOURCES.contains(&meta_source) {
        return Some("comfyui");
    }
    None
}

fn normalize_parameters(
    params: &serde_json::Map<String, Value>,
) -> (serde_json::Map<String, Value>, Vec<String>) {
    let mut fields = serde_json::Map::new();
    let mut warnings = Vec::new();
    for (key, val) in params {
        match key.as_str() {
            "CFG scale" | "scale" => {
                if let Some(f) = val.as_f64() {
                    fields.insert("cfg".into(), json!(f));
                } else if let Some(s) = val.as_str() {
                    if let Ok(f) = s.parse::<f64>() {
                        fields.insert("cfg".into(), json!(f));
                    } else {
                        warnings.push(key.clone());
                    }
                } else {
                    warnings.push(key.clone());
                }
            }
            "Size" => {
                if let Some(s) = val.as_str() {
                    if let Some((w, h)) = s.split_once('x') {
                        match (w.parse::<i64>(), h.parse::<i64>()) {
                            (Ok(w), Ok(h)) => {
                                fields.insert("width".into(), json!(w));
                                fields.insert("height".into(), json!(h));
                            }
                            _ => warnings.push(key.clone()),
                        }
                    } else {
                        warnings.push(key.clone());
                    }
                } else {
                    warnings.push(key.clone());
                }
            }
            "Seed" => {
                if let Some(n) = val.as_i64() {
                    fields.insert("seed".into(), json!(n));
                } else if let Some(s) = val.as_str() {
                    if let Ok(n) = s.parse::<i64>() {
                        fields.insert("seed".into(), json!(n));
                    } else {
                        warnings.push(key.clone());
                    }
                } else {
                    warnings.push(key.clone());
                }
            }
            "Steps" => {
                if let Some(n) = val.as_i64() {
                    fields.insert("steps".into(), json!(n));
                } else if let Some(s) = val.as_str() {
                    if let Ok(n) = s.parse::<i64>() {
                        fields.insert("steps".into(), json!(n));
                    } else {
                        warnings.push(key.clone());
                    }
                } else {
                    warnings.push(key.clone());
                }
            }
            "Sampler" => {
                if let Some(s) = val.as_str() {
                    fields.insert("sampler".into(), json!(s));
                }
            }
            "Model" | "model_name" => {
                if let Some(s) = val.as_str() {
                    fields.insert("model".into(), json!(s));
                }
            }
            _ => warnings.push(key.clone()),
        }
    }
    (fields, warnings)
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
            Json(json!({"ok": false, "error": "unavailable"})),
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

/// POST /api/recipe/import — admin scope required
pub async fn recipe_import(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_scope_error(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// POST /api/recipe/import/batch — admin scope required
pub async fn recipe_import_batch(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_scope_error(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

/// POST /api/recipe/export/batch — admin scope required
pub async fn recipe_export_batch(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(r) = admin_scope_error(&state, auth.as_ref()) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
        .into_response()
}

pub async fn recipe_export(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
    Path(file_id): Path<i64>,
) -> Response {
    if let Some(err) = admin_scope_error(&state, auth_context.as_ref()) {
        return err;
    }

    let row = sqlx::query(
        "SELECT f.meta_source, tm.raw_prompt, tm.raw_negative, tm.raw_meta_json, tm.model_name, tm.model_hash \
         FROM files f \
         LEFT JOIN templates tm ON tm.file_id = f.id \
         WHERE f.id = ? AND f.is_deleted = 0",
    )
    .bind(file_id)
    .fetch_optional(&state.db_read)
    .await;

    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Json(json!({"ok": false, "error": "no gen metadata for this file"}))
                .into_response();
        }
        Err(e) => {
            tracing::error!("recipe_export db error: {e}");
            return Json(json!({"ok": false, "error": "database error"})).into_response();
        }
    };

    let meta_source: Option<String> = row.try_get("meta_source").ok().flatten();
    let bridge_id = match meta_source.as_deref().and_then(meta_source_to_bridge_id) {
        Some(id) => id,
        None => {
            return Json(json!({"ok": false, "error": "no gen metadata for this file"}))
                .into_response();
        }
    };

    let raw_prompt: Option<String> = row.try_get("raw_prompt").ok().flatten();
    let raw_negative: Option<String> = row.try_get("raw_negative").ok().flatten();
    let model_name: Option<String> = row.try_get("model_name").ok().flatten();
    let model_hash: Option<String> = row.try_get("model_hash").ok().flatten();
    let raw_meta_json: Option<String> = row.try_get("raw_meta_json").ok().flatten();

    let mut recipe = serde_json::Map::new();
    recipe.insert("schema".into(), json!(SCHEMA));
    recipe.insert("bridge_id".into(), json!(bridge_id));
    recipe.insert("positive".into(), json!(raw_prompt.unwrap_or_default()));
    recipe.insert("negative".into(), json!(raw_negative.unwrap_or_default()));

    let mut capture_warnings: Vec<String> = Vec::new();

    if let Some(name) = model_name {
        recipe.insert("model".into(), json!(name));
    }
    if bridge_id != "nai" {
        if let Some(hash) = model_hash {
            recipe.insert("model_hash".into(), json!(hash));
        }
    }

    if let Some(raw) = raw_meta_json {
        match serde_json::from_str::<Value>(&raw) {
            Ok(meta) => {
                if let Some(params) = meta.get("parameters").and_then(|p| p.as_object()) {
                    let (fields, warns) = normalize_parameters(params);
                    recipe.extend(fields);
                    capture_warnings.extend(warns);
                }
            }
            Err(_) => capture_warnings.push("parse_error".into()),
        }
    }

    recipe.insert("capture_warnings".into(), json!(capture_warnings));

    // Python api_success spreads payload keys at top level (body.update(payload))
    let mut body = serde_json::Map::new();
    body.insert("ok".into(), json!(true));
    body.insert("error".into(), json!(null));
    body.insert("data".into(), json!(null));
    body.extend(recipe);
    Json(Value::Object(body)).into_response()
}
