use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;

use crate::{
    auth::{scope::require_admin_scope, AuthContext},
    state::SharedState,
};

/// GET /api/ocr/engines
pub async fn ocr_engines(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|e| &e.0),
    ) {
        return resp;
    }
    // ponytail: ai_servers is not wired here yet; Phase 2 can read config.
    Json(json!({"engines": [], "manga_ocr_available": false})).into_response()
}

#[derive(Deserialize, Default)]
pub struct ResultGetParams {
    pub task: Option<String>,
    pub engine: Option<String>,
    pub all: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct ResultDeleteParams {
    pub task: Option<String>,
    pub engine: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct TranslationsParams {
    pub target_lang: Option<String>,
}

const RESULT_COLS: &str =
    "id, file_id, engine, task, regions_json, full_text, language, structured_json, created_at";

fn row_to_result(row: &sqlx::sqlite::SqliteRow) -> serde_json::Value {
    let regions: serde_json::Value = row
        .try_get::<Option<String>, _>("regions_json")
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!([]));
    let structured: serde_json::Value = row
        .try_get::<Option<String>, _>("structured_json")
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}));

    json!({
        "ok": true,
        "error": null,
        "data": null,
        "id": row.get::<i64, _>("id"),
        "file_id": row.get::<i64, _>("file_id"),
        "engine": row.get::<String, _>("engine"),
        "task": row.get::<String, _>("task"),
        "regions": regions,
        "full_text": row.try_get::<Option<String>, _>("full_text").ok().flatten().unwrap_or_default(),
        "language": row.try_get::<Option<String>, _>("language").ok().flatten().unwrap_or_default(),
        "headings": structured.get("headings").cloned().unwrap_or_else(|| json!([])),
        "tables": structured.get("tables").cloned().unwrap_or_else(|| json!([])),
        "page_layout": structured.get("page_layout").cloned().unwrap_or_else(|| json!("")),
        "created_at": row.get::<i64, _>("created_at"),
    })
}

/// GET /api/ocr/result/{file_id}
pub async fn ocr_result_get(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
    Path(file_id): Path<i64>,
    Query(params): Query<ResultGetParams>,
) -> Response {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|e| &e.0),
    ) {
        return resp;
    }

    let all_truthy = params
        .all
        .as_deref()
        .is_some_and(|v| !v.is_empty() && v != "0" && v != "false");
    if all_truthy {
        let rows = sqlx::query(&format!(
            "SELECT {RESULT_COLS} FROM file_ocr_results WHERE file_id=? ORDER BY created_at DESC, id DESC"
        ))
        .bind(file_id)
        .fetch_all(&state.db_read)
        .await;
        return match rows {
            Ok(rows) => Json(json!({
                "ok": true,
                "error": null,
                "data": null,
                "file_id": file_id,
                "results": rows.iter().map(row_to_result).collect::<Vec<_>>()
            }))
            .into_response(),
            Err(e) => {
                tracing::error!("ocr_result_get all: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "error": "db_error"})),
                )
                    .into_response()
            }
        };
    }

    let row = match (&params.task, &params.engine) {
        (Some(task), Some(engine)) => {
            sqlx::query(&format!(
                "SELECT {RESULT_COLS} FROM file_ocr_results WHERE file_id=? AND task=? AND engine=? LIMIT 1"
            ))
            .bind(file_id)
            .bind(task)
            .bind(engine)
            .fetch_optional(&state.db_read)
            .await
        }
        (Some(task), None) => {
            sqlx::query(&format!(
                "SELECT {RESULT_COLS} FROM file_ocr_results WHERE file_id=? AND task=? ORDER BY created_at DESC, id DESC LIMIT 1"
            ))
            .bind(file_id)
            .bind(task)
            .fetch_optional(&state.db_read)
            .await
        }
        _ => {
            sqlx::query(&format!(
                "SELECT {RESULT_COLS} FROM file_ocr_results WHERE file_id=? ORDER BY created_at DESC, id DESC LIMIT 1"
            ))
            .bind(file_id)
            .fetch_optional(&state.db_read)
            .await
        }
    };

    match row {
        Ok(Some(row)) => Json(row_to_result(&row)).into_response(),
        Ok(None) => Json(json!({"ok": true, "error": null, "data": null, "status": "not_found"}))
            .into_response(),
        Err(e) => {
            tracing::error!("ocr_result_get: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "db_error"})),
            )
                .into_response()
        }
    }
}

/// GET /api/ocr/translations/{file_id}
pub async fn ocr_translations(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
    Path(file_id): Path<i64>,
    Query(params): Query<TranslationsParams>,
) -> Response {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|e| &e.0),
    ) {
        return resp;
    }

    let base_sql = r#"
        SELECT
            t.id,
            t.ocr_result_id,
            t.target_lang,
            t.translated_text,
            t.engine,
            t.region_translations_json,
            t.created_at,
            r.file_id,
            r.task,
            r.engine AS ocr_engine
        FROM file_translations t
        JOIN file_ocr_results r ON r.id = t.ocr_result_id
        WHERE r.file_id=?
    "#;

    let rows = if let Some(target_lang) = params.target_lang.as_deref().filter(|s| !s.is_empty()) {
        sqlx::query(&format!(
            "{base_sql} AND t.target_lang=? ORDER BY t.created_at DESC, t.id DESC"
        ))
        .bind(file_id)
        .bind(target_lang)
        .fetch_all(&state.db_read)
        .await
    } else {
        sqlx::query(&format!("{base_sql} ORDER BY t.created_at DESC, t.id DESC"))
            .bind(file_id)
            .fetch_all(&state.db_read)
            .await
    };

    match rows {
        Ok(rows) => {
            let translations: Vec<_> = rows
                .iter()
                .map(|row| {
                    let region_translations: serde_json::Value = row
                        .try_get::<Option<String>, _>("region_translations_json")
                        .ok()
                        .flatten()
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_else(|| json!([]));
                    json!({
                        "id": row.get::<i64, _>("id"),
                        "ocr_result_id": row.get::<i64, _>("ocr_result_id"),
                        "target_lang": row.get::<String, _>("target_lang"),
                        "translated_text": row.try_get::<Option<String>, _>("translated_text").ok().flatten(),
                        "engine": row.try_get::<Option<String>, _>("engine").ok().flatten().unwrap_or_default(),
                        "created_at": row.get::<i64, _>("created_at"),
                        "region_translations": region_translations,
                        "file_id": row.get::<i64, _>("file_id"),
                        "task": row.get::<String, _>("task"),
                        "ocr_engine": row.get::<String, _>("ocr_engine"),
                    })
                })
                .collect();
            Json(json!({
                "ok": true,
                "error": null,
                "data": null,
                "file_id": file_id,
                "translations": translations,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("ocr_translations: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "db_error"})),
            )
                .into_response()
        }
    }
}

/// DELETE /api/ocr/result/{file_id}
pub async fn ocr_result_delete(
    State(state): State<SharedState>,
    Path(file_id): Path<i64>,
    Query(params): Query<ResultDeleteParams>,
) -> Response {
    let (trans_sql, results_sql) = match (&params.task, &params.engine) {
        (Some(_), Some(_)) => (
            "DELETE FROM file_translations WHERE ocr_result_id IN (SELECT id FROM file_ocr_results WHERE file_id=? AND task=? AND engine=?)",
            "DELETE FROM file_ocr_results WHERE file_id=? AND task=? AND engine=?",
        ),
        (Some(_), None) => (
            "DELETE FROM file_translations WHERE ocr_result_id IN (SELECT id FROM file_ocr_results WHERE file_id=? AND task=?)",
            "DELETE FROM file_ocr_results WHERE file_id=? AND task=?",
        ),
        _ => (
            "DELETE FROM file_translations WHERE ocr_result_id IN (SELECT id FROM file_ocr_results WHERE file_id=?)",
            "DELETE FROM file_ocr_results WHERE file_id=?",
        ),
    };

    let trans_result = match (&params.task, &params.engine) {
        (Some(task), Some(engine)) => {
            sqlx::query(trans_sql)
                .bind(file_id)
                .bind(task)
                .bind(engine)
                .execute(&state.db)
                .await
        }
        (Some(task), None) => {
            sqlx::query(trans_sql)
                .bind(file_id)
                .bind(task)
                .execute(&state.db)
                .await
        }
        _ => {
            sqlx::query(trans_sql)
                .bind(file_id)
                .execute(&state.db)
                .await
        }
    };
    if let Err(e) = trans_result {
        tracing::error!("ocr_result_delete translations: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": "db_error"})),
        )
            .into_response();
    }

    let result = match (&params.task, &params.engine) {
        (Some(task), Some(engine)) => {
            sqlx::query(results_sql)
                .bind(file_id)
                .bind(task)
                .bind(engine)
                .execute(&state.db)
                .await
        }
        (Some(task), None) => {
            sqlx::query(results_sql)
                .bind(file_id)
                .bind(task)
                .execute(&state.db)
                .await
        }
        _ => {
            sqlx::query(results_sql)
                .bind(file_id)
                .execute(&state.db)
                .await
        }
    };

    match result {
        Ok(r) => Json(json!({"deleted": r.rows_affected()})).into_response(),
        Err(e) => {
            tracing::error!("ocr_result_delete: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "db_error"})),
            )
                .into_response()
        }
    }
}
