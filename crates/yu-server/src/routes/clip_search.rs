//! Native read-side handlers for the Hailo semantic-search extension.

use std::{collections::HashSet, path::Path, time::Instant};

use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{QueryBuilder, Row, Sqlite};

use crate::{
    auth::{scope::require_admin_scope, AuthContext},
    infer_client::InferClientError,
    state::SharedState,
};

use super::vector_store::{self, DEFAULT_MODEL};

const MAX_QUERY_CHARS: usize = 500;
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;
const DEFAULT_THRESHOLD: f32 = 0.2;
const IMAGE_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "webp", "gif", "avif", "bmp", "tiff", "tif", "heif", "heic", "jxl", "svg",
];
const VIDEO_EXTENSIONS: &[&str] = &["webm", "mp4", "avi", "mov", "mkv", "m4v", "ogv"];

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
    pub limit: Option<String>,
    pub threshold: Option<String>,
    #[serde(rename = "format")]
    pub format: Option<String>,
    pub format_exts: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub model_filter: Option<String>,
    pub min_width: Option<String>,
    pub max_width: Option<String>,
    pub min_height: Option<String>,
    pub max_height: Option<String>,
    pub in_path: Option<String>,
    pub fav_only: Option<String>,
}

fn admin_or_response(
    state: &SharedState,
    auth: Option<&Extension<AuthContext>>,
) -> Option<Response> {
    require_admin_scope(
        state.config.pin_auth_enabled,
        auth.map(|extension| &extension.0),
    )
}

/// Text inference is sidecar-only in v1. This intentionally does not fall
/// back to a local ONNX encoder: standalone means no Python process, not no
/// `yu-infer` process.
pub(crate) async fn call_clip_text(
    state: &SharedState,
    text: String,
) -> Result<Vec<f32>, ClipCallError> {
    let client = state
        .infer_client
        .as_ref()
        .ok_or(ClipCallError::Unavailable)?;
    let value = client
        .infer_clip_text(text)
        .await
        .map_err(ClipCallError::Infer)?;
    parse_vector(value)
}

/// Canonicalizes and fail-closed validates a file against configured scan
/// roots before sending its bytes to the Hailo image sidecar.
pub(crate) async fn call_clip_image(
    state: &SharedState,
    path: &Path,
) -> Result<Vec<f32>, ClipCallError> {
    let path = validate_scan_path(state, path).ok_or(ClipCallError::PathRejected)?;
    let data = tokio::fs::read(path)
        .await
        .map_err(|error| ClipCallError::Io(error.to_string()))?;
    // yu-infer independently enforces the decoded/base64 budgets. This bound
    // avoids allocating an unbounded request before that second boundary.
    if data.len() > 16 * 1024 * 1024 {
        return Err(ClipCallError::Io(
            "image exceeds 16 MiB local read limit".to_string(),
        ));
    }
    let client = state
        .infer_client
        .as_ref()
        .ok_or(ClipCallError::Unavailable)?;
    use base64::Engine as _;
    let value = client
        .infer_clip_image(base64::engine::general_purpose::STANDARD.encode(data))
        .await
        .map_err(ClipCallError::Infer)?;
    parse_vector(value)
}

fn validate_scan_path(state: &SharedState, path: &Path) -> Option<std::path::PathBuf> {
    let real_path = std::fs::canonicalize(path).ok()?;
    let roots: Vec<std::path::PathBuf> = state
        .config
        .app_config
        .get("scan_roots")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|entry| entry.get("path").and_then(Value::as_str))
        .filter_map(|entry| std::fs::canonicalize(entry).ok())
        .collect();
    (!roots.is_empty() && roots.iter().any(|root| real_path.starts_with(root))).then_some(real_path)
}

#[derive(Debug)]
pub(crate) enum ClipCallError {
    Unavailable,
    PathRejected,
    Io(String),
    Infer(InferClientError),
    InvalidResponse,
}

fn parse_vector(value: Value) -> Result<Vec<f32>, ClipCallError> {
    let vector = value
        .get("data")
        .and_then(|data| data.get("vector"))
        .and_then(Value::as_array)
        .ok_or(ClipCallError::InvalidResponse)?
        .iter()
        .map(|entry| {
            entry
                .as_f64()
                .map(|value| value as f32)
                .filter(|value| value.is_finite())
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(ClipCallError::InvalidResponse)?;
    (vector.len() == 512)
        .then_some(vector)
        .ok_or(ClipCallError::InvalidResponse)
}

pub async fn search_handler(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
    Query(query): Query<SearchQuery>,
) -> Response {
    if let Some(response) = admin_or_response(&state, auth.as_ref()) {
        return response;
    }
    let query_text = query.q.as_deref().unwrap_or_default().trim().to_string();
    if query_text.is_empty() {
        return bad_request("Query parameter 'q' is required");
    }
    if query_text.chars().count() > MAX_QUERY_CHARS {
        return bad_request("Query too long (max 500 chars)");
    }
    let limit = match parse_limit(query.limit.as_deref()) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let threshold = match parse_threshold(query.threshold.as_deref()) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };

    let started = Instant::now();
    let vector = match call_clip_text(&state, query_text.clone()).await {
        Ok(vector) => vector,
        Err(ClipCallError::Unavailable) => {
            return service_unavailable("CLIP text encoder is unavailable")
        }
        Err(ClipCallError::Infer(InferClientError::BadStatus { status: 503, .. })) => {
            return service_unavailable("CLIP text encoder is unavailable")
        }
        Err(error) => {
            tracing::error!(?error, "CLIP text inference failed");
            return internal_error("Search failed");
        }
    };

    let allowed = match build_filter_ids(&state, &query).await {
        Ok(ids) => ids,
        Err(error) => {
            tracing::error!(%error, "CLIP filter query failed");
            return internal_error("Search filter failed");
        }
    };
    if let Err(error) = ensure_current_index(&state).await {
        tracing::error!(%error, "CLIP index load/rebuild failed");
        return internal_error("Search index unavailable");
    }
    // Match the Python FAISS path: request additional nearest candidates
    // before applying a SQL-derived allow-list, then cap the final response.
    let matches = match state.clip_index.search(
        &vector,
        candidate_limit(limit, allowed.is_some()),
        threshold,
    ) {
        Ok(matches) => matches,
        Err(error) => {
            tracing::error!(%error, "CLIP index search failed");
            return internal_error("Search failed");
        }
    };
    let matches: Vec<_> = matches
        .into_iter()
        .filter(|(file_id, _)| allowed.as_ref().is_none_or(|ids| ids.contains(file_id)))
        .take(limit)
        .collect();
    let paths = match vector_store::get_file_paths_by_ids(
        &state.db_read,
        &matches.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
    )
    .await
    {
        Ok(paths) => paths,
        Err(error) => {
            tracing::error!(%error, "CLIP result path lookup failed");
            return internal_error("Search failed");
        }
    };
    let results: Vec<Value> = matches
        .into_iter()
        .map(|(file_id, score)| {
            json!({
                "file_id": file_id,
                "path": paths.get(&file_id).cloned().unwrap_or_default(),
                "score": (score * 10_000.0).round() / 10_000.0,
            })
        })
        .collect();
    let indexed_count = state
        .clip_index
        .active_meta()
        .map_or(0, |meta| meta.vector_count);
    let status = if results.is_empty() { "empty" } else { "ok" };
    Json(json!({
        "status": status,
        "total": results.len(),
        "results": results,
        "query": query_text,
        "indexed_count": indexed_count,
        "threshold": threshold,
        "timing": {"total_ms": started.elapsed().as_millis(), "backend": "usearch"},
    }))
    .into_response()
}

pub async fn runtime_handler(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(response) = admin_or_response(&state, auth.as_ref()) {
        return response;
    }
    let counts = state
        .clip_runtime_cache
        .get_or_try_insert_with(|| async {
            let indexed =
                vector_store::count_indexed(&state.vectors_db_read, DEFAULT_MODEL).await?;
            let unindexed = vector_store::count_unindexed(
                &state.db_read,
                &state.vectors_db_read,
                DEFAULT_MODEL,
            )
            .await?;
            Ok::<_, vector_store::VectorStoreError>((indexed, unindexed))
        })
        .await;
    match counts {
        Ok((indexed_count, unindexed_count)) => Json(json!({
            "status": "ok", "indexed_count": indexed_count, "unindexed_count": unindexed_count,
            "backends": backends_payload(&state)["backends"].clone(),
            "auto_index_on_scan": false, "preferred_backend": "auto",
        }))
        .into_response(),
        Err(error) => {
            tracing::error!(%error, "CLIP runtime counts failed");
            internal_error("Runtime status unavailable")
        }
    }
}

pub async fn backends_handler(
    State(state): State<SharedState>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(response) = admin_or_response(&state, auth.as_ref()) {
        return response;
    }
    Json(backends_payload(&state)).into_response()
}

fn backends_payload(state: &SharedState) -> Value {
    let text_ready = super::clip_model::model_ready(&state.config.cache_dir);
    let hailo_available = state.infer_client.is_some();
    json!({
        "backends": [{
            "name": "hailo-10h", "available": hailo_available, "priority": 1,
            "status": {"image_backend": "hailo-10h", "sidecar_connected": hailo_available},
        }],
        // Deliberately separate from image backends: v1 has no ONNX image fallback.
        "text_backend": {"name": "onnx", "available": text_ready, "role": "text_encoder"},
        "any_available": hailo_available && text_ready,
    })
}

pub(crate) async fn ensure_current_index(
    state: &SharedState,
) -> Result<(), super::clip_index::ClipIndexError> {
    if let Some(meta) = state.clip_index.active_meta() {
        if !state
            .clip_index
            .is_drifted(&state.vectors_db_read, &meta)
            .await?
        {
            return Ok(());
        }
    }
    if !state
        .clip_index
        .load_if_current(&state.vectors_db_read)
        .await?
    {
        state
            .clip_index
            .rebuild(&state.vectors_db_read, None)
            .await?;
    }
    Ok(())
}

async fn build_filter_ids(
    state: &SharedState,
    args: &SearchQuery,
) -> Result<Option<HashSet<i64>>, sqlx::Error> {
    let mut builder = QueryBuilder::<Sqlite>::new("SELECT id FROM files WHERE is_deleted = 0");
    let mut has_filter = false;
    if let Some(format) = args
        .format
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "all")
    {
        let exts: &[&str] = if format == "image" {
            IMAGE_EXTENSIONS
        } else if format == "video" {
            VIDEO_EXTENSIONS
        } else {
            &[]
        };
        append_extensions(&mut builder, exts, &mut has_filter);
    }
    if let Some(exts) = args.format_exts.as_deref() {
        let valid: Vec<String> = exts
            .split(',')
            .map(str::trim)
            .map(|ext| ext.trim_start_matches('.'))
            .map(str::to_ascii_lowercase)
            .filter(|ext| {
                !ext.is_empty()
                    && ext.len() <= 10
                    && ext
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
            .collect();
        let valid_refs: Vec<&str> = valid.iter().map(String::as_str).collect();
        append_extensions(&mut builder, &valid_refs, &mut has_filter);
    }
    for (value, column, end_of_day) in [
        (args.from.as_deref(), "mtime", false),
        (args.to.as_deref(), "mtime", true),
    ] {
        if let Some(value) = value.and_then(parse_date) {
            has_filter = true;
            builder
                .push(" AND ")
                .push(column)
                .push(if end_of_day { " < " } else { " >= " })
                .push_bind(if end_of_day { value + 86_400 } else { value });
        }
    }
    if let Some(model) = args
        .model_filter
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "all")
    {
        has_filter = true;
        builder
            .push(" AND id IN (SELECT file_id FROM templates WHERE meta_source = ")
            .push_bind(model)
            .push(")");
    }
    for (value, column, op) in [
        (args.min_width.as_deref(), "width", ">="),
        (args.max_width.as_deref(), "width", "<="),
        (args.min_height.as_deref(), "height", ">="),
        (args.max_height.as_deref(), "height", "<="),
    ] {
        if let Some(value) = value
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
        {
            has_filter = true;
            builder
                .push(" AND ")
                .push(column)
                .push(" ")
                .push(op)
                .push(" ")
                .push_bind(value);
        }
    }
    if let Some(path) = args.in_path.as_deref().filter(|value| !value.is_empty()) {
        has_filter = true;
        builder
            .push(" AND path LIKE ")
            .push_bind(format!("%{path}%"));
    }
    if args.fav_only.as_deref() == Some("true") {
        has_filter = true;
        builder.push(" AND id IN (SELECT file_id FROM favorites)");
    }
    if !has_filter {
        return Ok(None);
    }
    Ok(Some(
        builder
            .build()
            .fetch_all(&state.db_read)
            .await?
            .into_iter()
            .map(|row| row.get("id"))
            .collect(),
    ))
}

fn append_extensions(
    builder: &mut QueryBuilder<Sqlite>,
    extensions: &[&str],
    has_filter: &mut bool,
) {
    if extensions.is_empty() {
        return;
    }
    *has_filter = true;
    builder.push(" AND (");
    for (index, extension) in extensions.iter().enumerate() {
        if index > 0 {
            builder.push(" OR ");
        }
        builder
            .push("lower(path) LIKE ")
            .push_bind(format!("%.{extension}"));
    }
    builder.push(")");
}

fn parse_date(value: &str) -> Option<i64> {
    Some(
        chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .ok()?
            .and_hms_opt(0, 0, 0)?
            .and_utc()
            .timestamp(),
    )
}

fn parse_limit(value: Option<&str>) -> Result<usize, &'static str> {
    match value {
        None | Some("") => Ok(DEFAULT_LIMIT),
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|value| (1..=MAX_LIMIT).contains(value))
            .ok_or("limit must be between 1 and 200"),
    }
}
fn parse_threshold(value: Option<&str>) -> Result<f32, &'static str> {
    match value {
        None | Some("") => Ok(DEFAULT_THRESHOLD),
        Some(value) => value
            .parse::<f32>()
            .ok()
            .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))
            .ok_or("threshold must be a finite value between 0.0 and 1.0"),
    }
}

fn candidate_limit(limit: usize, has_filter: bool) -> usize {
    limit.saturating_mul(if has_filter { 4 } else { 2 })
}
fn bad_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"status":"error", "message":message.into()})),
    )
        .into_response()
}
fn service_unavailable(message: impl Into<String>) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"status":"error", "message":message.into()})),
    )
        .into_response()
}
fn internal_error(message: impl Into<String>) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"status":"error", "message":message.into()})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_numeric_boundaries() {
        assert_eq!(parse_limit(Some("200")), Ok(200));
        assert!(parse_limit(Some("201")).is_err());
        assert_eq!(parse_threshold(Some("0")), Ok(0.0));
        assert_eq!(parse_threshold(Some("1")), Ok(1.0));
        assert!(parse_threshold(Some("NaN")).is_err());
        assert!(parse_threshold(Some("1.01")).is_err());
        assert_eq!(candidate_limit(50, false), 100);
        assert_eq!(candidate_limit(50, true), 200);
    }

    #[tokio::test]
    async fn read_routes_require_admin_scope() {
        let state = crate::state::semantic_test_state(true).await;
        let query = SearchQuery {
            q: Some("cat".to_string()),
            limit: None,
            threshold: None,
            format: None,
            format_exts: None,
            from: None,
            to: None,
            model_filter: None,
            min_width: None,
            max_width: None,
            min_height: None,
            max_height: None,
            in_path: None,
            fav_only: None,
        };
        assert_eq!(
            search_handler(State(state.clone()), None, Query(query))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            runtime_handler(State(state.clone()), None).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            backends_handler(State(state), None).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn search_rejects_empty_and_too_long_queries_before_inference() {
        let state = crate::state::semantic_test_state(false).await;
        for q in [
            "".to_string(),
            " ".to_string(),
            "x".repeat(MAX_QUERY_CHARS + 1),
        ] {
            let response = search_handler(
                State(state.clone()),
                None,
                Query(SearchQuery {
                    q: Some(q),
                    limit: None,
                    threshold: None,
                    format: None,
                    format_exts: None,
                    from: None,
                    to: None,
                    model_filter: None,
                    min_width: None,
                    max_width: None,
                    min_height: None,
                    max_height: None,
                    in_path: None,
                    fav_only: None,
                }),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
}
