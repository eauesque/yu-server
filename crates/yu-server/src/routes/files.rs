use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::state::SharedState;

async fn fwd_python_file(state: &SharedState, path: &str) -> Response {
    if state.config.python_url.is_empty() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
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

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct FileEntry {
    pub id: i64,
    pub path: String,
    pub mtime: i64,
}

pub async fn list_files(State(state): State<SharedState>) -> Response {
    match sqlx::query_as::<_, FileEntry>(
        "SELECT id, path, mtime FROM files ORDER BY path LIMIT 500",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(files) => Json(files).into_response(),
        Err(error) => {
            tracing::error!(?error, "failed to list files");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "internal_server_error",
                })),
            )
                .into_response()
        }
    }
}

fn guess_mime(path: &str) -> &'static str {
    match path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "avif" => "image/avif",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "mkv" => "video/x-matroska",
        "ogv" => "video/ogg",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "opus" => "audio/opus",
        "m4a" | "aac" => "audio/aac",
        "flac" => "audio/flac",
        _ => "application/octet-stream",
    }
}

fn is_av_or_pdf(ext: &str) -> bool {
    matches!(
        ext,
        "webm"
            | "mp4"
            | "mov"
            | "m4v"
            | "ogv"
            | "avi"
            | "mkv"
            | "mp3"
            | "wav"
            | "ogg"
            | "opus"
            | "m4a"
            | "aac"
            | "flac"
            | "pdf"
    )
}

fn parse_range(s: &str, size: u64) -> Option<(u64, u64)> {
    let s = s.strip_prefix("bytes=")?;
    let (a, b) = s.split_once('-')?;
    let start: u64 = a.parse().ok()?;
    let end: u64 = if b.is_empty() {
        size - 1
    } else {
        b.parse().ok()?
    };
    (start <= end && end < size).then_some((start, end))
}

async fn serve_range(
    path: PathBuf,
    mime: &'static str,
    etag: String,
    req_headers: &HeaderMap,
) -> Response {
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let size = match file.metadata().await {
        Ok(m) => m.len(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if req_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v == etag)
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }

    if let Some(range_val) = req_headers.get(header::RANGE) {
        if let Some((start, end)) = range_val.to_str().ok().and_then(|s| parse_range(s, size)) {
            let length = end - start + 1;
            let mut f = file;
            let _ = f.seek(std::io::SeekFrom::Start(start)).await;
            let body = Body::from_stream(ReaderStream::new(f.take(length)));
            return Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, mime)
                .header(header::ETAG, &etag)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{size}"))
                .body(body)
                .unwrap();
        }
        return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::ETAG, &etag)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, size.to_string())
        .body(Body::from_stream(ReaderStream::new(file)))
        .unwrap()
}

async fn lookup_file(state: &SharedState, file_id: i64) -> Result<(String, i64), Response> {
    match sqlx::query_as::<_, (String, i64)>("SELECT path, mtime FROM files WHERE id = ?")
        .bind(file_id)
        .fetch_optional(&state.db_read)
        .await
    {
        Ok(Some(row)) => Ok(row),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
            .into_response()),
        Err(e) => {
            tracing::error!(?e, "db lookup failed in files route");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

pub async fn serve_original(
    State(state): State<SharedState>,
    Path(file_id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let (path_str, mtime) = match lookup_file(&state, file_id).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if path_str.contains('!') {
        return fwd_python_file(&state, &format!("/api/file/{file_id}/original")).await;
    }

    let ext = path_str
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();

    if matches!(ext.as_str(), "heif" | "heic" | "jxl") {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "HEIF/JXL requires Python backend",
        )
            .into_response();
    }

    let file_path = PathBuf::from(&path_str);
    let Ok(meta) = tokio::fs::metadata(&file_path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let etag = format!("\"{:x}-{:x}\"", meta.len(), mtime as u64);
    let mime = guess_mime(&path_str);

    let mut resp = serve_range(file_path, mime, etag, &headers).await;
    if ext == "svg" {
        let h = resp.headers_mut();
        h.insert(
            "content-security-policy",
            HeaderValue::from_static(
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
            ),
        );
        h.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
    }
    resp
}

pub async fn serve_preview(
    State(state): State<SharedState>,
    Path(file_id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let (path_str, mtime) = match lookup_file(&state, file_id).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if path_str.contains('!') {
        return fwd_python_file(&state, &format!("/api/file/{file_id}/preview")).await;
    }

    let ext = path_str
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();

    // Video/audio/PDF: preview == original
    if is_av_or_pdf(&ext) {
        let file_path = PathBuf::from(&path_str);
        let Ok(meta) = tokio::fs::metadata(&file_path).await else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let etag = format!("\"{:x}-{:x}\"", meta.len(), mtime as u64);
        return serve_range(file_path, guess_mime(&path_str), etag, &headers).await;
    }

    // Cache key: sha256("preview:{path}:{mtime}")[:32 hex chars]
    let cache_key = {
        let mut h = Sha256::new();
        h.update(format!("preview:{path_str}:{mtime}").as_bytes());
        hex::encode(&h.finalize()[..16])
    };
    let cache_dir = state.config.cache_dir.join("previews");

    // Check disk cache (webp preferred, fall back to jpg)
    for cache_ext in ["webp", "jpg"] {
        let p = cache_dir.join(format!("{cache_key}.{cache_ext}"));
        if let Ok(meta) = tokio::fs::metadata(&p).await {
            let ts = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let etag = format!("\"{:x}-{:x}\"", meta.len(), ts);
            let mime = if cache_ext == "webp" {
                "image/webp"
            } else {
                "image/jpeg"
            };
            let mut resp = serve_range(p, mime, etag, &headers).await;
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400, stale-while-revalidate=604800"),
            );
            return resp;
        }
    }

    // Cache miss — check file on disk
    let file_path = PathBuf::from(&path_str);
    let Ok(meta) = tokio::fs::metadata(&file_path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let file_size = meta.len();
    let etag = format!("\"{:x}-{:x}\"", file_size, mtime as u64);
    let mime = guess_mime(&path_str);

    // Small file: serve directly without generating a preview
    if file_size < 200 * 1024 {
        return serve_range(file_path, mime, etag, &headers).await;
    }

    if matches!(ext.as_str(), "heif" | "heic" | "jxl") {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "HEIF/JXL requires Python backend",
        )
            .into_response();
    }

    // Generate resized preview (blocking — CPU-bound image work)
    let _ = tokio::fs::create_dir_all(&cache_dir).await;
    let dest = cache_dir.join(format!("{cache_key}.webp"));
    let src = file_path.clone();
    let result = tokio::task::spawn_blocking(move || generate_preview_sync(&src, &dest)).await;

    match result {
        Ok(Ok(generated)) => {
            let Ok(gm) = std::fs::metadata(&generated) else {
                return serve_range(file_path, mime, etag, &headers).await;
            };
            let ts = gm
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let gen_etag = format!("\"{:x}-{:x}\"", gm.len(), ts);
            let gen_mime = match generated.extension().and_then(|e| e.to_str()) {
                Some("webp") => "image/webp",
                _ => "image/jpeg",
            };
            let mut resp = serve_range(generated, gen_mime, gen_etag, &headers).await;
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400, stale-while-revalidate=604800"),
            );
            resp
        }
        _ => serve_range(file_path, mime, etag, &headers).await,
    }
}

fn generate_preview_sync(
    src: &std::path::Path,
    dest: &std::path::Path,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    use image::GenericImageView;

    let img = image::open(src)?;
    let (w, h) = img.dimensions();
    if w.max(h) <= 1200 {
        return Ok(src.to_path_buf());
    }

    let max_dim = w.max(h) as f64;
    let resized = img.resize(
        ((w as f64 * 1200.0 / max_dim) as u32).max(1),
        ((h as f64 * 1200.0 / max_dim) as u32).max(1),
        image::imageops::FilterType::CatmullRom,
    );

    // Write to .tmp then rename for atomicity
    let tmp = dest.with_extension("webp.tmp");
    let mut buf = std::io::Cursor::new(Vec::<u8>::new());
    if resized.write_to(&mut buf, image::ImageFormat::WebP).is_ok() {
        std::fs::write(&tmp, buf.into_inner())?;
        std::fs::rename(&tmp, dest)?;
        return Ok(dest.to_path_buf());
    }

    // WebP failed — fall back to JPEG
    let jpg = dest.with_extension("jpg");
    let tmp_jpg = dest.with_extension("jpg.tmp");
    let mut f = std::fs::File::create(&tmp_jpg)?;
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut f, 82).encode_image(&resized)?;
    drop(f);
    std::fs::rename(&tmp_jpg, &jpg)?;
    Ok(jpg)
}

/// Resolve the preview file path for a given source path + mtime.
/// Returns (path, mime) or None on error/unsupported.
async fn resolve_preview_path(
    state: &SharedState,
    path_str: &str,
    mtime: i64,
) -> Option<(PathBuf, &'static str)> {
    if path_str.contains('!') {
        return None;
    }
    let ext = path_str
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if is_av_or_pdf(&ext) {
        let p = PathBuf::from(path_str);
        tokio::fs::metadata(&p).await.ok()?;
        return Some((p, guess_mime(path_str)));
    }
    if matches!(ext.as_str(), "heif" | "heic" | "jxl") {
        return None;
    }
    let cache_key = {
        let mut h = Sha256::new();
        h.update(format!("preview:{path_str}:{mtime}").as_bytes());
        hex::encode(&h.finalize()[..16])
    };
    let cache_dir = state.config.cache_dir.join("previews");
    for cache_ext in ["webp", "jpg"] {
        let p = cache_dir.join(format!("{cache_key}.{cache_ext}"));
        if tokio::fs::metadata(&p).await.is_ok() {
            let mime = if cache_ext == "webp" {
                "image/webp"
            } else {
                "image/jpeg"
            };
            return Some((p, mime));
        }
    }
    let file_path = PathBuf::from(path_str);
    let Ok(meta) = tokio::fs::metadata(&file_path).await else {
        return None;
    };
    if meta.len() < 200 * 1024 {
        return Some((file_path, guess_mime(path_str)));
    }
    let _ = tokio::fs::create_dir_all(&cache_dir).await;
    let dest = cache_dir.join(format!("{cache_key}.webp"));
    let src = file_path.clone();
    match tokio::task::spawn_blocking(move || generate_preview_sync(&src, &dest)).await {
        Ok(Ok(generated)) if std::fs::metadata(&generated).is_ok() => {
            let mime = match generated.extension().and_then(|e| e.to_str()) {
                Some("webp") => "image/webp",
                _ => "image/jpeg",
            };
            Some((generated, mime))
        }
        _ => Some((file_path, guess_mime(path_str))),
    }
}

pub async fn thumbnails_warmup(
    State(state): State<SharedState>,
    body: axum::body::Bytes,
) -> Response {
    let data = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(serde_json::Value::Object(data)) => data,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "JSON object body is required",
                    "code": "invalid_json_object"
                })),
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid JSON body",
                    "code": "invalid_json"
                })),
            )
                .into_response()
        }
    };
    let Some(values) = data
        .get("file_ids")
        .and_then(serde_json::Value::as_array)
        .filter(|values| !values.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "file_ids required"})),
        )
            .into_response();
    };
    let file_ids: Vec<i64> = values
        .iter()
        .take(2000)
        .filter_map(|value| match value {
            serde_json::Value::Number(number) => number
                .as_i64()
                .filter(|id| *id > 0)
                .or_else(|| number.as_f64().filter(|id| *id > 0.0).map(|id| id as i64)),
            serde_json::Value::Bool(true) => Some(1),
            _ => None,
        })
        .collect();
    let count = file_ids.len();
    let mut key_ids = file_ids.iter().copied().take(100).collect::<Vec<_>>();
    key_ids.sort_unstable();
    let mut hasher = Sha256::new();
    for id in key_ids {
        hasher.update(id.to_le_bytes());
    }
    let job_id = format!("thumbnail-warmup:{}", hex::encode(hasher.finalize()));
    let started = state
        .job_manager
        .start_if_idle(&job_id, "Thumbnail warmup")
        .is_some();
    if started {
        let state = state.clone();
        tokio::spawn(async move {
            for id in file_ids {
                if let Ok((path, mtime)) = lookup_file(&state, id).await {
                    let _ = resolve_preview_path(&state, &path, mtime).await;
                }
            }
            state.job_manager.finish(&job_id, None, None);
        });
    }
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"ok": true, "started": started, "count": count})),
    )
        .into_response()
}

pub async fn thumbnails_batch(
    State(state): State<SharedState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let ids: Vec<i64> = body
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_i64()).take(50).collect())
        .unwrap_or_default();

    let mut handles = Vec::with_capacity(ids.len());
    for &id in &ids {
        let state2 = state.clone();
        handles.push(tokio::spawn(async move {
            let (path_str, mtime) = lookup_file(&state2, id).await.ok()?;
            let (preview_path, mime) = resolve_preview_path(&state2, &path_str, mtime).await?;
            let bytes = tokio::fs::read(&preview_path).await.ok()?;
            Some((
                id,
                format!("data:{mime};base64,{}", STANDARD.encode(&bytes)),
            ))
        }));
    }

    let mut thumbnails = serde_json::Map::new();
    for handle in handles {
        if let Ok(Some((id, data_url))) = handle.await {
            thumbnails.insert(id.to_string(), serde_json::Value::String(data_url));
        }
    }
    Json(serde_json::json!({ "thumbnails": thumbnails })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashSet, path::PathBuf, str::FromStr, sync::Arc};

    use axum::body::to_bytes;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use crate::state::{AppState, Config};

    async fn test_state_with_cache(cache_dir: PathBuf) -> SharedState {
        let pool = SqlitePoolOptions::new()
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TABLE files (
               id INTEGER PRIMARY KEY,
               path TEXT NOT NULL UNIQUE,
               mtime INTEGER NOT NULL
             );
             INSERT INTO files(id, path, mtime) VALUES
               (1, '/z.png', 300),
               (2, '/a.png', 100);",
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
                    app_config: serde_json::json!({}),
                    cache_dir,
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

    async fn test_state() -> SharedState {
        test_state_with_cache(PathBuf::from(".")).await
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn thumbnails_warmup_requires_nonempty_file_ids_list() {
        for body in [
            serde_json::json!({}),
            serde_json::json!({"file_ids": []}),
            serde_json::json!({"file_ids": "1"}),
        ] {
            let response = thumbnails_warmup(
                State(test_state().await),
                serde_json::to_vec(&body).unwrap().into(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response_json(response).await,
                serde_json::json!({"error": "file_ids required"})
            );
        }
    }

    #[tokio::test]
    async fn thumbnails_warmup_reports_malformed_json_separately() {
        let response = thumbnails_warmup(State(test_state().await), "{".into()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await,
            serde_json::json!({"error": "Invalid JSON body", "code": "invalid_json"})
        );
    }

    #[tokio::test]
    async fn thumbnails_warmup_truncates_to_2000_ids() {
        let body = serde_json::json!({"file_ids": (1..=3000).collect::<Vec<_>>()});
        let response = thumbnails_warmup(
            State(test_state().await),
            serde_json::to_vec(&body).unwrap().into(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response_json(response).await["count"], 2000);
    }

    #[tokio::test]
    async fn thumbnails_warmup_filters_ids_before_counting() {
        let body = serde_json::json!({"file_ids": [0, -1, "2", null, {}, 3.9, 2]});
        let response = thumbnails_warmup(
            State(test_state().await),
            serde_json::to_vec(&body).unwrap().into(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response_json(response).await["count"], 2);
    }

    #[tokio::test]
    async fn thumbnails_warmup_deduplicates_an_in_flight_set() {
        let state = test_state().await;
        let body: axum::body::Bytes = serde_json::to_vec(&serde_json::json!({
            "file_ids": [2, 1]
        }))
        .unwrap()
        .into();
        let first = thumbnails_warmup(State(state.clone()), body.clone()).await;
        let second = thumbnails_warmup(State(state), body).await;

        assert_eq!(first.status(), StatusCode::ACCEPTED);
        assert_eq!(second.status(), StatusCode::ACCEPTED);
        assert_eq!(response_json(first).await["started"], true);
        assert_eq!(response_json(second).await["started"], false);
    }

    #[tokio::test]
    async fn thumbnails_warmup_allows_different_sets_in_flight() {
        let state = test_state().await;
        let first = thumbnails_warmup(
            State(state.clone()),
            serde_json::to_vec(&serde_json::json!({"file_ids": [1]}))
                .unwrap()
                .into(),
        )
        .await;
        let second = thumbnails_warmup(
            State(state),
            serde_json::to_vec(&serde_json::json!({"file_ids": [2]}))
                .unwrap()
                .into(),
        )
        .await;

        assert_eq!(response_json(first).await["started"], true);
        assert_eq!(response_json(second).await["started"], true);
    }

    #[tokio::test]
    async fn thumbnails_warmup_populates_preview_cache() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.bmp");
        image::RgbImage::new(1201, 1201).save(&source).unwrap();
        let cache_dir = temp.path().join("cache");
        let state = test_state_with_cache(cache_dir.clone()).await;
        sqlx::query("UPDATE files SET path = ?, mtime = 123 WHERE id = 1")
            .bind(source.to_string_lossy().as_ref())
            .execute(&state.db)
            .await
            .unwrap();

        let response = thumbnails_warmup(
            State(state),
            serde_json::to_vec(&serde_json::json!({"file_ids": [1]}))
                .unwrap()
                .into(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response_json(response).await["started"], true);

        let path = source.to_string_lossy();
        let mut hasher = Sha256::new();
        hasher.update(format!("preview:{path}:123").as_bytes());
        let cache_key = hex::encode(&hasher.finalize()[..16]);
        let preview = cache_dir.join("previews").join(format!("{cache_key}.webp"));
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while tokio::fs::metadata(&preview).await.is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("preview cache was not populated");
    }

    #[tokio::test]
    async fn list_files_returns_files_ordered_by_path() {
        let response = list_files(State(test_state().await)).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let files: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(files[0]["id"], 2);
        assert_eq!(files[0]["path"], "/a.png");
        assert_eq!(files[0]["mtime"], 100);
        assert_eq!(files[1]["path"], "/z.png");
    }

    #[tokio::test]
    async fn list_files_returns_500_json_on_query_error() {
        let pool = SqlitePoolOptions::new()
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:").unwrap())
            .await
            .unwrap();
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
                    config_path: PathBuf::from("config.json"),
                    project_root: PathBuf::from("."),
                    app_config: serde_json::json!({}),
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
        );

        let response = list_files(State(state)).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "internal_server_error");
    }
}
