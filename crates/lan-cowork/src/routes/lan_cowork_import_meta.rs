//! LAN Cowork remote-import metadata queries.

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use axum::{
    body::{Body, Bytes},
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{Map, Value};
use sqlx::{
    sqlite::{SqliteRow, SqliteValueRef},
    Decode, QueryBuilder, Row, Sqlite, SqlitePool, TypeInfo, ValueRef,
};
use tokio::sync::Semaphore;
use tokio_util::io::ReaderStream;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

use crate::{auth::peer_transport::require_peer_auth, routes::lan_cowork_host::LanCoworkState};

pub(crate) const IN_CHUNK_SIZE: usize = 500;
const ZIP_BUILD_PERMITS: usize = 32;
const FILE_COLUMNS: &[&str] = &[
    "id",
    "path",
    "hash",
    "phash",
    "mtime",
    "size",
    "width",
    "height",
    "meta_source",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetaMode {
    Index,
    Full,
}

pub fn chunks<T>(items: &[T], size: usize) -> impl Iterator<Item = &[T]> {
    items.chunks(size)
}

pub(crate) fn unique_file_ids<T: Eq + std::hash::Hash + Clone>(file_ids: &[T]) -> Vec<T> {
    let mut seen = HashSet::new();
    file_ids
        .iter()
        .filter(|id| seen.insert(*id))
        .cloned()
        .collect()
}

/// Return only the basename for peer-facing metadata payloads.
pub fn redact_file_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    // Python pathlib returns ".." here, but Path::file_name returns None and thus an
    // empty string. A filesystem basename cannot literally be "..", so deliberately
    // accept this fail-closed divergence to avoid exposing more path information.
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn sqlite_value_to_json(value: SqliteValueRef<'_>) -> Result<Value, sqlx::Error> {
    if value.is_null() {
        return Ok(Value::Null);
    }
    match value.type_info().name() {
        "INTEGER" => Ok(Value::from(
            <i64 as Decode<Sqlite>>::decode(value).map_err(sqlx::Error::Decode)?,
        )),
        "REAL" => Ok(Value::from(
            <f64 as Decode<Sqlite>>::decode(value).map_err(sqlx::Error::Decode)?,
        )),
        "TEXT" => Ok(Value::String(
            <String as Decode<Sqlite>>::decode(value).map_err(sqlx::Error::Decode)?,
        )),
        "BLOB" => Ok(Value::String(
            String::from_utf8(
                <Vec<u8> as Decode<Sqlite>>::decode(value).map_err(sqlx::Error::Decode)?,
            )
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
        )),
        _ => Err(sqlx::Error::Protocol(
            "unsupported SQLite value type".into(),
        )),
    }
}

fn row_to_object(row: &SqliteRow, columns: &[&str]) -> Result<Value, sqlx::Error> {
    let mut object = Map::new();
    for column in columns {
        object.insert(
            (*column).into(),
            sqlite_value_to_json(row.try_get_raw(*column)?)?,
        );
    }
    Ok(Value::Object(object))
}

fn annotation_value(value: SqliteValueRef<'_>) -> Result<(Value, &'static str), sqlx::Error> {
    if !value.is_null() && value.type_info().name() == "BLOB" {
        let bytes = <Vec<u8> as Decode<Sqlite>>::decode(value).map_err(sqlx::Error::Decode)?;
        return Ok(match String::from_utf8(bytes) {
            Ok(text) => (Value::String(text), "utf8"),
            Err(error) => (Value::String(STANDARD.encode(error.into_bytes())), "base64"),
        });
    }
    Ok((sqlite_value_to_json(value)?, "utf8"))
}

pub async fn query_files_full(
    pool: &SqlitePool,
    after_rowid: Option<i64>,
) -> Result<(Vec<Value>, i64), sqlx::Error> {
    let rows = match after_rowid {
        Some(after_rowid) => {
            sqlx::query(
                "SELECT id,path,hash,phash,mtime,size,width,height,meta_source \
             FROM files WHERE is_deleted=0 AND id>? ORDER BY id",
            )
            .bind(after_rowid)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query(
                "SELECT id,path,hash,phash,mtime,size,width,height,meta_source \
             FROM files WHERE is_deleted=0 ORDER BY id",
            )
            .fetch_all(pool)
            .await?
        }
    };
    let files = rows
        .iter()
        .map(|row| row_to_object(row, FILE_COLUMNS))
        .collect::<Result<Vec<_>, _>>()?;
    let max_rowid = files
        .last()
        .and_then(|file| file["id"].as_i64())
        .unwrap_or_else(|| after_rowid.unwrap_or(0));
    Ok((files, max_rowid))
}

pub async fn query_tags(
    pool: &SqlitePool,
    file_ids: &[i64],
) -> Result<HashMap<String, Vec<String>>, sqlx::Error> {
    let ids = unique_file_ids(file_ids);
    let mut result = HashMap::new();
    for chunk in chunks(&ids, IN_CHUNK_SIZE) {
        let mut query = QueryBuilder::<Sqlite>::new(
            "SELECT ft.file_id, t.tag FROM file_tags ft JOIN tags t ON ft.tag_id=t.id WHERE ft.file_id IN (",
        );
        let mut separated = query.separated(",");
        for id in chunk {
            separated.push_bind(id);
        }
        separated.push_unseparated(")");
        // SQLite does not guarantee this SELECT's row order; callers/tests sort if needed.
        for row in query.build().fetch_all(pool).await? {
            let file_id = sqlite_value_to_json(row.try_get_raw("file_id")?)?;
            let tag = sqlite_value_to_json(row.try_get_raw("tag")?)?;
            if let (Some(file_id), Some(tag)) = (file_id.as_i64(), tag.as_str()) {
                result
                    .entry(file_id.to_string())
                    .or_insert_with(Vec::new)
                    .push(tag.into());
            }
        }
    }
    Ok(result)
}

pub async fn query_collections(pool: &SqlitePool) -> Result<Vec<Value>, sqlx::Error> {
    sqlx::query("SELECT id,name FROM collections")
        .fetch_all(pool)
        .await?
        .iter()
        .map(|row| row_to_object(row, &["id", "name"]))
        .collect()
}

pub async fn query_ratings(
    pool: &SqlitePool,
    file_ids: &[i64],
) -> Result<HashMap<String, Value>, sqlx::Error> {
    let ids = unique_file_ids(file_ids);
    let mut result = HashMap::new();
    for chunk in chunks(&ids, IN_CHUNK_SIZE) {
        let mut query = QueryBuilder::<Sqlite>::new(
            "SELECT file_id,rating FROM file_ratings WHERE file_id IN (",
        );
        let mut separated = query.separated(",");
        for id in chunk {
            separated.push_bind(id);
        }
        separated.push_unseparated(")");
        for row in query.build().fetch_all(pool).await? {
            let file_id = sqlite_value_to_json(row.try_get_raw("file_id")?)?;
            let rating = sqlite_value_to_json(row.try_get_raw("rating")?)?;
            if let Some(file_id) = file_id.as_i64() {
                result.insert(file_id.to_string(), rating);
            }
        }
    }
    Ok(result)
}

pub async fn query_annotations(
    pool: &SqlitePool,
    file_ids: &[i64],
) -> Result<HashMap<String, Vec<Value>>, sqlx::Error> {
    let ids = unique_file_ids(file_ids);
    let mut result = HashMap::new();
    for chunk in chunks(&ids, IN_CHUNK_SIZE) {
        let mut query = QueryBuilder::<Sqlite>::new(
            "SELECT file_id,source,key,value,confidence,created_at FROM file_annotations WHERE file_id IN (",
        );
        let mut separated = query.separated(",");
        for id in chunk {
            separated.push_bind(id);
        }
        separated.push_unseparated(")");
        // SQLite does not guarantee this SELECT's row order; callers/tests sort if needed.
        for row in query.build().fetch_all(pool).await? {
            let file_id = sqlite_value_to_json(row.try_get_raw("file_id")?)?;
            let (value, value_enc) = annotation_value(row.try_get_raw("value")?)?;
            let mut annotation = Map::new();
            for column in ["source", "key", "confidence", "created_at"] {
                annotation.insert(
                    column.into(),
                    sqlite_value_to_json(row.try_get_raw(column)?)?,
                );
            }
            annotation.insert("value".into(), value);
            annotation.insert("value_enc".into(), Value::String(value_enc.into()));
            if let Some(file_id) = file_id.as_i64() {
                result
                    .entry(file_id.to_string())
                    .or_insert_with(Vec::new)
                    .push(Value::Object(annotation));
            }
        }
    }
    Ok(result)
}

/// Returns a raw local path; never include it in a peer-facing payload.
pub async fn query_file_path(
    pool: &SqlitePool,
    file_id: i64,
) -> Result<Option<String>, sqlx::Error> {
    let Some(row) = sqlx::query("SELECT path FROM files WHERE id=? AND is_deleted=0")
        .bind(file_id)
        .fetch_optional(pool)
        .await?
    else {
        return Ok(None);
    };
    let path = sqlite_value_to_json(row.try_get_raw("path")?)?;
    match path {
        Value::String(path) => Ok(Some(path)),
        _ => Err(sqlx::Error::Protocol("file path is not text".into())),
    }
}

pub async fn build_meta_response(
    pool: &SqlitePool,
    mode: MetaMode,
    after_rowid: Option<i64>,
) -> Result<Value, sqlx::Error> {
    let (mut files, max_rowid) = query_files_full(pool, after_rowid).await?;
    for file in &mut files {
        if let Some(object) = file.as_object_mut() {
            let path = object
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default();
            object.insert("path".into(), Value::String(redact_file_path(path)));
        }
    }
    let file_ids = files
        .iter()
        .filter_map(|file| file["id"].as_i64())
        .collect::<Vec<_>>();
    let tags = query_tags(pool, &file_ids).await?;
    let mut response = Map::new();
    response.insert(
        "tags".into(),
        serde_json::to_value(tags).expect("string map serializes"),
    );
    response.insert("max_rowid".into(), Value::from(max_rowid));
    match mode {
        MetaMode::Index => {
            let slim = files
                .into_iter()
                .map(|file| {
                    let object = file.as_object().expect("file object");
                    Value::Object(
                        ["id", "path", "hash", "phash", "size"]
                            .into_iter()
                            .filter_map(|key| {
                                object.get(key).cloned().map(|value| (key.into(), value))
                            })
                            .collect(),
                    )
                })
                .collect();
            response.insert("files".into(), Value::Array(slim));
        }
        MetaMode::Full => {
            response.insert("files".into(), Value::Array(files));
            response.insert(
                "collections".into(),
                Value::Array(query_collections(pool).await?),
            );
            response.insert(
                "file_ratings".into(),
                serde_json::to_value(query_ratings(pool, &file_ids).await?)
                    .expect("string map serializes"),
            );
            response.insert(
                "file_annotations".into(),
                serde_json::to_value(query_annotations(pool, &file_ids).await?)
                    .expect("string map serializes"),
            );
        }
    }
    Ok(Value::Object(response))
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (urlencoding::decode(key).ok()?.as_ref() == name)
            .then(|| {
                urlencoding::decode(value)
                    .ok()
                    .map(|value| value.into_owned())
            })
            .flatten()
    })
}

fn parse_path_file_id(file_id: &str) -> Option<i64> {
    (!file_id.is_empty() && file_id.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| file_id.parse().ok())
        .flatten()
}

fn import_path_is_denied(path: &Path) -> bool {
    let path = crate::path_guard::normalize_path(path);
    let normalize_base = |base: &Path| {
        std::fs::canonicalize(base)
            .ok()
            .map(|base| crate::path_guard::normalize_path(&base))
    };
    let path_starts_with = |base: &Path| crate::path_guard::path_is_within(&path, base);
    if path.parent().is_none() {
        return true;
    }
    if Path::new("/").exists()
        && [
            "/etc",
            "/bin",
            "/sbin",
            "/boot",
            "/dev",
            "/proc",
            "/run",
            "/sys",
            "/lib",
            "/lib64",
            "/usr/bin",
            "/usr/sbin",
            "/usr/lib",
            "/usr/lib64",
            "/usr/local/bin",
            "/usr/local/lib",
        ]
        .iter()
        .filter_map(|denied| normalize_base(Path::new(denied)))
        .any(|base| path_starts_with(&base))
    {
        return true;
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        if let Some(home) = normalize_base(&PathBuf::from(home)) {
            if path_starts_with(&home)
                && path
                    .components()
                    .nth(home.components().count())
                    .is_some_and(|component| {
                        component.as_os_str().to_string_lossy().starts_with('.')
                    })
            {
                return true;
            }
        }
    }
    #[cfg(windows)]
    if std::env::var_os("APPDATA")
        .into_iter()
        .chain(std::env::var_os("LOCALAPPDATA"))
        .filter_map(|denied| normalize_base(Path::new(&denied)))
        .any(|base| path_starts_with(&base))
        || [
            r"C:\Windows",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ]
        .iter()
        .filter_map(|denied| normalize_base(Path::new(denied)))
        .any(|base| path_starts_with(&base))
    {
        return true;
    }
    false
}

fn readable_import_path(path: &str) -> Option<PathBuf> {
    let path = std::fs::canonicalize(path).ok()?;
    (!import_path_is_denied(&path)
        && std::fs::metadata(&path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false))
    .then_some(path)
}

async fn query_file_paths(
    pool: &SqlitePool,
    file_ids: &[i64],
) -> Result<HashMap<i64, String>, sqlx::Error> {
    let mut paths = HashMap::new();
    for chunk in chunks(&unique_file_ids(file_ids), IN_CHUNK_SIZE) {
        let mut query = QueryBuilder::<Sqlite>::new("SELECT id,path FROM files WHERE id IN (");
        let mut separated = query.separated(",");
        for file_id in chunk {
            separated.push_bind(file_id);
        }
        separated.push_unseparated(") AND is_deleted=0");
        for row in query.build().fetch_all(pool).await? {
            paths.insert(row.try_get("id")?, row.try_get("path")?);
        }
    }
    Ok(paths)
}

fn zip_build_semaphore() -> Arc<Semaphore> {
    static SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEMAPHORE
        .get_or_init(|| Arc::new(Semaphore::new(ZIP_BUILD_PERMITS)))
        .clone()
}

fn build_import_zip(
    file_ids: Vec<i64>,
    path_by_id: HashMap<i64, String>,
) -> Result<Option<File>, Box<dyn std::error::Error + Send + Sync>> {
    let file = tempfile::tempfile()?;
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .large_file(true);
    let mut count = 0;
    for file_id in file_ids {
        let Some(path) = path_by_id.get(&file_id) else {
            continue;
        };
        let Some(path) = readable_import_path(path) else {
            continue;
        };
        let basename = redact_file_path(path.to_string_lossy().as_ref());
        if basename.is_empty() {
            continue;
        }
        let arcname = format!("{file_id}/{basename}");
        if let Err(error) = writer.start_file(&arcname, options) {
            tracing::warn!(file_id, "lan_cowork import zip entry read failed");
            return Err(Box::new(error));
        }
        let mut source = match File::open(path) {
            Ok(source) => source,
            Err(error) => {
                tracing::warn!(file_id, "lan_cowork import zip entry read failed");
                return Err(Box::new(error));
            }
        };
        if let Err(error) = std::io::copy(&mut source, &mut writer) {
            tracing::warn!(file_id, "lan_cowork import zip entry read failed");
            return Err(Box::new(error));
        }
        count += 1;
    }
    if count == 0 {
        return Ok(None);
    }
    let mut file = writer.finish()?;
    file.seek(SeekFrom::Start(0))?;
    Ok(Some(file))
}

fn internal_error_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"ok": false, "error": "internal error"})),
    )
        .into_response()
}

fn success_response(data: Value) -> Response {
    let Some(mut data) = data.as_object().cloned() else {
        return internal_error_response();
    };
    data.insert("ok".into(), Value::Bool(true));
    Json(Value::Object(data)).into_response()
}

async fn import_meta(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = require_peer_auth(
        &*state,
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or(""),
        &headers,
        &body,
    )
    .await
    {
        return response;
    }
    let mode = match query_param(uri.query().unwrap_or(""), "mode").as_deref() {
        None | Some("full") => MetaMode::Full,
        Some("index") => MetaMode::Index,
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "error": "invalid mode"})),
            )
                .into_response()
        }
    };
    match build_meta_response(state.db_read(), mode, None).await {
        Ok(data) => success_response(data),
        Err(error) => {
            tracing::warn!(error_kind = ?std::mem::discriminant(&error), "lan_cowork import metadata query failed");
            internal_error_response()
        }
    }
}

async fn import_diff(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = require_peer_auth(
        &*state,
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or(""),
        &headers,
        &body,
    )
    .await
    {
        return response;
    }
    let after_rowid = query_param(uri.query().unwrap_or(""), "after_rowid")
        .and_then(|value| value.trim().parse().ok())
        .filter(|value: &i64| *value != 0);
    match build_meta_response(state.db_read(), MetaMode::Full, after_rowid).await {
        Ok(data) => success_response(data),
        Err(error) => {
            tracing::warn!(error_kind = ?std::mem::discriminant(&error), "lan_cowork import diff query failed");
            internal_error_response()
        }
    }
}

async fn import_file_response(
    state: LanCoworkState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    file_id: String,
) -> Response {
    if let Err(response) = require_peer_auth(
        &*state,
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or(""),
        &headers,
        &body,
    )
    .await
    {
        return response;
    }
    let Some(file_id) = parse_path_file_id(&file_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let path = match query_file_path(state.db_read(), file_id).await {
        Ok(Some(path)) => path,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"ok": false, "error": "file not found"})),
            )
                .into_response()
        }
        Err(error) => {
            tracing::warn!(error_kind = ?std::mem::discriminant(&error), "lan_cowork import file query failed");
            return internal_error_response();
        }
    };
    let Some(path) = readable_import_path(&path) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"ok": false, "error": "file missing on disk"})),
        )
            .into_response();
    };
    match tokio::fs::File::open(path).await {
        Ok(file) => {
            let mut response = Response::new(Body::from_stream(ReaderStream::new(file)));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            response
        }
        Err(_) => {
            tracing::warn!("lan_cowork import file open failed");
            internal_error_response()
        }
    }
}

async fn import_file(
    State(state): State<LanCoworkState>,
    AxumPath(file_id): AxumPath<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    import_file_response(state, method, uri, headers, body, file_id).await
}

async fn import_stream(
    State(state): State<LanCoworkState>,
    AxumPath(file_id): AxumPath<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    import_file_response(state, method, uri, headers, body, file_id).await
}

async fn import_zip(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = require_peer_auth(
        &*state,
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or(""),
        &headers,
        &body,
    )
    .await
    {
        return response;
    }
    let ids = query_param(uri.query().unwrap_or(""), "ids").unwrap_or_default();
    let file_ids = match ids
        .split(',')
        .filter_map(|id| (!id.trim().is_empty()).then_some(id.trim()))
        .map(str::parse::<i64>)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(ids) if !ids.is_empty() => ids,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "error": "no ids"})),
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "error": "invalid ids"})),
            )
                .into_response()
        }
    };
    let file_ids = unique_file_ids(&file_ids);
    let path_by_id = match query_file_paths(state.db_read(), &file_ids).await {
        Ok(paths) => paths,
        Err(error) => {
            tracing::warn!(error_kind = ?std::mem::discriminant(&error), "lan_cowork import zip query failed");
            return internal_error_response();
        }
    };
    let permit = zip_build_semaphore()
        .acquire_owned()
        .await
        .expect("import zip semaphore is never closed");
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        build_import_zip(file_ids, path_by_id)
    })
    .await;
    match result {
        Ok(Ok(Some(file))) => {
            let mut response = Response::new(Body::from_stream(ReaderStream::new(
                tokio::fs::File::from_std(file),
            )));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/zip"),
            );
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=import.zip"),
            );
            response
        }
        Ok(Ok(None)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"ok": false, "error": "no files"})),
        )
            .into_response(),
        Ok(Err(_)) | Err(_) => internal_error_response(),
    }
}

pub fn routes() -> Router<LanCoworkState> {
    Router::new()
        .route("/ext/lan_cowork/api/peer/import/meta", get(import_meta))
        .route("/ext/lan_cowork/api/peer/import/diff", get(import_diff))
        .route(
            "/ext/lan_cowork/api/peer/import/file/{file_id}",
            get(import_file),
        )
        .route("/ext/lan_cowork/api/peer/import/zip", get(import_zip))
        .route(
            "/ext/lan_cowork/api/peer/import/stream/{file_id}",
            get(import_stream),
        )
}

pub fn import_routes(enabled: bool) -> Router<LanCoworkState> {
    if enabled {
        routes()
    } else {
        Router::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, time::Duration};

    use axum::{body::to_bytes, http::Request};
    use serde_json::json;
    use sqlx::sqlite::SqlitePoolOptions;
    use tower::ServiceExt;

    use crate::schema::apply_standalone_schema;
    use crate::state::{semantic_test_state_with, SharedState};

    const VECTORS: &str = include_str!("../../tests/vectors/import_meta_vectors.json");
    const DENY_PATH_VECTORS: &str =
        include_str!("../../tests/vectors/import_deny_paths_vectors.json");
    const DDL: &str = "
        CREATE TABLE files (id INTEGER, path TEXT, hash TEXT, phash TEXT, mtime INTEGER, size INTEGER, width INTEGER, height INTEGER, meta_source TEXT, is_deleted INTEGER);
        CREATE TABLE tags (id INTEGER, tag TEXT);
        CREATE TABLE file_tags (file_id INTEGER, tag_id INTEGER);
        CREATE TABLE collections (id INTEGER, name TEXT);
        CREATE TABLE file_ratings (file_id INTEGER, rating);
        CREATE TABLE file_annotations (file_id INTEGER, source TEXT, key TEXT, value, confidence, created_at);
    ";

    async fn mem_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        for statement in DDL
            .split(';')
            .filter(|statement| !statement.trim().is_empty())
        {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
        pool
    }

    async fn fixture_pool() -> SqlitePool {
        let pool = mem_pool().await;
        sqlx::query("INSERT INTO files VALUES (1,'/fixture-parent/alpha.png','h1','p1',10,100,20,30,'scan',0),(2,'/fixture-parent/beta.jpg','h2','p2',11,200,40,50,'scan',0),(3,'/fixture-parent/deleted.png','h3','p3',12,300,60,70,'scan',1)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO tags VALUES (1,'cat'),(2,'dog')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO file_tags VALUES (1,1),(2,2)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO collections VALUES (9,'fixture set')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO file_ratings VALUES (1,3)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO file_annotations VALUES (1,'fixture','caption','hello',1,99)")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    const ROUTE_SEED: [u8; 32] = [3; 32];
    const ROUTE_PEER_ID: &str = "import-peer";
    const ROUTE_TOKEN: &str = "import-test-token";

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    async fn route_state() -> SharedState {
        let state = semantic_test_state_with(false, String::new()).await;
        apply_standalone_schema(&state.db).await.unwrap();
        for statement in DDL
            .split(';')
            .filter(|statement| !statement.trim().is_empty())
        {
            sqlx::query(statement).execute(&state.db).await.unwrap();
        }
        sqlx::query("INSERT INTO files VALUES (1,'/route-fixture-parent/alpha.png','h1','p1',10,100,20,30,'scan',0),(2,'/route-fixture-parent/beta.jpg','h2','p2',11,200,40,50,'scan',0),(6,'/route-fixture-parent/gamma.webp','h6','p6',12,600,60,70,'scan',0)")
            .execute(&state.db)
            .await
            .unwrap();
        let pubkey = openssl::pkey::PKey::private_key_from_raw_bytes(
            &ROUTE_SEED,
            openssl::pkey::Id::ED25519,
        )
        .unwrap()
        .raw_public_key()
        .unwrap();
        sqlx::query("INSERT INTO peers (peer_id,name,api_host,api_port,pubkey,created_at,updated_at) VALUES (?1,'n','10.0.0.2',5000,?2,0,0)")
        .bind(ROUTE_PEER_ID)
        .bind(pubkey)
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO peer_tokens (peer_id,token_hash,issued_at,expires_at,revoked_at,source) VALUES (?1,?2,0,?3,NULL,'pairing')")
        .bind(ROUTE_PEER_ID)
        .bind(crate::auth::peer_transport::hash_token(ROUTE_TOKEN))
        .bind(now_secs() + 86_400)
        .execute(&state.db)
        .await
        .unwrap();
        state
    }

    async fn route_state_with_files() -> (SharedState, tempfile::TempDir) {
        let state = route_state().await;
        let dir = tempfile::tempdir().unwrap();
        for (file_id, name, content) in [
            (1, "alpha.png", b"alpha".as_slice()),
            (2, "beta.jpg", b"beta".as_slice()),
            (6, "with\\backslash.webp", b"gamma".as_slice()),
        ] {
            let path = dir.path().join(name);
            fs::write(&path, content).unwrap();
            sqlx::query("UPDATE files SET path=? WHERE id=?")
                .bind(path.to_string_lossy().to_string())
                .bind(file_id)
                .execute(&state.db)
                .await
                .unwrap();
        }
        (state, dir)
    }

    fn signed_request(uri: &str, valid: bool) -> Request<axum::body::Body> {
        use crate::auth::peer_transport::{build_canonical_message, sign_canonical};

        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        let timestamp = now_secs().to_string();
        let canonical = build_canonical_message("GET", path, query, &timestamp, b"");
        let signature = if valid {
            base64::engine::general_purpose::URL_SAFE
                .encode(sign_canonical(&ROUTE_SEED, &canonical).unwrap())
        } else {
            "invalid".into()
        };
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("X-Peer-Id", ROUTE_PEER_ID)
            .header("X-Peer-Ts", timestamp)
            .header("X-Peer-Sig", signature)
            .header("Authorization", format!("Bearer {ROUTE_TOKEN}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    async fn response_json(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("import meta vectors parse")
    }

    fn sorted(mut value: Value) -> Value {
        if let Some(object) = value.as_object_mut() {
            for value in object.values_mut() {
                *value = sorted(value.take());
            }
        }
        if let Some(array) = value.as_array_mut() {
            for value in array.iter_mut() {
                *value = sorted(value.take());
            }
            array.sort_by_key(Value::to_string);
        }
        value
    }

    #[tokio::test]
    async fn meta_response_matches_python_golden_with_unordered_rows_sorted() {
        let pool = fixture_pool().await;
        let expected = &vectors()["expected"];
        for (mode, rust_mode) in [("index", MetaMode::Index), ("full", MetaMode::Full)] {
            assert_eq!(
                sorted(build_meta_response(&pool, rust_mode, None).await.unwrap()),
                sorted(expected[mode].clone())
            );
        }
    }

    #[tokio::test]
    async fn files_filter_deleted_and_keep_empty_max_rowid_parity() {
        let pool = fixture_pool().await;
        assert_eq!(query_files_full(&pool, None).await.unwrap().1, 2);
        assert_eq!(query_files_full(&pool, Some(2)).await.unwrap(), (vec![], 2));
        let empty = mem_pool().await;
        assert_eq!(query_files_full(&empty, None).await.unwrap(), (vec![], 0));
        assert_eq!(
            query_files_full(&empty, Some(0)).await.unwrap(),
            (vec![], 0)
        );
    }

    #[test]
    fn paths_follow_pathlib_posix_semantics() {
        assert_eq!(redact_file_path("/a/b/file.png"), "file.png");
        assert_eq!(redact_file_path(""), "");
        assert_eq!(redact_file_path("/a/b/"), "b");
        assert_eq!(redact_file_path("/a/b/.."), "");
        assert_eq!(
            redact_file_path("/a/b/with\\backslash.png"),
            "with\\backslash.png"
        );
    }

    #[test]
    fn verbatim_paths_normalize_before_windows_deny_checks() {
        assert_eq!(
            crate::path_guard::normalize_path(Path::new(r"\\?\C:\Windows\System32\x.dll")),
            PathBuf::from(r"C:\Windows\System32\x.dll")
        );
        assert_eq!(
            crate::path_guard::normalize_path(Path::new(r"\\?\UNC\server\share\x.dll")),
            PathBuf::from(r"\\server\share\x.dll")
        );
    }

    #[tokio::test]
    async fn annotations_preserve_storage_types_and_never_decompress_blobs() {
        let pool = mem_pool().await;
        let blobs = [
            ("utf8", b"hello".to_vec()),
            ("binary", vec![0xff, 0]),
            ("zstd", vec![0x28, 0xb5, 0x2f, 0xfd, 0]),
        ];
        for (key, value) in blobs {
            sqlx::query("INSERT INTO file_annotations VALUES (1,'s',?, ?,1,1)")
                .bind(key)
                .bind(value)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO file_annotations VALUES (1,'s','text','plain',1,1),(1,'s','integer',7,1,1),(1,'s','real',1.5,1.0,1),(1,'s','null',NULL,NULL,1)").execute(&pool).await.unwrap();
        let mut items = query_annotations(&pool, &[1])
            .await
            .unwrap()
            .remove("1")
            .unwrap();
        items.sort_by_key(|item| item["key"].to_string());
        let by_key = items
            .into_iter()
            .map(|item| (item["key"].as_str().unwrap().to_string(), item))
            .collect::<HashMap<_, _>>();
        assert_eq!(by_key["utf8"]["value"], json!("hello"));
        assert_eq!(by_key["utf8"]["value_enc"], json!("utf8"));
        assert_eq!(by_key["binary"]["value"], json!("/wA="));
        assert_eq!(by_key["binary"]["value_enc"], json!("base64"));
        assert_eq!(by_key["zstd"]["value"], json!("KLUv/QA="));
        assert_eq!(by_key["zstd"]["value_enc"], json!("base64"));
        assert_eq!(by_key["text"]["value"], json!("plain"));
        assert_eq!(by_key["integer"]["value"], json!(7));
        assert_eq!(by_key["real"]["value"], json!(1.5));
        assert_eq!(by_key["null"]["value"], Value::Null);
        assert_eq!(by_key["null"]["value_enc"], json!("utf8"));
        assert_eq!(by_key["integer"]["confidence"].to_string(), "1");
        assert_eq!(by_key["real"]["confidence"].to_string(), "1.0");
    }

    #[tokio::test]
    async fn response_is_slim_in_index_and_never_leaks_parent_path() {
        let pool = fixture_pool().await;
        for mode in [MetaMode::Index, MetaMode::Full] {
            let response = build_meta_response(&pool, mode, None).await.unwrap();
            assert!(!response.to_string().contains("fixture-parent"));
            assert!(response["files"]
                .as_array()
                .unwrap()
                .iter()
                .all(|file| file["path"]
                    .as_str()
                    .is_some_and(|path| !path.contains('/'))));
        }
        let index = build_meta_response(&pool, MetaMode::Index, None)
            .await
            .unwrap();
        assert_eq!(index.as_object().unwrap().len(), 3);
        assert_eq!(index["files"][0].as_object().unwrap().len(), 5);
        assert!(index.get("collections").is_none());
        assert!(index.get("file_ratings").is_none());
        assert!(index.get("file_annotations").is_none());
    }

    #[test]
    fn duplicate_file_ids_keep_first_seen_order() {
        assert_eq!(unique_file_ids(&[3, 1, 3, 2, 1]), vec![3, 1, 2]);
    }

    #[tokio::test]
    async fn query_file_path_returns_only_raw_active_path() {
        let pool = fixture_pool().await;
        assert_eq!(
            query_file_path(&pool, 1).await.unwrap(),
            Some("/fixture-parent/alpha.png".into())
        );
        assert_eq!(query_file_path(&pool, 3).await.unwrap(), None);
    }

    #[tokio::test]
    async fn import_meta_404_when_gate_off() {
        let state = semantic_test_state_with(false, String::new()).await;
        let app = import_routes(false).with_state(LanCoworkState::from_shared(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ext/lan_cowork/api/peer/import/meta")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn import_diff_404_when_gate_off() {
        let state = semantic_test_state_with(false, String::new()).await;
        let app = import_routes(false).with_state(LanCoworkState::from_shared(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ext/lan_cowork/api/peer/import/diff")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn import_meta_accepts_signed_request_without_nonce_and_redacts_paths() {
        let state = route_state().await;
        let app = import_routes(true).with_state(LanCoworkState::from_shared(&state));
        let request = signed_request("/ext/lan_cowork/api/peer/import/meta?mode=full", true);
        assert!(request.headers().get("X-Peer-Nonce").is_none());
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["ok"], true);
        assert!(!body.to_string().contains("route-fixture-parent"));
    }

    #[tokio::test]
    async fn import_routes_reject_missing_and_invalid_signatures() {
        let state = route_state().await;
        let app = import_routes(true).with_state(LanCoworkState::from_shared(&state));
        let missing = Request::builder()
            .uri("/ext/lan_cowork/api/peer/import/meta")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(missing).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.oneshot(signed_request(
                "/ext/lan_cowork/api/peer/import/diff",
                false
            ))
            .await
            .unwrap()
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn import_meta_supports_full_index_and_rejects_invalid_mode() {
        let state = route_state().await;
        let app = import_routes(true).with_state(LanCoworkState::from_shared(&state));
        for mode in ["full", "index"] {
            assert_eq!(
                app.clone()
                    .oneshot(signed_request(
                        &format!("/ext/lan_cowork/api/peer/import/meta?mode={mode}"),
                        true
                    ))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        let response = app
            .oneshot(signed_request(
                "/ext/lan_cowork/api/peer/import/meta?mode=other",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await,
            json!({"ok": false, "error": "invalid mode"})
        );
    }

    #[tokio::test]
    async fn import_meta_ignores_after_rowid_and_diff_treats_zero_as_unset() {
        let state = route_state().await;
        let app = import_routes(true).with_state(LanCoworkState::from_shared(&state));
        let meta = response_json(
            app.clone()
                .oneshot(signed_request("/ext/lan_cowork/api/peer/import/meta", true))
                .await
                .unwrap(),
        )
        .await;
        let meta_after = response_json(
            app.clone()
                .oneshot(signed_request(
                    "/ext/lan_cowork/api/peer/import/meta?after_rowid=5",
                    true,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(meta, meta_after);
        let diff = response_json(
            app.clone()
                .oneshot(signed_request("/ext/lan_cowork/api/peer/import/diff", true))
                .await
                .unwrap(),
        )
        .await;
        let diff_zero = response_json(
            app.oneshot(signed_request(
                "/ext/lan_cowork/api/peer/import/diff?after_rowid=0",
                true,
            ))
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(diff, diff_zero);
    }

    #[tokio::test]
    async fn import_diff_trims_after_rowid_before_parsing() {
        let state = route_state().await;
        let app = import_routes(true).with_state(LanCoworkState::from_shared(&state));
        let response = app
            .oneshot(signed_request(
                "/ext/lan_cowork/api/peer/import/diff?after_rowid=%205",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let files = response_json(response).await["files"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["id"], 6);
    }

    #[test]
    fn import_deny_paths_match_shared_vectors() {
        for vector in serde_json::from_str::<Vec<Value>>(DENY_PATH_VECTORS).unwrap() {
            let platform = vector["platform"].as_str().unwrap();
            if platform == "unix" && cfg!(windows) || platform == "windows" && !cfg!(windows) {
                continue;
            }
            let mut path = vector["path"].as_str().unwrap().to_string();
            path = path.replace(
                "$HOME",
                &std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .expect("home directory is set for deny-list vectors"),
            );
            if path.contains("$APPDATA") {
                let Ok(appdata) = std::env::var("APPDATA") else {
                    continue;
                };
                path = path.replace("$APPDATA", &appdata);
            }
            assert_eq!(
                import_path_is_denied(Path::new(&path)),
                vector["denied"].as_bool().unwrap(),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn file_routes_are_absent_when_gate_is_off() {
        for path in [
            "/ext/lan_cowork/api/peer/import/file/1",
            "/ext/lan_cowork/api/peer/import/zip",
            "/ext/lan_cowork/api/peer/import/stream/1",
        ] {
            let state = semantic_test_state_with(false, String::new()).await;
            let app = import_routes(false).with_state(LanCoworkState::from_shared(&state));
            assert_eq!(
                app.oneshot(
                    Request::builder()
                        .uri(path)
                        .body(axum::body::Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
                StatusCode::NOT_FOUND
            );
        }
    }

    #[tokio::test]
    async fn file_routes_reject_missing_and_invalid_signatures() {
        let (state, _dir) = route_state_with_files().await;
        let app = import_routes(true).with_state(LanCoworkState::from_shared(&state));
        for path in [
            "/ext/lan_cowork/api/peer/import/file/1",
            "/ext/lan_cowork/api/peer/import/zip?ids=1",
            "/ext/lan_cowork/api/peer/import/stream/1",
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(
                        Request::builder()
                            .uri(path)
                            .body(axum::body::Body::empty())
                            .unwrap()
                    )
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                app.clone()
                    .oneshot(signed_request(path, false))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[tokio::test]
    async fn file_ids_match_werkzeug_unsigned_route_rule() {
        let (state, _dir) = route_state_with_files().await;
        let app = import_routes(true).with_state(LanCoworkState::from_shared(&state));
        for route in ["file", "stream"] {
            for file_id in ["-1", "abc", "1.5"] {
                assert_eq!(
                    app.clone()
                        .oneshot(signed_request(
                            &format!("/ext/lan_cowork/api/peer/import/{route}/{file_id}"),
                            true,
                        ))
                        .await
                        .unwrap()
                        .status(),
                    StatusCode::NOT_FOUND
                );
            }
        }
    }

    #[tokio::test]
    async fn file_and_stream_send_octet_stream_without_nonce() {
        let (state, _dir) = route_state_with_files().await;
        let app = import_routes(true).with_state(LanCoworkState::from_shared(&state));
        for (route, expected) in [
            ("file/1", b"alpha".as_slice()),
            ("stream/2", b"beta".as_slice()),
        ] {
            let response = app
                .clone()
                .oneshot(signed_request(
                    &format!("/ext/lan_cowork/api/peer/import/{route}"),
                    true,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                "application/octet-stream"
            );
            assert_eq!(
                to_bytes(response.into_body(), usize::MAX).await.unwrap(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn zip_ids_decode_trim_and_preserve_raw_entry_names() {
        let (state, _dir) = route_state_with_files().await;
        let app = import_routes(true).with_state(LanCoworkState::from_shared(&state));
        let response = app
            .clone()
            .oneshot(signed_request(
                "/ext/lan_cowork/api/peer/import/zip?ids=1%2C2%2C6",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip");
        assert_eq!(
            response.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=import.zip"
        );
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let names = (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            ["1/alpha.png", "2/beta.jpg", "6/with\\backslash.webp"]
        );

        let trimmed = app
            .oneshot(signed_request(
                "/ext/lan_cowork/api/peer/import/zip?ids=1,%202",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(trimmed.status(), StatusCode::OK);
        assert_eq!(
            zip::ZipArchive::new(std::io::Cursor::new(
                to_bytes(trimmed.into_body(), usize::MAX).await.unwrap(),
            ))
            .unwrap()
            .len(),
            2
        );
    }

    #[tokio::test]
    async fn zip_ids_preserve_negative_parity_and_error_bodies() {
        let (state, _dir) = route_state_with_files().await;
        let app = import_routes(true).with_state(LanCoworkState::from_shared(&state));
        let negative = app
            .clone()
            .oneshot(signed_request(
                "/ext/lan_cowork/api/peer/import/zip?ids=-1",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(negative.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response_json(negative).await,
            json!({"ok": false, "error": "no files"})
        );
        let missing = app
            .oneshot(signed_request("/ext/lan_cowork/api/peer/import/zip", true))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(missing).await,
            json!({"ok": false, "error": "no ids"})
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn zip_skips_denied_and_non_file_paths() {
        let (state, dir) = route_state_with_files().await;
        sqlx::query("UPDATE files SET path='/etc/passwd' WHERE id=1")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("UPDATE files SET path=? WHERE id=6")
            .bind(dir.path().to_string_lossy().to_string())
            .execute(&state.db)
            .await
            .unwrap();
        let app = import_routes(true).with_state(LanCoworkState::from_shared(&state));
        let response = app
            .clone()
            .oneshot(signed_request(
                "/ext/lan_cowork/api/peer/import/zip?ids=1,2,6",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            zip::ZipArchive::new(std::io::Cursor::new(
                to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            ))
            .unwrap()
            .len(),
            1
        );
        let no_files = app
            .oneshot(signed_request(
                "/ext/lan_cowork/api/peer/import/zip?ids=1,6",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(no_files.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response_json(no_files).await,
            json!({"ok": false, "error": "no files"})
        );
    }

    #[tokio::test]
    async fn zip_build_permit_stays_with_blocking_work() {
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            std::thread::sleep(Duration::from_millis(100));
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), semaphore.clone().acquire_owned())
                .await
                .is_err()
        );
        worker.await.unwrap();
        assert!(semaphore.acquire_owned().await.is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_path_returns_404_without_blocking() {
        let (state, dir) = route_state_with_files().await;
        let fifo = dir.path().join("blocked.fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        sqlx::query("UPDATE files SET path=? WHERE id=1")
            .bind(fifo.to_string_lossy().to_string())
            .execute(&state.db)
            .await
            .unwrap();
        let app = import_routes(true).with_state(LanCoworkState::from_shared(&state));
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            app.oneshot(signed_request(
                "/ext/lan_cowork/api/peer/import/file/1",
                true,
            )),
        )
        .await
        .expect("FIFO must not block")
        .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response_json(response).await,
            json!({"ok": false, "error": "file missing on disk"})
        );
    }
}
