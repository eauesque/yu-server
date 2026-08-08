//! LAN Cowork operator-side local import session routes.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    extract::{Extension, Path as AxumPath, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::{
    path_guard::{is_under_any, resolve_non_strict, under_home_dot_dir},
    routes::{
        lan_cowork::{api_err, session_guard},
        lan_cowork_discovery::load_identity_seed,
        lan_cowork_host::{LanCoworkHost, LanCoworkState},
        lan_cowork_import_executor, lan_cowork_import_state,
        lan_cowork_inbound_read::assemble_local_peer_info,
        lan_cowork_transport::PeerTransport,
    },
};

const PREFIX: &str = "/ext/lan_cowork/api/peer/import";

pub fn routes() -> Router<LanCoworkState> {
    Router::new()
        .route(&format!("{PREFIX}/sessions"), get(list_sessions))
        .route(&format!("{PREFIX}/session"), post(create_session))
        .route(&format!("{PREFIX}/execute"), post(execute_import))
        .route(&format!("{PREFIX}/index"), post(fetch_index))
        .route(
            &format!("{PREFIX}/session/{{session_id}}"),
            get(get_session),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteImportRequest {
    session_id: String,
    #[serde(default)]
    file_ids: Option<Vec<i64>>,
}

fn validate_execute_request(
    mut request: ExecuteImportRequest,
) -> Result<ExecuteImportRequest, &'static str> {
    request.session_id = request.session_id.trim().to_owned();
    if request.session_id.is_empty()
        || request
            .file_ids
            .as_ref()
            .is_some_and(|ids| ids.iter().any(|id| *id <= 0))
    {
        return Err("body: validation error");
    }
    Ok(request)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchIndexRequest {
    peer_id: String,
    import_folder: String,
    #[serde(default)]
    options: Map<String, Value>,
}

fn validate_fetch_index_request(
    mut request: FetchIndexRequest,
) -> Result<FetchIndexRequest, &'static str> {
    request.peer_id = request.peer_id.trim().to_owned();
    request.import_folder = request.import_folder.trim().to_owned();
    if request.peer_id.is_empty() || request.import_folder.is_empty() {
        return Err("body: validation error");
    }
    Ok(request)
}

fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value
            .as_i64()
            .map(|number| number != 0)
            .or_else(|| value.as_u64().map(|number| number != 0))
            .or_else(|| value.as_f64().map(|number| number != 0.0))
            .unwrap_or(false),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn python_value_string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

async fn execute_import(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Some(response) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return response;
    }
    let content_type_ok = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(';').next().unwrap_or("").trim() == "application/json");
    if !content_type_ok {
        return api_err(
            "JSON body is required",
            "invalid_content_type",
            StatusCode::BAD_REQUEST,
        );
    }
    let value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return api_err("Invalid JSON body", "invalid_json", StatusCode::BAD_REQUEST),
    };
    if !value.is_object() {
        return api_err(
            "JSON object body is required",
            "invalid_json_object",
            StatusCode::BAD_REQUEST,
        );
    }
    let request = match serde_json::from_value(value) {
        Ok(request) => request,
        Err(error) => {
            return api_err(
                &format!("body: {error}"),
                "validation_error",
                StatusCode::BAD_REQUEST,
            )
        }
    };
    let request = match validate_execute_request(request) {
        Ok(request) => request,
        Err(error) => return api_err(error, "validation_error", StatusCode::BAD_REQUEST),
    };
    let imported = match lan_cowork_import_state::get(state.db_read(), &request.session_id).await {
        Ok(Some(imported)) => imported,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"ok": false, "error": "session not found"})),
            )
                .into_response()
        }
        Err(_) => {
            return api_err(
                "internal error",
                "db_error",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    };

    // Resolve every native-daemon prerequisite before mkdir, preserving Python's no-side-effect 503.
    let (Some(registry), Some(local), Some(seed)) = (
        state.peer_registry.get().cloned(),
        assemble_local_peer_info(&*state).await,
        load_identity_seed(state.db_read()).await,
    ) else {
        return api_err(
            "LAN Cowork not enabled",
            "service_unavailable",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    let Some(peer_id) = imported.get("peer_id").and_then(Value::as_str) else {
        return api_err(
            "internal error",
            "db_error",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    };
    let Some(peer) = registry.get(peer_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "peer not in registry"})),
        )
            .into_response();
    };
    let Some(import_folder) = imported.get("import_folder").and_then(Value::as_str) else {
        return api_err(
            "internal error",
            "db_error",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    };
    let folder = match validate_import_folder(import_folder, state.project_root(), dirs::home_dir())
    {
        Ok(folder) => folder,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": error})),
            )
                .into_response()
        }
    };
    if let Err(error) = std::fs::create_dir_all(&folder) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": format!("cannot create import_folder: {error}")})),
        )
            .into_response();
    }

    let local_peer_id = registry.local_peer_id();
    let transport = PeerTransport::new(
        local_peer_id.clone(),
        seed.clone(),
        registry.clone(),
        state.host.clone(),
    );
    let registration = json!({"host": local.api_host, "port": local.api_port});
    let (registered, registration_body) = transport
        .send(&peer, "/api/peer/register", Some(&registration), "POST")
        .await;
    if !registered {
        // PeerTransport guarantees error on failures; retain Python's falsy-preserving get semantics.
        let error = python_value_string(
            registration_body
                .get("error")
                .expect("PeerTransport failure always contains error"),
        );
        tracing::warn!(peer_id = %peer.peer_id, stage = "self_registration", "LAN Cowork peer request failed");
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({"ok": false, "error": format!("self-registration failed: {error}")})),
        )
            .into_response();
    }

    let mode = imported
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let path = if mode == "diff" {
        let after_rowid = imported
            .get("last_seen_rowid")
            .and_then(Value::as_i64)
            .filter(|rowid| *rowid != 0)
            .unwrap_or(0);
        format!("/api/peer/import/diff?after_rowid={after_rowid}")
    } else {
        "/api/peer/import/meta?mode=full".to_owned()
    };
    let (meta_ok, mut meta) = transport.send(&peer, &path, None, "GET").await;
    if !meta_ok {
        let error = meta
            .get("error")
            .filter(|value| python_truthy(value))
            .map(python_value_string)
            .unwrap_or_else(|| "unknown error".to_owned());
        let detail = meta
            .get("status")
            .filter(|value| python_truthy(value))
            .map(|status| format!("HTTP {}: {error}", python_value_string(status)))
            .unwrap_or(error);
        tracing::warn!(peer_id = %peer.peer_id, stage = "fetch_meta", "LAN Cowork peer request failed");
        return (StatusCode::BAD_GATEWAY, Json(json!({"ok": false, "error": format!("failed to fetch meta from remote: {detail}")}))).into_response();
    }
    if mode == "selective" && request.file_ids.as_ref().is_some_and(|ids| !ids.is_empty()) {
        let ids = request.file_ids.as_ref().expect("checked above");
        let files = meta
            .get("files")
            .and_then(Value::as_array)
            .map(|files| {
                files
                    .iter()
                    .filter(|file| {
                        file.get("id")
                            .and_then(Value::as_i64)
                            .is_some_and(|id| ids.contains(&id))
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        meta["files"] = Value::Array(files);
    }

    let meta = meta.as_object().cloned().unwrap_or_default();
    match lan_cowork_import_state::claim_execution(
        state.db(),
        &request.session_id,
        super::lan_cowork_import_transfer::SESSION_DOWNLOAD_LIMIT,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"ok": false, "error": "session already executed"})),
            )
                .into_response()
        }
        Err(_) => {
            return api_err(
                "internal error",
                "db_error",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
    let options = imported
        .get("options")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let pool = state.db().clone();
    let session_id = request.session_id;
    let task_session_id = session_id.clone();
    let host: Arc<dyn LanCoworkHost> = state.host.clone();
    let registry: Arc<_> = registry;
    tokio::spawn(async move {
        if lan_cowork_import_executor::run(
            &pool,
            &task_session_id,
            &peer,
            &meta,
            &folder,
            &options,
            Some(&local_peer_id),
            &seed,
            &registry,
            &*host,
            true,
        )
        .await
        .is_err()
        {
            tracing::error!(session_id = %task_session_id, "LAN Cowork import executor failed");
            let _ = lan_cowork_import_state::update_standalone(
                &pool,
                &task_session_id,
                json!({"status": "failed"})
                    .as_object()
                    .expect("JSON object"),
            )
            .await;
        }
    });
    Json(json!({"ok": true, "message": "import started", "session_id": session_id})).into_response()
}

async fn fetch_index(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Some(response) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return response;
    }
    let content_type_ok = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(';').next().unwrap_or("").trim() == "application/json");
    if !content_type_ok {
        return api_err(
            "JSON body is required",
            "invalid_content_type",
            StatusCode::BAD_REQUEST,
        );
    }
    let value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return api_err("Invalid JSON body", "invalid_json", StatusCode::BAD_REQUEST),
    };
    if !value.is_object() {
        return api_err(
            "JSON object body is required",
            "invalid_json_object",
            StatusCode::BAD_REQUEST,
        );
    }
    let request: FetchIndexRequest = match serde_json::from_value(value) {
        Ok(request) => request,
        Err(error) => {
            return api_err(
                &format!("body: {error}"),
                "validation_error",
                StatusCode::BAD_REQUEST,
            )
        }
    };
    let request = match validate_fetch_index_request(request) {
        Ok(request) => request,
        Err(error) => return api_err(error, "validation_error", StatusCode::BAD_REQUEST),
    };
    let folder = match validate_import_folder(
        &request.import_folder,
        state.project_root(),
        dirs::home_dir(),
    ) {
        Ok(folder) => folder,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": error})),
            )
                .into_response()
        }
    };
    let (Some(registry), Some(seed)) = (
        state.peer_registry.get().cloned(),
        load_identity_seed(state.db_read()).await,
    ) else {
        return api_err(
            "LAN Cowork not enabled",
            "service_unavailable",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    let Some(peer) = registry.get(&request.peer_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "peer not in registry"})),
        )
            .into_response();
    };
    let transport =
        PeerTransport::new(registry.local_peer_id(), seed, registry, state.host.clone());
    let (ok, index) = transport
        .send(&peer, "/api/peer/import/meta?mode=index", None, "GET")
        .await;
    if !ok {
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({"ok": false, "error": "failed to fetch index"})),
        )
            .into_response();
    }
    match lan_cowork_import_state::create_standalone(
        state.db(),
        &request.peer_id,
        &peer.name,
        "selective",
        &folder.to_string_lossy(),
        &request.options,
    )
    .await
    {
        Ok(session_id) => {
            Json(json!({"ok": true, "session_id": session_id, "index": index})).into_response()
        }
        Err(_) => api_err(
            "internal error",
            "db_error",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}

async fn list_sessions(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    if let Some(response) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return response;
    }
    match lan_cowork_import_state::list_all(state.db_read()).await {
        Ok(sessions) => Json(json!({"ok": true, "sessions": sessions})).into_response(),
        Err(_) => api_err(
            "internal error",
            "db_error",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}

async fn get_session(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    AxumPath(session_id): AxumPath<String>,
) -> Response {
    if let Some(response) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return response;
    }
    match lan_cowork_import_state::get(state.db_read(), &session_id).await {
        Ok(Some(session)) => Json(json!({"ok": true, "session": session})).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "session not found"})),
        )
            .into_response(),
        Err(_) => api_err(
            "internal error",
            "db_error",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSessionRequest {
    peer_id: String,
    #[serde(default)]
    peer_name: String,
    #[serde(default = "default_mode")]
    mode: String,
    import_folder: String,
    #[serde(default)]
    options: Map<String, Value>,
}

fn default_mode() -> String {
    "full".into()
}

fn validate_request(
    mut request: CreateSessionRequest,
) -> Result<CreateSessionRequest, &'static str> {
    request.peer_id = request.peer_id.trim().to_owned();
    request.peer_name = request.peer_name.trim().to_owned();
    request.import_folder = request.import_folder.trim().to_owned();
    if request.peer_id.is_empty()
        || request.import_folder.is_empty()
        || !matches!(request.mode.as_str(), "full" | "diff" | "selective")
    {
        return Err("body: validation error");
    }
    Ok(request)
}

fn validate_import_folder(
    import_folder: &str,
    project_root: &Path,
    home: Option<PathBuf>,
) -> Result<PathBuf, String> {
    if import_folder.contains('\0') {
        return Err("import_folder is not allowed".into());
    }
    let resolved = resolve_non_strict(Path::new(import_folder))
        .map_err(|error| format!("invalid import_folder: {error}"))?;
    if resolved.parent().is_none() {
        return Err("import_folder is not allowed".into());
    }
    let home = home.ok_or_else(|| "import_folder is not allowed".to_string())?;
    let home =
        resolve_non_strict(&home).map_err(|error| format!("invalid import_folder: {error}"))?;
    if under_home_dot_dir(&resolved, &home) {
        return Err("import_folder is not allowed".into());
    }
    let bases = crate::path_guard::resolve_sensitive_bases(&[project_root.to_path_buf()], &home);
    if is_under_any(&resolved, &bases) {
        return Err("import_folder is not allowed".into());
    }
    Ok(resolved)
}

async fn create_session(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Some(response) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return response;
    }
    let content_type_ok = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(';').next().unwrap_or("").trim() == "application/json");
    if !content_type_ok {
        return api_err(
            "JSON body is required",
            "invalid_content_type",
            StatusCode::BAD_REQUEST,
        );
    }
    let value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return api_err("Invalid JSON body", "invalid_json", StatusCode::BAD_REQUEST),
    };
    if !value.is_object() {
        return api_err(
            "JSON object body is required",
            "invalid_json_object",
            StatusCode::BAD_REQUEST,
        );
    }
    let request: CreateSessionRequest = match serde_json::from_value(value) {
        Ok(request) => request,
        Err(error) => {
            return api_err(
                &format!("body: {error}"),
                "validation_error",
                StatusCode::BAD_REQUEST,
            )
        }
    };
    let request = match validate_request(request) {
        Ok(request) => request,
        Err(error) => {
            return api_err(
                &format!("body: {error}"),
                "validation_error",
                StatusCode::BAD_REQUEST,
            )
        }
    };
    let folder = match validate_import_folder(
        &request.import_folder,
        state.project_root(),
        dirs::home_dir(),
    ) {
        Ok(folder) => folder,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": error})),
            )
                .into_response()
        }
    };
    if let Err(error) = std::fs::create_dir_all(&folder) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": format!("cannot create import_folder: {error}")})),
        )
            .into_response();
    }
    match lan_cowork_import_state::create_standalone(
        state.db(),
        &request.peer_id,
        &request.peer_name,
        &request.mode,
        &folder.to_string_lossy(),
        &request.options,
    )
    .await
    {
        Ok(session_id) => Json(json!({"ok": true, "session_id": session_id})).into_response(),
        Err(_) => api_err(
            "internal error",
            "db_error",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SharedState;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use std::{
        sync::{atomic::Ordering, Arc},
        time::Duration,
    };
    use tower::ServiceExt;

    const SESSIONS_PATH: &str = "/ext/lan_cowork/api/peer/import/sessions";
    const SESSION_PATH: &str = "/ext/lan_cowork/api/peer/import/session";
    const SESSION_ID_PATH: &str = "/ext/lan_cowork/api/peer/import/session/test-session";
    const EXECUTE_PATH: &str = "/ext/lan_cowork/api/peer/import/execute";
    const INDEX_PATH: &str = "/ext/lan_cowork/api/peer/import/index";

    async fn test_state(root: &Path) -> SharedState {
        // `project_root` is a non-existent subdirectory of `root`, not `root`
        // itself: several tests place import folders directly under `root`
        // (e.g. `root/created`), and those must NOT collide with the
        // sensitive-base guard that rejects folders inside `project_root`.
        let state =
            crate::state::semantic_test_state_with_root(false, String::new(), root.join("project"))
                .await;
        sqlx::raw_sql(
            "CREATE TABLE import_session (
                id TEXT PRIMARY KEY, peer_id TEXT NOT NULL, peer_name TEXT NOT NULL,
                mode TEXT NOT NULL, status TEXT NOT NULL, last_seen_rowid INTEGER,
                snapshot_max_rowid INTEGER, total_files INTEGER, done_files INTEGER NOT NULL,
                import_folder TEXT NOT NULL, options TEXT NOT NULL,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
            );",
        )
        .execute(&state.db)
        .await
        .unwrap();
        state
    }

    async fn json(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    async fn send(app: Router, method: &str, path: &str, body: &str) -> Response {
        app.oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    async fn add_session(state: &SharedState, id: &str) {
        sqlx::query("INSERT INTO import_session (id,peer_id,peer_name,mode,status,last_seen_rowid,snapshot_max_rowid,total_files,done_files,import_folder,options,created_at,updated_at) VALUES (?,'peer','Peer','full','pending',NULL,NULL,NULL,0,'/tmp/import','{}',1,1)")
            .bind(id).execute(&state.db).await.unwrap();
    }

    fn test_peer(port: u16) -> crate::routes::lan_cowork_registry::PeerInfo {
        crate::routes::lan_cowork_registry::PeerInfo {
            peer_id: "peer".into(),
            name: "Peer".into(),
            api_host: "127.0.0.1".into(),
            api_port: port,
            token: Some("test-token".into()),
            token_expires_at: Some(2_000_000_000),
            token_issued_at: Some(1),
            pubkey: None,
            x25519_pk: None,
            version: "test".into(),
            bridges: vec![],
            inference_types: vec![],
            gpu: String::new(),
            generating: false,
            queue_depth: 0,
            status: "online".into(),
            last_seen: 0.0,
            session_id: String::new(),
            roles: vec![],
            last_reached_at: None,
            last_attempted_at: None,
        }
    }

    async fn enable_native(state: &SharedState, lc: &LanCoworkState, port: u16) {
        use crate::routes::{
            lan_cowork_descriptor::{LocalDescriptor, TEST_ALLOW_LOOPBACK, TEST_DESCRIPTOR},
            lan_cowork_registry::PeerRegistry,
        };
        sqlx::raw_sql("CREATE TABLE lan_cowork_identity (key TEXT PRIMARY KEY, value BLOB NOT NULL); CREATE TABLE peers (peer_id TEXT PRIMARY KEY, name TEXT, api_host TEXT, api_port INTEGER, token TEXT, token_expires_at INTEGER, token_issued_at INTEGER, pubkey BLOB, x25519_pk BLOB, created_at INTEGER, updated_at INTEGER);")
            .execute(&state.db).await.unwrap();
        sqlx::query("INSERT INTO lan_cowork_identity VALUES ('ed25519_seed', ?)")
            .bind(vec![7u8; 32])
            .execute(&state.db)
            .await
            .unwrap();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        *TEST_DESCRIPTOR
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(Ok(LocalDescriptor {
            peer_id: "local".into(),
            name: "Local".into(),
            api_host: "127.0.0.1".into(),
            api_port: 9999,
            version: "test".into(),
            bridges: vec![],
        }));
        let registry = Arc::new(PeerRegistry::new(
            state.db.clone(),
            Duration::from_secs(30),
            "local".into(),
        ));
        registry.upsert(test_peer(port)).await.unwrap();
        assert!(
            lc.peer_registry.set(registry).is_ok(),
            "test registry is installed once"
        );
    }

    async fn enable_native_without_peer(state: &SharedState, lc: &LanCoworkState) {
        use crate::routes::{
            lan_cowork_descriptor::{LocalDescriptor, TEST_ALLOW_LOOPBACK, TEST_DESCRIPTOR},
            lan_cowork_registry::PeerRegistry,
        };
        sqlx::raw_sql(
            "CREATE TABLE lan_cowork_identity (key TEXT PRIMARY KEY, value BLOB NOT NULL);",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO lan_cowork_identity VALUES ('ed25519_seed', ?)")
            .bind(vec![7u8; 32])
            .execute(&state.db)
            .await
            .unwrap();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        *TEST_DESCRIPTOR
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(Ok(LocalDescriptor {
            peer_id: "local".into(),
            name: "Local".into(),
            api_host: "127.0.0.1".into(),
            api_port: 9999,
            version: "test".into(),
            bridges: vec![],
        }));
        let registry = Arc::new(PeerRegistry::new(
            state.db.clone(),
            Duration::from_secs(30),
            "local".into(),
        ));
        assert!(
            lc.peer_registry.set(registry).is_ok(),
            "test registry is installed once"
        );
    }

    async fn two_response_server(
        first: &'static str,
        second: &'static str,
    ) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind is required for execute route coverage");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut lines = Vec::new();
            for response in [first, second] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let size = stream.read(&mut request).await.unwrap();
                lines.push(
                    String::from_utf8_lossy(&request[..size])
                        .lines()
                        .next()
                        .unwrap()
                        .to_owned(),
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            lines
        });
        (port, server)
    }

    async fn one_response_server(response: String) -> (u16, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind is required for execute route coverage");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let size = stream.read(&mut request).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&request[..size])
                .lines()
                .next()
                .unwrap()
                .to_owned()
        });
        (port, server)
    }

    fn http(status: &str, body: &str) -> String {
        format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len())
    }

    async fn wait_for_status(state: &SharedState, id: &str, status: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let current: String =
                    sqlx::query_scalar("SELECT status FROM import_session WHERE id=?")
                        .bind(id)
                        .fetch_one(&state.db)
                        .await
                        .unwrap();
                if current == status {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("background import must update session status");
    }

    async fn add_execute_session(
        state: &SharedState,
        id: &str,
        mode: &str,
        last_seen: Option<i64>,
        folder: &Path,
    ) {
        sqlx::query("INSERT INTO import_session (id,peer_id,peer_name,mode,status,last_seen_rowid,snapshot_max_rowid,total_files,done_files,import_folder,options,created_at,updated_at) VALUES (?,'peer','Peer',?,'pending',?,NULL,NULL,0,?,'{}',1,1)")
            .bind(id).bind(mode).bind(last_seen).bind(folder.to_string_lossy().as_ref()).execute(&state.db).await.unwrap();
    }

    #[test]
    fn execute_request_rejects_invalid_ids_and_preserves_optional_file_ids() {
        assert_eq!(
            validate_execute_request(ExecuteImportRequest {
                session_id: " s ".into(),
                file_ids: Some(vec![1, 1]),
            })
            .unwrap()
            .session_id,
            "s"
        );
        for request in [
            ExecuteImportRequest {
                session_id: " ".into(),
                file_ids: None,
            },
            ExecuteImportRequest {
                session_id: "s".into(),
                file_ids: Some(vec![0]),
            },
            ExecuteImportRequest {
                session_id: "s".into(),
                file_ids: Some(vec![-1]),
            },
        ] {
            assert!(validate_execute_request(request).is_err());
        }
    }

    #[tokio::test]
    async fn execute_route_pins_session_before_native_daemon_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let missing = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            EXECUTE_PATH,
            &json!({"session_id":"missing"}).to_string(),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            json(missing).await,
            json!({"ok":false,"error":"session not found"})
        );
        add_session(&state, "known").await;
        let gated = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            EXECUTE_PATH,
            &json!({"session_id":"known"}).to_string(),
        )
        .await;
        assert_eq!(gated.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json(gated).await["error"], "LAN Cowork not enabled");
    }

    #[tokio::test]
    async fn execute_route_requires_session_with_exact_response() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path()).await;
        Arc::get_mut(&mut state).unwrap().config.pin_auth_enabled = true;
        let response = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            EXECUTE_PATH,
            &json!({"session_id":"known"}).to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json(response).await,
            json!({"ok":false,"error":"session required"})
        );
    }

    #[tokio::test]
    async fn execute_route_reports_unknown_registry_peer_after_native_gate() {
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let lc = LanCoworkState::from_shared(&state);
        enable_native_without_peer(&state, &lc).await;
        add_execute_session(
            &state,
            "unknown-peer",
            "full",
            None,
            &tmp.path().join("import"),
        )
        .await;
        let response = send(
            routes().with_state(lc.clone()),
            "POST",
            EXECUTE_PATH,
            r#"{"session_id":"unknown-peer"}"#,
        )
        .await;
        assert_ne!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            json(response).await,
            json!({"ok":false,"error":"peer not in registry"})
        );
        crate::routes::lan_cowork_descriptor::reset_client_state();
    }

    #[tokio::test]
    async fn execute_route_rejects_each_json_validation_stage() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        let no_type = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(EXECUTE_PATH)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(json(no_type).await["code"], "invalid_content_type");
        for body in [
            "{",
            "[]",
            r#"{"session_id":" "}"#,
            r#"{"session_id":"s","file_ids":[0]}"#,
            r#"{"session_id":"s","extra":true}"#,
        ] {
            let response = send(app.clone(), "POST", EXECUTE_PATH, body).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn execute_route_uses_expected_meta_urls_and_starts_import() {
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        for (mode, last_seen, expected) in [
            (
                "full",
                None,
                "GET /ext/lan_cowork/api/peer/import/meta?mode=full HTTP/1.1",
            ),
            (
                "selective",
                None,
                "GET /ext/lan_cowork/api/peer/import/meta?mode=full HTTP/1.1",
            ),
            (
                "diff",
                None,
                "GET /ext/lan_cowork/api/peer/import/diff?after_rowid=0 HTTP/1.1",
            ),
            (
                "diff",
                Some(0),
                "GET /ext/lan_cowork/api/peer/import/diff?after_rowid=0 HTTP/1.1",
            ),
            (
                "diff",
                Some(42),
                "GET /ext/lan_cowork/api/peer/import/diff?after_rowid=42 HTTP/1.1",
            ),
            (
                "diff",
                Some(-5),
                "GET /ext/lan_cowork/api/peer/import/diff?after_rowid=-5 HTTP/1.1",
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let state = test_state(tmp.path()).await;
            let lc = LanCoworkState::from_shared(&state);
            let (port, server) = two_response_server(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"files\":[]}",
            ).await;
            enable_native(&state, &lc, port).await;
            add_execute_session(&state, "run", mode, last_seen, &tmp.path().join("import")).await;
            let body = if mode == "selective" {
                json!({"session_id":"run","file_ids":null})
            } else {
                json!({"session_id":"run"})
            };
            let response = send(
                routes().with_state(lc.clone()),
                "POST",
                EXECUTE_PATH,
                &body.to_string(),
            )
            .await;
            assert_ne!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                json(response).await,
                json!({"ok":true,"message":"import started","session_id":"run"})
            );
            let lines = tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .expect("stub must receive both execute requests")
                .unwrap();
            assert_eq!(lines[0], "POST /ext/lan_cowork/api/peer/register HTTP/1.1");
            assert_eq!(lines[1], expected);
        }
        crate::routes::lan_cowork_descriptor::reset_client_state();
    }

    #[tokio::test]
    async fn execute_route_rejects_configured_project_root_before_peer_io() {
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let lc = LanCoworkState::from_shared(&state);
        enable_native(&state, &lc, 1).await;
        let project_root = state.config.project_root.clone();
        add_execute_session(&state, "project", "full", None, &project_root).await;
        let response = send(
            routes().with_state(lc.clone()),
            "POST",
            EXECUTE_PATH,
            &json!({"session_id":"project"}).to_string(),
        )
        .await;
        assert_ne!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        crate::routes::lan_cowork_descriptor::reset_client_state();
    }

    // `execute_route_rejects_api_key_without_session` was relocated to yu-server's
    // `lan_cowork_split_integration_tests.rs` (S4d step 4): it layers
    // `auth_middleware`, which lives in yu-server and is unreachable across the
    // crate boundary.

    #[tokio::test]
    async fn execute_route_reports_registration_failure_verbatim() {
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let lc = LanCoworkState::from_shared(&state);
        let (port, server) =
            one_response_server(http("500 Internal Server Error", r#"{"error":"remote"}"#)).await;
        enable_native(&state, &lc, port).await;
        add_execute_session(&state, "register", "full", None, &tmp.path().join("import")).await;
        let response = send(
            routes().with_state(lc.clone()),
            "POST",
            EXECUTE_PATH,
            &json!({"session_id":"register"}).to_string(),
        )
        .await;
        assert_ne!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            json(response).await["error"],
            "self-registration failed: remote"
        );
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("stub must receive registration")
            .unwrap();
        crate::routes::lan_cowork_descriptor::reset_client_state();
    }

    #[tokio::test]
    async fn execute_route_reports_meta_failure_status_and_falsy_error() {
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        for (id, response, expected) in [
            ("status", "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"error\":\"bad\"}", "failed to fetch meta from remote: HTTP 502: bad"),
            ("falsy", "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{\"error\":null}", "failed to fetch meta from remote: HTTP 502: unknown error"),
        ] {
            let tmp = tempfile::tempdir().unwrap(); let state = test_state(tmp.path()).await;
            let lc = LanCoworkState::from_shared(&state);
            let (port, server) = two_response_server("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}", response).await;
            enable_native(&state, &lc, port).await; add_execute_session(&state, id, "full", None, &tmp.path().join("import")).await;
            let result = send(
                routes().with_state(lc.clone()),
                "POST",
                EXECUTE_PATH,
                &json!({"session_id":id}).to_string(),
            )
            .await;
            assert_ne!(result.status(), StatusCode::SERVICE_UNAVAILABLE); assert_eq!(result.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(json(result).await["error"], expected);
            tokio::time::timeout(Duration::from_secs(5), server).await.expect("stub must receive both requests").unwrap();
        }
        crate::routes::lan_cowork_descriptor::reset_client_state();
    }

    #[tokio::test]
    async fn execute_route_reports_meta_transport_failure_without_http_prefix() {
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let lc = LanCoworkState::from_shared(&state);
        // The listener exits after self-registration, so the meta request takes record_failure.
        let (port, server) = one_response_server(http("200 OK", r#"{"ok":true}"#)).await;
        enable_native(&state, &lc, port).await;
        add_execute_session(
            &state,
            "transport",
            "full",
            None,
            &tmp.path().join("import"),
        )
        .await;
        let response = send(
            routes().with_state(lc.clone()),
            "POST",
            EXECUTE_PATH,
            r#"{"session_id":"transport"}"#,
        )
        .await;
        assert_ne!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let error = json(response).await["error"].as_str().unwrap().to_owned();
        assert!(error.starts_with("failed to fetch meta from remote: "));
        assert!(!error.contains("HTTP "));
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("stub must receive self-registration")
            .unwrap();
        crate::routes::lan_cowork_descriptor::reset_client_state();
    }

    #[tokio::test]
    async fn execute_route_selective_empty_ids_keeps_all_meta_files() {
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let lc = LanCoworkState::from_shared(&state);
        let (port, server) = two_response_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
            "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"files\":[{},{}]}",
        )
        .await;
        enable_native(&state, &lc, port).await;
        add_execute_session(&state, "all", "selective", None, &tmp.path().join("import")).await;
        let result = send(
            routes().with_state(lc.clone()),
            "POST",
            EXECUTE_PATH,
            r#"{"session_id":"all","file_ids":[]}"#,
        )
        .await;
        assert_ne!(result.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(result.status(), StatusCode::OK);
        wait_for_status(&state, "all", "completed").await;
        let total: Option<i64> =
            sqlx::query_scalar("SELECT total_files FROM import_session WHERE id='all'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(total, Some(2));
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("stub must receive both requests")
            .unwrap();
        crate::routes::lan_cowork_descriptor::reset_client_state();
    }

    #[tokio::test]
    async fn execute_route_marks_failed_after_executor_error() {
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let lc = LanCoworkState::from_shared(&state);
        let (port, server) = two_response_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
            "HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\n{\"files\":\"not-an-array\"}",
        )
        .await;
        enable_native(&state, &lc, port).await;
        add_execute_session(&state, "failed", "full", None, &tmp.path().join("import")).await;
        let result = send(
            routes().with_state(lc.clone()),
            "POST",
            EXECUTE_PATH,
            r#"{"session_id":"failed"}"#,
        )
        .await;
        assert_ne!(result.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(result.status(), StatusCode::OK);
        wait_for_status(&state, "failed", "failed").await;
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("stub must receive both requests")
            .unwrap();
        crate::routes::lan_cowork_descriptor::reset_client_state();
    }

    #[tokio::test]
    async fn execute_route_selective_filter_drops_malformed_files() {
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let lc = LanCoworkState::from_shared(&state);
        let (port, server) = two_response_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
            "HTTP/1.1 200 OK\r\nContent-Length: 28\r\n\r\n{\"files\":[{\"id\":1},{},null]}",
        )
        .await;
        enable_native(&state, &lc, port).await;
        add_execute_session(
            &state,
            "filtered",
            "selective",
            None,
            &tmp.path().join("import"),
        )
        .await;
        let result = send(
            routes().with_state(lc.clone()),
            "POST",
            EXECUTE_PATH,
            r#"{"session_id":"filtered","file_ids":[1]}"#,
        )
        .await;
        assert_ne!(result.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(result.status(), StatusCode::OK);
        wait_for_status(&state, "filtered", "failed").await;
        let total: Option<i64> =
            sqlx::query_scalar("SELECT total_files FROM import_session WHERE id='filtered'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(total, Some(1));
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("stub must receive both requests")
            .unwrap();
        crate::routes::lan_cowork_descriptor::reset_client_state();
    }

    #[tokio::test]
    async fn execute_route_accepts_array_meta_as_empty_import() {
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let lc = LanCoworkState::from_shared(&state);
        let (port, server) = two_response_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]",
        )
        .await;
        enable_native(&state, &lc, port).await;
        add_execute_session(&state, "array", "full", None, &tmp.path().join("import")).await;
        let result = send(
            routes().with_state(lc.clone()),
            "POST",
            EXECUTE_PATH,
            r#"{"session_id":"array"}"#,
        )
        .await;
        assert_ne!(result.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(result.status(), StatusCode::OK);
        wait_for_status(&state, "array", "completed").await;
        let total: Option<i64> =
            sqlx::query_scalar("SELECT total_files FROM import_session WHERE id='array'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(total, Some(0));
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("stub must receive both requests")
            .unwrap();
        crate::routes::lan_cowork_descriptor::reset_client_state();
    }

    #[test]
    fn guard_rejects_configured_project_root_and_allows_media() {
        let root = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        assert!(validate_import_folder(
            root.path().to_str().unwrap(),
            root.path(),
            Some(home.path().into())
        )
        .is_err());
        assert!(validate_import_folder(
            &root.path().join("nested").to_string_lossy(),
            root.path(),
            Some(home.path().into())
        )
        .is_err());
        assert_eq!(
            validate_import_folder(
                &home.path().join("Pictures/import").to_string_lossy(),
                root.path(),
                Some(home.path().into())
            )
            .unwrap(),
            home.path().join("Pictures/import")
        );
    }

    #[test]
    fn guard_rejects_root_dot_dirs_and_missing_home() {
        let root = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        assert!(validate_import_folder(
            "/tmp/import\0suffix",
            root.path(),
            Some(home.path().into())
        )
        .is_err());
        assert!(validate_import_folder("/", root.path(), Some(home.path().into())).is_err());
        assert!(validate_import_folder(
            &home.path().join(".config/x").to_string_lossy(),
            root.path(),
            Some(home.path().into())
        )
        .is_err());
        assert!(validate_import_folder("/tmp/import", root.path(), None).is_err());
    }

    #[test]
    fn request_strips_only_strict_strings() {
        let request = validate_request(CreateSessionRequest {
            peer_id: " p ".into(),
            peer_name: " n ".into(),
            mode: " full ".into(),
            import_folder: " /tmp/x ".into(),
            options: Map::new(),
        });
        assert!(request.is_err());
    }

    #[tokio::test]
    async fn route_requires_session_with_exact_response() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = test_state(tmp.path()).await;
        Arc::get_mut(&mut state).unwrap().config.pin_auth_enabled = true;
        let response = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "GET",
            SESSIONS_PATH,
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json(response).await,
            json!({"ok": false, "error": "session required"})
        );
    }

    // `valid_api_key_without_session_reaches_route_and_is_rejected` was relocated
    // to yu-server's `lan_cowork_split_integration_tests.rs` (S4d step 4): it
    // layers `auth_middleware`, which lives in yu-server and is unreachable
    // across the crate boundary.

    #[tokio::test]
    async fn list_and_get_routes_return_sessions_and_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        add_session(&state, "known").await;
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        let listed = send(app.clone(), "GET", SESSIONS_PATH, "").await;
        assert_eq!(listed.status(), StatusCode::OK);
        let listed = json(listed).await;
        assert_eq!(listed["ok"], true);
        assert_eq!(listed["sessions"][0]["id"], "known");
        let found = send(
            app.clone(),
            "GET",
            "/ext/lan_cowork/api/peer/import/session/known",
            "",
        )
        .await;
        assert_eq!(found.status(), StatusCode::OK);
        let found = json(found).await;
        assert_eq!(found["ok"], true);
        assert_eq!(found["session"]["id"], "known");
        let missing = send(app, "GET", SESSION_ID_PATH, "").await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            json(missing).await,
            json!({"ok": false, "error": "session not found"})
        );
    }

    #[tokio::test]
    async fn create_route_persists_resolved_import_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let folder = tmp
            .path()
            .join("..")
            .join(tmp.path().file_name().unwrap())
            .join("created");
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        let body = json!({"peer_id":"peer", "import_folder":folder, "options":{}}).to_string();
        let response = send(app.clone(), "POST", SESSION_PATH, &body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let unexpected = send(app, "POST", SESSION_ID_PATH, &body).await;
        assert!(matches!(
            unexpected.status(),
            StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_FOUND
        ));
        let response = json(response).await;
        assert_eq!(response["ok"], true);
        let id = response["session_id"].as_str().unwrap().to_owned();
        let saved: String =
            sqlx::query_scalar("SELECT import_folder FROM import_session WHERE id=?")
                .bind(id)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(saved, folder.canonicalize().unwrap().to_string_lossy());
    }

    #[tokio::test]
    async fn create_route_rejects_configured_project_root() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let project_root = state.config.project_root.clone();
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        for import_folder in [project_root.clone(), project_root.join("ui")] {
            let response = send(
                app.clone(),
                "POST",
                SESSION_PATH,
                &json!({"peer_id":"peer", "import_folder":import_folder}).to_string(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn create_route_rejects_each_json_validation_stage() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        let no_type = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(SESSION_PATH)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(json(no_type).await["code"], "invalid_content_type");
        let bad = send(app.clone(), "POST", SESSION_PATH, "{").await;
        assert_eq!(json(bad).await["code"], "invalid_json");
        let array = send(app.clone(), "POST", SESSION_PATH, "[]").await;
        assert_eq!(json(array).await["code"], "invalid_json_object");
        for body in [
            json!({"peer_id":"p", "import_folder":"/tmp/x", "extra":true}),
            json!({"peer_id":"p", "import_folder":"/tmp/x", "options":null}),
            json!({"peer_id":"p", "import_folder":"/tmp/x", "mode":" full "}),
            json!({"peer_id":"p", "import_folder":"   "}),
        ] {
            let response = send(app.clone(), "POST", SESSION_PATH, &body.to_string()).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(json(response).await["code"], "validation_error");
        }
    }

    #[cfg(unix)]
    #[test]
    fn guard_rejects_symlinked_sensitive_paths_and_bases() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let etc_link = root.path().join("etc-link");
        symlink("/etc", &etc_link).unwrap();
        assert!(validate_import_folder(
            &etc_link.join("x").to_string_lossy(),
            root.path(),
            Some(home.path().into())
        )
        .is_err());
        let usr = root.path().join("usr/lib");
        std::fs::create_dir_all(&usr).unwrap();
        let lib = root.path().join("lib");
        symlink(&usr, &lib).unwrap();
        assert!(validate_import_folder(
            &usr.join("x").to_string_lossy(),
            &lib,
            Some(home.path().into())
        )
        .is_err());
    }

    #[tokio::test]
    async fn create_route_reports_mkdir_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let file = tmp.path().join("not-a-directory");
        std::fs::write(&file, "x").unwrap();
        let response = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            SESSION_PATH,
            &json!({"peer_id":"peer", "import_folder":file}).to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(json(response).await["error"]
            .as_str()
            .unwrap()
            .contains("cannot create import_folder"));
    }

    // `index_route_requires_session_and_rejects_api_key_without_session` was
    // relocated to yu-server's `lan_cowork_split_integration_tests.rs` (S4d
    // step 4): it layers `auth_middleware`, which lives in yu-server and is
    // unreachable across the crate boundary.

    #[tokio::test]
    async fn index_route_validates_folder_before_native_gate_and_checks_native_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let lc = LanCoworkState::from_shared(&state);
        let app = routes().with_state(lc.clone());
        for body in [
            json!({}),
            json!({"peer_id":"p","import_folder":"/tmp/x","extra":true}),
            json!({"peer_id":" ","import_folder":"/tmp/x"}),
            json!({"peer_id":5,"import_folder":"/tmp/x"}),
            json!({"peer_id":"p","import_folder":"/tmp/x","options":null}),
        ] {
            let response = send(app.clone(), "POST", INDEX_PATH, &body.to_string()).await;
            assert_ne!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        let response = send(
            app.clone(),
            "POST",
            INDEX_PATH,
            &json!({"peer_id":"p","import_folder":state.config.project_root}).to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = send(
            app,
            "POST",
            INDEX_PATH,
            &json!({"peer_id":"p","import_folder":tmp.path().join("import")}).to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        enable_native_without_peer(&state, &lc).await;
        let response = send(
            routes().with_state(lc.clone()),
            "POST",
            INDEX_PATH,
            &json!({"peer_id":"p","import_folder":tmp.path().join("import")}).to_string(),
        )
        .await;
        assert_ne!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn index_route_fetches_without_mkdir_and_persists_payload() {
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path()).await;
        let lc = LanCoworkState::from_shared(&state);
        let index = json!({"files":[{"id":1,"nested":{"path":["a","b"]}}]});
        let (port, server) = one_response_server(http("200 OK", &index.to_string())).await;
        enable_native(&state, &lc, port).await;
        *crate::routes::lan_cowork_descriptor::TEST_DESCRIPTOR
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
        let folder = tmp.path().join("not-created");
        let response = send(
            routes().with_state(lc.clone()),
            "POST",
            INDEX_PATH,
            &json!({"peer_id":"peer","import_folder":folder}).to_string(),
        )
        .await;
        assert_ne!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["index"], index);
        assert!(!folder.is_dir());
        let id = body["session_id"].as_str().unwrap();
        let saved: (String, String, String) =
            sqlx::query_as("SELECT mode, peer_name, options FROM import_session WHERE id=?")
                .bind(id)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(saved.0, "selective");
        assert_eq!(saved.1, "Peer");
        assert_eq!(
            serde_json::from_str::<Value>(&saved.2).unwrap(),
            json!({"include_favorites":false,"merge_metadata":false})
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .expect("stub must receive index request")
                .unwrap(),
            "GET /ext/lan_cowork/api/peer/import/meta?mode=index HTTP/1.1"
        );
    }

    #[tokio::test]
    async fn index_route_persists_options_hides_failures_and_maps_non_objects() {
        let _guard = crate::routes::lan_cowork_descriptor::test_guard();
        for (reply, options, expected_status, expected_index) in [
            (
                r#"{"nested":{"a":1}}"#,
                json!({"a":1}),
                StatusCode::OK,
                Some(json!({"nested":{"a":1}})),
            ),
            (
                r#"{"error":"peer secret"}"#,
                json!({}),
                StatusCode::BAD_GATEWAY,
                None,
            ),
            ("[]", json!({}), StatusCode::OK, Some(json!({}))),
            ("1", json!({}), StatusCode::OK, Some(json!({}))),
            (r#""text""#, json!({}), StatusCode::OK, Some(json!({}))),
            ("true", json!({}), StatusCode::OK, Some(json!({}))),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let state = test_state(tmp.path()).await;
            let lc = LanCoworkState::from_shared(&state);
            let status = if reply.contains("peer secret") {
                "500 Internal Server Error"
            } else {
                "200 OK"
            };
            let (port, server) = one_response_server(http(status, reply)).await;
            enable_native(&state, &lc, port).await;
            let response = send(
                routes().with_state(lc.clone()),
                "POST",
                INDEX_PATH,
                &json!({"peer_id":"peer","import_folder":tmp.path().join("import"),"options":options}).to_string(),
            )
            .await;
            assert_ne!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.status(), expected_status);
            let body = json(response).await;
            if let Some(expected_index) = expected_index {
                assert_eq!(body["index"], expected_index);
                if options == json!({"a":1}) {
                    let saved: String =
                        sqlx::query_scalar("SELECT options FROM import_session WHERE id=?")
                            .bind(body["session_id"].as_str().unwrap())
                            .fetch_one(&state.db)
                            .await
                            .unwrap();
                    assert_eq!(
                        serde_json::from_str::<Value>(&saved).unwrap(),
                        json!({"a":1,"include_favorites":false,"merge_metadata":false})
                    );
                }
            } else {
                assert_eq!(body, json!({"ok":false,"error":"failed to fetch index"}));
            }
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .expect("stub must receive index request")
                .unwrap();
        }
    }
}
