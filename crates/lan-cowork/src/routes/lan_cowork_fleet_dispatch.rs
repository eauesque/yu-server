//! Chief-side fleet update/restart dispatch runners and history.
//!
//! Dispatches are intentionally process-local: Python does not resume them after
//! process exit. A cancelled task also intentionally leaves its ledger entry in
//! `running`, matching Python rather than inventing recovery in this increment.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::{Extension, RawQuery, State},
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::{stream, StreamExt};
use indexmap::IndexMap;
use reqwest::header::HeaderValue;
use serde::Serialize;
use serde_json::{json, Map, Value};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::routes::{
    lan_cowork::load_config_json,
    lan_cowork_client::{build_peer_client, read_peer_response_capped, OutboundFailure},
    lan_cowork_discovery::load_identity_seed,
    lan_cowork_fleet_config::get_fleet_timings,
    lan_cowork_fleet_manager::{chief_enabled, FleetManager},
    lan_cowork_host::LanCoworkState,
    lan_cowork_registry::{PeerInfo, PeerRegistry},
    lan_cowork_transport::build_peer_headers_at,
};

/// Routes owned by this module, mounted on `LanCoworkState`. `main.rs` applies
/// `.with_state(lc_state)` to this sub-router before merging it into the
/// core `SharedState` builder chain (see the S3 decoupling plan's §3 proof).
pub fn routes() -> Router<LanCoworkState> {
    Router::new()
        .route(
            "/ext/lan_cowork/fleet/update/dispatch",
            post(fleet_update_dispatch),
        )
        .route(
            "/ext/lan_cowork/fleet/update/dispatch/status",
            get(fleet_update_dispatch_status),
        )
        .route(
            "/ext/lan_cowork/fleet/restart/dispatch",
            post(fleet_restart_dispatch),
        )
}

const INFO_PATH: &str = "/ext/lan_cowork/fleet/info";
const RESTART_PATH: &str = "/ext/lan_cowork/fleet/restart";
const UPDATE_PATH: &str = "/ext/lan_cowork/fleet/update";
const UPDATE_STATUS_PATH: &str = "/ext/lan_cowork/fleet/update/status";
const MAX_RESTART_FANOUT: usize = 10;
const MAX_DISPATCH_HISTORY: usize = 10;

fn response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

async fn dispatch_registry(
    state: &LanCoworkState,
    session: Option<&tower_sessions::Session>,
) -> Result<Arc<PeerRegistry>, Response> {
    let Some(registry) = state.peer_registry.get().cloned() else {
        return Err(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"service_unavailable"}),
        ));
    };
    if state.require_session(session).await.is_some() {
        return Err(response(
            StatusCode::UNAUTHORIZED,
            json!({"error":"session required"}),
        ));
    }
    if !chief_enabled(&**state) {
        return Err(response(
            StatusCode::FORBIDDEN,
            json!({"error":"not_chief","message":"chief only"}),
        ));
    }
    Ok(registry)
}

// Axum responses stay unboxed to preserve the existing handler error contract.
#[allow(clippy::result_large_err)]
fn json_object(headers: &HeaderMap, body: &[u8]) -> Result<Map<String, Value>, Response> {
    let mime = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or("")
        .to_ascii_lowercase();
    if mime != "application/json" && !mime.ends_with("+json") {
        return Err(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"JSON body is required","code":"invalid_content_type"}),
        ));
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        response(
            StatusCode::BAD_REQUEST,
            json!({"error":"Invalid JSON body","code":"invalid_json"}),
        )
    })?;
    if value.is_null() {
        return Err(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"Invalid JSON body","code":"invalid_json"}),
        ));
    }
    value.as_object().cloned().ok_or_else(|| {
        response(
            StatusCode::BAD_REQUEST,
            json!({"error":"JSON object body is required","code":"invalid_json_object"}),
        )
    })
}

fn validation_error(error: &str, message: &str) -> Response {
    response(
        StatusCode::BAD_REQUEST,
        json!({"error":error,"message":message}),
    )
}

// Axum responses stay unboxed to preserve the existing handler error contract.
#[allow(clippy::result_large_err)]
fn validate_peer_ids(data: &Map<String, Value>) -> Result<Vec<String>, Response> {
    let value = data.get("peer_ids");
    if value.is_none() || value.is_some_and(|value| !python_truthy(value)) {
        return Ok(Vec::new());
    }
    let Some(items) = value.and_then(Value::as_array) else {
        return Err(validation_error(
            "invalid_peer_ids",
            "peer_ids must be a list",
        ));
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    validation_error(
                        "invalid_peer_ids",
                        "peer_ids must be a list of non-empty strings",
                    )
                })
        })
        .collect()
}

// Axum responses stay unboxed to preserve the existing handler error contract.
#[allow(clippy::result_large_err)]
fn validate_consent_tokens(data: &Map<String, Value>) -> Result<HashMap<String, String>, Response> {
    let value = data.get("consent_tokens");
    if value.is_none() || value.is_some_and(|value| !python_truthy(value)) {
        return Ok(HashMap::new());
    }
    let Some(tokens) = value.and_then(Value::as_object) else {
        return Err(validation_error(
            "invalid_consent_tokens",
            "consent_tokens must be an object",
        ));
    };
    tokens
        .iter()
        .map(|(peer_id, token)| {
            let peer_id = peer_id.trim();
            if peer_id.is_empty() {
                return Err(validation_error(
                    "invalid_consent_tokens",
                    "consent_tokens keys must be non-empty strings",
                ));
            }
            let Some(token) = token.as_str() else {
                return Err(validation_error(
                    "invalid_consent_tokens",
                    "consent_tokens values must be strings",
                ));
            };
            Ok((peer_id.to_owned(), token.to_owned()))
        })
        .collect()
}

// Axum responses stay unboxed to preserve the existing handler error contract.
#[allow(clippy::result_large_err)]
fn required_string(
    data: &Map<String, Value>,
    key: &str,
    default: &str,
) -> Result<String, Response> {
    let value = match data.get(key) {
        None => default,
        Some(value) => value.as_str().unwrap_or(""),
    }
    .trim();
    if value.is_empty() {
        return Err(validation_error(
            &format!("invalid_{key}"),
            &format!("{key} must be a non-empty string"),
        ));
    }
    Ok(value.to_owned())
}

fn runner_error(message: String) -> Response {
    validation_error("cannot_dispatch_self", &message)
}

fn dispatch_id(prefix: &str) -> String {
    format!("{prefix}{}", &Uuid::new_v4().simple().to_string()[..8])
}

fn query_value(query: Option<&str>, key: &str) -> String {
    url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .find_map(|(name, value)| (name == key).then(|| value.trim().to_owned()))
        .unwrap_or_default()
}

async fn finish_dispatch(manager: Arc<FleetManager>, project_root: PathBuf, status: Option<Value>) {
    if let Some(status) = status {
        save_dispatch_history(&project_root, &status);
    }
    manager.dispatches.gc_dispatches().await;
}

pub async fn fleet_update_dispatch(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let registry =
        match dispatch_registry(&state, session.as_ref().map(|Extension(session)| session)).await {
            Ok(registry) => registry,
            Err(response) => return response,
        };
    let data = match json_object(&headers, &body) {
        Ok(data) => data,
        Err(response) => return response,
    };
    let peer_ids = match validate_peer_ids(&data) {
        Ok(peer_ids) => peer_ids,
        Err(response) => return response,
    };
    let consent_tokens = match validate_consent_tokens(&data) {
        Ok(tokens) => tokens,
        Err(response) => return response,
    };
    let source = match required_string(&data, "source", "origin") {
        Ok(source) => source,
        Err(response) => return response,
    };
    let branch = match required_string(&data, "branch", "main") {
        Ok(branch) => branch,
        Err(response) => return response,
    };
    if peer_ids.is_empty() {
        return validation_error("no_peers", "peer_ids is required");
    }
    if peer_ids
        .iter()
        .any(|peer_id| peer_id == &registry.local_peer_id())
    {
        return validation_error("cannot_dispatch_self", "chief cannot dispatch to itself");
    }

    let dispatch_id = dispatch_id("disp_");
    let runner = match DispatchRunner::new(
        state.clone(),
        dispatch_id.clone(),
        peer_ids.clone(),
        source,
        branch,
        consent_tokens,
    ) {
        Ok(runner) => runner,
        Err(message) => return runner_error(message),
    };
    state
        .fleet_manager
        .dispatches
        .insert(dispatch_id.clone(), DispatchHandle::Update(runner.clone()))
        .await;
    let manager = state.fleet_manager.clone();
    let project_root = state.project_root().to_path_buf();
    tokio::spawn(async move {
        let worker = runner.clone();
        let status = tokio::spawn(async move {
            worker.run().await;
            worker.get_status().await
        })
        .await
        .ok();
        finish_dispatch(manager, project_root, status).await;
    });
    Json(json!({"dispatch_id":dispatch_id,"peer_count":peer_ids.len()})).into_response()
}

pub async fn fleet_update_dispatch_status(
    State(state): State<LanCoworkState>,
    RawQuery(query): RawQuery,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    if let Err(response) =
        dispatch_registry(&state, session.as_ref().map(|Extension(session)| session)).await
    {
        return response;
    }
    let dispatch_id = query_value(query.as_deref(), "dispatch_id");
    if let Some(runner) = state.fleet_manager.dispatches.get(&dispatch_id).await {
        return Json(runner.get_status().await).into_response();
    }
    if let Some(entry) = load_dispatch_history(state.project_root())
        .into_iter()
        .find(|entry| {
            entry.get("dispatch_id").and_then(Value::as_str) == Some(dispatch_id.as_str())
        })
    {
        return Json(entry).into_response();
    }
    response(StatusCode::NOT_FOUND, json!({"error":"dispatch_not_found"}))
}

pub async fn fleet_restart_dispatch(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let registry =
        match dispatch_registry(&state, session.as_ref().map(|Extension(session)| session)).await {
            Ok(registry) => registry,
            Err(response) => return response,
        };
    let data = match json_object(&headers, &body) {
        Ok(data) => data,
        Err(response) => return response,
    };
    let peer_ids = match validate_peer_ids(&data) {
        Ok(peer_ids) => peer_ids,
        Err(response) => return response,
    };
    if peer_ids.is_empty() {
        return validation_error("no_peers", "peer_ids is required");
    }
    if peer_ids
        .iter()
        .any(|peer_id| peer_id == &registry.local_peer_id())
    {
        return validation_error("cannot_dispatch_self", "chief cannot dispatch to itself");
    }

    let dispatch_id = dispatch_id("rstrt_");
    let runner =
        match RestartDispatchRunner::new(state.clone(), dispatch_id.clone(), peer_ids.clone()) {
            Ok(runner) => runner,
            Err(message) => return runner_error(message),
        };
    state
        .fleet_manager
        .dispatches
        .insert(dispatch_id.clone(), DispatchHandle::Restart(runner.clone()))
        .await;
    let manager = state.fleet_manager.clone();
    let project_root = state.project_root().to_path_buf();
    tokio::spawn(async move {
        let worker = runner.clone();
        let status = tokio::spawn(async move {
            worker.run().await;
            worker.get_status().await
        })
        .await
        .ok();
        finish_dispatch(manager, project_root, status).await;
    });
    Json(json!({"dispatch_id":dispatch_id,"peer_count":peer_ids.len()})).into_response()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DispatchState {
    Pending,
    Running,
    Success,
    Failed,
}

#[derive(Debug)]
enum DispatchError {
    PeerNotFound,
    Timeout,
    Code(String),
}

impl DispatchError {
    fn update_code(self, peer_id: &str) -> String {
        match self {
            Self::PeerNotFound => format!("peer {peer_id} not found"),
            Self::Timeout => "timeout".to_owned(),
            Self::Code(code) => code,
        }
    }
}

#[async_trait]
trait DispatchTransport: Send + Sync {
    async fn fetch_uptime(&self, peer_id: &str) -> Result<u64, DispatchError>;
    async fn post_restart(&self, peer_id: &str) -> Result<(), DispatchError>;
    async fn post_update_to_peer(
        &self,
        peer_id: &str,
        source: &str,
        branch: &str,
        consent_token: Option<&str>,
    ) -> Result<Value, DispatchError>;
    async fn poll_peer_job(
        &self,
        peer_id: &str,
        job_id: &str,
        timeout: Duration,
    ) -> Result<Value, DispatchError>;
}

struct HttpDispatchTransport {
    state: LanCoworkState,
}

impl HttpDispatchTransport {
    fn peer(&self, peer_id: &str) -> Result<PeerInfo, DispatchError> {
        self.state
            .peer_registry
            .get()
            .and_then(|registry| registry.get(peer_id))
            .ok_or(DispatchError::PeerNotFound)
    }

    async fn headers(
        &self,
        peer: &PeerInfo,
        requested_with: &'static str,
        method: &str,
        path: &str,
        query: &str,
        body: &[u8],
    ) -> Result<reqwest::header::HeaderMap, DispatchError> {
        let registry = self
            .state
            .peer_registry
            .get()
            .ok_or_else(|| DispatchError::Code("registry_unavailable".to_owned()))?;
        let seed = load_identity_seed(self.state.db_read())
            .await
            .ok_or_else(|| DispatchError::Code("identity_unavailable".to_owned()))?;
        let mut headers = build_peer_headers_at(
            unix_now(),
            &seed,
            &registry.local_peer_id(),
            peer,
            method,
            path,
            query,
            body,
        )
        .map_err(|_| DispatchError::Code("header_build_failed".to_owned()))?;
        headers.insert("X-Requested-With", HeaderValue::from_static(requested_with));
        Ok(headers)
    }

    async fn client(
        peer: &PeerInfo,
        timeout: Duration,
    ) -> Result<(reqwest::Client, String), DispatchError> {
        build_peer_client(&peer.api_host, peer.api_port, Some(timeout), None)
            .await
            .map_err(|_| DispatchError::Code("request_failed".to_owned()))
    }
}

#[async_trait]
impl DispatchTransport for HttpDispatchTransport {
    async fn fetch_uptime(&self, peer_id: &str) -> Result<u64, DispatchError> {
        let peer = self.peer(peer_id)?;
        let headers = self
            .headers(&peer, "RestartDispatchRunner", "GET", INFO_PATH, "", &[])
            .await?;
        let (client, base) = Self::client(&peer, Duration::from_secs(5)).await?;
        let response = client
            .get(format!("{base}{INFO_PATH}"))
            .headers(headers)
            .send()
            .await
            .map_err(request_error)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(DispatchError::Code(format!(
                "http_{}",
                response.status().as_u16()
            )));
        }
        let body = read_peer_response_capped(response)
            .await
            .map_err(response_error)?;
        parse_uptime(&body).map_err(|_| DispatchError::Code("non_json_200".to_owned()))
    }

    async fn post_restart(&self, peer_id: &str) -> Result<(), DispatchError> {
        let peer = self.peer(peer_id)?;
        let body = b"{}";
        let headers = self
            .headers(
                &peer,
                "RestartDispatchRunner",
                "POST",
                RESTART_PATH,
                "",
                body,
            )
            .await?;
        let (client, base) = Self::client(&peer, Duration::from_secs(10)).await?;
        let response = client
            .post(format!("{base}{RESTART_PATH}"))
            .headers(headers)
            .body(body.as_slice().to_owned())
            .send()
            .await
            .map_err(request_error)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(DispatchError::Code(format!(
                "http_{}",
                response.status().as_u16()
            )));
        }
        Ok(())
    }

    async fn post_update_to_peer(
        &self,
        peer_id: &str,
        source: &str,
        branch: &str,
        consent_token: Option<&str>,
    ) -> Result<Value, DispatchError> {
        let peer = self.peer(peer_id)?;
        let body = update_body(source, branch);
        let mut headers = self
            .headers(&peer, "DispatchRunner", "POST", UPDATE_PATH, "", &body)
            .await?;
        if let Some(token) = consent_token {
            headers.insert(
                "X-Consent-Token",
                HeaderValue::try_from(token)
                    .map_err(|_| DispatchError::Code("header_build_failed".to_owned()))?,
            );
        }
        let (client, base) = Self::client(&peer, Duration::from_secs(30)).await?;
        let response = client
            .post(format!("{base}{UPDATE_PATH}"))
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(request_error)?;
        let status = response.status();
        let body = read_peer_response_capped(response)
            .await
            .map_err(response_error)?;
        serde_json::from_str(&body).map_err(|_| {
            DispatchError::Code(if status == reqwest::StatusCode::OK {
                "non_json_200".to_owned()
            } else {
                format!("http_{}", status.as_u16())
            })
        })
    }

    async fn poll_peer_job(
        &self,
        peer_id: &str,
        job_id: &str,
        timeout: Duration,
    ) -> Result<Value, DispatchError> {
        let peer = self.peer(peer_id)?;
        let query = format!("job_id={job_id}");
        let headers = self
            .headers(
                &peer,
                "DispatchRunner",
                "GET",
                UPDATE_STATUS_PATH,
                &query,
                &[],
            )
            .await?;
        let (client, base) = Self::client(&peer, Duration::from_secs(10)).await?;
        let url = format!("{base}{UPDATE_STATUS_PATH}?{query}");
        tokio::time::timeout(timeout, async {
            loop {
                if let Ok(response) = client.get(&url).headers(headers.clone()).send().await {
                    if response.status() == reqwest::StatusCode::OK {
                        if let Ok(body) = read_peer_response_capped(response).await {
                            if let Ok(result) = serde_json::from_str::<Value>(&body) {
                                if matches!(
                                    result.get("status").and_then(Value::as_str),
                                    Some("success" | "failed")
                                ) {
                                    return result;
                                }
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        })
        .await
        .map_err(|_| DispatchError::Timeout)
    }
}

fn request_error(error: reqwest::Error) -> DispatchError {
    if error.is_timeout() {
        DispatchError::Timeout
    } else {
        DispatchError::Code("request_failed".to_owned())
    }
}

fn response_error(error: OutboundFailure) -> DispatchError {
    DispatchError::Code(
        match error {
            OutboundFailure::BodyTooLarge => "response_too_large",
            _ => "non_json_200",
        }
        .to_owned(),
    )
}

fn parse_uptime(body: &str) -> Result<u64, ()> {
    let value: Value = serde_json::from_str(body).map_err(|_| ())?;
    let uptime = value.get("process_uptime_sec").unwrap_or(&Value::Null);
    Ok(uptime
        .as_u64()
        .or_else(|| uptime.as_str().and_then(|value| value.parse().ok()))
        .unwrap_or(0))
}

fn update_body(source: &str, branch: &str) -> Vec<u8> {
    format!(
        "{{\"source\":{},\"branch\":{}}}",
        serde_json::to_string(source).expect("string serialization cannot fail"),
        serde_json::to_string(branch).expect("string serialization cannot fail")
    )
    .into_bytes()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn timestamp() -> String {
    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
}

#[derive(Clone, Serialize)]
struct RestartPeerStatus {
    peer_id: String,
    status: DispatchState,
    current_step: Option<String>,
    error: Option<Value>,
    pre_uptime: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    post_uptime: Option<u64>,
}

#[derive(Serialize)]
struct RestartStatus {
    dispatch_id: String,
    kind: &'static str,
    status: DispatchState,
    started_at: String,
    finished_at: Option<String>,
    peers: Vec<RestartPeerStatus>,
}

#[derive(Clone)]
pub(crate) struct RestartDispatchRunner {
    status: Arc<RwLock<RestartStatus>>,
    transport: Arc<dyn DispatchTransport>,
}

impl RestartDispatchRunner {
    pub(crate) fn new(
        state: LanCoworkState,
        dispatch_id: String,
        peer_ids: Vec<String>,
    ) -> Result<Self, String> {
        let local_peer_id = state
            .peer_registry
            .get()
            .map(|registry| registry.local_peer_id())
            .ok_or_else(|| "registry_unavailable".to_owned())?;
        Self::build(
            &local_peer_id,
            dispatch_id,
            peer_ids,
            Arc::new(HttpDispatchTransport { state }),
        )
    }

    fn build(
        local_peer_id: &str,
        dispatch_id: String,
        peer_ids: Vec<String>,
        transport: Arc<dyn DispatchTransport>,
    ) -> Result<Self, String> {
        if peer_ids.iter().any(|peer_id| peer_id == local_peer_id) {
            return Err("cannot_dispatch_self".to_owned());
        }
        Ok(Self {
            status: Arc::new(RwLock::new(RestartStatus {
                dispatch_id,
                kind: "restart",
                status: DispatchState::Pending,
                started_at: timestamp(),
                finished_at: None,
                peers: peer_ids
                    .into_iter()
                    .map(|peer_id| RestartPeerStatus {
                        peer_id,
                        status: DispatchState::Pending,
                        current_step: None,
                        error: None,
                        pre_uptime: None,
                        post_uptime: None,
                    })
                    .collect(),
            })),
            transport,
        })
    }

    pub(crate) async fn get_status(&self) -> Value {
        serde_json::to_value(&*self.status.read().await).unwrap_or_else(|_| json!({}))
    }

    pub(crate) async fn run(&self) {
        self.status.write().await.status = DispatchState::Running;
        let peer_count = self.status.read().await.peers.len();
        stream::iter(0..peer_count)
            .for_each_concurrent(MAX_RESTART_FANOUT, |index| self.restart_one(index))
            .await;
        let mut status = self.status.write().await;
        status.status = if status
            .peers
            .iter()
            .any(|peer| peer.status == DispatchState::Failed)
        {
            DispatchState::Failed
        } else {
            DispatchState::Success
        };
        status.finished_at = Some(timestamp());
    }

    async fn restart_one(&self, index: usize) {
        let peer_id = self.status.read().await.peers[index].peer_id.clone();
        let pre_uptime = match self.transport.fetch_uptime(&peer_id).await {
            Ok(uptime) => uptime,
            Err(DispatchError::PeerNotFound) => {
                self.fail_restart(index, "peer_not_found").await;
                return;
            }
            Err(_) => {
                self.fail_restart(index, "pre_uptime_unavailable").await;
                return;
            }
        };
        {
            let mut status = self.status.write().await;
            let peer = &mut status.peers[index];
            peer.pre_uptime = Some(pre_uptime);
            peer.status = DispatchState::Running;
            peer.current_step = Some("restart_signal".to_owned());
        }
        if let Err(error) = self.transport.post_restart(&peer_id).await {
            let error = match error {
                DispatchError::PeerNotFound => "peer_not_found".to_owned(),
                DispatchError::Timeout => "timeout".to_owned(),
                DispatchError::Code(code) => code,
            };
            self.fail_restart(index, &error).await;
            return;
        }
        self.status.write().await.peers[index].current_step = Some("awaiting_restart".to_owned());

        // Operational caveat / Rust-Python divergence: Python keeps a plain
        // `saw_down && uptime < pre_uptime` conjunction, because its own
        // restart is slow enough that the first poll reliably observes the
        // peer down first. A Rust peer can restart (execv) faster than the
        // first 3-second poll interval, so `saw_down` may never become true
        // even though the restart genuinely succeeded -- the old conjunction
        // alone would then misreport `restart_timeout` for 60s and drive
        // fleet-wide restart-retry loops. Rust therefore ALSO accepts a
        // restart as soon as the peer's reported uptime is younger than how
        // long we have been watching it (`elapsed_since_t0`); this is a pure
        // OR addition, the original conjunction path below is unchanged.
        // Safety: `uptime_seconds` is served from `state.start_time.elapsed()`
        // where `start_time = Instant::now()` at `AppState` construction
        // (yu-server/src/routes/server_info.rs, yu-server/src/state.rs), so
        // it is process uptime and resets on `execv`. Absent a restart, the
        // peer's true uptime at any poll is `pre_uptime + true_elapsed_since_t0`,
        // which is always >= `elapsed_since_t0` (pre_uptime >= 0), so the new
        // condition is false for every peer that has not restarted. It is
        // one-directional and can only fire when a restart genuinely
        // happened; it can never turn a real FAILED into a false SUCCESS.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let t0 = tokio::time::Instant::now();
        let mut saw_down = false;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let Ok(uptime) = self.transport.fetch_uptime(&peer_id).await else {
                saw_down = true;
                continue;
            };
            // No slack term here, deliberately: both sources of measurement
            // error bias the comparison toward detecting a real restart, not
            // away from it, so they need no compensation. (1) `fetch_uptime`
            // reports whole seconds truncated from `Instant::elapsed().as_secs()`
            // (see lan_cowork_fleet_machine.rs), so the reported value can
            // only read LOWER than the true uptime, which makes
            // `uptime < elapsed_since_t0` easier to satisfy for a genuine
            // restart, not harder. (2) the peer samples its uptime before
            // the HTTP response reaches us, while we read `elapsed_since_t0`
            // after it arrives, so the reported uptime is stale-low relative
            // to our clock -- again easier, not harder. Detection is already
            // strict without slack: exec happens at some `t_exec > t0`, so
            // at poll time the new process's true age is
            // `elapsed_since_t0 - (t_exec - t0) < elapsed_since_t0`, and
            // flooring only lowers the reported value further, so a genuine
            // restart always satisfies the strict `<` below. Conversely, for
            // a peer that never restarts, uptime = pre_uptime +
            // elapsed_since_t0, so the condition reduces to `pre_uptime < 0`,
            // which is never true for a `u64` -- unconditionally safe. Any
            // positive epsilon `E` would instead reduce it to
            // `pre_uptime < E`, firing at the very first poll, forever, for
            // every peer whose pre_uptime happened to be under `E` when the
            // restart was dispatched, independent of what actually happened
            // to it -- exactly the false-success path this change exists to
            // avoid, and precisely misreporting the boot-loop case an
            // operator most needs to see. So: no epsilon.
            let elapsed_since_t0 = tokio::time::Instant::now()
                .saturating_duration_since(t0)
                .as_secs_f64();
            let restarted_before_first_poll = (uptime as f64) < elapsed_since_t0;
            if (saw_down && uptime < pre_uptime) || restarted_before_first_poll {
                let mut status = self.status.write().await;
                let peer = &mut status.peers[index];
                peer.status = DispatchState::Success;
                peer.current_step = Some("online".to_owned());
                peer.post_uptime = Some(uptime);
                return;
            }
        }
        self.fail_restart(index, "restart_timeout").await;
    }

    async fn fail_restart(&self, index: usize, error: &str) {
        let mut status = self.status.write().await;
        status.peers[index].status = DispatchState::Failed;
        status.peers[index].error = Some(json!(error));
    }
}

#[derive(Clone, Serialize)]
struct UpdatePeerStatus {
    peer_id: String,
    job_id: Option<String>,
    status: DispatchState,
    current_step: Option<String>,
    error: Option<Value>,
}

#[derive(Serialize)]
struct UpdateDispatchStatus {
    dispatch_id: String,
    status: DispatchState,
    started_at: String,
    finished_at: Option<String>,
    source: String,
    branch: String,
    peers: Vec<UpdatePeerStatus>,
}

#[derive(Clone)]
pub(crate) struct DispatchRunner {
    status: Arc<RwLock<UpdateDispatchStatus>>,
    consent_tokens: Arc<HashMap<String, String>>,
    transport: Arc<dyn DispatchTransport>,
    timeout: Arc<dyn Fn() -> Duration + Send + Sync>,
}

impl DispatchRunner {
    pub(crate) fn new(
        state: LanCoworkState,
        dispatch_id: String,
        peer_ids: Vec<String>,
        source: String,
        branch: String,
        consent_tokens: HashMap<String, String>,
    ) -> Result<Self, String> {
        let local_peer_id = state
            .peer_registry
            .get()
            .map(|registry| registry.local_peer_id())
            .ok_or_else(|| "registry_unavailable".to_owned())?;
        let transport = Arc::new(HttpDispatchTransport {
            state: state.clone(),
        });
        let timeout_state = state;
        Self::build(
            &local_peer_id,
            dispatch_id,
            peer_ids,
            source,
            branch,
            consent_tokens,
            transport,
            Arc::new(move || update_timeout(&timeout_state)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        local_peer_id: &str,
        dispatch_id: String,
        peer_ids: Vec<String>,
        source: String,
        branch: String,
        consent_tokens: HashMap<String, String>,
        transport: Arc<dyn DispatchTransport>,
        timeout: Arc<dyn Fn() -> Duration + Send + Sync>,
    ) -> Result<Self, String> {
        if peer_ids.iter().any(|peer_id| peer_id == local_peer_id) {
            return Err("cannot_dispatch_self".to_owned());
        }
        Ok(Self {
            status: Arc::new(RwLock::new(UpdateDispatchStatus {
                dispatch_id,
                status: DispatchState::Pending,
                started_at: timestamp(),
                finished_at: None,
                source,
                branch,
                peers: peer_ids
                    .into_iter()
                    .map(|peer_id| UpdatePeerStatus {
                        peer_id,
                        job_id: None,
                        status: DispatchState::Pending,
                        current_step: None,
                        error: None,
                    })
                    .collect(),
            })),
            consent_tokens: Arc::new(consent_tokens),
            transport,
            timeout,
        })
    }

    pub(crate) async fn get_status(&self) -> Value {
        serde_json::to_value(&*self.status.read().await).unwrap_or_else(|_| json!({}))
    }

    /// Dispatches sequentially; failure skips only the current peer's remainder.
    pub(crate) async fn run(&self) {
        self.status.write().await.status = DispatchState::Running;
        let peer_count = self.status.read().await.peers.len();
        for index in 0..peer_count {
            let peer_id = self.status.read().await.peers[index].peer_id.clone();
            let source = self.status.read().await.source.clone();
            let branch = self.status.read().await.branch.clone();
            let consent = self
                .consent_tokens
                .get(&peer_id)
                .filter(|token| !token.is_empty())
                .map(String::as_str);
            let job = match self
                .transport
                .post_update_to_peer(&peer_id, &source, &branch, consent)
                .await
            {
                Ok(job) => job,
                Err(error) => {
                    self.fail_update(index, error.update_code(&peer_id)).await;
                    continue;
                }
            };
            let Some(job_id) = job
                .get("job_id")
                .and_then(Value::as_str)
                .filter(|job_id| !job_id.is_empty())
                .map(str::to_owned)
            else {
                let error = job
                    .get("error")
                    .filter(|value| python_truthy(value))
                    .cloned()
                    .unwrap_or_else(|| json!("no_job_id"));
                let mut status = self.status.write().await;
                status.peers[index].status = DispatchState::Failed;
                status.peers[index].error = Some(error);
                continue;
            };
            {
                let mut status = self.status.write().await;
                status.peers[index].job_id = Some(job_id.clone());
                status.peers[index].status = DispatchState::Running;
            }

            // Read inside the loop so config changes affect the next peer.
            let timeout = (self.timeout)();
            match self
                .transport
                .poll_peer_job(&peer_id, &job_id, timeout)
                .await
            {
                Ok(result) => {
                    let mut status = self.status.write().await;
                    let peer = &mut status.peers[index];
                    peer.status = match result.get("status").and_then(Value::as_str) {
                        Some("success") => DispatchState::Success,
                        _ => DispatchState::Failed,
                    };
                    peer.current_step = result
                        .get("steps")
                        .and_then(Value::as_array)
                        .and_then(|steps| steps.last())
                        .and_then(|step| step.get("name"))
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    peer.error = result
                        .get("error")
                        .cloned()
                        .filter(|value| !value.is_null());
                }
                Err(error) => self.fail_update(index, error.update_code(&peer_id)).await,
            }
        }

        let mut status = self.status.write().await;
        status.status = if status
            .peers
            .iter()
            .any(|peer| peer.status == DispatchState::Failed)
        {
            DispatchState::Failed
        } else {
            DispatchState::Success
        };
        status.finished_at = Some(timestamp());
    }

    async fn fail_update(&self, index: usize, error: String) {
        let mut status = self.status.write().await;
        status.peers[index].status = DispatchState::Failed;
        status.peers[index].error = Some(json!(error));
    }
}

fn update_timeout(state: &LanCoworkState) -> Duration {
    let timings = get_fleet_timings(&load_config_json(state.config_path()));
    let seconds = timings["update_job_timeout_sec"].as_i64().unwrap_or(600)
        + timings["postcheck_timeout_sec"].as_i64().unwrap_or(180);
    Duration::from_secs(seconds.max(0) as u64)
}

fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

#[derive(Clone)]
pub(crate) enum DispatchHandle {
    Update(DispatchRunner),
    Restart(RestartDispatchRunner),
}

impl DispatchHandle {
    pub(crate) async fn get_status(&self) -> Value {
        match self {
            Self::Update(runner) => runner.get_status().await,
            Self::Restart(runner) => runner.get_status().await,
        }
    }

    async fn is_terminal(&self) -> bool {
        matches!(
            self.get_status().await["status"].as_str(),
            Some("success" | "failed")
        )
    }
}

#[derive(Default)]
pub(crate) struct DispatchLedger {
    entries: RwLock<IndexMap<String, DispatchHandle>>,
}

impl DispatchLedger {
    pub(crate) async fn insert(&self, dispatch_id: String, runner: DispatchHandle) {
        self.entries.write().await.insert(dispatch_id, runner);
    }

    pub(crate) async fn get(&self, dispatch_id: &str) -> Option<DispatchHandle> {
        self.entries.read().await.get(dispatch_id).cloned()
    }

    pub(crate) async fn gc_dispatches(&self) {
        let snapshot = self
            .entries
            .read()
            .await
            .iter()
            .map(|(id, runner)| (id.clone(), runner.clone()))
            .collect::<Vec<_>>();
        let mut terminal = Vec::new();
        for (id, runner) in snapshot {
            if runner.is_terminal().await {
                terminal.push(id);
            }
        }
        let remove_count = terminal.len().saturating_sub(5);
        let mut entries = self.entries.write().await;
        for id in terminal.into_iter().take(remove_count) {
            entries.shift_remove(&id);
        }
    }
}

fn dispatch_history_path(repo_root: &Path) -> PathBuf {
    repo_root.join("data").join("fleet_dispatches.json")
}

pub(crate) fn load_dispatch_history(repo_root: &Path) -> Vec<Value> {
    let Ok(data) = std::fs::read(dispatch_history_path(repo_root)) else {
        return Vec::new();
    };
    serde_json::from_slice::<Value>(&data)
        .ok()
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
}

pub(crate) fn save_dispatch_history(repo_root: &Path, dispatch_status: &Value) {
    static HISTORY_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = HISTORY_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let _ = save_dispatch_history_inner(repo_root, dispatch_status);
}

fn save_dispatch_history_inner(repo_root: &Path, dispatch_status: &Value) -> std::io::Result<()> {
    let path = dispatch_history_path(repo_root);
    let dispatch_id = dispatch_status.get("dispatch_id");
    let mut history = load_dispatch_history(repo_root);
    history.retain(|entry| entry.get("dispatch_id") != dispatch_id);
    history.insert(0, dispatch_status.clone());
    history.truncate(MAX_DISPATCH_HISTORY);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(&history)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{header, Method, Request as HttpRequest},
        Router,
    };
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tower::ServiceExt;

    use crate::{
        routes::{lan_cowork::write_config_json, lan_cowork_registry::PeerRegistry},
        state::SharedState,
    };

    #[derive(Default)]
    struct FakeTransport {
        uptime: Mutex<HashMap<String, VecDeque<Result<u64, DispatchError>>>>,
        uptime_default: Mutex<HashMap<String, u64>>,
        post_results: Mutex<HashMap<String, Result<Value, DispatchError>>>,
        poll_results: Mutex<HashMap<String, Result<Value, DispatchError>>>,
        events: Mutex<Vec<String>>,
        post_delay: Duration,
        active: AtomicUsize,
        max_active: AtomicUsize,
        consent: Mutex<Vec<Option<String>>>,
    }

    impl FakeTransport {
        fn scripted(values: Vec<Result<u64, DispatchError>>, default: u64) -> Arc<Self> {
            let fake = Arc::new(Self::default());
            fake.uptime
                .lock()
                .unwrap()
                .insert("peer".to_owned(), values.into());
            fake.uptime_default
                .lock()
                .unwrap()
                .insert("peer".to_owned(), default);
            fake
        }
    }

    fn route_app() -> Router<LanCoworkState> {
        routes()
    }

    /// Builds a test `SharedState` plus the LAN-Cowork-owned `LanCoworkState`
    /// derived from it via `LanCoworkState::from_shared` (the single
    /// production construction seam, also used by `main.rs`). Both are
    /// returned so callers thread the *same* `LanCoworkState` instance
    /// through every route/setup call instead of re-deriving fresh,
    /// independent `Arc`s per call.
    async fn route_state(
        root: &Path,
        pin: bool,
        registry: bool,
        chief: bool,
    ) -> (SharedState, LanCoworkState) {
        let state =
            crate::state::semantic_test_state_with_root(pin, String::new(), root.to_path_buf())
                .await;
        write_config_json(
            &state.config.config_path,
            &json!({"extensions":{"builtin-lan-cowork":{"fleet":{"chief":chief}}}}),
        )
        .unwrap();
        let lc = LanCoworkState::from_shared(&state);
        if registry {
            lc.peer_registry
                .set(Arc::new(PeerRegistry::new(
                    state.db.clone(),
                    Duration::from_secs(30),
                    "local".to_owned(),
                )))
                .ok();
        }
        (state, lc)
    }

    async fn session() -> tower_sessions::Session {
        let session = tower_sessions::Session::new(
            None,
            Arc::new(tower_sessions::MemoryStore::default()),
            None,
        );
        session.insert("pin_ok", true).await.unwrap();
        session
    }

    fn route_request(
        method: Method,
        uri: &str,
        body: &str,
        session: Option<tower_sessions::Session>,
        content_type: Option<&str>,
        xrw: bool,
    ) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder().method(method).uri(uri);
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        if xrw {
            builder = builder.header("X-Requested-With", "test");
        }
        let mut request = builder.body(Body::from(body.to_owned())).unwrap();
        if let Some(session) = session {
            request.extensions_mut().insert(session);
        }
        request
    }

    async fn send_route(app: Router, request: HttpRequest<Body>) -> (StatusCode, Value) {
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[async_trait]
    impl DispatchTransport for FakeTransport {
        async fn fetch_uptime(&self, peer_id: &str) -> Result<u64, DispatchError> {
            if let Some(result) = self
                .uptime
                .lock()
                .unwrap()
                .entry(peer_id.to_owned())
                .or_default()
                .pop_front()
            {
                return result;
            }
            self.uptime_default
                .lock()
                .unwrap()
                .get(peer_id)
                .copied()
                .map_or(Ok(1), Ok)
        }

        async fn post_restart(&self, peer_id: &str) -> Result<(), DispatchError> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            if !self.post_delay.is_zero() {
                tokio::time::sleep(self.post_delay).await;
            }
            self.active.fetch_sub(1, Ordering::SeqCst);
            self.events
                .lock()
                .unwrap()
                .push(format!("restart:{peer_id}"));
            Ok(())
        }

        async fn post_update_to_peer(
            &self,
            peer_id: &str,
            _source: &str,
            _branch: &str,
            consent_token: Option<&str>,
        ) -> Result<Value, DispatchError> {
            self.events.lock().unwrap().push(format!("post:{peer_id}"));
            self.consent
                .lock()
                .unwrap()
                .push(consent_token.map(str::to_owned));
            if !self.post_delay.is_zero() {
                tokio::time::sleep(self.post_delay).await;
            }
            self.post_results
                .lock()
                .unwrap()
                .remove(peer_id)
                .unwrap_or_else(|| Ok(json!({"job_id":format!("job-{peer_id}")})))
        }

        async fn poll_peer_job(
            &self,
            peer_id: &str,
            _job_id: &str,
            _timeout: Duration,
        ) -> Result<Value, DispatchError> {
            self.events.lock().unwrap().push(format!("poll:{peer_id}"));
            self.poll_results
                .lock()
                .unwrap()
                .remove(peer_id)
                .unwrap_or_else(|| Ok(json!({"status":"success","steps":[]})))
        }
    }

    fn restart(fake: Arc<FakeTransport>) -> RestartDispatchRunner {
        RestartDispatchRunner::build(
            "self",
            "rstrt_test".to_owned(),
            vec!["peer".to_owned()],
            fake,
        )
        .unwrap()
    }

    async fn expire_restart(runner: RestartDispatchRunner) -> Value {
        let task = tokio::spawn(async move {
            runner.run().await;
            runner.get_status().await
        });
        tokio::task::yield_now().await;
        for _ in 0..21 {
            tokio::time::advance(Duration::from_secs(3)).await;
            tokio::task::yield_now().await;
        }
        task.await.unwrap()
    }

    #[tokio::test]
    async fn dispatch_authorization_is_three_stage_with_exact_bodies() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = [
            (Method::POST, "/ext/lan_cowork/fleet/update/dispatch"),
            (
                Method::GET,
                "/ext/lan_cowork/fleet/update/dispatch/status?dispatch_id=x",
            ),
            (Method::POST, "/ext/lan_cowork/fleet/restart/dispatch"),
        ];

        let (_disabled, lc_disabled) = route_state(tmp.path(), true, false, true).await;
        for (method, path) in &paths {
            let (status, body) = send_route(
                route_app().with_state(lc_disabled.clone()),
                route_request(
                    method.clone(),
                    path,
                    "{}",
                    None,
                    Some("application/json"),
                    true,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body, json!({"error":"service_unavailable"}));
        }

        let (_enabled, lc_enabled) = route_state(tmp.path(), true, true, true).await;
        for (method, path) in &paths {
            let (status, body) = send_route(
                route_app().with_state(lc_enabled.clone()),
                route_request(
                    method.clone(),
                    path,
                    "{}",
                    None,
                    Some("application/json"),
                    true,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body, json!({"error":"session required"}));
        }

        let (_non_chief, lc_non_chief) = route_state(tmp.path(), true, true, false).await;
        let operator = session().await;
        for (method, path) in &paths {
            let (status, body) = send_route(
                route_app().with_state(lc_non_chief.clone()),
                route_request(
                    method.clone(),
                    path,
                    "{}",
                    Some(operator.clone()),
                    Some("application/json"),
                    true,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body, json!({"error":"not_chief","message":"chief only"}));
        }

        let (_chief, lc_chief) = route_state(tmp.path(), true, true, true).await;
        let (status, body) = send_route(
            route_app().with_state(lc_chief.clone()),
            route_request(
                Method::POST,
                "/ext/lan_cowork/fleet/update/dispatch",
                "{}",
                Some(operator.clone()),
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "no_peers");
        let (status, body) = send_route(
            route_app().with_state(lc_chief.clone()),
            route_request(
                Method::GET,
                "/ext/lan_cowork/fleet/update/dispatch/status?dispatch_id=x",
                "",
                Some(operator.clone()),
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "dispatch_not_found");
        let (status, body) = send_route(
            route_app().with_state(lc_chief),
            route_request(
                Method::POST,
                "/ext/lan_cowork/fleet/restart/dispatch",
                "{}",
                Some(operator),
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "no_peers");
    }

    #[tokio::test]
    async fn json_object_errors_keep_all_three_codes() {
        let tmp = tempfile::tempdir().unwrap();
        let (_state, lc) = route_state(tmp.path(), false, true, true).await;
        for (content_type, body, code) in [
            (None, "{}", "invalid_content_type"),
            (Some("application/json"), "{", "invalid_json"),
            (Some("application/json"), "[]", "invalid_json_object"),
        ] {
            let (status, value) = send_route(
                route_app().with_state(lc.clone()),
                route_request(
                    Method::POST,
                    "/ext/lan_cowork/fleet/update/dispatch",
                    body,
                    None,
                    content_type,
                    true,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(value["code"], code);
            assert!(value.get("ok").is_none());
        }
        let (status, value) = send_route(
            route_app().with_state(lc),
            route_request(
                Method::POST,
                "/ext/lan_cowork/fleet/update/dispatch",
                "{}",
                None,
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value["error"], "no_peers");
    }

    #[tokio::test]
    async fn update_validation_order_strip_and_positive_dispatch_are_pinned() {
        let tmp = tempfile::tempdir().unwrap();
        let (_state, lc) = route_state(tmp.path(), false, true, true).await;
        let cases = [
            (
                r#"{"peer_ids":{"peer":true},"consent_tokens":[1],"source":1,"branch":1}"#,
                "invalid_peer_ids",
            ),
            (
                r#"{"peer_ids":["peer"],"consent_tokens":[1],"source":1,"branch":1}"#,
                "invalid_consent_tokens",
            ),
            (r#"{"peer_ids":[],"source":123}"#, "invalid_source"),
            (
                r#"{"peer_ids":[" local "],"source":"origin","branch":1}"#,
                "invalid_branch",
            ),
            (r#"{"peer_ids":[]}"#, "no_peers"),
            (r#"{"peer_ids":[" local "]}"#, "cannot_dispatch_self"),
            (r#"{"peer_ids":"peer"}"#, "invalid_peer_ids"),
            (r#"{"peer_ids":["   "]}"#, "invalid_peer_ids"),
        ];
        for (body, error) in cases {
            let (status, value) = send_route(
                route_app().with_state(lc.clone()),
                route_request(
                    Method::POST,
                    "/ext/lan_cowork/fleet/update/dispatch",
                    body,
                    None,
                    Some("application/json"),
                    true,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(value["error"], error, "{body}");
        }

        let (status, value) = send_route(
            route_app().with_state(lc),
            route_request(
                Method::POST,
                "/ext/lan_cowork/fleet/update/dispatch",
                r#"{"peer_ids":[" peer "],"source":" origin ","branch":" main "}"#,
                None,
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["peer_count"], 1);
        assert!(value["dispatch_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("disp_") && id.len() == 13));
    }

    #[tokio::test]
    async fn restart_validation_order_strip_and_positive_dispatch_are_pinned() {
        let tmp = tempfile::tempdir().unwrap();
        let (_state, lc) = route_state(tmp.path(), false, true, true).await;
        for (body, error) in [
            (r#"{"peer_ids":"peer"}"#, "invalid_peer_ids"),
            (r#"{"peer_ids":[" "]}"#, "invalid_peer_ids"),
            (r#"{"peer_ids":[]}"#, "no_peers"),
            (r#"{"peer_ids":[" local "]}"#, "cannot_dispatch_self"),
        ] {
            let (status, value) = send_route(
                route_app().with_state(lc.clone()),
                route_request(
                    Method::POST,
                    "/ext/lan_cowork/fleet/restart/dispatch",
                    body,
                    None,
                    Some("application/json"),
                    true,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(value["error"], error, "{body}");
        }
        let (status, value) = send_route(
            route_app().with_state(lc),
            route_request(
                Method::POST,
                "/ext/lan_cowork/fleet/restart/dispatch",
                r#"{"peer_ids":[" peer "]}"#,
                None,
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["peer_count"], 1);
        assert!(value["dispatch_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("rstrt_") && id.len() == 14));
    }

    #[tokio::test]
    async fn consent_null_defaults_and_non_object_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let (_state, lc) = route_state(tmp.path(), false, true, true).await;
        let (status, value) = send_route(
            route_app().with_state(lc.clone()),
            route_request(
                Method::POST,
                "/ext/lan_cowork/fleet/update/dispatch",
                r#"{"peer_ids":["peer"],"consent_tokens":[1]}"#,
                None,
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value["error"], "invalid_consent_tokens");
        let (status, value) = send_route(
            route_app().with_state(lc),
            route_request(
                Method::POST,
                "/ext/lan_cowork/fleet/update/dispatch",
                r#"{"peer_ids":["peer"],"consent_tokens":null}"#,
                None,
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["peer_count"], 1);
    }

    #[tokio::test]
    async fn second_runner_gate_and_route_message_mapping_are_distinct() {
        let fake = Arc::new(FakeTransport::default());
        assert_eq!(
            DispatchRunner::build(
                "local",
                "disp_gate".to_owned(),
                vec!["local".to_owned()],
                "origin".to_owned(),
                "main".to_owned(),
                HashMap::new(),
                fake.clone(),
                Arc::new(|| Duration::ZERO),
            )
            .err(),
            Some("cannot_dispatch_self".to_owned())
        );
        assert!(DispatchRunner::build(
            "local",
            "disp_ok".to_owned(),
            vec!["peer".to_owned()],
            "origin".to_owned(),
            "main".to_owned(),
            HashMap::new(),
            fake,
            Arc::new(|| Duration::ZERO),
        )
        .is_ok());

        let response = runner_error("cannot_dispatch_self".to_owned());
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error":"cannot_dispatch_self","message":"cannot_dispatch_self"})
        );
        let response = validation_error("cannot_dispatch_self", "chief cannot dispatch to itself");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error":"cannot_dispatch_self","message":"chief cannot dispatch to itself"})
        );

        let tmp = tempfile::tempdir().unwrap();
        let (_state, lc) = route_state(tmp.path(), false, true, true).await;
        for path in [
            "/ext/lan_cowork/fleet/update/dispatch",
            "/ext/lan_cowork/fleet/restart/dispatch",
        ] {
            let (status, value) = send_route(
                route_app().with_state(lc.clone()),
                route_request(
                    Method::POST,
                    path,
                    r#"{"peer_ids":["local"]}"#,
                    None,
                    Some("application/json"),
                    true,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(value["error"], "cannot_dispatch_self", "{path}");
            assert_eq!(
                value["message"], "chief cannot dispatch to itself",
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn status_prefers_memory_then_returns_history_verbatim_and_404s_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = route_state(tmp.path(), false, true, true).await;
        let fake = Arc::new(FakeTransport::default());
        let memory = DispatchRunner::build(
            "local",
            "disp_same".to_owned(),
            vec!["peer".to_owned()],
            "memory".to_owned(),
            "main".to_owned(),
            HashMap::new(),
            fake,
            Arc::new(|| Duration::ZERO),
        )
        .unwrap();
        lc.fleet_manager
            .dispatches
            .insert("disp_same".to_owned(), DispatchHandle::Update(memory))
            .await;
        save_dispatch_history(
            &state.config.project_root,
            &json!({"dispatch_id":"disp_same","status":"success","source":"history"}),
        );
        let (status, value) = send_route(
            route_app().with_state(lc.clone()),
            route_request(
                Method::GET,
                "/ext/lan_cowork/fleet/update/dispatch/status?dispatch_id=%20disp_same%20",
                "",
                None,
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["source"], "memory");

        let exact = json!({
            "dispatch_id":"disp_history",
            "status":"failed",
            "unknown":{"nested":[1,true,null]}
        });
        save_dispatch_history(&state.config.project_root, &exact);
        let (status, value) = send_route(
            route_app().with_state(lc.clone()),
            route_request(
                Method::GET,
                "/ext/lan_cowork/fleet/update/dispatch/status?dispatch_id=disp_history",
                "",
                None,
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value, exact);

        let (status, value) = send_route(
            route_app().with_state(lc),
            route_request(
                Method::GET,
                "/ext/lan_cowork/fleet/update/dispatch/status?dispatch_id=missing",
                "",
                None,
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(value, json!({"error":"dispatch_not_found"}));
    }

    #[tokio::test]
    async fn gc_removal_makes_status_fall_back_to_history_only() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = route_state(tmp.path(), false, true, true).await;
        let fake = Arc::new(FakeTransport::default());
        for id in 0..7 {
            let dispatch_id = format!("disp_gc_{id}");
            let runner = DispatchRunner::build(
                "local",
                dispatch_id.clone(),
                Vec::new(),
                "origin".to_owned(),
                "main".to_owned(),
                HashMap::new(),
                fake.clone(),
                Arc::new(|| Duration::ZERO),
            )
            .unwrap();
            runner.run().await;
            save_dispatch_history(&state.config.project_root, &runner.get_status().await);
            lc.fleet_manager
                .dispatches
                .insert(dispatch_id, DispatchHandle::Update(runner))
                .await;
        }
        lc.fleet_manager.dispatches.gc_dispatches().await;
        assert!(lc.fleet_manager.dispatches.get("disp_gc_0").await.is_none());
        assert!(lc.fleet_manager.dispatches.get("disp_gc_6").await.is_some());
        let (status, value) = send_route(
            route_app().with_state(lc),
            route_request(
                Method::GET,
                "/ext/lan_cowork/fleet/update/dispatch/status?dispatch_id=disp_gc_0",
                "",
                None,
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["dispatch_id"], "disp_gc_0");
    }

    #[tokio::test]
    async fn finish_saves_only_completed_status_and_always_runs_gc() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = route_state(tmp.path(), false, true, true).await;
        let fake = Arc::new(FakeTransport::default());
        for id in 0..6 {
            let dispatch_id = format!("disp_finish_{id}");
            let runner = DispatchRunner::build(
                "local",
                dispatch_id.clone(),
                Vec::new(),
                "origin".to_owned(),
                "main".to_owned(),
                HashMap::new(),
                fake.clone(),
                Arc::new(|| Duration::ZERO),
            )
            .unwrap();
            runner.run().await;
            lc.fleet_manager
                .dispatches
                .insert(dispatch_id, DispatchHandle::Update(runner))
                .await;
        }

        finish_dispatch(
            lc.fleet_manager.clone(),
            state.config.project_root.clone(),
            None,
        )
        .await;
        assert!(load_dispatch_history(&state.config.project_root).is_empty());
        assert!(lc
            .fleet_manager
            .dispatches
            .get("disp_finish_0")
            .await
            .is_none());

        let exact = json!({"dispatch_id":"disp_finished","status":"success","raw":42});
        finish_dispatch(
            lc.fleet_manager.clone(),
            state.config.project_root.clone(),
            Some(exact.clone()),
        )
        .await;
        assert_eq!(load_dispatch_history(&state.config.project_root), [exact]);
        assert!(lc
            .fleet_manager
            .dispatches
            .get("disp_finish_5")
            .await
            .is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn restart_succeeds_only_after_down_and_lower_uptime() {
        let fake = FakeTransport::scripted(vec![Ok(100), Err(DispatchError::Timeout), Ok(5)], 5);
        let status = expire_restart(restart(fake)).await;
        assert_eq!(status["status"], "success");
        assert_eq!(status["peers"][0]["post_uptime"], 5);
    }

    #[tokio::test(start_paused = true)]
    async fn restart_never_down_with_lower_uptime_is_not_success() {
        // 90 must stay above the 60s deadline for the whole poll loop (no
        // epsilon is added on top -- see the safety note at restart_one's
        // poll loop), or the frozen fake value would eventually cross
        // `elapsed_since_t0` and the time-based OR path would legitimately
        // read a frozen-but-unrealistic "uptime < elapsed_since_t0" as a
        // restart: no genuinely non-restarted peer can hold a frozen uptime
        // while our watch clock keeps advancing. This test exists to prove
        // the OLD saw_down-gated path alone still rejects an uptime dip that
        // was never preceded by an observed down.
        let fake = FakeTransport::scripted(vec![Ok(100), Ok(90)], 90);
        let status = expire_restart(restart(fake)).await;
        assert_eq!(status["status"], "failed");
        assert_eq!(status["peers"][0]["error"], "restart_timeout");
    }

    #[tokio::test(start_paused = true)]
    async fn restart_succeeds_when_peer_restarts_before_first_poll() {
        // Regression test for the flag-day false-FAILED bug: a Rust peer can
        // execv fast enough that its restart completes before the first
        // 3-second poll even happens, so `saw_down` never becomes true and
        // uptime only ever looks low, never "dropping". Pre-fix this loops
        // to `restart_timeout` for a restart that actually succeeded.
        let fake = FakeTransport::scripted(vec![Ok(50), Ok(2)], 2);
        let status = expire_restart(restart(fake)).await;
        assert_eq!(status["status"], "success");
        assert_eq!(status["peers"][0]["post_uptime"], 2);
    }

    #[tokio::test(start_paused = true)]
    async fn restart_still_fails_when_uptime_only_rises_no_restart() {
        // The critical anti-false-success guard: a peer that never actually
        // restarted reports uptime tracking real elapsed time (pre_uptime +
        // ~3s per poll), so it is always at or above `elapsed_since_t0`
        // (pre_uptime = 100 keeps it strictly above). This must time out
        // exactly like before the fix -- the new OR path must never fire
        // here.
        let pre_uptime = 100u64;
        let mut values = vec![Ok(pre_uptime)];
        for tick in 1..=20u64 {
            values.push(Ok(pre_uptime + tick * 3));
        }
        let fake = FakeTransport::scripted(values, pre_uptime + 200);
        let status = expire_restart(restart(fake)).await;
        assert_eq!(status["status"], "failed");
        assert_eq!(status["peers"][0]["error"], "restart_timeout");
    }

    #[tokio::test(start_paused = true)]
    async fn restart_fails_for_freshly_booted_peer_that_does_not_restart() {
        // Guards the elapsed-cancellation defect: for a peer that never
        // restarts, uptime = pre_uptime + elapsed_since_t0, so the time-based
        // condition `uptime < elapsed_since_t0` reduces to `pre_uptime < 0`,
        // which is never true for a u64 -- the comparison is unconditionally
        // safe. A positive epsilon E would instead reduce it to
        // `pre_uptime < E`, which fires at the very first poll, forever, for
        // every peer whose pre_uptime happened to be under E when the
        // restart was dispatched -- regardless of whether it ever actually
        // restarted. Freshly-booted peers (pre_uptime near 0) are exactly
        // the peers most likely to be stuck in a boot loop, so this is the
        // case an operator most needs correctly reported as failed.
        for pre_uptime in [0u64, 1u64] {
            let mut values = vec![Ok(pre_uptime)];
            for tick in 1..=20u64 {
                values.push(Ok(pre_uptime + tick * 3));
            }
            let fake = FakeTransport::scripted(values, pre_uptime + 200);
            let status = expire_restart(restart(fake)).await;
            assert_eq!(
                status["status"], "failed",
                "pre_uptime={pre_uptime} must not falsely succeed"
            );
            assert_eq!(status["peers"][0]["error"], "restart_timeout");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn restart_slow_path_saw_down_then_lower_uptime_still_succeeds() {
        // The pre-existing slow-restart path must be unaffected by the new
        // OR branch: saw_down is observed first, then a genuinely lower
        // uptime follows. Duplicates the intent of
        // `restart_succeeds_only_after_down_and_lower_uptime` above,
        // written explicitly here per the flag-day fix's test requirements.
        let fake = FakeTransport::scripted(vec![Ok(100), Err(DispatchError::Timeout), Ok(5)], 5);
        let status = expire_restart(restart(fake)).await;
        assert_eq!(status["status"], "success");
        assert_eq!(status["peers"][0]["post_uptime"], 5);
    }

    #[tokio::test(start_paused = true)]
    async fn restart_down_with_higher_uptime_is_not_success() {
        let fake =
            FakeTransport::scripted(vec![Ok(100), Err(DispatchError::Timeout), Ok(101)], 101);
        let status = expire_restart(restart(fake)).await;
        assert_eq!(status["status"], "failed");
    }

    #[tokio::test(start_paused = true)]
    async fn restart_parallelism_is_capped_at_ten() {
        let fake = Arc::new(FakeTransport {
            post_delay: Duration::from_secs(1),
            ..FakeTransport::default()
        });
        let peers = (0..11).map(|id| format!("peer-{id}")).collect::<Vec<_>>();
        for peer_id in &peers {
            fake.uptime.lock().unwrap().insert(
                peer_id.clone(),
                vec![Ok(100), Err(DispatchError::Timeout), Ok(1)].into(),
            );
            fake.uptime_default
                .lock()
                .unwrap()
                .insert(peer_id.clone(), 1);
        }
        let runner =
            RestartDispatchRunner::build("self", "rstrt_cap".to_owned(), peers, fake.clone())
                .unwrap();
        let task = tokio::spawn(async move { runner.run().await });
        tokio::task::yield_now().await;
        assert_eq!(fake.max_active.load(Ordering::SeqCst), 10);
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(3)).await;
            tokio::task::yield_now().await;
        }
        task.await.unwrap();
        assert_eq!(fake.max_active.load(Ordering::SeqCst), 10);
        assert_eq!(fake.events.lock().unwrap().len(), 11);
    }

    #[tokio::test(start_paused = true)]
    async fn update_dispatch_is_sequential_and_omits_missing_consent() {
        let fake = Arc::new(FakeTransport {
            post_delay: Duration::from_secs(1),
            ..FakeTransport::default()
        });
        let timeout_reads = Arc::new(AtomicUsize::new(0));
        let timeout_reads_for_runner = timeout_reads.clone();
        let runner = DispatchRunner::build(
            "self",
            "disp_test".to_owned(),
            vec!["one".to_owned(), "two".to_owned()],
            "origin".to_owned(),
            "main".to_owned(),
            HashMap::from([("two".to_owned(), "consent".to_owned())]),
            fake.clone(),
            Arc::new(move || {
                timeout_reads_for_runner.fetch_add(1, Ordering::SeqCst);
                Duration::from_secs(780)
            }),
        )
        .unwrap();
        let task = tokio::spawn(async move { runner.run().await });
        tokio::task::yield_now().await;
        assert_eq!(*fake.events.lock().unwrap(), ["post:one"]);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            *fake.events.lock().unwrap(),
            ["post:one", "poll:one", "post:two"]
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        task.await.unwrap();
        assert_eq!(
            *fake.consent.lock().unwrap(),
            [None, Some("consent".to_owned())]
        );
        assert_eq!(timeout_reads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn update_continues_after_peer_error_and_preserves_remote_error() {
        let fake = Arc::new(FakeTransport::default());
        fake.post_results.lock().unwrap().insert(
            "one".to_owned(),
            Ok(json!({"error":"remote_update_disabled"})),
        );
        fake.post_results
            .lock()
            .unwrap()
            .insert("two".to_owned(), Ok(json!({"error":""})));
        let runner = DispatchRunner::build(
            "self",
            "disp_test".to_owned(),
            vec!["one".to_owned(), "two".to_owned()],
            "origin".to_owned(),
            "main".to_owned(),
            HashMap::new(),
            fake.clone(),
            Arc::new(|| Duration::from_secs(780)),
        )
        .unwrap();
        runner.run().await;
        let status = runner.get_status().await;
        assert_eq!(status["status"], "failed");
        assert_eq!(status["peers"][0]["error"], "remote_update_disabled");
        assert_eq!(status["peers"][1]["error"], "no_job_id");
        assert!(fake.events.lock().unwrap().contains(&"post:two".to_owned()));
    }

    #[tokio::test]
    async fn update_missing_peer_stays_asymmetric_and_local_errors_are_closed() {
        let fake = Arc::new(FakeTransport::default());
        fake.post_results
            .lock()
            .unwrap()
            .insert("one".to_owned(), Err(DispatchError::PeerNotFound));
        fake.post_results.lock().unwrap().insert(
            "two".to_owned(),
            Err(DispatchError::Code("request_failed".to_owned())),
        );
        let runner = DispatchRunner::build(
            "self",
            "disp_errors".to_owned(),
            vec!["one".to_owned(), "two".to_owned()],
            "origin".to_owned(),
            "main".to_owned(),
            HashMap::new(),
            fake,
            Arc::new(|| Duration::from_secs(780)),
        )
        .unwrap();
        runner.run().await;
        let status = runner.get_status().await;
        assert_eq!(status["peers"][0]["error"], "peer one not found");
        assert_eq!(status["peers"][1]["error"], "request_failed");
    }

    #[tokio::test]
    async fn restart_does_not_signal_when_pre_uptime_fetch_fails() {
        let fake = FakeTransport::scripted(
            vec![Err(DispatchError::Code("request_failed".to_owned()))],
            1,
        );
        let runner = restart(fake.clone());
        runner.run().await;
        let status = runner.get_status().await;
        assert_eq!(status["peers"][0]["error"], "pre_uptime_unavailable");
        assert!(fake.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn both_runners_reject_self_and_status_shapes_differ() {
        let fake = Arc::new(FakeTransport::default());
        assert_eq!(
            RestartDispatchRunner::build(
                "self",
                "r".to_owned(),
                vec!["self".to_owned()],
                fake.clone(),
            )
            .err(),
            Some("cannot_dispatch_self".to_owned())
        );
        assert_eq!(
            DispatchRunner::build(
                "self",
                "d".to_owned(),
                vec!["self".to_owned()],
                "origin".to_owned(),
                "main".to_owned(),
                HashMap::new(),
                fake.clone(),
                Arc::new(|| Duration::ZERO),
            )
            .err(),
            Some("cannot_dispatch_self".to_owned())
        );
        let restart = restart(fake.clone()).get_status().await;
        let update = DispatchRunner::build(
            "self",
            "d".to_owned(),
            vec!["peer".to_owned()],
            "origin".to_owned(),
            "main".to_owned(),
            HashMap::new(),
            fake,
            Arc::new(|| Duration::ZERO),
        )
        .unwrap()
        .get_status()
        .await;
        assert_eq!(restart["kind"], "restart");
        assert!(restart["peers"][0].get("post_uptime").is_none());
        assert!(update.get("kind").is_none());
        assert_eq!(update["source"], "origin");
    }

    #[test]
    fn uptime_parity_and_signed_bodies_are_exact() {
        assert_eq!(parse_uptime("{}"), Ok(0));
        assert_eq!(parse_uptime(r#"{"process_uptime_sec":null}"#), Ok(0));
        assert_eq!(parse_uptime(r#"{"process_uptime_sec":0}"#), Ok(0));
        assert_eq!(
            update_body("origin", "main"),
            br#"{"source":"origin","branch":"main"}"#
        );
        assert_eq!(b"{}", br#"{}"#);
    }

    #[test]
    fn history_is_newest_first_deduplicated_capped_and_corruption_safe() {
        let root = tempfile::tempdir().unwrap();
        for id in 0..12 {
            save_dispatch_history(root.path(), &json!({"dispatch_id":id,"status":"success"}));
        }
        save_dispatch_history(root.path(), &json!({"dispatch_id":5,"status":"failed"}));
        let history = load_dispatch_history(root.path());
        assert_eq!(history.len(), 10);
        assert_eq!(history[0], json!({"dispatch_id":5,"status":"failed"}));
        assert_eq!(
            history
                .iter()
                .filter(|entry| entry["dispatch_id"] == 5)
                .count(),
            1
        );
        std::fs::write(dispatch_history_path(root.path()), b"not json").unwrap();
        assert!(load_dispatch_history(root.path()).is_empty());
    }

    #[tokio::test]
    async fn ledger_gc_keeps_newest_five_terminal_and_all_nonterminal() {
        let ledger = DispatchLedger::default();
        let fake = Arc::new(FakeTransport::default());
        for id in 0..7 {
            let runner = DispatchRunner::build(
                "self",
                format!("d{id}"),
                Vec::new(),
                "origin".to_owned(),
                "main".to_owned(),
                HashMap::new(),
                fake.clone(),
                Arc::new(|| Duration::ZERO),
            )
            .unwrap();
            runner.run().await;
            ledger
                .insert(format!("d{id}"), DispatchHandle::Update(runner))
                .await;
        }
        let pending = restart(fake);
        ledger
            .insert("pending".to_owned(), DispatchHandle::Restart(pending))
            .await;
        ledger.gc_dispatches().await;
        assert!(ledger.get("d0").await.is_none());
        assert!(ledger.get("d1").await.is_none());
        for id in 2..7 {
            assert!(ledger.get(&format!("d{id}")).await.is_some());
        }
        assert!(ledger.get("pending").await.is_some());
    }
}
