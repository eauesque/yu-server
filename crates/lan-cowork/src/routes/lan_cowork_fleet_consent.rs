//! Fleet consent peer routes and process-local one-time consent state.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde_json::{json, Value};

use crate::{
    auth::peer_transport::require_peer_auth,
    routes::lan_cowork_host::{LanCoworkHost, LanCoworkState},
};

#[cfg(test)]
use crate::auth::peer_transport::{require_peer_auth_with_nonce_store, PeerNonceStore};

use super::{
    lan_cowork::{ext_config, load_config_json, session_guard, write_config_json},
    lan_cowork_discovery::load_identity_seed,
    lan_cowork_fleet_config::get_fleet_timings,
    lan_cowork_transport::PeerTransport,
};

#[derive(Clone)]
struct Consent {
    chief_peer_id: String,
    expires_at: f64,
    decision: Option<String>,
    permanent: bool,
    decided_at: Option<f64>,
}

#[derive(Default)]
struct ConsentState {
    store: HashMap<String, Consent>,
    deny_cooldown: HashMap<String, f64>,
}

fn consent_state() -> &'static Mutex<ConsentState> {
    static STATE: OnceLock<Mutex<ConsentState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(ConsentState::default()))
}

#[cfg(test)]
pub(crate) fn consent_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs_f64())
        .unwrap_or(0.0)
}
fn response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}
fn fleet(state: &dyn LanCoworkHost) -> Value {
    ext_config(&load_config_json(state.config_path()))
        .get("fleet")
        .cloned()
        .unwrap_or_else(|| json!({}))
}

pub(crate) fn consume_consent_token(request_id: &str, chief_peer_id: &str) -> bool {
    let mut state = consent_state().lock().unwrap_or_else(|e| e.into_inner());
    let accepted = state.store.get(request_id).is_some_and(|entry| {
        entry.decision.as_deref() == Some("approved")
            && entry.chief_peer_id == chief_peer_id
            && now() <= entry.expires_at
    });
    if accepted {
        state.store.remove(request_id);
    }
    accepted
}

#[cfg(test)]
pub(crate) fn insert_test_consent(request_id: &str, chief_peer_id: &str) {
    consent_state()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .store
        .insert(
            request_id.to_owned(),
            Consent {
                chief_peer_id: chief_peer_id.to_owned(),
                expires_at: now() + 60.0,
                decision: Some("approved".to_owned()),
                permanent: false,
                decided_at: Some(now()),
            },
        );
}

pub(crate) fn run_consent_janitor_once() {
    let current = now();
    let mut state = consent_state().lock().unwrap_or_else(|e| e.into_inner());
    state
        .store
        .retain(|_, entry| match entry.decision.as_deref() {
            None => current <= entry.expires_at,
            Some(_) => entry.decided_at.is_some_and(|at| current <= at + 60.0),
        });
    state
        .deny_cooldown
        .retain(|_, expires_at| current <= *expires_at);
}

async fn peer_only(
    state: &dyn LanCoworkHost,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, Response> {
    #[cfg(test)]
    if let Some(nonces) = test_peer_nonce_store() {
        return require_peer_auth_with_nonce_store(
            state,
            method.as_str(),
            uri.path(),
            uri.query().unwrap_or(""),
            headers,
            body,
            &nonces,
        )
        .await;
    }
    require_peer_auth(
        state,
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or(""),
        headers,
        body,
    )
    .await
}

#[cfg(test)]
#[derive(Default)]
struct TestPeerNonceState {
    store: Option<std::sync::Arc<PeerNonceStore>>,
    users: usize,
}

#[cfg(test)]
fn test_peer_nonce_state() -> &'static Mutex<TestPeerNonceState> {
    static STATE: OnceLock<Mutex<TestPeerNonceState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(TestPeerNonceState::default()))
}

#[cfg(test)]
fn test_peer_nonce_store() -> Option<std::sync::Arc<PeerNonceStore>> {
    test_peer_nonce_state()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .store
        .clone()
}

#[cfg(test)]
struct TestPeerNonceOverride;

#[cfg(test)]
impl Drop for TestPeerNonceOverride {
    fn drop(&mut self) {
        let mut state = test_peer_nonce_state()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.users -= 1;
        if state.users == 0 {
            state.store = None;
        }
    }
}

#[cfg(test)]
fn enable_test_peer_auth() -> TestPeerNonceOverride {
    let mut state = test_peer_nonce_state()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if state.store.is_none() {
        state.store = Some(std::sync::Arc::new(PeerNonceStore::with_grace(0)));
    }
    state.users += 1;
    TestPeerNonceOverride
}

async fn session_only(
    state: &dyn LanCoworkHost,
    session: Option<&tower_sessions::Session>,
) -> Result<(), Response> {
    session_guard(state, session).await.map_or(Ok(()), Err)
}
async fn session_and_chief(
    state: &dyn LanCoworkHost,
    session: Option<&tower_sessions::Session>,
) -> Result<(), Response> {
    session_only(state, session).await?;
    fleet(state)
        .get("chief")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        .then_some(())
        .ok_or_else(|| response(StatusCode::FORBIDDEN, json!({"error":"not_chief"})))
}

// Axum responses stay unboxed to preserve the existing handler error contract.
#[allow(clippy::result_large_err)]
fn json_body(headers: &HeaderMap, body: &[u8]) -> Result<Value, Response> {
    if headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v.split(';').next().unwrap_or("").trim() != "application/json")
    {
        return Err(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"JSON body is required"}),
        ));
    }
    serde_json::from_slice::<Value>(body)
        .ok()
        .filter(Value::is_object)
        .ok_or_else(|| {
            response(
                StatusCode::BAD_REQUEST,
                json!({"error":"invalid JSON body"}),
            )
        })
}

async fn request(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let requester = match peer_only(&*state, &method, &uri, &headers, &body).await {
        Ok(peer) => peer,
        Err(response) => return response,
    };
    let data = match json_body(&headers, &body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let request_id = data
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if request_id.is_empty() {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"error":"request_id required"}),
        );
    }
    let timeout = get_fleet_timings(&load_config_json(state.config_path()))["consent_timeout_sec"]
        .as_f64()
        .unwrap_or(300.0);
    let current = now();
    let mut consent = consent_state().lock().unwrap_or_else(|e| e.into_inner());
    if current
        < consent
            .deny_cooldown
            .get(&requester)
            .copied()
            .unwrap_or(0.0)
    {
        return response(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error":"deny_cooldown","retry_after_sec":(consent.deny_cooldown[&requester]-current) as i64}),
        );
    }
    if let Some(entry) = consent
        .store
        .values()
        .find(|entry| entry.decision.is_none() && current < entry.expires_at)
    {
        return response(
            StatusCode::CONFLICT,
            json!({"error":"consent_pending","remaining_sec":(entry.expires_at-current) as i64}),
        );
    }
    consent.store.insert(
        request_id.to_owned(),
        Consent {
            chief_peer_id: requester,
            expires_at: current + timeout,
            decision: None,
            permanent: false,
            decided_at: None,
        },
    );
    response(StatusCode::OK, json!({"status":"accepted"}))
}

async fn respond(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = session_only(&*state, session.as_ref().map(|Extension(v)| v)).await {
        return response;
    }
    let data = match json_body(&headers, &body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let request_id = data
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let decision = data.get("decision").and_then(Value::as_str).unwrap_or("");
    let permanent = data.get("permanent").and_then(Value::as_bool);
    if request_id.is_empty() || !matches!(decision, "approved" | "denied") {
        return response(StatusCode::BAD_REQUEST, json!({"error":"invalid request"}));
    }
    let Some(permanent) = permanent else {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"error":"permanent must be a boolean"}),
        );
    };
    let needs_persist = {
        let current = now();
        let mut consent = consent_state().lock().unwrap_or_else(|e| e.into_inner());
        let Some(expires_at) = consent.store.get(request_id).map(|entry| entry.expires_at) else {
            return response(StatusCode::NOT_FOUND, json!({"error":"not_found"}));
        };
        if current > expires_at {
            consent.store.remove(request_id);
            return response(StatusCode::GONE, json!({"error":"expired"}));
        }
        let denied_peer = {
            let entry = consent.store.get_mut(request_id).expect("checked above");
            entry.decision = Some(decision.to_owned());
            entry.permanent = permanent;
            entry.decided_at = Some(current);
            (decision == "denied").then(|| entry.chief_peer_id.clone())
        };
        if let Some(peer) = denied_peer {
            let timeout = get_fleet_timings(&load_config_json(state.config_path()))
                ["consent_timeout_sec"]
                .as_f64()
                .unwrap_or(300.0);
            consent.deny_cooldown.insert(peer, current + timeout);
        }
        decision == "approved" && permanent
    };
    if needs_persist {
        let _guard = state.settings_lock.lock().await;
        let mut config = load_config_json(state.config_path());
        if let Some(root) = config.as_object_mut() {
            let extensions = root.entry("extensions").or_insert_with(|| json!({}));
            if let Some(extensions) = extensions.as_object_mut() {
                let ext = extensions
                    .entry("builtin-lan-cowork")
                    .or_insert_with(|| json!({}));
                if let Some(ext) = ext.as_object_mut() {
                    ext.entry("fleet")
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                        .map(|fleet| fleet.insert("allow_remote_update".into(), json!(true)));
                }
            }
        }
        if write_config_json(state.config_path(), &config).is_err() {
            tracing::warn!("fleet consent permanent setting write failed");
        }
    }
    response(StatusCode::OK, json!({"status":"ok"}))
}

async fn status(
    State(state): State<LanCoworkState>,
    Path(request_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = peer_only(&*state, &method, &uri, &headers, &body).await {
        return response;
    }
    let current = now();
    let mut consent = consent_state().lock().unwrap_or_else(|e| e.into_inner());
    if consent
        .store
        .get(&request_id)
        .is_some_and(|entry| entry.decision.is_none() && current > entry.expires_at)
    {
        consent.store.remove(&request_id);
        return response(
            StatusCode::OK,
            json!({"status":"expired","permanent":false,"remaining_sec":0}),
        );
    }
    match consent.store.get(&request_id) {
        None => response(
            StatusCode::OK,
            json!({"status":"not_found","permanent":false,"remaining_sec":0}),
        ),
        Some(entry) => {
            let decision = entry.decision.as_deref().unwrap_or("pending");
            response(
                StatusCode::OK,
                json!({"status":decision,"permanent":entry.permanent,"remaining_sec":if decision == "pending" { (entry.expires_at-current).max(0.0) as i64 } else { 0 }}),
            )
        }
    }
}

async fn pending(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    if let Err(response) = session_only(&*state, session.as_ref().map(|Extension(v)| v)).await {
        return response;
    }
    let current = now();
    let consent = consent_state().lock().unwrap_or_else(|e| e.into_inner());
    let pending = consent
        .store
        .iter()
        .find(|(_, entry)| entry.decision.is_none() && current < entry.expires_at)
        .map(|(id, entry)| {
            json!({"request_id":id,"chief_peer_id":entry.chief_peer_id,"remaining_sec":(entry.expires_at-current).max(0.0) as i64})
        });
    response(StatusCode::OK, json!({"pending":pending}))
}

async fn relay(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    _method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    status_only: bool,
) -> Response {
    if let Err(response) =
        session_and_chief(&*state, session.as_ref().map(|Extension(value)| value)).await
    {
        return response;
    }
    let (peer_id, request_id) = if status_only {
        let query = uri.query().unwrap_or("");
        let value = |key| {
            query
                .split('&')
                .find_map(|part| {
                    part.split_once('=')
                        .filter(|(name, _)| *name == key)
                        .map(|(_, value)| value)
                })
                .unwrap_or("")
        };
        (value("peer_id").to_owned(), value("request_id").to_owned())
    } else {
        let data = match json_body(&headers, &body) {
            Ok(data) => data,
            Err(response) => return response,
        };
        (
            data.get("peer_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_owned(),
            data.get("request_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_owned(),
        )
    };
    if peer_id.is_empty() || request_id.is_empty() {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"error":"peer_id and request_id required"}),
        );
    }
    let (Some(registry), Some(seed)) = (
        state.peer_registry.get().cloned(),
        load_identity_seed(state.db_read()).await,
    ) else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"service_unavailable"}),
        );
    };
    let Some(peer) = registry.get(&peer_id) else {
        return if status_only {
            response(
                StatusCode::OK,
                json!({"status":"not_found","permanent":false,"remaining_sec":0}),
            )
        } else {
            response(StatusCode::NOT_FOUND, json!({"error":"peer_not_found"}))
        };
    };
    let path = if status_only {
        format!("/ext/lan_cowork/fleet/consent/status/{request_id}")
    } else {
        "/ext/lan_cowork/fleet/consent/request".to_owned()
    };
    let transport =
        PeerTransport::new(registry.local_peer_id(), seed, registry, state.host.clone());
    let payload = (!status_only).then(|| json!({"request_id":request_id}));
    let (ok, payload) = transport
        .send(
            &peer,
            &path,
            payload.as_ref(),
            if status_only { "GET" } else { "POST" },
        )
        .await;
    response(relay_response_status(ok, &payload), payload)
}

fn relay_response_status(ok: bool, payload: &Value) -> StatusCode {
    payload
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|value| StatusCode::from_u16(value as u16).ok())
        .unwrap_or(if ok {
            StatusCode::OK
        } else {
            StatusCode::BAD_GATEWAY
        })
}

pub fn start_consent_janitor() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            run_consent_janitor_once();
        }
    });
}

async fn relay_request(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    relay(State(state), session, method, uri, headers, body, false).await
}
async fn relay_status(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    relay(State(state), session, method, uri, headers, body, true).await
}

pub fn routes() -> Router<LanCoworkState> {
    Router::new()
        .route("/ext/lan_cowork/fleet/consent/request", post(request))
        .route("/ext/lan_cowork/fleet/consent/respond", post(respond))
        .route(
            "/ext/lan_cowork/fleet/consent/status/{request_id}",
            get(status),
        )
        .route("/ext/lan_cowork/fleet/consent/pending", get(pending))
        .route(
            "/ext/lan_cowork/fleet/consent/relay/request",
            post(relay_request),
        )
        .route(
            "/ext/lan_cowork/fleet/consent/relay/status",
            get(relay_status),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SharedState;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    const TEST_SEED: [u8; 32] = [11; 32];

    async fn signed_peer_state() -> (SharedState, String) {
        use crate::schema::apply_standalone_schema;
        use sqlx::query;
        let state = crate::state::semantic_test_state_with(true, String::new()).await;
        apply_standalone_schema(&state.db).await.unwrap();
        let pubkey =
            openssl::pkey::PKey::private_key_from_raw_bytes(&TEST_SEED, openssl::pkey::Id::ED25519)
                .unwrap()
                .raw_public_key()
                .unwrap();
        let token = "fleet-test-token".to_owned();
        let now = super::now() as i64;
        query("INSERT INTO peers (peer_id,name,api_host,api_port,pubkey,created_at,updated_at) VALUES ('peer','n','10.0.0.2',5000,?1,0,0)").bind(pubkey).execute(&state.db).await.unwrap();
        query("INSERT INTO peer_tokens (peer_id,token_hash,issued_at,expires_at,revoked_at,source) VALUES ('peer',?1,?2,?3,NULL,'pairing')").bind(crate::auth::peer_transport::hash_token(&token)).bind(now).bind(now + 86_400).execute(&state.db).await.unwrap();
        (state, token)
    }

    fn signed_request_with_nonce(
        method: &str,
        uri: &str,
        body: &str,
        token: &str,
        nonce: &str,
    ) -> Request<Body> {
        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        let mut headers = crate::auth::peer_transport::sign_headers(
            &TEST_SEED,
            method,
            path,
            query,
            body.as_bytes(),
            super::now() as i64,
            nonce,
            "peer",
        );
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(body.to_owned()))
            .unwrap();
        *request.headers_mut() = headers;
        request
    }

    async fn response_json(response: Response) -> Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn consent_is_one_time_and_janitor_removes_expired_state() {
        let _test_guard = consent_test_guard();
        {
            let mut state = consent_state()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.store.clear();
            state.deny_cooldown.clear();
            state.store.insert(
                "token".into(),
                Consent {
                    chief_peer_id: "peer".into(),
                    expires_at: now() + 60.0,
                    decision: Some("approved".into()),
                    permanent: false,
                    decided_at: Some(now()),
                },
            );
        }
        assert!(consume_consent_token("token", "peer"));
        assert!(!consume_consent_token("token", "peer"));
        {
            let mut state = consent_state()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.store.insert(
                "expired".into(),
                Consent {
                    chief_peer_id: "peer".into(),
                    expires_at: now() - 1.0,
                    decision: None,
                    permanent: false,
                    decided_at: None,
                },
            );
            state.store.insert(
                "decided".into(),
                Consent {
                    chief_peer_id: "peer".into(),
                    expires_at: now() + 60.0,
                    decision: Some("denied".into()),
                    permanent: false,
                    decided_at: Some(now() - 61.0),
                },
            );
            state.deny_cooldown.insert("peer".into(), now() - 1.0);
        }
        run_consent_janitor_once();
        let state = consent_state()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(!state.store.contains_key("expired"));
        assert!(!state.store.contains_key("decided"));
        assert!(!state.deny_cooldown.contains_key("peer"));
    }

    #[tokio::test]
    async fn consent_routes_reject_unauthenticated_requests() {
        let state = crate::state::semantic_test_state_with(true, String::new()).await;
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        for (method, uri, body) in [
            (
                "POST",
                "/ext/lan_cowork/fleet/consent/request",
                r#"{"request_id":"x"}"#,
            ),
            (
                "POST",
                "/ext/lan_cowork/fleet/consent/respond",
                r#"{"request_id":"x","decision":"approved","permanent":false}"#,
            ),
            ("GET", "/ext/lan_cowork/fleet/consent/status/x", ""),
            ("GET", "/ext/lan_cowork/fleet/consent/pending", ""),
            (
                "POST",
                "/ext/lan_cowork/fleet/consent/relay/request",
                r#"{"peer_id":"x","request_id":"x"}"#,
            ),
            (
                "GET",
                "/ext/lan_cowork/fleet/consent/relay/status?peer_id=x&request_id=x",
                "",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn session_only_consent_routes_reject_peer_headers() {
        let state = crate::state::semantic_test_state_with(true, String::new()).await;
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        for (method, uri, body) in [
            (
                "POST",
                "/ext/lan_cowork/fleet/consent/respond",
                r#"{"request_id":"x","decision":"approved","permanent":false}"#,
            ),
            ("GET", "/ext/lan_cowork/fleet/consent/pending", ""),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("content-type", "application/json")
                        .header("X-Peer-Id", "peer")
                        .header("X-Peer-Ts", "0")
                        .header("X-Peer-Sig", "invalid")
                        .header("Authorization", "Bearer invalid")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn peer_auth_is_rejected_on_session_only_consent_routes() {
        let (state, token) = signed_peer_state().await;
        let _peer_auth = enable_test_peer_auth();
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        for (index, (method, uri, body)) in [
            (
                "POST",
                "/ext/lan_cowork/fleet/consent/respond",
                r#"{"request_id":"x","decision":"approved","permanent":false}"#,
            ),
            ("GET", "/ext/lan_cowork/fleet/consent/pending", ""),
            (
                "POST",
                "/ext/lan_cowork/fleet/consent/relay/request",
                r#"{"peer_id":"x","request_id":"x"}"#,
            ),
            (
                "GET",
                "/ext/lan_cowork/fleet/consent/relay/status?peer_id=x&request_id=x",
                "",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let response = app
                .clone()
                .oneshot(signed_request_with_nonce(
                    method,
                    uri,
                    body,
                    &token,
                    &format!("session-only-{index}"),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn session_auth_is_rejected_on_peer_only_consent_routes() {
        let state = crate::state::semantic_test_state_with(true, String::new()).await;
        let session = tower_sessions::Session::new(
            None,
            std::sync::Arc::new(tower_sessions::MemoryStore::default()),
            None,
        );
        session.insert("pin_ok", true).await.unwrap();
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        for (method, uri, body) in [
            (
                "POST",
                "/ext/lan_cowork/fleet/consent/request",
                r#"{"request_id":"x"}"#,
            ),
            ("GET", "/ext/lan_cowork/fleet/consent/status/x", ""),
        ] {
            let mut request = Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            request.extensions_mut().insert(session.clone());
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn pending_omits_expired_undecided_consent() {
        let _test_guard = consent_test_guard();
        let state = crate::state::semantic_test_state_with(true, String::new()).await;
        let request_id = format!("expired-pending-{}", now());
        {
            let mut consent = consent_state()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            consent.store.insert(
                request_id.clone(),
                Consent {
                    chief_peer_id: "peer".into(),
                    expires_at: now() - 1.0,
                    decision: None,
                    permanent: false,
                    decided_at: None,
                },
            );
        }
        let session = tower_sessions::Session::new(
            None,
            std::sync::Arc::new(tower_sessions::MemoryStore::default()),
            None,
        );
        session.insert("pin_ok", true).await.unwrap();
        let mut request = Request::builder()
            .uri("/ext/lan_cowork/fleet/consent/pending")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(session);
        let response = routes()
            .with_state(LanCoworkState::from_shared(&state))
            .oneshot(request)
            .await
            .unwrap();
        assert_ne!(
            response_json(response).await["pending"]["request_id"],
            request_id.as_str()
        );
        consent_state()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .store
            .remove(&request_id);
    }

    #[tokio::test]
    async fn signed_peer_auth_reaches_peer_only_consent_request() {
        let _test_guard = consent_test_guard();
        let (state, token) = signed_peer_state().await;
        let _peer_auth = enable_test_peer_auth();
        let request_id = format!("peer-auth-success-{}", now());
        let body = format!(r#"{{"request_id":"{request_id}"}}"#);
        let response = routes()
            .with_state(LanCoworkState::from_shared(&state))
            .oneshot(signed_request_with_nonce(
                "POST",
                "/ext/lan_cowork/fleet/consent/request",
                &body,
                &token,
                "peer-auth-success",
            ))
            .await
            .unwrap();
        let status = response.status();
        let value = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        consent_state()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .store
            .remove(&request_id);
    }

    #[tokio::test]
    async fn status_expires_and_removes_undecided_consent() {
        let _test_guard = consent_test_guard();
        let (state, token) = signed_peer_state().await;
        let _peer_auth = enable_test_peer_auth();
        let request_id = format!("expired-status-{}", now());
        {
            let mut consent = consent_state()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            consent.store.insert(
                request_id.clone(),
                Consent {
                    chief_peer_id: "peer".into(),
                    expires_at: now() - 1.0,
                    decision: None,
                    permanent: false,
                    decided_at: None,
                },
            );
        }
        let uri = format!("/ext/lan_cowork/fleet/consent/status/{request_id}");
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        let response = app
            .clone()
            .oneshot(signed_request_with_nonce(
                "GET",
                &uri,
                "",
                &token,
                "expired-status-first",
            ))
            .await
            .unwrap();
        let status = response.status();
        let value = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(value["status"], "expired");
        let response = app
            .oneshot(signed_request_with_nonce(
                "GET",
                &uri,
                "",
                &token,
                "expired-status-second",
            ))
            .await
            .unwrap();
        let status = response.status();
        let value = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(value["status"], "not_found");
    }

    #[test]
    fn relay_passes_through_peer_status() {
        for status in [409, 429, 410] {
            assert_eq!(
                relay_response_status(false, &json!({"status":status})),
                StatusCode::from_u16(status).unwrap()
            );
        }
    }
}
