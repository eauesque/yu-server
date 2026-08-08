//! Chief-side LAN Cowork fleet peer-management routes.

use std::{sync::Arc, time::Duration};

use axum::{
    body::Bytes,
    extract::{Extension, RawQuery, State},
    http::{header::CONTENT_TYPE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Map, Value};

use crate::routes::{
    lan_cowork::api_err,
    lan_cowork_client::{build_peer_client, read_peer_response_capped},
    lan_cowork_discovery::load_identity_seed,
    lan_cowork_fleet_manager::chief_enabled,
    lan_cowork_host::LanCoworkState,
    lan_cowork_registry::{PeerInfo, PeerRegistry},
    lan_cowork_transport::build_peer_headers_at,
};

/// Routes owned by this module, mounted on `LanCoworkState`. `main.rs` applies
/// `.with_state(lc_state)` to this sub-router before merging it into the
/// core `SharedState` builder chain (see the S3 decoupling plan's §3 proof).
pub fn routes() -> Router<LanCoworkState> {
    Router::new()
        .route("/ext/lan_cowork/fleet/peers", get(fleet_peers))
        .route(
            "/ext/lan_cowork/fleet/peer-allowlist-status",
            get(fleet_peer_allowlist_status),
        )
        .route("/ext/lan_cowork/fleet/peer-grant", post(fleet_peer_grant))
        .route("/ext/lan_cowork/fleet/peer-revoke", post(fleet_peer_revoke))
}

const GRANT_PATH: &str = "/ext/lan_cowork/fleet/allowlists/grant";
const REVOKE_PATH: &str = "/ext/lan_cowork/fleet/allowlists/revoke";
const STATUS_PATH: &str = "/ext/lan_cowork/fleet/allowlists/check";
const GRANT_TIMEOUT: Duration = Duration::from_secs(15);
const STATUS_TIMEOUT: Duration = Duration::from_secs(10);

fn response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

async fn allowlist_registry(
    state: &LanCoworkState,
    session: Option<&tower_sessions::Session>,
) -> Result<Arc<PeerRegistry>, Response> {
    let Some(registry) = state.peer_registry.get().cloned() else {
        return Err(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"service_unavailable"}),
        ));
    };
    if let Some(response) = state.require_session(session).await {
        return Err(response);
    }
    if !chief_enabled(&**state) {
        return Err(response(
            StatusCode::FORBIDDEN,
            json!({"ok":false,"error":"not_chief"}),
        ));
    }
    Ok(registry)
}

fn json_object(headers: &HeaderMap, body: &[u8]) -> Result<Map<String, Value>, Box<Response>> {
    let mime = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or("")
        .to_ascii_lowercase();
    if mime != "application/json" && !mime.ends_with("+json") {
        return Err(Box::new(api_err(
            "JSON body is required",
            "invalid_content_type",
            StatusCode::BAD_REQUEST,
        )));
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        Box::new(api_err(
            "Invalid JSON body",
            "invalid_json",
            StatusCode::BAD_REQUEST,
        ))
    })?;
    if value.is_null() {
        return Err(Box::new(api_err(
            "Invalid JSON body",
            "invalid_json",
            StatusCode::BAD_REQUEST,
        )));
    }
    value.as_object().cloned().ok_or_else(|| {
        Box::new(api_err(
            "JSON object body is required",
            "invalid_json_object",
            StatusCode::BAD_REQUEST,
        ))
    })
}

fn query_value(query: Option<&str>, key: &str) -> String {
    query
        .into_iter()
        .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
        .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
        .unwrap_or_default()
}

fn force_refresh(query: Option<&str>) -> bool {
    query_value(query, "force_refresh").to_lowercase() == "true"
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

fn categories(data: &Map<String, Value>) -> Value {
    data.get("categories")
        .filter(|value| python_truthy(value))
        .cloned()
        .unwrap_or_else(|| json!(["log_stream", "update"]))
}

async fn outbound_headers(
    state: &LanCoworkState,
    registry: &PeerRegistry,
    peer: &PeerInfo,
    method: &str,
    path: &str,
    body: &[u8],
    requested_with: HeaderValue,
) -> Result<HeaderMap, ()> {
    let seed = load_identity_seed(state.db_read()).await.ok_or(())?;
    let mut headers = build_peer_headers_at(
        unix_now(),
        &seed,
        &registry.local_peer_id(),
        peer,
        method,
        path,
        "",
        body,
    )
    .map_err(|_| ())?;
    headers.insert("X-Requested-With", requested_with);
    Ok(headers)
}

async fn proxy_allowlist(
    state: &LanCoworkState,
    registry: &PeerRegistry,
    peer: &PeerInfo,
    path: &str,
    categories: Value,
) -> Response {
    if peer.token.as_deref().is_none_or(str::is_empty) {
        return response(
            StatusCode::CONFLICT,
            json!({"ok":false,"error":"no_pairing_token","message":"peer has no pairing token"}),
        );
    }
    let body = serde_json::to_vec(&json!({"categories": categories})).unwrap_or_default();
    let result = async {
        let headers = outbound_headers(
            state,
            registry,
            peer,
            "POST",
            path,
            &body,
            HeaderValue::from_static("FleetPeerGrant"),
        )
        .await?;
        let (client, base) =
            build_peer_client(&peer.api_host, peer.api_port, Some(GRANT_TIMEOUT), None)
                .await
                .map_err(|_| ())?;
        client
            .post(format!("{base}{path}"))
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|_| ())
    }
    .await;
    let Ok(peer_response) = result else {
        return response(
            StatusCode::BAD_GATEWAY,
            json!({"ok":false,"error":"peer_unreachable","message":"request failed"}),
        );
    };
    peer_json_response(peer_response).await
}

async fn fetch_allowlist_status(
    state: &LanCoworkState,
    registry: &PeerRegistry,
    peer: &PeerInfo,
) -> Response {
    if peer.token.as_deref().is_none_or(str::is_empty) {
        return response(
            StatusCode::CONFLICT,
            json!({"ok":false,"error":"no_pairing_token"}),
        );
    }
    let result = async {
        let headers = outbound_headers(
            state,
            registry,
            peer,
            "GET",
            STATUS_PATH,
            &[],
            HeaderValue::from_static("FleetPeerStatus"),
        )
        .await?;
        let (client, base) =
            build_peer_client(&peer.api_host, peer.api_port, Some(STATUS_TIMEOUT), None)
                .await
                .map_err(|_| ())?;
        client
            .get(format!("{base}{STATUS_PATH}"))
            .headers(headers)
            .send()
            .await
            .map_err(|_| ())
    }
    .await;
    let Ok(peer_response) = result else {
        return response(
            StatusCode::OK,
            json!({"ok":false,"reachable":false,"error":"peer_unreachable","message":"request failed"}),
        );
    };
    peer_json_response(peer_response).await
}

async fn peer_json_response(peer_response: reqwest::Response) -> Response {
    let status = peer_response.status();
    let value = match read_peer_response_capped(peer_response).await {
        Ok(body) => serde_json::from_str(&body)
            .unwrap_or_else(|_| json!({"ok":false,"error":format!("http_{}", status.as_u16())})),
        Err(_) => json!({"ok":false,"error":format!("http_{}", status.as_u16())}),
    };
    response(status, value)
}

pub async fn fleet_peers(
    State(state): State<LanCoworkState>,
    RawQuery(query): RawQuery,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    if state.peer_registry.get().is_none() {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"service_unavailable","message":"LAN Cowork not enabled"}),
        );
    }
    if state
        .require_session(session.as_ref().map(|Extension(session)| session))
        .await
        .is_some()
    {
        return response(
            StatusCode::UNAUTHORIZED,
            json!({"error":"session required"}),
        );
    }
    if !chief_enabled(&*state) {
        return response(
            StatusCode::FORBIDDEN,
            json!({"error":"not_chief","message":"chief only"}),
        );
    }
    if !state.fleet_manager.is_running().await {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"fleet_manager_not_running","message":"FleetManager not initialized"}),
        );
    }
    if force_refresh(query.as_deref()) {
        state.fleet_manager.refresh(&state, true).await;
    }
    Json(state.fleet_manager.get_peers_snapshot(&state)).into_response()
}

async fn peer_action(
    state: LanCoworkState,
    session: Option<Extension<tower_sessions::Session>>,
    headers: HeaderMap,
    body: Bytes,
    path: &'static str,
) -> Response {
    let registry = match allowlist_registry(
        &state,
        session.as_ref().map(|Extension(session)| session),
    )
    .await
    {
        Ok(registry) => registry,
        Err(response) => return response,
    };
    let data = match json_object(&headers, &body) {
        Ok(data) => data,
        Err(response) => return *response,
    };
    let peer_id = data
        .get("peer_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if peer_id.is_empty() {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok":false,"error":"peer_id required"}),
        );
    }
    let Some(peer) = registry.get(peer_id) else {
        return response(
            StatusCode::NOT_FOUND,
            json!({"ok":false,"error":"peer_not_found"}),
        );
    };
    proxy_allowlist(&state, &registry, &peer, path, categories(&data)).await
}

pub async fn fleet_peer_grant(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    peer_action(state, session, headers, body, GRANT_PATH).await
}

pub async fn fleet_peer_revoke(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    peer_action(state, session, headers, body, REVOKE_PATH).await
}

pub async fn fleet_peer_allowlist_status(
    State(state): State<LanCoworkState>,
    RawQuery(query): RawQuery,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    let registry = match allowlist_registry(
        &state,
        session.as_ref().map(|Extension(session)| session),
    )
    .await
    {
        Ok(registry) => registry,
        Err(response) => return response,
    };
    let peer_id = query_value(query.as_deref(), "peer_id");
    let peer_id = peer_id.trim();
    if peer_id.is_empty() {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok":false,"error":"peer_id required"}),
        );
    }
    let Some(peer) = registry.get(peer_id) else {
        return response(
            StatusCode::NOT_FOUND,
            json!({"ok":false,"error":"peer_not_found"}),
        );
    };
    fetch_allowlist_status(&state, &registry, &peer).await
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        extract::Request,
        http::{header, Method, Request as HttpRequest},
        routing::{get, post},
        Router,
    };
    use openssl::pkey::{Id, PKey};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    use tower::ServiceExt;

    use crate::{
        auth::peer_transport::verify_request_signature,
        routes::{
            lan_cowork::write_config_json,
            lan_cowork_descriptor::{reset_client_state, test_guard, TEST_ALLOW_LOOPBACK},
        },
        state::SharedState,
    };

    const TEST_SEED: [u8; 32] = [23; 32];

    fn app() -> Router<LanCoworkState> {
        routes()
    }

    async fn state(
        root: &std::path::Path,
        pin: bool,
        registry: bool,
        chief: bool,
    ) -> (SharedState, LanCoworkState) {
        let state =
            crate::state::semantic_test_state_with_root(pin, String::new(), root.to_path_buf())
                .await;
        crate::schema::apply_standalone_schema(&state.db)
            .await
            .unwrap();
        write_config_json(
            &state.config.config_path,
            &json!({"extensions":{"builtin-lan-cowork":{"fleet":{
                "chief": chief,
                "timings":{"peers_poll_interval_sec":3600}
            }}}}),
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

    async fn insert_seed(state: &SharedState) {
        sqlx::query("INSERT INTO lan_cowork_identity (key, value) VALUES ('ed25519_seed', ?1)")
            .bind(TEST_SEED.as_slice())
            .execute(&state.db)
            .await
            .unwrap();
    }

    fn peer(peer_id: &str, port: u16, token: Option<&str>) -> PeerInfo {
        PeerInfo {
            peer_id: peer_id.to_owned(),
            name: peer_id.to_owned(),
            api_host: "127.0.0.1".to_owned(),
            api_port: port,
            token: token.map(str::to_owned),
            token_expires_at: None,
            token_issued_at: None,
            pubkey: None,
            x25519_pk: None,
            version: String::new(),
            bridges: Vec::new(),
            inference_types: Vec::new(),
            gpu: String::new(),
            generating: false,
            queue_depth: 0,
            status: "online".to_owned(),
            last_seen: 0.0,
            session_id: String::new(),
            roles: Vec::new(),
            last_reached_at: Some(unix_now()),
            last_attempted_at: None,
        }
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

    fn request(
        method: Method,
        uri: &str,
        body: &'static str,
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
        let mut request = builder.body(Body::from(body)).unwrap();
        if let Some(session) = session {
            request.extensions_mut().insert(session);
        }
        request
    }

    async fn send(app: Router, request: HttpRequest<Body>) -> (StatusCode, Value) {
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn authorization_order_and_route_specific_bodies_are_pinned() {
        let tmp = tempfile::tempdir().unwrap();
        let (_disabled, lc_disabled) = state(tmp.path(), true, false, false).await;
        let (status, body) = send(
            app().with_state(lc_disabled.clone()),
            request(
                Method::GET,
                "/ext/lan_cowork/fleet/peers",
                "",
                None,
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            json!({"error":"service_unavailable","message":"LAN Cowork not enabled"})
        );
        let (status, body) = send(
            app().with_state(lc_disabled),
            request(
                Method::POST,
                "/ext/lan_cowork/fleet/peer-grant",
                "{}",
                None,
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, json!({"error":"service_unavailable"}));

        let (_enabled, lc_enabled) = state(tmp.path(), true, true, false).await;
        let (status, body) = send(
            app().with_state(lc_enabled.clone()),
            request(
                Method::GET,
                "/ext/lan_cowork/fleet/peers",
                "",
                None,
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, json!({"error":"session required"}));
        let (status, body) = send(
            app().with_state(lc_enabled.clone()),
            request(
                Method::POST,
                "/ext/lan_cowork/fleet/peer-grant",
                "{}",
                None,
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, json!({"ok":false,"error":"session required"}));

        let operator = session().await;
        let (status, body) = send(
            app().with_state(lc_enabled.clone()),
            request(
                Method::GET,
                "/ext/lan_cowork/fleet/peers",
                "",
                Some(operator.clone()),
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error":"not_chief","message":"chief only"}));
        let (status, body) = send(
            app().with_state(lc_enabled),
            request(
                Method::POST,
                "/ext/lan_cowork/fleet/peer-grant",
                "{}",
                Some(operator),
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"ok":false,"error":"not_chief"}));
    }

    #[tokio::test]
    async fn peers_requires_running_manager_and_post_is_405() {
        let tmp = tempfile::tempdir().unwrap();
        let (_state, lc) = state(tmp.path(), true, true, true).await;
        let (status, body) = send(
            app().with_state(lc.clone()),
            request(
                Method::GET,
                "/ext/lan_cowork/fleet/peers",
                "",
                Some(session().await),
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            json!({"error":"fleet_manager_not_running","message":"FleetManager not initialized"})
        );
        let response = app()
            .with_state(lc.clone())
            .oneshot(request(
                Method::POST,
                "/ext/lan_cowork/fleet/peers",
                "",
                None,
                None,
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn all_authorization_conditions_return_peer_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let (_state, lc) = state(tmp.path(), true, true, true).await;
        lc.fleet_manager.start(lc.clone()).await;
        let (status, body) = send(
            app().with_state(lc.clone()),
            request(
                Method::GET,
                "/ext/lan_cowork/fleet/peers",
                "",
                Some(session().await),
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({"responder_peer_id":"local","roles_index":{},"peers":[]})
        );
        lc.fleet_manager.stop().await;
    }

    #[test]
    fn force_refresh_is_case_insensitive_only_for_true() {
        for query in [
            "force_refresh=true",
            "force_refresh=TRUE",
            "force_refresh=True",
            "force_refresh=tRuE",
        ] {
            assert!(force_refresh(Some(query)), "{query}");
        }
        for query in ["force_refresh=1", "force_refresh=yes", "force_refresh="] {
            assert!(!force_refresh(Some(query)), "{query}");
        }
        assert!(!force_refresh(None));
    }

    #[test]
    fn categories_use_python_or_semantics_without_type_filtering() {
        let omitted = Map::new();
        assert_eq!(categories(&omitted), json!(["log_stream", "update"]));
        for empty in [json!([]), json!(false), json!(""), json!({})] {
            let data = Map::from_iter([("categories".to_owned(), empty)]);
            assert_eq!(categories(&data), json!(["log_stream", "update"]));
        }
        let raw = json!({"raw":true});
        let data = Map::from_iter([("categories".to_owned(), raw.clone())]);
        assert_eq!(categories(&data), raw);
    }

    #[test]
    fn outbound_timeouts_match_python() {
        assert_eq!(GRANT_TIMEOUT, Duration::from_secs(15));
        assert_eq!(STATUS_TIMEOUT, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn json_body_branches_and_peer_id_validation_match_python() {
        let tmp = tempfile::tempdir().unwrap();
        let (_state, lc) = state(tmp.path(), false, true, true).await;
        let cases = [
            (None, "{}", "JSON body is required", "invalid_content_type"),
            (
                Some("application/json"),
                "{",
                "Invalid JSON body",
                "invalid_json",
            ),
            (
                Some("application/json"),
                "null",
                "Invalid JSON body",
                "invalid_json",
            ),
            (
                Some("application/json"),
                "[]",
                "JSON object body is required",
                "invalid_json_object",
            ),
        ];
        for (content_type, raw, error, code) in cases {
            let (status, body) = send(
                app().with_state(lc.clone()),
                request(
                    Method::POST,
                    "/ext/lan_cowork/fleet/peer-grant",
                    raw,
                    None,
                    content_type,
                    true,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body, json!({"ok":false,"error":error,"code":code}));
        }
        for raw in ["{}", r#"{"peer_id":"   "}"#] {
            let (status, body) = send(
                app().with_state(lc.clone()),
                request(
                    Method::POST,
                    "/ext/lan_cowork/fleet/peer-revoke",
                    raw,
                    None,
                    Some("application/json"),
                    true,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body, json!({"ok":false,"error":"peer_id required"}));
        }
    }

    #[tokio::test]
    async fn unknown_and_tokenless_peers_are_distinct_without_sending() {
        let tmp = tempfile::tempdir().unwrap();
        let (_state, lc) = state(tmp.path(), false, true, true).await;
        lc.peer_registry
            .get()
            .unwrap()
            .insert_for_test(peer("tokenless", 1, None));
        let (status, body) = send(
            app().with_state(lc.clone()),
            request(
                Method::POST,
                "/ext/lan_cowork/fleet/peer-grant",
                r#"{"peer_id":"missing"}"#,
                None,
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, json!({"ok":false,"error":"peer_not_found"}));
        let (status, body) = send(
            app().with_state(lc.clone()),
            request(
                Method::POST,
                "/ext/lan_cowork/fleet/peer-grant",
                r#"{"peer_id":"tokenless"}"#,
                None,
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body,
            json!({"ok":false,"error":"no_pairing_token","message":"peer has no pairing token"})
        );
        let (status, body) = send(
            app().with_state(lc.clone()),
            request(
                Method::GET,
                "/ext/lan_cowork/fleet/peer-allowlist-status?peer_id=tokenless",
                "",
                None,
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"ok":false,"error":"no_pairing_token"}));
    }

    #[tokio::test]
    async fn unreachable_mapping_is_asymmetric() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = state(tmp.path(), false, true, true).await;
        insert_seed(&state).await;
        let mut unreachable = peer("unreachable", 1, Some("token"));
        unreachable.api_host = "invalid/host".to_owned();
        lc.peer_registry.get().unwrap().insert_for_test(unreachable);
        for path in [
            "/ext/lan_cowork/fleet/peer-grant",
            "/ext/lan_cowork/fleet/peer-revoke",
        ] {
            let (status, body) = send(
                app().with_state(lc.clone()),
                request(
                    Method::POST,
                    path,
                    r#"{"peer_id":"unreachable"}"#,
                    None,
                    Some("application/json"),
                    true,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            assert_eq!(body["error"], "peer_unreachable");
        }
        let (status, body) = send(
            app().with_state(lc.clone()),
            request(
                Method::GET,
                "/ext/lan_cowork/fleet/peer-allowlist-status?peer_id=unreachable",
                "",
                None,
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["reachable"], false);
        assert_eq!(body["error"], "peer_unreachable");
    }

    #[tokio::test]
    async fn outbound_header_builder_pins_nonce_route_header_and_absolute_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = state(tmp.path(), false, true, true).await;
        insert_seed(&state).await;
        let registry = lc.peer_registry.get().unwrap();
        let peer = peer("target", 1, Some("token"));
        for (method, path, body, requested_with) in [
            (
                "POST",
                GRANT_PATH,
                br#"{"categories":["update"]}"#.as_slice(),
                "FleetPeerGrant",
            ),
            (
                "POST",
                REVOKE_PATH,
                br#"{"categories":["update"]}"#.as_slice(),
                "FleetPeerGrant",
            ),
            ("GET", STATUS_PATH, b"".as_slice(), "FleetPeerStatus"),
        ] {
            let headers = outbound_headers(
                &lc,
                registry,
                &peer,
                method,
                path,
                body,
                HeaderValue::from_str(requested_with).unwrap(),
            )
            .await
            .unwrap();
            let observed = Observed {
                method: Method::from_bytes(method.as_bytes()).unwrap(),
                path: path.to_owned(),
                headers,
                body: body.to_vec(),
            };
            assert_signed(&observed, path, requested_with);
        }
    }

    #[derive(Debug)]
    struct Observed {
        method: Method,
        path: String,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    #[derive(Default)]
    struct MockState {
        count: AtomicUsize,
        observed: Mutex<Vec<Observed>>,
    }

    async fn mock_peer(State(state): State<Arc<MockState>>, request: Request) -> Response {
        let (parts, body) = request.into_parts();
        let body = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        state.count.fetch_add(1, Ordering::SeqCst);
        state.observed.lock().unwrap().push(Observed {
            method: parts.method,
            path: parts.uri.path().to_owned(),
            headers: parts.headers,
            body,
        });
        response(StatusCode::OK, json!({"ok":true}))
    }

    async fn mock_server() -> (u16, Arc<MockState>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(MockState::default());
        let app = Router::new()
            .route(GRANT_PATH, post(mock_peer))
            .route(REVOKE_PATH, post(mock_peer))
            .route(STATUS_PATH, get(mock_peer))
            .route("/ext/lan_cowork/fleet/info", get(mock_peer))
            .with_state(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (port, state, server)
    }

    struct LoopbackGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl LoopbackGuard {
        fn new() -> Self {
            let guard = test_guard();
            reset_client_state();
            TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
            Self { _guard: guard }
        }
    }

    impl Drop for LoopbackGuard {
        fn drop(&mut self) {
            reset_client_state();
        }
    }

    fn assert_signed(request: &Observed, expected_path: &str, requested_with: &str) {
        assert_eq!(request.path, expected_path);
        assert!(request.headers.contains_key("X-Peer-Nonce"));
        assert_eq!(request.headers["X-Requested-With"], requested_with);
        assert!(request.headers.contains_key(header::AUTHORIZATION));
        let key = PKey::private_key_from_raw_bytes(&TEST_SEED, Id::ED25519).unwrap();
        assert!(verify_request_signature(
            &key.raw_public_key().unwrap(),
            request.method.as_str(),
            expected_path,
            "",
            &request.body,
            request.headers["X-Peer-Ts"].to_str().unwrap(),
            request.headers["X-Peer-Sig"].to_str().unwrap(),
        ));
    }

    #[tokio::test]
    async fn outbound_success_pins_defaults_values_nonce_headers_paths_and_timeouts() {
        let _loopback = LoopbackGuard::new();
        let (port, mock, server) = mock_server().await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = state(tmp.path(), false, true, true).await;
        insert_seed(&state).await;
        lc.peer_registry
            .get()
            .unwrap()
            .insert_for_test(peer("target", port, Some("token")));
        lc.peer_registry
            .get()
            .unwrap()
            .insert_for_test(peer("tokenless", port, None));
        let (status, _) = send(
            app().with_state(lc.clone()),
            request(
                Method::POST,
                "/ext/lan_cowork/fleet/peer-grant",
                r#"{"peer_id":"tokenless"}"#,
                None,
                Some("application/json"),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(mock.count.load(Ordering::SeqCst), 0);
        let calls = [
            (
                "/ext/lan_cowork/fleet/peer-grant",
                r#"{"peer_id":"target"}"#,
            ),
            (
                "/ext/lan_cowork/fleet/peer-revoke",
                r#"{"peer_id":"target","categories":[]}"#,
            ),
            (
                "/ext/lan_cowork/fleet/peer-grant",
                r#"{"peer_id":"target","categories":{"raw":true}}"#,
            ),
        ];
        for (path, body) in calls {
            let (status, body) = send(
                app().with_state(lc.clone()),
                request(
                    Method::POST,
                    path,
                    body,
                    None,
                    Some("application/json"),
                    true,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["ok"], true);
        }
        let (status, body) = send(
            app().with_state(lc.clone()),
            request(
                Method::GET,
                "/ext/lan_cowork/fleet/peer-allowlist-status?peer_id=target",
                "",
                None,
                None,
                false,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert_eq!(GRANT_TIMEOUT, Duration::from_secs(15));
        assert_eq!(STATUS_TIMEOUT, Duration::from_secs(10));

        let observed = mock.observed.lock().unwrap();
        assert_eq!(observed.len(), 4);
        assert_signed(&observed[0], GRANT_PATH, "FleetPeerGrant");
        assert_signed(&observed[1], REVOKE_PATH, "FleetPeerGrant");
        assert_signed(&observed[2], GRANT_PATH, "FleetPeerGrant");
        assert_signed(&observed[3], STATUS_PATH, "FleetPeerStatus");
        assert_eq!(
            serde_json::from_slice::<Value>(&observed[0].body).unwrap()["categories"],
            json!(["log_stream", "update"])
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&observed[1].body).unwrap()["categories"],
            json!(["log_stream", "update"])
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&observed[2].body).unwrap()["categories"],
            json!({"raw":true})
        );
        drop(observed);
        server.abort();
    }

    #[tokio::test]
    async fn peers_success_and_force_refresh_call_controls() {
        let _loopback = LoopbackGuard::new();
        let (port, mock, server) = mock_server().await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = state(tmp.path(), true, true, true).await;
        insert_seed(&state).await;
        lc.peer_registry
            .get()
            .unwrap()
            .insert_for_test(peer("target", port, Some("token")));
        lc.fleet_manager.start(lc.clone()).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while mock.count.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let operator = session().await;
        for value in ["true", "TRUE", "True"] {
            let before = mock.count.load(Ordering::SeqCst);
            let uri = format!("/ext/lan_cowork/fleet/peers?force_refresh={value}");
            let (status, body) = send(
                app().with_state(lc.clone()),
                request(Method::GET, &uri, "", Some(operator.clone()), None, false),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.get("ok").is_none());
            let object = body.as_object().unwrap();
            assert_eq!(object.len(), 3);
            for key in ["responder_peer_id", "roles_index", "peers"] {
                assert!(object.contains_key(key));
            }
            assert_eq!(mock.count.load(Ordering::SeqCst), before + 1);
        }
        for value in ["1", "yes", ""] {
            let before = mock.count.load(Ordering::SeqCst);
            let uri = format!("/ext/lan_cowork/fleet/peers?force_refresh={value}");
            let (status, _) = send(
                app().with_state(lc.clone()),
                request(Method::GET, &uri, "", Some(operator.clone()), None, false),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(mock.count.load(Ordering::SeqCst), before);
        }
        lc.fleet_manager.stop().await;
        server.abort();
    }
}
