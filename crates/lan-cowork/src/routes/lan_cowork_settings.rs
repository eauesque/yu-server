//! LAN Cowork operator-side settings routes.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Extension, RawQuery, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use futures_util::future::join_all;
use serde_json::{json, Value};
use tokio::sync::Semaphore;

use crate::routes::{
    lan_cowork::session_guard,
    lan_cowork_client::build_peer_client,
    lan_cowork_discovery::load_identity_seed,
    lan_cowork_host::LanCoworkState,
    lan_cowork_registry::{PeerInfo, PeerRegistry},
    lan_cowork_transport::PeerTransport,
};

const PATH: &str = "/ext/lan_cowork/api/settings/fleet/my-permissions";
const ALLOWLIST_PATH: &str = "/ext/lan_cowork/fleet/allowlists/check";
const CACHE_TTL: Duration = Duration::from_secs(10);
const OUTER_TIMEOUT: Duration = Duration::from_secs(3);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_PEERS: usize = 10;

type PermissionCache = HashMap<String, (Value, Instant)>;

fn permission_cache() -> &'static Mutex<PermissionCache> {
    static CACHE: OnceLock<Mutex<PermissionCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn permission_semaphore() -> &'static Semaphore {
    static SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();
    SEMAPHORE.get_or_init(|| Semaphore::new(MAX_CONCURRENT_PEERS))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn query_has_bust(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == "bust")
    })
}

fn python_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
    }
}

fn failed(peer: &PeerInfo, error: &'static str) -> Value {
    json!({
        "peer_id": peer.peer_id,
        "name": peer.name,
        "status": peer.status,
        "restart": null,
        "update": null,
        "log_stream": null,
        "allow_remote_update": null,
        "error": error,
    })
}

fn log_query_complete(peer_count: usize) {
    tracing::debug!(peer_count, "LAN Cowork permissions queried");
}

async fn fetch_allowlist(
    state: &LanCoworkState,
    registry: Arc<PeerRegistry>,
    peer: &PeerInfo,
) -> Result<(Value, StatusCode), ()> {
    let seed = load_identity_seed(state.db_read()).await.ok_or(())?;
    let transport =
        PeerTransport::new(registry.local_peer_id(), seed, registry, state.host.clone());
    let mut headers = transport
        .build_peer_headers(peer, "GET", ALLOWLIST_PATH, "", &[])
        .map_err(|_| ())?;
    headers.insert(
        "X-Requested-With",
        HeaderValue::from_static("FleetPeerStatus"),
    );
    let (client, base) =
        build_peer_client(&peer.api_host, peer.api_port, Some(CLIENT_TIMEOUT), None)
            .await
            .map_err(|_| ())?;
    let response = client
        .get(format!("{base}{ALLOWLIST_PATH}"))
        .headers(headers)
        .send()
        .await
        .map_err(|_| ())?;
    let status = response.status();
    let body = response
        .json::<Value>()
        .await
        .unwrap_or_else(|_| json!({"ok": false, "error": format!("http_{}", status.as_u16())}));
    Ok((body, status))
}

async fn fetch_one(
    state: LanCoworkState,
    registry: Arc<PeerRegistry>,
    peer: PeerInfo,
    bust: bool,
    now: Instant,
) -> Value {
    if !bust {
        if let Some(cached) = permission_cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&peer.peer_id)
            .filter(|(_, expires)| now < *expires)
            .map(|(value, _)| value.clone())
        {
            return cached;
        }
    }
    if peer.status != "online" {
        return failed(&peer, "peer_offline");
    }

    let _permit = permission_semaphore()
        .acquire()
        .await
        .expect("process-global semaphore is never closed");
    let (body, status) =
        match tokio::time::timeout(OUTER_TIMEOUT, fetch_allowlist(&state, registry, &peer)).await {
            Err(_) => return failed(&peer, "timeout"),
            Ok(Err(())) => return failed(&peer, "peer_unreachable"),
            Ok(Ok(result)) => result,
        };

    let error = match status {
        StatusCode::CONFLICT => Some("no_pairing_token"),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Some("auth_failed"),
        _ if !python_truthy(body.get("ok")) => Some("peer_unreachable"),
        _ => None,
    };
    if let Some(error) = error {
        return failed(&peer, error);
    }

    let result = json!({
        "peer_id": peer.peer_id,
        "name": peer.name,
        "status": peer.status,
        "restart": python_truthy(body.get("restart")),
        "update": python_truthy(body.get("update")),
        "log_stream": python_truthy(body.get("log_stream")),
        "allow_remote_update": python_truthy(body.get("allow_remote_update")),
        "error": null,
    });
    permission_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(peer.peer_id, (result.clone(), now + CACHE_TTL));
    result
}

async fn my_permissions(
    State(state): State<LanCoworkState>,
    RawQuery(query): RawQuery,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    if let Some(response) =
        session_guard(&*state, session.as_ref().map(|Extension(session)| session)).await
    {
        return response;
    }
    let Some(registry) = state.peer_registry.get().cloned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "error": "LAN Cowork not enabled"})),
        )
            .into_response();
    };

    let local_peer_id = registry.local_peer_id();
    let wall_now = unix_now();
    let peers = registry
        .list_all()
        .into_iter()
        .filter(|peer| peer.peer_id != local_peer_id)
        .filter(|peer| peer.token.as_deref().is_some_and(|token| !token.is_empty()))
        .filter(|peer| {
            peer.token_expires_at
                .is_none_or(|expires_at| expires_at > wall_now)
        })
        .collect::<Vec<_>>();
    let bust = query_has_bust(query.as_deref());
    let now = Instant::now();
    let results = join_all(
        peers
            .into_iter()
            .map(|peer| fetch_one(state.clone(), registry.clone(), peer, bust, now)),
    )
    .await;
    log_query_complete(results.len());
    Json(json!({"ok": true, "peers": results})).into_response()
}

pub fn routes() -> Router<LanCoworkState> {
    Router::new().route(PATH, get(my_permissions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{header, HeaderMap, Request},
    };
    use socket2::{Domain, Socket, Type};
    use std::{
        collections::{HashSet, VecDeque},
        net::SocketAddr,
        path::Path,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tower::ServiceExt;

    use crate::routes::lan_cowork_descriptor::{
        reset_client_state, test_guard, TEST_ALLOW_LOOPBACK,
    };
    use crate::state::SharedState;

    const TEST_SEED: [u8; 32] = [31; 32];

    #[derive(Clone)]
    struct MockReply {
        status: StatusCode,
        body: &'static str,
        content_type: &'static str,
        delay: Duration,
    }

    struct MockState {
        replies: Mutex<VecDeque<MockReply>>,
        calls: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
        release_at: AtomicUsize,
        released: AtomicBool,
        release: Semaphore,
        headers: Mutex<Vec<HeaderMap>>,
    }

    impl MockState {
        fn new(replies: Vec<MockReply>) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(replies.into()),
                calls: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                max_active: AtomicUsize::new(0),
                release_at: AtomicUsize::new(0),
                released: AtomicBool::new(false),
                release: Semaphore::new(0),
                headers: Mutex::new(Vec::new()),
            })
        }
    }

    fn reply(status: StatusCode, body: &'static str) -> MockReply {
        MockReply {
            status,
            body,
            content_type: "application/json",
            delay: Duration::ZERO,
        }
    }

    async fn mock_handler(State(state): State<Arc<MockState>>, headers: HeaderMap) -> Response {
        state.calls.fetch_add(1, Ordering::SeqCst);
        state
            .headers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(headers);
        let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
        state.max_active.fetch_max(active, Ordering::SeqCst);
        let release_at = state.release_at.load(Ordering::SeqCst);
        if release_at > 0
            && active >= release_at
            && state
                .released
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            state.release.add_permits(release_at - 1);
        } else if release_at > 0 && !state.released.load(Ordering::SeqCst) {
            state.release.acquire().await.unwrap().forget();
        }
        let response = state
            .replies
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop_front()
            .unwrap_or_else(|| reply(StatusCode::OK, r#"{"ok":true}"#));
        tokio::time::sleep(response.delay).await;
        state.active.fetch_sub(1, Ordering::SeqCst);
        (
            response.status,
            [(header::CONTENT_TYPE, response.content_type)],
            response.body,
        )
            .into_response()
    }

    async fn mock_server(
        replies: Vec<MockReply>,
    ) -> (u16, Arc<MockState>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = MockState::new(replies);
        let app = Router::new()
            .route(ALLOWLIST_PATH, get(mock_handler))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (port, state, server)
    }

    async fn test_state(
        root: &Path,
        pin_auth_enabled: bool,
        enabled: bool,
    ) -> (SharedState, LanCoworkState) {
        let state = crate::state::semantic_test_state_with_root(
            pin_auth_enabled,
            String::new(),
            root.to_path_buf(),
        )
        .await;
        crate::schema::apply_standalone_schema(&state.db)
            .await
            .unwrap();
        let lc = LanCoworkState::from_shared(&state);
        if enabled {
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

    fn peer(peer_id: &str, port: u16) -> PeerInfo {
        PeerInfo {
            peer_id: peer_id.to_owned(),
            name: peer_id.to_owned(),
            api_host: "127.0.0.1".to_owned(),
            api_port: port,
            token: Some(format!("token-{peer_id}")),
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
            last_reached_at: None,
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

    fn request(uri: &str, session: Option<tower_sessions::Session>) -> Request<Body> {
        let mut request = Request::builder().uri(uri).body(Body::empty()).unwrap();
        if let Some(session) = session {
            request.extensions_mut().insert(session);
        }
        request
    }

    async fn send(
        app: Router,
        uri: &str,
        session: Option<tower_sessions::Session>,
    ) -> (StatusCode, Value) {
        let response = app.oneshot(request(uri, session)).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn reset_test_state() {
        reset_client_state();
        permission_cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        assert_eq!(
            permission_semaphore().available_permits(),
            MAX_CONCURRENT_PEERS
        );
    }

    fn registry(lc: &LanCoworkState) -> Arc<PeerRegistry> {
        lc.peer_registry.get().unwrap().clone()
    }

    fn assert_null_permissions(value: &Value) {
        for field in ["restart", "update", "log_stream", "allow_remote_update"] {
            assert!(value[field].is_null(), "{field}: {value}");
        }
    }

    #[tokio::test]
    async fn authorization_order_and_success_match_python() {
        let _guard = test_guard();
        reset_test_state();
        let tmp = tempfile::tempdir().unwrap();
        let (_disabled, disabled_lc) = test_state(tmp.path(), true, false).await;

        let (status, body) = send(routes().with_state(disabled_lc.clone()), PATH, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, json!({"ok":false,"error":"session required"}));

        let (status, body) = send(
            routes().with_state(disabled_lc.clone()),
            PATH,
            Some(session().await),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, json!({"ok":false,"error":"LAN Cowork not enabled"}));

        let (_enabled, enabled_lc) = test_state(tmp.path(), true, true).await;
        let (status, body) = send(
            routes().with_state(enabled_lc.clone()),
            PATH,
            Some(session().await),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({"ok":true,"peers":[]}));
    }

    // `admin_api_key_without_session_is_rejected_by_handler` relocated to
    // yu-server's `lan_cowork_split_integration_tests.rs` (S4d step 4): it
    // layers `auth_middleware`, which lives in yu-server and is unreachable
    // across the crate boundary.

    #[tokio::test]
    async fn peer_filter_covers_self_tokens_and_expiry_without_order_assumption() {
        let _guard = test_guard();
        reset_test_state();
        let tmp = tempfile::tempdir().unwrap();
        let (_state, lc) = test_state(tmp.path(), false, true).await;
        let registry = registry(&lc);
        let mut self_peer = peer("local", 1);
        self_peer.status = "offline".to_owned();
        registry.insert_for_test(self_peer);
        let mut missing = peer("missing", 1);
        missing.token = None;
        registry.insert_for_test(missing);
        let mut empty = peer("empty", 1);
        empty.token = Some(String::new());
        registry.insert_for_test(empty);
        let mut expired = peer("expired", 1);
        expired.token_expires_at = Some(unix_now());
        registry.insert_for_test(expired);
        for (id, expiry) in [("unlimited", None), ("future", Some(unix_now() + 60))] {
            let mut included = peer(id, 1);
            included.status = "offline".to_owned();
            included.token_expires_at = expiry;
            registry.insert_for_test(included);
        }

        let (status, body) = send(routes().with_state(lc.clone()), PATH, None).await;
        assert_eq!(status, StatusCode::OK);
        let ids = body["peers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|peer| peer["peer_id"].as_str().unwrap())
            .collect::<HashSet<_>>();
        assert_eq!(ids, HashSet::from(["unlimited", "future"]));
    }

    #[tokio::test]
    async fn cache_hit_bust_expiry_error_and_offline_precedence_are_pinned() {
        let _guard = test_guard();
        reset_test_state();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        assert_eq!(CACHE_TTL, Duration::from_secs(10));
        let replies = vec![
            reply(StatusCode::OK, r#"{"ok":true,"restart":false}"#),
            reply(StatusCode::OK, r#"{"ok":true,"restart":true}"#),
            reply(StatusCode::OK, r#"{"ok":false}"#),
            reply(StatusCode::OK, r#"{"ok":true,"update":true}"#),
        ];
        let (port, mock, server) = mock_server(replies).await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path(), false, true).await;
        insert_seed(&state).await;
        let registry = registry(&lc);
        registry.insert_for_test(peer("cached", port));
        let app = routes().with_state(lc.clone());

        let (_, first) = send(app.clone(), PATH, None).await;
        let (_, second) = send(app.clone(), PATH, None).await;
        assert_eq!(first, second);
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);

        let (_, busted) = send(app.clone(), &format!("{PATH}?bust"), None).await;
        assert_eq!(busted["peers"][0]["restart"], true);
        assert_eq!(mock.calls.load(Ordering::SeqCst), 2);

        permission_cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut("cached")
            .unwrap()
            .1 = Instant::now() - Duration::from_millis(1);
        let (_, failed) = send(app.clone(), PATH, None).await;
        assert_eq!(failed["peers"][0]["error"], "peer_unreachable");
        let (_, recovered) = send(app.clone(), PATH, None).await;
        assert_eq!(recovered["peers"][0]["update"], true);
        assert_eq!(mock.calls.load(Ordering::SeqCst), 4);

        let mut offline = peer("cached", port);
        offline.name = "new name".to_owned();
        offline.status = "offline".to_owned();
        registry.insert_for_test(offline);
        let (_, cached_offline) = send(app, PATH, None).await;
        assert_eq!(cached_offline["peers"][0]["name"], "cached");
        assert_eq!(cached_offline["peers"][0]["status"], "online");
        assert!(cached_offline["peers"][0]["error"].is_null());
        assert_eq!(mock.calls.load(Ordering::SeqCst), 4);
        server.abort();
    }

    #[tokio::test]
    async fn offline_peer_is_not_contacted_and_keeps_raw_identity() {
        let _guard = test_guard();
        reset_test_state();
        let tmp = tempfile::tempdir().unwrap();
        let (_state, lc) = test_state(tmp.path(), false, true).await;
        let mut offline = peer("offline", 1);
        offline.name = String::new();
        offline.status = "sleeping".to_owned();
        registry(&lc).insert_for_test(offline);
        let (status, body) = send(routes().with_state(lc.clone()), PATH, None).await;
        assert_eq!(status, StatusCode::OK);
        let result = &body["peers"][0];
        assert_eq!(result["name"], "");
        assert_eq!(result["status"], "sleeping");
        assert_eq!(result["error"], "peer_offline");
        assert_null_permissions(result);
    }

    #[tokio::test]
    async fn outer_timeout_starts_after_permit_acquisition() {
        let _guard = test_guard();
        reset_test_state();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let mut delayed = reply(StatusCode::OK, r#"{"ok":true}"#);
        delayed.delay = Duration::from_secs(1);
        let (port, _, server) = mock_server(vec![delayed]).await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path(), false, true).await;
        insert_seed(&state).await;
        registry(&lc).insert_for_test(peer("permit", port));
        let permits = permission_semaphore()
            .acquire_many(MAX_CONCURRENT_PEERS as u32)
            .await
            .unwrap();
        let request = tokio::spawn(send(routes().with_state(lc.clone()), PATH, None));
        tokio::time::sleep(Duration::from_secs(4)).await;
        drop(permits);
        let (status, body) = request.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert!(body["peers"][0]["error"].is_null());
        server.abort();
    }

    #[tokio::test]
    async fn slow_response_maps_to_timeout() {
        let _guard = test_guard();
        reset_test_state();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let mut delayed = reply(StatusCode::OK, r#"{"ok":true}"#);
        delayed.delay = OUTER_TIMEOUT + Duration::from_secs(1);
        let (port, _, server) = mock_server(vec![delayed]).await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path(), false, true).await;
        insert_seed(&state).await;
        registry(&lc).insert_for_test(peer("slow", port));
        let (status, body) = send(routes().with_state(lc.clone()), PATH, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["peers"][0]["error"], "timeout");
        assert_null_permissions(&body["peers"][0]);
        server.abort();
    }

    #[tokio::test]
    async fn connection_failure_is_unreachable_not_timeout() {
        let _guard = test_guard();
        reset_test_state();
        assert_eq!(CLIENT_TIMEOUT, Duration::from_secs(10));
        assert_eq!(OUTER_TIMEOUT, Duration::from_secs(3));
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        // Reserve the port without listening so connect fails immediately with ECONNREFUSED.
        let reservation = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        reservation
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
            .unwrap();
        let port = reservation
            .local_addr()
            .unwrap()
            .as_socket()
            .unwrap()
            .port();
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path(), false, true).await;
        insert_seed(&state).await;
        registry(&lc).insert_for_test(peer("refused", port));
        let (status, body) = send(routes().with_state(lc.clone()), PATH, None).await;
        drop(reservation);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["peers"][0]["error"], "peer_unreachable");
    }

    #[tokio::test]
    async fn status_and_body_error_mapping_preserves_token() {
        let _guard = test_guard();
        reset_test_state();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let mut non_json = reply(StatusCode::UNAUTHORIZED, "not json");
        non_json.content_type = "text/plain";
        let replies = vec![
            reply(StatusCode::CONFLICT, r#"{"ok":false}"#),
            reply(StatusCode::UNAUTHORIZED, r#"{"ok":false}"#),
            reply(StatusCode::FORBIDDEN, r#"{"ok":false}"#),
            non_json,
            reply(StatusCode::OK, r#"{"ok":false}"#),
        ];
        let (port, mock, server) = mock_server(replies).await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path(), false, true).await;
        insert_seed(&state).await;
        let registry = registry(&lc);
        registry.insert_for_test(peer("mapped", port));
        let app = routes().with_state(lc.clone());
        for expected in [
            "no_pairing_token",
            "auth_failed",
            "auth_failed",
            "auth_failed",
            "peer_unreachable",
        ] {
            let (status, body) = send(app.clone(), &format!("{PATH}?bust=1"), None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["peers"][0]["error"], expected);
            assert_null_permissions(&body["peers"][0]);
        }
        assert_eq!(mock.calls.load(Ordering::SeqCst), 5);
        assert_eq!(
            registry.get("mapped").unwrap().token.as_deref(),
            Some("token-mapped")
        );
        server.abort();
    }

    #[tokio::test]
    async fn missing_seed_is_per_peer_unreachable() {
        let _guard = test_guard();
        reset_test_state();
        let tmp = tempfile::tempdir().unwrap();
        let (_state, lc) = test_state(tmp.path(), false, true).await;
        registry(&lc).insert_for_test(peer("seedless", 1));
        let (status, body) = send(routes().with_state(lc.clone()), PATH, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["peers"][0]["error"], "peer_unreachable");
    }

    #[tokio::test]
    async fn success_normalizes_python_truthiness_and_sends_signed_headers() {
        let _guard = test_guard();
        reset_test_state();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let body = r#"{"ok":1,"restart":1,"update":"","log_stream":[1],"allow_remote_update":{}}"#;
        let (port, mock, server) = mock_server(vec![reply(StatusCode::OK, body)]).await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path(), false, true).await;
        insert_seed(&state).await;
        let mut remote = peer("raw", port);
        remote.name = String::new();
        registry(&lc).insert_for_test(remote);
        let (status, response) = send(routes().with_state(lc.clone()), PATH, None).await;
        assert_eq!(status, StatusCode::OK);
        let result = &response["peers"][0];
        assert_eq!(result["name"], "");
        assert_eq!(result["restart"], true);
        assert_eq!(result["update"], false);
        assert_eq!(result["log_stream"], true);
        assert_eq!(result["allow_remote_update"], false);
        assert!(result["error"].is_null());
        let headers = mock.headers.lock().unwrap();
        assert_eq!(headers[0]["x-requested-with"], "FleetPeerStatus");
        assert_eq!(headers[0][header::AUTHORIZATION], "Bearer token-raw");
        assert!(headers[0].contains_key("x-peer-sig"));
        server.abort();
    }

    #[tokio::test]
    async fn semaphore_is_shared_across_concurrent_route_requests() {
        let _guard = test_guard();
        reset_test_state();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let (port, mock, server) =
            mock_server(vec![reply(StatusCode::OK, r#"{"ok":true}"#); 12]).await;
        mock.release_at.store(10, Ordering::SeqCst);
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path(), false, true).await;
        insert_seed(&state).await;
        let registry = registry(&lc);
        for index in 0..6 {
            registry.insert_for_test(peer(&format!("peer-{index}"), port));
        }
        let app = routes().with_state(lc.clone());
        let first_uri = format!("{PATH}?bust=first");
        let second_uri = format!("{PATH}?bust=second");
        let (first, second) = tokio::join!(
            send(app.clone(), &first_uri, None),
            send(app, &second_uri, None),
        );
        assert_eq!(first.0, StatusCode::OK);
        assert_eq!(second.0, StatusCode::OK);
        assert_eq!(first.1["peers"].as_array().unwrap().len(), 6);
        assert_eq!(second.1["peers"].as_array().unwrap().len(), 6);
        assert!([&first.1, &second.1].into_iter().all(|body| body["peers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|peer| peer["error"].is_null())));
        assert_eq!(mock.calls.load(Ordering::SeqCst), 12);
        assert_eq!(mock.max_active.load(Ordering::SeqCst), 10);
        server.abort();
    }

    #[tokio::test]
    async fn peer_client_rejects_public_and_link_local_targets() {
        let _guard = test_guard();
        reset_test_state();
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path(), false, true).await;
        insert_seed(&state).await;
        let registry = registry(&lc);
        let mut public = peer("public", 80);
        public.api_host = "8.8.8.8".to_owned();
        registry.insert_for_test(public);
        let mut link_local = peer("link-local", 80);
        link_local.api_host = "169.254.1.1".to_owned();
        registry.insert_for_test(link_local);
        let (status, body) = send(routes().with_state(lc.clone()), PATH, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["peers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|peer| peer["error"] == "peer_unreachable"));
        let production = include_str!("lan_cowork_settings.rs")
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap();
        assert!(production.contains("session_guard("));
        assert!(production.contains("build_peer_client("));
        assert!(production.contains("build_peer_headers("));
        assert!(!production.contains("reqwest::Client::"));
        assert!(!production.contains("fleet_peer_guard"));
        assert!(!production.contains("fleet_session_guard"));
        assert!(!production.contains("transport.send("));
        assert!(!production.contains("send_with_reason"));
    }

    // `query_logging_has_positive_control_without_secrets` relocated to
    // yu-server's `lan_cowork_split_integration_tests.rs` (S4d step 4): it
    // exercises `crate::logs::LogRingBuffer`/`tracing_layer::TracingLayer`,
    // yu-server's production tracing infrastructure, unreachable across the
    // crate boundary.
}
