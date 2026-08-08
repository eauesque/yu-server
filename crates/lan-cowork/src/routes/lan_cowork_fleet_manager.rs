//! Chief-side LAN Cowork fleet peer polling and cache.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::future::join_all;
use reqwest::header::HeaderValue;
use serde_json::{json, Value};
use tokio::{sync::Semaphore, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::routes::{
    lan_cowork::{ext_config, load_config_json},
    lan_cowork_client::{build_peer_client, read_peer_response_capped, OutboundFailure},
    lan_cowork_discovery::load_identity_seed,
    lan_cowork_fleet_config::get_fleet_timings,
    lan_cowork_host::{LanCoworkHost, LanCoworkState},
    lan_cowork_registry::{PeerInfo, PeerRegistry},
    lan_cowork_transport::build_peer_headers_at,
};

const FLEET_INFO_PATH: &str = "/ext/lan_cowork/fleet/info";
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_PEERS: usize = 10;
const NOISE_THRESHOLD: usize = 3;

#[derive(Clone, Debug)]
struct CacheEntry {
    name: String,
    info: Option<Value>,
    last_fetched_at: String,
    last_heartbeat_at: Option<String>,
    reachable: bool,
    last_error: Option<String>,
}

#[derive(Default)]
struct FleetCache {
    entries: HashMap<String, CacheEntry>,
    consecutive_failures: HashMap<String, usize>,
}

struct RunningTask {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

pub struct FleetManager {
    cache: Mutex<FleetCache>,
    running: tokio::sync::Mutex<Option<RunningTask>>,
    fanout: Semaphore,
    pub(crate) dispatches: super::lan_cowork_fleet_dispatch::DispatchLedger,
    #[cfg(test)]
    poll_ticks: std::sync::atomic::AtomicUsize,
}

impl FleetManager {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(FleetCache::default()),
            running: tokio::sync::Mutex::new(None),
            fanout: Semaphore::new(MAX_CONCURRENT_PEERS),
            dispatches: super::lan_cowork_fleet_dispatch::DispatchLedger::default(),
            #[cfg(test)]
            poll_ticks: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub async fn start(self: &Arc<Self>, state: LanCoworkState) {
        let mut running = self.running.lock().await;
        if running.is_some() {
            return;
        }
        let cancel = CancellationToken::new();
        let manager = self.clone();
        let task_cancel = cancel.clone();
        let handle = tokio::spawn(async move { manager.poll_loop(state, task_cancel).await });
        *running = Some(RunningTask { cancel, handle });
        tracing::info!("FleetManager polling started");
    }

    pub async fn stop(&self) {
        let Some(task) = self.running.lock().await.take() else {
            return;
        };
        task.cancel.cancel();
        if let Err(error) = task.handle.await {
            tracing::debug!(%error, "FleetManager polling task ended unexpectedly");
        }
    }

    pub async fn is_running(&self) -> bool {
        self.running.lock().await.is_some()
    }

    pub async fn refresh(&self, state: &LanCoworkState, force: bool) {
        let Some(registry) = state.peer_registry.get().cloned() else {
            return;
        };
        let local_id = registry.local_peer_id();
        let mut peers = registry
            .list_all()
            .into_iter()
            .filter(|peer| peer.peer_id != local_id)
            .collect::<Vec<_>>();
        let known_ids = peers
            .iter()
            .map(|peer| peer.peer_id.clone())
            .collect::<HashSet<_>>();
        {
            let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
            cache
                .entries
                .retain(|peer_id, _| peer_id == &local_id || known_ids.contains(peer_id));
            cache
                .consecutive_failures
                .retain(|peer_id, _| peer_id == &local_id || known_ids.contains(peer_id));
        }

        if !force {
            let soft_cutoff = unix_now() - fleet_timing(state, "soft_prune_sec", 3_600);
            peers.retain(|peer| Self::is_polling_eligible(peer, soft_cutoff));
        }

        join_all(peers.into_iter().map(|peer| {
            let registry = registry.clone();
            async move {
                let _permit = self
                    .fanout
                    .acquire()
                    .await
                    .expect("FleetManager semaphore is never closed");
                self.fetch_peer(state, &registry, &peer).await;
            }
        }))
        .await;
    }

    fn is_polling_eligible(peer: &PeerInfo, soft_cutoff: i64) -> bool {
        peer.last_reached_at
            .is_none_or(|last_reached| last_reached >= soft_cutoff)
    }

    pub fn get_peers_snapshot(&self, state: &LanCoworkState) -> Value {
        let Some(registry) = state.peer_registry.get() else {
            return json!({"responder_peer_id": "", "roles_index": {}, "peers": []});
        };
        let local_id = registry.local_peer_id();
        let registry_peers = registry
            .list_all()
            .into_iter()
            .map(|peer| (peer.peer_id.clone(), peer))
            .collect::<HashMap<_, _>>();
        let cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        let mut peers = Vec::new();
        let mut roles_index: HashMap<String, Vec<String>> = HashMap::new();

        for (peer_id, entry) in &cache.entries {
            if peer_id == &local_id {
                continue;
            }
            let Some(registry_peer) = registry_peers.get(peer_id) else {
                continue;
            };
            let info = entry
                .info
                .clone()
                .filter(python_truthy)
                .unwrap_or_else(|| json!({}));
            let last_error = entry.last_error.as_deref().unwrap_or_default();
            if !python_truthy(&info) && last_error.starts_with("http_4") {
                continue;
            }
            let roles = info
                .get("roles")
                .and_then(Value::as_array)
                .map(|roles| {
                    roles
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            for role in &roles {
                let peer_ids = roles_index.entry(role.clone()).or_default();
                if !peer_ids.contains(peer_id) {
                    peer_ids.push(peer_id.clone());
                }
            }
            peers.push(json!({
                "peer_id": peer_id,
                "name": entry.name,
                "roles": roles,
                "info": info,
                "last_fetched_at": entry.last_fetched_at,
                "last_heartbeat_at": entry.last_heartbeat_at,
                "reachable": entry.reachable,
                "last_error": entry.last_error,
                "last_reached_at": registry_peer.last_reached_at,
                "last_attempted_at": registry_peer.last_attempted_at,
            }));
        }

        json!({
            "responder_peer_id": local_id,
            "roles_index": roles_index,
            "peers": peers,
        })
    }

    async fn poll_loop(self: Arc<Self>, state: LanCoworkState, cancel: CancellationToken) {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = self.refresh(&state, false) => {}
            }
            #[cfg(test)]
            self.poll_ticks
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let interval = Duration::from_secs(
                fleet_timing(&state, "peers_poll_interval_sec", 30).max(1) as u64,
            );
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(interval) => {}
            }
        }
    }

    async fn fetch_peer(&self, state: &LanCoworkState, registry: &PeerRegistry, peer: &PeerInfo) {
        let now = unix_now();
        let fetched_at = chrono::Local::now().to_rfc3339();
        let result = tokio::time::timeout(FETCH_TIMEOUT, request_peer(state, registry, peer)).await;
        match result {
            Ok(Ok(info)) => {
                {
                    let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
                    let last_heartbeat_at = cache
                        .entries
                        .get(&peer.peer_id)
                        .and_then(|entry| entry.last_heartbeat_at.clone());
                    cache.entries.insert(
                        peer.peer_id.clone(),
                        CacheEntry {
                            name: peer.name.clone(),
                            info: Some(info),
                            last_fetched_at: fetched_at,
                            last_heartbeat_at,
                            reachable: true,
                            last_error: None,
                        },
                    );
                    cache.consecutive_failures.remove(&peer.peer_id);
                }
                if let Err(error) = registry
                    .update_telemetry(&peer.peer_id, Some(now), None)
                    .await
                {
                    tracing::debug!(peer_id = %peer.peer_id, %error, "FleetManager reached telemetry update failed");
                }
            }
            result => {
                let last_error = match result {
                    Err(_) => "timeout".to_owned(),
                    Ok(Err(error)) => error,
                    Ok(Ok(_)) => unreachable!(),
                };
                let failures = {
                    let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
                    let existing = cache.entries.get(&peer.peer_id).cloned();
                    let failures = cache
                        .consecutive_failures
                        .entry(peer.peer_id.clone())
                        .and_modify(|count| *count += 1)
                        .or_insert(1)
                        .to_owned();
                    cache.entries.insert(
                        peer.peer_id.clone(),
                        CacheEntry {
                            name: peer.name.clone(),
                            info: existing.as_ref().and_then(|entry| entry.info.clone()),
                            last_fetched_at: fetched_at,
                            last_heartbeat_at: existing.and_then(|entry| entry.last_heartbeat_at),
                            reachable: false,
                            last_error: Some(last_error.clone()),
                        },
                    );
                    failures
                };
                if failure_logs_at_warn(failures) {
                    tracing::warn!(peer_id = %peer.peer_id, error = %last_error, "FleetManager fetch failed");
                } else {
                    tracing::debug!(peer_id = %peer.peer_id, failures, error = %last_error, "FleetManager fetch failed; repeated failure suppressed");
                }
                if let Err(error) = registry
                    .update_telemetry(&peer.peer_id, None, Some(now))
                    .await
                {
                    tracing::debug!(peer_id = %peer.peer_id, %error, "FleetManager attempted telemetry update failed");
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn test_poll_ticks(&self) -> usize {
        self.poll_ticks.load(std::sync::atomic::Ordering::SeqCst)
    }
}

async fn request_peer(
    state: &LanCoworkState,
    registry: &PeerRegistry,
    peer: &PeerInfo,
) -> Result<Value, String> {
    let seed = load_identity_seed(state.db_read())
        .await
        .ok_or_else(|| "identity_unavailable".to_owned())?;
    let mut headers = build_peer_headers_at(
        unix_now(),
        &seed,
        &registry.local_peer_id(),
        peer,
        "GET",
        FLEET_INFO_PATH,
        "",
        &[],
    )
    .map_err(|_| "header_build_failed".to_owned())?;
    headers.insert("X-Requested-With", HeaderValue::from_static("FleetManager"));
    let (client, base) =
        build_peer_client(&peer.api_host, peer.api_port, Some(FETCH_TIMEOUT), None)
            .await
            .map_err(|_| "request_failed".to_owned())?;
    let response = client
        .get(format!("{base}{FLEET_INFO_PATH}"))
        .headers(headers)
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                "timeout".to_owned()
            } else {
                "request_failed".to_owned()
            }
        })?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("http_{}", response.status().as_u16()));
    }
    let body = read_peer_response_capped(response)
        .await
        .map_err(|error| match error {
            OutboundFailure::BodyTooLarge => "response_too_large".to_owned(),
            _ => "non_json_200".to_owned(),
        })?;
    serde_json::from_str(&body).map_err(|_| "non_json_200".to_owned())
}

fn fleet_timing(state: &LanCoworkState, key: &str, default: i64) -> i64 {
    get_fleet_timings(&load_config_json(state.config_path()))[key]
        .as_i64()
        .unwrap_or(default)
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

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn failure_logs_at_warn(failures: usize) -> bool {
    failures <= NOISE_THRESHOLD
}

pub fn chief_enabled(state: &dyn LanCoworkHost) -> bool {
    ext_config(&load_config_json(state.config_path()))
        .get("fleet")
        .and_then(|fleet| fleet.get("chief"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(crate) async fn sync_fleet_manager(state: &LanCoworkState, chief: bool) {
    if chief && state.peer_registry.get().is_some() {
        state.fleet_manager.start(state.clone()).await;
    } else {
        state.fleet_manager.stop().await;
    }
}

pub async fn start_fleet_manager_if_configured(state: &LanCoworkState) {
    sync_fleet_manager(state, chief_enabled(&**state)).await;
}

impl Default for FleetManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(unused_variables)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::{header::CONTENT_TYPE, HeaderMap, HeaderValue, StatusCode},
        response::{IntoResponse, Response},
        routing::get,
        Router,
    };
    use std::{
        collections::HashSet,
        sync::atomic::{AtomicUsize, Ordering},
        time::Instant,
    };

    use crate::routes::{
        lan_cowork::write_config_json,
        lan_cowork_descriptor::{reset_client_state, test_guard, TEST_ALLOW_LOOPBACK},
    };
    use crate::state::SharedState;

    const TEST_SEED: [u8; 32] = [7; 32];

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

    #[derive(Clone)]
    struct MockReply {
        status: StatusCode,
        body: &'static str,
        content_type: &'static str,
        delay: Duration,
    }

    #[derive(Debug)]
    struct ObservedRequest {
        has_nonce: bool,
        requested_with: Option<String>,
        has_authorization: bool,
    }

    struct MockState {
        reply: MockReply,
        count: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
        observed: Mutex<Vec<ObservedRequest>>,
    }

    async fn mock_fleet_info(State(state): State<Arc<MockState>>, headers: HeaderMap) -> Response {
        state.count.fetch_add(1, Ordering::SeqCst);
        let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
        state.max_active.fetch_max(active, Ordering::SeqCst);
        state
            .observed
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(ObservedRequest {
                has_nonce: headers.contains_key("X-Peer-Nonce"),
                requested_with: headers
                    .get("X-Requested-With")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
                has_authorization: headers.contains_key(reqwest::header::AUTHORIZATION),
            });
        tokio::time::sleep(state.reply.delay).await;
        state.active.fetch_sub(1, Ordering::SeqCst);
        let mut response = (state.reply.status, state.reply.body).into_response();
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static(state.reply.content_type),
        );
        response
    }

    async fn spawn_mock(reply: MockReply) -> (u16, Arc<MockState>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(MockState {
            reply,
            count: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            observed: Mutex::new(Vec::new()),
        });
        let app = Router::new()
            .route(FLEET_INFO_PATH, get(mock_fleet_info))
            .with_state(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (port, state, server)
    }

    async fn test_state(root: &std::path::Path) -> (SharedState, LanCoworkState) {
        let state =
            crate::state::semantic_test_state_with_root(false, String::new(), root.to_path_buf())
                .await;
        crate::schema::apply_standalone_schema(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO lan_cowork_identity (key, value) VALUES ('ed25519_seed', ?1)")
            .bind(TEST_SEED.as_slice())
            .execute(&state.db)
            .await
            .unwrap();
        let lc = LanCoworkState::from_shared(&state);
        lc.peer_registry
            .set(Arc::new(PeerRegistry::new(
                state.db.clone(),
                Duration::from_secs(30),
                "local".to_owned(),
            )))
            .ok();
        (state, lc)
    }

    fn registry(state: &LanCoworkState) -> Arc<PeerRegistry> {
        state.peer_registry.get().unwrap().clone()
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

    async fn add_peer(state: &LanCoworkState, peer: PeerInfo) {
        registry(state).upsert(peer).await.unwrap();
    }

    fn cache_entry(info: Option<Value>, error: Option<&str>) -> CacheEntry {
        CacheEntry {
            name: "cached".to_owned(),
            info,
            last_fetched_at: "now".to_owned(),
            last_heartbeat_at: None,
            reachable: error.is_none(),
            last_error: error.map(str::to_owned),
        }
    }

    fn snapshot_ids(snapshot: &Value) -> HashSet<&str> {
        snapshot["peers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|peer| peer["peer_id"].as_str())
            .collect()
    }

    fn write_poll_interval(state: &SharedState, seconds: i64) {
        write_config_json(
            &state.config.config_path,
            &json!({"extensions": {"builtin-lan-cowork": {"fleet": {"timings": {
                "peers_poll_interval_sec": seconds
            }}}}}),
        )
        .unwrap();
    }

    async fn wait_for<F: Fn() -> bool>(timeout: Duration, condition: F) {
        tokio::time::timeout(timeout, async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn snapshot_hides_only_empty_auth_failures_and_intersects_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path()).await;
        for id in ["hidden", "known", "server", "network"] {
            add_peer(&lc, peer(id, 1)).await;
        }
        let manager = &lc.fleet_manager;
        {
            let mut cache = manager.cache.lock().unwrap();
            cache
                .entries
                .insert("hidden".to_owned(), cache_entry(None, Some("http_401")));
            cache.entries.insert(
                "known".to_owned(),
                cache_entry(Some(json!({"roles": ["worker"]})), Some("http_401")),
            );
            cache
                .entries
                .insert("server".to_owned(), cache_entry(None, Some("http_503")));
            cache.entries.insert(
                "network".to_owned(),
                cache_entry(None, Some("request_failed")),
            );
            cache.entries.insert(
                "removed".to_owned(),
                cache_entry(Some(json!({"roles": []})), None),
            );
            cache.entries.insert(
                "local".to_owned(),
                cache_entry(Some(json!({"roles": []})), None),
            );
        }

        let snapshot = manager.get_peers_snapshot(&lc);
        assert_eq!(
            snapshot_ids(&snapshot),
            HashSet::from(["known", "server", "network"])
        );
        assert_eq!(snapshot["roles_index"], json!({"worker": ["known"]}));
    }

    #[tokio::test]
    async fn refresh_prunes_cache_and_failure_counter_for_removed_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path()).await;
        add_peer(&lc, peer("gone", 1)).await;
        {
            let mut cache = lc.fleet_manager.cache.lock().unwrap();
            cache
                .entries
                .insert("gone".to_owned(), cache_entry(None, None));
            cache.consecutive_failures.insert("gone".to_owned(), 4);
            assert!(cache.entries.contains_key("gone"));
            assert_eq!(cache.consecutive_failures.get("gone"), Some(&4));
        }
        registry(&lc).remove("gone").await.unwrap();

        lc.fleet_manager.refresh(&lc, true).await;

        let cache = lc.fleet_manager.cache.lock().unwrap();
        assert!(!cache.entries.contains_key("gone"));
        assert!(!cache.consecutive_failures.contains_key("gone"));
    }

    #[tokio::test]
    async fn tokenless_poll_sends_nonce_and_fleet_header_then_hides_401() {
        let _loopback = LoopbackGuard::new();
        let (port, mock, server) = spawn_mock(MockReply {
            status: StatusCode::UNAUTHORIZED,
            body: "denied",
            content_type: "text/plain",
            delay: Duration::ZERO,
        })
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path()).await;
        let mut tokenless = peer("tokenless", port);
        tokenless.token = None;
        add_peer(&lc, tokenless).await;

        lc.fleet_manager.refresh(&lc, true).await;

        assert_eq!(mock.count.load(Ordering::SeqCst), 1);
        let observed = mock.observed.lock().unwrap();
        assert!(observed[0].has_nonce);
        assert_eq!(observed[0].requested_with.as_deref(), Some("FleetManager"));
        assert!(!observed[0].has_authorization);
        drop(observed);
        let cache = lc.fleet_manager.cache.lock().unwrap();
        assert_eq!(
            cache.entries["tokenless"].last_error.as_deref(),
            Some("http_401")
        );
        drop(cache);
        assert!(lc.fleet_manager.get_peers_snapshot(&lc)["peers"]
            .as_array()
            .unwrap()
            .is_empty());
        let telemetry = registry(&lc).get("tokenless").unwrap();
        assert!(telemetry.last_attempted_at.is_some());
        assert!(telemetry.last_reached_at.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn repeated_failures_cross_log_threshold_and_record_fetch_time() {
        let _loopback = LoopbackGuard::new();
        let (port, mock, server) = spawn_mock(MockReply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: "failed",
            content_type: "text/plain",
            delay: Duration::ZERO,
        })
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path()).await;
        add_peer(&lc, peer("offline", port)).await;

        for _ in 0..4 {
            lc.fleet_manager.refresh(&lc, true).await;
        }

        assert_eq!(mock.count.load(Ordering::SeqCst), 4);
        let cache = lc.fleet_manager.cache.lock().unwrap();
        assert_eq!(cache.consecutive_failures["offline"], 4);
        assert!(!cache.entries["offline"].last_fetched_at.is_empty());
        assert_eq!(
            cache.entries["offline"].last_error.as_deref(),
            Some("http_500")
        );
        assert!(failure_logs_at_warn(3));
        assert!(!failure_logs_at_warn(4));
        server.abort();
    }

    #[tokio::test]
    async fn successful_fetch_clears_the_failure_counter() {
        let _loopback = LoopbackGuard::new();
        let (failure_port, _, failure_server) = spawn_mock(MockReply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: "failed",
            content_type: "text/plain",
            delay: Duration::ZERO,
        })
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path()).await;
        add_peer(&lc, peer("recovering", failure_port)).await;

        for _ in 0..=NOISE_THRESHOLD {
            lc.fleet_manager.refresh(&lc, true).await;
        }
        assert_eq!(
            lc.fleet_manager.cache.lock().unwrap().consecutive_failures["recovering"],
            NOISE_THRESHOLD + 1
        );
        let (success_port, success_mock, success_server) = spawn_mock(MockReply {
            status: StatusCode::OK,
            body: r#"{"roles":["worker"]}"#,
            content_type: "application/json",
            delay: Duration::ZERO,
        })
        .await;
        add_peer(&lc, peer("recovering", success_port)).await;
        lc.fleet_manager.refresh(&lc, true).await;

        assert_eq!(success_mock.count.load(Ordering::SeqCst), 1);
        let cache = lc.fleet_manager.cache.lock().unwrap();
        assert!(!cache.consecutive_failures.contains_key("recovering"));
        assert!(cache.entries["recovering"].reachable);
        assert!(cache.entries["recovering"].last_error.is_none());
        failure_server.abort();
        success_server.abort();
    }

    #[tokio::test]
    async fn non_json_200_has_distinct_error() {
        let _loopback = LoopbackGuard::new();
        let (port, mock, server) = spawn_mock(MockReply {
            status: StatusCode::OK,
            body: "<html>decoy</html>",
            content_type: "text/html",
            delay: Duration::ZERO,
        })
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path()).await;
        add_peer(&lc, peer("decoy", port)).await;

        lc.fleet_manager.refresh(&lc, true).await;

        assert_eq!(mock.count.load(Ordering::SeqCst), 1);
        assert_eq!(
            lc.fleet_manager.cache.lock().unwrap().entries["decoy"]
                .last_error
                .as_deref(),
            Some("non_json_200")
        );
        server.abort();
    }

    #[tokio::test]
    async fn soft_prune_skips_old_peer_but_polls_never_reached_peer() {
        let _loopback = LoopbackGuard::new();
        let (port, mock, server) = spawn_mock(MockReply {
            status: StatusCode::OK,
            body: r#"{"roles":[]}"#,
            content_type: "application/json",
            delay: Duration::ZERO,
        })
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path()).await;
        let mut old = peer("old", port);
        old.last_reached_at = Some(unix_now() - 3_601);
        add_peer(&lc, old).await;
        add_peer(&lc, peer("new", port)).await;

        lc.fleet_manager.refresh(&lc, false).await;

        assert_eq!(mock.count.load(Ordering::SeqCst), 1);
        let cache = lc.fleet_manager.cache.lock().unwrap();
        assert!(cache.entries.contains_key("new"));
        assert!(!cache.entries.contains_key("old"));
        server.abort();
    }

    #[tokio::test]
    async fn poll_interval_is_reread_and_stop_awaits_loop_completion() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path()).await;
        write_poll_interval(&state, 1);
        lc.fleet_manager.start(lc.clone()).await;
        wait_for(Duration::from_secs(1), || {
            lc.fleet_manager.test_poll_ticks() >= 1
        })
        .await;
        write_poll_interval(&state, 2);
        wait_for(Duration::from_secs(2), || {
            lc.fleet_manager.test_poll_ticks() >= 2
        })
        .await;
        let second_tick = Instant::now();
        wait_for(Duration::from_secs(4), || {
            lc.fleet_manager.test_poll_ticks() >= 3
        })
        .await;
        assert!(second_tick.elapsed() >= Duration::from_millis(1_500));

        lc.fleet_manager.stop().await;
        assert!(!lc.fleet_manager.is_running().await);
        let stopped_at = lc.fleet_manager.test_poll_ticks();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(lc.fleet_manager.test_poll_ticks(), stopped_at);
    }

    #[tokio::test]
    async fn persisted_chief_boot_gate_requires_registry_and_starts_idempotently() {
        let tmp = tempfile::tempdir().unwrap();
        let state = crate::state::semantic_test_state_with_root(
            false,
            String::new(),
            tmp.path().to_path_buf(),
        )
        .await;
        let lc = LanCoworkState::from_shared(&state);
        write_config_json(
            &state.config.config_path,
            &json!({"extensions": {"builtin-lan-cowork": {"fleet": {"chief": true}}}}),
        )
        .unwrap();
        start_fleet_manager_if_configured(&lc).await;
        assert!(!lc.fleet_manager.is_running().await);

        crate::schema::apply_standalone_schema(&state.db)
            .await
            .unwrap();
        lc.peer_registry
            .set(Arc::new(PeerRegistry::new(
                state.db.clone(),
                Duration::from_secs(30),
                "local".to_owned(),
            )))
            .ok();
        start_fleet_manager_if_configured(&lc).await;
        start_fleet_manager_if_configured(&lc).await;
        wait_for(Duration::from_secs(1), || {
            lc.fleet_manager.test_poll_ticks() >= 1
        })
        .await;
        assert!(lc.fleet_manager.is_running().await);
        lc.fleet_manager.stop().await;
    }

    #[tokio::test]
    async fn force_refresh_and_background_poll_keep_cache_valid() {
        let _loopback = LoopbackGuard::new();
        let (port, mock, server) = spawn_mock(MockReply {
            status: StatusCode::OK,
            body: r#"{"roles":["worker"]}"#,
            content_type: "application/json",
            delay: Duration::from_millis(100),
        })
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path()).await;
        add_peer(&lc, peer("shared", port)).await;
        lc.fleet_manager.start(lc.clone()).await;
        wait_for(Duration::from_secs(1), || {
            mock.count.load(Ordering::SeqCst) >= 1
        })
        .await;

        lc.fleet_manager.refresh(&lc, true).await;
        lc.fleet_manager.stop().await;

        assert!(mock.count.load(Ordering::SeqCst) >= 2);
        let snapshot = lc.fleet_manager.get_peers_snapshot(&lc);
        assert_eq!(snapshot["peers"].as_array().unwrap().len(), 1);
        assert_eq!(snapshot["peers"][0]["info"]["roles"], json!(["worker"]));
        let telemetry = registry(&lc).get("shared").unwrap();
        assert!(telemetry.last_reached_at.is_some());
        assert_eq!(telemetry.last_reached_at, telemetry.last_attempted_at);
        server.abort();
    }

    #[tokio::test]
    async fn fanout_is_capped_at_ten_peers() {
        let _loopback = LoopbackGuard::new();
        let (port, mock, server) = spawn_mock(MockReply {
            status: StatusCode::OK,
            body: r#"{"roles":[]}"#,
            content_type: "application/json",
            delay: Duration::from_millis(100),
        })
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let (state, lc) = test_state(tmp.path()).await;
        for index in 0..11 {
            add_peer(&lc, peer(&format!("peer-{index}"), port)).await;
        }

        lc.fleet_manager.refresh(&lc, true).await;

        assert_eq!(mock.count.load(Ordering::SeqCst), 11);
        assert_eq!(mock.max_active.load(Ordering::SeqCst), 10);
        server.abort();
    }
}
