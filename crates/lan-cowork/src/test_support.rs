use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

use async_trait::async_trait;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use futures_util::stream::{self, BoxStream, StreamExt};
use serde_json::{json, Value};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use tokio::sync::broadcast;

use crate::routes::{
    lan_cowork_fleet_manager::FleetManager,
    lan_cowork_host::{LanCoworkHost, LanCoworkState, LogEvent, LogLine},
    lan_cowork_registry::PeerRegistry,
};

pub(crate) struct TestConfig {
    pub pin_auth_enabled: bool,
    pub safe_mode: bool,
    pub python_url: String,
    pub config_path: PathBuf,
    pub project_root: PathBuf,
    pub app_config: Value,
}

#[derive(Clone, Debug)]
pub(crate) struct TestSseEvent {
    pub event_type: String,
    #[allow(dead_code)]
    pub timestamp: f64,
    pub data: Value,
    pub source: String,
}

pub(crate) struct TestSseHub {
    sender: broadcast::Sender<Arc<TestSseEvent>>,
}

impl TestSseHub {
    fn new() -> Self {
        let (sender, _) = broadcast::channel(64);
        Self { sender }
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Arc<TestSseEvent>> {
        self.sender.subscribe()
    }

    fn send(&self, event: TestSseEvent) {
        let _ = self.sender.send(Arc::new(event));
    }

    fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

pub(crate) struct TestHost {
    pub config: TestConfig,
    pub db: SqlitePool,
    pub db_read: SqlitePool,
    pub python_client: reqwest::Client,
    pub version: String,
    pub start_time: Instant,
    pub sse_hub: Arc<TestSseHub>,
    pub log_stream_connections: Mutex<HashMap<String, usize>>,
}

pub(crate) type SharedState = Arc<TestHost>;

impl TestHost {
    pub(crate) fn new(
        pin_auth_enabled: bool,
        safe_mode: bool,
        python_url: String,
        project_root: PathBuf,
    ) -> Self {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_lazy("sqlite::memory:")
            .expect("test sqlite pool");
        Self {
            config: TestConfig {
                pin_auth_enabled,
                safe_mode,
                python_url,
                config_path: project_root.join("config.json"),
                project_root,
                app_config: json!({}),
            },
            db_read: db.clone(),
            db,
            python_client: reqwest::Client::new(),
            version: "test".to_owned(),
            start_time: Instant::now(),
            sse_hub: Arc::new(TestSseHub::new()),
            log_stream_connections: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl LanCoworkHost for TestHost {
    fn db(&self) -> &SqlitePool {
        &self.db
    }

    fn db_read(&self) -> &SqlitePool {
        &self.db_read
    }

    fn python_client(&self) -> &reqwest::Client {
        &self.python_client
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn start_time(&self) -> Instant {
        self.start_time
    }

    fn config_json(&self) -> &Value {
        &self.config.app_config
    }

    fn config_path(&self) -> &Path {
        &self.config.config_path
    }

    fn project_root(&self) -> &Path {
        &self.config.project_root
    }

    fn python_url(&self) -> &str {
        &self.config.python_url
    }

    fn pin_auth_enabled(&self) -> bool {
        self.config.pin_auth_enabled
    }

    fn safe_mode(&self) -> bool {
        self.config.safe_mode
    }

    fn sse_send(&self, source: &str, kind: &str, timestamp: f64, payload: Value) {
        self.sse_hub.send(TestSseEvent {
            source: source.to_owned(),
            event_type: kind.to_owned(),
            timestamp,
            data: payload,
        });
    }

    fn sse_receiver_count(&self) -> usize {
        self.sse_hub.receiver_count()
    }

    fn render_nav(&self, _csp_nonce: &str, _active: &str) -> String {
        String::new()
    }

    fn log_open(
        &self,
        _limit: usize,
        _level: Option<&str>,
    ) -> (BoxStream<'static, LogEvent>, Vec<LogLine>) {
        (stream::empty().boxed(), Vec::new())
    }

    fn register_log_stream_connection(&self, ip: &str) -> bool {
        let mut connections = self.log_stream_connections.lock().unwrap();
        let count = connections.entry(ip.to_string()).or_insert(0);
        if *count >= 3 {
            return false;
        }
        *count += 1;
        true
    }

    fn unregister_log_stream_connection(&self, ip: &str) {
        let mut connections = self.log_stream_connections.lock().unwrap();
        if let Some(count) = connections.get_mut(ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                connections.remove(ip);
            }
        }
    }

    async fn record_journal_action(
        &self,
        _session_id: &str,
        _tool_name: &str,
        _status: &str,
        _duration_ms: i64,
        _result_summary: &str,
    ) {
    }

    async fn require_session(&self, session: Option<&tower_sessions::Session>) -> Option<Response> {
        if !self.config.pin_auth_enabled {
            return None;
        }
        if let Some(session) = session {
            if session.get::<bool>("pin_ok").await.ok().flatten() == Some(true) {
                return None;
            }
        }
        Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"ok": false, "error": "session required"})),
            )
                .into_response(),
        )
    }
}

pub(crate) async fn semantic_test_state(pin_auth_enabled: bool) -> SharedState {
    semantic_test_state_with(pin_auth_enabled, String::new()).await
}

pub(crate) async fn semantic_test_state_with(
    pin_auth_enabled: bool,
    python_url: String,
) -> SharedState {
    semantic_test_state_with_root(pin_auth_enabled, python_url, PathBuf::from(".")).await
}

pub(crate) async fn semantic_test_state_with_root(
    pin_auth_enabled: bool,
    python_url: String,
    project_root: PathBuf,
) -> SharedState {
    Arc::new(TestHost::new(
        pin_auth_enabled,
        false,
        python_url,
        project_root,
    ))
}

#[allow(dead_code)]
pub(crate) fn lan_cowork_state(state: &SharedState) -> LanCoworkState {
    LanCoworkState::from_shared(state)
}

#[allow(dead_code)]
pub(crate) fn lan_cowork_state_with(
    state: &SharedState,
    peer_registry: Arc<OnceLock<Arc<PeerRegistry>>>,
    fleet_manager: Arc<FleetManager>,
    settings_lock: Arc<tokio::sync::Mutex<()>>,
) -> LanCoworkState {
    LanCoworkState::new(state, peer_registry, fleet_manager, settings_lock)
}
