use std::{
    path::Path,
    sync::{Arc, OnceLock},
    time::Instant,
};

use async_trait::async_trait;
use axum::response::Response;
use futures_util::stream::BoxStream;
use sqlx::SqlitePool;

use crate::routes::{lan_cowork_fleet_manager::FleetManager, lan_cowork_registry::PeerRegistry};

#[derive(Debug, Clone)]
pub struct LogLine {
    pub seq: u64,
    pub timestamp: f64,
    pub level: String,
    pub target: String,
    pub message: String,
}

#[derive(Clone)]
pub struct FleetUiNonce(pub String);

#[derive(Clone)]
pub struct PeerSourceIp(pub String);

#[derive(Debug, Clone)]
pub enum LogEvent {
    Line(LogLine),
    Closed,
}

#[async_trait]
pub trait LanCoworkHost: Send + Sync + 'static {
    fn db(&self) -> &SqlitePool;
    fn db_read(&self) -> &SqlitePool;
    fn python_client(&self) -> &reqwest::Client;
    fn version(&self) -> &str;
    fn start_time(&self) -> Instant;
    fn config_json(&self) -> &serde_json::Value;
    fn config_path(&self) -> &Path;
    fn project_root(&self) -> &Path;
    fn python_url(&self) -> &str;
    fn pin_auth_enabled(&self) -> bool;
    fn safe_mode(&self) -> bool;
    fn sse_send(&self, source: &str, kind: &str, timestamp: f64, payload: serde_json::Value);
    fn sse_receiver_count(&self) -> usize;
    /// Renders the host's navigation fragment for the Fleet Admin page, which
    /// substitutes it into `<!-- NAV_PLACEHOLDER -->`.
    ///
    /// This is the crate's only dependency on host-owned UI. Before the crate
    /// split, `/fleet/ui` reached into the host's template engine and rendered
    /// its `_nav.html` directly — the fifth known reverse edge, and the only
    /// one in the UI layer. Routing it through this method dissolves the code
    /// dependency; what remains is a runtime contract stated here.
    ///
    /// Returning an empty string is legitimate, not an error: the page then
    /// renders with no navigation. A host with no nav of its own should return
    /// `""` rather than invent one. The Fleet Admin page must stay usable in
    /// that case, so nothing may key off the fragment's contents.
    ///
    /// Implementors rendering a template must supply every context key it
    /// needs. yu-server's `_nav.html` needs three (`csp_nonce`, `dist_v`,
    /// `active`); omitting `dist_v` emits `?v=` in asset URLs and silently
    /// breaks cache-busting rather than failing.
    fn render_nav(&self, csp_nonce: &str, active: &str) -> String;
    fn log_open(
        &self,
        limit: usize,
        level: Option<&str>,
    ) -> (BoxStream<'static, LogEvent>, Vec<LogLine>);
    /// Reserves one fleet log-stream connection slot for `ip`. Returns `false`
    /// when that IP's connection budget is already exhausted; the caller must
    /// reject the request (HTTP 429) instead of opening a stream.
    fn register_log_stream_connection(&self, ip: &str) -> bool;
    /// Releases a fleet log-stream connection slot previously reserved via
    /// `register_log_stream_connection`. Must be called exactly once per
    /// successful reservation, including when the stream ends or the client
    /// disconnects (via a `Drop` guard).
    fn unregister_log_stream_connection(&self, ip: &str);
    async fn record_journal_action(
        &self,
        session_id: &str,
        tool_name: &str,
        status: &str,
        duration_ms: i64,
        result_summary: &str,
    );
    async fn require_session(&self, session: Option<&tower_sessions::Session>) -> Option<Response>;
}

#[derive(Clone)]
pub struct LanCoworkState {
    pub host: Arc<dyn LanCoworkHost>,
    pub peer_registry: Arc<OnceLock<Arc<PeerRegistry>>>,
    pub fleet_manager: Arc<FleetManager>,
    pub settings_lock: Arc<tokio::sync::Mutex<()>>,
}

impl std::ops::Deref for LanCoworkState {
    type Target = dyn LanCoworkHost;

    fn deref(&self) -> &Self::Target {
        &*self.host
    }
}

impl LanCoworkState {
    /// Stores the exact LAN-Cowork handle instances supplied by the assembler.
    pub fn new<T: LanCoworkHost>(
        shared: &Arc<T>,
        peer_registry: Arc<OnceLock<Arc<PeerRegistry>>>,
        fleet_manager: Arc<FleetManager>,
        settings_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        let host = Arc::clone(shared);
        let host: Arc<dyn LanCoworkHost> = host;
        Self {
            host,
            peer_registry,
            fleet_manager,
            settings_lock,
        }
    }

    pub fn from_shared<T: LanCoworkHost>(shared: &Arc<T>) -> Self {
        Self::new(
            shared,
            Arc::new(OnceLock::new()),
            Arc::new(FleetManager::new()),
            Arc::new(tokio::sync::Mutex::new(())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestHost;

    #[tokio::test]
    async fn lan_cowork_state_new_shares_caller_supplied_arc_identity() {
        let host = Arc::new(TestHost::new(false, false, String::new(), ".".into()));
        let peer_registry = Arc::new(OnceLock::new());
        let fleet_manager = Arc::new(FleetManager::new());
        let settings_lock = Arc::new(tokio::sync::Mutex::new(()));

        let state = LanCoworkState::new(
            &host,
            Arc::clone(&peer_registry),
            Arc::clone(&fleet_manager),
            Arc::clone(&settings_lock),
        );

        assert!(Arc::ptr_eq(&state.peer_registry, &peer_registry));
        assert!(Arc::ptr_eq(&state.fleet_manager, &fleet_manager));
        assert!(Arc::ptr_eq(&state.settings_lock, &settings_lock));
    }
}
