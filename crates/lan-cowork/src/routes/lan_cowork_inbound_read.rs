//! LAN Cowork inbound read handler logic (Increment B-d5b/b-1).
//!
//! discover/status Axum handlers + local self-identity assembly. Dead-code until
//! b-1b constructs the registry, merges `routes()`, and adds the auth-chain bypass.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::{json, Value};

use super::lan_cowork_client::{build_peer_client, read_peer_response_capped};
use super::lan_cowork_host::{LanCoworkHost, LanCoworkState};
use super::lan_cowork_peer_api::{
    discover_response, event_type_allowed, peer_from_public_dict, status_response, to_public_dict,
    validate_register_host, PeerEventRequest, PeerHeartbeatRequest, PeerRegisterRequest,
    RegisterHostError,
};
use super::lan_cowork_registry::{
    PeerInfo, PeerRegistry, HARD_PRUNE_SEC, OFFLINE_TIMEOUT_SEC, SOFT_PRUNE_SEC,
};
use crate::auth::peer_transport::{
    nonce_store, renew_if_not_revoked, require_peer_auth, require_peer_renew_auth, PeerNonceStore,
};

/// Derive the local identity (peer_id, ed25519 pubkey, x25519 pubkey) from the
/// stored ed25519 seed. **Pure crypto, no I/O** — unit-testable and deterministic
/// (MF-2: keeps the identity test off the process-global bound_port / real network).
fn derive_self_identity(seed: &[u8]) -> Option<(String, [u8; 32], [u8; 32])> {
    let ed_pub = openssl::pkey::PKey::private_key_from_raw_bytes(seed, openssl::pkey::Id::ED25519)
        .ok()?
        .raw_public_key()
        .ok()?;
    let pubkey: [u8; 32] = ed_pub.as_slice().try_into().ok()?;
    let peer_id = crate::routes::peer_identity::derive_peer_id(&ed_pub);
    // x25519_pubkey_from_ed25519_seed returns Option<Vec<u8>> (NOT Result): use `?`.
    let x25519_vec = crate::auth::peer_pairing_crypto::x25519_pubkey_from_ed25519_seed(seed)?;
    let x25519_pk: [u8; 32] = x25519_vec.as_slice().try_into().ok()?;
    Some((peer_id, pubkey, x25519_pk))
}

/// Assemble the local node's own PeerInfo (needed by `status`). Combines the pure
/// identity (seed) with the LAN descriptor (api_host/api_port via bound_port,
/// available at request time). Returns None if identity is unprovisioned or the
/// descriptor is unavailable. Not unit-tested (descriptor deps) — verified in b-1b.
pub async fn assemble_local_peer_info(state: &dyn LanCoworkHost) -> Option<PeerInfo> {
    let seed = super::lan_cowork_discovery::load_identity_seed(state.db_read()).await?;
    let (peer_id, pubkey, x25519_pk) = derive_self_identity(&seed)?;
    // Route through `descriptor_for_handler` (not `local_descriptor` directly) so the
    // status handler honours the `TEST_DESCRIPTOR` seam under
    // `cfg(any(test, feature = "test-seams"))`. In production builds
    // `descriptor_for_handler` is exactly `local_descriptor`, so this
    // is behaviour-invariant. Returns Result<LocalDescriptor, DescriptorError>: `.ok()?`.
    let descriptor = super::lan_cowork_client::descriptor_for_handler(state)
        .await
        .ok()?;
    Some(PeerInfo {
        peer_id,
        name: descriptor.name,
        api_host: descriptor.api_host,
        api_port: descriptor.api_port,
        token: None,
        token_expires_at: None,
        token_issued_at: None,
        pubkey: Some(pubkey),
        x25519_pk: Some(x25519_pk),
        version: state.version().to_owned(),
        bridges: descriptor.bridges,
        inference_types: vec![],
        gpu: String::new(),
        generating: false,
        queue_depth: 0,
        status: "online".to_string(),
        last_seen: now_secs_f64(),
        session_id: String::new(),
        roles: vec![],
        last_reached_at: None,
        last_attempted_at: None,
    })
}

fn now_secs_f64() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

/// SF-1 flood gate: window length for the accepted-event relay-log throttle.
const EVENT_RELAYED_LOG_WINDOW_SEC: f64 = 60.0;
/// SF-1 flood gate: window length for accepted events dropped without an SSE consumer.
const EVENT_DROP_LOG_WINDOW_SEC: f64 = 60.0;
const MAX_SMALL_PEER_EVENT_BODY_BYTES: usize = 65_536;
const MAX_GENERATION_SUBMIT_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Throttle state for the SF-1 accepted-event relay log. Process-global; bounds
/// the per-event INFO to at most one line per window.
struct EventRelayedWindow {
    window_start: f64,
    relayed: u64,
}

impl EventRelayedWindow {
    const fn new() -> Self {
        // window_start = NEG_INFINITY so the very first event trips the window
        // and logs immediately (first-event-visible).
        Self {
            window_start: f64::NEG_INFINITY,
            relayed: 0,
        }
    }
}

/// Throttle state for the SF-1 accepted-event drop log. Process-global; bounds the
/// per-event INFO to at most one line per window while preserving visibility when
/// accepted events arrive without a local SSE consumer.
struct EventDropWindow {
    window_start: f64,
    dropped: u64,
}

impl EventDropWindow {
    const fn new() -> Self {
        // window_start = NEG_INFINITY so the very first event trips the window and
        // logs immediately (first-event-visible).
        Self {
            window_start: f64::NEG_INFINITY,
            dropped: 0,
        }
    }
}

/// Count one relayed event; return `Some(count)` when the window has elapsed
/// (emit the summary and reset), else `None` (accumulate and suppress). Pure —
/// no logging, no I/O; `now` is injected so this is unit-testable without the
/// global. Note: after events cease mid-window, the trailing residual count is
/// emitted lazily on the next event arriving >= WINDOW later (which flushes
/// immediately), not on a timer.
fn note_relayed_event(w: &mut EventRelayedWindow, now: f64) -> Option<u64> {
    w.relayed += 1;
    if now - w.window_start >= EVENT_RELAYED_LOG_WINDOW_SEC {
        let count = w.relayed;
        w.relayed = 0;
        w.window_start = now;
        Some(count)
    } else {
        None
    }
}

/// Count one dropped event; return `Some(count)` when the window has elapsed
/// (emit the summary and reset), else `None` (accumulate and suppress). Pure — no
/// logging, no I/O; `now` is injected so this is unit-testable without the global.
fn note_dropped_event(w: &mut EventDropWindow, now: f64) -> Option<u64> {
    w.dropped += 1;
    if now - w.window_start >= EVENT_DROP_LOG_WINDOW_SEC {
        let count = w.dropped;
        w.dropped = 0;
        w.window_start = now;
        Some(count)
    } else {
        None
    }
}

fn peer_event_body_limit(event_type: &str) -> usize {
    // generation.submit may carry img2img base64 image data in params.
    if event_type == "generation.submit" {
        MAX_GENERATION_SUBMIT_BODY_BYTES
    } else {
        MAX_SMALL_PEER_EVENT_BODY_BYTES
    }
}

fn peer_event_body_allowed(event_type: &str, body_len: usize) -> bool {
    body_len <= peer_event_body_limit(event_type)
}

/// Local, LAN-Cowork-owned stand-in for core's SSE event type — carries the
/// same four fields the caller forwards to `LanCoworkHost::sse_send`
/// (`:562-567`), without naming the core type. `source` is intentionally left
/// as produced here (`peer:{id}`) — normalizing the wider `source` spelling
/// spread (`"lan_cowork"` / `"lan-cowork"` / `peer:{id}`) is a separate,
/// behavior-changing decision, not part of this decoupling.
struct RelayedSseEvent {
    event_type: String,
    timestamp: f64,
    data: Value,
    source: String,
}

fn relayed_sse_event(
    event_type: String,
    mut event_data: serde_json::Map<String, Value>,
    peer_id: &str,
    timestamp: f64,
) -> RelayedSseEvent {
    event_data.insert("_peer_relayed".to_string(), Value::Bool(true));
    event_data.insert("peer_id".to_string(), Value::String(peer_id.to_string()));
    RelayedSseEvent {
        event_type,
        timestamp,
        data: Value::Object(event_data),
        source: format!("peer:{peer_id}"),
    }
}

// SF-1: api_ok/api_err are private `fn` in lan_cowork.rs and cannot be imported.
// Duplicated here rather than making them `pub` (that would be an out-of-scope
// change to lan_cowork.rs, which this dead-code increment must not touch).
fn api_ok(data: Value) -> Response {
    Json(data).into_response()
}

fn api_err(message: &str, code: &str, status: StatusCode) -> Response {
    (
        status,
        Json(json!({"ok": false, "error": message, "code": code})),
    )
        .into_response()
}

/// session_ok mirrors Python `_session_ok`: PIN auth disabled -> always true;
/// otherwise the session's `pin_ok` flag.
async fn session_ok(state: &dyn LanCoworkHost, session: Option<&tower_sessions::Session>) -> bool {
    if !state.pin_auth_enabled() {
        return true;
    }
    match session {
        Some(s) => s
            .get::<bool>("pin_ok")
            .await
            .unwrap_or(None)
            .unwrap_or(false),
        None => false,
    }
}

/// Preload the set of peer_ids that currently hold a non-revoked inbound token
/// (Python `has_token`: existence only, ignores expiry). Only used when session_ok.
async fn preload_inbound_tokens(state: &dyn LanCoworkHost) -> HashSet<String> {
    sqlx::query_scalar::<_, String>("SELECT peer_id FROM peer_tokens WHERE revoked_at IS NULL")
        .fetch_all(state.db_read())
        .await
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// GET /ext/lan_cowork/api/peer/discover
async fn peer_discover(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    let Some(registry) = state.peer_registry.get() else {
        return api_err(
            "LAN Cowork not enabled",
            "unavailable",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    let ok = session_ok(&*state, session.as_ref().map(|Extension(s)| s)).await;
    let tokens = if ok {
        preload_inbound_tokens(&*state).await
    } else {
        HashSet::new()
    };
    let peers = registry.list_all();
    let local = registry.local_peer_id();
    let body = discover_response(&peers, &local, ok, |peer_id| tokens.contains(peer_id));
    api_ok(body)
}

/// GET /ext/lan_cowork/api/peer/status
async fn peer_status(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    if state.peer_registry.get().is_none() {
        return api_err(
            "LAN Cowork not enabled",
            "unavailable",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    let Some(local) = assemble_local_peer_info(&*state).await else {
        return api_err(
            "identity unavailable",
            "unavailable",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    let ok = session_ok(&*state, session.as_ref().map(|Extension(s)| s)).await;
    let has_self_token = if ok {
        preload_inbound_tokens(&*state)
            .await
            .contains(&local.peer_id)
    } else {
        false
    };
    api_ok(status_response(&local, ok, has_self_token))
}

/// POST /ext/lan_cowork/api/peer/register — unauthenticated. Validates the request,
/// SSRF-gates the host (B-d3, stricter than Python), fetches the peer's /status,
/// parses it panic-safely, restores existing tokens (M7), and upserts. 503 if the
/// registry slot is empty (native_daemon off / identity unprovisioned).
async fn peer_register(
    State(state): State<LanCoworkState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(registry) = state.peer_registry.get() else {
        return api_err(
            "LAN Cowork not enabled",
            "not_enabled",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    // Content-Type + parse + validate.
    let ct_ok = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim() == "application/json")
        .unwrap_or(false);
    if !ct_ok {
        return api_err(
            "JSON body is required",
            "invalid_content_type",
            StatusCode::BAD_REQUEST,
        );
    }
    let req: PeerRegisterRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return api_err(
                &format!("body: {e}"),
                "invalid_json",
                StatusCode::BAD_REQUEST,
            )
        }
    };
    if let Err(msg) = req.validate() {
        return api_err(msg, "validation_error", StatusCode::BAD_REQUEST);
    }
    // SSRF gate (IP literal, RFC1918 v4 / ULA v6 only). 400 on reject — no outbound.
    // NH-1: distinguish a non-IP host from a disallowed one, closer to Python's messages.
    if let Err(e) = validate_register_host(&req.host) {
        let (msg, code) = match e {
            RegisterHostError::InvalidIp => ("invalid IP address", "invalid_host"),
            _ => ("only private addresses allowed", "invalid_host"),
        };
        return api_err(msg, code, StatusCode::BAD_REQUEST);
    }
    // Outbound: fetch the peer's /status (absolute mounted path, M4).
    let (client, base) = match build_peer_client(
        &req.host,
        req.port,
        Some(std::time::Duration::from_secs(10)),
        None,
    )
    .await
    {
        Ok(cb) => cb,
        Err(_) => {
            return api_err(
                "peer not reachable",
                "peer_unreachable",
                StatusCode::BAD_GATEWAY,
            )
        }
    };
    let url = format!("{base}/ext/lan_cowork/api/peer/status");
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => {
            return api_err(
                "peer not reachable",
                "peer_unreachable",
                StatusCode::BAD_GATEWAY,
            )
        }
    };
    let text = match read_peer_response_capped(resp).await {
        Ok(t) => t,
        Err(_) => {
            return api_err(
                "peer not reachable",
                "peer_unreachable",
                StatusCode::BAD_GATEWAY,
            )
        }
    };
    let info: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => {
            return api_err(
                "peer not reachable",
                "peer_unreachable",
                StatusCode::BAD_GATEWAY,
            )
        }
    };
    let peer_val = info.get("peer").cloned().unwrap_or(Value::Null);
    let mut peer = match peer_from_public_dict(&peer_val) {
        Some(p) => p,
        None => {
            return api_err(
                "peer not reachable",
                "peer_unreachable",
                StatusCode::BAD_GATEWAY,
            )
        }
    };
    // Trust the validated register host/port over whatever the peer self-reports.
    peer.api_host = req.host.clone();
    peer.api_port = req.port;
    // M7: restore tokens (the /status public dict strips them; upsert is non-COALESCE).
    if let Some(existing) = registry.get(&peer.peer_id) {
        peer.token = existing.token;
        peer.token_expires_at = existing.token_expires_at;
        peer.token_issued_at = existing.token_issued_at;
    }
    if registry.upsert(peer.clone()).await.is_err() {
        return api_err(
            "registry write failed",
            "registry_error",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }
    api_ok(json!({ "ok": true, "peer": to_public_dict(&peer) }))
}

/// POST /ext/lan_cowork/api/peer/token/renew — signature+nonce auth (no Bearer).
/// Atomically reissues the caller's token unless it has been revoked.
async fn peer_token_renew(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if state.peer_registry.get().is_none() {
        return api_err(
            "LAN Cowork not enabled",
            "not_enabled",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    peer_token_renew_inner(
        &*state,
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or(""),
        &headers,
        &body,
        nonce_store(),
    )
    .await
}

async fn peer_token_renew_inner(
    state: &dyn LanCoworkHost,
    method: &str,
    path: &str,
    query: &str,
    headers: &axum::http::HeaderMap,
    body: &[u8],
    nonces: &PeerNonceStore,
) -> Response {
    let peer_id =
        match require_peer_renew_auth(state, method, path, query, headers, body, nonces).await {
            Ok(id) => id,
            Err(resp) => return resp,
        };
    match renew_if_not_revoked(state.db(), &peer_id, 30).await {
        Ok(Some((token, expires_at))) => {
            api_ok(json!({ "ok": true, "token": token, "expires_at": expires_at }))
        }
        Ok(None) => api_err("token has been revoked", "revoked", StatusCode::FORBIDDEN),
        Err(_) => api_err(
            "token store unavailable",
            "token_error",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    }
}

/// POST /ext/lan_cowork/api/peer/event — Bearer+signature authenticated. Accepts a
/// relayed peer event only if its type is on the RELAY_TYPES allowlist (M9); every
/// other type is 403.
/// Accepted events are relayed to the local SSE hub with the authenticated peer identity;
/// relay logging is throttled.
async fn peer_event(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if state.peer_registry.get().is_none() {
        return api_err(
            "LAN Cowork not enabled",
            "not_enabled",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    // Auth verifies the signature over the RAW body, so run it before parsing.
    let peer_id = match require_peer_auth(
        &*state,
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or(""),
        &headers,
        &body,
    )
    .await
    {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let req: PeerEventRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return api_err(
                &format!("body: {e}"),
                "invalid_json",
                StatusCode::BAD_REQUEST,
            )
        }
    };
    if req.event_type.is_empty() {
        return api_err(
            "event_type is required",
            "validation_error",
            StatusCode::BAD_REQUEST,
        );
    }
    if !peer_event_body_allowed(&req.event_type, body.len()) {
        return api_err(
            "event body too large",
            "payload_too_large",
            StatusCode::PAYLOAD_TOO_LARGE,
        );
    }
    // SF1: event_data must be a JSON object (Python `dict[str, Any]`) — reject a
    // non-object payload so the contract stays as tight as Python's before any future
    // local consumer relies on it.
    let Some(event_data_obj) = req.event_data.as_object() else {
        return api_err(
            "event_data must be an object",
            "validation_error",
            StatusCode::BAD_REQUEST,
        );
    };
    if !event_type_allowed(&req.event_type) {
        return api_err(
            "event type not allowed",
            "event_not_allowed",
            StatusCode::FORBIDDEN,
        );
    }
    let now = now_secs_f64();
    let has_local_consumer = state.sse_receiver_count() > 0;
    // Use the authenticated peer ID, never a body-supplied source_peer.
    let event = relayed_sse_event(
        req.event_type.clone(),
        event_data_obj.clone(),
        &peer_id,
        now,
    );
    state.sse_send(
        &event.source,
        &event.event_type,
        event.timestamp,
        event.data,
    );
    if has_local_consumer {
        // SF-1 flood gate: the relay log is throttled to <=1 INFO per window.
        static EVENT_RELAYED_THROTTLE: OnceLock<Mutex<EventRelayedWindow>> = OnceLock::new();
        let window = EVENT_RELAYED_THROTTLE.get_or_init(|| Mutex::new(EventRelayedWindow::new()));
        let summary = {
            let mut guard = window.lock().unwrap();
            note_relayed_event(&mut guard, now)
        };
        if let Some(count) = summary {
            tracing::info!(
                relayed = count,
                event_type = %req.event_type,
                source_peer = %peer_id,
                "lan_cowork: accepted peer events relayed to SSE (throttled summary)"
            );
        }
    } else {
        // Preserve first-event visibility without flooding when no SSE receiver exists.
        static EVENT_DROP_THROTTLE: OnceLock<Mutex<EventDropWindow>> = OnceLock::new();
        let window = EVENT_DROP_THROTTLE.get_or_init(|| Mutex::new(EventDropWindow::new()));
        let summary = {
            let mut guard = window.lock().unwrap();
            note_dropped_event(&mut guard, now)
        };
        if let Some(count) = summary {
            tracing::info!(
                dropped = count,
                event_type = %req.event_type,
                source_peer = %peer_id,
                "lan_cowork: accepted peer events (no local consumer; dropped, throttled summary)"
            );
        }
    }
    api_ok(json!({ "ok": true }))
}

/// POST /ext/lan_cowork/api/peer/heartbeat — Bearer+signature authenticated. Refreshes
/// the peer's runtime state. M6: `update_runtime` cannot signal an absent peer, so the
/// handler independently checks `registry.get(&peer_id)` and returns 403 for a peer that
/// authenticates (DB has its pubkey+token) but is not present in the in-memory registry.
async fn peer_heartbeat(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(registry) = state.peer_registry.get() else {
        return api_err(
            "LAN Cowork not enabled",
            "not_enabled",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    // Auth verifies the signature over the RAW body — run it before parsing (M4: full path).
    let peer_id = match require_peer_auth(
        &*state,
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or(""),
        &headers,
        &body,
    )
    .await
    {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let req: PeerHeartbeatRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return api_err(
                &format!("body: {e}"),
                "invalid_json",
                StatusCode::BAD_REQUEST,
            )
        }
    };
    // M6: update_runtime returns () and silently no-ops for an absent peer; check presence.
    if registry.get(&peer_id).is_none() {
        return api_err("unknown peer", "unknown_peer", StatusCode::FORBIDDEN);
    }
    registry.update_runtime(
        &peer_id,
        req.generating,
        req.queue_depth,
        req.bridges,
        req.inference_types,
        Some(now_secs_f64()),
        Some("online".to_string()),
    );
    api_ok(json!({ "ok": true }))
}

/// Router for the LAN Cowork inbound read routes. NOT merged until b-1b (dead-code).
pub fn routes() -> axum::Router<LanCoworkState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/ext/lan_cowork/api/peer/discover", get(peer_discover))
        .route("/ext/lan_cowork/api/peer/status", get(peer_status))
        .route("/ext/lan_cowork/api/peer/register", post(peer_register))
        .route(
            "/ext/lan_cowork/api/peer/token/renew",
            post(peer_token_renew),
        )
        .route(
            "/ext/lan_cowork/api/peer/event",
            post(peer_event).layer(axum::extract::DefaultBodyLimit::max(
                MAX_GENERATION_SUBMIT_BODY_BYTES,
            )),
        )
        .route("/ext/lan_cowork/api/peer/heartbeat", post(peer_heartbeat))
}

/// Router for the inbound read routes, gated by the `native_daemon` flag.
/// When disabled, returns an empty router — the discover/status routes are NOT
/// merged, so they 404 in production (dead-code discipline) until flag-day.
/// Merging an empty `Router::new()` is a no-op and cannot cause a matchit overlap.
pub fn inbound_routes(enabled: bool) -> axum::Router<LanCoworkState> {
    if enabled {
        routes()
    } else {
        axum::Router::new()
    }
}

/// Construct the peer registry at startup, fail-safe. Returns `None` — leaving the
/// slot empty so discover/status return 503 — when the daemon flag is off, when the
/// local identity is unprovisioned (no `ed25519_seed`; see the Known dependency note),
/// or when `load_all` fails (e.g. the standalone peers schema is absent). Never panics.
pub async fn build_peer_registry<S>(
    state: &S,
    native_daemon: bool,
) -> Option<std::sync::Arc<PeerRegistry>>
where
    S: std::ops::Deref,
    S::Target: LanCoworkHost,
{
    if !native_daemon {
        return None;
    }
    let seed: Vec<u8> = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT value FROM lan_cowork_identity WHERE key='ed25519_seed'",
    )
    .fetch_optional(state.db_read())
    .await
    .ok()
    .flatten()?; // no seed row -> None (fail-safe)
    let (local_peer_id, _ed_pub, _x_pub) = derive_self_identity(&seed)?;
    let registry = PeerRegistry::new(
        state.db().clone(), // write pool: load_all prunes (DELETE)
        std::time::Duration::from_secs(OFFLINE_TIMEOUT_SEC),
        local_peer_id,
    );
    let now = now_secs_f64();
    let now_i = now as i64;
    if let Err(e) = registry
        .load_all(now_i - HARD_PRUNE_SEC, now_i - SOFT_PRUNE_SEC, now)
        .await
    {
        tracing::warn!("lan_cowork: peer registry load_all failed; discover/status will 503: {e}");
        return None;
    }
    Some(std::sync::Arc::new(registry))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SharedState;

    #[test]
    fn note_relayed_event_first_visible_then_throttled_summary() {
        let mut w = EventRelayedWindow::new();
        // First event is immediately visible (NEG_INFINITY init).
        assert_eq!(note_relayed_event(&mut w, 1000.0), Some(1));
        // Within the window: accumulate, suppress.
        assert_eq!(note_relayed_event(&mut w, 1001.0), None);
        assert_eq!(note_relayed_event(&mut w, 1059.0), None);
        // At/after the boundary: flush the accumulated count (inclusive of this event).
        assert_eq!(note_relayed_event(&mut w, 1061.0), Some(3));
        // New window begins.
        assert_eq!(note_relayed_event(&mut w, 1062.0), None);
    }

    #[test]
    fn relayed_sse_event_uses_authenticated_peer_identity() {
        let event = relayed_sse_event(
            "generation.progress".to_string(),
            serde_json::json!({
                "_peer_relayed": false,
                "peer_id": "attacker",
                "pct": 10,
            })
            .as_object()
            .unwrap()
            .clone(),
            "authenticated-peer",
            123.0,
        );
        assert_eq!(event.event_type, "generation.progress");
        assert_eq!(event.timestamp, 123.0);
        assert_eq!(event.source, "peer:authenticated-peer");
        assert_eq!(event.data["_peer_relayed"], true);
        assert_eq!(event.data["peer_id"], "authenticated-peer");
        assert_eq!(event.data["pct"], 10);
    }

    #[test]
    fn note_dropped_event_first_visible_then_throttled_summary() {
        let mut w = EventDropWindow::new();
        // First event logs immediately with count 1 (first-event-visible).
        assert_eq!(note_dropped_event(&mut w, 1000.0), Some(1));
        // Subsequent events within the window are suppressed and accumulate.
        assert_eq!(note_dropped_event(&mut w, 1001.0), None);
        assert_eq!(note_dropped_event(&mut w, 1059.0), None);
        // The first event at/after the window boundary emits the accumulated count
        // (2 suppressed + the current triggering event = 3).
        assert_eq!(note_dropped_event(&mut w, 1061.0), Some(3));
        // Window resets again.
        assert_eq!(note_dropped_event(&mut w, 1062.0), None);
    }

    // MF-2: identity derivation is unit-tested as a PURE function (no DB / no
    // bound_port / no resolve_lan_ip), so it is deterministic and does not race
    // the process-global BOUND_PORT with sibling tests. The full
    // `assemble_local_peer_info` (which adds the LAN descriptor) is verified in
    // b-1b's HTTP integration test, not here.
    #[test]
    fn derive_self_identity_matches_seed() {
        let seed: Vec<u8> = (1u8..=32).collect();
        let (peer_id, pubkey, x25519) = derive_self_identity(&seed).expect("identity");
        let ed = openssl::pkey::PKey::private_key_from_raw_bytes(&seed, openssl::pkey::Id::ED25519)
            .unwrap()
            .raw_public_key()
            .unwrap();
        assert_eq!(peer_id, crate::routes::peer_identity::derive_peer_id(&ed));
        assert_eq!(pubkey.len(), 32);
        assert_eq!(x25519.len(), 32);
        // wrong-length seed -> None (ed25519 key construction fails).
        assert!(derive_self_identity(&[0u8; 10]).is_none());
    }

    use axum::body::to_bytes;
    use axum::extract::State;
    use serde_json::Value;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::schema::apply_standalone_schema;
    use crate::state::semantic_test_state_with;

    fn sample_peer(peer_id: String) -> super::PeerInfo {
        super::PeerInfo {
            peer_id,
            name: "n".into(),
            api_host: "10.0.0.2".into(),
            api_port: 8188,
            token: None,
            token_expires_at: None,
            token_issued_at: None,
            pubkey: None,
            x25519_pk: None,
            version: String::new(),
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

    async fn body_json(resp: super::Response) -> Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn discover_503_without_registry_and_lists_peers_excluding_self() {
        // no registry set -> 503 ("LAN Cowork not enabled").
        let bare = semantic_test_state_with(false, String::new()).await;
        let resp = super::peer_discover(State(LanCoworkState::from_shared(&bare)), None).await;
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        // with registry (pin_auth disabled -> session_ok=true): lists the one peer.
        let state = semantic_test_state_with(false, String::new()).await;
        apply_standalone_schema(&state.db).await.unwrap();
        let reg = super::super::lan_cowork_registry::PeerRegistry::new(
            state.db.clone(),
            Duration::from_secs(30),
            "self0".to_string(),
        );
        reg.upsert(sample_peer("bb".repeat(16))).await.unwrap();
        let lc = LanCoworkState::from_shared(&state);
        lc.peer_registry.set(Arc::new(reg)).ok();
        let resp = super::peer_discover(State(lc), None).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["peers"].as_array().unwrap().len(), 1);
    }

    // ── b-1b fixtures ──────────────────────────────────────────────────────────
    // Reuse b-1's exact constructor (`semantic_test_state_with`) and schema helper
    // (`apply_standalone_schema`); do NOT invent a new constructor.

    // Identity table ONLY (no peers family) — for the gate-off and peers-table-absent
    // cases. DDL mirrors migration 086's lan_cowork_identity (key TEXT PK, value BLOB).
    async fn test_state_no_registry() -> SharedState {
        let state = semantic_test_state_with(false, String::new()).await;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS lan_cowork_identity (key TEXT PRIMARY KEY, value BLOB)",
        )
        .execute(&state.db)
        .await
        .unwrap();
        state
    }

    // Identity + full standalone peers-family schema (migration 086), matching b-1's
    // discover test setup exactly.
    async fn test_state_with_peer_schema() -> SharedState {
        let state = semantic_test_state_with(false, String::new()).await;
        apply_standalone_schema(&state.db).await.unwrap();
        state
    }

    async fn seed_identity(state: &SharedState, seed: &[u8]) {
        sqlx::query("INSERT INTO lan_cowork_identity (key, value) VALUES ('ed25519_seed', ?1)")
            .bind(seed)
            .execute(&state.db)
            .await
            .unwrap();
    }

    // ── Task 1: route gate ─────────────────────────────────────────────────────
    #[tokio::test]
    async fn inbound_routes_gate_off_has_no_discover_route() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt; // oneshot
        let state = test_state_no_registry().await;
        let app = inbound_routes(false).with_state(LanCoworkState::from_shared(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ext/lan_cowork/api/peer/discover")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Gate off -> route not merged -> 404 (NOT 503, which would mean the route exists).
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Task 2: fail-safe registry construction ────────────────────────────────
    #[tokio::test]
    async fn build_registry_none_when_flag_off() {
        let state = test_state_no_registry().await;
        // Even with a seed present, flag off must yield None (dead-code discipline).
        seed_identity(&state, &[7u8; 32]).await;
        assert!(build_peer_registry(&state, false).await.is_none());
    }

    #[tokio::test]
    async fn build_registry_none_when_seed_missing() {
        let state = test_state_with_peer_schema().await; // schema present, no identity row
                                                         // native_daemon true but no seed -> None (fail-safe -> handlers 503). Pins the
                                                         // production-missing-identity path so the seeded happy path cannot hide it.
        assert!(build_peer_registry(&state, true).await.is_none());
    }

    #[tokio::test]
    async fn build_registry_some_when_seeded() {
        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        let reg = build_peer_registry(&state, true)
            .await
            .expect("seeded native_daemon must build a registry");
        // local_peer_id must equal the seed-derived peer_id (drives self-exclusion in discover).
        let expected = derive_self_identity(&[7u8; 32]).unwrap().0;
        assert_eq!(reg.local_peer_id(), expected);
    }

    #[tokio::test]
    async fn build_registry_none_when_peers_table_absent() {
        // Identity table + seed present, but peers table absent -> load_all Err -> None.
        let state = test_state_no_registry().await; // only lan_cowork_identity created
        seed_identity(&state, &[7u8; 32]).await;
        assert!(build_peer_registry(&state, true).await.is_none());
    }

    // ── Task 5: HTTP integration through Axum routing ──────────────────────────
    #[tokio::test]
    async fn discover_404_when_gate_off() {
        // (covered structurally by Task 1; kept here as the integration-suite entry)
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await;
        let app = inbound_routes(false).with_state(LanCoworkState::from_shared(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ext/lan_cowork/api/peer/discover")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn discover_503_when_gate_on_but_slot_empty() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await; // slot never set -> None
        let app = inbound_routes(true).with_state(LanCoworkState::from_shared(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ext/lan_cowork/api/peer/discover")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn discover_200_serves_peers_when_slot_set() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        let registry = build_peer_registry(&state, true).await.unwrap();
        let lc = LanCoworkState::from_shared(&state);
        let _ = lc.peer_registry.set(registry);
        let app = inbound_routes(true).with_state(lc);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ext/lan_cowork/api/peer/discover")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Body is the discover envelope; with no other peers loaded it lists an empty
        // peers array (self is excluded by local_peer_id). Assert it parses as ok=true.
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
    }

    // SF-2: prove the real production merge (lan_cowork routes + gated inbound routes)
    // constructs without a matchit overlap panic when the gate is ON. Construct-only —
    // no request driven, so it is non-flaky (no process-global state).
    #[tokio::test]
    async fn inbound_routes_merge_with_lan_cowork_does_not_panic() {
        let state = test_state_with_peer_schema().await;
        let _app: axum::Router<()> = crate::routes::lan_cowork::routes()
            .merge(inbound_routes(true))
            .with_state(LanCoworkState::from_shared(&state));
        // Reaching here means Router::merge did not panic on overlapping paths.
    }

    // SF-3: exercise assemble_local_peer_info end-to-end via the status handler using the
    // TEST_DESCRIPTOR seam (avoids the process-global bound_port double-set that made a
    // real-descriptor test unsafe in b-1). Serialized with test_guard(); cleaned up.
    #[tokio::test]
    async fn status_200_assembles_self_via_test_descriptor() {
        use super::super::lan_cowork_descriptor::{
            reset_client_state, LocalDescriptor, TEST_DESCRIPTOR,
        };
        use crate::routes::lan_cowork_descriptor::test_guard;
        let _guard = test_guard();
        reset_client_state();
        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        let registry = build_peer_registry(&state, true).await.unwrap();
        let lc = LanCoworkState::from_shared(&state);
        let _ = lc.peer_registry.set(registry);
        // Inject a fake descriptor so local_descriptor() succeeds without a bound port.
        *TEST_DESCRIPTOR.lock().unwrap_or_else(|e| e.into_inner()) = Some(Ok(LocalDescriptor {
            peer_id: "ignored".into(), // assemble uses the seed-derived peer_id, not this
            name: "self".into(),
            api_host: "10.0.0.1".into(),
            api_port: 8188,
            version: String::new(), // assemble uses state.version, not this
            bridges: vec![],
        }));
        let resp = super::peer_status(State(lc), None).await;
        reset_client_state();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    // ── b-2: register handler integration ──────────────────────────────────────
    #[tokio::test]
    async fn register_503_when_slot_empty() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await; // slot never set
        let app = inbound_routes(true).with_state(LanCoworkState::from_shared(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ext/lan_cowork/api/peer/register")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"host":"10.0.0.2","port":5000}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn register_400_on_ssrf_rejected_host() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        let registry = build_peer_registry(&state, true).await.unwrap();
        let lc = LanCoworkState::from_shared(&state);
        let _ = lc.peer_registry.set(registry);
        let app = inbound_routes(true).with_state(lc);
        // Public IP -> SSRF gate rejects -> 400, no outbound.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ext/lan_cowork/api/peer/register")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"host":"8.8.8.8","port":5000}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_upserts_peer_and_preserves_existing_token_m7() {
        use super::super::lan_cowork_descriptor::{
            reset_client_state, test_guard, TEST_ALLOW_LOOPBACK,
        };
        use std::sync::atomic::Ordering;
        let _guard = test_guard();
        reset_client_state();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);

        // Mock peer /status returning a public dict (no tokens) for peer_id "remote1".
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let pubkey_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode([9u8; 32])
        };
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/ext/lan_cowork/api/peer/status",
                axum::routing::get(move || {
                    let pk = pubkey_b64.clone();
                    async move {
                        axum::Json(serde_json::json!({
                            "ok": true,
                            "peer": {
                                "peer_id": "remote1", "name": "r",
                                "api_host": "0.0.0.0", "api_port": 1,
                                "pubkey": pk // base64 (MF-1: parser must base64-decode, not hex)
                            }
                        }))
                    }
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });

        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        let registry = build_peer_registry(&state, true).await.unwrap();
        // Pre-seed an existing token for remote1 to prove M7 restore (upsert is non-COALESCE).
        // `sample_peer` is b-1's in-module test constructor (lan_cowork_inbound_read.rs:274).
        let mut existing = sample_peer("remote1".to_string());
        existing.token = Some("SECRET".into());
        existing.token_issued_at = Some(123);
        registry.upsert(existing).await.unwrap();
        let registry_arc = registry.clone();
        let lc = LanCoworkState::from_shared(&state);
        let _ = lc.peer_registry.set(registry_arc.clone());

        let app = inbound_routes(true).with_state(lc);
        let body = format!(r#"{{"host":"127.0.0.1","port":{port}}}"#);
        let resp = {
            use axum::body::Body;
            use axum::http::Request;
            use tower::ServiceExt;
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ext/lan_cowork/api/peer/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
        };
        server.abort();
        reset_client_state();
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);

        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        // M7: the token pre-seeded in the registry survives (was NOT nulled by the
        // token-stripped /status upsert) and api_host is the validated register host.
        let stored = registry_arc.get("remote1").unwrap();
        assert_eq!(stored.token.as_deref(), Some("SECRET"));
        assert_eq!(stored.api_host, "127.0.0.1");
        // MF-1: the base64 pubkey from /status was decoded (NOT hex) and stored.
        assert_eq!(stored.pubkey, Some([9u8; 32]));
        // Response body is the public dict (no token).
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert!(v["peer"].get("token").is_none() || v["peer"]["token"].is_null());
    }

    // ── b-4: token renew handler slot gate ─────────────────────────────────────
    // SF-D: the mint paths (403/200) are component-tested in peer_transport.rs
    // (require_peer_renew_auth + renew_if_not_revoked); the router uses the
    // process-global nonce_store() (60s boot grace) so an in-test request 503s before
    // reaching renew. This pins the pre-auth slot-503 gate only.
    #[tokio::test]
    async fn token_renew_503_when_slot_empty() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await; // slot never set
        let app = inbound_routes(true).with_state(LanCoworkState::from_shared(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ext/lan_cowork/api/peer/token/renew")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    async fn seed_renew_peer(state: &SharedState, peer_id: &str, revoked_at: Option<i64>) {
        sqlx::query("INSERT INTO peers (peer_id, name, api_host, api_port, pubkey, created_at, updated_at) VALUES (?1,'n','10.0.0.2',5000,?2,0,0)")
        .bind(peer_id)
        .bind(event_test_pubkey())
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO peer_tokens (peer_id, token_hash, issued_at, expires_at, revoked_at, source) VALUES (?1,'oldhash',0,?2,?3,'pairing')")
        .bind(peer_id)
        .bind(test_now_secs() + 86_400)
        .bind(revoked_at)
        .execute(&state.db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn token_renew_inner_200_mints_token() {
        const PATH: &str = "/ext/lan_cowork/api/peer/token/renew";
        let state = test_state_with_peer_schema().await;
        seed_renew_peer(&state, "p1", None).await;
        let headers = crate::auth::peer_transport::sign_headers(
            &EVENT_TEST_SEED,
            "POST",
            PATH,
            "",
            b"",
            test_now_secs(),
            "renew-active",
            "p1",
        );
        let nonces = PeerNonceStore::with_grace(0);
        let resp =
            super::peer_token_renew_inner(&*state, "POST", PATH, "", &headers, b"", &nonces).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["ok"], true);
        assert!(!body["token"].as_str().unwrap_or_default().is_empty());
        assert!(body.get("expires_at").is_some());
    }

    #[tokio::test]
    async fn token_renew_inner_403_for_revoked_peer() {
        const PATH: &str = "/ext/lan_cowork/api/peer/token/renew";
        let state = test_state_with_peer_schema().await;
        seed_renew_peer(&state, "p1", Some(999)).await;
        let headers = crate::auth::peer_transport::sign_headers(
            &EVENT_TEST_SEED,
            "POST",
            PATH,
            "",
            b"",
            test_now_secs(),
            "renew-revoked",
            "p1",
        );
        let nonces = PeerNonceStore::with_grace(0);
        let resp =
            super::peer_token_renew_inner(&*state, "POST", PATH, "", &headers, b"", &nonces).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_json(resp).await["code"], "revoked");
    }

    // SF-1: a hostile /status response (peer_id missing, non-string array elements,
    // invalid base64 key) must NOT panic the handler — it returns 502, not 500/crash.
    #[tokio::test]
    async fn register_502_on_hostile_status_response_without_panic() {
        use super::super::lan_cowork_descriptor::{
            reset_client_state, test_guard, TEST_ALLOW_LOOPBACK,
        };
        use std::sync::atomic::Ordering;
        let _guard = test_guard();
        reset_client_state();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/ext/lan_cowork/api/peer/status",
                axum::routing::get(|| async {
                    // No peer_id, malformed arrays, bad base64 key — must parse to None.
                    axum::Json(serde_json::json!({
                        "ok": true,
                        "peer": {"name": "x", "bridges": [1, null], "pubkey": "!!bad!!"}
                    }))
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });

        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        let registry = build_peer_registry(&state, true).await.unwrap();
        let lc = LanCoworkState::from_shared(&state);
        let _ = lc.peer_registry.set(registry);
        let app = inbound_routes(true).with_state(lc);
        let body = format!(r#"{{"host":"127.0.0.1","port":{port}}}"#);
        let resp = {
            use axum::body::Body;
            use axum::http::Request;
            use tower::ServiceExt;
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ext/lan_cowork/api/peer/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
        };
        server.abort();
        reset_client_state();
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
        // peer_id missing -> peer_from_public_dict None -> 502 (never panic / 500).
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
    }

    // ── b-5: event handler integration (allowlist 200/403, auth, slot 503) ──────
    // Self-contained crypto: derive an ed25519 keypair from a fixed seed (same openssl
    // call `derive_self_identity` uses), so these tests do NOT depend on peer_transport's
    // test-private `vectors()`/`now_secs()`. `build_canonical_message`, `sign_canonical`,
    // and `hash_token` are `pub`; the timestamp is computed inline from a current clock
    // (verify_request_signature requires |now - ts| <= TS_TOLERANCE_SECS).
    const EVENT_TEST_SEED: [u8; 32] = [3u8; 32]; // distinct from identity's [7;32]

    fn event_test_pubkey() -> Vec<u8> {
        openssl::pkey::PKey::private_key_from_raw_bytes(
            &EVENT_TEST_SEED,
            openssl::pkey::Id::ED25519,
        )
        .unwrap()
        .raw_public_key()
        .unwrap()
    }

    fn test_now_secs() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    // Seed peers.pubkey (matching EVENT_TEST_SEED) + an active Bearer token; return the
    // raw token to send as `Authorization: Bearer`. Reuses b-4's exact peers column list
    // (created_at/updated_at = 0) and peer_tokens column list.
    async fn seed_event_peer(state: &SharedState, peer_id: &str) -> String {
        use crate::auth::peer_transport::hash_token;
        sqlx::query(
            "INSERT INTO peers (peer_id, name, api_host, api_port, pubkey, created_at, updated_at) \
             VALUES (?1,'n','10.0.0.2',5000,?2,0,0)",
        )
        .bind(peer_id)
        .bind(event_test_pubkey())
        .execute(&state.db)
        .await
        .unwrap();
        let raw_token = "test-bearer-token";
        sqlx::query(
            "INSERT INTO peer_tokens (peer_id, token_hash, issued_at, expires_at, revoked_at, source) \
             VALUES (?1,?2,0,?3,NULL,'pairing')",
        )
        .bind(peer_id)
        .bind(hash_token(raw_token))
        .bind(test_now_secs() + 86_400)
        .execute(&state.db)
        .await
        .unwrap();
        raw_token.to_string()
    }

    fn signed_event_request(
        peer_id: &str,
        raw_token: &str,
        body: &str,
    ) -> axum::http::Request<axum::body::Body> {
        use crate::auth::peer_transport::{build_canonical_message, sign_canonical};
        use base64::Engine as _;
        let ts = test_now_secs().to_string(); // current ts — within verify_request_signature's window
        let path = "/ext/lan_cowork/api/peer/event";
        let canonical = build_canonical_message("POST", path, "", &ts, body.as_bytes());
        let sig = base64::engine::general_purpose::URL_SAFE
            .encode(sign_canonical(&EVENT_TEST_SEED, &canonical).unwrap());
        axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("X-Peer-Id", peer_id)
            .header("X-Peer-Ts", ts)
            .header("X-Peer-Sig", sig)
            .header("Authorization", format!("Bearer {raw_token}"))
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn event_503_when_slot_empty() {
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await; // slot never set
        let app = inbound_routes(true).with_state(LanCoworkState::from_shared(&state));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/ext/lan_cowork/api/peer/event")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn event_200_for_allowlisted_type() {
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        let registry = build_peer_registry(&state, true).await.unwrap();
        let raw_token = seed_event_peer(&state, "p1").await;
        let lc = LanCoworkState::from_shared(&state);
        let _ = lc.peer_registry.set(registry);
        let mut rx = state.sse_hub.subscribe();
        let app = inbound_routes(true).with_state(lc);
        let req = signed_event_request(
            "p1",
            &raw_token,
            r#"{"event_type":"generation.progress","event_data":{"pct":10}}"#,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let event = rx.try_recv().expect("SSE event should be sent");
        assert_eq!(event.event_type, "generation.progress");
        assert_eq!(event.data["_peer_relayed"], true);
        assert_eq!(event.data["peer_id"], "p1");
        assert_eq!(event.source, "peer:p1");
    }

    fn event_body_at_len(event_type: &str, len: usize) -> String {
        let prefix = format!(r#"{{"event_type":"{event_type}","event_data":{{"payload":""#);
        let suffix = r#""}}"#;
        format!(
            "{prefix}{}{suffix}",
            "x".repeat(len - prefix.len() - suffix.len())
        )
    }

    #[tokio::test]
    async fn event_body_size_guard_applies_type_specific_limits_without_sse() {
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        let registry = build_peer_registry(&state, true).await.unwrap();
        let raw_token = seed_event_peer(&state, "p1").await;
        let lc = LanCoworkState::from_shared(&state);
        let _ = lc.peer_registry.set(registry);
        let mut rx = state.sse_hub.subscribe();
        let app = inbound_routes(true).with_state(lc);
        let at_limit = event_body_at_len("generation.submit", MAX_GENERATION_SUBMIT_BODY_BYTES);
        assert_eq!(at_limit.len(), MAX_GENERATION_SUBMIT_BODY_BYTES);
        let resp = app
            .clone()
            .oneshot(signed_event_request("p1", &raw_token, &at_limit))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        rx.try_recv().expect("limit-sized event should be sent");

        let over_submit_limit =
            event_body_at_len("generation.submit", MAX_GENERATION_SUBMIT_BODY_BYTES + 1);
        assert_eq!(
            over_submit_limit.len(),
            MAX_GENERATION_SUBMIT_BODY_BYTES + 1
        );
        let resp = app
            .clone()
            .oneshot(signed_event_request("p1", &raw_token, &over_submit_limit))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            rx.try_recv().is_err(),
            "over-limit submit event must not reach SSE"
        );

        let under_limit =
            event_body_at_len("generation.progress", MAX_SMALL_PEER_EVENT_BODY_BYTES - 1);
        assert_eq!(under_limit.len(), MAX_SMALL_PEER_EVENT_BODY_BYTES - 1);
        let resp = app
            .clone()
            .oneshot(signed_event_request("p1", &raw_token, &under_limit))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        rx.try_recv()
            .expect("under-limit non-submit event should be sent");

        let over_small_limit =
            event_body_at_len("generation.progress", MAX_SMALL_PEER_EVENT_BODY_BYTES + 1);
        assert_eq!(over_small_limit.len(), MAX_SMALL_PEER_EVENT_BODY_BYTES + 1);
        let resp = app
            .oneshot(signed_event_request("p1", &raw_token, &over_small_limit))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        assert!(rx.try_recv().is_err(), "oversized event must not reach SSE");
    }

    #[test]
    fn peer_event_body_limit_matches_relay_contract() {
        assert_eq!(
            peer_event_body_limit("generation.submit"),
            MAX_GENERATION_SUBMIT_BODY_BYTES
        );
        assert_eq!(
            peer_event_body_limit("generation.progress"),
            MAX_SMALL_PEER_EVENT_BODY_BYTES
        );
    }

    #[tokio::test]
    async fn event_403_for_non_allowlisted_type() {
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        let registry = build_peer_registry(&state, true).await.unwrap();
        let raw_token = seed_event_peer(&state, "p1").await;
        let lc = LanCoworkState::from_shared(&state);
        let _ = lc.peer_registry.set(registry);
        let app = inbound_routes(true).with_state(lc);
        let req = signed_event_request("p1", &raw_token, r#"{"event_type":"generation.evil"}"#);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN); // M9 allowlist
    }

    #[tokio::test]
    async fn event_401_or_403_without_valid_auth() {
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        let registry = build_peer_registry(&state, true).await.unwrap();
        let lc = LanCoworkState::from_shared(&state);
        let _ = lc.peer_registry.set(registry); // no peer seeded -> unknown
        let app = inbound_routes(true).with_state(lc);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/ext/lan_cowork/api/peer/event")
                    .header("content-type", "application/json")
                    .header("X-Peer-Id", "nobody")
                    .body(axum::body::Body::from(
                        r#"{"event_type":"sync.file_changed"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        // unknown peer (no pubkey) -> require_peer_auth 403; a missing sig also fails auth.
        assert!(matches!(
            resp.status(),
            axum::http::StatusCode::FORBIDDEN | axum::http::StatusCode::UNAUTHORIZED
        ));
    }

    // ── b-3: heartbeat handler integration (M6 200/403, slot 503, auth) ──────────
    // Reuses b-5's EVENT_TEST_SEED / event_test_pubkey / test_now_secs / seed_event_peer
    // and b-1's sample_peer. heartbeat is NOT nonce-required, so the Bearer+signature
    // happy path is fully router-testable.
    fn signed_heartbeat_request(
        peer_id: &str,
        raw_token: &str,
        body: &str,
    ) -> axum::http::Request<axum::body::Body> {
        use crate::auth::peer_transport::{build_canonical_message, sign_canonical};
        use base64::Engine as _;
        let ts = test_now_secs().to_string();
        let path = "/ext/lan_cowork/api/peer/heartbeat";
        let canonical = build_canonical_message("POST", path, "", &ts, body.as_bytes());
        let sig = base64::engine::general_purpose::URL_SAFE
            .encode(sign_canonical(&EVENT_TEST_SEED, &canonical).unwrap());
        axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("X-Peer-Id", peer_id)
            .header("X-Peer-Ts", ts)
            .header("X-Peer-Sig", sig)
            .header("Authorization", format!("Bearer {raw_token}"))
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn heartbeat_503_when_slot_empty() {
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await; // slot never set
        let app = inbound_routes(true).with_state(LanCoworkState::from_shared(&state));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/ext/lan_cowork/api/peer/heartbeat")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn heartbeat_403_when_peer_authenticates_but_absent_from_registry() {
        // M6: peer is in the DB (auth passes: pubkey + Bearer token) but NOT in the
        // in-memory registry -> update_runtime would silently no-op -> handler must 403.
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        let registry = build_peer_registry(&state, true).await.unwrap();
        let raw_token = seed_event_peer(&state, "p1").await; // DB peer, NOT registry-hydrated
        let lc = LanCoworkState::from_shared(&state);
        let _ = lc.peer_registry.set(registry);
        let app = inbound_routes(true).with_state(lc);
        let req = signed_heartbeat_request("p1", &raw_token, r#"{"generating":true}"#);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN); // M6
    }

    #[tokio::test]
    async fn heartbeat_200_updates_runtime_when_peer_present() {
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        // `build_peer_registry` returns `Arc<PeerRegistry>` (b-2 M7 template). Use it directly:
        let registry = build_peer_registry(&state, true).await.unwrap();
        let raw_token = seed_event_peer(&state, "p1").await;
        // Put the peer in the registry (as b-6 hydration would after pairing).
        registry
            .upsert(sample_peer("p1".to_string()))
            .await
            .unwrap();
        let lc = LanCoworkState::from_shared(&state);
        let _ = lc.peer_registry.set(registry.clone());
        let app = inbound_routes(true).with_state(lc);
        let req =
            signed_heartbeat_request("p1", &raw_token, r#"{"generating":true,"queue_depth":5}"#);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        // update_runtime reflected in the registry (read via the same Arc).
        let updated = registry.get("p1").unwrap();
        assert!(updated.generating);
        assert_eq!(updated.queue_depth, 5);
        assert_eq!(updated.status, "online");
    }

    #[tokio::test]
    async fn heartbeat_401_or_403_without_valid_auth() {
        use tower::ServiceExt;
        let state = test_state_with_peer_schema().await;
        seed_identity(&state, &[7u8; 32]).await;
        let registry = build_peer_registry(&state, true).await.unwrap();
        let lc = LanCoworkState::from_shared(&state);
        let _ = lc.peer_registry.set(registry); // no peer seeded -> unknown at auth
        let app = inbound_routes(true).with_state(lc);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/ext/lan_cowork/api/peer/heartbeat")
                    .header("content-type", "application/json")
                    .header("X-Peer-Id", "nobody")
                    .body(axum::body::Body::from(r#"{"generating":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(
            resp.status(),
            axum::http::StatusCode::FORBIDDEN | axum::http::StatusCode::UNAUTHORIZED
        ));
    }
}
