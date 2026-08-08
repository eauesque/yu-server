//! LAN Cowork responder-side pairing — Rust port of
//! `extensions/builtin_lan_cowork/routes/pair_api.py` + `core_impl/pairing_service.py`.
//!
//! Increment E2. All five responder routes move together and cannot be split:
//! the plaintext PIN produced by `approve` lives **only in process memory** (the
//! DB stores just its scrypt hash, which cannot be reversed), so `approve` and
//! `verify` must run in the same process. Migrating a subset would break every
//! pairing (design 2026-07-19 Increment E, MF-E8).
//!
//! Crypto primitives come from [`crate::auth::peer_pairing_crypto`] (Increment E1),
//! already pinned byte-for-byte against Python.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use rand::Rng;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::peer_pairing_crypto as pc;
use crate::routes::lan_cowork_host::{LanCoworkHost, LanCoworkState, PeerSourceIp};

// Limits — mirrored 1:1 from pairing_service.py / pair_api.py (MF-E9).
const RATE_LIMIT_PER_MIN: usize = 10; // POST /pair/request, per source IP
const PENDING_CAP_PER_IP: usize = 3; // concurrent pending+approved, per source IP
const VERIFY_RATE_PER_MIN: usize = 30; // POST /pair/verify, per source IP
const MAX_VERIFY_ATTEMPTS: i64 = 5;
const PIN_TTL_SECONDS: i64 = 300;
const PENDING_TTL_SECONDS: i64 = 600;
const CLEANUP_AFTER_SECONDS: i64 = 86_400;
const TOKEN_TTL_DAYS: i64 = 30;
const RATE_WINDOW_SECONDS: f64 = 60.0;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn api_ok(data: Value) -> Response {
    Json(data).into_response()
}

fn api_ok_status(status: StatusCode, data: Value) -> Response {
    (status, Json(data)).into_response()
}

fn api_err(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"ok": false, "error": message}))).into_response()
}

async fn session_guard(
    state: &dyn LanCoworkHost,
    session: Option<&tower_sessions::Session>,
) -> Option<Response> {
    state.require_session(session).await
}

// ── process-local pairing state ───────────────────────────────────────────────

/// In-memory state that has no DB equivalent.
///
/// A module-level static (rather than a core-state field) keeps the nine
/// existing `AppState` literals untouched; the lifetime is the process, which is
/// exactly the lifetime Python gives this state. Restarting drops in-flight
/// pairings, which is the documented fail-closed behaviour.
#[derive(Default)]
struct PairingState {
    /// request_id → plaintext PIN. The DB holds only the scrypt hash.
    approved_pins: HashMap<String, String>,
    /// source_ip → recent `/pair/request` timestamps (10/min window).
    ip_requests: HashMap<String, VecDeque<f64>>,
    /// source_ip → request_ids currently pending/approved (cap 3).
    ip_pending: HashMap<String, HashSet<String>>,
    /// source_ip → recent `/pair/verify` timestamps (30/min window).
    verify_log: HashMap<String, VecDeque<f64>>,
}

fn pairing_state() -> &'static std::sync::Mutex<PairingState> {
    static STATE: std::sync::OnceLock<std::sync::Mutex<PairingState>> = std::sync::OnceLock::new();
    STATE.get_or_init(|| std::sync::Mutex::new(PairingState::default()))
}

fn prune_window(log: &mut VecDeque<f64>, now: f64) {
    while log.front().is_some_and(|t| now - *t > RATE_WINDOW_SECONDS) {
        log.pop_front();
    }
}

/// 10 requests / 60s per source IP.
fn rate_limit_ok(ip: &str) -> bool {
    let mut st = pairing_state().lock().expect("pairing state poisoned");
    let now = now_f64();
    let log = st.ip_requests.entry(ip.to_string()).or_default();
    prune_window(log, now);
    if log.len() >= RATE_LIMIT_PER_MIN {
        return false;
    }
    log.push_back(now);
    true
}

/// 30 verifies / 60s per source IP.
fn verify_rate_ok(ip: &str) -> bool {
    let mut st = pairing_state().lock().expect("pairing state poisoned");
    let now = now_f64();
    let log = st.verify_log.entry(ip.to_string()).or_default();
    prune_window(log, now);
    if log.len() >= VERIFY_RATE_PER_MIN {
        return false;
    }
    log.push_back(now);
    true
}

fn pending_cap_ok(ip: &str, active_ids: &HashSet<String>) -> bool {
    let mut st = pairing_state().lock().expect("pairing state poisoned");
    let entry = st.ip_pending.entry(ip.to_string()).or_default();
    // The DB is authoritative for which requests are still open; memory only
    // caches it, so re-seed from the caller's query before deciding.
    *entry = active_ids.clone();
    entry.len() < PENDING_CAP_PER_IP
}

fn track_pending(ip: &str, request_id: &str) {
    let mut st = pairing_state().lock().expect("pairing state poisoned");
    st.ip_pending
        .entry(ip.to_string())
        .or_default()
        .insert(request_id.to_string());
}

fn untrack_pending(request_id: &str) {
    let mut st = pairing_state().lock().expect("pairing state poisoned");
    for ids in st.ip_pending.values_mut() {
        ids.remove(request_id);
    }
}

fn store_pin(request_id: &str, pin: &str) {
    let mut st = pairing_state().lock().expect("pairing state poisoned");
    st.approved_pins
        .insert(request_id.to_string(), pin.to_string());
}

fn take_pin(request_id: &str) -> Option<String> {
    let st = pairing_state().lock().expect("pairing state poisoned");
    st.approved_pins.get(request_id).cloned()
}

fn drop_pin(request_id: &str) {
    let mut st = pairing_state().lock().expect("pairing state poisoned");
    st.approved_pins.remove(request_id);
}

/// 8-digit zero-padded PIN, matching `f"{secrets.randbelow(100_000_000):08d}"`.
fn generate_pin() -> String {
    let n: u32 = rand::rng().random_range(0..100_000_000);
    format!("{n:08}")
}

// ── local identity ────────────────────────────────────────────────────────────

/// The local node's Ed25519 + X25519 public keys, echoed back on verify so the
/// initiator can pin us.
pub(crate) async fn local_identity(state: &dyn LanCoworkHost) -> Option<(Vec<u8>, Vec<u8>)> {
    let seed = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT value FROM lan_cowork_identity WHERE key='ed25519_seed'",
    )
    .fetch_optional(state.db_read())
    .await
    .ok()
    .flatten()?;
    let ed = openssl::pkey::PKey::private_key_from_raw_bytes(&seed, openssl::pkey::Id::ED25519)
        .ok()?
        .raw_public_key()
        .ok()?;
    let x = pc::x25519_pubkey_from_ed25519_seed(&seed)?;
    Some((ed, x))
}

// ── POST /pair/request ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairRequestReq {
    peer_id: String,
    host: String,
    port: i64,
    pubkey: String,
    #[serde(default)]
    x25519_pk: Option<String>,
    commit: String,
}

async fn pair_request(
    State(state): State<LanCoworkState>,
    client_ip: Option<Extension<PeerSourceIp>>,
    Json(req): Json<PairRequestReq>,
) -> Response {
    let source_ip = client_ip
        .map(|Extension(ip)| ip.0)
        .unwrap_or_else(|| "unknown".to_string());

    if req.peer_id.is_empty() || req.host.is_empty() || !(1..=65535).contains(&req.port) {
        return api_err(StatusCode::BAD_REQUEST, "invalid pairing fields");
    }
    let (Some(pubkey), Some(commit)) = (b64_decode(&req.pubkey), b64_decode(&req.commit)) else {
        return api_err(StatusCode::BAD_REQUEST, "invalid pairing fields");
    };
    let x25519_pk = match req.x25519_pk.as_deref() {
        None => None,
        Some(s) => match b64_decode(s) {
            Some(v) => Some(v),
            None => return api_err(StatusCode::BAD_REQUEST, "invalid pairing fields"),
        },
    };
    if let Some(x) = &x25519_pk {
        if x.len() != 32 || pc::is_low_order_x25519(x) {
            return api_err(StatusCode::BAD_REQUEST, "invalid x25519_pk");
        }
    }
    // peer_id must be the fingerprint of the presented key, else a peer could
    // claim someone else's identity.
    if pubkey.len() != 32 || crate::routes::peer_identity::derive_peer_id(&pubkey) != req.peer_id {
        return api_err(StatusCode::BAD_REQUEST, "peer_id does not match pubkey");
    }

    if !rate_limit_ok(&source_ip) {
        return api_err(StatusCode::TOO_MANY_REQUESTS, "rate limit");
    }

    // Retire any earlier open request from the same peer before opening a new one
    // (Python `_expire_prior_for_peer`). A peer that retries after a lost SAS or a
    // timeout would otherwise pile up rows that consume its own pending-cap slots
    // and leave the operator with several "approve" actions for one identity.
    // Done before the cap check so a retry is not blocked by its own leftovers.
    let prior: Vec<String> = sqlx::query_scalar(
        "SELECT request_id FROM peer_pairing_requests \
         WHERE peer_id = ?1 AND status IN ('pending','approved')",
    )
    .bind(&req.peer_id)
    .fetch_all(state.db_read())
    .await
    .unwrap_or_default();
    if !prior.is_empty() {
        let _ = sqlx::query(
            "UPDATE peer_pairing_requests SET status='expired', pin_hash=NULL, updated_at=?1 \
             WHERE peer_id = ?2 AND status IN ('pending','approved')",
        )
        .bind(now_secs())
        .bind(&req.peer_id)
        .execute(state.db())
        .await;
        for request_id in &prior {
            drop_pin(request_id);
            untrack_pending(request_id);
        }
    }

    // Pending cap is decided from the DB, which is authoritative.
    let active: Vec<String> = match sqlx::query_scalar(
        "SELECT request_id FROM peer_pairing_requests \
         WHERE source_ip = ?1 AND status IN ('pending','approved')",
    )
    .bind(&source_ip)
    .fetch_all(state.db_read())
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("pair_request pending query failed: {e}");
            return api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    if !pending_cap_ok(&source_ip, &active.into_iter().collect()) {
        return api_err(StatusCode::TOO_MANY_REQUESTS, "pending cap exceeded");
    }

    // SAS binds both peers' identities; it degrades to the legacy 3-input form
    // when either side lacks an X25519 key (MF-E4).
    let request_id = uuid::Uuid::new_v4().to_string();
    let sas = match local_identity(&*state).await {
        Some((server_ed, server_x)) => match (&x25519_pk, server_x.len()) {
            (Some(client_x), 32) => {
                pc::compute_sas_v2(&pubkey, client_x, &server_ed, &server_x, &request_id)
            }
            _ => pc::compute_sas_legacy(&pubkey, &server_ed, &request_id),
        },
        None => String::new(),
    };

    let now = now_secs();
    let inserted = sqlx::query(
        "INSERT INTO peer_pairing_requests \
         (request_id, peer_id, host, port, status, created_at, updated_at, \
          pubkey, x25519_pk, commit_hash, sas, source_ip, verify_attempts) \
         VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?5, ?6, ?7, ?8, ?9, ?10, 0)",
    )
    .bind(&request_id)
    .bind(&req.peer_id)
    .bind(&req.host)
    .bind(req.port)
    .bind(now)
    .bind(&pubkey)
    .bind(&x25519_pk)
    .bind(&commit)
    .bind(&sas)
    .bind(&source_ip)
    .execute(state.db())
    .await;
    if let Err(e) = inserted {
        tracing::warn!("pair_request insert failed: {e}");
        return api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }
    track_pending(&source_ip, &request_id);

    state.sse_send(
        "lan_cowork",
        "peer.pairing_request",
        now as f64,
        json!({"request_id": request_id, "peer_id": req.peer_id, "host": req.host}),
    );

    api_ok_status(
        StatusCode::ACCEPTED,
        json!({"ok": true, "request_id": request_id, "sas": sas}),
    )
}

// ── POST /pair/approve, /pair/reject ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestIdReq {
    request_id: String,
}

async fn pair_approve(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    Json(req): Json<RequestIdReq>,
) -> Response {
    if let Some(r) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return r;
    }
    let status: Option<String> =
        match sqlx::query_scalar("SELECT status FROM peer_pairing_requests WHERE request_id = ?1")
            .bind(&req.request_id)
            .fetch_optional(state.db_read())
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("pair_approve status query failed: {e}");
                return api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
            }
        };
    match status.as_deref() {
        Some("pending") => {}
        Some(other) => {
            return api_err(StatusCode::CONFLICT, &format!("request is {other}"));
        }
        None => return api_err(StatusCode::CONFLICT, "unknown request"),
    }

    let pin = generate_pin();
    let pin_hash = pc::hash_pairing_pin(&pin);
    let now = now_secs();
    let updated = sqlx::query(
        "UPDATE peer_pairing_requests \
         SET status='approved', pin_hash=?1, pin_expires_at=?2, updated_at=?3 \
         WHERE request_id=?4 AND status='pending'",
    )
    .bind(&pin_hash)
    .bind(now + PIN_TTL_SECONDS)
    .bind(now)
    .bind(&req.request_id)
    .execute(state.db())
    .await;
    match updated {
        Ok(r) if r.rows_affected() == 0 => {
            return api_err(StatusCode::CONFLICT, "request is not pending")
        }
        Err(e) => {
            tracing::warn!("pair_approve update failed: {e}");
            return api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
        Ok(_) => {}
    }
    store_pin(&req.request_id, &pin);

    // The PIN is returned only here, to the authenticated operator, who reads it
    // out of band to the peer. It is never sent to the requesting peer.
    api_ok(json!({"ok": true, "pin": pin, "expires_in": PIN_TTL_SECONDS}))
}

async fn pair_reject(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
    Json(req): Json<RequestIdReq>,
) -> Response {
    if let Some(r) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return r;
    }
    // Only an open request can be rejected — never overwrite a request that has
    // already completed (its token is live) or expired.
    if let Err(e) = sqlx::query(
        "UPDATE peer_pairing_requests SET status='rejected', pin_hash=NULL, updated_at=?1 \
         WHERE request_id=?2 AND status IN ('pending','approved')",
    )
    .bind(now_secs())
    .bind(&req.request_id)
    .execute(state.db())
    .await
    {
        tracing::warn!("pair_reject update failed: {e}");
        return api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }
    drop_pin(&req.request_id);
    untrack_pending(&req.request_id);
    api_ok(json!({"ok": true}))
}

// ── POST /pair/verify ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairVerifyReq {
    request_id: String,
    encrypted_bundle: String,
}

#[derive(sqlx::FromRow)]
struct PairingRow {
    peer_id: String,
    host: String,
    port: i64,
    status: String,
    pin_expires_at: Option<i64>,
    verify_attempts: i64,
    x25519_pk: Option<Vec<u8>>,
    commit_hash: Option<Vec<u8>>,
    source_ip: Option<String>,
}

async fn pair_verify(
    State(state): State<LanCoworkState>,
    client_ip: Option<Extension<PeerSourceIp>>,
    Json(req): Json<PairVerifyReq>,
) -> Response {
    let source_ip = client_ip
        .map(|Extension(ip)| ip.0)
        .unwrap_or_else(|| "unknown".to_string());
    if !verify_rate_ok(&source_ip) {
        return api_err(StatusCode::TOO_MANY_REQUESTS, "rate limit");
    }
    let Some(bundle) = b64_decode(&req.encrypted_bundle) else {
        return api_err(StatusCode::BAD_REQUEST, "invalid bundle");
    };

    let row: Option<PairingRow> = match sqlx::query_as(
        "SELECT peer_id, host, port, status, pin_expires_at, verify_attempts, x25519_pk, \
                commit_hash, source_ip \
         FROM peer_pairing_requests WHERE request_id = ?1",
    )
    .bind(&req.request_id)
    .fetch_optional(state.db_read())
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("pair_verify row query failed: {e}");
            return api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    let Some(row) = row else {
        return api_err(StatusCode::UNAUTHORIZED, "pairing verification failed");
    };
    if row.status == "completed" {
        return api_err(StatusCode::GONE, "already completed");
    }
    if row.status != "approved" {
        return api_err(StatusCode::UNAUTHORIZED, "pairing verification failed");
    }
    // A request is bound to the address that created it: only that peer may
    // complete it. Without this, anyone who learns a request_id (it travels the
    // LAN alongside the SAS) could attempt verification from elsewhere.
    if row
        .source_ip
        .as_deref()
        .is_some_and(|stored| stored != source_ip)
    {
        return api_err(StatusCode::UNAUTHORIZED, "pairing verification failed");
    }
    let now = now_secs();
    if row.pin_expires_at.is_some_and(|exp| now > exp) {
        expire_request(&*state, &req.request_id, row.verify_attempts).await;
        return api_err(StatusCode::UNAUTHORIZED, "pairing verification failed");
    }
    // The PIN is memory-only; a restart between approve and verify loses it and
    // the pairing must fail closed rather than fall back to anything weaker.
    let Some(pin) = take_pin(&req.request_id) else {
        return api_err(StatusCode::UNAUTHORIZED, "pairing verification failed");
    };
    let Some(commit) = row.commit_hash.clone() else {
        return api_err(StatusCode::UNAUTHORIZED, "pairing verification failed");
    };

    // n=2^17 scrypt: offloaded and concurrency-capped so a burst cannot pin the
    // runtime or allocate N x 128 MiB (MF-E6).
    let Some(key) = pc::pin_kdf_async(pin, req.request_id.clone()).await else {
        return api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    let material = pc::verify_bundle(
        &key,
        &req.request_id,
        &commit,
        &bundle,
        row.x25519_pk.as_deref(),
    );
    let Some(material) = material else {
        let attempts = row.verify_attempts + 1;
        if attempts >= MAX_VERIFY_ATTEMPTS {
            expire_request(&*state, &req.request_id, attempts).await;
        } else {
            let _ = sqlx::query(
                "UPDATE peer_pairing_requests SET verify_attempts=?1, updated_at=?2 WHERE request_id=?3",
            )
            .bind(attempts)
            .bind(now)
            .bind(&req.request_id)
            .execute(state.db())
            .await;
        }
        return api_err(StatusCode::UNAUTHORIZED, "pairing verification failed");
    };

    // MF-E10: token issuance, request completion and the peers upsert all land in
    // ONE transaction. Python commits the first two and writes peers afterwards,
    // leaving a window where a token is valid but `peers.pubkey` is absent — which
    // `require_peer_auth` would reject as "peer not paired".
    let raw_token = generate_token();
    let token_hash = crate::auth::peer_transport::hash_token(&raw_token);
    let expires_at = now + TOKEN_TTL_DAYS * 86_400;

    let mut tx = match state.db().begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!("pair_verify begin failed: {e}");
            return api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    let completed = async {
        sqlx::query(
            "INSERT INTO peer_tokens (peer_id, token_hash, issued_at, expires_at, revoked_at, source, note) \
             VALUES (?1, ?2, ?3, ?4, NULL, 'pairing', NULL) \
             ON CONFLICT(peer_id) DO UPDATE SET token_hash=excluded.token_hash, \
               issued_at=excluded.issued_at, expires_at=excluded.expires_at, \
               revoked_at=NULL, source=excluded.source",
        )
        .bind(&row.peer_id)
        .bind(&token_hash)
        .bind(now)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE peer_pairing_requests SET status='completed', pin_hash=NULL, updated_at=?1 \
             WHERE request_id=?2",
        )
        .bind(now)
        .bind(&req.request_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO peers (peer_id, name, api_host, api_port, pubkey, x25519_pk, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7) \
             ON CONFLICT(peer_id) DO UPDATE SET api_host=excluded.api_host, \
               api_port=excluded.api_port, pubkey=excluded.pubkey, \
               x25519_pk=excluded.x25519_pk, updated_at=excluded.updated_at",
        )
        .bind(&row.peer_id)
        .bind(&row.peer_id)
        .bind(&row.host)
        .bind(row.port)
        .bind(&material.pubkey)
        .bind(&material.x25519_pk)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        Ok::<(), sqlx::Error>(())
    }
    .await;
    if let Err(e) = completed {
        tracing::warn!("pair_verify completion failed: {e}");
        return api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }
    if let Err(e) = tx.commit().await {
        tracing::warn!("pair_verify commit failed: {e}");
        return api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    // b-6: hydrate the just-paired peer into the in-memory registry (U-B5-2). Slot-gated:
    // a no-op when native_daemon is off (slot empty). `registry.upsert` is NON-COALESCE for
    // token* AND runtime fields — it replaces the whole in-memory entry — so if this peer_id
    // is ALREADY known (re-pair, or bidirectional pairing where this node also holds an
    // outbound token in peers.token from the initiator flow), a fresh all-defaults PeerInfo
    // would silently NULL that real token and wipe live telemetry. So mirror the
    // token-preservation in `lan_cowork_discovery::handle_hello`: start from the existing
    // entry and refresh ONLY the identity fields pair_verify authoritatively re-establishes
    // (api_host/api_port/pubkey/x25519_pk); preserve token* and runtime telemetry. For a
    // brand-new peer, build defaults (token* None — auth uses peer_tokens, never the registry
    // token). Non-fatal on error: the peer is already committed to the DB.
    if let Some(registry) = state.peer_registry.get() {
        let pubkey = <[u8; 32]>::try_from(material.pubkey.as_slice()).ok();
        let x25519_pk = material
            .x25519_pk
            .as_deref()
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        let api_port = u16::try_from(row.port).unwrap_or(0);
        let hydrated = match registry.get(&row.peer_id) {
            // Known peer: refresh identity only, keep token* + runtime telemetry.
            Some(mut existing) => {
                existing.api_host = row.host.clone();
                existing.api_port = api_port;
                if pubkey.is_some() {
                    existing.pubkey = pubkey;
                }
                if x25519_pk.is_some() {
                    existing.x25519_pk = x25519_pk;
                }
                // Liveness: a successful pair_verify is a live round-trip now — refresh
                // status/last_seen even for a known peer (mirrors handle_hello). Runtime
                // telemetry (generating/bridges/...) and credentials (token*) stay preserved.
                existing.status = "online".to_string();
                existing.last_seen = now as f64;
                existing
            }
            // New peer: mirror pair_verify's `peers` INSERT (name=peer_id, token* NULL).
            None => crate::routes::lan_cowork_registry::PeerInfo {
                peer_id: row.peer_id.clone(),
                name: row.peer_id.clone(),
                api_host: row.host.clone(),
                api_port,
                token: None,
                token_expires_at: None,
                token_issued_at: None,
                pubkey,
                x25519_pk,
                version: String::new(),
                bridges: vec![],
                inference_types: vec![],
                gpu: String::new(),
                generating: false,
                queue_depth: 0,
                status: "online".to_string(),
                last_seen: now as f64,
                session_id: String::new(),
                roles: vec![],
                last_reached_at: None,
                last_attempted_at: None,
            },
        };
        if let Err(e) = registry.upsert(hydrated).await {
            tracing::warn!("pair_verify registry hydration failed (non-fatal): {e}");
        }
    }

    drop_pin(&req.request_id);
    untrack_pending(&req.request_id);

    state.sse_send(
        "lan_cowork",
        "peer.paired",
        now as f64,
        json!({"request_id": req.request_id, "peer_id": row.peer_id}),
    );

    let mut body = json!({
        "ok": true,
        "token": raw_token,
        "expires_at": expires_at,
        "peer_id": row.peer_id,
    });
    if let Some((server_ed, server_x)) = local_identity(&*state).await {
        body["server_pubkey"] = json!(b64(&server_ed));
        body["server_x25519_pk"] = json!(b64(&server_x));
    }
    api_ok(body)
}

/// 32 random bytes, urlsafe-base64 — matches `secrets.token_urlsafe(32)` in shape.
fn generate_token() -> String {
    let mut raw = [0u8; 32];
    rand::rng().fill(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

async fn expire_request(state: &dyn LanCoworkHost, request_id: &str, attempts: i64) {
    let _ = sqlx::query(
        "UPDATE peer_pairing_requests \
         SET status='expired', pin_hash=NULL, verify_attempts=?1, updated_at=?2 WHERE request_id=?3",
    )
    .bind(attempts)
    .bind(now_secs())
    .bind(request_id)
    .execute(state.db())
    .await;
    drop_pin(request_id);
    untrack_pending(request_id);
}

// ── GET /pair/requests ────────────────────────────────────────────────────────

#[derive(sqlx::FromRow, serde::Serialize)]
struct PendingRow {
    request_id: String,
    peer_id: String,
    host: String,
    port: i64,
    status: String,
    created_at: i64,
    updated_at: i64,
    sas: Option<String>,
}

async fn pair_requests(
    State(state): State<LanCoworkState>,
    session: Option<Extension<tower_sessions::Session>>,
) -> Response {
    if let Some(r) = session_guard(&*state, session.as_ref().map(|Extension(s)| s)).await {
        return r;
    }
    let rows: Result<Vec<PendingRow>, sqlx::Error> = sqlx::query_as(
        "SELECT request_id, peer_id, host, port, status, created_at, updated_at, sas \
         FROM peer_pairing_requests WHERE status IN ('pending','approved') \
         ORDER BY created_at DESC",
    )
    .fetch_all(state.db_read())
    .await;
    match rows {
        Ok(requests) => api_ok(json!({"ok": true, "requests": requests})),
        Err(e) => {
            tracing::warn!("pair_requests query failed: {e}");
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// Mark timed-out requests expired and drop long-dead rows (`sweep_expired`).
/// Exposed for the periodic sweeper; safe to call concurrently.
pub async fn sweep_expired(state: &dyn LanCoworkHost) {
    let now = now_secs();
    const STALE_PREDICATE: &str = "status IN ('pending','approved') AND ( \
         (pin_expires_at IS NOT NULL AND ?1 > pin_expires_at) OR \
         (pin_expires_at IS NULL AND ?1 > created_at + ?2))";

    // Collect first: the plaintext PINs of swept requests must leave memory too.
    // A request that can never reach `approved` again has no use for its PIN, and
    // leaving it resident would keep a secret alive indefinitely and grow the map
    // without bound.
    let stale: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT request_id FROM peer_pairing_requests WHERE {STALE_PREDICATE}"
    ))
    .bind(now)
    .bind(PENDING_TTL_SECONDS)
    .fetch_all(state.db_read())
    .await
    .unwrap_or_default();

    let _ = sqlx::query(&format!(
        "UPDATE peer_pairing_requests SET status='expired', pin_hash=NULL, updated_at=?1 \
         WHERE {STALE_PREDICATE}"
    ))
    .bind(now)
    .bind(PENDING_TTL_SECONDS)
    .execute(state.db())
    .await;

    for request_id in &stale {
        drop_pin(request_id);
        untrack_pending(request_id);
    }
    let _ = sqlx::query(
        "DELETE FROM peer_pairing_requests \
         WHERE status IN ('expired','rejected','completed') AND updated_at < ?1",
    )
    .bind(now - CLEANUP_AFTER_SECONDS)
    .execute(state.db())
    .await;
}

/// How often the independent pairing sweeper runs. Bounds expired-plaintext-PIN
/// RAM residency to <= PIN_TTL_SECONDS + this interval, independent of pairing
/// traffic (the request path only cleans up lazily on writes).
const PAIRING_SWEEP_INTERVAL_SECS: u64 = 60;

/// Spawn the independent periodic pairing-PIN sweeper. Fire-and-forget; the caller
/// gates this on `native_daemon` (dead code until flag-day). Sleep-first so startup
/// does no DB work before the app is serving.
///
/// Note: `sweep_expired` reads a pre-UPDATE snapshot and then evicts in-memory PINs
/// for that snapshot; a pairing write racing the sub-millisecond SELECT->UPDATE
/// window can leave a DB row `approved` with its plaintext PIN already evicted
/// (fail-closed: the secret is dropped, never leaked; pairing is retryable). A
/// RETURNING-based single-statement fix is deferred to a future increment.
pub fn start_pairing_sweeper(state: LanCoworkState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(PAIRING_SWEEP_INTERVAL_SECS)).await;
            sweep_expired(&*state).await;
        }
    });
}

pub fn routes() -> Router<LanCoworkState> {
    Router::new()
        .route("/ext/lan_cowork/api/peer/pair/request", post(pair_request))
        .route("/ext/lan_cowork/api/peer/pair/approve", post(pair_approve))
        .route("/ext/lan_cowork/api/peer/pair/reject", post(pair_reject))
        .route("/ext/lan_cowork/api/peer/pair/verify", post(pair_verify))
        .route("/ext/lan_cowork/api/peer/pair/requests", get(pair_requests))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SharedState;
    use axum::body::to_bytes;
    use std::sync::Arc;
    use tower::ServiceExt;

    const REQUEST_PATH: &str = "/ext/lan_cowork/api/peer/pair/request";
    const APPROVE_PATH: &str = "/ext/lan_cowork/api/peer/pair/approve";
    const REJECT_PATH: &str = "/ext/lan_cowork/api/peer/pair/reject";
    const VERIFY_PATH: &str = "/ext/lan_cowork/api/peer/pair/verify";
    const LIST_PATH: &str = "/ext/lan_cowork/api/peer/pair/requests";

    async fn test_state() -> SharedState {
        let tmp = std::path::PathBuf::from("/tmp/yu-pairing-test-config.json");
        let state = crate::state::semantic_test_state_with_root(false, String::new(), tmp).await;
        sqlx::raw_sql(
            "CREATE TABLE peer_pairing_requests (
               request_id TEXT PRIMARY KEY, peer_id TEXT NOT NULL, host TEXT NOT NULL,
               port INTEGER NOT NULL, pin_hash TEXT, pin_expires_at INTEGER,
               verify_attempts INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
               created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
               pubkey BLOB, x25519_pk BLOB, commit_hash BLOB, sas TEXT, source_ip TEXT
             );
             CREATE TABLE peer_tokens (
               peer_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, issued_at INTEGER NOT NULL,
               expires_at INTEGER NOT NULL, revoked_at INTEGER,
               source TEXT NOT NULL DEFAULT 'pairing', note TEXT
             );
             CREATE TABLE peers (
               peer_id TEXT PRIMARY KEY, name TEXT, api_host TEXT, api_port INTEGER,
               token TEXT, token_expires_at INTEGER, token_issued_at INTEGER,
               pubkey BLOB, x25519_pk BLOB,
               created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
             );
             CREATE TABLE lan_cowork_identity (key TEXT PRIMARY KEY, value BLOB);",
        )
        .execute(&state.db)
        .await
        .unwrap();
        // Local server identity, so verify can echo server_pubkey/server_x25519_pk.
        sqlx::query("INSERT INTO lan_cowork_identity (key, value) VALUES ('ed25519_seed', ?1)")
            .bind((101u8..=132).collect::<Vec<u8>>())
            .execute(&state.db)
            .await
            .unwrap();
        state
    }

    /// A distinct peer identity per `lead` byte → (seed, ed25519 pk, x25519 pk, peer_id).
    fn peer_identity_seeded(lead: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>, String) {
        let seed: Vec<u8> = (0u8..32).map(|i| lead.wrapping_add(i)).collect();
        let ed = openssl::pkey::PKey::private_key_from_raw_bytes(&seed, openssl::pkey::Id::ED25519)
            .unwrap()
            .raw_public_key()
            .unwrap();
        let x = pc::x25519_pubkey_from_ed25519_seed(&seed).unwrap();
        let pid = crate::routes::peer_identity::derive_peer_id(&ed);
        (seed, ed, x, pid)
    }

    fn peer_identity() -> (Vec<u8>, Vec<u8>, Vec<u8>, String) {
        peer_identity_seeded(1)
    }

    async fn json_body(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    /// Each test uses a distinct source IP: the rate-limit maps are process-global,
    /// so sharing one IP would make parallel tests throttle each other.
    async fn send(app: Router, method: &str, path: &str, ip: &str, body: Value) -> Response {
        let mut b = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .extension(PeerSourceIp(ip.to_string()));
        if method == "GET" {
            b = b.header("x-none", "1");
            return app
                .oneshot(b.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
        }
        app.oneshot(b.body(axum::body::Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    fn request_body(pid: &str, ed: &[u8], x: &[u8], commit: &[u8]) -> Value {
        json!({
            "peer_id": pid, "host": "192.168.1.50", "port": 5000,
            "pubkey": b64(ed), "x25519_pk": b64(x), "commit": b64(commit),
        })
    }

    /// Full pairing handshake with real crypto: request → approve → verify.
    /// This is the only test that runs the n=2^17 KDF (twice: once to build the
    /// bundle, once inside verify), so it is deliberately the sole heavy case.
    #[tokio::test]
    async fn full_pairing_handshake_completes_atomically() {
        let state = test_state().await;
        let (_seed, ed, x, pid) = peer_identity();
        let nonce: Vec<u8> = (64u8..96).collect();
        let commit = pc::make_commit_v2(&ed, &x, &nonce);

        // 1) request
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            REQUEST_PATH,
            "10.0.0.1",
            request_body(&pid, &ed, &x, &commit),
        )
        .await;
        assert_eq!(r.status(), StatusCode::ACCEPTED);
        let body = json_body(r).await;
        let rid = body["request_id"].as_str().unwrap().to_string();
        assert!(
            !body["sas"].as_str().unwrap().is_empty(),
            "SAS must be computed"
        );

        // 2) approve — the PIN is returned only to the operator here
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            APPROVE_PATH,
            "10.0.0.1",
            json!({"request_id": rid}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = json_body(r).await;
        let pin = body["pin"].as_str().unwrap().to_string();
        assert_eq!(pin.len(), 8, "PIN is 8 digits zero-padded");
        assert_eq!(body["expires_in"], 300);

        // 3) the peer encrypts its material under the PIN-derived key
        let key = pc::pin_kdf(&pin, &rid);
        let mut plain = ed.clone();
        plain.extend_from_slice(&x);
        plain.extend_from_slice(&nonce);
        let bundle = pc::encrypt_bundle_random_iv(&key, &plain, rid.as_bytes()).unwrap();

        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            VERIFY_PATH,
            "10.0.0.1",
            json!({"request_id": rid, "encrypted_bundle": b64(&bundle)}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = json_body(r).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["peer_id"], pid);
        assert!(body["token"].as_str().unwrap().len() > 20);
        assert!(body["server_pubkey"].is_string());
        assert!(body["server_x25519_pk"].is_string());

        // All three writes must have landed together (MF-E10): a token without
        // the peers.pubkey row would be rejected by require_peer_auth.
        let status: String =
            sqlx::query_scalar("SELECT status FROM peer_pairing_requests WHERE request_id=?1")
                .bind(&rid)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(status, "completed");
        let tokens: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM peer_tokens WHERE peer_id=?1")
            .bind(&pid)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(tokens, 1);
        let stored_pubkey: Vec<u8> =
            sqlx::query_scalar("SELECT pubkey FROM peers WHERE peer_id=?1")
                .bind(&pid)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(stored_pubkey, ed);

        // Replaying a completed request is 410, not a second token.
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            VERIFY_PATH,
            "10.0.0.1",
            json!({"request_id": rid, "encrypted_bundle": b64(&bundle)}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::GONE);
    }

    /// b-6: when the registry slot is set (native_daemon on), a successful
    /// pair_verify hydrates the just-paired peer into the in-memory registry.
    /// Mirrors full_pairing_handshake_completes_atomically's handshake exactly,
    /// then sets the slot before verify and asserts the hydrated entry after.
    #[tokio::test]
    async fn pair_verify_hydrates_registry_when_slot_set() {
        let state = test_state().await;
        let (_seed, ed, x, pid) = peer_identity();
        let nonce: Vec<u8> = (64u8..96).collect();
        let commit = pc::make_commit_v2(&ed, &x, &nonce);

        // b-6: populate the registry slot BEFORE verify (mirrors build_peer_registry
        // at runtime). local_peer_id is DISTINCT from the paired peer_id, else upsert's
        // self-skip would drop the hydration.
        let registry = std::sync::Arc::new(crate::routes::lan_cowork_registry::PeerRegistry::new(
            state.db.clone(),
            std::time::Duration::from_secs(30),
            "self-local".to_string(),
        ));
        let lc = LanCoworkState::from_shared(&state);
        lc.peer_registry.set(registry).ok();

        // 1) request
        let r = send(
            routes().with_state(lc.clone()),
            "POST",
            REQUEST_PATH,
            "10.0.0.1",
            request_body(&pid, &ed, &x, &commit),
        )
        .await;
        assert_eq!(r.status(), StatusCode::ACCEPTED);
        let body = json_body(r).await;
        let rid = body["request_id"].as_str().unwrap().to_string();

        // 2) approve
        let r = send(
            routes().with_state(lc.clone()),
            "POST",
            APPROVE_PATH,
            "10.0.0.1",
            json!({"request_id": rid}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = json_body(r).await;
        let pin = body["pin"].as_str().unwrap().to_string();

        // 3) the peer encrypts its material under the PIN-derived key
        let key = pc::pin_kdf(&pin, &rid);
        let mut plain = ed.clone();
        plain.extend_from_slice(&x);
        plain.extend_from_slice(&nonce);
        let bundle = pc::encrypt_bundle_random_iv(&key, &plain, rid.as_bytes()).unwrap();

        let r = send(
            routes().with_state(lc.clone()),
            "POST",
            VERIFY_PATH,
            "10.0.0.1",
            json!({"request_id": rid, "encrypted_bundle": b64(&bundle)}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = json_body(r).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["peer_id"], pid);

        // Existing DB assertion still holds: peers.pubkey was written.
        let stored_pubkey: Vec<u8> =
            sqlx::query_scalar("SELECT pubkey FROM peers WHERE peer_id=?1")
                .bind(&pid)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(stored_pubkey, ed);

        // NEW: the peer is now in the in-memory registry with the right identity, no token.
        let reg = lc.peer_registry.get().unwrap();
        let hydrated = reg
            .get(&pid)
            .expect("peer hydrated into registry after pair_verify");
        assert_eq!(hydrated.pubkey.map(|k| k.to_vec()), Some(ed.clone()));
        // SF-1: api_host/api_port come from row.host/row.port = the pairing REQUEST's
        // request_body host/port ("192.168.1.50"/5000), NOT the source IP "10.0.0.1".
        assert_eq!(hydrated.api_host, "192.168.1.50".to_string());
        assert_eq!(hydrated.api_port, 5000u16);
        // NH-1: x25519 hydrated too.
        assert_eq!(hydrated.x25519_pk.map(|k| k.to_vec()), Some(x.clone()));
        assert_eq!(hydrated.token, None); // registry never holds the plaintext token
        assert_eq!(hydrated.status, "online");
    }

    /// b-6 MUST-FIX regression: re-pairing an ALREADY-KNOWN peer must NOT null its
    /// pre-existing outbound token or wipe live telemetry. `registry.upsert` replaces
    /// the whole in-memory entry (non-COALESCE for token*/runtime), so hydration must
    /// get-then-merge: refresh identity only, preserve token* + runtime. Pre-seed the
    /// registry with a token + telemetry, run the full pairing cycle, assert survival.
    #[tokio::test]
    async fn pair_verify_preserves_existing_token_and_runtime_on_repair() {
        let state = test_state().await;
        let (_seed, ed, x, pid) = peer_identity();
        let nonce: Vec<u8> = (64u8..96).collect();
        let commit = pc::make_commit_v2(&ed, &x, &nonce);

        let registry = std::sync::Arc::new(crate::routes::lan_cowork_registry::PeerRegistry::new(
            state.db.clone(),
            std::time::Duration::from_secs(30),
            "self-local".to_string(),
        ));
        // Pre-seed the registry with an existing entry for `pid`: a real outbound token
        // and live telemetry (as if this node already paired to that peer as initiator
        // and saw a heartbeat). All 21 fields — the fresh-peer literal with token/telemetry
        // overridden.
        let prior = crate::routes::lan_cowork_registry::PeerInfo {
            peer_id: pid.clone(),
            name: pid.clone(),
            api_host: "10.9.9.9".to_string(),
            api_port: 1u16,
            token: Some("OUTBOUND-SECRET".to_string()),
            token_expires_at: Some(99_999_999_999),
            token_issued_at: Some(1),
            pubkey: None,
            x25519_pk: None,
            version: String::new(),
            bridges: vec!["comfyui".to_string()],
            inference_types: vec![],
            gpu: String::new(),
            generating: true,
            queue_depth: 0,
            status: "offline".to_string(),
            last_seen: 1.0,
            session_id: String::new(),
            roles: vec![],
            last_reached_at: None,
            last_attempted_at: None,
        };
        registry.upsert(prior).await.unwrap();
        let lc = LanCoworkState::from_shared(&state);
        lc.peer_registry.set(registry).ok();

        // Run the FULL pairing cycle for the same `pid` — mirrors
        // pair_verify_hydrates_registry_when_slot_set exactly.
        // 1) request
        let r = send(
            routes().with_state(lc.clone()),
            "POST",
            REQUEST_PATH,
            "10.0.0.14",
            request_body(&pid, &ed, &x, &commit),
        )
        .await;
        assert_eq!(r.status(), StatusCode::ACCEPTED);
        let rid = json_body(r).await["request_id"]
            .as_str()
            .unwrap()
            .to_string();

        // 2) approve
        let r = send(
            routes().with_state(lc.clone()),
            "POST",
            APPROVE_PATH,
            "10.0.0.14",
            json!({"request_id": rid}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let pin = json_body(r).await["pin"].as_str().unwrap().to_string();

        // 3) the peer encrypts its material under the PIN-derived key
        let key = pc::pin_kdf(&pin, &rid);
        let mut plain = ed.clone();
        plain.extend_from_slice(&x);
        plain.extend_from_slice(&nonce);
        let bundle = pc::encrypt_bundle_random_iv(&key, &plain, rid.as_bytes()).unwrap();

        let r = send(
            routes().with_state(lc.clone()),
            "POST",
            VERIFY_PATH,
            "10.0.0.14",
            json!({"request_id": rid, "encrypted_bundle": b64(&bundle)}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);

        let reg = lc.peer_registry.get().unwrap();
        let after = reg.get(&pid).expect("peer still in registry after re-pair");
        // MF: the pre-existing outbound token is preserved (NOT nulled by hydration).
        assert_eq!(after.token.as_deref(), Some("OUTBOUND-SECRET"));
        assert_eq!(after.token_expires_at, Some(99_999_999_999));
        // SF-1: live telemetry preserved.
        assert!(after.generating);
        assert_eq!(after.bridges, vec!["comfyui".to_string()]);
        // Identity fields still refreshed by the pairing.
        assert_eq!(after.api_host, "192.168.1.50".to_string());
        assert_eq!(after.pubkey.map(|k| k.to_vec()), Some(ed.clone()));
        assert_eq!(after.status, "online"); // liveness refreshed by the live pairing round-trip
        assert!(after.last_seen > 1.0); // last_seen bumped to pairing time, not the stale 1.0
    }

    #[tokio::test]
    async fn request_rejects_peer_id_not_matching_pubkey() {
        let state = test_state().await;
        let (_s, ed, x, _pid) = peer_identity();
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            REQUEST_PATH,
            "10.0.0.2",
            request_body("deadbeefdeadbeefdeadbeefdeadbeef", &ed, &x, &[0u8; 32]),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn request_rejects_low_order_x25519() {
        let state = test_state().await;
        let (_s, ed, _x, pid) = peer_identity();
        let low = vec![0u8; 32];
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            REQUEST_PATH,
            "10.0.0.3",
            request_body(&pid, &ed, &low, &[0u8; 32]),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(r).await["error"], "invalid x25519_pk");
    }

    #[tokio::test]
    async fn approve_rejects_non_pending_request() {
        let state = test_state().await;
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            APPROVE_PATH,
            "10.0.0.4",
            json!({"request_id": "nonexistent"}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn verify_with_bad_bundle_counts_attempt_then_expires() {
        let state = test_state().await;
        let (_s, ed, x, pid) = peer_identity();
        let commit = pc::make_commit_v2(&ed, &x, &[0u8; 32]);
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            REQUEST_PATH,
            "10.0.0.5",
            request_body(&pid, &ed, &x, &commit),
        )
        .await;
        let rid = json_body(r).await["request_id"]
            .as_str()
            .unwrap()
            .to_string();
        send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            APPROVE_PATH,
            "10.0.0.5",
            json!({"request_id": rid}),
        )
        .await;

        // Garbage bundle: decryption fails, so the attempt counter advances.
        let garbage = b64(&[9u8; 64]);
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            VERIFY_PATH,
            "10.0.0.5",
            json!({"request_id": rid, "encrypted_bundle": garbage}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let attempts: i64 = sqlx::query_scalar(
            "SELECT verify_attempts FROM peer_pairing_requests WHERE request_id=?1",
        )
        .bind(&rid)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(attempts, 1);

        // Jump to the attempt ceiling; the next failure must expire the request.
        sqlx::query("UPDATE peer_pairing_requests SET verify_attempts=?1 WHERE request_id=?2")
            .bind(MAX_VERIFY_ATTEMPTS - 1)
            .bind(&rid)
            .execute(&state.db)
            .await
            .unwrap();
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            VERIFY_PATH,
            "10.0.0.5",
            json!({"request_id": rid, "encrypted_bundle": garbage}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let status: String =
            sqlx::query_scalar("SELECT status FROM peer_pairing_requests WHERE request_id=?1")
                .bind(&rid)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(status, "expired");
    }

    #[tokio::test]
    async fn reject_marks_rejected_and_clears_pin_hash() {
        let state = test_state().await;
        let (_s, ed, x, pid) = peer_identity();
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            REQUEST_PATH,
            "10.0.0.6",
            request_body(&pid, &ed, &x, &[0u8; 32]),
        )
        .await;
        let rid = json_body(r).await["request_id"]
            .as_str()
            .unwrap()
            .to_string();
        send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            APPROVE_PATH,
            "10.0.0.6",
            json!({"request_id": rid}),
        )
        .await;
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            REJECT_PATH,
            "10.0.0.6",
            json!({"request_id": rid}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let (status, pin_hash): (String, Option<String>) = sqlx::query_as(
            "SELECT status, pin_hash FROM peer_pairing_requests WHERE request_id=?1",
        )
        .bind(&rid)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(status, "rejected");
        assert!(pin_hash.is_none(), "PIN hash must be cleared on reject");
    }

    #[tokio::test]
    async fn pending_cap_blocks_fourth_concurrent_request() {
        // Distinct peers: a repeat from the *same* peer retires its own earlier
        // request, so the cap can only be reached by different identities.
        let state = test_state().await;
        for lead in 0..(PENDING_CAP_PER_IP as u8) {
            let (_s, ed, x, pid) = peer_identity_seeded(lead * 40 + 1);
            let r = send(
                routes().with_state(LanCoworkState::from_shared(&state)),
                "POST",
                REQUEST_PATH,
                "10.0.0.7",
                request_body(&pid, &ed, &x, &[0u8; 32]),
            )
            .await;
            assert_eq!(r.status(), StatusCode::ACCEPTED);
        }
        let (_s, ed, x, pid) = peer_identity_seeded(200);
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            REQUEST_PATH,
            "10.0.0.7",
            request_body(&pid, &ed, &x, &[0u8; 32]),
        )
        .await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(json_body(r).await["error"], "pending cap exceeded");
    }

    #[tokio::test]
    async fn repeat_request_from_same_peer_retires_the_previous_one() {
        let state = test_state().await;
        let (_s, ed, x, pid) = peer_identity();
        let first = json_body(
            send(
                routes().with_state(LanCoworkState::from_shared(&state)),
                "POST",
                REQUEST_PATH,
                "10.0.0.11",
                request_body(&pid, &ed, &x, &[0u8; 32]),
            )
            .await,
        )
        .await["request_id"]
            .as_str()
            .unwrap()
            .to_string();
        send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            REQUEST_PATH,
            "10.0.0.11",
            request_body(&pid, &ed, &x, &[0u8; 32]),
        )
        .await;
        let status: String =
            sqlx::query_scalar("SELECT status FROM peer_pairing_requests WHERE request_id=?1")
                .bind(&first)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(status, "expired", "the earlier request must be retired");
    }

    #[tokio::test]
    async fn verify_is_bound_to_the_requesting_ip() {
        let state = test_state().await;
        let (_s, ed, x, pid) = peer_identity();
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            REQUEST_PATH,
            "10.0.0.12",
            request_body(&pid, &ed, &x, &[0u8; 32]),
        )
        .await;
        let rid = json_body(r).await["request_id"]
            .as_str()
            .unwrap()
            .to_string();
        send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            APPROVE_PATH,
            "10.0.0.12",
            json!({"request_id": rid}),
        )
        .await;
        // Same request, different source address → refused before any PIN work.
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            VERIFY_PATH,
            "10.9.9.9",
            json!({"request_id": rid, "encrypted_bundle": b64(&[9u8; 64])}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        // The attempt counter must not advance for a wrong-origin caller.
        let attempts: i64 = sqlx::query_scalar(
            "SELECT verify_attempts FROM peer_pairing_requests WHERE request_id=?1",
        )
        .bind(&rid)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(attempts, 0);
    }

    #[tokio::test]
    async fn reject_does_not_overwrite_a_completed_request() {
        let state = test_state().await;
        let now = now_secs();
        sqlx::query(
            "INSERT INTO peer_pairing_requests (request_id, peer_id, host, port, status, created_at, updated_at, verify_attempts) \
             VALUES ('done','p','h',1,'completed',?1,?1,0)",
        )
        .bind(now)
        .execute(&state.db)
        .await
        .unwrap();
        send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            REJECT_PATH,
            "10.0.0.13",
            json!({"request_id": "done"}),
        )
        .await;
        let status: String =
            sqlx::query_scalar("SELECT status FROM peer_pairing_requests WHERE request_id='done'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(
            status, "completed",
            "a completed request must stay completed"
        );
    }

    #[tokio::test]
    async fn sweep_drops_in_memory_pins_for_expired_requests() {
        let state = test_state().await;
        let now = now_secs();
        sqlx::query(
            "INSERT INTO peer_pairing_requests (request_id, peer_id, host, port, status, created_at, updated_at, verify_attempts, pin_expires_at) \
             VALUES ('swept','p','h',1,'approved',?1,?1,0,?2)",
        )
        .bind(now - PENDING_TTL_SECONDS - 10)
        .bind(now - 10) // PIN already past its TTL
        .execute(&state.db)
        .await
        .unwrap();
        store_pin("swept", "12345678");

        sweep_expired(&*state).await;

        assert!(
            take_pin("swept").is_none(),
            "a swept request must not leave its plaintext PIN in memory"
        );
    }

    #[tokio::test]
    async fn request_rate_limit_trips_after_ten_per_minute() {
        let state = test_state().await;
        let (_s, ed, x, pid) = peer_identity();
        // Reject each one so the pending cap never fires first — this isolates
        // the 10/min rate limiter.
        let mut saw_rate_limit = false;
        for _ in 0..(RATE_LIMIT_PER_MIN + 1) {
            let r = send(
                routes().with_state(LanCoworkState::from_shared(&state)),
                "POST",
                REQUEST_PATH,
                "10.0.0.8",
                request_body(&pid, &ed, &x, &[0u8; 32]),
            )
            .await;
            if r.status() == StatusCode::TOO_MANY_REQUESTS {
                if json_body(r).await["error"] == "rate limit" {
                    saw_rate_limit = true;
                    break;
                }
            } else {
                let rid = json_body(r).await["request_id"]
                    .as_str()
                    .unwrap()
                    .to_string();
                send(
                    routes().with_state(LanCoworkState::from_shared(&state)),
                    "POST",
                    REJECT_PATH,
                    "10.0.0.8",
                    json!({"request_id": rid}),
                )
                .await;
            }
        }
        assert!(saw_rate_limit, "10/min rate limit must trip");
    }

    #[tokio::test]
    async fn session_guarded_routes_401_when_pin_auth_enabled() {
        let mut state = test_state().await;
        Arc::get_mut(&mut state).unwrap().config.pin_auth_enabled = true;
        for (method, path, body) in [
            ("POST", APPROVE_PATH, json!({"request_id": "x"})),
            ("POST", REJECT_PATH, json!({"request_id": "x"})),
            ("GET", LIST_PATH, json!({})),
        ] {
            let r = send(
                routes().with_state(LanCoworkState::from_shared(&state)),
                method,
                path,
                "10.0.0.9",
                body,
            )
            .await;
            assert_eq!(
                r.status(),
                StatusCode::UNAUTHORIZED,
                "{path} must require session"
            );
        }
    }

    #[tokio::test]
    async fn requests_list_returns_pending_and_approved() {
        let state = test_state().await;
        let (_s, ed, x, pid) = peer_identity();
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "POST",
            REQUEST_PATH,
            "10.0.0.10",
            request_body(&pid, &ed, &x, &[0u8; 32]),
        )
        .await;
        let rid = json_body(r).await["request_id"]
            .as_str()
            .unwrap()
            .to_string();
        let r = send(
            routes().with_state(LanCoworkState::from_shared(&state)),
            "GET",
            LIST_PATH,
            "10.0.0.10",
            json!({}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = json_body(r).await;
        let list = body["requests"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["request_id"], rid);
        assert_eq!(list[0]["status"], "pending");
    }

    #[tokio::test]
    async fn sweep_expires_stale_and_deletes_ancient() {
        let state = test_state().await;
        let now = now_secs();
        sqlx::query(
            "INSERT INTO peer_pairing_requests (request_id, peer_id, host, port, status, created_at, updated_at, verify_attempts) \
             VALUES ('stale','p','h',1,'pending',?1,?1,0), ('ancient','p','h',1,'completed',?2,?2,0)",
        )
        .bind(now - PENDING_TTL_SECONDS - 10)
        .bind(now - CLEANUP_AFTER_SECONDS - 10)
        .execute(&state.db)
        .await
        .unwrap();

        sweep_expired(&*state).await;

        let stale: String =
            sqlx::query_scalar("SELECT status FROM peer_pairing_requests WHERE request_id='stale'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(stale, "expired");
        let ancient: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM peer_pairing_requests WHERE request_id='ancient'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(ancient, 0, "rows past the cleanup window must be deleted");
    }
}
