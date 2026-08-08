//! Peer transport authentication — Rust port of the Python `require_peer_auth`
//! chain (`extensions/builtin_lan_cowork/core_impl/peer_auth.py`) plus the crypto
//! in `core/crypto_identity/request_signer.py` / `request_verifier.py` and
//! `token_store._hash_token`.
//!
//! Byte-compatible with the Python protocol so a Rust node interoperates with
//! Python peers on the same LAN. All parameters are pinned by
//! `tests/vectors/peer_transport_vectors.json` (design 2026-07-19 Increment A,
//! MF-1..MF-5). Primitives: openssl for Ed25519, RustCrypto `scrypt` for the
//! token KDF, openssl constant-time memcmp for the hash comparison.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use openssl::pkey::{Id, PKey};
use openssl::sign::Verifier;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::routes::lan_cowork_host::LanCoworkHost;

const TOKEN_SALT: &[u8] = b"yu-ai-peer-token";
const SCRYPT_LOG_N: u8 = 14; // n = 16384
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_DKLEN: usize = 64; // dklen unspecified in Python → CPython default 64 bytes
const TS_TOLERANCE_SECS: i64 = 30; // REQUEST_TIMESTAMP_TOLERANCE
const NONCE_GRACE_SECS: u64 = 60; // = tolerance * 2
const NONCE_TTL_SECS: i64 = 60; // expiry = ts + tolerance * 2

// Kept in lock-step with core/crypto_identity/request_signer.py NONCE_REQUIRED_*.
const NONCE_REQUIRED_SUFFIXES: &[&str] = &[
    "/api/peer/message",
    "/api/peer/token/renew",
    "/api/peer/generate",
    "/api/peer/cancel",
    "/api/peer/sync/push",
    "/api/peer/sync/notify",
    "/api/peer/negotiate",
];
const NONCE_REQUIRED_PREFIXES: &[&str] = &[
    "/api/peer/infer/",
    "/api/peer/import/",
    "/ext/lan_cowork/fleet/",
];

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Canonical signed message: `METHOD\npath\nqs\nts\nsha256(body).hex()\n`
/// (request_signer.build_canonical_message). Shared with the future outbound
/// `sign()` (Increment C, SF-2).
pub fn build_canonical_message(
    method: &str,
    path: &str,
    query_string: &str,
    ts_str: &str,
    body: &[u8],
) -> Vec<u8> {
    let body_hash = hex::encode(Sha256::digest(body));
    format!(
        "{}\n{}\n{}\n{}\n{}\n",
        method.to_uppercase(),
        path,
        query_string,
        ts_str,
        body_hash
    )
    .into_bytes()
}

/// Verify the Ed25519 request signature within the ±30s timestamp window.
pub fn verify_request_signature(
    pubkey: &[u8],
    method: &str,
    path: &str,
    query_string: &str,
    body: &[u8],
    ts_header: &str,
    sig_header: &str,
) -> bool {
    let ts: i64 = match ts_header.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if (now_secs() - ts).abs() > TS_TOLERANCE_SECS {
        return false;
    }
    let sig = match base64::engine::general_purpose::URL_SAFE.decode(sig_header) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let canonical = build_canonical_message(method, path, query_string, ts_header, body);
    let pk = match PKey::public_key_from_raw_bytes(pubkey, Id::ED25519) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let mut verifier = match Verifier::new_without_digest(&pk) {
        Ok(v) => v,
        Err(_) => return false,
    };
    verifier.verify_oneshot(&sig, &canonical).unwrap_or(false)
}

/// Sign a canonical message with a raw 32-byte Ed25519 seed.
///
/// Increment C (outbound signing). Deliberately shares `build_canonical_message`
/// with the verify path so the two can never diverge (design SF-2). The first
/// production caller lands in Increment D (heartbeat); until then this is
/// exercised only by the byte-compat vector tests.
#[allow(dead_code)]
pub fn sign_canonical(seed: &[u8], canonical: &[u8]) -> Option<Vec<u8>> {
    let pk = PKey::private_key_from_raw_bytes(seed, Id::ED25519).ok()?;
    let mut signer = openssl::sign::Signer::new_without_digest(&pk).ok()?;
    signer.sign_oneshot_to_vec(canonical).ok()
}

/// Build the outbound peer signature headers (Python `make_signature_headers`).
/// Returns `(X-Peer-Ts, X-Peer-Sig)`; the signature is base64 urlsafe.
#[allow(dead_code)]
pub fn make_signature_headers(
    seed: &[u8],
    method: &str,
    path: &str,
    query_string: &str,
    body: &[u8],
) -> Option<(String, String)> {
    let ts = now_secs().to_string();
    let canonical = build_canonical_message(method, path, query_string, &ts, body);
    let sig = sign_canonical(seed, &canonical)?;
    Some((ts, base64::engine::general_purpose::URL_SAFE.encode(sig)))
}

/// Fresh nonce for nonce-required endpoints (Python `make_nonce_header`).
#[allow(dead_code)]
pub fn make_nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn path_requires_nonce(path: &str) -> bool {
    if NONCE_REQUIRED_SUFFIXES.iter().any(|s| path.ends_with(s)) {
        return true;
    }
    NONCE_REQUIRED_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// scrypt(token) hex — 128 hex chars (64 bytes), matches `token_store._hash_token`.
pub fn hash_token(raw: &str) -> String {
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
        .expect("static scrypt params are valid");
    let mut out = [0u8; SCRYPT_DKLEN];
    scrypt::scrypt(raw.as_bytes(), TOKEN_SALT, &params, &mut out).expect("scrypt kdf");
    hex::encode(out)
}

/// Constant-time comparison of a raw token against a stored hex hash (MF-4).
fn token_hash_matches(raw: &str, stored_hex: &str) -> bool {
    let candidate = hash_token(raw);
    let a = candidate.as_bytes();
    let b = stored_hex.as_bytes();
    // openssl::memcmp::eq is constant-time but requires equal length.
    a.len() == b.len() && openssl::memcmp::eq(a, b)
}

#[derive(Debug, PartialEq, Eq)]
pub enum NonceResult {
    Accepted,
    Duplicate,
    Grace,
}

/// In-memory nonce dedup with a startup grace period, mirroring
/// `request_verifier.NonceStore`. Constructed once at server start so the grace
/// window is measured from process start (MF-3).
pub struct PeerNonceStore {
    started_at: Instant,
    grace: Duration,
    seen: std::sync::Mutex<HashMap<String, i64>>, // nonce -> expiry_ts
}

impl PeerNonceStore {
    pub fn new() -> Self {
        Self::with_grace(NONCE_GRACE_SECS)
    }

    pub fn with_grace(grace_secs: u64) -> Self {
        Self {
            started_at: Instant::now(),
            grace: Duration::from_secs(grace_secs),
            seen: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn check_and_store(&self, nonce: &str, ts: i64) -> NonceResult {
        if self.started_at.elapsed() < self.grace {
            return NonceResult::Grace;
        }
        let now = now_secs();
        let mut seen = self.seen.lock().expect("nonce store poisoned");
        seen.retain(|_, exp| *exp > now);
        let expiry = ts + NONCE_TTL_SECS;
        if expiry <= now {
            return NonceResult::Duplicate;
        }
        if seen.contains_key(nonce) {
            return NonceResult::Duplicate;
        }
        seen.insert(nonce.to_string(), expiry);
        NonceResult::Accepted
    }
}

impl Default for PeerNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-wide nonce store, mirroring Python's module-global `_nonce_store`.
///
/// A boot-pinned module static rather than a `SharedState` field: `main.rs` calls
/// `nonce_store()` at startup so the grace window is anchored to process boot
/// (design MF-3), and cleanup is inline in `check_and_store` (matching Python's
/// `_evict_expired`; SF-3's separate task was descoped as parity-neutral). No
/// nonce-required route ships in Increment A — peer self-delete is not in the
/// nonce set — but the store is boot-anchored now so Increment C/D can add one
/// without a forcing-function gap.
static NONCE_STORE: std::sync::OnceLock<PeerNonceStore> = std::sync::OnceLock::new();

pub fn nonce_store() -> &'static PeerNonceStore {
    NONCE_STORE.get_or_init(PeerNonceStore::new)
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({"ok": false, "error": msg}))).into_response()
}

/// Full inbound peer-auth chain (Python `require_peer_auth`). Reads the DB as the
/// authority (`peers.pubkey` + `peer_tokens` via scrypt). Returns the verified
/// `peer_id`, or an error `Response` whose status matches Python (MF-5):
/// unknown peer → 403, not paired → 403, bad signature → 401, missing token → 401,
/// invalid/expired/revoked token → 401, nonce grace → 503, nonce replay → 401.
pub async fn require_peer_auth(
    state: &dyn LanCoworkHost,
    method: &str,
    path: &str,
    query_string: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, Response> {
    require_peer_auth_with_nonce_store(
        state,
        method,
        path,
        query_string,
        headers,
        body,
        nonce_store(),
    )
    .await
}

pub async fn require_peer_auth_with_nonce_store(
    state: &dyn LanCoworkHost,
    method: &str,
    path: &str,
    query_string: &str,
    headers: &HeaderMap,
    body: &[u8],
    nonces: &PeerNonceStore,
) -> Result<String, Response> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };

    let peer_id = header("X-Peer-Id").trim().to_string();
    if peer_id.is_empty() {
        return Err(err(StatusCode::UNAUTHORIZED, "missing X-Peer-Id"));
    }

    let pubkey =
        sqlx::query_scalar::<_, Option<Vec<u8>>>("SELECT pubkey FROM peers WHERE peer_id = ?1")
            .bind(&peer_id)
            .fetch_optional(state.db_read())
            .await
            .map_err(|e| {
                tracing::warn!("require_peer_auth peers lookup failed: {e}");
                err(StatusCode::SERVICE_UNAVAILABLE, "peer store unavailable")
            })?;
    let pubkey = match pubkey {
        None => return Err(err(StatusCode::FORBIDDEN, "unknown peer")),
        Some(None) => return Err(err(StatusCode::FORBIDDEN, "peer not paired")),
        Some(Some(pk)) if pk.is_empty() => {
            return Err(err(StatusCode::FORBIDDEN, "peer not paired"))
        }
        Some(Some(pk)) => pk,
    };

    if !verify_request_signature(
        &pubkey,
        method,
        path,
        query_string,
        body,
        &header("X-Peer-Ts"),
        &header("X-Peer-Sig"),
    ) {
        return Err(err(StatusCode::UNAUTHORIZED, "signature invalid"));
    }

    if path_requires_nonce(path) {
        let nonce = header("X-Peer-Nonce");
        if nonce.is_empty() {
            return Err(err(StatusCode::UNAUTHORIZED, "missing nonce"));
        }
        let ts: i64 = header("X-Peer-Ts").parse().unwrap_or(0);
        match nonces.check_and_store(&nonce, ts) {
            NonceResult::Accepted => {}
            NonceResult::Grace => {
                return Err(err(StatusCode::SERVICE_UNAVAILABLE, "nonce grace period"))
            }
            NonceResult::Duplicate => return Err(err(StatusCode::UNAUTHORIZED, "nonce rejected")),
        }
    }

    let auth = header("Authorization");
    let token = match auth.strip_prefix("Bearer ") {
        Some(t) => t.trim(),
        None => return Err(err(StatusCode::UNAUTHORIZED, "missing token")),
    };

    let row = sqlx::query_as::<_, (String, i64, Option<i64>)>(
        "SELECT token_hash, expires_at, revoked_at FROM peer_tokens WHERE peer_id = ?1",
    )
    .bind(&peer_id)
    .fetch_optional(state.db_read())
    .await
    .map_err(|e| {
        tracing::warn!("require_peer_auth token lookup failed: {e}");
        err(StatusCode::SERVICE_UNAVAILABLE, "token store unavailable")
    })?;
    let valid = match row {
        Some((stored_hash, expires_at, revoked_at)) => {
            if revoked_at.is_some() || now_secs() > expires_at {
                false
            } else {
                // scrypt is CPU-bound (n=2^14 → 16 MiB, tens of ms) and runs on
                // every authenticated peer request. Keep it off the async worker
                // threads, mirroring Python's `asyncio.to_thread` offload in
                // peer_auth.py — calling it inline stalls the whole runtime.
                let token = token.to_string();
                tokio::task::spawn_blocking(move || token_hash_matches(&token, &stored_hash))
                    .await
                    .unwrap_or(false)
            }
        }
        None => false,
    };
    if !valid {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid token"));
    }

    Ok(peer_id)
}

/// Raw inbound token: 32 random bytes as URL_SAFE_NO_PAD base64 (matches Python
/// `secrets.token_urlsafe(32)`). Opaque — stored only as a scrypt hash.
fn generate_raw_token() -> String {
    let mut bytes = [0u8; 32];
    openssl::rand::rand_bytes(&mut bytes).expect("openssl rand_bytes");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Atomically reissue a peer's inbound token unless it has been revoked. Mirrors
/// Python `TokenStore.renew_if_not_revoked`: `BEGIN IMMEDIATE`, check `revoked_at`,
/// and either roll back (revoked) or upsert a fresh `source='renew'` token. Returns
/// `Ok(None)` when the current token is revoked or `peer_id` is empty; a MISSING row
/// proceeds to issue the first token (Python parity).
pub async fn renew_if_not_revoked(
    pool: &sqlx::SqlitePool,
    peer_id: &str,
    ttl_days: i64,
) -> Result<Option<(String, i64)>, sqlx::Error> {
    if peer_id.is_empty() {
        return Ok(None);
    }
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    // Inner body kept separate so any error path rolls back the transaction.
    async fn body(
        conn: &mut sqlx::SqliteConnection,
        peer_id: &str,
        ttl_days: i64,
    ) -> Result<Option<(String, i64)>, sqlx::Error> {
        // Outer Option = row present?, inner = revoked_at value. Some(Some(_)) =
        // present and revoked -> refuse; Some(None) = present and active -> reissue;
        // None = no row -> reissue (Python parity).
        let existing: Option<Option<i64>> = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT revoked_at FROM peer_tokens WHERE peer_id = ?1",
        )
        .bind(peer_id)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(Some(_revoked_ts)) = existing {
            return Ok(None); // present and revoked -> refuse
        }
        let raw = generate_raw_token();
        // scrypt is CPU-bound; offload like require_peer_auth does.
        let raw_for_hash = raw.clone();
        let token_hash = tokio::task::spawn_blocking(move || hash_token(&raw_for_hash))
            .await
            .expect("hash_token task");
        let now = now_secs();
        let expires_at = now + ttl_days * 86_400;
        sqlx::query(
            "INSERT INTO peer_tokens (peer_id, token_hash, issued_at, expires_at, revoked_at, source, note)
             VALUES (?1, ?2, ?3, ?4, NULL, 'renew', NULL)
             ON CONFLICT(peer_id) DO UPDATE SET
               token_hash=excluded.token_hash, issued_at=excluded.issued_at,
               expires_at=excluded.expires_at, revoked_at=NULL,
               source=excluded.source, note=excluded.note",
        )
        .bind(peer_id)
        .bind(&token_hash)
        .bind(now)
        .bind(expires_at)
        .execute(&mut *conn)
        .await?;
        Ok(Some((raw, expires_at)))
    }

    // SF-B: on ANY error path — including a failing COMMIT — roll back so the
    // connection is not returned to the pool mid-transaction (which would poison
    // every subsequent renew on that connection).
    match body(&mut conn, peer_id, ttl_days).await {
        Ok(v) => {
            if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(e);
            }
            Ok(v)
        }
        Err(e) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(e)
        }
    }
}

/// Renew-specific inbound auth (Python `require_peer_renew_auth`). Unlike
/// `require_peer_auth`: NO Bearer token (an expired-but-not-revoked peer must still
/// renew — M5), the nonce is FORCED, and an unknown peer returns 404 (not 403). The
/// `nonces` store is a parameter (the handler passes `nonce_store()`; tests inject
/// `with_grace(0)`) — the D5 testability seam.
pub async fn require_peer_renew_auth(
    state: &dyn LanCoworkHost,
    method: &str,
    path: &str,
    query_string: &str,
    headers: &HeaderMap,
    body: &[u8],
    nonces: &PeerNonceStore,
) -> Result<String, Response> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let peer_id = header("X-Peer-Id").trim().to_string();
    if peer_id.is_empty() {
        return Err(err(StatusCode::UNAUTHORIZED, "missing X-Peer-Id"));
    }
    let pubkey =
        sqlx::query_scalar::<_, Option<Vec<u8>>>("SELECT pubkey FROM peers WHERE peer_id = ?1")
            .bind(&peer_id)
            .fetch_optional(state.db_read())
            .await
            .map_err(|e| {
                tracing::warn!("require_peer_renew_auth peers lookup failed: {e}");
                err(StatusCode::SERVICE_UNAVAILABLE, "peer store unavailable")
            })?;
    // Unknown peer (no row) -> 404 (renew reveals registration status, MF-5). But a
    // row that exists WITHOUT a pubkey is "not paired" -> 403, matching Python
    // `_lookup_peer_or_response` (peer None -> unknown_status=404; `not peer.pubkey`
    // -> hard 403 "peer not paired") and the sibling `require_peer_auth` (MF-A).
    let pubkey = match pubkey {
        None => return Err(err(StatusCode::NOT_FOUND, "unknown peer")),
        Some(None) => return Err(err(StatusCode::FORBIDDEN, "peer not paired")),
        Some(Some(pk)) if pk.is_empty() => {
            return Err(err(StatusCode::FORBIDDEN, "peer not paired"))
        }
        Some(Some(pk)) => pk,
    };
    if !verify_request_signature(
        &pubkey,
        method,
        path,
        query_string,
        body,
        &header("X-Peer-Ts"),
        &header("X-Peer-Sig"),
    ) {
        return Err(err(StatusCode::UNAUTHORIZED, "signature invalid"));
    }
    // Forced nonce (no path_requires_nonce gate).
    let nonce = header("X-Peer-Nonce");
    if nonce.is_empty() {
        return Err(err(StatusCode::UNAUTHORIZED, "missing nonce"));
    }
    let ts: i64 = header("X-Peer-Ts").parse().unwrap_or(0);
    match nonces.check_and_store(&nonce, ts) {
        NonceResult::Accepted => {}
        NonceResult::Grace => {
            return Err(err(StatusCode::SERVICE_UNAVAILABLE, "nonce grace period"))
        }
        NonceResult::Duplicate => return Err(err(StatusCode::UNAUTHORIZED, "nonce rejected")),
    }
    // No Bearer/token check — that is the whole point of renew.
    Ok(peer_id)
}

#[cfg(any(test, feature = "test-seams"))]
#[doc(hidden)]
// Keep the test-seam signature stable for downstream integration tests.
#[allow(clippy::too_many_arguments)]
pub fn sign_headers(
    seed: &[u8],
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
    ts: i64,
    nonce: &str,
    peer_id: &str,
) -> HeaderMap {
    let ts_s = ts.to_string();
    let canonical = build_canonical_message(method, path, query, &ts_s, body);
    let sig = sign_canonical(seed, &canonical).unwrap();
    let sig_b64 = base64::engine::general_purpose::URL_SAFE.encode(&sig);
    let mut h = HeaderMap::new();
    h.insert("X-Peer-Id", peer_id.parse().unwrap());
    h.insert("X-Peer-Ts", ts_s.parse().unwrap());
    h.insert("X-Peer-Sig", sig_b64.parse().unwrap());
    if !nonce.is_empty() {
        h.insert("X-Peer-Nonce", nonce.parse().unwrap());
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SharedState;
    use serde_json::Value;

    // Python-generated ground-truth vectors (scripts/gen_peer_transport_vectors.py).
    const VECTORS: &str = include_str!("../../tests/vectors/peer_transport_vectors.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("vectors json parses")
    }

    #[test]
    fn token_hash_matches_python_vector() {
        let v = vectors();
        let t = &v["token_scrypt"];
        let raw = t["raw"].as_str().unwrap();
        let expected = t["hash_hex"].as_str().unwrap();
        assert_eq!(expected.len(), 128, "token hash must be 64 bytes / 128 hex");
        assert_eq!(hash_token(raw), expected);
    }

    #[test]
    fn constant_time_token_compare() {
        let v = vectors();
        let t = &v["token_scrypt"];
        let raw = t["raw"].as_str().unwrap();
        let hash = t["hash_hex"].as_str().unwrap();
        assert!(token_hash_matches(raw, hash));
        assert!(!token_hash_matches("wrong", hash));
        assert!(!token_hash_matches(raw, "deadbeef")); // length mismatch → false, no panic
    }

    #[test]
    fn canonical_matches_python_vector() {
        let v = vectors();
        for case in v["request_signature"]["cases"].as_array().unwrap() {
            let canonical = build_canonical_message(
                case["method"].as_str().unwrap(),
                case["path"].as_str().unwrap(),
                case["query_string"].as_str().unwrap(),
                case["ts"].as_str().unwrap(),
                case["body_utf8"].as_str().unwrap().as_bytes(),
            );
            assert_eq!(
                hex::encode(&canonical),
                case["canonical_hex"].as_str().unwrap(),
                "canonical mismatch for {}",
                case["path"]
            );
        }
    }

    #[test]
    fn vector_signature_verifies_over_canonical() {
        // The vector sig is over a fixed (past) ts, so bypass the ts window and
        // verify the raw Ed25519 signature over the canonical bytes directly.
        let v = vectors();
        let pubkey = hex::decode(v["request_signature"]["pubkey_hex"].as_str().unwrap()).unwrap();
        let pk = PKey::public_key_from_raw_bytes(&pubkey, Id::ED25519).unwrap();
        for case in v["request_signature"]["cases"].as_array().unwrap() {
            let canonical = hex::decode(case["canonical_hex"].as_str().unwrap()).unwrap();
            let sig = base64::engine::general_purpose::URL_SAFE
                .decode(case["sig_b64url"].as_str().unwrap())
                .unwrap();
            let mut verifier = Verifier::new_without_digest(&pk).unwrap();
            assert!(
                verifier.verify_oneshot(&sig, &canonical).unwrap(),
                "sig fails for {}",
                case["path"]
            );
        }
    }

    #[test]
    fn verify_request_signature_roundtrip_current_ts() {
        let v = vectors();
        let seed = hex::decode(v["request_signature"]["seed_hex"].as_str().unwrap()).unwrap();
        let pubkey = hex::decode(v["request_signature"]["pubkey_hex"].as_str().unwrap()).unwrap();
        let ts = now_secs().to_string();
        let body = br#"{"x":1}"#;
        let canonical =
            build_canonical_message("POST", "/ext/lan_cowork/api/peer/x", "", &ts, body);
        let sig = sign_canonical(&seed, &canonical).unwrap();
        let sig_b64 = base64::engine::general_purpose::URL_SAFE.encode(&sig);

        assert!(verify_request_signature(
            &pubkey,
            "POST",
            "/ext/lan_cowork/api/peer/x",
            "",
            body,
            &ts,
            &sig_b64
        ));
        // Tampered body → false.
        assert!(!verify_request_signature(
            &pubkey,
            "POST",
            "/ext/lan_cowork/api/peer/x",
            "",
            b"tampered",
            &ts,
            &sig_b64
        ));
        // Stale timestamp → false (outside ±30s window).
        let stale = (now_secs() - 120).to_string();
        assert!(!verify_request_signature(
            &pubkey,
            "POST",
            "/ext/lan_cowork/api/peer/x",
            "",
            body,
            &stale,
            &sig_b64
        ));
    }

    #[test]
    fn path_requires_nonce_matches_python() {
        let v = vectors();
        for (path, expected) in v["nonce"]["probe"].as_object().unwrap() {
            assert_eq!(
                path_requires_nonce(path),
                expected.as_bool().unwrap(),
                "nonce classification mismatch for {path}"
            );
        }
    }

    #[test]
    fn nonce_store_grace_accept_duplicate() {
        // Grace window active → everything rejected as GRACE.
        let grace = PeerNonceStore::with_grace(3600);
        assert_eq!(grace.check_and_store("n1", now_secs()), NonceResult::Grace);

        // Grace elapsed → fresh accepted, replay is duplicate.
        let store = PeerNonceStore::with_grace(0);
        let ts = now_secs();
        assert_eq!(store.check_and_store("n1", ts), NonceResult::Accepted);
        assert_eq!(store.check_and_store("n1", ts), NonceResult::Duplicate);
        assert_eq!(store.check_and_store("n2", ts), NonceResult::Accepted);
        // A timestamp already past its TTL is rejected as duplicate/stale.
        assert_eq!(
            store.check_and_store("n3", now_secs() - NONCE_TTL_SECS - 5),
            NonceResult::Duplicate
        );
    }

    // ── Increment C: outbound signing ────────────────────────────────────────
    #[test]
    fn sign_reproduces_python_vector_signature() {
        // Ed25519 is deterministic (RFC 8032): signing the same canonical bytes
        // with the same seed must reproduce Python's signature byte-for-byte.
        // This is the strongest available proof that outbound signing is
        // wire-compatible with Python peers.
        let v = vectors();
        let seed = hex::decode(v["request_signature"]["seed_hex"].as_str().unwrap()).unwrap();
        for case in v["request_signature"]["cases"].as_array().unwrap() {
            let canonical = hex::decode(case["canonical_hex"].as_str().unwrap()).unwrap();
            let sig = sign_canonical(&seed, &canonical).unwrap();
            assert_eq!(
                base64::engine::general_purpose::URL_SAFE.encode(&sig),
                case["sig_b64url"].as_str().unwrap(),
                "signature mismatch for {}",
                case["path"]
            );
        }
    }

    #[test]
    fn make_signature_headers_verifies_roundtrip() {
        let v = vectors();
        let seed = hex::decode(v["request_signature"]["seed_hex"].as_str().unwrap()).unwrap();
        let pubkey = hex::decode(v["request_signature"]["pubkey_hex"].as_str().unwrap()).unwrap();
        let body = br#"{"hello":1}"#;
        let (ts, sig) = make_signature_headers(
            &seed,
            "POST",
            "/ext/lan_cowork/api/peer/message",
            "a=1",
            body,
        )
        .unwrap();
        assert!(verify_request_signature(
            &pubkey,
            "POST",
            "/ext/lan_cowork/api/peer/message",
            "a=1",
            body,
            &ts,
            &sig
        ));
    }

    #[test]
    fn make_signature_headers_rejects_bad_seed() {
        assert!(make_signature_headers(b"too-short", "GET", "/x", "", b"").is_none());
    }

    #[test]
    fn make_nonce_is_unique() {
        let a = make_nonce();
        let b = make_nonce();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36, "uuid v4 hyphenated form");
    }

    // ── b-4: token renew store (renew_if_not_revoked) ───────────────────────────
    use crate::schema::apply_standalone_schema;
    use crate::state::semantic_test_state_with;

    async fn renew_test_pool() -> sqlx::SqlitePool {
        // SF-A: max_connections(1) so the test's seed INSERT and renew_if_not_revoked's
        // acquired connection hit the SAME in-memory DB (a multi-connection `:memory:`
        // pool gives each connection its own DB -> "no such table: peer_tokens").
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        apply_standalone_schema(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn renew_issues_fresh_token_for_active_peer() {
        let pool = renew_test_pool().await;
        // Pre-existing active token.
        sqlx::query("INSERT INTO peer_tokens (peer_id, token_hash, issued_at, expires_at, revoked_at, source) VALUES ('p1','oldhash',1,2,NULL,'pairing')")
            .execute(&pool).await.unwrap();
        let (raw, expires_at) = renew_if_not_revoked(&pool, "p1", 30)
            .await
            .unwrap()
            .expect("active -> reissue");
        assert!(!raw.is_empty());
        assert!(expires_at > now_secs());
        // Row updated: new hash, source='renew', revoked_at NULL.
        let (hash, source, revoked): (String, String, Option<i64>) = sqlx::query_as(
            "SELECT token_hash, source, revoked_at FROM peer_tokens WHERE peer_id='p1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(hash, hash_token(&raw));
        assert_eq!(source, "renew");
        assert!(revoked.is_none());
    }

    #[tokio::test]
    async fn renew_refuses_revoked_token() {
        let pool = renew_test_pool().await;
        sqlx::query("INSERT INTO peer_tokens (peer_id, token_hash, issued_at, expires_at, revoked_at, source) VALUES ('p1','h',1,2,999,'pairing')")
            .execute(&pool).await.unwrap();
        assert!(renew_if_not_revoked(&pool, "p1", 30)
            .await
            .unwrap()
            .is_none());
        // Row unchanged (still revoked).
        let revoked: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at FROM peer_tokens WHERE peer_id='p1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(revoked, Some(999));
    }

    #[tokio::test]
    async fn renew_issues_first_token_when_none_exists() {
        let pool = renew_test_pool().await; // no row for p1
        let out = renew_if_not_revoked(&pool, "p1", 30).await.unwrap();
        assert!(out.is_some()); // missing row -> issues first token (Python parity)
        let source: String =
            sqlx::query_scalar("SELECT source FROM peer_tokens WHERE peer_id='p1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(source, "renew");
    }

    #[tokio::test]
    async fn renew_empty_peer_id_is_none() {
        let pool = renew_test_pool().await;
        assert!(renew_if_not_revoked(&pool, "", 30).await.unwrap().is_none());
    }

    // ── b-4: require_peer_renew_auth ────────────────────────────────────────────
    // Reuse the module's existing test crypto (vectors seed/pubkey,
    // build_canonical_message, sign_canonical). Do NOT invent a parallel path.
    fn seed_bytes() -> Vec<u8> {
        hex::decode(vectors()["request_signature"]["seed_hex"].as_str().unwrap()).unwrap()
    }

    fn pubkey_bytes() -> Vec<u8> {
        hex::decode(
            vectors()["request_signature"]["pubkey_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    }

    // SF-C: semantic_test_state_with's single `sqlite::memory:` pool backs BOTH
    // state.db and state.db_read, so a peers INSERT on state.db is visible to the
    // db_read pubkey lookup (proven by b-1b). Do NOT build a raw pool here.
    async fn renew_auth_test_state() -> SharedState {
        let state = semantic_test_state_with(false, String::new()).await;
        apply_standalone_schema(&state.db).await.unwrap();
        state
    }

    async fn renew_auth_state_with_peer(peer_id: &str) -> (SharedState, Vec<u8>, Vec<u8>) {
        let state = renew_auth_test_state().await;
        // peers has created_at/updated_at NOT NULL — supply them.
        sqlx::query(
            "INSERT INTO peers (peer_id, name, api_host, api_port, pubkey, created_at, updated_at) \
             VALUES (?1,'n','10.0.0.2',5000,?2,0,0)",
        )
        .bind(peer_id)
        .bind(pubkey_bytes())
        .execute(&state.db)
        .await
        .unwrap();
        (state, seed_bytes(), pubkey_bytes())
    }

    const RENEW_PATH: &str = "/ext/lan_cowork/api/peer/token/renew";

    #[tokio::test]
    async fn renew_auth_unknown_peer_is_404() {
        let state = renew_auth_test_state().await; // peers table empty
        let nonces = PeerNonceStore::with_grace(0);
        let headers = sign_headers(
            &seed_bytes(),
            "POST",
            RENEW_PATH,
            "",
            b"",
            now_secs(),
            &make_nonce(),
            "p1",
        );
        let r =
            require_peer_renew_auth(&*state, "POST", RENEW_PATH, "", &headers, b"", &nonces).await;
        let resp = r.unwrap_err();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND); // unknown -> 404 (NOT 403)
    }

    #[tokio::test]
    async fn renew_auth_not_paired_peer_is_403() {
        // Row exists in `peers` but pubkey is NULL -> 403 "peer not paired" (NOT 404).
        let state = renew_auth_test_state().await;
        sqlx::query(
            "INSERT INTO peers (peer_id, name, api_host, api_port, pubkey, created_at, updated_at) \
             VALUES ('p1','n','10.0.0.2',5000,NULL,0,0)",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let nonces = PeerNonceStore::with_grace(0);
        let headers = sign_headers(
            &seed_bytes(),
            "POST",
            RENEW_PATH,
            "",
            b"",
            now_secs(),
            &make_nonce(),
            "p1",
        );
        let r =
            require_peer_renew_auth(&*state, "POST", RENEW_PATH, "", &headers, b"", &nonces).await;
        assert_eq!(r.unwrap_err().status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn renew_auth_bad_signature_is_401() {
        let (state, _priv, _pub) = renew_auth_state_with_peer("p1").await;
        let nonces = PeerNonceStore::with_grace(0);
        // Sign with the WRONG key (any other 32-byte ed25519 seed).
        let wrong_key = [9u8; 32];
        let headers = sign_headers(
            &wrong_key,
            "POST",
            RENEW_PATH,
            "",
            b"",
            now_secs(),
            &make_nonce(),
            "p1",
        );
        let r =
            require_peer_renew_auth(&*state, "POST", RENEW_PATH, "", &headers, b"", &nonces).await;
        assert_eq!(
            r.unwrap_err().status(),
            axum::http::StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn renew_auth_happy_path_returns_peer_id() {
        let (state, priv_key, _pub) = renew_auth_state_with_peer("p1").await;
        let nonces = PeerNonceStore::with_grace(0); // D5 seam: accept nonces immediately
        let headers = sign_headers(
            &priv_key,
            "POST",
            RENEW_PATH,
            "",
            b"",
            now_secs(),
            &make_nonce(),
            "p1",
        );
        let peer_id =
            require_peer_renew_auth(&*state, "POST", RENEW_PATH, "", &headers, b"", &nonces)
                .await
                .unwrap();
        assert_eq!(peer_id, "p1");
    }

    #[tokio::test]
    async fn renew_auth_grace_is_503_and_forced_nonce_missing_is_401() {
        let (state, priv_key, _pub) = renew_auth_state_with_peer("p1").await;
        let ts = now_secs();
        // Missing nonce -> 401 even with a valid signature (forced nonce).
        let no_nonce = sign_headers(&priv_key, "POST", RENEW_PATH, "", b"", ts, "", "p1");
        let nonces_open = PeerNonceStore::with_grace(0);
        assert_eq!(
            require_peer_renew_auth(
                &*state,
                "POST",
                RENEW_PATH,
                "",
                &no_nonce,
                b"",
                &nonces_open
            )
            .await
            .unwrap_err()
            .status(),
            axum::http::StatusCode::UNAUTHORIZED
        );
        // Valid nonce but store in grace -> 503.
        let headers = sign_headers(
            &priv_key,
            "POST",
            RENEW_PATH,
            "",
            b"",
            ts,
            &make_nonce(),
            "p1",
        );
        let grace = PeerNonceStore::with_grace(3600);
        assert_eq!(
            require_peer_renew_auth(&*state, "POST", RENEW_PATH, "", &headers, b"", &grace)
                .await
                .unwrap_err()
                .status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
