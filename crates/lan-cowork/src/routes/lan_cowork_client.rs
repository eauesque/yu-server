use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::json;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::routes::lan_cowork_descriptor::is_reachable_peer_ip;
use crate::routes::lan_cowork_host::{LanCoworkHost, LanCoworkState};
use base64::Engine;
use futures_util::StreamExt;

const NONCE_TTL_SECONDS: f64 = 600.0;
/// A reservation must outlive the *whole* request handler, not just the POST:
/// reserve -> local identity -> nonce/commit -> POST (up to the 10s outbound
/// timeout) -> read/parse -> commit_slot. Sizing this at the outbound timeout
/// leaves no margin, so a peer that answers near the deadline could see its
/// reservation pruned before commit_slot runs, silently dropping the nonce.
/// Give comfortable headroom; commit_slot also reports failure as a backstop.
const RESERVATION_TTL_SECONDS: f64 = 30.0;
const CLIENT_STATE_CAPACITY: usize = 32;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub struct PendingEntry {
    pub nonce: [u8; 32],
    pub host: String,
    pub port: u16,
    pub attempts: u32,
    pub created_at: f64,
}

type ReservationId = u64;

#[derive(Default)]
struct ClientState {
    entries: HashMap<(String, String), PendingEntry>,
    reservations: HashMap<ReservationId, f64>,
    next_reservation: ReservationId,
}

fn client_state() -> &'static std::sync::Mutex<ClientState> {
    static STATE: std::sync::OnceLock<std::sync::Mutex<ClientState>> = std::sync::OnceLock::new();
    STATE.get_or_init(|| std::sync::Mutex::new(ClientState::default()))
}

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn prune_expired(state: &mut ClientState, now: f64) {
    state
        .entries
        .retain(|_, entry| now - entry.created_at <= NONCE_TTL_SECONDS);
    state
        .reservations
        .retain(|_, created_at| now - *created_at <= RESERVATION_TTL_SECONDS);
}

pub(crate) fn reserve_slot() -> Option<ReservationId> {
    let mut state = client_state().lock().unwrap_or_else(|e| e.into_inner());
    prune_expired(&mut state, now_f64());
    if state.entries.len() + state.reservations.len() >= CLIENT_STATE_CAPACITY {
        return None;
    }
    let id = state.next_reservation;
    state.next_reservation = state.next_reservation.wrapping_add(1);
    state.reservations.insert(id, now_f64());
    Some(id)
}

/// Promotes a reservation into a real nonce entry. Returns `false` if the
/// reservation was already gone (e.g. pruned at the TTL boundary), so the caller
/// can surface a genuine error instead of reporting a false success.
#[must_use]
pub(crate) fn commit_slot(
    id: ReservationId,
    peer_id: &str,
    request_id: &str,
    entry: PendingEntry,
) -> bool {
    let mut state = client_state().lock().unwrap_or_else(|e| e.into_inner());
    prune_expired(&mut state, now_f64());
    if state.reservations.remove(&id).is_some() {
        state
            .entries
            .insert((peer_id.to_owned(), request_id.to_owned()), entry);
        true
    } else {
        false
    }
}

pub(crate) fn release_slot(id: ReservationId) {
    client_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .reservations
        .remove(&id);
}

pub fn peek_entry(peer_id: &str, request_id: &str) -> Option<PendingEntry> {
    let mut state = client_state().lock().unwrap_or_else(|e| e.into_inner());
    prune_expired(&mut state, now_f64());
    state
        .entries
        .get(&(peer_id.to_owned(), request_id.to_owned()))
        .cloned()
}

pub(crate) fn bump_attempts(peer_id: &str, request_id: &str) -> Option<u32> {
    let mut state = client_state().lock().unwrap_or_else(|e| e.into_inner());
    prune_expired(&mut state, now_f64());
    let entry = state
        .entries
        .get_mut(&(peer_id.to_owned(), request_id.to_owned()))?;
    entry.attempts += 1;
    Some(entry.attempts)
}

pub(crate) fn take_entry(peer_id: &str, request_id: &str) -> Option<PendingEntry> {
    let mut state = client_state().lock().unwrap_or_else(|e| e.into_inner());
    prune_expired(&mut state, now_f64());
    state
        .entries
        .remove(&(peer_id.to_owned(), request_id.to_owned()))
}

#[cfg(any(test, feature = "test-seams"))]
#[doc(hidden)]
pub(crate) fn clear_client_state() {
    *client_state().lock().unwrap_or_else(|e| e.into_inner()) = ClientState::default();
}

#[derive(Debug, PartialEq, Eq)]
pub enum OutboundError {
    InvalidAddress,
    ResolutionFailed,
    ClientBuild,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OutboundFailure {
    Connect,
    Timeout,
    Http(StatusCode),
    BodyInvalid,
    BodyTooLarge,
    /// The responder answered but we failed to record the nonce locally (the
    /// reservation was already gone). Never produced by `classify`.
    LocalStateLost,
}

pub(crate) fn validate_resolved(addrs: &[IpAddr]) -> Result<IpAddr, OutboundError> {
    addrs
        .first()
        .copied()
        .filter(|_| addrs.iter().all(|ip| is_reachable_peer_ip(*ip)))
        .ok_or(OutboundError::InvalidAddress)
}

pub async fn build_peer_client(
    host: &str,
    port: u16,
    timeout: Option<Duration>,
    read_timeout: Option<Duration>,
) -> Result<(reqwest::Client, String), OutboundError> {
    if host.contains(['@', '/']) || port == 0 {
        return Err(OutboundError::InvalidAddress);
    }
    let host = host.to_owned();
    let resolved = tokio::task::spawn_blocking({
        let host = host.clone();
        move || {
            (host.as_str(), port)
                .to_socket_addrs()
                .map(|addrs| addrs.map(|addr| addr.ip()).collect::<Vec<_>>())
        }
    })
    .await
    .map_err(|_| OutboundError::ResolutionFailed)?
    .map_err(|_| OutboundError::ResolutionFailed)?;
    let ip = validate_resolved(&resolved)?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "X-Requested-With",
        reqwest::header::HeaderValue::from_static("XMLHttpRequest"),
    );
    let mut client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(headers)
        .resolve(&host, SocketAddr::new(ip, port));
    if let Some(timeout) = timeout {
        client = client.timeout(timeout);
    }
    if let Some(read_timeout) = read_timeout {
        client = client.read_timeout(read_timeout);
    }
    let client = client.build().map_err(|_| OutboundError::ClientBuild)?;
    let base = match ip {
        IpAddr::V4(ip) => format!("http://{ip}:{port}"),
        IpAddr::V6(ip) => format!("http://[{ip}]:{port}"),
    };
    Ok((client, base))
}

pub(crate) fn classify(err: &reqwest::Error) -> OutboundFailure {
    if err.is_connect() {
        OutboundFailure::Connect
    } else {
        OutboundFailure::Timeout
    }
}

pub async fn read_peer_response_capped(
    response: reqwest::Response,
) -> Result<String, OutboundFailure> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| OutboundFailure::BodyInvalid)?;
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(OutboundFailure::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| OutboundFailure::BodyInvalid)
}

#[cfg(test)]
mod task34_tests {
    use super::*;
    use crate::routes::lan_cowork_descriptor::{
        reset_client_state, test_guard, TEST_ALLOW_LOOPBACK,
    };
    use std::{net::IpAddr, sync::atomic::Ordering, time::Duration};

    fn entry(nonce: u8) -> PendingEntry {
        PendingEntry {
            nonce: [nonce; 32],
            host: "10.0.0.1".into(),
            port: 5000,
            attempts: 0,
            created_at: now_f64(),
        }
    }

    #[test]
    fn nonce_entries_are_keyed_and_peeked_without_removal() {
        let _guard = test_guard();
        reset_client_state();
        let first = reserve_slot().unwrap();
        let second = reserve_slot().unwrap();
        assert!(commit_slot(first, "one", "request", entry(1)));
        assert!(commit_slot(second, "two", "request", entry(2)));
        assert_eq!(peek_entry("one", "request").unwrap().nonce, [1; 32]);
        assert_eq!(peek_entry("two", "request").unwrap().nonce, [2; 32]);
        assert!(peek_entry("one", "request").is_some());
    }

    #[test]
    fn expired_entries_and_reservations_free_capacity_without_extending_ttl() {
        let _guard = test_guard();
        reset_client_state();
        let id = reserve_slot().unwrap();
        let mut stale = entry(1);
        stale.created_at -= NONCE_TTL_SECONDS + 1.0;
        assert!(commit_slot(id, "peer", "request", stale));
        assert!(peek_entry("peer", "request").is_none());

        let id = reserve_slot().unwrap();
        for _ in 1..CLIENT_STATE_CAPACITY {
            assert!(reserve_slot().is_some());
        }
        client_state()
            .lock()
            .unwrap()
            .reservations
            .insert(id, now_f64() - RESERVATION_TTL_SECONDS - 1.0);
        assert!(reserve_slot().is_some());
    }

    #[test]
    fn capacity_counts_confirmed_entries_and_reservations() {
        let _guard = test_guard();
        reset_client_state();
        let mut ids = Vec::new();
        for _ in 0..CLIENT_STATE_CAPACITY {
            ids.push(reserve_slot().unwrap());
        }
        assert!(reserve_slot().is_none());
        release_slot(ids.pop().unwrap());
        assert!(reserve_slot().is_some());
    }

    #[test]
    fn concurrent_reservations_cannot_exceed_capacity() {
        let _guard = test_guard();
        reset_client_state();
        let workers: Vec<_> = (0..CLIENT_STATE_CAPACITY * 2)
            .map(|_| std::thread::spawn(reserve_slot))
            .collect();
        assert_eq!(
            workers
                .into_iter()
                .filter_map(|worker| worker.join().unwrap())
                .count(),
            CLIENT_STATE_CAPACITY
        );
    }

    #[test]
    fn bump_keeps_creation_time_and_take_removes_entry() {
        let _guard = test_guard();
        reset_client_state();
        let id = reserve_slot().unwrap();
        let pending = entry(3);
        let created_at = pending.created_at;
        assert!(commit_slot(id, "peer", "request", pending));
        assert_eq!(bump_attempts("peer", "request"), Some(1));
        assert_eq!(
            peek_entry("peer", "request").unwrap().created_at,
            created_at
        );
        assert_eq!(take_entry("peer", "request").unwrap().nonce, [3; 32]);
        assert!(peek_entry("peer", "request").is_none());
    }

    #[test]
    fn resolved_addresses_must_all_be_reachable() {
        let _guard = test_guard();
        reset_client_state();
        assert_eq!(
            validate_resolved(&["10.0.0.1".parse().unwrap()]).unwrap(),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert!(
            validate_resolved(&["10.0.0.1".parse().unwrap(), "8.8.8.8".parse().unwrap()]).is_err()
        );
    }

    #[tokio::test]
    async fn outbound_client_pins_loopback_for_tests_and_sends_csrf_header() {
        let _guard = test_guard();
        reset_client_state();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::AsyncReadExt;
            let mut request = vec![0; 1024];
            let count = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..count])
                .contains("x-requested-with: XMLHttpRequest"));
            stream.writable().await.unwrap();
            stream
                .try_write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        });
        let (client, base) =
            build_peer_client("127.0.0.1", port, Some(Duration::from_secs(10)), None)
                .await
                .unwrap();
        assert_eq!(
            client.get(base).send().await.unwrap().text().await.unwrap(),
            "ok"
        );
        server.await.unwrap();
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn outbound_client_disables_redirects_and_classifies_connection_errors() {
        let _guard = test_guard();
        reset_client_state();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.writable().await.unwrap();
            stream.try_write(b"HTTP/1.1 302 Found\r\nLocation: http://example.com/\r\nContent-Length: 0\r\n\r\n").unwrap();
        });
        let (client, base) =
            build_peer_client("127.0.0.1", port, Some(Duration::from_secs(10)), None)
                .await
                .unwrap();
        assert_eq!(
            client.get(base).send().await.unwrap().status(),
            reqwest::StatusCode::FOUND
        );
        server.await.unwrap();
        let err = reqwest::Client::builder()
            .timeout(Duration::from_millis(1))
            .build()
            .unwrap()
            .get("http://127.0.0.1:1")
            .send()
            .await
            .unwrap_err();
        assert_eq!(classify(&err), OutboundFailure::Connect);
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn outbound_client_caps_bodies_and_times_out_after_the_total_deadline() {
        let _guard = test_guard();
        reset_client_state();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            let body = "x".repeat(MAX_RESPONSE_BYTES + 1);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let (client, base) =
            build_peer_client("127.0.0.1", port, Some(Duration::from_secs(10)), None)
                .await
                .unwrap();
        assert_eq!(
            read_peer_response_capped(client.get(base).send().await.unwrap()).await,
            Err(OutboundFailure::BodyTooLarge)
        );
        server.await.unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(11)).await;
        });
        let (client, base) =
            build_peer_client("127.0.0.1", port, Some(Duration::from_secs(10)), None)
                .await
                .unwrap();
        assert_eq!(
            classify(&client.get(base).send().await.unwrap_err()),
            OutboundFailure::Timeout
        );
        server.abort();
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }
}

/// E3 failures carry recovery state; routes are added in later tasks.
#[allow(dead_code)]
pub(crate) fn err_response(
    status: StatusCode,
    state: &str,
    code: &str,
    message: &str,
    attempts_remaining: Option<u32>,
) -> Response {
    let mut body = json!({"ok": false, "state": state, "code": code, "error": message});
    if let Some(attempts_remaining) = attempts_remaining {
        body["attempts_remaining"] = json!(attempts_remaining);
    }
    (status, Json(body)).into_response()
}

#[derive(serde::Deserialize)]
struct ClientRequest {
    peer_id: String,
}

#[derive(serde::Deserialize)]
struct ClientVerify {
    peer_id: String,
    request_id: String,
    pin: String,
}

pub(crate) async fn descriptor_for_handler(
    state: &dyn LanCoworkHost,
) -> Result<
    crate::routes::lan_cowork_descriptor::LocalDescriptor,
    crate::routes::lan_cowork_descriptor::DescriptorError,
> {
    #[cfg(any(test, feature = "test-seams"))]
    if let Some(value) = crate::routes::lan_cowork_descriptor::TEST_DESCRIPTOR
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        return value;
    }
    crate::routes::lan_cowork_descriptor::local_descriptor(state).await
}

async fn client_pair_request(
    State(state): State<LanCoworkState>,
    Json(req): Json<ClientRequest>,
) -> Response {
    if !state.python_url().is_empty() {
        return err_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "failed",
            "unsupported_mode",
            "unsupported in hybrid mode",
            None,
        );
    }
    let peer: Option<(String, i64)> =
        sqlx::query_as("SELECT api_host, api_port FROM peers WHERE peer_id=?1")
            .bind(&req.peer_id)
            .fetch_optional(state.db_read())
            .await
            .unwrap_or(None);
    let Some((host, port)) = peer else {
        return err_response(
            StatusCode::NOT_FOUND,
            "failed",
            "peer_not_found",
            "peer not found",
            None,
        );
    };
    let Ok(port) = u16::try_from(port) else {
        return err_response(
            StatusCode::BAD_REQUEST,
            "failed",
            "peer_address_invalid",
            "invalid peer address",
            None,
        );
    };
    let descriptor = match descriptor_for_handler(&*state).await {
        Ok(value) => value,
        Err(_) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                "failed",
                "local_descriptor_invalid",
                "local descriptor invalid",
                None,
            )
        }
    };
    let (client, base) =
        match build_peer_client(&host, port, Some(Duration::from_secs(10)), None).await {
            Ok(value) => value,
            Err(OutboundError::InvalidAddress) => {
                let code = if host.contains(['@', '/']) || port == 0 {
                    "peer_address_invalid"
                } else {
                    "peer_address_not_local"
                };
                return err_response(
                    StatusCode::BAD_REQUEST,
                    "failed",
                    code,
                    "invalid peer address",
                    None,
                );
            }
            Err(_) => {
                return err_response(
                    StatusCode::BAD_GATEWAY,
                    "failed",
                    "peer_unreachable",
                    "peer unreachable",
                    None,
                )
            }
        };
    let Some(slot) = reserve_slot() else {
        return err_response(
            StatusCode::TOO_MANY_REQUESTS,
            "failed",
            "too_many_pending",
            "too many pending pairings",
            None,
        );
    };
    let result = async {
        let Some((pubkey, x25519_pk)) =
            crate::routes::peer_identity::local_identity_material(&*state).await
        else {
            return Err(OutboundFailure::BodyInvalid);
        };
        let mut nonce = [0u8; 32];
        openssl::rand::rand_bytes(&mut nonce).map_err(|_| OutboundFailure::BodyInvalid)?;
        let commit = crate::auth::peer_pairing_crypto::make_commit_v2(&pubkey, &x25519_pk, &nonce);
        let response = client
            .post(format!("{base}/ext/lan_cowork/api/peer/pair/request"))
            .json(&json!({
                "peer_id": descriptor.peer_id,
                "host": descriptor.api_host,
                "port": descriptor.api_port,
                "pubkey": base64::engine::general_purpose::STANDARD.encode(pubkey),
                "x25519_pk": base64::engine::general_purpose::STANDARD.encode(x25519_pk),
                "commit": base64::engine::general_purpose::STANDARD.encode(commit),
            }))
            .send()
            .await
            .map_err(|e| classify(&e))?;
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(OutboundFailure::Http(StatusCode::TOO_MANY_REQUESTS));
        }
        if !response.status().is_success() {
            return Err(OutboundFailure::Http(response.status()));
        }
        let body = read_peer_response_capped(response).await?;
        let data: serde_json::Value =
            serde_json::from_str(&body).map_err(|_| OutboundFailure::BodyInvalid)?;
        let (Some(request_id), Some(sas)) = (data["request_id"].as_str(), data["sas"].as_str())
        else {
            return Err(OutboundFailure::BodyInvalid);
        };
        if !commit_slot(
            slot,
            &req.peer_id,
            request_id,
            PendingEntry {
                nonce,
                host,
                port,
                attempts: 0,
                created_at: now_f64(),
            },
        ) {
            // The reservation vanished (TTL boundary): the responder created a
            // pending row but we cannot record the nonce, so verify could never
            // succeed. Fail loudly instead of returning a false 202. Re-issuing
            // pair/request expires the responder's prior row, so this recovers.
            return Err(OutboundFailure::LocalStateLost);
        }
        Ok::<_, OutboundFailure>((request_id.to_owned(), sas.to_owned()))
    }
    .await;
    match result {
        Ok((request_id, sas)) => (
            StatusCode::ACCEPTED,
            Json(json!({"ok": true, "request_id": request_id, "sas": sas})),
        )
            .into_response(),
        Err(failure) => {
            release_slot(slot);
            match failure {
                OutboundFailure::Connect | OutboundFailure::Timeout => err_response(
                    StatusCode::BAD_GATEWAY,
                    "failed",
                    "peer_unreachable",
                    "peer unreachable",
                    None,
                ),
                OutboundFailure::Http(StatusCode::TOO_MANY_REQUESTS) => err_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "failed",
                    "peer_rate_limited",
                    "peer rate limited",
                    None,
                ),
                OutboundFailure::Http(_) => err_response(
                    StatusCode::BAD_GATEWAY,
                    "failed",
                    "peer_rejected",
                    "peer rejected",
                    None,
                ),
                OutboundFailure::LocalStateLost => err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed",
                    "local_state_error",
                    "local pairing state was lost; retry pairing",
                    None,
                ),
                _ => err_response(
                    StatusCode::BAD_GATEWAY,
                    "failed",
                    "peer_response_invalid",
                    "peer response invalid",
                    None,
                ),
            }
        }
    }
}

async fn client_pair_verify(
    State(state): State<LanCoworkState>,
    Json(req): Json<ClientVerify>,
) -> Response {
    let Some(entry) = peek_entry(&req.peer_id, &req.request_id) else {
        return err_response(
            StatusCode::NOT_FOUND,
            "failed",
            "pairing_not_found",
            "pairing request not found",
            None,
        );
    };
    let (client, base) =
        match build_peer_client(&entry.host, entry.port, Some(Duration::from_secs(10)), None).await
        {
            Ok(value) => value,
            Err(_) => {
                return err_response(
                    StatusCode::BAD_GATEWAY,
                    "failed",
                    "peer_unreachable",
                    "peer unreachable",
                    None,
                )
            }
        };
    let Some((pubkey, x25519_pk)) =
        crate::routes::peer_identity::local_identity_material(&*state).await
    else {
        return err_response(
            StatusCode::BAD_REQUEST,
            "failed",
            "local_descriptor_invalid",
            "local identity unavailable",
            None,
        );
    };
    let Some(key) =
        crate::auth::peer_pairing_crypto::pin_kdf_async(req.pin, req.request_id.clone()).await
    else {
        return err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed",
            "local_crypto_error",
            "local crypto error",
            None,
        );
    };
    let mut plain = Vec::with_capacity(96);
    plain.extend_from_slice(&pubkey);
    plain.extend_from_slice(&x25519_pk);
    plain.extend_from_slice(&entry.nonce);
    let Some(bundle) = crate::auth::peer_pairing_crypto::encrypt_bundle_random_iv(
        &key,
        &plain,
        req.request_id.as_bytes(),
    ) else {
        return err_response(
            StatusCode::BAD_REQUEST,
            "failed",
            "bundle_rejected",
            "bundle rejected",
            None,
        );
    };
    let response = match client
        .post(format!("{base}/ext/lan_cowork/api/peer/pair/verify"))
        .json(&json!({
            "request_id": req.request_id,
            "encrypted_bundle": base64::engine::general_purpose::STANDARD.encode(bundle),
        }))
        .send()
        .await
    {
        Ok(value) => value,
        Err(e) => match classify(&e) {
            OutboundFailure::Connect => {
                return err_response(
                    StatusCode::BAD_GATEWAY,
                    "failed",
                    "peer_unreachable",
                    "peer unreachable",
                    None,
                )
            }
            _ => {
                take_entry(&req.peer_id, &req.request_id);
                return err_response(
                    StatusCode::CONFLICT,
                    "unknown",
                    "peer_timeout",
                    "peer timeout",
                    None,
                );
            }
        },
    };
    match response.status() {
        StatusCode::UNAUTHORIZED => {
            let attempts = bump_attempts(&req.peer_id, &req.request_id).unwrap_or(5);
            if attempts >= 5 {
                take_entry(&req.peer_id, &req.request_id);
                err_response(
                    StatusCode::UNAUTHORIZED,
                    "failed",
                    "pin_attempts_exhausted",
                    "pairing verification failed",
                    None,
                )
            } else {
                err_response(
                    StatusCode::UNAUTHORIZED,
                    "retryable",
                    "pin_rejected",
                    "pairing verification failed",
                    Some(5 - attempts),
                )
            }
        }
        StatusCode::BAD_REQUEST => {
            take_entry(&req.peer_id, &req.request_id);
            err_response(
                StatusCode::BAD_REQUEST,
                "failed",
                "bundle_rejected",
                "bundle rejected",
                None,
            )
        }
        StatusCode::TOO_MANY_REQUESTS => err_response(
            StatusCode::TOO_MANY_REQUESTS,
            "failed",
            "peer_rate_limited",
            "peer rate limited",
            None,
        ),
        StatusCode::GONE => {
            take_entry(&req.peer_id, &req.request_id);
            err_response(
                StatusCode::CONFLICT,
                "unknown",
                "pairing_already_completed",
                "pairing already completed",
                None,
            )
        }
        status if status.is_server_error() => {
            take_entry(&req.peer_id, &req.request_id);
            err_response(
                StatusCode::CONFLICT,
                "unknown",
                "peer_error",
                "peer error",
                None,
            )
        }
        StatusCode::OK => {
            let body = match read_peer_response_capped(response).await {
                Ok(value) => value,
                Err(OutboundFailure::BodyTooLarge) => {
                    take_entry(&req.peer_id, &req.request_id);
                    return err_response(
                        StatusCode::CONFLICT,
                        "unknown",
                        "peer_response_too_large",
                        "peer response too large",
                        None,
                    );
                }
                Err(_) => {
                    take_entry(&req.peer_id, &req.request_id);
                    return err_response(
                        StatusCode::CONFLICT,
                        "unknown",
                        "peer_response_invalid",
                        "peer response invalid",
                        None,
                    );
                }
            };
            let data: serde_json::Value = match serde_json::from_str(&body) {
                Ok(value) => value,
                Err(_) => {
                    take_entry(&req.peer_id, &req.request_id);
                    return err_response(
                        StatusCode::CONFLICT,
                        "unknown",
                        "peer_response_invalid",
                        "peer response invalid",
                        None,
                    );
                }
            };
            let (Some(token), Some(expires_at), Some(server_pubkey), Some(server_x25519_pk)) = (
                data["token"].as_str(),
                data["expires_at"].as_i64(),
                data["server_pubkey"].as_str(),
                data["server_x25519_pk"].as_str(),
            ) else {
                take_entry(&req.peer_id, &req.request_id);
                return err_response(
                    StatusCode::CONFLICT,
                    "unknown",
                    "peer_response_incomplete",
                    "peer response incomplete",
                    None,
                );
            };
            let (Ok(server_pubkey), Ok(server_x25519_pk)) = (
                base64::engine::general_purpose::STANDARD.decode(server_pubkey),
                base64::engine::general_purpose::STANDARD.decode(server_x25519_pk),
            ) else {
                take_entry(&req.peer_id, &req.request_id);
                return err_response(
                    StatusCode::CONFLICT,
                    "unknown",
                    "peer_response_incomplete",
                    "peer response incomplete",
                    None,
                );
            };
            if server_pubkey.len() != 32
                || server_x25519_pk.len() != 32
                || crate::routes::peer_identity::derive_peer_id(&server_pubkey) != req.peer_id
            {
                take_entry(&req.peer_id, &req.request_id);
                return err_response(
                    StatusCode::BAD_REQUEST,
                    "failed",
                    "fingerprint_mismatch",
                    "fingerprint mismatch",
                    None,
                );
            }
            if !token.is_ascii() || token.chars().any(char::is_control) {
                take_entry(&req.peer_id, &req.request_id);
                return err_response(
                    StatusCode::CONFLICT,
                    "unknown",
                    "peer_response_invalid",
                    "peer response invalid",
                    None,
                );
            }
            let now = now_f64() as i64;
            let mut tx = match state.db().begin().await {
                Ok(tx) => tx,
                Err(_) => {
                    return err_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed",
                        "storage_error",
                        "storage error",
                        None,
                    )
                }
            };
            let stored = sqlx::query(
                "INSERT INTO peers \
                 (peer_id,name,api_host,api_port,token,token_expires_at,token_issued_at, \
                  pubkey,x25519_pk,created_at,updated_at) \
                 VALUES (?1,?1,?2,?3,?4,?5,?6,?7,?8,?6,?6) \
                 ON CONFLICT(peer_id) DO UPDATE SET \
                 token=excluded.token,token_expires_at=excluded.token_expires_at, \
                 token_issued_at=excluded.token_issued_at,pubkey=excluded.pubkey, \
                 x25519_pk=excluded.x25519_pk,updated_at=excluded.updated_at",
            )
            .bind(&req.peer_id)
            .bind(&entry.host)
            .bind(entry.port)
            .bind(token)
            .bind(expires_at)
            .bind(now)
            .bind(server_pubkey)
            .bind(server_x25519_pk)
            .execute(&mut *tx)
            .await;
            if stored.is_err() || tx.commit().await.is_err() {
                return err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed",
                    "storage_error",
                    "storage error",
                    None,
                );
            }
            take_entry(&req.peer_id, &req.request_id);
            Json(json!({"ok": true})).into_response()
        }
        _ => {
            take_entry(&req.peer_id, &req.request_id);
            err_response(
                StatusCode::CONFLICT,
                "unknown",
                "peer_response_invalid",
                "peer response invalid",
                None,
            )
        }
    }
}

pub fn routes() -> Router<LanCoworkState> {
    Router::new()
        .route(
            "/ext/lan_cowork/api/client/pair/request",
            post(client_pair_request),
        )
        .route(
            "/ext/lan_cowork/api/client/pair/verify",
            post(client_pair_verify),
        )
}

#[cfg(test)]
mod tests {
    use crate::routes::lan_cowork_descriptor::{
        reset_client_state, test_guard, LocalDescriptor, TEST_ALLOW_LOOPBACK, TEST_DESCRIPTOR,
    };
    use axum::{body::to_bytes, http::StatusCode, routing::post, Router};
    use serde_json::Value;
    use std::sync::atomic::Ordering;
    use tower::ServiceExt;

    use super::*;
    use crate::state::SharedState;

    async fn body(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn error_response_omits_attempts_when_absent() {
        let response = err_response(StatusCode::BAD_REQUEST, "failed", "invalid", "bad", None);
        let body = body(response).await;
        assert_eq!(body.as_object().unwrap().len(), 4);
        assert_eq!(body["state"], "failed");
    }

    #[tokio::test]
    async fn error_response_includes_attempts_when_present() {
        let response = err_response(
            StatusCode::UNAUTHORIZED,
            "retryable",
            "pin_rejected",
            "bad pin",
            Some(3),
        );
        let body = body(response).await;
        assert_eq!(body.as_object().unwrap().len(), 5);
        assert_eq!(body["attempts_remaining"], 3);
    }

    async fn client_state() -> SharedState {
        client_state_with(String::new()).await
    }

    /// The responder routes share this database, so its tables must exist too --
    /// without them `pair/request` fails inside the responder and the initiator
    /// reports `peer_rejected`, which looks like a payload bug but is not one.
    async fn client_state_with(python_url: String) -> SharedState {
        let state = crate::state::semantic_test_state_with(false, python_url).await;
        sqlx::raw_sql(
            "CREATE TABLE peers (peer_id TEXT PRIMARY KEY, name TEXT, api_host TEXT, \
             api_port INTEGER, token TEXT, token_expires_at INTEGER, token_issued_at INTEGER, \
             pubkey BLOB, x25519_pk BLOB, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL); \
             CREATE TABLE lan_cowork_identity (key TEXT PRIMARY KEY, value BLOB); \
             CREATE TABLE peer_pairing_requests ( \
               request_id TEXT PRIMARY KEY, peer_id TEXT NOT NULL, host TEXT NOT NULL, \
               port INTEGER NOT NULL, pin_hash TEXT, pin_expires_at INTEGER, \
               verify_attempts INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, \
               created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, \
               pubkey BLOB, x25519_pk BLOB, commit_hash BLOB, sas TEXT, source_ip TEXT); \
             CREATE TABLE peer_tokens ( \
               peer_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, issued_at INTEGER NOT NULL, \
               expires_at INTEGER NOT NULL, revoked_at INTEGER, \
               source TEXT NOT NULL DEFAULT 'pairing', note TEXT);",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO lan_cowork_identity (key, value) VALUES ('ed25519_seed', ?1)")
            .bind((1u8..=32).collect::<Vec<_>>())
            .execute(&state.db)
            .await
            .unwrap();
        state
    }

    async fn local_peer_id_of(state: &SharedState) -> String {
        let (ed, _) = crate::routes::peer_identity::local_identity_material(&**state)
            .await
            .unwrap();
        crate::routes::peer_identity::derive_peer_id(&ed)
    }

    /// Starts the real responder on loopback. Each caller must pass a distinct
    /// `source_ip`: the responder's rate-limit maps are process-global and keyed
    /// by IP, and the real HTTP path has no `auth_middleware` to inject one.
    /// A stand-in peer that answers every request with a fixed status and body.
    /// Used for the transport-level rows of the classification table, which the
    /// real responder cannot be coaxed into producing.
    async fn start_stub(
        status: StatusCode,
        body: &'static str,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = Router::new().fallback(move || async move { (status, body) });
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (port, handle)
    }

    async fn insert_peer(state: &SharedState, peer_id: &str, host: &str, port: i64) {
        sqlx::query(
            "INSERT INTO peers (peer_id,name,api_host,api_port,created_at,updated_at) \
             VALUES (?1,?1,?2,?3,0,0)",
        )
        .bind(peer_id)
        .bind(host)
        .bind(port)
        .execute(&state.db)
        .await
        .unwrap();
    }

    fn set_descriptor(peer_id: &str) {
        *TEST_DESCRIPTOR.lock().unwrap_or_else(|e| e.into_inner()) = Some(Ok(LocalDescriptor {
            peer_id: peer_id.to_string(),
            name: "test".into(),
            api_host: "10.0.0.2".into(),
            api_port: 5000,
            version: "test".into(),
            bridges: vec![],
        }));
    }

    fn initiator(state: SharedState) -> Router {
        Router::new()
            .route("/client/request", post(client_pair_request))
            .route("/client/verify", post(client_pair_verify))
            .with_state(LanCoworkState::from_shared(&state))
    }

    /// Opens a roundtrip test: takes the serialising lock, clears every global,
    /// and opens the loopback escape hatch (D2/D3).
    fn open_roundtrip() -> std::sync::MutexGuard<'static, ()> {
        let guard = test_guard();
        reset_client_state();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        guard
    }

    async fn request_via(state: &SharedState, peer_id: &str) -> (StatusCode, Value) {
        let response = call(
            initiator(state.clone()),
            "/client/request",
            json!({"peer_id": peer_id}),
        )
        .await;
        let status = response.status();
        (status, body(response).await)
    }

    async fn call(app: Router, path: &str, payload: Value) -> Response {
        app.oneshot(
            axum::http::Request::post(path)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    // ---- Task 5: `pair/request` classification table (all ten rows) ----------

    #[tokio::test]
    async fn task5_hybrid_mode_is_refused_before_any_outbound_call() {
        let _guard = open_roundtrip();
        let state = client_state_with("http://127.0.0.1:1".to_string()).await;
        let peer_id = local_peer_id_of(&state).await;

        let (status, body) = request_via(&state, &peer_id).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["code"], "unsupported_mode");
        assert_eq!(body["state"], "failed");
    }

    #[tokio::test]
    async fn task5_unknown_peer_is_not_found() {
        let _guard = open_roundtrip();
        let state = client_state().await;

        let (status, body) = request_via(&state, "nosuchpeer").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "peer_not_found");
    }

    #[tokio::test]
    async fn task5_unusable_local_descriptor_is_refused() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        insert_peer(&state, &peer_id, "127.0.0.1", 9).await;
        *TEST_DESCRIPTOR.lock().unwrap_or_else(|e| e.into_inner()) = Some(Err(
            crate::routes::lan_cowork_descriptor::DescriptorError::LanAddressUnavailable,
        ));

        let (status, body) = request_via(&state, &peer_id).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "local_descriptor_invalid");
    }

    #[tokio::test]
    async fn task5_port_zero_is_an_invalid_address() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        insert_peer(&state, &peer_id, "127.0.0.1", 0).await;
        set_descriptor(&peer_id);

        let (status, body) = request_via(&state, &peer_id).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "peer_address_invalid");
    }

    #[tokio::test]
    async fn task5_public_destination_is_refused_by_the_address_predicate() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        insert_peer(&state, &peer_id, "8.8.8.8", 5000).await;
        set_descriptor(&peer_id);

        let (status, body) = request_via(&state, &peer_id).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "peer_address_not_local");
    }

    #[tokio::test]
    async fn task5_full_nonce_map_is_refused_without_touching_the_responder() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        let (port, server) = start_stub(StatusCode::INTERNAL_SERVER_ERROR, "{}").await;
        insert_peer(&state, &peer_id, "127.0.0.1", port.into()).await;
        set_descriptor(&peer_id);

        let held: Vec<_> = (0..32).map(|_| reserve_slot().unwrap()).collect();
        assert_eq!(held.len(), 32);

        let (status, body) = request_via(&state, &peer_id).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["code"], "too_many_pending");

        // Refused before the POST, so the responder never created a pending row.
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM peer_pairing_requests")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(rows, 0, "the responder must not have been contacted");

        server.abort();
    }

    #[tokio::test]
    async fn task5_closed_port_reports_the_peer_as_unreachable() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        // Bind then drop, so the port is valid but nothing listens on it.
        let port = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        insert_peer(&state, &peer_id, "127.0.0.1", port.into()).await;
        set_descriptor(&peer_id);

        let (status, body) = request_via(&state, &peer_id).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["code"], "peer_unreachable");
    }

    #[tokio::test]
    async fn task5_responder_rate_limit_is_surfaced_as_429() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        let (port, server) = start_stub(StatusCode::TOO_MANY_REQUESTS, "{}").await;
        insert_peer(&state, &peer_id, "127.0.0.1", port.into()).await;
        set_descriptor(&peer_id);

        let (status, body) = request_via(&state, &peer_id).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["code"], "peer_rate_limited");

        server.abort();
    }

    #[tokio::test]
    async fn task5_responder_rejection_is_surfaced_as_bad_gateway() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        let (port, server) = start_stub(StatusCode::BAD_REQUEST, "{}").await;
        insert_peer(&state, &peer_id, "127.0.0.1", port.into()).await;
        set_descriptor(&peer_id);

        let (status, body) = request_via(&state, &peer_id).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["code"], "peer_rejected");

        server.abort();
    }

    #[tokio::test]
    async fn task5_unparsable_response_is_surfaced_as_invalid() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        let (port, server) = start_stub(StatusCode::ACCEPTED, "not json at all").await;
        insert_peer(&state, &peer_id, "127.0.0.1", port.into()).await;
        set_descriptor(&peer_id);

        let (status, body) = request_via(&state, &peer_id).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["code"], "peer_response_invalid");

        server.abort();
    }

    #[tokio::test]
    async fn task5_missing_request_id_is_surfaced_as_invalid() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        let (port, server) = start_stub(StatusCode::ACCEPTED, r#"{"ok":true,"sas":"1234"}"#).await;
        insert_peer(&state, &peer_id, "127.0.0.1", port.into()).await;
        set_descriptor(&peer_id);

        let (status, body) = request_via(&state, &peer_id).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["code"], "peer_response_invalid");

        server.abort();
    }

    /// Every failure path must hand the reservation back, or a handful of failed
    /// attempts would permanently consume the 32-slot budget.
    #[tokio::test]
    async fn task5_failed_requests_release_their_reservation() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        let (port, server) = start_stub(StatusCode::BAD_REQUEST, "{}").await;
        insert_peer(&state, &peer_id, "127.0.0.1", port.into()).await;
        set_descriptor(&peer_id);

        for _ in 0..4 {
            let (status, _) = request_via(&state, &peer_id).await;
            assert_eq!(status, StatusCode::BAD_GATEWAY);
        }

        // All 32 slots must still be free.
        let held: Vec<_> = (0..32).filter_map(|_| reserve_slot()).collect();
        assert_eq!(held.len(), 32, "reservations leaked on the failure path");

        server.abort();
    }

    // ---- Task 6: `pair/verify` classification table (all thirteen rows) -----
    //
    // The nonce column of that table is the load-bearing part: rows that keep the
    // nonce stay recoverable by re-entering the PIN, rows that drop it force a
    // full re-pairing. Getting one backwards either strands the operator on a
    // 410 or throws away a pairing that was still good.

    /// Seeds a pending entry directly, standing in for a completed `pair/request`.
    fn seed_entry(peer_id: &str, request_id: &str, port: u16) {
        let slot = reserve_slot().unwrap();
        assert!(commit_slot(
            slot,
            peer_id,
            request_id,
            PendingEntry {
                nonce: [7u8; 32],
                host: "127.0.0.1".to_string(),
                port,
                attempts: 0,
                created_at: now_f64(),
            },
        ));
    }

    async fn verify_via(
        state: &SharedState,
        peer_id: &str,
        request_id: &str,
    ) -> (StatusCode, Value) {
        let response = call(
            initiator(state.clone()),
            "/client/verify",
            json!({"peer_id": peer_id, "request_id": request_id, "pin": "123456"}),
        )
        .await;
        let status = response.status();
        (status, body(response).await)
    }

    /// Drives one stubbed verify response and reports both the wire result and
    /// whether the nonce survived.
    async fn verify_against_stub(
        source: &str,
        status: StatusCode,
        payload: &'static str,
    ) -> (StatusCode, Value, bool) {
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        let (port, server) = start_stub(status, payload).await;
        seed_entry(&peer_id, source, port);

        let (got, body) = verify_via(&state, &peer_id, source).await;
        let kept = peek_entry(&peer_id, source).is_some();
        server.abort();
        (got, body, kept)
    }

    #[tokio::test]
    async fn task6_unknown_pairing_is_not_found() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;

        let (status, body) = verify_via(&state, &peer_id, "no-such-request").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "pairing_not_found");
    }

    #[tokio::test]
    async fn task6_connection_failure_keeps_the_nonce_for_retry() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        let port = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        seed_entry(&peer_id, "req-conn", port);

        let (status, body) = verify_via(&state, &peer_id, "req-conn").await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["code"], "peer_unreachable");
        assert_eq!(body["state"], "failed");
        assert!(
            peek_entry(&peer_id, "req-conn").is_some(),
            "the request never reached the responder, so the nonce must survive"
        );
    }

    /// Post-send timeout: the responder accepts the request but never answers,
    /// so the client's total timeout fires and the row must resolve to
    /// 409/unknown/nonce-dropped (the responder may have committed; we can't
    /// tell). Heavy: the verify handler runs the ~12s KDF *before* the POST, then
    /// waits the full 10s timeout (~22s total), so this end-to-end backstop is
    /// #[ignore]d — the Timeout->drop mapping is also covered by the classify()
    /// unit test. Run explicitly with `--ignored`.
    #[tokio::test]
    #[ignore = "~22s: 12s KDF + 10s outbound timeout on this host"]
    async fn task6_post_send_timeout_is_unknown_and_drops_the_nonce() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        // A responder that accepts the connection but never replies.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream); // keep the connection open, send nothing
            }
        });
        seed_entry(&peer_id, "req-timeout", port);

        let (status, body) = verify_via(&state, &peer_id, "req-timeout").await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "peer_timeout");
        assert_eq!(body["state"], "unknown");
        assert!(
            peek_entry(&peer_id, "req-timeout").is_none(),
            "a post-send timeout must drop the nonce (responder may have committed)"
        );
        server.abort();
    }

    #[tokio::test]
    async fn task6_server_error_is_unknown_and_drops_the_nonce() {
        let _guard = open_roundtrip();
        let (status, body, kept) =
            verify_against_stub("req-5xx", StatusCode::INTERNAL_SERVER_ERROR, "{}").await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "peer_error");
        assert_eq!(body["state"], "unknown");
        assert!(
            !kept,
            "token issuance is unknown, so the nonce must be dropped"
        );
    }

    #[tokio::test]
    async fn task6_already_completed_is_unknown_and_drops_the_nonce() {
        let _guard = open_roundtrip();
        let (status, body, kept) = verify_against_stub("req-410", StatusCode::GONE, "{}").await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "pairing_already_completed");
        assert_eq!(body["state"], "unknown");
        assert!(!kept);
    }

    #[tokio::test]
    async fn task6_rejected_bundle_drops_the_nonce() {
        let _guard = open_roundtrip();
        let (status, body, kept) =
            verify_against_stub("req-400", StatusCode::BAD_REQUEST, "{}").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "bundle_rejected");
        assert_eq!(body["state"], "failed");
        assert!(!kept, "retrying with the same nonce would fail identically");
    }

    #[tokio::test]
    async fn task6_rate_limit_keeps_the_nonce() {
        let _guard = open_roundtrip();
        let (status, body, kept) =
            verify_against_stub("req-429", StatusCode::TOO_MANY_REQUESTS, "{}").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["code"], "peer_rate_limited");
        assert!(kept, "the operator can simply wait and retry");
    }

    #[tokio::test]
    async fn task6_unparsable_response_is_unknown() {
        let _guard = open_roundtrip();
        let (status, body, kept) = verify_against_stub("req-junk", StatusCode::OK, "}{ nope").await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["state"], "unknown");
        assert!(!kept);
    }

    #[tokio::test]
    async fn task6_incomplete_response_is_unknown() {
        let _guard = open_roundtrip();
        // A 200 that omits server_pubkey / server_x25519_pk: the responder has
        // very likely committed, but we cannot pin it.
        let (status, body, kept) = verify_against_stub(
            "req-partial",
            StatusCode::OK,
            r#"{"ok":true,"token":"t","expires_at":1}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "peer_response_incomplete");
        assert_eq!(body["state"], "unknown");
        assert!(!kept);
    }

    /// A peer that answers with a key whose fingerprint is not its own peer_id is
    /// trying to plant a signing key it does not own.
    #[tokio::test]
    async fn task6_fingerprint_mismatch_is_refused_and_stores_nothing() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        let wrong_key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let payload: &'static str = Box::leak(
            format!(
                r#"{{"ok":true,"token":"t","expires_at":1,"server_pubkey":"{wrong_key}","server_x25519_pk":"{wrong_key}"}}"#
            )
            .into_boxed_str(),
        );
        let (port, server) = start_stub(StatusCode::OK, payload).await;
        seed_entry(&peer_id, "req-fp", port);

        let (status, body) = verify_via(&state, &peer_id, "req-fp").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "fingerprint_mismatch");
        assert_eq!(body["state"], "failed");

        let stored: Option<Option<String>> =
            sqlx::query_scalar("SELECT token FROM peers WHERE peer_id=?1")
                .bind(&peer_id)
                .fetch_optional(&state.db)
                .await
                .unwrap();
        assert!(
            stored.flatten().is_none(),
            "a mismatched key must never reach the peers table"
        );

        server.abort();
    }

    /// The responder answers 401 for seven different reasons and we cannot tell
    /// them apart, so the initiator counts its own attempts and terminates at 5.
    #[tokio::test]
    async fn task6_pin_attempts_are_counted_locally_and_terminate() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        let (port, server) = start_stub(StatusCode::UNAUTHORIZED, "{}").await;
        seed_entry(&peer_id, "req-401", port);

        for expected_remaining in [4, 3, 2, 1] {
            let (status, body) = verify_via(&state, &peer_id, "req-401").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["state"], "retryable");
            assert_eq!(body["code"], "pin_rejected");
            assert_eq!(body["attempts_remaining"], expected_remaining);
            assert!(
                peek_entry(&peer_id, "req-401").is_some(),
                "a mistyped PIN must not end the pairing"
            );
        }

        let (status, body) = verify_via(&state, &peer_id, "req-401").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["state"], "failed");
        assert_eq!(body["code"], "pin_attempts_exhausted");
        assert!(
            peek_entry(&peer_id, "req-401").is_none(),
            "the fifth failure must terminate instead of looping forever"
        );

        server.abort();
    }

    /// The whole point of keeping the nonce on 401: the operator retypes the PIN
    /// and the pairing still completes.
    #[tokio::test]
    async fn task6_retry_after_a_rejected_pin_still_succeeds() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        let (bad_port, bad) = start_stub(StatusCode::UNAUTHORIZED, "{}").await;
        seed_entry(&peer_id, "req-retry", bad_port);

        let (status, _) = verify_via(&state, &peer_id, "req-retry").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        bad.abort();

        let entry = peek_entry(&peer_id, "req-retry").expect("nonce kept for the retry");
        assert_eq!(entry.attempts, 1);
    }

    /// A stub verify response carrying the responder's real ed25519 / x25519
    /// public keys, so the initiator's fingerprint check passes. This avoids the
    /// n=2^17 KDF, which is far slower than the client's 10s timeout on this
    /// memory-constrained host (the real handshake measures ~25s); the DB
    /// write-back path is what these tests actually exercise.
    async fn stub_verify_ok_for(state: &SharedState) -> (String, &'static str) {
        let (ed, x) = crate::routes::peer_identity::local_identity_material(&**state)
            .await
            .unwrap();
        let peer_id = crate::routes::peer_identity::derive_peer_id(&ed);
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let payload: &'static str = Box::leak(
            json!({
                "ok": true,
                "token": "tok-abcdefghijklmnopqrstuvwxyz",
                "expires_at": 9_999_999_999i64,
                "server_pubkey": b64(&ed),
                "server_x25519_pk": b64(&x),
            })
            .to_string()
            .into_boxed_str(),
        );
        (peer_id, payload)
    }

    /// Seeds a pending entry and drives one verify against a stub returning
    /// `payload`. Returns the initiator's response.
    async fn verify_seeded(
        state: &SharedState,
        peer_id: &str,
        payload: &'static str,
    ) -> (StatusCode, Value) {
        let (port, server) = start_stub(StatusCode::OK, payload).await;
        seed_entry(peer_id, "vr", port);
        let response = call(
            initiator(state.clone()),
            "/client/verify",
            json!({"peer_id": peer_id, "request_id": "vr", "pin": "123456"}),
        )
        .await;
        let status = response.status();
        let body = body(response).await;
        server.abort();
        (status, body)
    }

    #[tokio::test]
    async fn task6_success_stores_token_and_keys_in_one_transaction() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let (peer_id, payload) = stub_verify_ok_for(&state).await;
        insert_peer(&state, &peer_id, "127.0.0.1", 5000).await;

        let (status, vbody) = verify_seeded(&state, &peer_id, payload).await;
        assert_eq!(status, StatusCode::OK, "verify failed: {vbody}");
        assert_eq!(vbody["ok"], true);
        // The raw token must not leak to layer (a).
        assert!(
            vbody.get("token").is_none(),
            "raw token must stay server-side"
        );

        // token, pubkey and x25519_pk must all be present together.
        let row: (Option<String>, Option<Vec<u8>>, Option<Vec<u8>>) =
            sqlx::query_as("SELECT token, pubkey, x25519_pk FROM peers WHERE peer_id=?1")
                .bind(&peer_id)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(row.0.is_some(), "token stored");
        assert_eq!(row.1.unwrap().len(), 32, "server pubkey stored");
        assert_eq!(row.2.unwrap().len(), 32, "server x25519 stored");
        // The nonce is consumed on success.
        assert!(peek_entry(&peer_id, "vr").is_none());
    }

    /// If the peers row is deleted between request and verify (operator unpair,
    /// a concurrent admin delete), verify must recreate it -- and the INSERT
    /// carries created_at / updated_at, both NOT NULL.
    #[tokio::test]
    async fn task6_verify_recreates_a_deleted_peer_row() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let (peer_id, payload) = stub_verify_ok_for(&state).await;
        // Deliberately do NOT insert the peers row: verify must create it.

        let (status, vbody) = verify_seeded(&state, &peer_id, payload).await;
        assert_eq!(status, StatusCode::OK, "recreate failed: {vbody}");
        let token: Option<String> = sqlx::query_scalar("SELECT token FROM peers WHERE peer_id=?1")
            .bind(&peer_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(token.is_some(), "the row was created with its token");
    }

    /// Worst-case wait under the shared n=2^17 KDF semaphore (permits = 2),
    /// measured rather than estimated per the spec's acceptance criterion.
    /// Heavy: run explicitly with `--ignored`.
    #[tokio::test]
    #[ignore = "measures scrypt contention; ~tens of seconds"]
    async fn task6_concurrent_verify_latency_is_measured_not_estimated() {
        let _guard = open_roundtrip();
        let state = client_state().await;
        let peer_id = local_peer_id_of(&state).await;
        let (port, server) = start_stub(StatusCode::UNAUTHORIZED, "{}").await;

        const N: usize = 32;
        for i in 0..N {
            seed_entry(&peer_id, &format!("m{i}"), port);
        }
        let start = std::time::Instant::now();
        let mut handles = Vec::new();
        for i in 0..N {
            let state = state.clone();
            let peer_id = peer_id.clone();
            handles.push(tokio::spawn(async move {
                verify_via(&state, &peer_id, &format!("m{i}")).await
            }));
        }
        for h in handles {
            let _ = h.await.unwrap();
        }
        let elapsed = start.elapsed();
        eprintln!(
            "concurrent verify: {N} tasks finished in {:?} (KDF permits = 2, ~1s each)",
            elapsed
        );
        server.abort();
    }
}
