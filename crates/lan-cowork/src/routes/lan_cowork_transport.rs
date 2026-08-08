//! Signed outbound LAN Cowork peer transport.
//!
//! This module deliberately has no route. `build_peer_client` retains its
//! loopback-pinning and private-address checks; request timeout is overridden
//! to Python PeerTransport's five-second total deadline.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use futures_util::StreamExt;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Method, Url,
};
use serde_json::{json, Map, Value};

use crate::{
    auth::peer_transport::{
        build_canonical_message, make_nonce, path_requires_nonce, sign_canonical,
    },
    routes::{
        lan_cowork_client::build_peer_client,
        lan_cowork_host::LanCoworkHost,
        lan_cowork_registry::{PeerInfo, PeerRegistry},
    },
};

const PREFIX: &str = "/ext/lan_cowork";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Python loads the full JSON response. This finite 64 MiB ceiling exceeds
/// practical peer libraries; callers with exceptional payloads can raise it.
const DEFAULT_JSON_RESPONSE_LIMIT: usize = 64 * 1024 * 1024;

/// Stateful equivalent of Python's `PeerTransport`.
pub struct PeerTransport {
    local_peer_id: String,
    seed: Vec<u8>,
    registry: Arc<PeerRegistry>,
    host: Arc<dyn LanCoworkHost>,
    failure_counts: Mutex<HashMap<String, u32>>,
}

impl PeerTransport {
    pub fn new(
        local_peer_id: String,
        seed: Vec<u8>,
        registry: Arc<PeerRegistry>,
        host: Arc<dyn LanCoworkHost>,
    ) -> Self {
        Self {
            local_peer_id,
            seed,
            registry,
            host,
            failure_counts: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn full_path(path: &str) -> String {
        if path.starts_with("/api/peer/") {
            format!("{PREFIX}{path}")
        } else {
            path.to_owned()
        }
    }

    pub(crate) fn build_url(peer: &PeerInfo, path: &str) -> String {
        format!(
            "http://{}:{}{}",
            peer.api_host,
            peer.api_port,
            Self::full_path(path)
        )
    }

    pub fn build_peer_headers(
        &self,
        peer: &PeerInfo,
        method: &str,
        path: &str,
        query_string: &str,
        body: &[u8],
    ) -> Result<HeaderMap, String> {
        build_peer_headers_at(
            now_secs(),
            &self.seed,
            &self.local_peer_id,
            peer,
            method,
            path,
            query_string,
            body,
        )
    }

    pub async fn send(
        &self,
        peer: &PeerInfo,
        path: &str,
        data: Option<&Value>,
        method: &str,
    ) -> (bool, Value) {
        self.send_with_reason(peer, path, data, method, "401_transport")
            .await
    }

    pub(crate) async fn send_with_reason(
        &self,
        peer: &PeerInfo,
        path: &str,
        data: Option<&Value>,
        method: &str,
        auth_lost_reason: &str,
    ) -> (bool, Value) {
        let full_path_with_query = Self::full_path(path);
        let (full_path, query_string) = full_path_with_query
            .split_once('?')
            .map_or((full_path_with_query.as_str(), ""), |(path, query)| {
                (path, query)
            });
        let method = match Method::from_bytes(method.as_bytes()) {
            Ok(method) => method,
            Err(error) => return (false, json!({"error": error.to_string()})),
        };
        let send_body = data.is_some() && matches!(method, Method::POST | Method::PUT);
        let body = if send_body {
            match serde_json::to_vec(data.expect("checked Some")) {
                Ok(body) => body,
                Err(error) => return (false, json!({"error": error.to_string()})),
            }
        } else {
            Vec::new()
        };
        let headers =
            match self.build_peer_headers(peer, method.as_str(), full_path, query_string, &body) {
                Ok(headers) => headers,
                Err(error) => return (false, json!({"error": error})),
            };
        let (client, base) = match build_peer_client(
            &peer.api_host,
            peer.api_port,
            Some(Duration::from_secs(10)),
            None,
        )
        .await
        {
            Ok(client) => client,
            Err(error) => {
                return self.record_failure(&Self::build_url(peer, path), &format!("{error:?}"))
            }
        };
        let url = match Url::parse(&format!("{base}{full_path_with_query}")) {
            Ok(url)
                if url.path() == full_path && url.query().unwrap_or_default() == query_string =>
            {
                url
            }
            Ok(_) => {
                return self.record_failure(
                    &Self::build_url(peer, path),
                    "signed path/query differs from request URL",
                )
            }
            Err(error) => {
                return self.record_failure(&Self::build_url(peer, path), &error.to_string())
            }
        };
        let request = client
            .request(method.clone(), url.clone())
            .timeout(REQUEST_TIMEOUT)
            .headers(headers);
        let response = match if send_body {
            request.body(body).send().await
        } else {
            request.send().await
        } {
            Ok(response) => response,
            Err(error) => return self.record_failure(url.as_str(), &error.to_string()),
        };
        self.reset_failures(url.as_str());
        let status = response.status();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            invalidate_outbound_token(&self.registry, &*self.host, &peer.peer_id).await;
            self.emit_auth_lost(&peer.peer_id, auth_lost_reason);
        }
        let bytes = match read_peer_response_capped(response, DEFAULT_JSON_RESPONSE_LIMIT).await {
            Ok(bytes) => bytes,
            Err(error) => return self.record_failure(url.as_str(), &error),
        };
        let body_len = bytes.len();
        let mut body = parse_json_object(&bytes);
        let ok = status.as_u16() < 400;
        if !ok {
            tracing::warn!(
                "{}",
                response_log_summary(
                    method.as_str(),
                    url.as_str(),
                    status.as_u16(),
                    body_len,
                    &content_type
                )
            );
            body.entry("error".to_owned())
                .or_insert_with(|| Value::String(format!("HTTP {}", status.as_u16())));
            body.insert("status".to_owned(), json!(status.as_u16()));
        }
        (ok, Value::Object(body))
    }

    fn emit_auth_lost(&self, peer_id: &str, reason: &str) {
        self.host.sse_send(
            "lan-cowork",
            "peer.auth_lost",
            now_secs() as f64,
            json!({"peer_id": peer_id, "reason": reason}),
        );
    }

    fn reset_failures(&self, url: &str) {
        self.failure_counts
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(url);
    }

    fn record_failure(&self, url: &str, error: &str) -> (bool, Value) {
        let count = {
            let mut counts = self
                .failure_counts
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let count = counts.entry(url.to_owned()).or_default();
            *count += 1;
            *count
        };
        if failure_should_warn(count) {
            tracing::warn!(%url, %error, "peer transport failed");
        } else {
            tracing::debug!(%url, count, %error, "peer transport failed");
        }
        (false, json!({"error": error}))
    }
}

pub async fn invalidate_outbound_token(
    registry: &PeerRegistry,
    host: &dyn LanCoworkHost,
    peer_id: &str,
) {
    let Some(mut peer) = registry.get(peer_id) else {
        return;
    };
    peer.token = None;
    peer.token_expires_at = None;
    peer.token_issued_at = None;
    if let Err(error) = registry.upsert(peer).await {
        tracing::debug!(%peer_id, %error, "could not clear outbound peer token");
    }
    host.sse_send(
        "lan-cowork",
        "peer.token_revoked",
        now_secs() as f64,
        json!({"peer_id": peer_id}),
    );
}

/// Header seam for golden vectors. The timestamp is both signed and used for
/// token-expiry parity, while production calls `PeerTransport::build_peer_headers`.
#[allow(clippy::too_many_arguments)]
pub fn build_peer_headers_at(
    timestamp: i64,
    seed: &[u8],
    local_peer_id: &str,
    peer: &PeerInfo,
    method: &str,
    path: &str,
    query_string: &str,
    body: &[u8],
) -> Result<HeaderMap, String> {
    let ts = timestamp.to_string();
    let canonical = build_canonical_message(method, path, query_string, &ts, body);
    let signature =
        sign_canonical(seed, &canonical).ok_or_else(|| "could not sign peer request".to_owned())?;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    insert_header(&mut headers, "X-Peer-Id", local_peer_id)?;
    insert_header(&mut headers, "X-Requested-With", "PeerTransport")?;
    if peer.token.as_deref().is_some_and(|token| !token.is_empty())
        && peer
            .token_expires_at
            .is_none_or(|expires_at| expires_at > timestamp)
    {
        insert_header(
            &mut headers,
            AUTHORIZATION.as_str(),
            &format!("Bearer {}", peer.token.as_deref().unwrap_or_default()),
        )?;
    }
    insert_header(&mut headers, "X-Peer-Ts", &ts)?;
    insert_header(
        &mut headers,
        "X-Peer-Sig",
        &base64::engine::general_purpose::URL_SAFE.encode(signature),
    )?;
    if path_requires_nonce(path) {
        insert_header(&mut headers, "X-Peer-Nonce", &make_nonce())?;
    }
    Ok(headers)
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str) -> Result<(), String> {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| error.to_string())?;
    let value = HeaderValue::from_str(value).map_err(|error| error.to_string())?;
    headers.insert(name, value);
    Ok(())
}

/// Callers must not log `body["error"]`: doing so would reintroduce response-body leakage.
/// Unlike `lan_cowork_client::read_peer_response_capped`, this accepts a limit and returns bytes because its fixed 64 KiB/String API serves other callers.
async fn read_peer_response_capped(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| error.to_string())?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err("peer response body exceeds limit".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_json_object(body: &[u8]) -> Map<String, Value> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

fn failure_should_warn(count: u32) -> bool {
    count == 1 || count.is_multiple_of(6)
}

fn response_log_summary(
    method: &str,
    url: &str,
    status: u16,
    body_len: usize,
    content_type: &str,
) -> String {
    format!(
        "peer transport HTTP failure method={method} url={url} status={status} body_len={body_len} content_type={content_type}"
    )
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::lan_cowork_descriptor::{test_guard, TEST_ALLOW_LOOPBACK};
    use crate::state::semantic_test_state;
    use sqlx::{sqlite::SqlitePoolOptions, Row};
    use std::sync::atomic::Ordering;

    fn peer(port: u16) -> PeerInfo {
        PeerInfo {
            peer_id: "remote".to_owned(),
            name: "remote".to_owned(),
            api_host: "127.0.0.1".to_owned(),
            api_port: port,
            token: Some("outbound-token".to_owned()),
            token_expires_at: Some(2_000_000_000),
            token_issued_at: Some(1_700_000_000),
            pubkey: None,
            x25519_pk: None,
            version: String::new(),
            bridges: vec![],
            inference_types: vec![],
            gpu: String::new(),
            generating: false,
            queue_depth: 0,
            status: "online".to_owned(),
            last_seen: 0.0,
            session_id: String::new(),
            roles: vec![],
            last_reached_at: None,
            last_attempted_at: None,
        }
    }

    async fn registry() -> (Arc<PeerRegistry>, sqlx::SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE peers (peer_id TEXT PRIMARY KEY, name TEXT, api_host TEXT, api_port INTEGER, \
             token TEXT, token_expires_at INTEGER, token_issued_at INTEGER, pubkey BLOB, x25519_pk BLOB, \
             created_at INTEGER, updated_at INTEGER)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("CREATE TABLE peer_tokens (peer_id TEXT PRIMARY KEY, revoked_at INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
        (
            Arc::new(PeerRegistry::new(
                pool.clone(),
                Duration::from_secs(30),
                "local".to_owned(),
            )),
            pool,
        )
    }

    fn transport(registry: Arc<PeerRegistry>, host: Arc<dyn LanCoworkHost>) -> PeerTransport {
        PeerTransport::new(
            "local".to_owned(),
            hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                .unwrap(),
            registry,
            host,
        )
    }

    async fn response_server(response: &'static [u8]) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream.write_all(response).await.unwrap();
        });
        (port, server)
    }

    #[test]
    fn path_and_failure_parity() {
        assert_eq!(
            PeerTransport::full_path("/api/peer/status"),
            "/ext/lan_cowork/api/peer/status"
        );
        assert_eq!(PeerTransport::full_path("/fleet/status"), "/fleet/status");
        assert_eq!(
            PeerTransport::build_url(&peer(8188), "/api/peer/status"),
            "http://127.0.0.1:8188/ext/lan_cowork/api/peer/status"
        );
        assert!(failure_should_warn(1));
        assert!(!failure_should_warn(2));
        assert!(failure_should_warn(6));
    }

    #[test]
    fn headers_use_injected_timestamp_and_vector_signature() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/vectors/peer_transport_vectors.json"
        ))
        .unwrap();
        for case in vectors["request_signature"]["cases"].as_array().unwrap() {
            let headers = build_peer_headers_at(
                case["ts"].as_str().unwrap().parse().unwrap(),
                &hex::decode(vectors["request_signature"]["seed_hex"].as_str().unwrap()).unwrap(),
                "local",
                &peer(8188),
                case["method"].as_str().unwrap(),
                case["path"].as_str().unwrap(),
                case["query_string"].as_str().unwrap(),
                case["body_utf8"].as_str().unwrap().as_bytes(),
            )
            .unwrap();
            assert_eq!(headers["X-Peer-Ts"], case["ts"].as_str().unwrap());
            assert_eq!(headers["X-Peer-Sig"], case["sig_b64url"].as_str().unwrap());
            assert_eq!(headers["X-Requested-With"], "PeerTransport");
        }
        let mut valid = peer(8188);
        assert!(
            build_peer_headers_at(10, &[1; 32], "local", &valid, "GET", "/x", "", b"")
                .unwrap()
                .contains_key(AUTHORIZATION)
        );
        valid.token_expires_at = None;
        assert!(
            build_peer_headers_at(10, &[1; 32], "local", &valid, "GET", "/x", "", b"")
                .unwrap()
                .contains_key(AUTHORIZATION)
        );
        valid.token_expires_at = Some(10);
        assert!(
            !build_peer_headers_at(10, &[1; 32], "local", &valid, "GET", "/x", "", b"")
                .unwrap()
                .contains_key(AUTHORIZATION)
        );
        valid.token = Some(String::new());
        assert!(
            !build_peer_headers_at(9, &[1; 32], "local", &valid, "GET", "/x", "", b"")
                .unwrap()
                .contains_key(AUTHORIZATION)
        );
    }

    #[test]
    fn headers_include_nonce_only_for_nonce_required_paths() {
        for (path, needs_nonce) in [
            ("/ext/lan_cowork/fleet/status", true),
            ("/ext/lan_cowork/api/peer/message", true),
            ("/ext/lan_cowork/api/peer/status", false),
        ] {
            let headers =
                build_peer_headers_at(10, &[1; 32], "local", &peer(8188), "GET", path, "", b"")
                    .unwrap();
            assert_eq!(headers.contains_key("X-Peer-Nonce"), needs_nonce);
        }
    }

    #[test]
    fn response_log_summary_excludes_body() {
        let secret = "response-secret";
        assert!(
            !response_log_summary("GET", "http://peer", 500, secret.len(), "application/json")
                .contains(secret)
        );
    }

    #[tokio::test]
    async fn send_preserves_signed_body_and_normalizes_json() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let count = stream.read(&mut request).await.unwrap();
            request.truncate(count);
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]").await.unwrap();
            request
        });
        let (registry, _) = registry().await;
        let peer = peer(port);
        registry.upsert(peer.clone()).await.unwrap();
        let state = semantic_test_state(true).await;
        let transport = transport(registry, state);
        let data = json!({"z":"あ","a":1.5});
        let expected = serde_json::to_vec(&data).unwrap();
        let (ok, body) = transport
            .send(&peer, "/api/peer/message", Some(&data), "POST")
            .await;
        assert!(ok);
        assert_eq!(body, json!({}));
        let request = server.await.unwrap();
        let wire = String::from_utf8_lossy(&request);
        assert!(wire.contains("x-requested-with: PeerTransport"));
        assert!(request.ends_with(&expected));
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn send_keeps_http_error_and_non_json_parity() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let (registry, _) = registry().await;
        let transport = transport(registry.clone(), semantic_test_state(true).await);

        let (port, server) = response_server(
            b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"error\":\"remote\"}",
        )
        .await;
        let remote = peer(port);
        registry.upsert(remote.clone()).await.unwrap();
        let (ok, body) = transport
            .send(&remote, "/api/peer/status", None, "GET")
            .await;
        assert!(!ok);
        assert_eq!(body["error"], "remote");
        assert_eq!(body["status"], 404);
        server.await.unwrap();

        let (port, server) = response_server(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8\r\n\r\nnot-json",
        )
        .await;
        let remote = peer(port);
        registry.upsert(remote.clone()).await.unwrap();
        let (ok, body) = transport
            .send(&remote, "/api/peer/status", None, "GET")
            .await;
        assert!(ok);
        assert_eq!(body, json!({}));
        server.await.unwrap();
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn send_rejects_url_that_changes_the_signed_path() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let (registry, _) = registry().await;
        let transport = transport(registry, semantic_test_state(true).await);
        let (ok, body) = transport
            .send(&peer(1), "/api/peer/path with space", None, "GET")
            .await;
        assert!(!ok);
        assert_eq!(body["error"], "signed path/query differs from request URL");
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn send_401_clears_only_outbound_token_and_emits_both_events() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}").await.unwrap();
        });
        let (registry, pool) = registry().await;
        let peer = peer(port);
        registry.upsert(peer.clone()).await.unwrap();
        sqlx::query("INSERT INTO peer_tokens (peer_id, revoked_at) VALUES ('remote', NULL)")
            .execute(&pool)
            .await
            .unwrap();
        let state = semantic_test_state(true).await;
        let mut events = state.sse_hub.subscribe();
        let transport = transport(registry.clone(), state);
        let (ok, body) = transport.send(&peer, "/api/peer/status", None, "GET").await;
        assert!(!ok);
        assert_eq!(body["error"], "HTTP 401");
        assert_eq!(registry.get("remote").unwrap().token, None);
        let row = sqlx::query("SELECT revoked_at FROM peer_tokens WHERE peer_id='remote'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.get::<Option<i64>, _>("revoked_at"), None);
        let first = events.recv().await.unwrap();
        let second = events.recv().await.unwrap();
        let event_types = [first.event_type.as_str(), second.event_type.as_str()];
        assert!(event_types.contains(&"peer.token_revoked"));
        assert!(event_types.contains(&"peer.auth_lost"));
        server.await.unwrap();
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }
}
