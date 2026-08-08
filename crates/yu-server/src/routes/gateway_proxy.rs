//! Gateway wildcard proxy handlers (E-2): Ollama + SD WebUI

use std::{net::SocketAddr, time::Duration};

use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderName, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use reqwest::Url;
use serde_json::json;

use crate::{
    auth::chain::is_loopback_addr,
    routes::{
        sd_webui_bridge::{ext_config, sd_api_url},
        settings::load_config_json,
    },
    state::SharedState,
};

static SD_ALLOWED: &[(&str, &str)] = &[
    ("POST", "/sdapi/v1/txt2img"),
    ("POST", "/sdapi/v1/img2img"),
    ("POST", "/sdapi/v1/extra-single-image"),
    ("POST", "/sdapi/v1/interrupt"),
    ("GET", "/sdapi/v1/samplers"),
    ("GET", "/sdapi/v1/sd-models"),
    ("GET", "/sdapi/v1/loras"),
    ("GET", "/sdapi/v1/embeddings"),
    ("GET", "/sdapi/v1/upscalers"),
    ("GET", "/sdapi/v1/sd-vae"),
    ("GET", "/sdapi/v1/progress"),
    ("GET", "/sdapi/v1/scripts"),
    ("GET", "/sdapi/v1/script-info"),
    ("GET", "/sdapi/v1/cmd-flags"),
    ("GET", "/sdapi/v1/options"),
    ("POST", "/sdapi/v1/options"),
    ("POST", "/sdapi/v1/refresh-checkpoints"),
    ("POST", "/sdapi/v1/refresh-vae"),
    ("POST", "/sdapi/v1/refresh-loras"),
    ("POST", "/sdapi/v1/reload-checkpoint"),
];

static REQ_STRIP: &[&str] = &[
    "authorization",
    "x-api-key",
    "cookie",
    "host",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "connection",
    "keep-alive",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "user-agent",
];

static RESP_STRIP: &[&str] = &[
    "connection",
    "keep-alive",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "server",
    "set-cookie",
];

fn err_401() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error":{"message":"Unauthorized","type":"authentication_error","code":"invalid_api_key"}})),
    )
        .into_response()
}

fn err_403() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error":{"message":"Forbidden","type":"invalid_request_error","code":"forbidden"}})),
    )
        .into_response()
}

fn err_404_backend() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error":{"message":"Backend not found","type":"server_error","code":"backend_not_found"}})),
    )
        .into_response()
}

fn err_404_path() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error":{"message":"Not Found","type":"invalid_request_error","code":"not_found"}})),
    )
        .into_response()
}

fn err_502() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error":{"message":"Bad Gateway","type":"server_error","code":"backend_unavailable"}})),
    )
        .into_response()
}

fn err_504() -> Response {
    (
        StatusCode::GATEWAY_TIMEOUT,
        Json(json!({"error":{"message":"Gateway Timeout","type":"server_error","code":"backend_timeout"}})),
    )
        .into_response()
}

fn proxy_origin_allowed(headers: &HeaderMap) -> bool {
    let host_str = match headers.get("host").and_then(|v| v.to_str().ok()) {
        Some(h) => h,
        None => return true,
    };
    let expected = parse_host_port(host_str);
    for name in ["origin", "referer"] {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
            if !value.is_empty() && parse_url_host_port(value) != expected {
                return false;
            }
        }
    }
    true
}

fn parse_host_port(host: &str) -> Option<(String, Option<u16>)> {
    let (h, p) = if let Some((h, p)) = host.rsplit_once(':') {
        (h, p.parse::<u16>().ok())
    } else {
        (host, None)
    };
    if h.is_empty() {
        None
    } else {
        Some((h.to_lowercase(), p))
    }
}

fn parse_url_host_port(url: &str) -> Option<(String, Option<u16>)> {
    let u = Url::parse(url).ok()?;
    Some((u.host_str()?.to_lowercase(), u.port()))
}

async fn stream_proxy(
    upstream_url: Url,
    method: Method,
    mut headers: HeaderMap,
    client_ip: &str,
    body_bytes: bytes::Bytes,
    timeout: Option<Duration>,
    strip_content_length: bool,
) -> Response {
    if let Ok(v) = client_ip.parse::<axum::http::HeaderValue>() {
        headers.insert("x-forwarded-for", v);
    }

    let strip_names: Vec<HeaderName> = REQ_STRIP
        .iter()
        .filter_map(|s| s.parse::<HeaderName>().ok())
        .collect();
    for name in &strip_names {
        headers.remove(name);
    }
    if strip_content_length {
        headers.remove("content-length");
    }

    let client = {
        let mut b = reqwest::Client::builder();
        if let Some(d) = timeout {
            b = b.timeout(d);
        }
        match b.build() {
            Ok(c) => c,
            Err(_) => return err_502(),
        }
    };

    let mut req_builder = client.request(method, upstream_url).body(body_bytes);
    for (name, value) in &headers {
        req_builder = req_builder.header(name, value);
    }

    let upstream_resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            if e.is_timeout() {
                return err_504();
            }
            return err_502();
        }
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_stream = upstream_resp.bytes_stream();
    let body = Body::from_stream(resp_stream);

    let mut builder = Response::builder().status(status.as_u16());
    let bh = builder.headers_mut().expect("builder valid");
    let resp_strip: Vec<HeaderName> = RESP_STRIP
        .iter()
        .filter_map(|s| s.parse::<HeaderName>().ok())
        .collect();
    for (name, value) in resp_headers {
        if let Some(n) = name {
            if !resp_strip.contains(&n) {
                bh.insert(n, value);
            }
        }
    }

    builder.body(body).unwrap_or_else(|_| err_502())
}

pub async fn ollama_handler(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((name, sub)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    let client_ip = addr.ip().to_string();

    if !is_loopback_addr(&client_ip) {
        return err_401();
    }

    let (parts, body) = request.into_parts();

    if !proxy_origin_allowed(&parts.headers) {
        return err_403();
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => return err_502(),
    };

    // config_path から毎回ディスク再読込し backend を解決
    let base_url = {
        let cfg = load_config_json(&state.config.config_path);
        cfg.get("gateway")
            .and_then(|g| g.get("backends"))
            .and_then(|b| b.as_object())
            .and_then(|map| {
                map.values().find(|v| {
                    v.get("type").and_then(|t| t.as_str()) == Some("ollama")
                        && v.get("name").and_then(|n| n.as_str()) == Some(&name)
                })
            })
            .and_then(|v| v.get("base_url")?.as_str().map(|s| s.to_string()))
    };
    let base_url = match base_url {
        Some(u) => u,
        None => return err_404_backend(),
    };

    // /ollama/{name}/api/blobs/* は無制限、それ以外は 300s
    let timeout = if sub.starts_with("api/blobs/") {
        None
    } else {
        Some(Duration::from_secs(300))
    };

    let upstream_url = match Url::parse(&format!("{}/{sub}", base_url.trim_end_matches('/'))) {
        Ok(u) => u,
        Err(_) => return err_502(),
    };

    // TODO(gateway-auth): OLLAMA_PROXY scope gate を追加
    stream_proxy(
        upstream_url,
        parts.method,
        parts.headers,
        &client_ip,
        body_bytes,
        timeout,
        true,
    )
    .await
}

pub async fn sd_handler(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(sub): Path<String>,
    request: Request<Body>,
) -> Response {
    let client_ip = addr.ip().to_string();

    if !is_loopback_addr(&client_ip) {
        return err_401();
    }

    let (parts, body) = request.into_parts();

    if !proxy_origin_allowed(&parts.headers) {
        return err_403();
    }

    // layer 3: SD path allowlist（認証より前の独立ゲート）
    let full_path = format!("/sdapi/v1/{sub}");
    if !SD_ALLOWED
        .iter()
        .any(|(m, p)| *m == parts.method.as_str() && *p == full_path)
    {
        return err_404_path();
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => return err_502(),
    };

    let cfg = ext_config(&state);
    let sd_base = sd_api_url(&cfg);

    let upstream_url = match Url::parse(&format!("{}{}", sd_base.trim_end_matches('/'), full_path))
    {
        Ok(u) => u,
        Err(_) => return err_502(),
    };

    stream_proxy(
        upstream_url,
        parts.method,
        parts.headers,
        &client_ip,
        body_bytes,
        Some(Duration::from_secs(1800)),
        false,
    )
    .await
}
