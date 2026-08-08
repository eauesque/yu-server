//! `/v1/router/capabilities` and `/v1/node/services` — stub only.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::state::SharedState;

fn gateway_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": {"message": "gateway_unavailable", "type": "server_error", "code": 503}})),
    )
        .into_response()
}

async fn fwd_get(state: &SharedState, path: &str) -> Response {
    if state.config.python_url.is_empty() {
        return gateway_unavailable();
    }
    let url = format!("{}{}", state.config.python_url.trim_end_matches('/'), path);
    match state
        .python_client
        .get(&url)
        .header("X-Remote-User", "yu-proxy-auth")
        .send()
        .await
    {
        Ok(r) => {
            let s = r.status();
            r.bytes().await.map_or_else(
                |_| StatusCode::BAD_GATEWAY.into_response(),
                |b| (s, b).into_response(),
            )
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

/// GET /v1/router/capabilities
pub async fn router_capabilities() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
}

/// GET /v1/node/services
pub async fn node_services() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
}
