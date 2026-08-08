//! Peer-authenticated fleet allowlist grant, revoke, and status routes.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use super::lan_cowork::{
    ext_config, load_config_json, notify_fleet_allowlists_changed, write_config_json,
};
use crate::{auth::peer_transport::require_peer_auth, routes::lan_cowork_host::LanCoworkState};

const CATEGORIES: &[(&str, &str)] = &[
    ("log_stream", "allow_log_stream_from"),
    ("update", "allow_update_from"),
];
fn response(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}
fn fleet(state: &LanCoworkState) -> Value {
    ext_config(&load_config_json(state.config_path()))
        .get("fleet")
        .cloned()
        .unwrap_or_else(|| json!({}))
}
fn normalize_entries(entries: &mut Vec<Value>) {
    let mut seen = std::collections::HashSet::new();
    *entries = entries
        .iter()
        .filter_map(|entry| match entry {
            Value::String(value) => Some(value.trim()),
            Value::Object(value) => value.get("peer_id").and_then(Value::as_str).map(str::trim),
            _ => None,
        })
        .filter(|value| !value.is_empty() && seen.insert((*value).to_owned()))
        .map(|value| json!(value))
        .collect();
}
// Axum responses stay unboxed to preserve the existing handler error contract.
#[allow(clippy::result_large_err)]
fn categories(data: &Value, required: bool) -> Result<Vec<String>, Response> {
    let Some(values) = data.get("categories").and_then(Value::as_array) else {
        return Err(response(
            StatusCode::BAD_REQUEST,
            json!({"ok":false,"error":"categories required"}),
        ));
    };
    if required && values.is_empty() {
        return Err(response(
            StatusCode::BAD_REQUEST,
            json!({"ok":false,"error":"categories required"}),
        ));
    }
    let values: Option<Vec<_>> = values
        .iter()
        .map(Value::as_str)
        .map(|value| value.map(str::to_owned))
        .collect();
    let Some(values) = values else {
        return Err(response(
            StatusCode::BAD_REQUEST,
            json!({"ok":false,"error":"categories must be a list of strings"}),
        ));
    };
    let invalid: Vec<_> = values
        .iter()
        .filter(|item| {
            !CATEGORIES
                .iter()
                .any(|(category, _)| *category == item.as_str())
        })
        .collect();
    if !invalid.is_empty() {
        let invalid = invalid
            .iter()
            .map(|item| format!("'{}'", item.replace('\\', "\\\\").replace('\'', "\\'")))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(response(
            StatusCode::BAD_REQUEST,
            json!({"ok":false,"error":format!("invalid categories: [{invalid}]")}),
        ));
    }
    Ok(values)
}
// Axum responses stay unboxed to preserve the existing handler error contract.
#[allow(clippy::result_large_err)]
fn revoke_categories(data: &Value) -> Result<Vec<String>, Response> {
    if data.get("categories").is_none()
        || data.get("categories").is_some_and(Value::is_null)
        || data
            .get("categories")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        Ok(CATEGORIES
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect())
    } else {
        categories(data, false)
    }
}
// Axum responses stay unboxed to preserve the existing handler error contract.
#[allow(clippy::result_large_err)]
fn update_entries(
    fleet: &mut serde_json::Map<String, Value>,
    peer: &str,
    categories: &[String],
    grant: bool,
) -> Result<(), Response> {
    for (_, key) in CATEGORIES {
        if let Some(entries) = fleet
            .entry((*key).to_owned())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            normalize_entries(entries);
        }
    }
    for category in categories {
        let key = CATEGORIES
            .iter()
            .find(|(name, _)| *name == category)
            .map(|(_, key)| *key)
            .unwrap();
        let values = fleet
            .entry(key)
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| {
                response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"ok":false,"error":"write_failed"}),
                )
            })?;
        if grant {
            if !values.iter().any(|value| value.as_str() == Some(peer)) {
                values.push(json!(peer));
            }
        } else {
            values.retain(|value| value.as_str() != Some(peer));
        }
    }
    Ok(())
}
async fn authenticated(
    state: &LanCoworkState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, Response> {
    require_peer_auth(
        &**state,
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or(""),
        headers,
        body,
    )
    .await
}
// Axum responses stay unboxed to preserve the existing handler error contract.
#[allow(clippy::result_large_err)]
fn json_body(headers: &HeaderMap, body: &[u8]) -> Result<Value, Response> {
    if headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v.split(';').next().unwrap_or("").trim() != "application/json")
    {
        return Err(response(
            StatusCode::BAD_REQUEST,
            json!({"ok":false,"error":"JSON body is required"}),
        ));
    }
    serde_json::from_slice::<Value>(body)
        .ok()
        .filter(Value::is_object)
        .ok_or_else(|| {
            response(
                StatusCode::BAD_REQUEST,
                json!({"ok":false,"error":"invalid JSON body"}),
            )
        })
}
async fn update(
    state: &LanCoworkState,
    peer: &str,
    categories: &[String],
    grant: bool,
) -> Result<Value, Response> {
    let _guard = state.settings_lock.lock().await;
    let mut config = load_config_json(state.config_path());
    let root = config.as_object_mut().ok_or_else(|| {
        response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"ok":false,"error":"write_failed"}),
        )
    })?;
    let extensions = root
        .entry("extensions")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"ok":false,"error":"write_failed"}),
            )
        })?;
    let ext = extensions
        .entry("builtin-lan-cowork")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"ok":false,"error":"write_failed"}),
            )
        })?;
    let fleet = ext
        .entry("fleet")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"ok":false,"error":"write_failed"}),
            )
        })?;
    update_entries(fleet, peer, categories, grant)?;
    let updated = Value::Object(fleet.clone());
    write_config_json(state.config_path(), &config).map_err(|_| {
        response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"ok":false,"error":"write_failed"}),
        )
    })?;
    let _ = notify_fleet_allowlists_changed(&**state).await;
    Ok(updated)
}
async fn grant(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let peer = match authenticated(&state, &method, &uri, &headers, &body).await {
        Ok(peer) => peer,
        Err(response) => return response,
    };
    let data = match json_body(&headers, &body) {
        Ok(data) => data,
        Err(response) => return response,
    };
    let categories = match categories(&data, true) {
        Ok(categories) => categories,
        Err(response) => return response,
    };
    match update(&state, &peer, &categories, true).await {
        Ok(fleet) => response(
            StatusCode::OK,
            json!({"ok":true,"granted_to":peer,"categories":categories,"allow_log_stream_from":fleet["allow_log_stream_from"],"allow_update_from":fleet["allow_update_from"],"allow_remote_update":fleet["allow_remote_update"].as_bool().unwrap_or(false)}),
        ),
        Err(response) => response,
    }
}
async fn revoke(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let peer = match authenticated(&state, &method, &uri, &headers, &body).await {
        Ok(peer) => peer,
        Err(response) => return response,
    };
    let data = match json_body(&headers, &body) {
        Ok(data) => data,
        Err(response) => return response,
    };
    let categories = revoke_categories(&data);
    let categories = match categories {
        Ok(categories) => categories,
        Err(response) => return response,
    };
    match update(&state, &peer, &categories, false).await {
        Ok(fleet) => response(
            StatusCode::OK,
            json!({"ok":true,"revoked_from":peer,"categories":categories,"allow_log_stream_from":fleet["allow_log_stream_from"],"allow_update_from":fleet["allow_update_from"]}),
        ),
        Err(response) => response,
    }
}
async fn check(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let peer = match authenticated(&state, &method, &uri, &headers, &body).await {
        Ok(peer) => peer,
        Err(response) => return response,
    };
    let fleet = fleet(&state);
    let has = |key| {
        fleet
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|entries| {
                super::lan_cowork_fleet_config::peer_id_in_allowlist(
                    &peer,
                    &super::lan_cowork_fleet_config::parse_allowlist(entries),
                )
            })
    };
    response(
        StatusCode::OK,
        json!({"ok":true,"requester_peer_id":peer,"peer_id":peer,"restart":has("allow_update_from") || has("allow_restart_from"),"update":has("allow_update_from"),"log_stream":has("allow_log_stream_from"),"allow_remote_update":fleet["allow_remote_update"].as_bool().unwrap_or(false)}),
    )
}
pub fn routes() -> Router<LanCoworkState> {
    Router::new()
        .route("/ext/lan_cowork/fleet/allowlists/grant", post(grant))
        .route("/ext/lan_cowork/fleet/allowlists/revoke", post(revoke))
        .route("/ext/lan_cowork/fleet/allowlists/check", get(check))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn allowlist_routes_reject_unauthenticated_requests() {
        let state = crate::state::semantic_test_state_with(true, String::new()).await;
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        for (method, uri, body) in [
            (
                "POST",
                "/ext/lan_cowork/fleet/allowlists/grant",
                r#"{"categories":["update"]}"#,
            ),
            (
                "POST",
                "/ext/lan_cowork/fleet/allowlists/revoke",
                r#"{"categories":["update"]}"#,
            ),
            ("GET", "/ext/lan_cowork/fleet/allowlists/check", ""),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn restart_category_is_rejected() {
        let response = categories(&json!({"categories":["restart"]}), true).unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["error"],
            "invalid categories: ['restart']"
        );
    }

    #[test]
    fn revoke_normalizes_dict_form_entries() {
        let mut fleet = json!({"allow_update_from":[{"peer_id":"peer"}]})
            .as_object()
            .unwrap()
            .clone();
        update_entries(&mut fleet, "peer", &["update".to_owned()], false).unwrap();
        assert_eq!(fleet["allow_update_from"], json!([]));
    }

    #[test]
    fn revoke_with_null_categories_clears_all() {
        let categories = revoke_categories(&json!({"categories":null})).unwrap();
        let mut fleet = json!({
            "allow_log_stream_from":["peer"],
            "allow_update_from":["peer"]
        })
        .as_object()
        .unwrap()
        .clone();
        update_entries(&mut fleet, "peer", &categories, false).unwrap();
        assert_eq!(fleet["allow_log_stream_from"], json!([]));
        assert_eq!(fleet["allow_update_from"], json!([]));
    }
}
