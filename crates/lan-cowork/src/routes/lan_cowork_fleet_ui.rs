//! LAN Cowork Fleet Admin UI routes.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};

use crate::routes::{
    lan_cowork_fleet_manager::chief_enabled,
    lan_cowork_host::{FleetUiNonce, LanCoworkState},
};

/// Routes owned by this module, mounted on `LanCoworkState`. `main.rs` applies
/// `.with_state(lc_state)` to this sub-router before merging it into the
/// core `SharedState` builder chain (see the S3 decoupling plan's §3 proof).
pub fn routes() -> Router<LanCoworkState> {
    Router::new().route("/ext/lan_cowork/fleet/ui", get(fleet_ui))
}

pub async fn fleet_ui(
    State(state): State<LanCoworkState>,
    Extension(FleetUiNonce(nonce)): Extension<FleetUiNonce>,
) -> Response {
    if state.peer_registry.get().is_none() || !chief_enabled(&*state) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let path = state
        .project_root()
        .join("extensions/builtin_lan_cowork/ui/fleet/fleet.html");
    let Ok(html) = std::fs::read_to_string(path) else {
        return (StatusCode::NOT_FOUND, "Fleet UI not found").into_response();
    };
    let nav = state.render_nav(&nonce, "fleet");

    Html(
        html.replace("{{ csp_nonce }}", &nonce)
            .replace("<!-- NAV_PLACEHOLDER -->", &nav),
    )
    .into_response()
}

#[cfg(test)]
mod tests {
    use std::{path::Path, sync::Arc, time::Duration};

    use axum::{body::to_bytes, http::StatusCode};
    use serde_json::json;

    use super::*;
    use crate::{routes::lan_cowork_registry::PeerRegistry, state::SharedState};

    // `static_app`/`request`/`session` helpers and the 2 static-file tests
    // (`static_file_requires_and_accepts_session`, `static_path_traversal_is_404`)
    // were relocated to yu-server's `lan_cowork_split_integration_tests.rs`
    // (S4d step 4): they exercise `auth_middleware`, which lives in yu-server
    // and is unreachable across the crate boundary.

    const FLEET_HTML: &str =
        r#"<main nonce="{{ csp_nonce }}"><!-- NAV_PLACEHOLDER -->Fleet</main>"#;

    async fn state(
        root: &Path,
        registry: bool,
        chief: bool,
        nav: Option<&str>,
    ) -> (SharedState, LanCoworkState) {
        std::fs::create_dir_all(root.join("extensions/builtin_lan_cowork/ui/fleet")).unwrap();
        std::fs::create_dir_all(root.join("ui/default/templates")).unwrap();
        std::fs::write(
            root.join("config.json"),
            json!({"extensions":{"builtin-lan-cowork":{"fleet":{"chief":chief}}}}).to_string(),
        )
        .unwrap();
        if let Some(nav) = nav {
            std::fs::write(root.join("ui/default/templates/_nav.html"), nav).unwrap();
        }
        let shared =
            crate::state::semantic_test_state_with_root(true, String::new(), root.to_path_buf())
                .await;
        // Built once here via `LanCoworkState::from_shared`, the single production
        // construction seam (also used by `main.rs`): the registry is set on THIS
        // instance and returned to the caller, so `call`/`static_app` never
        // re-derive a fresh (empty) `LanCoworkState`.
        let lc = LanCoworkState::from_shared(&shared);
        if registry {
            lc.peer_registry
                .set(Arc::new(PeerRegistry::new(
                    shared.db.clone(),
                    Duration::from_secs(30),
                    "local".to_owned(),
                )))
                .ok();
        }
        (shared, lc)
    }

    async fn call(lc: LanCoworkState, nonce: &str) -> (StatusCode, String, String) {
        let response = fleet_ui(State(lc), Extension(FleetUiNonce(nonce.to_owned()))).await;
        let status = response.status();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (
            status,
            content_type,
            String::from_utf8(body.to_vec()).unwrap(),
        )
    }

    #[tokio::test]
    async fn ui_without_registry_is_empty_404() {
        let root = tempfile::tempdir().unwrap();
        let (_, lc) = state(root.path(), false, true, Some("nav")).await;
        std::fs::write(
            root.path()
                .join("extensions/builtin_lan_cowork/ui/fleet/fleet.html"),
            FLEET_HTML,
        )
        .unwrap();

        let (status, _, body) = call(lc, "nonce").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn ui_on_non_chief_is_empty_404() {
        let root = tempfile::tempdir().unwrap();
        let (_, lc) = state(root.path(), true, false, Some("nav")).await;
        std::fs::write(
            root.path()
                .join("extensions/builtin_lan_cowork/ui/fleet/fleet.html"),
            FLEET_HTML,
        )
        .unwrap();

        let (status, _, body) = call(lc, "nonce").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn ui_on_chief_returns_html() {
        let root = tempfile::tempdir().unwrap();
        let (_, lc) = state(root.path(), true, true, Some("nav")).await;
        std::fs::write(
            root.path()
                .join("extensions/builtin_lan_cowork/ui/fleet/fleet.html"),
            FLEET_HTML,
        )
        .unwrap();

        let (status, content_type, body) = call(lc, "nonce").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "text/html; charset=utf-8");
        assert!(body.contains("Fleet"));
    }

    #[tokio::test]
    async fn ui_missing_file_has_distinct_404_body() {
        let root = tempfile::tempdir().unwrap();
        let (_, lc) = state(root.path(), true, true, Some("nav")).await;

        let (status, _, body) = call(lc, "nonce").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, "Fleet UI not found");
    }

    #[tokio::test]
    async fn ui_replaces_nonce() {
        let root = tempfile::tempdir().unwrap();
        let (_, lc) = state(root.path(), true, true, Some("nav")).await;
        std::fs::write(
            root.path()
                .join("extensions/builtin_lan_cowork/ui/fleet/fleet.html"),
            FLEET_HTML,
        )
        .unwrap();

        let (_, _, body) = call(lc, "test-nonce").await;
        assert!(body.contains(r#"nonce="test-nonce""#));
        assert!(!body.contains("{{ csp_nonce }}"));
    }

    // `ui_renders_nav_with_all_context_keys` relocated to yu-server's
    // `lan_cowork_split_integration_tests.rs` (S4d step 4): it asserts on
    // `render_nav`'s real minijinja template substitution (`dist_v`,
    // `active`), which only yu-server's `AppState` implements — `TestHost`'s
    // `render_nav` is a fixed empty-string stub and can never satisfy it.

    #[tokio::test]
    async fn ui_ignores_nav_render_failure() {
        let root = tempfile::tempdir().unwrap();
        let (_, lc) = state(root.path(), true, true, None).await;
        std::fs::write(
            root.path()
                .join("extensions/builtin_lan_cowork/ui/fleet/fleet.html"),
            FLEET_HTML,
        )
        .unwrap();

        let (status, _, body) = call(lc, "nonce").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"<main nonce="nonce">Fleet</main>"#);
    }
}
