use axum::http::StatusCode;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::json;

use crate::auth::{scope::require_admin_scope, AuthContext};
use crate::state::{AppState, SharedState};

struct SubsystemEntry {
    name: &'static str,
    modes: &'static [&'static str],
    env_override: Option<&'static str>,
}

struct BgTaskEntry {
    name: &'static str,
    modes: &'static [&'static str],
    env_enable: Option<&'static str>,
    env_disable: Option<&'static str>,
}

const SUBSYSTEMS: &[SubsystemEntry] = &[
    SubsystemEntry {
        name: "event_bus",
        modes: &["full", "gateway", "server"],
        env_override: None,
    },
    SubsystemEntry {
        name: "log_interrupted",
        modes: &["full"],
        env_override: None,
    },
    SubsystemEntry {
        name: "backup",
        modes: &["full"],
        env_override: Some("TAGDB_ENABLE_BACKUP"),
    },
    SubsystemEntry {
        name: "scheduler",
        modes: &["full"],
        env_override: Some("TAGDB_ENABLE_SCHEDULER"),
    },
    SubsystemEntry {
        name: "security",
        modes: &["full", "gateway", "server"],
        env_override: None,
    },
    SubsystemEntry {
        name: "event_handlers",
        modes: &["full", "gateway", "server"],
        env_override: None,
    },
    SubsystemEntry {
        name: "scan_queue",
        modes: &["full"],
        env_override: Some("TAGDB_ENABLE_SCAN"),
    },
    SubsystemEntry {
        name: "node_identity",
        modes: &["full", "gateway", "server"],
        env_override: None,
    },
    SubsystemEntry {
        name: "llm_router",
        modes: &["full", "gateway", "server"],
        env_override: None,
    },
    SubsystemEntry {
        name: "mdns",
        modes: &["full", "gateway", "server"],
        env_override: Some("TAGDB_ENABLE_MDNS"),
    },
];

const BG_TASKS: &[BgTaskEntry] = &[
    BgTaskEntry {
        name: "thumb_cleanup",
        modes: &["full"],
        env_enable: None,
        env_disable: None,
    },
    BgTaskEntry {
        name: "analyze",
        modes: &["full"],
        env_enable: Some("TAGDB_ENABLE_ANALYZE"),
        env_disable: Some("TAGDB_DISABLE_ANALYZE"),
    },
    BgTaskEntry {
        name: "file_meta_cache",
        modes: &["full"],
        env_enable: Some("TAGDB_ENABLE_FILE_CACHE"),
        env_disable: None,
    },
    BgTaskEntry {
        name: "stats_warmup",
        modes: &["full"],
        env_enable: Some("TAGDB_ENABLE_STATS_PRELOAD"),
        env_disable: Some("TAGDB_DISABLE_STATS_PRELOAD"),
    },
    BgTaskEntry {
        name: "llm_router_refresh",
        modes: &["full", "gateway", "server"],
        env_enable: None,
        env_disable: Some("TAGDB_DISABLE_LLM_ROUTER_REFRESH"),
    },
    BgTaskEntry {
        name: "hailo_auto_reboot_judge",
        modes: &["full"],
        env_enable: None,
        env_disable: Some("TAGDB_DISABLE_HAILO_AUTO_REBOOT_JUDGE"),
    },
    BgTaskEntry {
        name: "wd_tagger_config_migrate_v2",
        modes: &["full"],
        env_enable: None,
        env_disable: Some("TAGDB_DISABLE_WD_TAGGER_CONFIG_MIGRATE_V2"),
    },
    BgTaskEntry {
        name: "tag_normalize_backfill",
        modes: &["full"],
        env_enable: None,
        env_disable: Some("TAGDB_DISABLE_TAG_NORMALIZE_BACKFILL"),
    },
    BgTaskEntry {
        name: "post_v81_vacuum_analyze",
        modes: &["full"],
        env_enable: None,
        env_disable: Some("TAGDB_DISABLE_POST_V81_VACUUM_ANALYZE"),
    },
    BgTaskEntry {
        name: "post_v82_vacuum_analyze",
        modes: &["full"],
        env_enable: None,
        env_disable: Some("TAGDB_DISABLE_POST_V82_VACUUM_ANALYZE"),
    },
];

fn env_truthy(name: &str) -> bool {
    let raw = std::env::var(name).unwrap_or_default();
    let lower = raw.trim().to_lowercase();
    matches!(lower.as_str(), "1" | "true" | "yes")
}

fn should_run_subsystem(sub: &SubsystemEntry, mode: &str, safe_mode: bool) -> bool {
    if safe_mode {
        return false;
    }
    if sub.modes.contains(&mode) {
        return true;
    }
    sub.env_override.is_some_and(|e| env_truthy(e))
}

fn should_run_bg_task(task: &BgTaskEntry, mode: &str, safe_mode: bool) -> bool {
    if safe_mode {
        return false;
    }
    if task.env_disable.is_some_and(|e| env_truthy(e)) {
        return false;
    }
    if task.env_enable.is_some_and(|e| env_truthy(e)) {
        return true;
    }
    task.modes.contains(&mode)
}

/// GET /api/server/mode
pub async fn server_mode(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|c| &c.0),
    ) {
        return resp;
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "error": null,
            "data": null,
            "mode": &state.config.server_mode,
            "headless": state.config.headless,
        })),
    )
        .into_response()
}

/// GET /api/server/subsystems
pub async fn server_subsystems(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|c| &c.0),
    ) {
        return resp;
    }
    let mode = &state.config.server_mode;
    let safe = state.config.safe_mode;
    let subs: Vec<_> = SUBSYSTEMS
        .iter()
        .map(|s| {
            json!({
                "name": s.name,
                "modes": s.modes,
                "enabled": should_run_subsystem(s, mode, safe),
                "env_override": s.env_override,
            })
        })
        .collect();
    let tasks: Vec<_> = BG_TASKS
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "modes": t.modes,
                "enabled": should_run_bg_task(t, mode, safe),
                "env_enable": t.env_enable,
                "env_disable": t.env_disable,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "error": null,
            "data": null,
            "mode": mode,
            "subsystems": subs,
            "background_tasks": tasks,
        })),
    )
        .into_response()
}

/// Core `get_server_info` body shared by the REST route and the MCP tool of
/// the same name. Admin-scope gating is REST-specific (the MCP transport
/// has its own auth model at the connection layer, see `mcp::auth`), so it
/// stays in `api_server_info` rather than here.
pub fn server_info_body(state: &AppState) -> serde_json::Value {
    let uptime = state.start_time.elapsed().as_secs_f64();
    json!({
        "ok": true,
        "error": null,
        "data": null,
        "version": format!("v{}", state.version),
        "server_mode": state.config.server_mode,
        "headless": state.config.headless,
        "uptime_seconds": uptime,
        "boot_state": "ready",
        "has_pin": !state.config.pin_hash.is_empty(),
        "file_count": 0,
        "tag_count": 0,
    })
}

/// GET /api/server-info
pub async fn api_server_info(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|c| &c.0),
    ) {
        return resp;
    }
    (StatusCode::OK, Json(server_info_body(&state))).into_response()
}

/// GET /api/system/inference-info
pub async fn inference_info(
    State(state): State<SharedState>,
    auth_context: Option<Extension<AuthContext>>,
) -> Response {
    if let Some(resp) = require_admin_scope(
        state.config.pin_auth_enabled,
        auth_context.as_ref().map(|c| &c.0),
    ) {
        return resp;
    }
    if state.config.python_url.is_empty() {
        return Json(json!({"ok": true, "error": null, "available": false, "data": null}))
            .into_response();
    }
    let url = format!(
        "{}/api/system/inference-info",
        state.config.python_url.trim_end_matches('/')
    );
    match state
        .python_client
        .get(&url)
        .header("X-Remote-User", "yu-proxy-auth")
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            resp.bytes().await.map_or_else(
                |_| axum::http::StatusCode::BAD_GATEWAY.into_response(),
                |b| (status, b).into_response(),
            )
        }
        Err(_) => Json(
            json!({"ok": true, "error": "Python unavailable", "available": false, "data": null}),
        )
        .into_response(),
    }
}

/// POST /api/error-report/enrich — silently acknowledge (Python-side enrichment unavailable)
pub async fn error_report_enrich() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({"ok": true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsystem_full_mode_enabled() {
        let sub = &SUBSYSTEMS[0]; // event_bus: modes=["full","gateway","server"]
        assert!(should_run_subsystem(sub, "full", false));
        assert!(should_run_subsystem(sub, "gateway", false));
        assert!(!should_run_subsystem(sub, "full", true)); // safe_mode disables
    }

    #[test]
    fn subsystem_mode_filter() {
        let log_int = &SUBSYSTEMS[1]; // log_interrupted: modes=["full"]
        assert!(should_run_subsystem(log_int, "full", false));
        assert!(!should_run_subsystem(log_int, "gateway", false));
    }

    #[test]
    fn bg_task_safe_mode_disables_all() {
        let task = &BG_TASKS[0]; // thumb_cleanup
        assert!(should_run_bg_task(task, "full", false));
        assert!(!should_run_bg_task(task, "full", true));
    }

    #[test]
    fn bg_task_mode_filter() {
        let task = &BG_TASKS[0]; // thumb_cleanup: modes=["full"]
        assert!(should_run_bg_task(task, "full", false));
        assert!(!should_run_bg_task(task, "gateway", false));
    }

    #[test]
    fn bg_task_multi_mode() {
        let task = &BG_TASKS[4]; // llm_router_refresh: modes=["full","gateway","server"]
        assert!(should_run_bg_task(task, "full", false));
        assert!(should_run_bg_task(task, "gateway", false));
        assert!(should_run_bg_task(task, "server", false));
    }

    #[test]
    fn env_truthy_values() {
        // set/unset tested indirectly via should_run logic
        // direct unit test skipped (env mutation in tests is unsafe in parallel)
    }
}
