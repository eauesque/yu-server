//! LAN Cowork fleet info, update, log-stream, and restart routes (F3a-F3c2).

use std::{
    collections::HashMap,
    convert::Infallible,
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

#[cfg(not(test))]
use std::process::Command;

use axum::{
    body::{Body, Bytes},
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::{sse::Event, IntoResponse, Response, Sse},
    routing::{get, post},
    Extension, Json, Router,
};
use futures_util::{stream, StreamExt};
use serde_json::{json, Value};

use crate::routes::lan_cowork_host::{
    LanCoworkHost, LanCoworkState, LogEvent, LogLine, PeerSourceIp,
};

#[cfg(not(test))]
use crate::auth::peer_transport::require_peer_auth;

#[cfg(test)]
use crate::auth::peer_transport::{require_peer_auth_with_nonce_store, PeerNonceStore};

// Duplicated from yu-server's `logs::ring::level_rank` (pub(crate) there, so not
// reachable across the crate boundary). Design decision §3.10(1): duplicate here.
// `pub` (not test-gated: `#[cfg(test)]` here would only activate when THIS crate
// is compiled under test, not when yu-server's test binary links it as a plain
// dependency) solely so yu-server's `lan_cowork_split_integration_tests.rs` can
// assert parity against `logs::ring::level_rank`.
pub fn level_rank(l: &str) -> u8 {
    match l {
        "TRACE" => 0,
        "DEBUG" => 1,
        "INFO" => 2,
        "WARN" => 3,
        "ERROR" => 4,
        _ => 0,
    }
}

use super::{
    lan_cowork::{ext_config, load_config_json},
    lan_cowork_client::build_peer_client,
    lan_cowork_discovery::load_identity_seed,
    lan_cowork_fleet_config::{parse_allowlist, peer_id_in_allowlist},
    lan_cowork_fleet_machine,
    lan_cowork_fleet_security::check_update_allowed,
    lan_cowork_registry::PeerRegistry,
    lan_cowork_transport::PeerTransport,
};

fn response(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

fn active_jobs() -> &'static Mutex<HashMap<String, Value>> {
    static JOBS: OnceLock<Mutex<HashMap<String, Value>>> = OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
fn test_nonce_store() -> &'static PeerNonceStore {
    static STORE: OnceLock<PeerNonceStore> = OnceLock::new();
    STORE.get_or_init(|| PeerNonceStore::with_grace(0))
}

async fn peer_only(
    state: &dyn LanCoworkHost,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, Response> {
    #[cfg(test)]
    return require_peer_auth_with_nonce_store(
        state,
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or(""),
        headers,
        body,
        test_nonce_store(),
    )
    .await;

    #[cfg(not(test))]
    require_peer_auth(
        state,
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or(""),
        headers,
        body,
    )
    .await
}

async fn fleet_peer_guard(
    state: &dyn LanCoworkHost,
    registry: &PeerRegistry,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, Response> {
    let peer_id = peer_only(state, method, uri, headers, body).await?;
    if registry.get(&peer_id).is_none() {
        return Err(response(
            StatusCode::FORBIDDEN,
            json!({"ok": false, "error": "unknown peer"}),
        ));
    }
    Ok(peer_id)
}

async fn fleet_info(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(registry) = state.peer_registry.get() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "LAN Cowork not enabled"}),
        );
    };
    if let Err(error) = fleet_peer_guard(&*state, registry, &method, &uri, &headers, &body).await {
        return error;
    }

    let version = state.version().to_owned();
    let project_root = state.project_root().to_owned();
    let start_time = state.start_time();
    match tokio::task::spawn_blocking(move || {
        lan_cowork_fleet_machine::collect(&version, &[], &project_root, "", start_time)
    })
    .await
    {
        Ok(info) => Json(info).into_response(),
        Err(_) => response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "collection_failed", "message": "machine info collection failed"}),
        ),
    }
}

fn last_job_path(project_root: &Path) -> PathBuf {
    project_root.join("data").join("fleet_update_last.json")
}

#[cfg(test)]
fn test_heads() -> &'static Mutex<HashMap<PathBuf, Option<String>>> {
    static HEADS: OnceLock<Mutex<HashMap<PathBuf, Option<String>>>> = OnceLock::new();
    HEADS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn git_short_head(project_root: &Path) -> Option<String> {
    #[cfg(test)]
    if let Some(head) = test_heads()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(project_root)
        .cloned()
    {
        return head;
    }

    let args = [
        OsString::from("rev-parse"),
        OsString::from("--short"),
        OsString::from("HEAD"),
    ];
    let output = run_git(project_root, &args).ok()?;
    if !output.success {
        return None;
    }
    Some(output.stdout)
}

fn save_last_job(path: &Path, job: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(job)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)
}

fn load_last_job_with_head<F>(project_root: &Path, head: F) -> Option<Value>
where
    F: FnOnce() -> Option<String>,
{
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let path = last_job_path(project_root);
    let mut job: Value = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
    if job.get("status").and_then(Value::as_str) != Some("restarting") {
        return Some(job);
    }
    let post_commit = job.get("post_commit").and_then(Value::as_str).unwrap_or("");
    if post_commit.is_empty() || head().as_deref() != Some(post_commit) {
        return Some(job);
    }
    job["status"] = json!("success");
    job["finished_at"] =
        json!(chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false));
    let _ = save_last_job(&path, &job);
    Some(job)
}

fn load_last_job(project_root: &Path) -> Option<Value> {
    load_last_job_with_head(project_root, || git_short_head(project_root))
}

struct GitOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

#[cfg(test)]
enum GitTestResult {
    Output(GitOutput),
    Error(std::io::ErrorKind),
}

#[cfg(test)]
#[derive(Default)]
struct GitTestSeam {
    results: Option<std::collections::VecDeque<GitTestResult>>,
    commands: Vec<Vec<OsString>>,
}

#[cfg(test)]
fn git_test_seam() -> &'static Mutex<GitTestSeam> {
    static SEAM: OnceLock<Mutex<GitTestSeam>> = OnceLock::new();
    SEAM.get_or_init(|| Mutex::new(GitTestSeam::default()))
}

#[cfg(not(test))]
fn run_git(project_root: &Path, args: &[OsString]) -> std::io::Result<GitOutput> {
    let output = Command::new("git")
        .args(args)
        .current_dir(project_root)
        .output()?;
    Ok(GitOutput {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

#[cfg(test)]
fn run_git(_project_root: &Path, args: &[OsString]) -> std::io::Result<GitOutput> {
    let mut seam = git_test_seam()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    seam.commands.push(args.to_vec());
    let Some(results) = seam.results.as_mut() else {
        return Err(std::io::Error::other("test git seam is not configured"));
    };
    match results.pop_front() {
        Some(GitTestResult::Output(output)) => Ok(output),
        Some(GitTestResult::Error(kind)) => Err(std::io::Error::from(kind)),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "missing test git result",
        )),
    }
}

fn now_iso() -> String {
    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
}

fn update_step(name: &str, status: &str, output: impl Into<String>) -> Value {
    json!({"name": name, "status": status, "output": output.into()})
}

fn truncate(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn failed_update_job(
    job_id: &str,
    started_at: &str,
    mut steps: Vec<Value>,
    error: &str,
    step: &str,
    detail: &str,
) -> Value {
    let output = if detail.is_empty() {
        error.to_owned()
    } else {
        format!("{error}: {detail}")
    };
    steps.push(update_step(step, "failed", output));
    json!({
        "job_id": job_id,
        "status": "failed",
        "started_at": started_at,
        "finished_at": now_iso(),
        "steps": steps,
        "error": error,
    })
}

fn failed_git_step(
    job_id: &str,
    started_at: &str,
    mut steps: Vec<Value>,
    error: &str,
    step: &str,
    output: String,
) -> Value {
    steps.push(update_step(step, "failed", output));
    json!({
        "job_id": job_id,
        "status": "failed",
        "started_at": started_at,
        "finished_at": now_iso(),
        "steps": steps,
        "error": error,
    })
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

fn run_update_job(
    job_id: &str,
    source: &str,
    branch: &str,
    project_root: &Path,
    allowed_branches: &[String],
    allowed_local_sources: &[String],
) -> Value {
    let started_at = now_iso();
    let mut steps = Vec::new();
    if !allowed_branches.iter().any(|allowed| allowed == branch) {
        return failed_update_job(
            job_id,
            &started_at,
            steps,
            "branch_not_allowed",
            "git_precheck",
            &format!("branch={branch}"),
        );
    }

    let remote = if source == "origin" {
        OsString::from("origin")
    } else if let Some(path) = source.strip_prefix("local:") {
        let input = Path::new(path);
        let rejected = absolute_path(input);
        let Ok(resolved) = std::fs::canonicalize(input) else {
            return failed_update_job(
                job_id,
                &started_at,
                steps,
                "local_path_not_allowed",
                "git_precheck",
                &rejected.to_string_lossy(),
            );
        };
        let allowed = allowed_local_sources
            .iter()
            .any(|entry| std::fs::canonicalize(entry).is_ok_and(|entry| entry == resolved));
        if !allowed {
            return failed_update_job(
                job_id,
                &started_at,
                steps,
                "local_path_not_allowed",
                "git_precheck",
                &resolved.to_string_lossy(),
            );
        }
        resolved.into_os_string()
    } else {
        return failed_update_job(
            job_id,
            &started_at,
            steps,
            "invalid_source",
            "git_precheck",
            source,
        );
    };

    let version_args = [OsString::from("--version")];
    let version = match run_git(project_root, &version_args) {
        Ok(output) => output,
        Err(_) => {
            return failed_update_job(
                job_id,
                &started_at,
                steps,
                "git_not_available",
                "git_precheck",
                "",
            )
        }
    };
    if !version.success {
        return failed_update_job(
            job_id,
            &started_at,
            steps,
            "git_not_available",
            "git_precheck",
            &version.stderr,
        );
    }

    let status_args = [
        OsString::from("status"),
        OsString::from("--porcelain"),
        OsString::from("--untracked-files=no"),
    ];
    let dirty = match run_git(project_root, &status_args) {
        Ok(output) => output,
        Err(_) => {
            return failed_update_job(
                job_id,
                &started_at,
                steps,
                "git_working_tree_dirty",
                "git_precheck",
                "",
            )
        }
    };
    if !dirty.success || !dirty.stdout.is_empty() {
        return failed_update_job(
            job_id,
            &started_at,
            steps,
            "git_working_tree_dirty",
            "git_precheck",
            &truncate(&dirty.stdout, 200),
        );
    }

    let head_args = [
        OsString::from("rev-parse"),
        OsString::from("--short"),
        OsString::from("HEAD"),
    ];
    let pre_commit = run_git(project_root, &head_args)
        .map(|output| output.stdout)
        .unwrap_or_default();
    steps.push(update_step("git_precheck", "success", ""));

    let fetch_args = [OsString::from("fetch"), remote.clone()];
    let fetch = match run_git(project_root, &fetch_args) {
        Ok(output) => output,
        Err(error) => GitOutput {
            success: false,
            stdout: String::new(),
            stderr: error.to_string(),
        },
    };
    if !fetch.success {
        return failed_git_step(
            job_id,
            &started_at,
            steps,
            "git_fetch_failed",
            "git_fetch",
            truncate(&fetch.stderr, 500),
        );
    }
    steps.push(update_step(
        "git_fetch",
        "success",
        truncate(&fetch.stdout, 200),
    ));

    let pull_args = [
        OsString::from("pull"),
        OsString::from("--ff-only"),
        remote,
        OsString::from(branch),
    ];
    let pull = match run_git(project_root, &pull_args) {
        Ok(output) => output,
        Err(error) => GitOutput {
            success: false,
            stdout: String::new(),
            stderr: error.to_string(),
        },
    };
    if !pull.success {
        return failed_git_step(
            job_id,
            &started_at,
            steps,
            "git_pull_failed",
            "git_pull_ff_only",
            truncate(&pull.stderr, 500),
        );
    }
    let post_commit = run_git(project_root, &head_args)
        .map(|output| output.stdout)
        .unwrap_or_default();
    steps.push(update_step(
        "git_pull_ff_only",
        "success",
        truncate(&pull.stdout, 200),
    ));
    steps.push(update_step("restart_signal", "success", ""));
    let restarting = json!({
        "job_id": job_id,
        "status": "restarting",
        "started_at": started_at,
        "finished_at": null,
        "steps": steps,
        "pre_commit": pre_commit,
        "post_commit": post_commit,
        "error": null,
    });
    if let Err(error) = save_last_job(&last_job_path(project_root), &restarting) {
        let mut steps = restarting["steps"].as_array().cloned().unwrap_or_default();
        steps.pop();
        return failed_update_job(
            job_id,
            &started_at,
            steps,
            "restart_failed",
            "restart_signal",
            &error.to_string(),
        );
    }
    restarting
}

async fn fleet_update_status(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(registry) = state.peer_registry.get() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "LAN Cowork not enabled"}),
        );
    };
    if let Err(error) = fleet_peer_guard(&*state, registry, &method, &uri, &headers, &body).await {
        return error;
    }

    let query = Query::<HashMap<String, String>>::try_from_uri(&uri)
        .map(|Query(query)| query)
        .unwrap_or_default();
    let job_id = query.get("job_id").map_or("", String::as_str).trim();
    if job_id.is_empty() {
        return response(StatusCode::BAD_REQUEST, json!({"error": "missing job_id"}));
    }
    if let Some(job) = active_jobs()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(job_id)
        .cloned()
    {
        return Json(job).into_response();
    }
    let Some(job) = load_last_job(state.project_root()) else {
        return response(StatusCode::NOT_FOUND, json!({"error": "job_not_found"}));
    };
    if job.get("job_id").and_then(Value::as_str) != Some(job_id) {
        return response(StatusCode::NOT_FOUND, json!({"error": "job_not_found"}));
    }
    Json(job).into_response()
}

#[cfg(not(test))]
fn exec_restart() -> std::io::Result<()> {
    let current_exe = std::env::current_exe()?;

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt, ptr};

        #[cfg(target_os = "linux")]
        if current_exe.as_os_str().as_bytes().ends_with(b" (deleted)") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "current executable was replaced",
            ));
        }
        let args = std::iter::once(current_exe.into_os_string())
            .chain(std::env::args_os().skip(1))
            .map(|arg| {
                CString::new(arg.as_os_str().as_bytes()).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "process argument contains NUL",
                    )
                })
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        let mut argv: Vec<_> = args.iter().map(|arg| arg.as_ptr()).collect();
        argv.push(ptr::null());
        unsafe { libc::execv(args[0].as_ptr(), argv.as_ptr()) };
        Err(std::io::Error::last_os_error())
    }

    #[cfg(any(target_os = "macos", windows))]
    {
        let mut command = Command::new(current_exe);
        command.args(std::env::args_os().skip(1));

        #[cfg(target_os = "macos")]
        unsafe {
            use std::os::unix::process::CommandExt;

            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;

            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            command.creation_flags(CREATE_NEW_PROCESS_GROUP);
        }
        command.spawn()?;
        std::process::exit(0);
    }

    #[cfg(not(any(unix, windows)))]
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "restart is unsupported on this platform",
    ))
}

#[cfg(not(test))]
fn schedule_restart() {
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        if let Err(error) = exec_restart() {
            tracing::warn!(error = %error, "fleet restart failed");
        }
    });
}

#[cfg(test)]
static RESTART_SCHEDULE_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
static UPDATE_TASK_PAUSED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn schedule_restart() {
    RESTART_SCHEDULE_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

fn config_string_list(value: Option<&Value>, default: &[&str]) -> Vec<String> {
    let Some(values) = value.and_then(Value::as_array) else {
        return default.iter().map(|value| (*value).to_owned()).collect();
    };
    if values.is_empty() {
        return default.iter().map(|value| (*value).to_owned()).collect();
    }
    values
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

async fn fleet_update(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(registry) = state.peer_registry.get() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "LAN Cowork not enabled"}),
        );
    };
    let requester_peer_id =
        match fleet_peer_guard(&*state, registry, &method, &uri, &headers, &body).await {
            Ok(peer_id) => peer_id,
            Err(error) => return error,
        };
    if let Err(error) = check_update_allowed(&state, &headers, &requester_peer_id, true, false) {
        return response(
            StatusCode::FORBIDDEN,
            json!({"error": error, "message": error}),
        );
    }

    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or("");
    let content_type = content_type.to_ascii_lowercase();
    if content_type != "application/json" && !content_type.ends_with("+json") {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"error": "JSON body is required", "code": "invalid_content_type"}),
        );
    }
    let data: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return response(
                StatusCode::BAD_REQUEST,
                json!({"error": "Invalid JSON body", "code": "invalid_json"}),
            )
        }
    };
    let Some(data) = data.as_object() else {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"error": "JSON object body is required", "code": "invalid_json_object"}),
        );
    };
    let source = match data.get("source") {
        None => "origin".to_owned(),
        Some(Value::String(source)) => source.clone(),
        Some(_) => {
            return response(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_source", "message": "source must be a string"}),
            )
        }
    };
    let branch = match data.get("branch") {
        None => "main".to_owned(),
        Some(Value::String(branch)) => branch.clone(),
        Some(_) => {
            return response(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_branch", "message": "branch must be a string"}),
            )
        }
    };
    if source != "origin" && !source.starts_with("local:") {
        return response(
            StatusCode::BAD_REQUEST,
            json!({
                "error": "invalid_source",
                "message": "source must be 'origin' or 'local:<path>'",
            }),
        );
    }

    let fleet = fleet_config(&*state);
    let allowed_branches = config_string_list(fleet.get("allowed_branches"), &["main"]);
    if !allowed_branches.iter().any(|allowed| allowed == &branch) {
        return response(
            StatusCode::BAD_REQUEST,
            json!({
                "error": "branch_not_allowed",
                "message": format!("branch '{branch}' not in allowed_branches"),
            }),
        );
    }
    let allowed_local_sources = config_string_list(fleet.get("allowed_local_sources"), &[]);
    let job_id = uuid::Uuid::new_v4().simple().to_string()[..12].to_owned();
    {
        let mut jobs = active_jobs()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some((current_job_id, _)) = jobs.iter().find(|(_, job)| {
            matches!(
                job.get("status").and_then(Value::as_str),
                Some("pending" | "running" | "restarting")
            )
        }) {
            return response(
                StatusCode::CONFLICT,
                json!({
                    "error": "update_in_progress",
                    "current_job_id": current_job_id,
                }),
            );
        }
        jobs.insert(
            job_id.clone(),
            json!({
                "job_id": job_id,
                "status": "pending",
                "started_at": null,
                "finished_at": null,
                "steps": [],
                "error": null,
            }),
        );
    }

    let task_job_id = job_id.clone();
    let project_root = state.project_root().to_owned();
    tokio::spawn(async move {
        #[cfg(test)]
        while UPDATE_TASK_PAUSED.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        if let Some(job) = active_jobs()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(&task_job_id)
        {
            job["status"] = json!("running");
        }
        let run_job_id = task_job_id.clone();
        let run_root = project_root.clone();
        let result = tokio::task::spawn_blocking(move || {
            run_update_job(
                &run_job_id,
                &source,
                &branch,
                &run_root,
                &allowed_branches,
                &allowed_local_sources,
            )
        })
        .await;
        let Ok(result) = result else {
            if let Some(job) = active_jobs()
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get_mut(&task_job_id)
            {
                job["status"] = json!("failed");
                job["error"] = json!("update_job_failed");
            }
            return;
        };
        let restarting = result.get("status").and_then(Value::as_str) == Some("restarting");
        {
            let mut jobs = active_jobs()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(job) = jobs.get_mut(&task_job_id) {
                *job = result.clone();
            }
            let _ = save_last_job(&last_job_path(&project_root), &result);
        }
        if restarting {
            schedule_restart();
        }
    });
    response(
        StatusCode::OK,
        json!({"job_id": job_id, "status": "pending"}),
    )
}

async fn fleet_restart(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(registry) = state.peer_registry.get() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "LAN Cowork not enabled"}),
        );
    };
    let requester_peer_id =
        match fleet_peer_guard(&*state, registry, &method, &uri, &headers, &body).await {
            Ok(peer_id) => peer_id,
            Err(error) => return error,
        };
    if let Err(error) = check_update_allowed(&state, &headers, &requester_peer_id, true, true) {
        return response(
            StatusCode::FORBIDDEN,
            json!({"error": error, "message": error}),
        );
    }
    schedule_restart();
    response(
        StatusCode::OK,
        json!({"accepted": true, "message": "restart scheduled"}),
    )
}

fn fleet_config(state: &dyn LanCoworkHost) -> Value {
    ext_config(&load_config_json(state.config_path()))
        .get("fleet")
        .cloned()
        .unwrap_or_else(|| json!({}))
}

async fn fleet_session_guard(
    state: &dyn LanCoworkHost,
    session: Option<&tower_sessions::Session>,
) -> Result<(), Response> {
    if state.require_session(session).await.is_some() {
        return Err(response(
            StatusCode::UNAUTHORIZED,
            json!({"error":"session required"}),
        ));
    }
    Ok(())
}

// The unit error is part of the existing public parsing contract.
#[allow(clippy::result_unit_err)]
pub fn parse_lines(value: Option<&str>) -> Result<usize, ()> {
    match value.unwrap_or("200").trim().parse::<i64>() {
        Ok(value) => Ok(value.clamp(1, 1000) as usize),
        Err(error) => match error.kind() {
            std::num::IntErrorKind::PosOverflow => Ok(1000),
            std::num::IntErrorKind::NegOverflow => Ok(1),
            _ => Err(()),
        },
    }
}

fn relay_target(uri: &Uri) -> String {
    url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
        .find_map(|(key, value)| (key == "peer_id").then(|| value.into_owned()))
        .unwrap_or_default()
}

pub fn parse_level(value: Option<&str>) -> Option<&str> {
    match value {
        Some(level @ ("DEBUG" | "INFO" | "WARNING" | "ERROR")) => Some(level),
        _ => None,
    }
}

fn fleet_log_event(entry: LogLine) -> Event {
    let level = match entry.level.as_str() {
        "WARN" => "WARNING",
        "TRACE" => "DEBUG",
        level => level,
    };
    Event::default().event("log").data(
        json!({
            "timestamp": entry.timestamp,
            "message": entry.message,
            "seq": entry.seq,
            "source": entry.target,
            "level": level,
        })
        .to_string(),
    )
}

/// Releases a fleet log-stream connection slot when the SSE stream ends or is
/// dropped (client disconnect), mirroring core's `LogConnectionGuard`
/// (`yu-server/src/logs/routes.rs`). Holds a `Weak` handle rather than an
/// owned `Arc`: the connection budget is bookkeeping, not a reason to keep
/// the whole host (and everything it owns, e.g. the log ring) alive for the
/// stream's lifetime. If the host has already been torn down by the time
/// this guard drops, there is nothing left to release either.
struct FleetLogStreamGuard {
    host: std::sync::Weak<dyn LanCoworkHost>,
    ip: String,
}

impl Drop for FleetLogStreamGuard {
    fn drop(&mut self) {
        if let Some(host) = self.host.upgrade() {
            host.unregister_log_stream_connection(&self.ip);
        }
    }
}

pub fn local_log_response(
    host: Arc<dyn LanCoworkHost>,
    lines: usize,
    level: Option<&str>,
    client_ip: &str,
) -> Response {
    if !host.register_log_stream_connection(client_ip) {
        return response(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error": "too_many_log_sse_connections"}),
        );
    }
    let guard = FleetLogStreamGuard {
        host: Arc::downgrade(&host),
        ip: client_ip.to_string(),
    };
    let ring_level = level.map(|level| if level == "WARNING" { "WARN" } else { level });
    let min_rank = ring_level.map(level_rank).unwrap_or(0);
    let (live, backlog) = host.log_open(lines, ring_level);
    let event_stream = stream::unfold(
        (backlog.into_iter(), live, false, guard),
        move |(mut backlog, mut live, closed, guard)| async move {
            if closed {
                return None;
            }
            if let Some(entry) = backlog.next() {
                return Some((
                    Ok::<_, Infallible>(fleet_log_event(entry)),
                    (backlog, live, false, guard),
                ));
            }
            loop {
                match live.next().await {
                    Some(LogEvent::Line(entry)) if level_rank(&entry.level) >= min_rank => {
                        return Some((Ok(fleet_log_event(entry)), (backlog, live, false, guard)));
                    }
                    Some(LogEvent::Line(_)) => continue,
                    Some(LogEvent::Closed) => {
                        return Some((
                            Ok(Event::default().event("close").data("{}")),
                            (backlog, live, true, guard),
                        ));
                    }
                    None => return None,
                }
            }
        },
    );
    let mut response = Sse::new(event_stream).into_response();
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
}

fn raw_sse_response(body: Body) -> Response {
    let mut response = body.into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
}

fn relay_error_response(message: &str) -> Response {
    raw_sse_response(Body::from(format!(
        "event: error\ndata: {}\n\nevent: close\ndata: {{}}\n\n",
        json!({"error": message})
    )))
}

fn relay_close_response() -> Response {
    raw_sse_response(Body::from("event: close\ndata: {}\n\n"))
}

async fn relay_log_response(
    state: &LanCoworkState,
    registry: std::sync::Arc<PeerRegistry>,
    peer: super::lan_cowork_registry::PeerInfo,
    lines: usize,
    level: Option<&str>,
) -> Response {
    let Some(seed) = load_identity_seed(state.db_read()).await else {
        return relay_close_response();
    };
    let query = level.map_or_else(
        || format!("lines={lines}"),
        |level| format!("lines={lines}&level={level}"),
    );
    let path = "/ext/lan_cowork/fleet/logs/stream";
    let transport =
        PeerTransport::new(registry.local_peer_id(), seed, registry, state.host.clone());
    let mut headers = match transport.build_peer_headers(&peer, "GET", path, &query, &[]) {
        Ok(headers) => headers,
        Err(_) => return relay_close_response(),
    };
    headers.insert(
        "X-Requested-With",
        reqwest::header::HeaderValue::from_static("FleetRelay"),
    );
    headers.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("text/event-stream"),
    );
    let (client, base) = match build_peer_client(&peer.api_host, peer.api_port, None, None).await {
        Ok(value) => value,
        Err(_) => return relay_close_response(),
    };
    let upstream = match client
        .get(format!("{base}{path}?{query}"))
        .headers(headers)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return relay_close_response(),
    };
    if upstream.status() != reqwest::StatusCode::OK {
        return relay_error_response(&format!("peer returned {}", upstream.status().as_u16()));
    }
    let body = upstream
        .bytes_stream()
        .filter_map(|chunk| async move { chunk.ok().map(Ok::<_, Infallible>) })
        .chain(stream::once(async {
            Ok::<_, Infallible>(Bytes::from_static(b"event: close\ndata: {}\n\n"))
        }));
    raw_sse_response(Body::from_stream(body))
}

async fn fleet_logs_stream(
    State(state): State<LanCoworkState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    session: Option<Extension<tower_sessions::Session>>,
    client_ip: Option<Extension<PeerSourceIp>>,
    body: Bytes,
) -> Response {
    let Some(registry) = state.peer_registry.get().cloned() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"service_unavailable"}),
        );
    };
    let target_peer_id = relay_target(&uri);
    let local_peer_id = registry.local_peer_id();
    let relay_peer = if !target_peer_id.is_empty() && target_peer_id != local_peer_id {
        if let Err(error) =
            fleet_session_guard(&*state, session.as_ref().map(|Extension(session)| session)).await
        {
            return error;
        }
        if !fleet_config(&*state)
            .get("chief")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return response(StatusCode::NOT_FOUND, json!({"error":"not_chief"}));
        }
        let Some(peer) = registry.get(&target_peer_id) else {
            return response(StatusCode::NOT_FOUND, json!({"error":"peer_not_found"}));
        };
        Some(peer)
    } else if headers.contains_key("X-Peer-Id") {
        let peer_id = match peer_only(&*state, &method, &uri, &headers, &body).await {
            Ok(peer_id) => peer_id,
            Err(error) => return error,
        };
        let fleet = fleet_config(&*state);
        let allowed = parse_allowlist(
            fleet
                .get("allow_log_stream_from")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        if !peer_id_in_allowlist(&peer_id, &allowed) {
            return response(
                StatusCode::FORBIDDEN,
                json!({"error":"not_in_allowlist","message":"not in allow_log_stream_from"}),
            );
        }
        None
    } else {
        if let Err(error) =
            fleet_session_guard(&*state, session.as_ref().map(|Extension(session)| session)).await
        {
            return error;
        }
        None
    };
    let query = Query::<HashMap<String, String>>::try_from_uri(&uri)
        .map(|Query(query)| query)
        .unwrap_or_default();
    let lines = match parse_lines(query.get("lines").map(String::as_str)) {
        Ok(lines) => lines,
        Err(()) => {
            return response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"invalid lines"}),
            )
        }
    };
    let level = parse_level(query.get("level").map(String::as_str));
    match relay_peer {
        Some(peer) => relay_log_response(&state, registry, peer, lines, level).await,
        None => {
            let ip = client_ip
                .map(|Extension(PeerSourceIp(ip))| ip)
                .unwrap_or_else(|| "unknown".to_string());
            local_log_response(state.host.clone(), lines, level, &ip)
        }
    }
}

pub fn routes() -> Router<LanCoworkState> {
    Router::new()
        .route("/ext/lan_cowork/fleet/info", get(fleet_info))
        .route("/ext/lan_cowork/fleet/logs/stream", get(fleet_logs_stream))
        .route(
            "/ext/lan_cowork/fleet/update/status",
            get(fleet_update_status),
        )
        .route("/ext/lan_cowork/fleet/update", post(fleet_update))
        .route("/ext/lan_cowork/fleet/restart", post(fleet_restart))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SharedState;
    use axum::{body::Body, http::Request};
    use std::{
        sync::{atomic::Ordering, Arc},
        time::Duration,
    };
    use tower::ServiceExt;

    use crate::routes::{
        lan_cowork::write_config_json,
        lan_cowork_descriptor::{test_guard, TEST_ALLOW_LOOPBACK},
        lan_cowork_registry::PeerInfo,
    };

    const TEST_SEED: [u8; 32] = [21; 32];

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn peer(pubkey: [u8; 32]) -> PeerInfo {
        PeerInfo {
            peer_id: "peer".into(),
            name: "peer".into(),
            api_host: "10.0.0.2".into(),
            api_port: 5000,
            token: None,
            token_expires_at: None,
            token_issued_at: None,
            pubkey: Some(pubkey),
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

    async fn peer_state(
        present_in_registry: bool,
        root: &Path,
    ) -> (SharedState, LanCoworkState, String) {
        use crate::schema::apply_standalone_schema;

        let state =
            crate::state::semantic_test_state_with_root(true, String::new(), root.to_path_buf())
                .await;
        apply_standalone_schema(&state.db).await.unwrap();
        let key =
            openssl::pkey::PKey::private_key_from_raw_bytes(&TEST_SEED, openssl::pkey::Id::ED25519)
                .unwrap();
        let public: [u8; 32] = key.raw_public_key().unwrap().try_into().unwrap();
        let token = "fleet-f3a-test-token".to_owned();
        let timestamp = now();
        sqlx::query(
            "INSERT INTO peers (peer_id,name,api_host,api_port,pubkey,created_at,updated_at) VALUES ('peer','peer','10.0.0.2',5000,?1,0,0)",
        )
        .bind(public.as_slice())
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO peer_tokens (peer_id,token_hash,issued_at,expires_at,revoked_at,source) VALUES ('peer',?1,?2,?3,NULL,'pairing')",
        )
        .bind(crate::auth::peer_transport::hash_token(&token))
        .bind(timestamp)
        .bind(timestamp + 86_400)
        .execute(&state.db)
        .await
        .unwrap();
        let registry = Arc::new(PeerRegistry::new(
            state.db.clone(),
            Duration::from_secs(30),
            "self".into(),
        ));
        if present_in_registry {
            registry.upsert(peer(public)).await.unwrap();
        }
        let lc = LanCoworkState::from_shared(&state);
        lc.peer_registry.set(registry).ok();
        (state, lc, token)
    }

    fn signed_request_with(
        method: &str,
        uri: &str,
        body: &[u8],
        token: Option<&str>,
        nonce: &str,
    ) -> Request<Body> {
        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        let mut headers = crate::auth::peer_transport::sign_headers(
            &TEST_SEED,
            method,
            path,
            query,
            body,
            now(),
            nonce,
            "peer",
        );
        if let Some(token) = token {
            headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        }
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(body.to_vec()))
            .unwrap();
        *request.headers_mut() = headers;
        request
    }

    fn signed_request(uri: &str, token: Option<&str>, nonce: &str) -> Request<Body> {
        signed_request_with("GET", uri, &[], token, nonce)
    }

    fn signed_restart_request(
        token: &str,
        nonce: &str,
        consent_token: Option<&str>,
    ) -> Request<Body> {
        let mut request = signed_request_with(
            "POST",
            "/ext/lan_cowork/fleet/restart",
            &[],
            Some(token),
            nonce,
        );
        if let Some(consent_token) = consent_token {
            request
                .headers_mut()
                .insert("X-Consent-Token", consent_token.parse().unwrap());
        }
        request
    }

    fn signed_update_request(
        token: &str,
        nonce: &str,
        body: Value,
        consent_token: Option<&str>,
    ) -> Request<Body> {
        let body = serde_json::to_vec(&body).unwrap();
        let mut request = signed_request_with(
            "POST",
            "/ext/lan_cowork/fleet/update",
            &body,
            Some(token),
            nonce,
        );
        request.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        if let Some(consent_token) = consent_token {
            request
                .headers_mut()
                .insert("X-Consent-Token", consent_token.parse().unwrap());
        }
        request
    }

    fn restart_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn reset_restart_count() {
        RESTART_SCHEDULE_COUNT.store(0, Ordering::SeqCst);
    }

    fn restart_count() -> usize {
        RESTART_SCHEDULE_COUNT.load(Ordering::SeqCst)
    }

    fn git_output(
        success: bool,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
    ) -> GitTestResult {
        GitTestResult::Output(GitOutput {
            success,
            stdout: stdout.into(),
            stderr: stderr.into(),
        })
    }

    fn set_git_results(results: impl IntoIterator<Item = GitTestResult>) {
        let mut seam = git_test_seam()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        seam.results = Some(results.into_iter().collect());
        seam.commands.clear();
    }

    fn git_commands() -> Vec<Vec<OsString>> {
        git_test_seam()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .commands
            .clone()
    }

    fn reset_update_test_state() {
        reset_restart_count();
        UPDATE_TASK_PAUSED.store(false, Ordering::SeqCst);
        active_jobs()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        let mut seam = git_test_seam()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        seam.results = None;
        seam.commands.clear();
    }

    async fn wait_for_job(job_id: &str) -> Value {
        for _ in 0..2_000 {
            if let Some(job) = active_jobs()
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get(job_id)
                .cloned()
            {
                if !matches!(
                    job.get("status").and_then(Value::as_str),
                    Some("pending" | "running")
                ) {
                    return job;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("update job did not finish");
    }

    async fn json_body(response: Response) -> Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    async fn accepted_job_id(response: Response) -> String {
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["status"], "pending");
        body["job_id"].as_str().unwrap().to_owned()
    }

    async fn session() -> tower_sessions::Session {
        let session = tower_sessions::Session::new(
            None,
            Arc::new(tower_sessions::MemoryStore::default()),
            None,
        );
        session.insert("pin_ok", true).await.unwrap();
        session
    }

    fn request(uri: &str, session: Option<tower_sessions::Session>) -> Request<Body> {
        let mut request = Request::builder().uri(uri).body(Body::empty()).unwrap();
        if let Some(session) = session {
            request.extensions_mut().insert(session);
        }
        request
    }

    fn configure_fleet(state: &SharedState, chief: bool, allow: &[&str]) {
        write_config_json(
            &state.config.config_path,
            &json!({"extensions":{"builtin-lan-cowork":{"fleet":{
                "chief": chief,
                "allow_log_stream_from": allow,
            }}}}),
        )
        .unwrap();
    }

    fn configure_restart_fleet(
        state: &SharedState,
        allow_remote_update: bool,
        allow_update_from: &[&str],
        allow_restart_from: &[&str],
    ) {
        write_config_json(
            &state.config.config_path,
            &json!({"extensions":{"builtin-lan-cowork":{"fleet":{
                "allow_remote_update": allow_remote_update,
                "allow_update_from": allow_update_from,
                "allow_restart_from": allow_restart_from,
            }}}}),
        )
        .unwrap();
    }

    fn configure_update_fleet(
        state: &SharedState,
        allow_remote_update: bool,
        allow_update_from: &[&str],
        allow_restart_from: &[&str],
        allowed_branches: Value,
        allowed_local_sources: &[&str],
    ) {
        write_config_json(
            &state.config.config_path,
            &json!({"extensions":{"builtin-lan-cowork":{"fleet":{
                "allow_remote_update": allow_remote_update,
                "allow_update_from": allow_update_from,
                "allow_restart_from": allow_restart_from,
                "allowed_branches": allowed_branches,
                "allowed_local_sources": allowed_local_sources,
            }}}}),
        )
        .unwrap();
    }

    async fn empty_stream_state(root: &Path, local_peer_id: &str) -> (SharedState, LanCoworkState) {
        use crate::schema::apply_standalone_schema;

        let state =
            crate::state::semantic_test_state_with_root(true, String::new(), root.to_path_buf())
                .await;
        apply_standalone_schema(&state.db).await.unwrap();
        let lc = LanCoworkState::from_shared(&state);
        lc.peer_registry
            .set(Arc::new(PeerRegistry::new(
                state.db.clone(),
                Duration::from_secs(30),
                local_peer_id.to_owned(),
            )))
            .ok();
        (state, lc)
    }

    async fn insert_identity_seed(state: &SharedState) {
        sqlx::query("INSERT INTO lan_cowork_identity (key, value) VALUES ('ed25519_seed', ?1)")
            .bind(TEST_SEED.as_slice())
            .execute(&state.db)
            .await
            .unwrap();
    }

    async fn response_server(response: Vec<u8>) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let count = stream.read(&mut request).await.unwrap();
            request.truncate(count);
            stream.write_all(&response).await.unwrap();
            request
        });
        (port, server)
    }

    async fn point_peer_at(lc: &LanCoworkState, port: u16) {
        let registry = lc.peer_registry.get().unwrap();
        let mut peer = registry.get("peer").unwrap();
        peer.api_host = "127.0.0.1".into();
        peer.api_port = port;
        peer.token = Some("relay-token".into());
        peer.token_expires_at = Some(now() + 3600);
        registry.upsert(peer).await.unwrap();
    }

    fn write_job(root: &Path, job: &Value) {
        save_last_job(&last_job_path(root), job).unwrap();
    }

    #[tokio::test]
    async fn info_requires_peer_id_signature_nonce_and_token() {
        let root = tempfile::tempdir().unwrap();
        let (_state, lc, token) = peer_state(true, root.path()).await;
        let app = routes().with_state(lc.clone());

        let missing_id = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ext/lan_cowork/fleet/info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_id.status(), StatusCode::UNAUTHORIZED);

        let mut bad_signature =
            signed_request("/ext/lan_cowork/fleet/info", Some(&token), "info-bad-sig");
        bad_signature
            .headers_mut()
            .insert("X-Peer-Sig", "invalid".parse().unwrap());
        assert_eq!(
            app.clone().oneshot(bad_signature).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(signed_request(
                    "/ext/lan_cowork/fleet/info",
                    Some(&token),
                    "",
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.oneshot(signed_request(
                "/ext/lan_cowork/fleet/info",
                None,
                "info-no-token",
            ))
            .await
            .unwrap()
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn info_rejects_nonce_replay_and_registry_absence() {
        let root = tempfile::tempdir().unwrap();
        let (_state, lc, token) = peer_state(true, root.path()).await;
        let app = routes().with_state(lc.clone());
        assert_eq!(
            app.clone()
                .oneshot(signed_request(
                    "/ext/lan_cowork/fleet/info",
                    Some(&token),
                    "info-replay",
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.oneshot(signed_request(
                "/ext/lan_cowork/fleet/info",
                Some(&token),
                "info-replay",
            ))
            .await
            .unwrap()
            .status(),
            StatusCode::UNAUTHORIZED
        );

        let (_state, lc, token) = peer_state(false, root.path()).await;
        let response = routes()
            .with_state(lc.clone())
            .oneshot(signed_request(
                "/ext/lan_cowork/fleet/info",
                Some(&token),
                "info-no-registry-peer",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"ok": false, "error": "unknown peer"})
        );
    }

    #[tokio::test]
    async fn valid_info_returns_machine_info_without_allowlist() {
        let root = tempfile::tempdir().unwrap();
        let (_state, lc, token) = peer_state(true, root.path()).await;
        let response = routes()
            .with_state(lc.clone())
            .oneshot(signed_request(
                "/ext/lan_cowork/fleet/info",
                Some(&token),
                "info-ok",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert!(body.get("cpu").is_some());
        assert_eq!(body["roles"], json!([]));
    }

    #[tokio::test]
    async fn restart_auth_chain_rejects_disabled_missing_unknown_and_unpaired_peers() {
        let _guard = restart_test_guard();
        reset_restart_count();
        let path = "/ext/lan_cowork/fleet/restart";

        let disabled = crate::state::semantic_test_state_with(true, String::new()).await;
        let response = routes()
            .with_state(LanCoworkState::from_shared(&disabled))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            json_body(response).await,
            json!({"ok": false, "error": "LAN Cowork not enabled"})
        );

        let root = tempfile::tempdir().unwrap();
        let (state, lc, token) = peer_state(true, root.path()).await;
        let app = routes().with_state(lc.clone());
        let missing_peer_id = Request::builder()
            .method("POST")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(missing_peer_id).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let missing_signature = Request::builder()
            .method("POST")
            .uri(path)
            .header("X-Peer-Id", "peer")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(missing_signature)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(signed_restart_request(&token, "", None))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        sqlx::query("UPDATE peers SET pubkey = NULL WHERE peer_id = 'peer'")
            .execute(&state.db)
            .await
            .unwrap();
        let response = app
            .oneshot(signed_restart_request(&token, "restart-unpaired", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"ok": false, "error": "peer not paired"})
        );

        let root = tempfile::tempdir().unwrap();
        let (_state, lc, token) = peer_state(false, root.path()).await;
        let response = routes()
            .with_state(lc.clone())
            .oneshot(signed_restart_request(
                &token,
                "restart-registry-absent",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"ok": false, "error": "unknown peer"})
        );
        assert_eq!(restart_count(), 0);
    }

    #[tokio::test]
    async fn restart_policy_preserves_consent_and_allowlist_exclusivity() {
        let _guard = restart_test_guard();
        let _consent_guard = crate::routes::lan_cowork_fleet_consent::consent_test_guard();
        reset_restart_count();
        let root = tempfile::tempdir().unwrap();
        let (state, lc, token) = peer_state(true, root.path()).await;
        let app = routes().with_state(lc.clone());

        configure_restart_fleet(&state, false, &[], &[]);
        let response = app
            .clone()
            .oneshot(signed_restart_request(&token, "restart-no-consent", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"error": "remote_update_disabled", "message": "remote_update_disabled"})
        );
        let response = app
            .clone()
            .oneshot(signed_restart_request(
                &token,
                "restart-invalid-consent",
                Some("invalid"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"error": "consent_token_invalid", "message": "consent_token_invalid"})
        );

        crate::routes::lan_cowork_fleet_consent::insert_test_consent(
            "restart-valid-consent",
            "peer",
        );
        let response = app
            .clone()
            .oneshot(signed_restart_request(
                &token,
                "restart-consent-allowed",
                Some("restart-valid-consent"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await,
            json!({"accepted": true, "message": "restart scheduled"})
        );
        assert_eq!(restart_count(), 1);

        reset_restart_count();
        configure_restart_fleet(&state, true, &[], &[]);
        let response = app
            .clone()
            .oneshot(signed_restart_request(
                &token,
                "restart-not-allowlisted",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"error": "not_in_allowlist", "message": "not_in_allowlist"})
        );

        configure_restart_fleet(&state, true, &["peer"], &[]);
        assert_eq!(
            app.clone()
                .oneshot(signed_restart_request(
                    &token,
                    "restart-update-allowlist",
                    None,
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        configure_restart_fleet(&state, true, &[], &["peer"]);
        assert_eq!(
            app.clone()
                .oneshot(signed_restart_request(
                    &token,
                    "restart-specific-allowlist",
                    None,
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );

        crate::routes::lan_cowork_fleet_consent::insert_test_consent(
            "restart-unused-consent",
            "peer",
        );
        configure_restart_fleet(&state, true, &["peer"], &[]);
        assert_eq!(
            app.clone()
                .oneshot(signed_restart_request(
                    &token,
                    "restart-consent-ignored",
                    Some("restart-unused-consent"),
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        configure_restart_fleet(&state, false, &[], &[]);
        assert_eq!(
            app.oneshot(signed_restart_request(
                &token,
                "restart-consent-still-valid",
                Some("restart-unused-consent"),
            ))
            .await
            .unwrap()
            .status(),
            StatusCode::OK
        );
        assert_eq!(restart_count(), 4);
    }

    #[tokio::test]
    async fn restart_seam_rejects_replay_and_accepts_each_authorized_request() {
        let _guard = restart_test_guard();
        reset_restart_count();
        let root = tempfile::tempdir().unwrap();
        let (state, lc, token) = peer_state(true, root.path()).await;
        configure_restart_fleet(&state, true, &["peer"], &[]);
        let app = routes().with_state(lc.clone());

        let first = app
            .clone()
            .oneshot(signed_restart_request(&token, "restart-replay", None))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(restart_count(), 1);
        let replay = app
            .clone()
            .oneshot(signed_restart_request(&token, "restart-replay", None))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(restart_count(), 1);

        reset_restart_count();
        for nonce in ["restart-double-one", "restart-double-two"] {
            assert_eq!(
                app.clone()
                    .oneshot(signed_restart_request(&token, nonce, None))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        assert_eq!(restart_count(), 2);
    }

    #[tokio::test]
    async fn restart_allows_post_only_without_scheduling_other_methods() {
        let _guard = restart_test_guard();
        reset_restart_count();
        let state = crate::state::semantic_test_state_with(true, String::new()).await;
        let app = routes().with_state(LanCoworkState::from_shared(&state));
        for method in ["GET", "PUT", "DELETE"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/ext/lan_cowork/fleet/restart")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        }
        assert_eq!(restart_count(), 0);
    }

    #[tokio::test]
    async fn update_auth_chain_rejects_disabled_missing_unknown_unpaired_and_replayed_peers() {
        let _guard = restart_test_guard();
        reset_update_test_state();
        let path = "/ext/lan_cowork/fleet/update";

        let disabled = crate::state::semantic_test_state_with(true, String::new()).await;
        let response = routes()
            .with_state(LanCoworkState::from_shared(&disabled))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            json_body(response).await,
            json!({"ok": false, "error": "LAN Cowork not enabled"})
        );

        let root = tempfile::tempdir().unwrap();
        let (state, lc, token) = peer_state(true, root.path()).await;
        configure_update_fleet(&state, true, &["peer"], &[], json!(["main"]), &[]);
        let app = routes().with_state(lc.clone());
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("X-Peer-Id", "peer")
                        .header("Authorization", format!("Bearer {token}"))
                        .header("Content-Type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(signed_update_request(&token, "", json!({}), None))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        set_git_results([GitTestResult::Error(std::io::ErrorKind::NotFound)]);
        let accepted = app
            .clone()
            .oneshot(signed_update_request(
                &token,
                "update-replay",
                json!({}),
                None,
            ))
            .await
            .unwrap();
        let job_id = accepted_job_id(accepted).await;
        assert_eq!(wait_for_job(&job_id).await["error"], "git_not_available");
        assert_eq!(
            app.clone()
                .oneshot(signed_update_request(
                    &token,
                    "update-replay",
                    json!({}),
                    None,
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        sqlx::query("UPDATE peers SET pubkey = NULL WHERE peer_id = 'peer'")
            .execute(&state.db)
            .await
            .unwrap();
        let response = app
            .oneshot(signed_update_request(
                &token,
                "update-unpaired",
                json!({}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"ok": false, "error": "peer not paired"})
        );

        let other_root = tempfile::tempdir().unwrap();
        let (_state, lc, token) = peer_state(false, other_root.path()).await;
        let response = routes()
            .with_state(lc.clone())
            .oneshot(signed_update_request(
                &token,
                "update-unknown",
                json!({}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"ok": false, "error": "unknown peer"})
        );
        assert_eq!(restart_count(), 0);
        reset_update_test_state();
    }

    #[tokio::test]
    async fn update_policy_uses_consent_or_update_allowlist_but_never_restart_allowlist() {
        let _guard = restart_test_guard();
        let _consent_guard = crate::routes::lan_cowork_fleet_consent::consent_test_guard();
        reset_update_test_state();
        let root = tempfile::tempdir().unwrap();
        let (state, lc, token) = peer_state(true, root.path()).await;
        let app = routes().with_state(lc.clone());

        configure_update_fleet(&state, false, &[], &[], json!(["main"]), &[]);
        let response = app
            .clone()
            .oneshot(signed_update_request(
                &token,
                "update-no-consent",
                json!({}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"error": "remote_update_disabled", "message": "remote_update_disabled"})
        );
        let response = app
            .clone()
            .oneshot(signed_update_request(
                &token,
                "update-bad-consent",
                json!({}),
                Some("invalid"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"error": "consent_token_invalid", "message": "consent_token_invalid"})
        );

        crate::routes::lan_cowork_fleet_consent::insert_test_consent("update-consent", "peer");
        set_git_results([GitTestResult::Error(std::io::ErrorKind::NotFound)]);
        let response = app
            .clone()
            .oneshot(signed_update_request(
                &token,
                "update-valid-consent",
                json!({}),
                Some("update-consent"),
            ))
            .await
            .unwrap();
        let job_id = accepted_job_id(response).await;
        wait_for_job(&job_id).await;

        configure_update_fleet(&state, true, &[], &[], json!(["main"]), &[]);
        let response = app
            .clone()
            .oneshot(signed_update_request(
                &token,
                "update-not-allowlisted",
                json!({}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"error": "not_in_allowlist", "message": "not_in_allowlist"})
        );

        configure_update_fleet(&state, true, &["peer"], &[], json!(["main"]), &[]);
        set_git_results([GitTestResult::Error(std::io::ErrorKind::NotFound)]);
        let response = app
            .clone()
            .oneshot(signed_update_request(
                &token,
                "update-update-allowlist",
                json!({}),
                None,
            ))
            .await
            .unwrap();
        let job_id = accepted_job_id(response).await;
        wait_for_job(&job_id).await;

        configure_update_fleet(&state, true, &[], &["peer"], json!(["main"]), &[]);
        let response = app
            .oneshot(signed_update_request(
                &token,
                "update-restart-only",
                json!({}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"error": "not_in_allowlist", "message": "not_in_allowlist"})
        );
        assert_eq!(restart_count(), 0);
        reset_update_test_state();
    }

    #[tokio::test]
    async fn update_validates_after_auth_and_reserves_one_node_wide_job() {
        let _guard = restart_test_guard();
        reset_update_test_state();
        let root = tempfile::tempdir().unwrap();
        let (state, lc, token) = peer_state(true, root.path()).await;
        let app = routes().with_state(lc.clone());

        configure_update_fleet(&state, true, &[], &["peer"], json!(["main"]), &[]);
        let response = app
            .clone()
            .oneshot(signed_update_request(
                &token,
                "update-auth-before-body",
                json!({"source": 1}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        configure_update_fleet(&state, true, &["peer"], &[], json!(["main"]), &[]);
        for (index, body, error, message) in [
            (
                0,
                json!({"source": 1}),
                "invalid_source",
                "source must be a string",
            ),
            (
                1,
                json!({"source": "upstream"}),
                "invalid_source",
                "source must be 'origin' or 'local:<path>'",
            ),
            (
                2,
                json!({"branch": 1}),
                "invalid_branch",
                "branch must be a string",
            ),
            (
                3,
                json!({"branch": "dev"}),
                "branch_not_allowed",
                "branch 'dev' not in allowed_branches",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(signed_update_request(
                    &token,
                    &format!("update-invalid-{index}"),
                    body,
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = json_body(response).await;
            assert_eq!(body["error"], error);
            assert_eq!(body["message"], message);
        }

        active_jobs().lock().unwrap().insert(
            "foreign-job".into(),
            json!({"job_id":"foreign-job","status":"pending","requester_peer_id":"other"}),
        );
        let response = app
            .clone()
            .oneshot(signed_update_request(
                &token,
                "update-node-wide-conflict",
                json!({}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            json_body(response).await,
            json!({"error":"update_in_progress","current_job_id":"foreign-job"})
        );
        active_jobs().lock().unwrap().clear();

        for method in ["GET", "PUT", "DELETE"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/ext/lan_cowork/fleet/update")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        }
        assert_eq!(restart_count(), 0);
        reset_update_test_state();
    }

    #[tokio::test]
    async fn local_sources_fail_asynchronously_fail_closed_and_hold_the_job_slot() {
        let _guard = restart_test_guard();
        reset_update_test_state();
        let root = tempfile::tempdir().unwrap();
        let remote = root.path().join("remote");
        std::fs::create_dir(&remote).unwrap();
        let (state, lc, token) = peer_state(true, root.path()).await;
        configure_update_fleet(&state, true, &["peer"], &[], json!(["main"]), &[]);
        let app = routes().with_state(lc.clone());

        UPDATE_TASK_PAUSED.store(true, Ordering::SeqCst);
        let response = app
            .clone()
            .oneshot(signed_update_request(
                &token,
                "update-local-denied",
                json!({"source": format!("local:{}", remote.display())}),
                None,
            ))
            .await
            .unwrap();
        let job_id = accepted_job_id(response).await;
        let response = app
            .clone()
            .oneshot(signed_update_request(
                &token,
                "update-local-slot",
                json!({}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(json_body(response).await["current_job_id"], job_id);
        UPDATE_TASK_PAUSED.store(false, Ordering::SeqCst);

        let job = wait_for_job(&job_id).await;
        assert_eq!(job["status"], "failed");
        assert_eq!(job["error"], "local_path_not_allowed");
        assert_eq!(
            job["steps"][0]["output"],
            format!(
                "local_path_not_allowed: {}",
                std::fs::canonicalize(&remote).unwrap().display()
            )
        );
        let status = app
            .clone()
            .oneshot(signed_request(
                &format!("/ext/lan_cowork/fleet/update/status?job_id={job_id}"),
                Some(&token),
                "update-local-status",
            ))
            .await
            .unwrap();
        assert_eq!(json_body(status).await, job);

        let missing = root.path().join("missing-input");
        let response = app
            .clone()
            .oneshot(signed_update_request(
                &token,
                "update-local-missing-input",
                json!({"source": format!("local:{}", missing.display())}),
                None,
            ))
            .await
            .unwrap();
        let missing_id = accepted_job_id(response).await;
        assert_eq!(
            wait_for_job(&missing_id).await["error"],
            "local_path_not_allowed"
        );

        configure_update_fleet(
            &state,
            true,
            &["peer"],
            &[],
            json!(["main"]),
            &[missing.to_str().unwrap()],
        );
        let response = app
            .oneshot(signed_update_request(
                &token,
                "update-local-missing-entry",
                json!({"source": format!("local:{}", remote.display())}),
                None,
            ))
            .await
            .unwrap();
        let missing_entry_id = accepted_job_id(response).await;
        assert_eq!(
            wait_for_job(&missing_entry_id).await["error"],
            "local_path_not_allowed"
        );
        assert_eq!(restart_count(), 0);
        reset_update_test_state();
    }

    #[test]
    fn update_state_machine_pins_commands_errors_and_output_limits() {
        let _guard = restart_test_guard();
        reset_update_test_state();
        let root = tempfile::tempdir().unwrap();
        let branches = vec!["main".to_owned()];

        set_git_results([
            git_output(true, "git version", ""),
            git_output(true, "x".repeat(250), ""),
        ]);
        let dirty = run_update_job("dirty", "origin", "main", root.path(), &branches, &[]);
        assert_eq!(dirty["error"], "git_working_tree_dirty");
        assert_eq!(
            dirty["steps"][0]["output"]
                .as_str()
                .unwrap()
                .strip_prefix("git_working_tree_dirty: ")
                .unwrap()
                .chars()
                .count(),
            200
        );

        set_git_results([
            git_output(true, "git version", ""),
            git_output(true, "", ""),
            git_output(true, "1111111", ""),
            git_output(false, "", "f".repeat(600)),
        ]);
        let fetch = run_update_job("fetch", "origin", "main", root.path(), &branches, &[]);
        assert_eq!(fetch["error"], "git_fetch_failed");
        assert_eq!(fetch["steps"][1]["name"], "git_fetch");
        assert_eq!(
            fetch["steps"][1]["output"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            500
        );

        set_git_results([
            git_output(true, "git version", ""),
            git_output(true, "", ""),
            git_output(true, "1111111", ""),
            git_output(true, "f".repeat(250), ""),
            git_output(false, "", "pull failed"),
        ]);
        let pull = run_update_job("pull", "origin", "main", root.path(), &branches, &[]);
        assert_eq!(pull["error"], "git_pull_failed");
        assert_eq!(
            pull["steps"][1]["output"].as_str().unwrap().chars().count(),
            200
        );

        set_git_results([
            git_output(true, "git version", ""),
            git_output(true, "", ""),
            git_output(true, "1111111", ""),
            git_output(true, "f".repeat(250), ""),
            git_output(true, "p".repeat(250), ""),
            git_output(true, "2222222", ""),
        ]);
        let success = run_update_job("success", "origin", "main", root.path(), &branches, &[]);
        assert_eq!(success["status"], "restarting");
        assert_eq!(success["pre_commit"], "1111111");
        assert_eq!(success["post_commit"], "2222222");
        assert_eq!(success["steps"][2]["name"], "git_pull_ff_only");
        assert_eq!(
            success["steps"][1]["output"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            200
        );
        assert_eq!(
            success["steps"][2]["output"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            200
        );
        assert_eq!(success["steps"][3]["name"], "restart_signal");
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(last_job_path(root.path())).unwrap())
                .unwrap(),
            success
        );
        let commands = git_commands()
            .into_iter()
            .map(|args| {
                args.into_iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            commands
                .iter()
                .map(|args| args.join(" "))
                .collect::<Vec<_>>(),
            vec![
                "--version".to_owned(),
                "status --porcelain --untracked-files=no".to_owned(),
                "rev-parse --short HEAD".to_owned(),
                "fetch origin".to_owned(),
                "pull --ff-only origin main".to_owned(),
                "rev-parse --short HEAD".to_owned(),
            ]
        );

        let local = root.path().join("allowed-local");
        std::fs::create_dir(&local).unwrap();
        set_git_results([
            git_output(true, "git version", ""),
            git_output(true, "", ""),
            git_output(true, "1111111", ""),
            git_output(true, "", ""),
            git_output(true, "", ""),
            git_output(true, "2222222", ""),
        ]);
        let local_source = format!("local:{}", local.display());
        let local_allowed = vec![
            root.path()
                .join("missing-allowed-local")
                .to_string_lossy()
                .into_owned(),
            local.to_string_lossy().into_owned(),
        ];
        assert_eq!(
            run_update_job(
                "local",
                &local_source,
                "main",
                root.path(),
                &branches,
                &local_allowed,
            )["status"],
            "restarting"
        );
        let commands = git_commands();
        let resolved = std::fs::canonicalize(&local).unwrap();
        assert_eq!(commands[3][1].as_os_str(), resolved.as_os_str());
        assert_eq!(restart_count(), 0);
        reset_update_test_state();
    }

    #[tokio::test]
    async fn update_route_persists_failures_before_scheduling_a_successful_restart() {
        let _guard = restart_test_guard();
        reset_update_test_state();
        let root = tempfile::tempdir().unwrap();
        let (state, lc, token) = peer_state(true, root.path()).await;
        configure_update_fleet(&state, true, &["peer"], &[], json!(["main"]), &[]);
        let app = routes().with_state(lc.clone());

        set_git_results([
            git_output(true, "git version", ""),
            git_output(true, "", ""),
            git_output(true, "1111111", ""),
            git_output(true, "", ""),
            git_output(false, "", "pull failed"),
        ]);
        let response = app
            .clone()
            .oneshot(signed_update_request(
                &token,
                "update-persist-failure",
                json!({}),
                None,
            ))
            .await
            .unwrap();
        let failed_id = accepted_job_id(response).await;
        let failed = wait_for_job(&failed_id).await;
        assert_eq!(failed["error"], "git_pull_failed");
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(last_job_path(root.path())).unwrap())
                .unwrap(),
            failed
        );
        assert_eq!(restart_count(), 0);

        set_git_results([
            git_output(true, "git version", ""),
            git_output(true, "", ""),
            git_output(true, "1111111", ""),
            git_output(true, "", ""),
            git_output(true, "", ""),
            git_output(true, "2222222", ""),
        ]);
        let response = app
            .oneshot(signed_update_request(
                &token,
                "update-restart-success",
                json!({}),
                None,
            ))
            .await
            .unwrap();
        let success_id = accepted_job_id(response).await;
        let success = wait_for_job(&success_id).await;
        for _ in 0..1_000 {
            if restart_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(restart_count(), 1);
        assert_eq!(success["status"], "restarting");
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(last_job_path(root.path())).unwrap())
                .unwrap(),
            success
        );
        reset_update_test_state();
    }

    #[tokio::test]
    async fn update_status_requires_auth_and_matches_unknown_peer_body() {
        let root = tempfile::tempdir().unwrap();
        let (_state, lc, _token) = peer_state(true, root.path()).await;
        let app = routes().with_state(lc.clone());
        let uri = "/ext/lan_cowork/fleet/update/status?job_id=x";
        assert_eq!(
            app.clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap(),)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(signed_request(uri, None, "status-no-token"))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(signed_request(uri, Some("invalid"), "status-bad-token",))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let (_state, lc, token) = peer_state(false, root.path()).await;
        let response = routes()
            .with_state(lc.clone())
            .oneshot(signed_request(uri, Some(&token), "status-no-registry-peer"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"ok": false, "error": "unknown peer"})
        );
    }

    #[tokio::test]
    async fn update_status_validates_job_id_and_returns_active_job_without_heal() {
        let _guard = restart_test_guard();
        reset_update_test_state();
        let root = tempfile::tempdir().unwrap();
        let (_state, lc, token) = peer_state(true, root.path()).await;
        let app = routes().with_state(lc.clone());
        let response = app
            .clone()
            .oneshot(signed_request(
                "/ext/lan_cowork/fleet/update/status",
                Some(&token),
                "status-missing-id",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(response).await,
            json!({"error": "missing job_id"})
        );

        let id = format!("active-{}", now());
        let job = json!({
            "job_id": id.clone(),
            "status": "restarting",
            "post_commit": "abc1234",
            "finished_at": null,
            "steps": []
        });
        active_jobs()
            .lock()
            .unwrap()
            .insert(id.clone(), job.clone());
        test_heads()
            .lock()
            .unwrap()
            .insert(root.path().to_path_buf(), Some("abc1234".into()));
        let response = app
            .oneshot(signed_request(
                &format!("/ext/lan_cowork/fleet/update/status?job_id={id}"),
                Some(&token),
                "status-active",
            ))
            .await
            .unwrap();
        assert_eq!(json_body(response).await, job);
        active_jobs().lock().unwrap().remove(&id);
        reset_update_test_state();
    }

    #[tokio::test]
    async fn disk_jobs_heal_only_on_matching_short_head() {
        let root = tempfile::tempdir().unwrap();
        let (_state, lc, token) = peer_state(true, root.path()).await;
        let app = routes().with_state(lc.clone());
        let root_path = root.path().to_path_buf();

        for (id, head, expected) in [
            ("match", Some("abc1234"), "success"),
            ("mismatch", Some("fffffff"), "restarting"),
            ("git-failure", None, "restarting"),
        ] {
            write_job(
                root.path(),
                &json!({
                    "job_id": id,
                    "status": "restarting",
                    "post_commit": "abc1234",
                    "finished_at": null,
                    "steps": []
                }),
            );
            test_heads()
                .lock()
                .unwrap()
                .insert(root_path.clone(), head.map(str::to_owned));
            let response = app
                .clone()
                .oneshot(signed_request(
                    &format!("/ext/lan_cowork/fleet/update/status?job_id={id}"),
                    Some(&token),
                    &format!("status-{id}"),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(json_body(response).await["status"], expected);
        }
    }

    #[tokio::test]
    async fn unknown_job_heals_and_writes_disk_before_404() {
        let root = tempfile::tempdir().unwrap();
        let (_state, lc, token) = peer_state(true, root.path()).await;
        write_job(
            root.path(),
            &json!({
                "job_id": "other",
                "status": "restarting",
                "post_commit": "abc1234",
                "finished_at": null,
                "steps": []
            }),
        );
        test_heads()
            .lock()
            .unwrap()
            .insert(root.path().to_path_buf(), Some("abc1234".into()));
        let response = routes()
            .with_state(lc.clone())
            .oneshot(signed_request(
                "/ext/lan_cowork/fleet/update/status?job_id=missing",
                Some(&token),
                "status-unknown",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(json_body(response).await, json!({"error": "job_not_found"}));
        let saved: Value =
            serde_json::from_slice(&std::fs::read(last_job_path(root.path())).unwrap()).unwrap();
        assert_eq!(saved["status"], "success");
    }

    #[tokio::test]
    async fn disk_job_shapes_and_lowercase_status_are_preserved() {
        let root = tempfile::tempdir().unwrap();
        let (_state, lc, token) = peer_state(true, root.path()).await;
        let app = routes().with_state(lc.clone());
        for (index, job) in [
            json!({
                "job_id": "success",
                "status": "success",
                "started_at": "2026-08-01T00:00:00+00:00",
                "finished_at": "2026-08-01T00:01:00+00:00",
                "steps": [{"name": "git_precheck", "status": "success", "output": "opaque"}],
                "pre_commit": "1111111",
                "post_commit": "2222222",
                "error": null
            }),
            json!({
                "job_id": "failed",
                "status": "failed",
                "started_at": "2026-08-01T00:00:00+00:00",
                "finished_at": "2026-08-01T00:01:00+00:00",
                "steps": [],
                "error": "failure"
            }),
            json!({
                "job_id": "pending",
                "status": "pending",
                "started_at": null,
                "finished_at": null,
                "steps": [],
                "error": null
            }),
        ]
        .into_iter()
        .enumerate()
        {
            write_job(root.path(), &job);
            let id = job["job_id"].as_str().unwrap();
            let response = app
                .clone()
                .oneshot(signed_request(
                    &format!("/ext/lan_cowork/fleet/update/status?job_id={id}"),
                    Some(&token),
                    &format!("status-shape-{index}"),
                ))
                .await
                .unwrap();
            assert_eq!(json_body(response).await, job);
        }
    }

    #[test]
    fn empty_post_commit_never_checks_git() {
        let root = tempfile::tempdir().unwrap();
        write_job(
            root.path(),
            &json!({"job_id":"empty","status":"restarting","post_commit":""}),
        );
        let called = std::sync::atomic::AtomicBool::new(false);
        let job = load_last_job_with_head(root.path(), || {
            called.store(true, std::sync::atomic::Ordering::Relaxed);
            Some("head".into())
        })
        .unwrap();
        assert_eq!(job["status"], "restarting");
        assert!(!called.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test]
    async fn log_relay_enforces_session_chief_peer_and_branch_precedence() {
        let root = tempfile::tempdir().unwrap();
        let (state, lc, token) = peer_state(true, root.path()).await;
        configure_fleet(&state, true, &[]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        point_peer_at(&lc, listener.local_addr().unwrap().port()).await;
        let app = routes().with_state(lc.clone());

        let response = app
            .clone()
            .oneshot(request(
                "/ext/lan_cowork/fleet/logs/stream?peer_id=peer&lines=abc",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json_body(response).await,
            json!({"error":"session required"})
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );

        configure_fleet(&state, false, &[]);
        let response = app
            .clone()
            .oneshot(request(
                "/ext/lan_cowork/fleet/logs/stream?peer_id=peer",
                Some(session().await),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(json_body(response).await, json!({"error":"not_chief"}));

        configure_fleet(&state, true, &[]);
        let response = app
            .clone()
            .oneshot(request(
                "/ext/lan_cowork/fleet/logs/stream?peer_id=missing",
                Some(session().await),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(json_body(response).await, json!({"error":"peer_not_found"}));

        let response = app
            .oneshot(signed_request(
                "/ext/lan_cowork/fleet/logs/stream?peer_id=peer",
                Some(&token),
                "relay-precedence",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json_body(response).await,
            json!({"error":"session required"})
        );
    }

    #[tokio::test]
    async fn log_relay_preconnect_failure_emits_close_without_error() {
        let root = tempfile::tempdir().unwrap();
        let (state, lc, _) = peer_state(true, root.path()).await;
        configure_fleet(&state, true, &[]);

        let response = routes()
            .with_state(lc.clone())
            .oneshot(request(
                "/ext/lan_cowork/fleet/logs/stream?peer_id=peer",
                Some(session().await),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains("event: error"));
        assert_eq!(body, "event: close\ndata: {}\n\n");
    }

    #[tokio::test]
    async fn log_relay_streams_signed_sse_and_closes_after_success_or_error() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let root = tempfile::tempdir().unwrap();
        let (state, lc, _) = peer_state(true, root.path()).await;
        insert_identity_seed(&state).await;
        configure_fleet(&state, true, &[]);

        let upstream_body = b"event: log\ndata: {\"message\":\"remote\"}\n\n";
        let success = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
            upstream_body.len(),
            String::from_utf8_lossy(upstream_body)
        )
        .into_bytes();
        let (port, server) = response_server(success).await;
        point_peer_at(&lc, port).await;
        let mut relay_request = request(
            "/ext/lan_cowork/fleet/logs/stream?peer_id=peer&lines=4&level=WARNING",
            Some(session().await),
        );
        relay_request
            .headers_mut()
            .insert("X-Peer-Id", "requester".parse().unwrap());
        let response = routes()
            .with_state(lc.clone())
            .oneshot(relay_request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.starts_with("event: log\n"));
        assert!(body.ends_with("event: close\ndata: {}\n\n"));
        let wire = String::from_utf8(server.await.unwrap())
            .unwrap()
            .to_ascii_lowercase();
        assert!(
            wire.contains("get /ext/lan_cowork/fleet/logs/stream?lines=4&level=warning http/1.1")
        );
        assert!(wire.contains("x-requested-with: fleetrelay"));
        assert!(wire.contains("accept: text/event-stream"));
        assert!(wire.contains("x-peer-id: self"));
        assert!(wire.contains("x-peer-sig:"));
        assert!(wire.contains("x-peer-nonce:"));
        assert!(wire.contains("authorization: bearer relay-token"));

        let failure = b"HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\n\r\n".to_vec();
        let (port, server) = response_server(failure).await;
        point_peer_at(&lc, port).await;
        let response = routes()
            .with_state(lc.clone())
            .oneshot(request(
                "/ext/lan_cowork/fleet/logs/stream?peer_id=peer",
                Some(session().await),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8(body.to_vec()).unwrap(),
            "event: error\ndata: {\"error\":\"peer returned 418\"}\n\nevent: close\ndata: {}\n\n"
        );
        server.await.unwrap();
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn log_peer_branch_preserves_auth_order_nonce_and_allowlist() {
        let root = tempfile::tempdir().unwrap();
        let (state, lc) = empty_stream_state(root.path(), "self").await;
        let app = routes().with_state(lc.clone());
        let mut unknown = Request::builder()
            .uri("/ext/lan_cowork/fleet/logs/stream?lines=abc")
            .body(Body::empty())
            .unwrap();
        unknown
            .headers_mut()
            .insert("X-Peer-Id", "peer".parse().unwrap());
        let response = app.clone().oneshot(unknown).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"ok":false,"error":"unknown peer"})
        );

        sqlx::query("INSERT INTO peers (peer_id,name,api_host,api_port,pubkey,created_at,updated_at) VALUES ('peer','peer','10.0.0.2',5000,NULL,0,0)")
            .execute(&state.db)
            .await
            .unwrap();
        let mut unpaired = Request::builder()
            .uri("/ext/lan_cowork/fleet/logs/stream")
            .body(Body::empty())
            .unwrap();
        unpaired
            .headers_mut()
            .insert("X-Peer-Id", "peer".parse().unwrap());
        let response = app.oneshot(unpaired).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"ok":false,"error":"peer not paired"})
        );

        let root = tempfile::tempdir().unwrap();
        let (state, lc, token) = peer_state(true, root.path()).await;
        let app = routes().with_state(lc.clone());
        let mut unsigned = Request::builder()
            .uri("/ext/lan_cowork/fleet/logs/stream")
            .body(Body::empty())
            .unwrap();
        unsigned
            .headers_mut()
            .insert("X-Peer-Id", "peer".parse().unwrap());
        assert_eq!(
            app.clone().oneshot(unsigned).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(signed_request(
                    "/ext/lan_cowork/fleet/logs/stream",
                    Some(&token),
                    "",
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = app
            .clone()
            .oneshot(signed_request(
                "/ext/lan_cowork/fleet/logs/stream?lines=abc",
                Some(&token),
                "peer-not-allowed",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"error":"not_in_allowlist","message":"not in allow_log_stream_from"})
        );

        configure_fleet(&state, false, &["peer"]);
        let first = app
            .clone()
            .oneshot(signed_request(
                "/ext/lan_cowork/fleet/logs/stream",
                Some(&token),
                "peer-replay",
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let replay = app
            .oneshot(signed_request(
                "/ext/lan_cowork/fleet/logs/stream",
                Some(&token),
                "peer-replay",
            ))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }

    // The following 4 tests were relocated to yu-server's
    // lan_cowork_split_integration_tests.rs (S4d step 4): they push into
    // `SharedState.log_ring` and call `LanCoworkHost::log_open` /
    // `set_log_open_seam_hook`, which depend on yu-server's real production
    // SharedState/LogRingBuffer types. The lan-cowork crate's TestHost double
    // (see `test_support.rs`) has no `log_ring` field, so they cannot run here.
    // Relocated: log_peer_positive_and_unauthenticated_self_have_discriminating_controls,
    // log_browser_branch_requires_only_session_and_parses_after_auth,
    // log_sse_backlog_payload_headers_levels_and_line_clamps_match_python,
    // log_sse_live_filter_seam_close_and_connection_budget_are_pinned.
    #[test]
    fn production_logs_only_nonsecret_restart_failure() {
        let production = include_str!("lan_cowork_fleet_ops.rs")
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap();
        assert_eq!(production.matches("tracing::").count(), 1);
        let restart_log = production
            .lines()
            .find(|line| line.contains("fleet restart failed"))
            .unwrap();
        assert!(restart_log.contains("tracing::warn!"));
        for forbidden in [
            "peer_id",
            "X-Peer",
            "Authorization",
            "body",
            "stdout",
            "stderr",
            "resolved",
            "source",
            "branch",
            "consent",
        ] {
            assert!(!restart_log.contains(forbidden));
        }
        assert!(!production.contains("log::"));
        assert!(!production.contains("println!"));
        assert!(!production.contains("eprintln!"));
        assert!(!production.contains("dbg!"));
    }

    #[tokio::test]
    async fn disabled_routes_return_503_before_auth_without_path_disclosure() {
        for path in [
            "/ext/lan_cowork/fleet/info",
            "/ext/lan_cowork/fleet/update/status?job_id=x",
        ] {
            let state = crate::state::semantic_test_state_with(true, String::new()).await;
            let response = routes()
                .with_state(LanCoworkState::from_shared(&state))
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let body = json_body(response).await;
            assert_eq!(
                body,
                json!({"ok": false, "error": "LAN Cowork not enabled"})
            );
            assert!(!body.to_string().contains("disk.path"));
        }
    }
}
