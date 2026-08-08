use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use axum::{
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::SharedState;

const SAFE_MODE_FLAG: &str = "--safe-mode";
const SAFE_MODE_MARKER_NAME: &str = ".safe_mode_marker";
const STALE_UPDATE_PENDING_SECONDS: i64 = 7 * 24 * 60 * 60;

#[derive(Deserialize)]
pub struct OpenRepairFolderBody {
    pub repair_dir: Option<String>,
}

fn api_result(payload: Value) -> Response {
    let mut body = match payload {
        Value::Object(map) => map,
        other => return Json(json!({"ok": true, "error": null, "data": other})).into_response(),
    };
    body.insert("ok".to_string(), Value::Bool(true));
    body.insert("error".to_string(), Value::Null);
    body.entry("data".to_string()).or_insert(Value::Null);
    Json(Value::Object(body)).into_response()
}

fn api_error(msg: &str, code: &str, status: StatusCode) -> Response {
    (
        status,
        Json(json!({"ok": false, "error": msg, "code": code})),
    )
        .into_response()
}

fn data_dir(project_root: &Path) -> PathBuf {
    std::env::var_os("TAGDB_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| project_root.join("data"))
}

fn default_repair_root(project_root: &Path) -> PathBuf {
    data_dir(project_root).join("repair")
}

fn is_safe_mode_from_args<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .skip(1)
        .any(|arg| arg.as_ref() == SAFE_MODE_FLAG)
}

fn safe_mode_payload<I, S>(data_dir: &Path, args: I) -> Value
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    json!({
        "safe_mode": is_safe_mode_from_args(args),
        "marker_exists": data_dir.join(SAFE_MODE_MARKER_NAME).is_file(),
    })
}

fn resolve_repair_dir(repair_root: &Path, value: Option<&str>) -> Result<PathBuf, String> {
    let value = value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "repair_dir is required".to_string())?;
    let root = repair_root
        .canonicalize()
        .map_err(|err| format!("repair root unavailable: {err}"))?;
    let path = PathBuf::from(value)
        .canonicalize()
        .map_err(|err| format!("repair_dir unavailable: {err}"))?;
    if !path.starts_with(&root) {
        return Err("repair_dir must be under repair root".to_string());
    }
    Ok(path)
}

fn is_wsl() -> bool {
    fs::read_to_string("/proc/version")
        .map(|text| {
            let lower = text.to_ascii_lowercase();
            lower.contains("microsoft") || lower.contains("wsl")
        })
        .unwrap_or(false)
}

fn spawn_repair_folder(path: &Path) -> std::io::Result<()> {
    let mut command = if cfg!(target_os = "windows") {
        Command::new("explorer")
    } else if is_wsl() {
        Command::new("explorer.exe")
    } else if cfg!(target_os = "macos") {
        Command::new("open")
    } else {
        Command::new("xdg-open")
    };
    command.arg(path).spawn().map(|_| ())
}

fn parse_created_at(raw: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S%.f").map(|naive| naive.and_utc())
        })
}

fn cleanup_stale_update_pending(
    project_root: &Path,
    now_rfc3339: &str,
) -> Result<(usize, Vec<String>), String> {
    let pending_dir = project_root.join("data").join("update_pending");
    if !pending_dir.exists() {
        return Ok((0, Vec::new()));
    }
    let now = parse_created_at(now_rfc3339).map_err(|err| err.to_string())?;
    let mut paths: Vec<PathBuf> = fs::read_dir(&pending_dir)
        .map_err(|err| err.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();

    let mut deleted = Vec::new();
    for path in paths {
        let mut remove = false;
        if let Ok(raw) = fs::read_to_string(&path) {
            match serde_json::from_str::<Value>(&raw)
                .ok()
                .and_then(|value| value.get("created_at").map(ToString::to_string))
            {
                Some(raw_created_at) => {
                    let trimmed = raw_created_at.trim_matches('"');
                    match parse_created_at(trimmed) {
                        Ok(created_at) => {
                            if (now - created_at).num_seconds() > STALE_UPDATE_PENDING_SECONDS {
                                remove = true;
                            }
                        }
                        Err(_) => remove = true,
                    }
                }
                None => remove = true,
            }
        } else {
            remove = true;
        }
        if remove {
            if fs::remove_file(&path).is_ok() {
                if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                    deleted.push(name.to_string());
                }
            }
        }
    }
    Ok((deleted.len(), deleted))
}

pub async fn safe_mode(State(state): State<SharedState>) -> Response {
    api_result(safe_mode_payload(
        &data_dir(&state.config.project_root),
        std::env::args(),
    ))
}

pub async fn open_repair_folder(
    State(state): State<SharedState>,
    body: Option<Json<OpenRepairFolderBody>>,
) -> Response {
    let repair_dir = body.and_then(|Json(body)| body.repair_dir);
    match resolve_repair_dir(
        &default_repair_root(&state.config.project_root),
        repair_dir.as_deref(),
    )
    .and_then(|path| {
        spawn_repair_folder(&path)
            .map_err(|err| err.to_string())
            .map(|_| path)
    }) {
        Ok(path) => api_result(json!({"repair_dir": path.to_string_lossy()})),
        Err(err) => api_error(&err, "open_repair_folder_failed", StatusCode::BAD_REQUEST),
    }
}

pub async fn cleanup_update_pending(State(state): State<SharedState>) -> Response {
    let now = Utc::now().to_rfc3339();
    match cleanup_stale_update_pending(&state.config.project_root, &now) {
        Ok((deleted, names)) => api_result(json!({"deleted": deleted, "names": names})),
        Err(err) => api_error(
            &err,
            "cleanup_update_pending_failed",
            StatusCode::BAD_REQUEST,
        ),
    }
}

fn py_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"ok": false, "error": "Python backend unavailable", "code": "python_unavailable"})),
    )
        .into_response()
}

async fn fwd_get(state: &SharedState, path: &str) -> Response {
    if state.config.python_url.is_empty() {
        return py_unavailable();
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

async fn fwd_post(state: &SharedState, path: &str, body: Bytes) -> Response {
    if state.config.python_url.is_empty() {
        return py_unavailable();
    }
    let url = format!("{}{}", state.config.python_url.trim_end_matches('/'), path);
    match state
        .python_client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Remote-User", "yu-proxy-auth")
        .header("X-Requested-With", "XMLHttpRequest")
        .body(body)
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

/// POST /api/diagnostics/bug-report
pub async fn bug_report() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
}

/// POST /api/diagnostics/doctor
pub async fn doctor_start() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
}

/// GET /api/diagnostics/doctor/:job_id
pub async fn doctor_status() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"ok": false, "error": "not implemented"})),
    )
}

fn zip_dir_to_path(repair_dir: &Path) -> Result<PathBuf, String> {
    if !repair_dir.is_dir() {
        return Err(format!("{} is not a directory", repair_dir.display()));
    }
    let zip_path = repair_dir.with_extension("zip");
    let file = std::fs::File::create(&zip_path).map_err(|e| e.to_string())?;
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip_collect(repair_dir, repair_dir, &mut writer, options)?;
    writer.finish().map_err(|e| e.to_string())?;
    Ok(zip_path)
}

fn zip_collect(
    root: &Path,
    dir: &Path,
    writer: &mut zip::ZipWriter<std::fs::File>,
    options: zip::write::SimpleFileOptions,
) -> Result<(), String> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            zip_collect(root, &path, writer, options)?;
        } else {
            let rel = path.strip_prefix(root).map_err(|e| e.to_string())?;
            let name = rel.to_string_lossy().replace('\\', "/");
            writer
                .start_file(name, options)
                .map_err(|e| e.to_string())?;
            let data = std::fs::read(&path).map_err(|e| e.to_string())?;
            use std::io::Write;
            writer.write_all(&data).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// POST /api/diagnostics/zip-repair
pub async fn zip_repair(
    State(state): State<SharedState>,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    let repair_dir_str = body
        .as_ref()
        .and_then(|Json(v)| v.get("repair_dir"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let repair_root = default_repair_root(&state.config.project_root);
    match resolve_repair_dir(&repair_root, Some(repair_dir_str)) {
        Err(err) => api_error(&err, "zip_repair_failed", StatusCode::BAD_REQUEST),
        Ok(path) => match zip_dir_to_path(&path) {
            Ok(zip_path) => api_result(json!({
                "repair_dir": path.to_string_lossy(),
                "zip_path": zip_path.to_string_lossy()
            })),
            Err(err) => api_error(&err, "zip_repair_failed", StatusCode::INTERNAL_SERVER_ERROR),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn safe_mode_uses_args_and_marker_file() {
        let temp = TempDir::new().unwrap();
        let marker = temp.path().join(".safe_mode_marker");
        fs::write(&marker, "safe-mode\n").unwrap();

        assert!(super::is_safe_mode_from_args(["yu-server", "--safe-mode"]));
        assert!(!super::is_safe_mode_from_args(["yu-server"]));
        assert!(
            super::safe_mode_payload(temp.path(), ["yu-server"])["marker_exists"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn repair_dir_must_stay_under_repair_root() {
        let temp = TempDir::new().unwrap();
        let repair_root = temp.path().join("data").join("repair");
        let allowed = repair_root.join("20260518-153012");
        let outside = temp.path().join("elsewhere");
        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&outside).unwrap();

        assert_eq!(
            super::resolve_repair_dir(&repair_root, Some(allowed.to_str().unwrap())).unwrap(),
            allowed.canonicalize().unwrap()
        );
        assert_eq!(
            super::resolve_repair_dir(&repair_root, Some(outside.to_str().unwrap()))
                .unwrap_err()
                .to_string(),
            "repair_dir must be under repair root"
        );
        assert_eq!(
            super::resolve_repair_dir(&repair_root, None)
                .unwrap_err()
                .to_string(),
            "repair_dir is required"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repair_dir_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let repair_root = temp.path().join("data").join("repair");
        let outside = temp.path().join("elsewhere");
        let link = repair_root.join("link");
        fs::create_dir_all(&repair_root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, &link).unwrap();

        assert_eq!(
            super::resolve_repair_dir(&repair_root, Some(link.to_str().unwrap()))
                .unwrap_err()
                .to_string(),
            "repair_dir must be under repair root"
        );
    }

    #[test]
    fn cleanup_update_pending_deletes_stale_and_unreadable_json_only() {
        let temp = TempDir::new().unwrap();
        let pending = temp.path().join("data").join("update_pending");
        fs::create_dir_all(&pending).unwrap();
        fs::write(
            pending.join("old.json"),
            json!({"created_at": "2026-06-01T00:00:00+00:00"}).to_string(),
        )
        .unwrap();
        fs::write(
            pending.join("fresh.json"),
            json!({"created_at": "2026-06-10T00:00:00+00:00"}).to_string(),
        )
        .unwrap();
        fs::write(pending.join("broken.json"), "{").unwrap();
        fs::write(pending.join("ignore.txt"), "not json").unwrap();

        let result =
            super::cleanup_stale_update_pending(temp.path(), "2026-06-12T00:00:00+00:00").unwrap();

        assert_eq!(
            result,
            (2, vec!["broken.json".to_string(), "old.json".to_string()])
        );
        assert!(pending.join("fresh.json").exists());
        assert!(pending.join("ignore.txt").exists());
    }
}
