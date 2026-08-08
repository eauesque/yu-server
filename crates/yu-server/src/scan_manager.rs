use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::json;

use scan_core::ipc::{
    self, clear_progress, clear_scan_state, is_worker_running, make_worker_ipc_paths,
    read_progress, signal_stop, WorkerIpcPaths,
};

use crate::sse::SseEvent;
use crate::state::AppState;

#[derive(Debug)]
pub enum ScanError {
    AlreadyRunning,
    SpawnFailed(String),
    WorkerRunning,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::AlreadyRunning => write!(f, "scan worker already running"),
            ScanError::SpawnFailed(e) => write!(f, "spawn failed: {e}"),
            ScanError::WorkerRunning => write!(f, "worker is running"),
        }
    }
}

pub enum ScanCmd {
    Start {
        root: String,
        recursive: bool,
        force: bool,
        scan_zips: bool,
        resume: bool,
        db_path: String,
    },
    ScanAll {
        force: bool,
        db_path: String,
    },
}

#[derive(Serialize)]
pub struct ScanStatus {
    pub running: bool,
    pub phase: Option<String>,
    pub message: Option<String>,
    pub current: u64,
    pub total: u64,
    pub percent: f32,
    pub job_id: String,
}

pub struct ScanManager {
    paths: WorkerIpcPaths,
    bridge_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    python_executable: String,
    project_root: PathBuf,
    python_url: String,
}

impl ScanManager {
    pub fn new(python_executable: String, project_root: PathBuf, python_url: String) -> Self {
        Self {
            paths: make_worker_ipc_paths("yu-scan"),
            bridge_handle: Mutex::new(None),
            python_executable,
            project_root,
            python_url,
        }
    }

    pub async fn spawn_worker(&self, cmd: ScanCmd, state: Arc<AppState>) -> Result<(), ScanError> {
        if is_worker_running(&self.paths) {
            return Err(ScanError::AlreadyRunning);
        }
        clear_progress(&self.paths);

        let mut command = Command::new(&self.python_executable);
        command
            .current_dir(&self.project_root)
            .arg("-m")
            .arg("core.scan.scan_worker");

        match &cmd {
            ScanCmd::Start {
                root,
                recursive,
                force,
                scan_zips,
                resume,
                db_path,
            } => {
                command
                    .arg("start")
                    .arg("--db")
                    .arg(db_path)
                    .arg("--root")
                    .arg(root);
                if *recursive {
                    command.arg("--recursive");
                }
                if *force {
                    command.arg("--force");
                }
                if *scan_zips {
                    command.arg("--scan-zips");
                }
                if *resume {
                    command.arg("--resume");
                }
            }
            ScanCmd::ScanAll { force, db_path } => {
                command.arg("scan-all").arg("--db").arg(db_path);
                if *force {
                    command.arg("--force");
                }
            }
        }

        #[cfg(unix)]
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = command
            .spawn()
            .map_err(|e| ScanError::SpawnFailed(e.to_string()))?;
        ipc::write_pid(&self.paths, child.id())
            .map_err(|e| ScanError::SpawnFailed(e.to_string()))?;

        send_sse(
            &state,
            "scan.started",
            json!({
                "recursive": matches!(&cmd, ScanCmd::Start { recursive: true, .. } | ScanCmd::ScanAll { .. }),
                "label": "フォルダスキャン",
                "job_id": "scan",
            }),
        );

        let paths = self.paths.clone();
        let state2 = state.clone();
        let python_url = self.python_url.clone();
        let handle = tokio::spawn(run_bridge(paths, state2, python_url));
        *self.bridge_handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    pub async fn reconnect_if_running(&self, state: Arc<AppState>) {
        if !is_worker_running(&self.paths) {
            return;
        }
        tracing::info!("[scan_manager] running worker detected, reconnecting bridge");
        let paths = self.paths.clone();
        let python_url = self.python_url.clone();
        let handle = tokio::spawn(run_bridge(paths, state, python_url));
        *self.bridge_handle.lock().unwrap() = Some(handle);
    }

    pub fn status(&self) -> ScanStatus {
        let running = is_worker_running(&self.paths);
        let progress = read_progress(&self.paths);
        match progress {
            Some(p) => ScanStatus {
                running: p.running && running,
                phase: p.phase,
                message: p.message,
                current: p.current,
                total: p.total,
                percent: p.percent,
                job_id: "scan".to_string(),
            },
            None => ScanStatus {
                running,
                phase: None,
                message: None,
                current: 0,
                total: 0,
                percent: 0.0,
                job_id: "scan".to_string(),
            },
        }
    }

    pub fn stop(&self) -> bool {
        signal_stop(&self.paths)
    }

    pub fn dismiss(&self) -> Result<(), ScanError> {
        clear_scan_state(&self.project_root);
        Ok(())
    }
}

fn now_ts() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs_f64()
}

fn send_sse(state: &AppState, event_type: &str, data: serde_json::Value) {
    state.sse_hub.send(SseEvent {
        event_type: event_type.to_string(),
        timestamp: now_ts(),
        data,
        source: "scan".to_string(),
    });
}

async fn run_bridge(paths: WorkerIpcPaths, state: Arc<AppState>, python_url: String) {
    tokio::time::sleep(Duration::from_millis(500)).await;
    send_sse(
        &state,
        "scan.db_busy",
        json!({"busy": true, "job_id": "scan"}),
    );

    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        interval.tick().await;
        match read_progress(&paths) {
            None => {
                if !is_worker_running(&paths) {
                    send_sse(
                        &state,
                        "scan.error",
                        json!({"error": "worker_terminated", "job_id": "scan"}),
                    );
                    break;
                }
            }
            Some(p) => {
                send_sse(
                    &state,
                    "scan.progress",
                    json!({
                        "current": p.current,
                        "total": p.total,
                        "percent": p.percent,
                        "detail": p.detail,
                        "phase": p.phase,
                        "job_id": "scan",
                    }),
                );
                if !p.running || !is_worker_running(&paths) {
                    send_sse(
                        &state,
                        "scan.complete",
                        json!({
                            "deleted": p.deleted,
                            "elapsed_seconds": p.elapsed_seconds,
                            "added_ids": p.added_ids,
                            "updated_ids": p.updated_ids,
                            "deleted_ids": p.deleted_ids,
                            "job_id": "scan",
                        }),
                    );
                    break;
                }
            }
        }
    }

    send_sse(
        &state,
        "scan.db_busy",
        json!({"busy": false, "job_id": "scan"}),
    );
    if !python_url.is_empty() {
        let url = format!(
            "{}/_internal/scan/queue/consume",
            python_url.trim_end_matches('/')
        );
        let _ = reqwest::Client::new().post(url).send().await;
    }
}
