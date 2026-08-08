pub mod model;

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, SystemTime},
};

use model::{Job, StatusResult};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

const HISTORY_TTL_SECS: u64 = 60;

pub struct JobManager {
    jobs: Mutex<HashMap<String, Job>>,
}

impl JobManager {
    pub fn new() -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new running job and return its cancellation token.
    pub fn start(&self, job_id: impl Into<String>, label: impl Into<String>) -> CancellationToken {
        let token = CancellationToken::new();
        let job = Job {
            job_id: job_id.into(),
            label: label.into(),
            running: true,
            phase: None,
            current: None,
            total: None,
            percent: None,
            message: None,
            detail: None,
            error: None,
            result: None,
            started_at: SystemTime::now(),
            finished_at: None,
            cancel_token: token.clone(),
        };
        let id = job.job_id.clone();
        self.jobs.lock().unwrap().insert(id, job);
        token
    }

    /// Create a new running job only when no job with this id is running.
    /// Returns the cancellation token for the new job, or `None` if one is
    /// already running.
    pub fn start_if_idle(
        &self,
        job_id: impl Into<String>,
        label: impl Into<String>,
    ) -> Option<CancellationToken> {
        let token = CancellationToken::new();
        let job = Job {
            job_id: job_id.into(),
            label: label.into(),
            running: true,
            phase: None,
            current: None,
            total: None,
            percent: None,
            message: None,
            detail: None,
            error: None,
            result: None,
            started_at: SystemTime::now(),
            finished_at: None,
            cancel_token: token.clone(),
        };
        let id = job.job_id.clone();
        let mut jobs = self.jobs.lock().unwrap();
        if jobs.get(&id).map(|job| job.running).unwrap_or(false) {
            return None;
        }
        jobs.insert(id, job);
        Some(token)
    }

    pub fn finish(&self, job_id: &str, result: Option<Value>, error: Option<String>) {
        if let Some(j) = self.jobs.lock().unwrap().get_mut(job_id) {
            j.running = false;
            j.phase = Some(if error.is_some() { "error" } else { "complete" }.into());
            j.finished_at = Some(SystemTime::now());
            j.result = result;
            j.error = error;
        }
    }

    pub fn finish_cancelled(&self, job_id: &str, result: Option<Value>) {
        if let Some(j) = self.jobs.lock().unwrap().get_mut(job_id) {
            j.running = false;
            j.phase = Some("cancelled".into());
            j.finished_at = Some(SystemTime::now());
            j.result = result;
            j.error = None;
        }
    }

    pub fn update_progress(&self, job_id: &str, current: u64, total: u64, message: Option<String>) {
        if let Some(j) = self.jobs.lock().unwrap().get_mut(job_id) {
            j.current = Some(current);
            j.total = Some(total);
            j.percent = if total > 0 {
                Some(current as f64 / total as f64 * 100.0)
            } else {
                None
            };
            j.message = message;
        }
    }

    pub fn set_phase(&self, job_id: &str, phase: impl Into<String>) {
        if let Some(j) = self.jobs.lock().unwrap().get_mut(job_id) {
            j.phase = Some(phase.into());
        }
    }

    pub fn get_job(&self, job_id: &str) -> Option<model::JobDict> {
        self.prune_history();
        self.jobs.lock().unwrap().get(job_id).map(|j| j.to_dict())
    }

    pub fn is_running(&self, job_id: &str) -> bool {
        self.jobs
            .lock()
            .unwrap()
            .get(job_id)
            .map(|j| j.running)
            .unwrap_or(false)
    }

    /// Cancel a running job. Returns true if the job existed and was running.
    pub fn cancel_job(&self, job_id: &str) -> bool {
        if let Some(j) = self.jobs.lock().unwrap().get(job_id) {
            if j.running {
                j.cancel_token.cancel();
                return true;
            }
        }
        false
    }

    pub fn get_status(&self) -> StatusResult {
        self.prune_history();
        let guard = self.jobs.lock().unwrap();
        let active: Vec<_> = guard
            .values()
            .filter(|j| j.running)
            .map(|j| j.to_dict())
            .collect();
        let recent: Vec<_> = guard
            .values()
            .filter(|j| !j.running)
            .map(|j| j.to_dict())
            .collect();
        StatusResult {
            has_active: !active.is_empty(),
            active,
            recent,
        }
    }

    fn prune_history(&self) {
        let cutoff = Duration::from_secs(HISTORY_TTL_SECS);
        self.jobs.lock().unwrap().retain(|_, j| {
            j.running
                || j.finished_at
                    .map(|t| t.elapsed().unwrap_or(Duration::ZERO) < cutoff)
                    .unwrap_or(true)
        });
    }
}

impl Default for JobManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_job_start_and_get() {
        let mgr = JobManager::new();
        mgr.start("j1", "My Job");
        let d = mgr.get_job("j1").expect("job must exist");
        assert_eq!(d.job_id, "j1");
        assert_eq!(d.label, "My Job");
        assert!(d.running);
    }

    #[test]
    fn test_start_if_idle_registers_job_when_idle() {
        let mgr = JobManager::new();

        let token = mgr
            .start_if_idle("j1", "My Job")
            .expect("idle job should start");

        assert!(!token.is_cancelled());
        let d = mgr.get_job("j1").expect("job must exist");
        assert_eq!(d.job_id, "j1");
        assert_eq!(d.label, "My Job");
        assert!(d.running);
    }

    #[test]
    fn test_start_if_idle_does_not_overwrite_running_job() {
        let mgr = JobManager::new();
        let original_token = mgr.start("j1", "Original Job");
        mgr.set_phase("j1", "indexing");

        assert!(mgr.start_if_idle("j1", "Replacement Job").is_none());
        assert!(!original_token.is_cancelled());
        let d = mgr.get_job("j1").expect("existing job must remain");
        assert_eq!(d.label, "Original Job");
        assert_eq!(d.phase.as_deref(), Some("indexing"));
        assert!(d.running);
    }

    #[test]
    fn test_job_finish_sets_running_false() {
        let mgr = JobManager::new();
        mgr.start("j2", "Finish Test");
        mgr.finish("j2", Some(json!({"ok": true})), None);
        let d = mgr.get_job("j2").unwrap();
        assert!(!d.running);
        assert_eq!(d.phase.unwrap(), "complete");
        assert_eq!(d.result.unwrap()["ok"], true);
    }

    #[test]
    fn test_job_finish_cancelled_sets_cancelled_phase() {
        let mgr = JobManager::new();
        mgr.start("j2-cancelled", "Cancelled Test");
        mgr.finish_cancelled("j2-cancelled", Some(json!({"ok": true})));

        let d = mgr.get_job("j2-cancelled").unwrap();
        assert!(!d.running);
        assert_eq!(d.phase.as_deref(), Some("cancelled"));
        assert!(d.error.is_none());
        assert_eq!(d.result.unwrap()["ok"], true);
    }

    #[test]
    fn test_job_finish_with_error() {
        let mgr = JobManager::new();
        mgr.start("j3", "Error Test");
        mgr.finish("j3", None, Some("something broke".into()));
        let d = mgr.get_job("j3").unwrap();
        assert!(!d.running);
        assert_eq!(d.phase.unwrap(), "error");
        assert_eq!(d.error.unwrap(), "something broke");
    }

    #[test]
    fn test_job_cancel() {
        let mgr = JobManager::new();
        let token = mgr.start("j4", "Cancel Test");
        assert!(!token.is_cancelled());
        assert!(mgr.cancel_job("j4"));
        assert!(token.is_cancelled());
    }

    #[test]
    fn test_job_cancel_nonexistent_returns_false() {
        let mgr = JobManager::new();
        assert!(!mgr.cancel_job("does-not-exist"));
    }

    #[test]
    fn test_job_is_running() {
        let mgr = JobManager::new();
        mgr.start("j5", "Running Check");
        assert!(mgr.is_running("j5"));
        mgr.finish("j5", None, None);
        assert!(!mgr.is_running("j5"));
        assert!(!mgr.is_running("unknown"));
    }

    #[test]
    fn test_job_update_progress() {
        let mgr = JobManager::new();
        mgr.start("j6", "Progress");
        mgr.update_progress("j6", 50, 100, Some("halfway".into()));
        let d = mgr.get_job("j6").unwrap();
        assert_eq!(d.current.unwrap(), 50);
        assert_eq!(d.total.unwrap(), 100);
        assert!((d.percent.unwrap() - 50.0).abs() < 0.001);
        assert_eq!(d.message.unwrap(), "halfway");
    }

    #[test]
    fn test_get_status_active_vs_recent() {
        let mgr = JobManager::new();
        mgr.start("active1", "Active");
        mgr.start("done1", "Done");
        mgr.finish("done1", None, None);
        let status = mgr.get_status();
        assert!(status.has_active);
        assert_eq!(status.active.len(), 1);
        assert_eq!(status.active[0].job_id, "active1");
        assert_eq!(status.recent.len(), 1);
        assert_eq!(status.recent[0].job_id, "done1");
    }

    #[test]
    fn test_get_job_unknown_returns_none() {
        let mgr = JobManager::new();
        assert!(mgr.get_job("never-started").is_none());
    }

    #[test]
    fn test_set_phase() {
        let mgr = JobManager::new();
        mgr.start("j7", "Phase Test");
        mgr.set_phase("j7", "indexing");
        let d = mgr.get_job("j7").unwrap();
        assert_eq!(d.phase.unwrap(), "indexing");
    }
}
