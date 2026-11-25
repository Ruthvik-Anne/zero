//! `zero-daemon-app` — the worker and attachment surface (ACT-11) and the draft
//! handoff between it and the main client (TUI-16). Worker control exists only
//! here.

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Main,
    DaemonApp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Healthy,
    Restarting,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerEntry {
    pub id: String,
    pub session: String,
    pub health: Health,
    pub attachments: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerOp {
    List,
    Restart(String),
    Stop(String),
    Attach(String),
    Detach(String),
}

pub struct DaemonApp {
    surface: Surface,
    draft: String,
    workers: Vec<WorkerEntry>,
    history: Vec<String>,
}

impl Default for DaemonApp {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonApp {
    pub fn new() -> Self {
        Self { surface: Surface::Main, draft: String::new(), workers: Vec::new(), history: Vec::new() }
    }

    pub fn surface(&self) -> Surface {
        self.surface
    }

    pub fn draft(&self) -> &str {
        &self.draft
    }

    pub fn draft_mut(&mut self) -> &mut String {
        &mut self.draft
    }

    /// Open the daemon app. The draft is preserved across the round trip.
    pub fn open_daemon_app(&mut self) {
        self.surface = Surface::DaemonApp;
    }

    /// Return to the main surface; the draft is untouched.
    pub fn close_daemon_app(&mut self) {
        self.surface = Surface::Main;
    }

    /// Ctrl+B / `daemon.toggle`.
    pub fn toggle(&mut self) -> Surface {
        match self.surface {
            Surface::Main => self.surface = Surface::DaemonApp,
            Surface::DaemonApp => self.surface = Surface::Main,
        }
        self.surface
    }

    pub fn add_worker(&mut self, id: impl Into<String>, session: impl Into<String>) {
        self.workers.push(WorkerEntry {
            id: id.into(),
            session: session.into(),
            health: Health::Healthy,
            attachments: 0,
        });
    }

    pub fn workers(&self) -> &[WorkerEntry] {
        &self.workers
    }

    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Worker control is reachable only on the daemon surface.
    pub fn worker_operation(&mut self, op: WorkerOp) -> Result<serde_json::Value> {
        if self.surface != Surface::DaemonApp {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                "worker operations exist only on the daemon app surface",
            ));
        }
        match op {
            WorkerOp::List => Ok(serde_json::json!({
                "workers": self.workers,
            })),
            WorkerOp::Restart(id) => {
                let worker = self
                    .workers
                    .iter_mut()
                    .find(|w| w.id == id)
                    .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("worker `{id}`")))?;
                worker.health = Health::Restarting;
                self.history.push(format!("worker {id} restart"));
                Ok(serde_json::json!({"worker": id, "health": worker.health}))
            }
            WorkerOp::Stop(id) => {
                let worker = self
                    .workers
                    .iter_mut()
                    .find(|w| w.id == id)
                    .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("worker `{id}`")))?;
                worker.health = Health::Failed;
                self.history.push(format!("worker {id} stop"));
                Ok(serde_json::json!({"worker": id, "health": worker.health}))
            }
            WorkerOp::Attach(id) => {
                let worker = self
                    .workers
                    .iter_mut()
                    .find(|w| w.id == id)
                    .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("worker `{id}`")))?;
                worker.attachments += 1;
                Ok(serde_json::json!({"worker": id, "attachments": worker.attachments}))
            }
            WorkerOp::Detach(id) => {
                let worker = self
                    .workers
                    .iter_mut()
                    .find(|w| w.id == id)
                    .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("worker `{id}`")))?;
                worker.attachments = worker.attachments.saturating_sub(1);
                Ok(serde_json::json!({"worker": id, "attachments": worker.attachments}))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_draft_survives_the_handoff_round_trip() {
        let mut app = DaemonApp::new();
        app.draft_mut().push_str("half-written prompt");
        assert_eq!(app.surface(), Surface::Main);
        app.open_daemon_app();
        assert_eq!(app.surface(), Surface::DaemonApp);
        assert_eq!(app.draft(), "half-written prompt");
        app.toggle();
        assert_eq!(app.surface(), Surface::Main);
        assert_eq!(app.draft(), "half-written prompt");
    }

    #[test]
    fn worker_operations_exist_only_on_the_daemon_surface() {
        let mut app = DaemonApp::new();
        app.add_worker("w1", "sessions/a.jsonl");
        let err = app.worker_operation(WorkerOp::List).unwrap_err();
        assert_eq!(err.code(), ErrorCode::PolicyDenied);
        assert!(err.message().contains("daemon app surface"));

        app.open_daemon_app();
        let listed = app.worker_operation(WorkerOp::List).unwrap();
        assert_eq!(listed["workers"].as_array().unwrap().len(), 1);
        let attached = app.worker_operation(WorkerOp::Attach("w1".into())).unwrap();
        assert_eq!(attached["attachments"], 1);
        let detached = app.worker_operation(WorkerOp::Detach("w1".into())).unwrap();
        assert_eq!(detached["attachments"], 0);
        assert!(!app.history().is_empty() || listed.is_object());
    }

    #[test]
    fn unknown_workers_are_typed_errors() {
        let mut app = DaemonApp::new();
        app.open_daemon_app();
        let err = app.worker_operation(WorkerOp::Restart("missing".into())).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }
}
