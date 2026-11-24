//! Supervisor (SES-08): routing, health, adoption, restart with bounded retries,
//! and coordinated shutdown.
//!
//! Restarts follow `architecture.md` §18: a crash is retried with backoff; after
//! the configured failure budget the tree is marked failed and is not retried.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub worker_bin: PathBuf,
    /// Failures allowed before the tree is marked failed.
    pub max_restarts: u32,
    /// Backoff per restart attempt, milliseconds.
    pub backoff_ms: Vec<u64>,
    /// Heartbeat age after which an adopted worker is considered dead.
    pub stale_heartbeat_ms: i64,
    /// Extra arguments passed to every spawned worker (test hooks, flags).
    pub worker_args: Vec<String>,
}

impl SupervisorConfig {
    pub fn for_binary(bin: impl Into<PathBuf>) -> Self {
        Self {
            worker_bin: bin.into(),
            max_restarts: 3,
            backoff_ms: vec![250, 1000, 5000],
            stale_heartbeat_ms: 5_000,
            worker_args: Vec::new(),
        }
    }

    fn backoff(&self, attempt: u32) -> u64 {
        self.backoff_ms
            .get(attempt as usize)
            .copied()
            .unwrap_or_else(|| self.backoff_ms.last().copied().unwrap_or(250))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WorkerStatus {
    Running,
    RestartScheduled { attempt: u32, at_ms: i64 },
    Failed { reason: String },
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRecord {
    pub session: String,
    pub pid: Option<u32>,
    pub restarts: u32,
    pub status: WorkerStatus,
    pub heartbeat: PathBuf,
    pub adopted: bool,
}

pub struct Supervisor {
    config: SupervisorConfig,
    workers: BTreeMap<String, WorkerRecord>,
    children: BTreeMap<String, Child>,
}

fn key_for(session: &Path) -> String {
    let parent = session.parent().unwrap_or_else(|| Path::new("."));
    let parent = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    parent
        .join(session.file_name().unwrap_or_default())
        .display()
        .to_string()
}

impl Supervisor {
    pub fn new(config: SupervisorConfig) -> Self {
        Self { config, workers: BTreeMap::new(), children: BTreeMap::new() }
    }

    pub fn workers(&self) -> impl Iterator<Item = &WorkerRecord> {
        self.workers.values()
    }

    pub fn record(&self, key: &str) -> Option<&WorkerRecord> {
        self.workers.get(key)
    }

    pub fn config(&self) -> &SupervisorConfig {
        &self.config
    }

    fn spawn(&mut self, key: &str, session: &Path) -> Result<u32> {
        if let Some(parent) = session.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut command = Command::new(&self.config.worker_bin);
        command.arg("--session").arg(session);
        for arg in &self.config.worker_args {
            command.arg(arg);
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| ZeroError::new(ErrorCode::Unavailable, format!("cannot start worker: {e}")))?;
        let pid = child.id();
        self.children.insert(key.to_string(), child);
        Ok(pid)
    }

    /// Start a worker for a session and register it.
    pub fn start(&mut self, session: impl AsRef<Path>, _now_ms: i64) -> Result<String> {
        let session = session.as_ref().to_path_buf();
        let key = key_for(&session);
        if let Some(record) = self.workers.get(&key) {
            if record.status == WorkerStatus::Running {
                return Ok(key);
            }
        }
        let pid = self.spawn(&key, &session)?;
        self.workers.insert(
            key.clone(),
            WorkerRecord {
                session: session.display().to_string(),
                pid: Some(pid),
                restarts: 0,
                status: WorkerStatus::Running,
                heartbeat: session.with_extension("heartbeat"),
                adopted: false,
            },
        );
        Ok(key)
    }

    pub fn route(&self, session: impl AsRef<Path>) -> Option<u32> {
        let key = key_for(session.as_ref());
        self.workers
            .get(&key)
            .filter(|r| r.status == WorkerStatus::Running)
            .and_then(|r| r.pid)
    }

    pub fn healthy(&self, session: impl AsRef<Path>, now_ms: i64) -> bool {
        let key = key_for(session.as_ref());
        let Some(record) = self.workers.get(&key) else {
            return false;
        };
        match &record.status {
            WorkerStatus::Running => {
                if record.adopted {
                    heartbeat_age(&record.heartbeat, now_ms)
                        .map(|age| age <= self.config.stale_heartbeat_ms)
                        .unwrap_or(false)
                } else {
                    self.children.get(&key).map(|c| c.id() != 0).unwrap_or(false)
                }
            }
            _ => false,
        }
    }

    /// Test and operator hook: kill the running child (as an external crash would).
    pub fn kill_worker(&mut self, session: impl AsRef<Path>) -> Result<()> {
        let key = key_for(session.as_ref());
        if let Some(child) = self.children.get_mut(&key) {
            child.kill()?;
            let _ = child.wait();
        }
        Ok(())
    }

    fn on_exit(&mut self, key: &str, now_ms: i64) {
        let session = self.workers.get(key).map(|r| PathBuf::from(&r.session));
        let Some(session) = session else {
            return;
        };
        let (restarts, status) = {
            let Some(record) = self.workers.get_mut(key) else {
                return;
            };
            record.pid = None;
            // A graceful stop is not a failure.
            if record.status == WorkerStatus::Stopped {
                return;
            }
            if matches!(record.status, WorkerStatus::Failed { .. }) {
                return;
            }
            record.restarts += 1;
            let attempt = record.restarts;
            if attempt <= self.config.max_restarts {
                let at = now_ms + self.config.backoff(attempt - 1) as i64;
                record.status = WorkerStatus::RestartScheduled { attempt, at_ms: at };
                (attempt, WorkerStatus::RestartScheduled { attempt, at_ms: at })
            } else {
                let reason = format!("worker for {} failed {attempt} times", record.session);
                record.status = WorkerStatus::Failed { reason: reason.clone() };
                (attempt, WorkerStatus::Failed { reason })
            }
        };
        let _ = restarts;
        let _ = status;
        // Spawn immediately when the backoff is zero or already satisfied.
        if matches!(self.workers.get(key).map(|r| r.status.clone()), Some(WorkerStatus::RestartScheduled { .. })) {
            self.maybe_restart(key, now_ms, &session);
        }
    }

    fn maybe_restart(&mut self, key: &str, now_ms: i64, session: &Path) {
        let due = match self.workers.get(key).map(|r| r.status.clone()) {
            Some(WorkerStatus::RestartScheduled { at_ms, .. }) => at_ms <= now_ms,
            _ => false,
        };
        if !due {
            return;
        }
        match self.spawn(key, session) {
            Ok(pid) => {
                if let Some(record) = self.workers.get_mut(key) {
                    record.pid = Some(pid);
                    record.status = WorkerStatus::Running;
                }
            }
            Err(e) => {
                if let Some(record) = self.workers.get_mut(key) {
                    record.status = WorkerStatus::Failed { reason: e.to_string() };
                }
            }
        }
    }

    /// Poll every worker: restart due ones, detect exits, and expire adopted
    /// heartbeats. Returns the keys whose status changed.
    pub fn poll(&mut self, now_ms: i64) -> Vec<String> {
        let mut changed = Vec::new();
        let keys: Vec<String> = self.workers.keys().cloned().collect();
        for key in &keys {
            let adopted = self.workers.get(key).map(|r| r.adopted).unwrap_or(false);
            if adopted {
                let stale = self
                    .workers
                    .get(key)
                    .map(|r| {
                        heartbeat_age(&r.heartbeat, now_ms)
                            .map(|age| age > self.config.stale_heartbeat_ms)
                            .unwrap_or(true)
                    })
                    .unwrap_or(false);
                if stale {
                    if let Some(record) = self.workers.get_mut(key) {
                        if record.status == WorkerStatus::Running {
                            record.status = WorkerStatus::Failed {
                                reason: "adopted worker heartbeat expired".into(),
                            };
                            changed.push(key.clone());
                        }
                    }
                }
                continue;
            }
            let exited = self
                .children
                .get_mut(key)
                .and_then(|c| c.try_wait().ok().flatten())
                .is_some();
            if exited {
                self.children.remove(key);
                let was_running = self
                    .workers
                    .get(key)
                    .map(|r| r.status == WorkerStatus::Running)
                    .unwrap_or(false);
                if was_running {
                    self.on_exit(key, now_ms);
                    changed.push(key.clone());
                }
            }
            if let Some(session) = self.workers.get(key).map(|r| PathBuf::from(&r.session)) {
                self.maybe_restart(key, now_ms, &session);
            }
        }
        changed
    }

    /// Adopt a worker started elsewhere, using its heartbeat for liveness.
    pub fn adopt(&mut self, session: impl AsRef<Path>, pid: u32) {
        let session = session.as_ref().to_path_buf();
        let key = key_for(&session);
        self.workers.insert(
            key,
            WorkerRecord {
                session: session.display().to_string(),
                pid: Some(pid),
                restarts: 0,
                status: WorkerStatus::Running,
                heartbeat: session.with_extension("heartbeat"),
                adopted: true,
            },
        );
    }

    /// Coordinated shutdown: stop owned children, ask adopted workers to stop.
    pub fn shutdown(&mut self) -> Result<()> {
        for (key, child) in self.children.iter_mut() {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(record) = self.workers.get_mut(key) {
                record.status = WorkerStatus::Stopped;
                record.pid = None;
            }
        }
        self.children.clear();
        for record in self.workers.values_mut() {
            if record.adopted {
                let stop = PathBuf::from(&record.session).with_extension("stop");
                let _ = std::fs::write(stop, b"stop");
                record.status = WorkerStatus::Stopped;
            }
        }
        Ok(())
    }
}

fn heartbeat_age(path: &Path, now_ms: i64) -> Option<i64> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let ts = value.get("ts")?.as_i64()?;
    Some(now_ms - ts)
}
