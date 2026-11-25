//! Durable headless user queue (POL-12, POL-09).
//!
//! Questions, approvals, credentials, irreversible actions, and product
//! decisions are queued durably. Independent work keeps running.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueKind {
    Question,
    Approval,
    Credential,
    Irreversible,
    Decision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    Open,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedItem {
    pub id: String,
    pub kind: QueueKind,
    pub prompt: String,
    pub created_ms: i64,
    pub state: ItemState,
    #[serde(default)]
    pub answer: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct QueueFile {
    items: Vec<QueuedItem>,
}

pub struct UserQueue {
    path: PathBuf,
    items: Vec<QueuedItem>,
    next_id: u64,
}

impl UserQueue {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (items, next_id) = if path.exists() {
            let file: QueueFile = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
            let next_id = file
                .items
                .iter()
                .filter_map(|i| i.id.strip_prefix("uq-").and_then(|n| n.parse::<u64>().ok()))
                .max()
                .unwrap_or(0)
                + 1;
            (file.items, next_id)
        } else {
            (Vec::new(), 1)
        };
        Ok(Self { path, items, next_id })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&QueueFile { items: self.items.clone() })?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn push(&mut self, kind: QueueKind, prompt: impl Into<String>, now_ms: i64) -> Result<QueuedItem> {
        let prompt = prompt.into();
        if prompt.trim().is_empty() {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "a user-queue item needs a prompt"));
        }
        let item = QueuedItem {
            id: format!("uq-{}", self.next_id),
            kind,
            prompt,
            created_ms: now_ms,
            state: ItemState::Open,
            answer: None,
        };
        self.next_id += 1;
        self.items.push(item.clone());
        self.save()?;
        Ok(item)
    }

    pub fn resolve(&mut self, id: &str, answer: impl Into<String>, now_ms: i64) -> Result<QueuedItem> {
        let item = self
            .items
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("user-queue item `{id}`")))?;
        if item.state == ItemState::Resolved {
            return Err(ZeroError::new(ErrorCode::PolicyDenied, format!("`{id}` is already resolved")));
        }
        item.state = ItemState::Resolved;
        item.answer = Some(answer.into());
        let _ = now_ms;
        let out = item.clone();
        self.save()?;
        Ok(out)
    }

    pub fn open_items(&self) -> Vec<&QueuedItem> {
        self.items.iter().filter(|i| i.state == ItemState::Open).collect()
    }

    pub fn all(&self) -> &[QueuedItem] {
        &self.items
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    Independent(String),
    NeedsUser { kind: QueueKind, prompt: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeadlessReport {
    pub completed: Vec<String>,
    pub queued: Vec<String>,
    pub blocked: Vec<String>,
}

/// Run independent work and queue everything that needs a human. Nothing
/// dependent is guessed; blockers never stall unrelated items.
pub fn run_headless(
    work: impl IntoIterator<Item = Work>,
    queue: &mut UserQueue,
    now_ms: i64,
) -> Result<HeadlessReport> {
    let mut report = HeadlessReport::default();
    for item in work {
        match item {
            Work::Independent(name) => report.completed.push(name),
            Work::NeedsUser { kind, prompt } => {
                let queued = queue.push(kind, prompt, now_ms)?;
                report.queued.push(queued.id.clone());
                report.blocked.push(queued.id);
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_headless_run_queues_one_item_and_completes_independent_work() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = UserQueue::open(dir.path().join("user-queue.json")).unwrap();
        let report = run_headless(
            vec![
                Work::NeedsUser { kind: QueueKind::Approval, prompt: "approve deleting old.txt (trash)".into() },
                Work::Independent("write the module".into()),
                Work::Independent("run the tests".into()),
            ],
            &mut queue,
            1000,
        )
        .unwrap();

        assert_eq!(report.completed, vec!["write the module", "run the tests"]);
        assert_eq!(report.queued.len(), 1);
        assert_eq!(report.blocked.len(), 1);
        assert_eq!(queue.open_items().len(), 1);
        assert_eq!(queue.open_items()[0].kind, QueueKind::Approval);
    }

    #[test]
    fn the_queue_is_durable_and_resolvable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");
        let id;
        {
            let mut queue = UserQueue::open(&path).unwrap();
            id = queue.push(QueueKind::Credential, "paste the API key", 0).unwrap().id;
        }
        let mut queue = UserQueue::open(&path).unwrap();
        assert_eq!(queue.open_items().len(), 1);
        queue.resolve(&id, "provided", 10).unwrap();
        assert!(queue.open_items().is_empty());
        let again = UserQueue::open(&path).unwrap();
        assert_eq!(again.all()[0].state, ItemState::Resolved);
        assert_eq!(again.all()[0].answer.as_deref(), Some("provided"));
    }

    #[test]
    fn resolving_twice_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = UserQueue::open(dir.path().join("q.json")).unwrap();
        let id = queue.push(QueueKind::Question, "which database?", 0).unwrap().id;
        queue.resolve(&id, "sqlite", 1).unwrap();
        assert!(queue.resolve(&id, "postgres", 2).is_err());
    }
}
