//! Durable message queue and steering (MON-01..MON-05).
//!
//! Items are persisted on every mutation. Delivery happens at a safe boundary:
//! while a tool call is executing, `steer` and `follow_up` are deferred and no
//! executing call is rewritten. `interrupt` requests cancellation but still
//! waits for the running call to report its result.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

pub const DEFAULT_CAP: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    /// Apply at the next safe boundary, before the next model turn.
    Steer,
    /// Apply after the current turn completes.
    FollowUp,
    /// Apply at the next boundary without changing the turn's shape.
    Auto,
    /// Cancel the turn at the next safe boundary.
    Interrupt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    Queued,
    Applied,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueItem {
    pub id: String,
    pub text: String,
    pub delivery: Delivery,
    pub created_seq: u64,
    pub state: ItemState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryOutcome {
    /// Items delivered now, in order.
    pub delivered: Vec<QueueItem>,
    /// True when an interrupt was requested. The running call still finishes.
    pub interrupt: bool,
}

pub struct MessageQueue {
    path: PathBuf,
    cap: usize,
    items: Vec<QueueItem>,
    next_id: u64,
    next_seq: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct QueueFile {
    items: Vec<QueueItem>,
}

impl MessageQueue {
    pub fn open(path: impl AsRef<Path>, cap: usize) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (items, next_id, next_seq) = if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            let file: QueueFile = serde_json::from_str(&text)?;
            let next_id = file.items.iter().filter_map(|i| i.id.strip_prefix("q")).filter_map(|n| n.parse::<u64>().ok()).max().unwrap_or(0) + 1;
            let next_seq = file.items.iter().map(|i| i.created_seq + 1).max().unwrap_or(0);
            (file.items, next_id, next_seq)
        } else {
            (Vec::new(), 1, 0)
        };
        Ok(Self { path, cap, items, next_id, next_seq })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn items(&self) -> &[QueueItem] {
        &self.items
    }

    pub fn queued(&self) -> Vec<&QueueItem> {
        self.items.iter().filter(|i| i.state == ItemState::Queued).collect()
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = QueueFile { items: self.items.clone() };
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&file)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Enqueue an item. When full, the new item is rejected and old items stay.
    pub fn enqueue(&mut self, text: impl Into<String>, delivery: Delivery) -> Result<QueueItem> {
        let text = text.into();
        if text.trim().is_empty() {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "queue item text is empty"));
        }
        if self.queued().len() >= self.cap {
            return Err(ZeroError::new(
                ErrorCode::QueueFull,
                format!("queue holds {} items; finish or cancel one first (nothing was dropped)", self.cap),
            ));
        }
        let item = QueueItem {
            id: format!("q{}", self.next_id),
            text,
            delivery,
            created_seq: self.next_seq,
            state: ItemState::Queued,
        };
        self.next_id += 1;
        self.next_seq += 1;
        self.items.push(item.clone());
        self.save()?;
        Ok(item)
    }

    fn find_mut(&mut self, id: &str) -> Result<&mut QueueItem> {
        self.items
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or_else(|| ZeroError::new(ErrorCode::QueueItemMissing, format!("queue item `{id}`")))
    }

    pub fn edit(&mut self, id: &str, text: impl Into<String>) -> Result<()> {
        let text = text.into();
        let item = self.find_mut(id)?;
        if item.state != ItemState::Queued {
            return Err(ZeroError::new(ErrorCode::QueueItemMissing, format!("`{id}` is no longer queued")));
        }
        item.text = text;
        self.save()
    }

    pub fn reorder(&mut self, ids: &[String]) -> Result<()> {
        let mut queued: Vec<QueueItem> = self.items.iter().filter(|i| i.state == ItemState::Queued).cloned().collect();
        let mut ordered = Vec::new();
        for id in ids {
            let pos = queued
                .iter()
                .position(|i| &i.id == id)
                .ok_or_else(|| ZeroError::new(ErrorCode::QueueItemMissing, format!("`{id}` is not queued")))?;
            ordered.push(queued.remove(pos));
        }
        ordered.extend(queued);
        let mut iter = ordered.into_iter();
        for item in self.items.iter_mut() {
            if item.state == ItemState::Queued {
                *item = iter.next().expect("same count");
            }
        }
        self.save()
    }

    pub fn cancel(&mut self, id: &str) -> Result<()> {
        let item = self.find_mut(id)?;
        item.state = ItemState::Cancelled;
        self.save()
    }

    /// Mark an item as an interrupt; it fires at the next safe boundary.
    pub fn send_now(&mut self, id: &str) -> Result<()> {
        let item = self.find_mut(id)?;
        if item.state != ItemState::Queued {
            return Err(ZeroError::new(ErrorCode::QueueItemMissing, format!("`{id}` is no longer queued")));
        }
        item.delivery = Delivery::Interrupt;
        self.save()
    }

    /// Remove an item and return its text, as if the user took it back.
    pub fn take_back(&mut self, id: &str) -> Result<String> {
        let pos = self
            .items
            .iter()
            .position(|i| i.id == id)
            .ok_or_else(|| ZeroError::new(ErrorCode::QueueItemMissing, format!("queue item `{id}`")))?;
        let item = self.items.remove(pos);
        self.save()?;
        Ok(item.text)
    }

    /// Apply queued items at a safe boundary. While a tool is executing, nothing
    /// is delivered and no executing call is rewritten.
    pub fn apply_at_boundary(&mut self, tool_running: bool) -> Result<BoundaryOutcome> {
        let interrupt = self
            .items
            .iter()
            .any(|i| i.state == ItemState::Queued && i.delivery == Delivery::Interrupt);
        if tool_running {
            return Ok(BoundaryOutcome { delivered: Vec::new(), interrupt });
        }
        let mut delivered = Vec::new();
        for item in self.items.iter_mut() {
            if item.state == ItemState::Queued {
                item.state = ItemState::Applied;
                delivered.push(item.clone());
            }
        }
        if !delivered.is_empty() {
            self.save()?;
        }
        Ok(BoundaryOutcome { delivered, interrupt })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steering_during_a_tool_call_defers_to_the_next_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = MessageQueue::open(dir.path().join("q.json"), DEFAULT_CAP).unwrap();
        queue.enqueue("look at the failing test", Delivery::Steer).unwrap();

        // Mid-tool: nothing is delivered, the item stays queued.
        let mid = queue.apply_at_boundary(true).unwrap();
        assert!(mid.delivered.is_empty());
        assert_eq!(queue.queued().len(), 1);

        // At the boundary: delivered exactly once.
        let boundary = queue.apply_at_boundary(false).unwrap();
        assert_eq!(boundary.delivered.len(), 1);
        assert_eq!(boundary.delivered[0].text, "look at the failing test");
        assert!(queue.queued().is_empty());
        let again = queue.apply_at_boundary(false).unwrap();
        assert!(again.delivered.is_empty(), "an applied item is never delivered twice");
    }

    #[test]
    fn queue_is_durable_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("q.json");
        {
            let mut queue = MessageQueue::open(&path, DEFAULT_CAP).unwrap();
            queue.enqueue("one", Delivery::Auto).unwrap();
            queue.enqueue("two", Delivery::FollowUp).unwrap();
        }
        let mut queue = MessageQueue::open(&path, DEFAULT_CAP).unwrap();
        assert_eq!(queue.queued().len(), 2);
        assert_eq!(queue.queued()[0].text, "one");
        let id = queue.queued()[1].id.clone();
        assert_eq!(queue.take_back(&id).unwrap(), "two");
        assert_eq!(queue.queued().len(), 1);
    }

    #[test]
    fn full_queue_rejects_new_items_without_dropping_old_ones() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = MessageQueue::open(dir.path().join("q.json"), 2).unwrap();
        queue.enqueue("keep-1", Delivery::Auto).unwrap();
        queue.enqueue("keep-2", Delivery::Auto).unwrap();
        let err = queue.enqueue("rejected", Delivery::Auto).unwrap_err();
        assert_eq!(err.code(), ErrorCode::QueueFull);
        assert!(err.message().contains("nothing was dropped"));
        assert_eq!(queue.queued().len(), 2);
        assert_eq!(queue.queued()[0].text, "keep-1");
    }

    #[test]
    fn management_operations_work_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = MessageQueue::open(dir.path().join("q.json"), 10).unwrap();
        let a = queue.enqueue("a", Delivery::Auto).unwrap();
        let b = queue.enqueue("b", Delivery::Auto).unwrap();
        let c = queue.enqueue("c", Delivery::Auto).unwrap();

        queue.edit(&a.id, "a2").unwrap();
        queue.reorder(&[c.id.clone(), a.id.clone(), b.id.clone()]).unwrap();
        let order: Vec<&str> = queue.queued().iter().map(|i| i.text.as_str()).collect();
        assert_eq!(order, vec!["c", "a2", "b"]);

        queue.cancel(&b.id).unwrap();
        assert_eq!(queue.queued().len(), 2);

        queue.send_now(&c.id).unwrap();
        let outcome = queue.apply_at_boundary(false).unwrap();
        assert!(outcome.interrupt);
        assert_eq!(outcome.delivered.len(), 2);
    }

    #[test]
    fn interrupt_mid_tool_requests_cancel_without_rewriting_the_call() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = MessageQueue::open(dir.path().join("q.json"), 10).unwrap();
        queue.enqueue("stop after this call", Delivery::Interrupt).unwrap();
        let mid = queue.apply_at_boundary(true).unwrap();
        assert!(mid.interrupt);
        assert!(mid.delivered.is_empty());
    }
}
