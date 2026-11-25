//! Durable dispatch queue (SCH-06, SCH-08, SCH-11).
//!
//! Calls are enqueued idempotently by key, claimed with a generation, and
//! journaled before dispatch. A restart marks an in-flight call `uncertain`
//! instead of re-dispatching it, so a killed process cannot duplicate a call.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zero_store::jsonl::{scan_raw, JsonlWriter};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Call {
    pub id: String,
    pub key: String,
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallState {
    Pending,
    InFlight { owner: String, generation: u64 },
    Done,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum QueueEvent {
    Enqueued { call: Call },
    Claimed { id: String, owner: String, generation: u64, ts: i64 },
    Completed { id: String, ts: i64 },
    Uncertain { id: String, reason: String, ts: i64 },
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub call: Call,
    pub state: CallState,
}

pub struct DurableQueue {
    path: PathBuf,
    writer: JsonlWriter,
    entries: BTreeMap<String, Entry>,
    by_key: BTreeMap<String, String>,
    generations: BTreeMap<String, u64>,
    dispatches: BTreeMap<String, u32>,
    next_id: u64,
}

impl DurableQueue {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (events, _) = scan_raw::<QueueEvent>(&path)?;
        let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
        let mut by_key = BTreeMap::new();
        let mut generations: BTreeMap<String, u64> = BTreeMap::new();
        let mut dispatches: BTreeMap<String, u32> = BTreeMap::new();
        let mut next_id = 1u64;
        for event in events {
            match event {
                QueueEvent::Enqueued { call } => {
                    if let Some(n) = call.id.strip_prefix("call-").and_then(|n| n.parse::<u64>().ok()) {
                        next_id = next_id.max(n + 1);
                    }
                    by_key.insert(call.key.clone(), call.id.clone());
                    entries.insert(call.id.clone(), Entry { call, state: CallState::Pending });
                }
                QueueEvent::Claimed { id, owner, generation, .. } => {
                    if let Some(entry) = entries.get_mut(&id) {
                        entry.state = CallState::InFlight { owner, generation };
                    }
                    generations.insert(id.clone(), generation);
                    *dispatches.entry(id).or_insert(0) += 1;
                }
                QueueEvent::Completed { id, .. } => {
                    if let Some(entry) = entries.get_mut(&id) {
                        entry.state = CallState::Done;
                    }
                }
                QueueEvent::Uncertain { id, .. } => {
                    if let Some(entry) = entries.get_mut(&id) {
                        entry.state = CallState::Uncertain;
                    }
                }
            }
        }
        let writer = JsonlWriter::open(&path)?;
        Ok(Self { path, writer, entries, by_key, generations, dispatches, next_id })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Idempotent by key: enqueueing the same key returns the existing id.
    pub fn enqueue(&mut self, key: &str, provider: &str, model: &str, payload: serde_json::Value) -> Result<String> {
        if let Some(existing) = self.by_key.get(key) {
            return Ok(existing.clone());
        }
        let id = format!("call-{}", self.next_id);
        self.next_id += 1;
        let call = Call { id: id.clone(), key: key.into(), provider: provider.into(), model: model.into(), payload };
        self.writer.append(&QueueEvent::Enqueued { call: call.clone() })?;
        self.by_key.insert(key.into(), id.clone());
        self.entries.insert(id.clone(), Entry { call, state: CallState::Pending });
        Ok(id)
    }

    pub fn pending(&self) -> Vec<&Call> {
        self.entries
            .values()
            .filter(|e| e.state == CallState::Pending)
            .map(|e| &e.call)
            .collect()
    }

    pub fn state(&self, id: &str) -> Option<&CallState> {
        self.entries.get(id).map(|e| &e.state)
    }

    pub fn dispatch_count(&self, id: &str) -> u32 {
        self.dispatches.get(id).copied().unwrap_or(0)
    }

    pub fn generation(&self, id: &str) -> u64 {
        self.generations.get(id).copied().unwrap_or(0)
    }

    /// Claim one pending call and journal the claim before returning it.
    pub fn claim_next(&mut self, owner: &str, now_ms: i64) -> Result<Option<(Call, u64)>> {
        let Some((id, call)) = self
            .entries
            .iter()
            .find(|(_, e)| e.state == CallState::Pending)
            .map(|(id, e)| (id.clone(), e.call.clone()))
        else {
            return Ok(None);
        };
        let generation = self.generation(&id) + 1;
        self.writer.append(&QueueEvent::Claimed { id: id.clone(), owner: owner.into(), generation, ts: now_ms })?;
        self.generations.insert(id.clone(), generation);
        *self.dispatches.entry(id.clone()).or_insert(0) += 1;
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.state = CallState::InFlight { owner: owner.into(), generation };
        }
        Ok(Some((call, generation)))
    }

    pub fn complete(&mut self, id: &str, now_ms: i64) -> Result<()> {
        if !self.entries.contains_key(id) {
            return Err(ZeroError::new(ErrorCode::NotFound, format!("call `{id}`")));
        }
        self.writer.append(&QueueEvent::Completed { id: id.into(), ts: now_ms })?;
        if let Some(entry) = self.entries.get_mut(id) {
            entry.state = CallState::Done;
        }
        Ok(())
    }

    /// After a restart, in-flight calls are reported uncertain and never
    /// re-dispatched.
    pub fn recover(&mut self, now_ms: i64) -> Result<Vec<String>> {
        let inflight: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| matches!(e.state, CallState::InFlight { .. }))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &inflight {
            self.writer.append(&QueueEvent::Uncertain {
                id: id.clone(),
                reason: "process restarted while the call was in flight".into(),
                ts: now_ms,
            })?;
            if let Some(entry) = self.entries.get_mut(id) {
                entry.state = CallState::Uncertain;
            }
        }
        Ok(inflight)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_is_idempotent_and_one_claim_per_call() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = DurableQueue::open(dir.path().join("q.jsonl")).unwrap();
        let a = queue.enqueue("k1", "openai", "gpt", serde_json::json!({"n": 1})).unwrap();
        let b = queue.enqueue("k1", "openai", "gpt", serde_json::json!({"n": 2})).unwrap();
        assert_eq!(a, b);
        assert_eq!(queue.len(), 1);
        let (call, generation) = queue.claim_next("w1", 0).unwrap().unwrap();
        assert_eq!(call.id, a);
        assert_eq!(generation, 1);
        assert!(queue.claim_next("w2", 1).unwrap().is_none(), "no duplicate dispatch");
        assert_eq!(queue.dispatch_count(&a), 1);
    }

    #[test]
    fn restart_reports_in_flight_as_uncertain_and_does_not_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("q.jsonl");
        let id;
        {
            let mut queue = DurableQueue::open(&path).unwrap();
            id = queue.enqueue("k", "p", "m", serde_json::json!({})).unwrap();
            queue.claim_next("w", 0).unwrap().unwrap();
        }
        let mut queue = DurableQueue::open(&path).unwrap();
        assert!(matches!(queue.state(&id), Some(CallState::InFlight { .. })));
        assert!(queue.claim_next("w2", 1).unwrap().is_none());
        assert_eq!(queue.recover(2).unwrap(), vec![id.clone()]);
        assert_eq!(queue.state(&id), Some(&CallState::Uncertain));
        assert!(queue.claim_next("w3", 3).unwrap().is_none());
        assert_eq!(queue.dispatch_count(&id), 1, "one dispatch across the restart");
        assert_eq!(DurableQueue::open(&path).unwrap().dispatch_count(&id), 1);
    }

    #[test]
    fn pending_calls_survive_and_complete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("q.jsonl");
        let a;
        {
            let mut queue = DurableQueue::open(&path).unwrap();
            a = queue.enqueue("a", "p", "m", serde_json::json!({})).unwrap();
            queue.enqueue("b", "p", "m", serde_json::json!({})).unwrap();
        }
        let mut queue = DurableQueue::open(&path).unwrap();
        assert_eq!(queue.pending().len(), 2);
        queue.claim_next("w", 0).unwrap();
        queue.claim_next("w", 1).unwrap();
        assert!(queue.pending().is_empty());
        queue.complete(&a, 2).unwrap();
        assert_eq!(queue.state(&a), Some(&CallState::Done));
    }
}
