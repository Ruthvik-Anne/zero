//! Hash-chained, append-only audit log (TRU-04, OBS-02).
//!
//! Every record hashes `(seq, ts, actor, kind, payload, prev)`. Verification
//! reports the first record whose stored hash or prev link does not match, so
//! tampering is localised rather than hidden.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: u64,
    pub ts: i64,
    pub actor: String,
    pub kind: String,
    pub payload: serde_json::Value,
    pub prev: String,
    pub hash: String,
}

fn compute_hash(seq: u64, ts: i64, actor: &str, kind: &str, payload: &serde_json::Value, prev: &str) -> String {
    let canonical = serde_json::to_vec(&serde_json::json!({
        "seq": seq, "ts": ts, "actor": actor, "kind": kind, "payload": payload, "prev": prev
    }))
    .unwrap_or_default();
    blake3::hash(&canonical).to_hex().to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    pub events: usize,
    pub valid: bool,
    pub broken_at: Option<u64>,
    pub reason: String,
}

pub struct AuditLog {
    path: PathBuf,
    writer: crate::jsonl::JsonlWriter,
    next_seq: u64,
    last_hash: String,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog").field("path", &self.path).field("len", &self.next_seq).finish()
    }
}

impl AuditLog {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let report = verify(&path)?;
        if !report.valid {
            return Err(ZeroError::new(
                ErrorCode::TamperDetected,
                format!("audit chain at {} is broken at seq {}: {}", path.display(), report.broken_at.unwrap_or(0), report.reason),
            ));
        }
        let (events, _) = crate::jsonl::scan_raw::<AuditEvent>(&path)?;
        let next_seq = events.last().map(|e| e.seq + 1).unwrap_or(0);
        let last_hash = events.last().map(|e| e.hash.clone()).unwrap_or_else(|| GENESIS.to_string());
        let writer = crate::jsonl::JsonlWriter::open(&path)?;
        Ok(Self { path, writer, next_seq, last_hash })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&mut self, ts: i64, actor: &str, kind: &str, payload: serde_json::Value) -> Result<AuditEvent> {
        let seq = self.next_seq;
        let hash = compute_hash(seq, ts, actor, kind, &payload, &self.last_hash);
        let event = AuditEvent {
            seq,
            ts,
            actor: actor.to_string(),
            kind: kind.to_string(),
            payload,
            prev: self.last_hash.clone(),
            hash: hash.clone(),
        };
        self.writer.append(&event)?;
        self.next_seq += 1;
        self.last_hash = hash;
        Ok(event)
    }

    pub fn len(&self) -> u64 {
        self.next_seq
    }

    pub fn is_empty(&self) -> bool {
        self.next_seq == 0
    }
}

/// Verify the whole chain. A missing file is a valid empty log.
pub fn verify(path: impl AsRef<Path>) -> Result<AuditReport> {
    let path = path.as_ref();
    let (events, _) = crate::jsonl::scan_raw::<AuditEvent>(path)?;
    let mut prev = GENESIS.to_string();
    for (index, event) in events.iter().enumerate() {
        if event.seq != prev_seq(index) {
            return Ok(AuditReport {
                events: events.len(),
                valid: false,
                broken_at: Some(event.seq),
                reason: format!("sequence {index} is not {}", prev_seq(index)),
            });
        }
        if event.prev != prev {
            return Ok(AuditReport {
                events: events.len(),
                valid: false,
                broken_at: Some(event.seq),
                reason: "prev link does not match the previous record".into(),
            });
        }
        let expected = compute_hash(event.seq, event.ts, &event.actor, &event.kind, &event.payload, &event.prev);
        if expected != event.hash {
            return Ok(AuditReport {
                events: events.len(),
                valid: false,
                broken_at: Some(event.seq),
                reason: "stored hash does not match the record".into(),
            });
        }
        prev = event.hash.clone();
    }
    Ok(AuditReport { events: events.len(), valid: true, broken_at: None, reason: "ok".into() })
}

fn prev_seq(index: usize) -> u64 {
    index as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn the_chain_verifies_and_detects_an_edited_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let mut log = AuditLog::open(&path).unwrap();
            log.append(1000, "agent", "policy.deny", serde_json::json!({"action":"write","path":"a"})).unwrap();
            log.append(1001, "user", "approval", serde_json::json!({"id":"ap-1"})).unwrap();
            log.append(1002, "agent", "trash", serde_json::json!({"path":"old.txt"})).unwrap();
            assert_eq!(log.len(), 3);
        }
        let report = verify(&path).unwrap();
        assert!(report.valid, "{report:?}");
        assert_eq!(report.events, 3);

        // Edit the payload of the second record.
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        lines[1] = lines[1].replace("\"ap-1\"", "\"ap-2\"");
        let mut file = std::fs::File::create(&path).unwrap();
        for line in &lines {
            writeln!(file, "{line}").unwrap();
        }
        drop(file);

        let report = verify(&path).unwrap();
        assert!(!report.valid);
        assert_eq!(report.broken_at, Some(1));
        assert!(report.reason.contains("hash"));
        assert_eq!(AuditLog::open(&path).unwrap_err().code(), ErrorCode::TamperDetected);
    }

    #[test]
    fn deleting_a_middle_record_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let mut log = AuditLog::open(&path).unwrap();
            for i in 0..4 {
                log.append(i, "agent", "test", serde_json::json!({"i": i})).unwrap();
            }
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        let report = verify(&path).unwrap();
        assert!(!report.valid);
        // The next surviving record (seq 2) is where the chain no longer links.
        assert_eq!(report.broken_at, Some(2));
    }

    #[test]
    fn an_empty_log_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        let report = verify(dir.path().join("missing.jsonl")).unwrap();
        assert!(report.valid);
        assert_eq!(report.events, 0);
    }
}
