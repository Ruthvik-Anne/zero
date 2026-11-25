//! Approvals (POL-09, POL-15): bound to the exact action hash, with an expiry,
//! a durable record, and one decision per prompt.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zero_store::jsonl::{scan_raw, JsonlWriter};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ApprovalEvent {
    Requested {
        id: String,
        action_hash: String,
        summary: String,
        created_ms: i64,
        expires_ms: i64,
    },
    Decided {
        id: String,
        approved: bool,
        actor: String,
        decided_ms: i64,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub approved: bool,
    pub actor: String,
    pub decided_ms: i64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub action_hash: String,
    pub summary: String,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub decision: Option<ApprovalDecision>,
}

impl Approval {
    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_ms
    }

    pub fn is_valid(&self, now_ms: i64) -> bool {
        self.decision.as_ref().map(|d| d.approved).unwrap_or(false) && !self.is_expired(now_ms)
    }
}

pub struct ApprovalStore {
    path: PathBuf,
    approvals: BTreeMap<String, Approval>,
    next_id: u64,
    writer: JsonlWriter,
}

impl ApprovalStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (events, _) = scan_raw::<ApprovalEvent>(&path)?;
        let mut approvals: BTreeMap<String, Approval> = BTreeMap::new();
        let mut next_id = 1u64;
        for event in events {
            match event {
                ApprovalEvent::Requested { id, action_hash, summary, created_ms, expires_ms } => {
                    if let Some(n) = id.strip_prefix("ap-").and_then(|n| n.parse::<u64>().ok()) {
                        next_id = next_id.max(n + 1);
                    }
                    approvals.insert(
                        id.clone(),
                        Approval { id, action_hash, summary, created_ms, expires_ms, decision: None },
                    );
                }
                ApprovalEvent::Decided { id, approved, actor, decided_ms, reason } => {
                    if let Some(approval) = approvals.get_mut(&id) {
                        if approval.decision.is_none() {
                            approval.decision = Some(ApprovalDecision { approved, actor, decided_ms, reason });
                        }
                    }
                }
            }
        }
        let writer = JsonlWriter::open(&path)?;
        Ok(Self { path, approvals, next_id, writer })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, id: &str) -> Option<&Approval> {
        self.approvals.get(id)
    }

    pub fn pending(&self, now_ms: i64) -> Vec<&Approval> {
        self.approvals
            .values()
            .filter(|a| a.decision.is_none() && !a.is_expired(now_ms))
            .collect()
    }

    /// Create a prompt for an exact action hash.
    pub fn request(&mut self, action_hash: &str, summary: impl Into<String>, now_ms: i64, ttl_ms: i64) -> Result<Approval> {
        if action_hash.len() != 64 {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "an approval needs a 64-hex action hash"));
        }
        let approval = Approval {
            id: format!("ap-{}", self.next_id),
            action_hash: action_hash.to_string(),
            summary: summary.into(),
            created_ms: now_ms,
            expires_ms: now_ms + ttl_ms,
            decision: None,
        };
        self.next_id += 1;
        self.writer.append(&ApprovalEvent::Requested {
            id: approval.id.clone(),
            action_hash: approval.action_hash.clone(),
            summary: approval.summary.clone(),
            created_ms: approval.created_ms,
            expires_ms: approval.expires_ms,
        })?;
        self.approvals.insert(approval.id.clone(), approval.clone());
        Ok(approval)
    }

    /// Decide a prompt. The action hash must match the request; the first valid
    /// decision wins and later ones see it resolved.
    pub fn decide(
        &mut self,
        id: &str,
        action_hash: &str,
        approved: bool,
        actor: impl Into<String>,
        reason: impl Into<String>,
        now_ms: i64,
    ) -> Result<Approval> {
        let approval = self
            .approvals
            .get(id)
            .cloned()
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("approval `{id}`")))?;
        if let Some(existing) = &approval.decision {
            return Err(ZeroError::new(
                ErrorCode::ApprovalResolved,
                format!("approval `{id}` was already decided by {}", existing.actor),
            ));
        }
        if approval.is_expired(now_ms) {
            return Err(ZeroError::new(ErrorCode::ApprovalExpired, format!("approval `{id}` expired")));
        }
        if approval.action_hash != action_hash {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                "the approval is bound to a different action hash; the action changed",
            ));
        }
        let decision = ApprovalDecision {
            approved,
            actor: actor.into(),
            decided_ms: now_ms,
            reason: reason.into(),
        };
        self.writer.append(&ApprovalEvent::Decided {
            id: id.to_string(),
            approved,
            actor: decision.actor.clone(),
            decided_ms: decision.decided_ms,
            reason: decision.reason.clone(),
        })?;
        let mut updated = approval;
        updated.decision = Some(decision);
        self.approvals.insert(id.to_string(), updated.clone());
        Ok(updated)
    }

    /// True when this exact hash has a live positive decision.
    pub fn is_valid(&self, action_hash: &str, now_ms: i64) -> bool {
        self.approvals.values().any(|a| a.action_hash == action_hash && a.is_valid(now_ms))
    }

    /// Expire stale pending prompts and report how many were removed from the
    /// pending set (the durable record remains).
    pub fn expire(&mut self, now_ms: i64) -> Vec<String> {
        self.approvals
            .values()
            .filter(|a| a.decision.is_none() && a.is_expired(now_ms))
            .map(|a| a.id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mutated_command_needs_a_new_approval() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::open(dir.path().join("approvals.jsonl")).unwrap();
        let hash_a = "a".repeat(64);
        let hash_b = "b".repeat(64);
        let approval = store.request(&hash_a, "rm old.txt", 1000, 60_000).unwrap();
        store.decide(&approval.id, &hash_a, true, "user", "looks right", 1100).unwrap();
        assert!(store.is_valid(&hash_a, 1200));
        assert!(!store.is_valid(&hash_b, 1200), "a different action hash is not approved");

        // The changed action cannot reuse the prompt.
        let err = store
            .request(&hash_b, "rm -rf /", 1300, 60_000)
            .and_then(|b| store.decide(&b.id, &hash_a, true, "user", "reuse", 1400))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PolicyDenied);
        assert!(!store.is_valid(&hash_b, 1500));
    }

    #[test]
    fn approvals_expire() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::open(dir.path().join("approvals.jsonl")).unwrap();
        let hash = "c".repeat(64);
        let approval = store.request(&hash, "write a.rs", 1000, 500).unwrap();
        store.decide(&approval.id, &hash, true, "user", "ok", 1100).unwrap();
        assert!(store.is_valid(&hash, 1499));
        assert!(!store.is_valid(&hash, 1500));
        let err = store
            .request(&"d".repeat(64), "later", 2000, 100)
            .and_then(|a| store.decide(&a.id, &"d".repeat(64), true, "user", "late", 2200))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ApprovalExpired);
    }

    #[test]
    fn the_first_valid_decision_wins_and_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.jsonl");
        let hash = "e".repeat(64);
        let id;
        {
            let mut store = ApprovalStore::open(&path).unwrap();
            let approval = store.request(&hash, "install package", 1000, 60_000).unwrap();
            id = approval.id.clone();
            store.decide(&id, &hash, true, "tui", "yes", 1100).unwrap();
            let err = store.decide(&id, &hash, false, "android", "no", 1200).unwrap_err();
            assert_eq!(err.code(), ErrorCode::ApprovalResolved);
        }
        let store = ApprovalStore::open(&path).unwrap();
        let approval = store.get(&id).expect("approval persisted");
        let decision = approval.decision.clone().expect("decision persisted");
        assert!(decision.approved);
        assert_eq!(decision.actor, "tui");
        assert!(store.is_valid(&hash, 2000));
    }

    #[test]
    fn stale_prompts_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::open(dir.path().join("a.jsonl")).unwrap();
        store.request(&"f".repeat(64), "x", 0, 10).unwrap();
        assert_eq!(store.expire(5).len(), 0);
        assert_eq!(store.expire(10).len(), 1);
        assert!(store.pending(20).is_empty());
    }
}
