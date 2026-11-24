//! Command journal (SES-09, ACT-07, AR-01): journal before dispatch, report an
//! uncertain result instead of replaying it, and replay one effect per key.

use crate::jsonl::{scan_raw, JsonlWriter};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum JournalEntry {
    Begin { key: String, action: String, args_digest: String, ts: i64 },
    Applied { key: String, result: serde_json::Value, ts: i64 },
    Failed { key: String, code: String, message: String, ts: i64 },
    Uncertain { key: String, reason: String, ts: i64 },
}

#[derive(Debug, Clone, PartialEq)]
pub enum CommandState {
    Applied(serde_json::Value),
    Failed { code: String, message: String },
    Uncertain { reason: String },
    InFlight,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApplyOutcome {
    /// The effect ran now and was recorded.
    Applied(serde_json::Value),
    /// The command was already applied; the recorded result is returned and the
    /// effect is not repeated.
    Replayed(serde_json::Value),
}

pub struct CommandJournal {
    path: PathBuf,
    writer: JsonlWriter,
    state: BTreeMap<String, CommandState>,
}

impl CommandJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (entries, _) = scan_raw::<JournalEntry>(&path)?;
        let mut state = BTreeMap::new();
        for entry in entries {
            match entry {
                JournalEntry::Begin { key, .. } => {
                    state.insert(key, CommandState::InFlight);
                }
                JournalEntry::Applied { key, result, .. } => {
                    state.insert(key, CommandState::Applied(result));
                }
                JournalEntry::Failed { key, code, message, .. } => {
                    state.insert(key, CommandState::Failed { code, message });
                }
                JournalEntry::Uncertain { key, reason, .. } => {
                    state.insert(key, CommandState::Uncertain { reason });
                }
            }
        }
        let writer = JsonlWriter::open(&path)?;
        Ok(Self { path, writer, state })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn state(&self, key: &str) -> Option<&CommandState> {
        self.state.get(key)
    }

    /// Apply `f` at most once per key. The begin record is fsynced before `f`
    /// runs. A key that began but never finished is reported as uncertain and is
    /// never re-executed.
    pub fn apply_once<F>(
        &mut self,
        key: &str,
        action: &str,
        args_digest: &str,
        now_ms: i64,
        f: F,
    ) -> Result<ApplyOutcome>
    where
        F: FnOnce() -> Result<serde_json::Value>,
    {
        match self.state.get(key).cloned() {
            Some(CommandState::Applied(result)) => return Ok(ApplyOutcome::Replayed(result)),
            Some(CommandState::Uncertain { reason }) => {
                return Err(ZeroError::new(
                    ErrorCode::CommandUncertain,
                    format!("command `{key}` has an uncertain outcome: {reason}"),
                ))
            }
            Some(CommandState::InFlight) => {
                let reason = "a previous dispatch began and never recorded a result".to_string();
                self.record(JournalEntry::Uncertain { key: key.into(), reason: reason.clone(), ts: now_ms })?;
                self.state.insert(key.into(), CommandState::Uncertain { reason: reason.clone() });
                return Err(ZeroError::new(
                    ErrorCode::CommandUncertain,
                    format!("command `{key}` was dispatched before a crash; its effect is not replayed ({reason})"),
                ));
            }
            Some(CommandState::Failed { code, message }) => {
                return Err(ZeroError::new(
                    ErrorCode::CommandUncertain,
                    format!("command `{key}` failed earlier with {code}: {message}; request a new key to retry"),
                ))
            }
            None => {}
        }

        self.record(JournalEntry::Begin {
            key: key.into(),
            action: action.into(),
            args_digest: args_digest.into(),
            ts: now_ms,
        })?;
        self.state.insert(key.into(), CommandState::InFlight);
        match f() {
            Ok(result) => {
                self.record(JournalEntry::Applied { key: key.into(), result: result.clone(), ts: now_ms })?;
                self.state.insert(key.into(), CommandState::Applied(result.clone()));
                Ok(ApplyOutcome::Applied(result))
            }
            Err(e) => {
                self.record(JournalEntry::Failed {
                    key: key.into(),
                    code: e.code().as_str().into(),
                    message: e.message().into(),
                    ts: now_ms,
                })?;
                self.state.insert(
                    key.into(),
                    CommandState::Failed { code: e.code().as_str().into(), message: e.message().into() },
                );
                Err(e)
            }
        }
    }

    fn record(&mut self, entry: JournalEntry) -> Result<()> {
        self.writer.append(&entry)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn replay_applies_one_effect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.jsonl");
        let effects = Cell::new(0);
        {
            let mut journal = CommandJournal::open(&path).unwrap();
            let first = journal
                .apply_once("client-1/cmd-1", "fs.write", "digest", 0, || {
                    effects.set(effects.get() + 1);
                    Ok(serde_json::json!({"bytes": 3}))
                })
                .unwrap();
            assert_eq!(first, ApplyOutcome::Applied(serde_json::json!({"bytes": 3})));
            let second = journal
                .apply_once("client-1/cmd-1", "fs.write", "digest", 1, || {
                    effects.set(effects.get() + 1);
                    Ok(serde_json::json!({"bytes": 999}))
                })
                .unwrap();
            assert_eq!(second, ApplyOutcome::Replayed(serde_json::json!({"bytes": 3})));
        }
        // Across a reopen, still one effect and the recorded result.
        let mut journal = CommandJournal::open(&path).unwrap();
        let third = journal
            .apply_once("client-1/cmd-1", "fs.write", "digest", 2, || {
                effects.set(effects.get() + 1);
                Ok(serde_json::json!({}))
            })
            .unwrap();
        assert_eq!(third, ApplyOutcome::Replayed(serde_json::json!({"bytes": 3})));
        assert_eq!(effects.get(), 1);
    }

    #[test]
    fn dispatch_before_apply_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.jsonl");
        let _journal = CommandJournal::open(&path).unwrap();
        // Simulate a crash: write the begin record, drop the journal before the
        // effect is applied.
        let mut writer = JsonlWriter::open(&path).unwrap();
        writer
            .append(&JournalEntry::Begin { key: "crash-1".into(), action: "fs.write".into(), args_digest: "d".into(), ts: 0 })
            .unwrap();
        drop(writer);

        let mut reopened = CommandJournal::open(&path).unwrap();
        assert_eq!(reopened.state("crash-1"), Some(&CommandState::InFlight));
        let effects = Cell::new(0);
        let err = reopened
            .apply_once("crash-1", "fs.write", "d", 1, || {
                effects.set(effects.get() + 1);
                Ok(serde_json::json!({}))
            })
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::CommandUncertain);
        assert_eq!(effects.get(), 0, "an uncertain side effect is never replayed");
        assert!(matches!(
            reopened.state("crash-1"),
            Some(CommandState::Uncertain { .. })
        ));
    }

    #[test]
    fn failed_commands_need_a_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.jsonl");
        let mut journal = CommandJournal::open(&path).unwrap();
        let err = journal
            .apply_once("k", "a", "d", 0, || Err(ZeroError::new(ErrorCode::Io, "disk full")))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Io);
        let retry = journal
            .apply_once("k", "a", "d", 1, || Ok(serde_json::json!(1)))
            .unwrap_err();
        assert_eq!(retry.code(), ErrorCode::CommandUncertain);
        assert!(journal
            .apply_once("k2", "a", "d", 2, || Ok(serde_json::json!(2)))
            .is_ok());
    }
}
