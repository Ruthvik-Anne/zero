//! Versioned session export and import (SES-12).
//!
//! A bundle carries the session metadata, every record, and every artifact as
//! base64. Export, wipe, import, and resume reproduce an identical transcript.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zero_store::session::{Entry, Record, SessionLog, SessionMeta, ENTRY_SCHEMA_VERSION};
use zero_types::error::{ErrorCode, Result, ZeroError};

pub const BUNDLE_FORMAT: &str = "zero.session.bundle";
pub const BUNDLE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleArtifact {
    pub name: String,
    pub hash: String,
    pub bytes_b64: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bundle {
    pub format: String,
    pub version: u32,
    pub exported_ts: i64,
    pub meta: SessionMeta,
    pub records: Vec<Record>,
    #[serde(default)]
    pub artifacts: Vec<BundleArtifact>,
}

impl Bundle {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(text: &str) -> Result<Self> {
        let bundle: Bundle = serde_json::from_str(text)?;
        if bundle.format != BUNDLE_FORMAT {
            return Err(ZeroError::new(
                ErrorCode::ImportIncompatible,
                format!("bundle format `{}` is not `{BUNDLE_FORMAT}`", bundle.format),
            ));
        }
        if bundle.version > BUNDLE_VERSION {
            return Err(ZeroError::new(
                ErrorCode::ImportIncompatible,
                format!("bundle version {} is newer than {BUNDLE_VERSION}", bundle.version),
            ));
        }
        Ok(bundle)
    }
}

/// Export a session and, when given, every artifact under `artifact_dir/<session>`.
pub fn export(
    log: &SessionLog,
    session_id: &str,
    artifact_dir: Option<&Path>,
    ts: i64,
) -> Result<Bundle> {
    let mut artifacts = Vec::new();
    if let Some(root) = artifact_dir {
        let dir = root.join(session_id);
        if dir.exists() {
            let mut names = Vec::new();
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    if let Some(name) = entry.file_name().to_str() {
                        if !name.starts_with('.') {
                            names.push(name.to_string());
                        }
                    }
                }
            }
            names.sort();
            for name in names {
                let bytes = std::fs::read(dir.join(&name))?;
                artifacts.push(BundleArtifact {
                    name,
                    hash: blake3::hash(&bytes).to_hex().to_string(),
                    bytes_b64: B64.encode(&bytes),
                });
            }
        }
    }
    Ok(Bundle {
        format: BUNDLE_FORMAT.into(),
        version: BUNDLE_VERSION,
        exported_ts: ts,
        meta: log.meta().clone(),
        records: log.records()?,
        artifacts,
    })
}

#[derive(Debug)]
pub struct Imported {
    pub id: String,
    pub log_path: PathBuf,
}

/// Import into `root`, creating `<id>.jsonl` and the artifacts. The transcript
/// order and content are preserved.
pub fn import(bundle: &Bundle, root: &Path, id: &str, ts: i64) -> Result<Imported> {
    std::fs::create_dir_all(root)?;
    let log_path = root.join(format!("{id}.jsonl"));
    if log_path.exists() {
        return Err(ZeroError::new(
            ErrorCode::AlreadyExists,
            format!("session `{id}` already exists at {}", log_path.display()),
        ));
    }
    for artifact in &bundle.artifacts {
        let bytes = B64.decode(&artifact.bytes_b64).map_err(|e| {
            ZeroError::new(ErrorCode::ImportIncompatible, format!("artifact `{}` is not base64: {e}", artifact.name))
        })?;
        let actual = blake3::hash(&bytes).to_hex().to_string();
        if actual != artifact.hash {
            return Err(ZeroError::new(
                ErrorCode::Corrupt,
                format!("artifact `{}` hash mismatch: {actual}", artifact.name),
            ));
        }
    }
    let mut meta = bundle.meta.clone();
    meta.schema = ENTRY_SCHEMA_VERSION;
    meta.created_ts = if meta.created_ts == 0 { ts } else { meta.created_ts };
    SessionLog::create(&log_path, meta)?;
    let mut log = SessionLog::open(&log_path)?;
    for record in &bundle.records {
        log.append(record.ts, record.entry.clone())?;
    }
    if !bundle.artifacts.is_empty() {
        let artifacts_root = root.join("artifacts").join(id);
        std::fs::create_dir_all(&artifacts_root)?;
        for artifact in &bundle.artifacts {
            let bytes = B64.decode(&artifact.bytes_b64).map_err(|e| {
                ZeroError::new(ErrorCode::ImportIncompatible, format!("{}: {e}", artifact.name))
            })?;
            std::fs::write(artifacts_root.join(&artifact.name), bytes)?;
        }
    }
    Ok(Imported { id: id.to_string(), log_path })
}

/// A transcript projection used to prove two sessions are identical.
pub fn transcript(records: &[Record]) -> Vec<String> {
    records
        .iter()
        .map(|r| match &r.entry {
            Entry::Message { role, text, tool_calls, tool_call_id } => format!(
                "message/{role:?}/{text}/{}/{}",
                tool_calls.len(),
                tool_call_id.clone().unwrap_or_default()
            ),
            Entry::Compaction { summary, keep_from_seq, removed_entries } => {
                format!("compaction/{summary}/{keep_from_seq}/{removed_entries}")
            }
            other => format!("{}/{}", other.kind(), serde_json::to_string(other).unwrap_or_default()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_store::session::Role;

    #[test]
    fn export_wipe_import_resume_produces_an_identical_transcript() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let mut log = SessionLog::create(
            src.join("s0001.jsonl"),
            SessionMeta {
                schema: ENTRY_SCHEMA_VERSION,
                generation: 3,
                created_ts: 100,
                name: "exported".into(),
                project: Some("proj".into()),
                parent: None,
            },
        )
        .unwrap();
        for i in 0..5 {
            log.append(i, Entry::Message {
                role: if i % 2 == 0 { Role::User } else { Role::Assistant },
                text: format!("m{i}"),
                tool_calls: vec![],
                tool_call_id: None,
            })
            .unwrap();
        }
        log.append(9, Entry::Message {
            role: Role::Tool,
            text: "result".into(),
            tool_calls: vec![],
            tool_call_id: Some("call-1".into()),
        })
        .unwrap();
        let artifacts = src.join("artifacts");
        std::fs::create_dir_all(artifacts.join("s0001")).unwrap();
        std::fs::write(artifacts.join("s0001").join("note.txt"), b"note").unwrap();

        let bundle = export(&log, "s0001", Some(&artifacts), 1000).unwrap();
        let json = bundle.to_json().unwrap();
        let original: Vec<String> = transcript(&log.records().unwrap());

        // Wipe the source.
        drop(log);
        std::fs::remove_dir_all(&src).unwrap();
        assert!(!src.exists());

        // Import into the same path from the serialized bundle.
        let bundle = Bundle::from_json(&json).unwrap();
        let imported = import(&bundle, &src, "s0001", 2000).unwrap();
        let resumed = SessionLog::open(&imported.log_path).unwrap();
        assert_eq!(transcript(&resumed.records().unwrap()), original);
        assert_eq!(resumed.meta().generation, 3);
        assert_eq!(resumed.meta().name, "exported");
        assert_eq!(
            std::fs::read(src.join("artifacts").join("s0001").join("note.txt")).unwrap(),
            b"note"
        );
    }

    #[test]
    fn incompatible_bundles_are_refused() {
        let mut value = serde_json::json!({
            "format": BUNDLE_FORMAT,
            "version": 99,
            "exported_ts": 0,
            "meta": {"schema": 1, "generation": 1, "created_ts": 0, "name": "x", "project": null, "parent": null},
            "records": [],
            "artifacts": []
        });
        assert_eq!(Bundle::from_json(&value.to_string()).unwrap_err().code(), ErrorCode::ImportIncompatible);
        value["version"] = serde_json::json!(1);
        value["format"] = serde_json::json!("other");
        assert_eq!(Bundle::from_json(&value.to_string()).unwrap_err().code(), ErrorCode::ImportIncompatible);
    }

    #[test]
    fn corrupted_artifact_bytes_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = Bundle {
            format: BUNDLE_FORMAT.into(),
            version: 1,
            exported_ts: 0,
            meta: SessionMeta {
                schema: 1,
                generation: 1,
                created_ts: 0,
                name: "x".into(),
                project: None,
                parent: None,
            },
            records: Vec::new(),
            artifacts: vec![BundleArtifact {
                name: "a.txt".into(),
                hash: "not-the-hash".into(),
                bytes_b64: B64.encode(b"bytes"),
            }],
        };
        let err = import(&bundle, dir.path(), "s1", 0).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Corrupt);
    }
}
