//! Per-session artifacts (SES-10) referenced from the transcript.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zero_store::session::{Entry, Record, SessionLog};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn session_dir(&self, session: &str) -> PathBuf {
        self.root.join(session)
    }

    pub fn path(&self, session: &str, name: &str) -> PathBuf {
        self.session_dir(session).join(name)
    }

    pub fn put(&self, session: &str, name: &str, bytes: &[u8]) -> Result<ArtifactRef> {
        if name.is_empty() || name.contains("..") || name.contains(['/', '\\']) {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "artifact name must be a bare file name",
            ));
        }
        let dir = self.session_dir(session);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(name);
        let tmp = dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &path)?;
        let hash = blake3::hash(bytes).to_hex().to_string();
        Ok(ArtifactRef {
            id: format!("art-{session}-{name}"),
            name: name.to_string(),
            size: bytes.len() as u64,
            hash,
        })
    }

    pub fn get(&self, session: &str, name: &str) -> Result<Vec<u8>> {
        let path = self.path(session, name);
        std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ZeroError::new(ErrorCode::ArtifactMissing, format!("artifact `{name}` for `{session}`"))
            } else {
                e.into()
            }
        })
    }

    pub fn exists(&self, session: &str, name: &str) -> bool {
        self.path(session, name).exists()
    }

    pub fn list(&self, session: &str) -> Result<Vec<String>> {
        let dir = self.session_dir(session);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(dir)? {
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
        Ok(names)
    }
}

pub const ARTIFACT_ENTRY: &str = "artifact";

/// Append the transcript reference for an artifact.
pub fn reference(log: &mut SessionLog, artifact: &ArtifactRef, ts: i64) -> Result<Record> {
    log.append(
        ts,
        Entry::Custom {
            name: ARTIFACT_ENTRY.into(),
            data: serde_json::to_value(artifact)?,
        },
    )
}

/// All artifact references in a transcript, in order.
pub fn refs_from_records(records: &[Record]) -> Vec<ArtifactRef> {
    records
        .iter()
        .filter_map(|r| match &r.entry {
            Entry::Custom { name, data } if name == ARTIFACT_ENTRY => {
                serde_json::from_value(data.clone()).ok()
            }
            _ => None,
        })
        .collect()
}

/// Resolve references after a resume: the file must still exist with the
/// recorded size and hash.
pub fn resolve(
    store: &ArtifactStore,
    session: &str,
    records: &[Record],
) -> Vec<(ArtifactRef, bool)> {
    refs_from_records(records)
        .into_iter()
        .map(|r| {
            let ok = store
                .get(session, &r.name)
                .map(|bytes| bytes.len() as u64 == r.size && blake3::hash(&bytes).to_hex().to_string() == r.hash)
                .unwrap_or(false);
            (r, ok)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_store::session::{SessionMeta, ENTRY_SCHEMA_VERSION};

    #[test]
    fn artifacts_resolve_from_the_transcript_after_resume() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(dir.path().join("artifacts")).unwrap();
        let log_path = dir.path().join("s.jsonl");
        let mut log = SessionLog::create(
            &log_path,
            SessionMeta {
                schema: ENTRY_SCHEMA_VERSION,
                generation: 1,
                created_ts: 0,
                name: "s".into(),
                project: None,
                parent: None,
            },
        )
        .unwrap();

        let artifact = store.put("s0001", "report.txt", b"artifact body").unwrap();
        reference(&mut log, &artifact, 0).unwrap();
        drop(log);

        // Resume: reopen the log and resolve from the transcript alone.
        let log = SessionLog::open(&log_path).unwrap();
        let records = log.records().unwrap();
        let resolved = resolve(&store, "s0001", &records);
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].1);
        assert_eq!(store.get("s0001", "report.txt").unwrap(), b"artifact body");
    }

    #[test]
    fn a_missing_or_changed_artifact_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(dir.path()).unwrap();
        let artifact = ArtifactRef {
            id: "a".into(),
            name: "gone.txt".into(),
            size: 3,
            hash: "abc".into(),
        };
        let records = vec![Record {
            seq: 0,
            ts: 0,
            entry: Entry::Custom {
                name: ARTIFACT_ENTRY.into(),
                data: serde_json::to_value(&artifact).unwrap(),
            },
        }];
        assert!(!resolve(&store, "s", &records)[0].1);
        assert_eq!(store.get("s", "gone.txt").unwrap_err().code(), ErrorCode::ArtifactMissing);
    }

    #[test]
    fn artifact_names_cannot_escape_the_session_directory() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(dir.path()).unwrap();
        for bad in ["../x", "a/b", "a\\b", ""] {
            assert_eq!(store.put("s", bad, b"x").unwrap_err().code(), ErrorCode::InvalidInput, "{bad}");
        }
    }
}
