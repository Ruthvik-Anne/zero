//! All-or-nothing file batches with a crash journal (FS-04, FS-08).
//!
//! Every touched path is snapshotted to a content-addressed blob before the first
//! change. A failure restores every file, and `recover` replays or rolls back a
//! batch whose journal has no terminal state after a crash. Removals go to the
//! OS trash; the snapshot is what makes rollback exact.

use crate::manager::atomic_write;
use crate::trash::TrashService;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zero_store::blob::BlobStore;
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchOp {
    Write { path: PathBuf, bytes: Vec<u8> },
    Remove { path: PathBuf },
    Rename { from: PathBuf, to: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchError {
    pub code: String,
    pub message: String,
    /// At most three lines of context; never a file body.
    pub context: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFile {
    pub path: PathBuf,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchReceipt {
    pub ok: bool,
    pub dry_run: bool,
    pub files: Vec<BatchFile>,
    pub first_error: Option<BatchError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotEntry {
    path: PathBuf,
    blob: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BatchJournal {
    id: String,
    state: String,
    snapshots: Vec<SnapshotEntry>,
}

pub struct BatchRunner {
    root: PathBuf,
    journal_dir: PathBuf,
    blobs: BlobStore,
    trash: TrashService,
}

impl BatchRunner {
    pub fn new(root: impl AsRef<Path>, trash: TrashService, journal_dir: impl AsRef<Path>) -> Result<Self> {
        let journal_dir = journal_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&journal_dir)?;
        let blobs = BlobStore::open(journal_dir.join("blobs"))?;
        Ok(Self { root: root.as_ref().to_path_buf(), journal_dir, blobs, trash })
    }

    fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        }
    }

    fn touched(&self, ops: &[BatchOp]) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        for op in ops {
            match op {
                BatchOp::Write { path, .. } | BatchOp::Remove { path } => paths.push(self.resolve(path)),
                BatchOp::Rename { from, to } => {
                    paths.push(self.resolve(from));
                    paths.push(self.resolve(to));
                }
            }
        }
        paths.sort();
        paths.dedup();
        paths
    }

    /// Validate without changing anything.
    pub fn dry_run(&self, ops: &[BatchOp]) -> BatchReceipt {
        let mut files = Vec::new();
        for op in ops {
            match op {
                BatchOp::Write { path, .. } => {
                    if self.resolve(path).is_dir() {
                        return self.fail(path, ErrorCode::InvalidInput, "cannot write over a directory", "write");
                    }
                    files.push(BatchFile { path: path.clone(), action: "write".into() });
                }
                BatchOp::Remove { path } => {
                    if !self.resolve(path).exists() {
                        return self.fail(path, ErrorCode::NotFound, "remove target is missing", "remove");
                    }
                    files.push(BatchFile { path: path.clone(), action: "remove".into() });
                }
                BatchOp::Rename { from, to } => {
                    if !self.resolve(from).exists() {
                        return self.fail(from, ErrorCode::NotFound, "rename source is missing", "rename");
                    }
                    if self.resolve(to).exists() {
                        return self.fail(to, ErrorCode::Conflict, "rename destination exists", "rename");
                    }
                    files.push(BatchFile { path: from.clone(), action: format!("rename -> {}", to.display()) });
                }
            }
        }
        BatchReceipt { ok: true, dry_run: true, files, first_error: None }
    }

    fn fail(&self, path: &Path, code: ErrorCode, message: &str, action: &str) -> BatchReceipt {
        BatchReceipt {
            ok: false,
            dry_run: true,
            files: vec![BatchFile { path: path.to_path_buf(), action: action.into() }],
            first_error: Some(BatchError {
                code: code.as_str().into(),
                message: message.into(),
                context: vec![format!("path: {}", path.display())],
            }),
        }
    }

    fn write_journal(&self, journal: &BatchJournal) -> Result<()> {
        let path = self.journal_dir.join(format!("{}.json", journal.id));
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(journal)?)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Apply the batch. On any failure every file is restored from its snapshot.
    pub fn apply(&mut self, ops: &[BatchOp], now_ms: i64) -> Result<BatchReceipt> {
        let dry = self.dry_run(ops);
        if !dry.ok {
            return Ok(dry);
        }
        let paths = self.touched(ops);
        let mut snapshots = Vec::new();
        for path in &paths {
            let blob = match std::fs::read(path) {
                Ok(bytes) => Some(self.blobs.put(&bytes)?.to_hex()),
                Err(_) => None,
            };
            snapshots.push(SnapshotEntry { path: path.clone(), blob });
        }
        let journal = BatchJournal { id: format!("batch-{now_ms}"), state: "begin".into(), snapshots: snapshots.clone() };
        self.write_journal(&journal)?;

        let mut applied: Vec<BatchFile> = Vec::new();
        for op in ops {
            let result = match op {
                BatchOp::Write { path, bytes } => atomic_write(&self.resolve(path), bytes),
                BatchOp::Remove { path } => {
                    let resolved = self.resolve(path);
                    match self.trash.trash(&resolved)? {
                        crate::trash::TrashOutcome::Trashed { .. } => Ok(()),
                        crate::trash::TrashOutcome::Refused { reason, .. } => Err(ZeroError::new(
                            ErrorCode::ProtectedPath,
                            format!("{}: {reason}", resolved.display()),
                        )),
                    }
                }
                BatchOp::Rename { from, to } => std::fs::rename(self.resolve(from), self.resolve(to)).map_err(ZeroError::from),
            };
            match result {
                Ok(()) => applied.push(BatchFile {
                    path: match op {
                        BatchOp::Write { path, .. } | BatchOp::Remove { path } => path.clone(),
                        BatchOp::Rename { from, .. } => from.clone(),
                    },
                    action: match op {
                        BatchOp::Write { .. } => "write",
                        BatchOp::Remove { .. } => "remove",
                        BatchOp::Rename { .. } => "rename",
                    }
                    .into(),
                }),
                Err(error) => {
                    self.rollback(&snapshots)?;
                    let mut journal = journal.clone();
                    journal.state = "rolled_back".into();
                    self.write_journal(&journal)?;
                    return Ok(BatchReceipt {
                        ok: false,
                        dry_run: false,
                        files: applied,
                        first_error: Some(BatchError {
                            code: error.code().as_str().into(),
                            message: truncate(error.message(), 240),
                            context: error.message().lines().take(3).map(|l| truncate(l, 120)).collect(),
                        }),
                    });
                }
            }
        }
        let mut journal = journal;
        journal.state = "committed".into();
        self.write_journal(&journal)?;
        Ok(BatchReceipt { ok: true, dry_run: false, files: applied, first_error: None })
    }

    fn rollback(&self, snapshots: &[SnapshotEntry]) -> Result<()> {
        for snapshot in snapshots {
            match &snapshot.blob {
                Some(hash) => {
                    let id = zero_store::blob::BlobId::parse(hash)?;
                    let bytes = self.blobs.get(id)?;
                    atomic_write(&snapshot.path, &bytes)?;
                }
                None => {
                    if snapshot.path.exists() {
                        std::fs::remove_file(&snapshot.path)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Recover batches with a `begin` state: a crash happened after the journal
    /// but before a terminal state. Restore every snapshot.
    pub fn recover(&mut self) -> Result<Vec<String>> {
        let mut recovered = Vec::new();
        for entry in std::fs::read_dir(&self.journal_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(entry.path())?;
            let mut journal: BatchJournal = serde_json::from_str(&text)?;
            if journal.state == "begin" {
                self.rollback(&journal.snapshots)?;
                journal.state = "recovered".into();
                self.write_journal(&journal)?;
                recovered.push(journal.id);
            }
        }
        Ok(recovered)
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        text.to_string()
    } else {
        format!("{}…", &text[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_types::paths::Platform;
    use zero_types::protected::ProtectedPaths;

    fn runner(dir: &Path) -> BatchRunner {
        let trash = TrashService::new(ProtectedPaths::new(
            dir,
            dir.join(".zero"),
            dir.join(".zero-config"),
            if cfg!(windows) { Platform::Windows } else { Platform::Linux },
        ));
        BatchRunner::new(dir, trash, dir.join(".journals")).unwrap()
    }

    #[test]
    fn a_failing_operation_restores_every_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut runner = runner(dir.path());
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, b"A-original").unwrap();
        std::fs::write(&b, b"B-original").unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let ops = vec![
            BatchOp::Write { path: a.clone(), bytes: b"A-new".to_vec() },
            BatchOp::Remove { path: b.clone() },
            // This write fails at apply time: its parent is a regular file.
            BatchOp::Write { path: blocker.join("child.txt"), bytes: b"x".to_vec() },
        ];
        let receipt = runner.apply(&ops, 1).unwrap();
        assert!(!receipt.ok);
        assert_eq!(receipt.files.len(), 2, "the two successful ops are reported before the failure");
        let error = receipt.first_error.unwrap();
        assert!(error.context.len() <= 3);
        assert_eq!(std::fs::read(&a).unwrap(), b"A-original", "write rolled back");
        assert_eq!(std::fs::read(&b).unwrap(), b"B-original", "remove rolled back");
    }

    #[test]
    fn dry_run_reports_without_touching_anything() {
        let dir = tempfile::tempdir().unwrap();
        let runner = runner(dir.path());
        let a = dir.path().join("a.txt");
        std::fs::write(&a, b"original").unwrap();
        let ops = vec![BatchOp::Write { path: a.clone(), bytes: b"new".to_vec() }];
        let receipt = runner.dry_run(&ops);
        assert!(receipt.ok && receipt.dry_run);
        assert_eq!(std::fs::read(&a).unwrap(), b"original");
        assert!(receipt.files.iter().any(|f| f.action == "write"));
    }

    #[test]
    fn a_successful_batch_commits_and_removals_are_trashed() {
        let dir = tempfile::tempdir().unwrap();
        let mut runner = runner(dir.path());
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, b"A").unwrap();
        std::fs::write(&b, b"B").unwrap();
        let renamed = dir.path().join("c.txt");
        let ops = vec![
            BatchOp::Write { path: a.clone(), bytes: b"A2".to_vec() },
            BatchOp::Remove { path: b.clone() },
            BatchOp::Rename { from: a.clone(), to: renamed.clone() },
        ];
        let receipt = runner.apply(&ops, 2).unwrap();
        assert!(receipt.ok, "{:?}", receipt.first_error);
        assert!(!b.exists());
        assert_eq!(std::fs::read(&renamed).unwrap(), b"A2");
        assert!(!a.exists());
    }

    #[test]
    fn recovery_restores_a_crashed_batch() {
        let dir = tempfile::tempdir().unwrap();
        let mut runner = runner(dir.path());
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"before").unwrap();
        // Simulate a crash after the journal and a partial write.
        let blob = runner.blobs.put(b"before").unwrap().to_hex();
        let journal = BatchJournal {
            id: "batch-crash".into(),
            state: "begin".into(),
            snapshots: vec![SnapshotEntry { path: file.clone(), blob: Some(blob) }],
        };
        runner.write_journal(&journal).unwrap();
        std::fs::write(&file, b"partial").unwrap();

        let recovered = runner.recover().unwrap();
        assert_eq!(recovered, vec!["batch-crash"]);
        assert_eq!(std::fs::read(&file).unwrap(), b"before");
        assert!(runner.recover().unwrap().is_empty(), "recovery is idempotent");
    }
}
