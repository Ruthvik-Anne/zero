//! Overwrite journal (DEL-05, DEL-06): snapshot prior content before any managed
//! overwrite, truncate, or move-over, and restore it byte-exactly.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use zero_store::blob::BlobStore;
use zero_store::jsonl::{scan_raw, JsonlWriter};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub path: String,
    pub hash: String,
    pub size: u64,
    pub ts: i64,
}

pub struct OverwriteJournal {
    root: PathBuf,
    blobs: BlobStore,
    index: PathBuf,
    next_id: u64,
    writer: JsonlWriter,
    snapshots: Vec<Snapshot>,
}

impl OverwriteJournal {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        let blobs = BlobStore::open(root.join("blobs"))?;
        let index = root.join("index.jsonl");
        let (snapshots, _) = scan_raw::<Snapshot>(&index)?;
        let next_id = snapshots
            .iter()
            .filter_map(|s| s.id.strip_prefix("ow-").and_then(|n| n.parse::<u64>().ok()))
            .max()
            .unwrap_or(0)
            + 1;
        let writer = JsonlWriter::open(&index)?;
        Ok(Self { root, blobs, index, next_id, writer, snapshots })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn snapshots(&self) -> &[Snapshot] {
        &self.snapshots
    }

    /// Snapshot a file before it changes. `None` when the file does not exist yet.
    pub fn snapshot(&mut self, path: impl AsRef<Path>, ts: i64) -> Result<Option<Snapshot>> {
        let path = path.as_ref();
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let blob = self.blobs.put(&bytes)?;
        let snapshot = Snapshot {
            id: format!("ow-{}", self.next_id),
            path: path.display().to_string(),
            hash: blob.to_hex(),
            size: bytes.len() as u64,
            ts,
        };
        self.next_id += 1;
        self.writer.append(&snapshot)?;
        self.snapshots.push(snapshot.clone());
        Ok(Some(snapshot))
    }

    /// Snapshot, then write atomically (temp, fsync, rename, sync directory).
    pub fn overwrite(&mut self, path: impl AsRef<Path>, bytes: &[u8], ts: i64) -> Result<Option<Snapshot>> {
        let path = path.as_ref().to_path_buf();
        let snapshot = self.snapshot(&path, ts)?;
        write_atomic(&path, bytes)?;
        Ok(snapshot)
    }

    /// Restore a snapshot byte-exactly.
    pub fn undo(&self, id: &str) -> Result<PathBuf> {
        let snapshot = self
            .snapshots
            .iter()
            .rev()
            .find(|s| s.id == id)
            .ok_or_else(|| ZeroError::new(ErrorCode::SnapshotMissing, format!("snapshot `{id}`")))?;
        let blob = zero_store::blob::BlobId::parse(&snapshot.hash)?;
        let bytes = self.blobs.get(blob)?;
        if bytes.len() as u64 != snapshot.size {
            return Err(ZeroError::new(ErrorCode::Corrupt, format!("snapshot `{id}` size changed")));
        }
        let path = PathBuf::from(&snapshot.path);
        write_atomic(&path, &bytes)?;
        Ok(path)
    }

    pub fn index_path(&self) -> &Path {
        &self.index
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("zero-tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // Best-effort directory sync so the rename is durable.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_overwrite_restores_byte_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = OverwriteJournal::open(dir.path().join("journal")).unwrap();
        let file = dir.path().join("data.bin");
        let original: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        std::fs::write(&file, &original).unwrap();

        let snapshot = journal.overwrite(&file, b"replacement", 100).unwrap().expect("snapshot");
        assert_eq!(std::fs::read(&file).unwrap(), b"replacement");
        assert_eq!(snapshot.size, original.len() as u64);
        assert_eq!(snapshot.hash.len(), 64);

        let restored = journal.undo(&snapshot.id).unwrap();
        assert_eq!(restored, file);
        assert_eq!(std::fs::read(&file).unwrap(), original, "byte-exact restore");
    }

    #[test]
    fn creating_a_new_file_has_no_snapshot_and_undo_is_typed() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = OverwriteJournal::open(dir.path().join("journal")).unwrap();
        let file = dir.path().join("new.txt");
        assert!(journal.overwrite(&file, b"new", 0).unwrap().is_none());
        assert_eq!(std::fs::read(&file).unwrap(), b"new");
        let err = journal.undo("ow-999").unwrap_err();
        assert_eq!(err.code(), ErrorCode::SnapshotMissing);
    }

    #[test]
    fn snapshots_survive_reopen_and_truncation_is_recoverable() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("journal");
        let file = dir.path().join("log.txt");
        std::fs::write(&file, b"line one\nline two\n").unwrap();
        let id;
        {
            let mut journal = OverwriteJournal::open(&root).unwrap();
            let snapshot = journal.overwrite(&file, b"", 1).unwrap().expect("snapshot");
            id = snapshot.id;
            assert_eq!(std::fs::read(&file).unwrap(), b"");
        }
        let journal = OverwriteJournal::open(&root).unwrap();
        assert_eq!(journal.snapshots().len(), 1);
        journal.undo(&id).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"line one\nline two\n");
    }
}
