//! Content-addressed blob store (FND-08): chunked, deduplicated, verified on read.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

pub const CHUNK_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobId([u8; 32]);

impl BlobId {
    pub fn of(bytes: &[u8]) -> Self {
        BlobId(*blake3::hash(bytes).as_bytes())
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn parse(s: &str) -> Result<Self> {
        if s.len() != 64 {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "blob id must be 64 hex characters"));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(chunk)
                .map_err(|_| ZeroError::new(ErrorCode::InvalidInput, "blob id is not ASCII"))?;
            out[i] = u8::from_str_radix(pair, 16)
                .map_err(|_| ZeroError::new(ErrorCode::InvalidInput, "blob id is not hex"))?;
        }
        Ok(BlobId(out))
    }
}

impl std::fmt::Display for BlobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, id: BlobId) -> PathBuf {
        let hex = id.to_hex();
        self.root.join(&hex[..2]).join(&hex[2..])
    }

    /// Store bytes, returning the content id. Storing twice writes nothing new.
    pub fn put(&self, bytes: &[u8]) -> Result<BlobId> {
        let id = BlobId::of(bytes);
        let path = self.path_for(id);
        if path.exists() {
            return Ok(id);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(id)
    }

    pub fn has(&self, id: BlobId) -> bool {
        self.path_for(id).exists()
    }

    /// Read and verify the content hash. Corruption is a typed error.
    pub fn get(&self, id: BlobId) -> Result<Vec<u8>> {
        let path = self.path_for(id);
        let mut f = File::open(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ZeroError::new(ErrorCode::NotFound, format!("blob {id} is missing"))
            } else {
                e.into()
            }
        })?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        let actual = BlobId::of(&bytes);
        if actual != id {
            return Err(ZeroError::new(
                ErrorCode::Corrupt,
                format!("blob {id} hashes to {actual}"),
            ));
        }
        Ok(bytes)
    }

    /// Store a large payload as fixed-size chunks; returns the chunk ids in order.
    pub fn put_chunked(&self, bytes: &[u8]) -> Result<Vec<BlobId>> {
        let mut ids = Vec::new();
        for chunk in bytes.chunks(CHUNK_BYTES) {
            ids.push(self.put(chunk)?);
        }
        if ids.is_empty() {
            ids.push(self.put(&[])?);
        }
        Ok(ids)
    }

    pub fn get_chunked(&self, ids: &[BlobId]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for id in ids {
            out.extend_from_slice(&self.get(*id)?);
        }
        Ok(out)
    }

    pub fn count(&self) -> Result<usize> {
        let mut n = 0;
        if !self.root.exists() {
            return Ok(0);
        }
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                n += std::fs::read_dir(entry.path())?.count();
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_is_deduplicated_and_verified() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();
        let a = store.put(b"hello").unwrap();
        let b = store.put(b"hello").unwrap();
        assert_eq!(a, b);
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(store.get(a).unwrap(), b"hello");
    }

    #[test]
    fn corruption_is_detected_on_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();
        let id = store.put(b"hello").unwrap();
        let path = store.path_for(id);
        std::fs::write(&path, b"tampered").unwrap();
        let err = store.get(id).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Corrupt);
    }

    #[test]
    fn missing_blob_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();
        let err = store.get(BlobId::of(b"nope")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[test]
    fn chunked_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();
        let data = vec![7u8; CHUNK_BYTES + 17];
        let ids = store.put_chunked(&data).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(store.get_chunked(&ids).unwrap(), data);
    }
}
