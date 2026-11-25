//! Versioned file handles and atomic writes (FS-01..FS-04, FS-07, FS-08).
//!
//! A handle records the content hash, size, mtime, and filesystem id on open.
//! A managed write refuses a stale handle: an external edit (shell, build, IDE)
//! wins the race and the caller must reopen. Writes are temp + fsync + atomic
//! replace, preserving mode and writing through symlinks.

use crate::identity::{identity, FileIdentity};
use crate::trash::{TrashOutcome, TrashService};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Newline {
    Lf,
    Crlf,
    Mixed,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub hash: String,
    pub size: u64,
    pub mtime_ms: i64,
    pub file_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handle {
    pub path: PathBuf,
    pub version: Version,
    pub encoding: Encoding,
    pub newline: Newline,
    pub line_count: u64,
}

#[derive(Debug, Clone)]
pub struct FileManager {
    root: PathBuf,
    trash: TrashService,
}

impl FileManager {
    pub fn new(root: impl AsRef<Path>, trash: TrashService) -> Self {
        Self { root: root.as_ref().to_path_buf(), trash }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn trash_service(&self) -> &TrashService {
        &self.trash
    }

    fn resolve(&self, path: impl AsRef<Path>) -> PathBuf {
        let path = path.as_ref();
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        }
    }

    pub fn read(&self, path: impl AsRef<Path>) -> Result<Vec<u8>> {
        Ok(std::fs::read(self.resolve(path))?)
    }

    pub fn version(&self, path: impl AsRef<Path>) -> Result<Version> {
        current_version(&self.resolve(path))
    }

    pub fn open(&self, path: impl AsRef<Path>) -> Result<Handle> {
        let path = self.resolve(path);
        let bytes = std::fs::read(&path)?;
        let version = current_version(&path)?;
        Ok(Handle {
            path: path.clone(),
            version,
            encoding: detect_encoding(&bytes),
            newline: detect_newline(&bytes),
            line_count: line_count(&bytes),
        })
    }

    /// Write with an exact expected version. A stale handle is refused and the
    /// file is left exactly as the external writer left it.
    pub fn write(&self, handle: &Handle, bytes: &[u8]) -> Result<Version> {
        let current = current_version(&handle.path)?;
        if current.hash != handle.version.hash || current.file_id != handle.version.file_id {
            return Err(ZeroError::new(
                ErrorCode::Stale,
                format!(
                    "{} changed since it was opened (expected {}, found {})",
                    handle.path.display(),
                    &handle.version.hash[..12],
                    &current.hash[..12]
                ),
            ));
        }
        atomic_write(&handle.path, bytes)?;
        current_version(&handle.path)
    }

    /// Write without a handle, used by batch staging and tests.
    pub fn write_path(&self, path: impl AsRef<Path>, bytes: &[u8]) -> Result<Version> {
        let path = self.resolve(path);
        atomic_write(&path, bytes)?;
        current_version(&path)
    }

    /// Delete always routes to the OS trash; the original is never unlinked.
    pub fn delete(&self, path: impl AsRef<Path>) -> Result<TrashOutcome> {
        self.trash.trash(self.resolve(path))
    }

    pub fn identity(&self, path: impl AsRef<Path>) -> Result<FileIdentity> {
        identity(self.resolve(path))
    }
}

pub fn current_version(path: &Path) -> Result<Version> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ZeroError::new(ErrorCode::NotFound, format!("{}", path.display()))
        } else {
            e.into()
        }
    })?;
    let bytes = std::fs::read(path)?;
    let id = identity(path)?;
    Ok(Version {
        hash: blake3::hash(&bytes).to_hex().to_string(),
        size: metadata.len(),
        mtime_ms: metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0),
        file_id: id.id,
    })
}

pub fn detect_encoding(bytes: &[u8]) -> Encoding {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        Encoding::Utf8Bom
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        Encoding::Utf16Le
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        Encoding::Utf16Be
    } else if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
        Encoding::Binary
    } else {
        Encoding::Utf8
    }
}

pub fn detect_newline(bytes: &[u8]) -> Newline {
    let crlf = bytes.windows(2).filter(|w| *w == b"\r\n").count();
    let lf = bytes.iter().filter(|b| **b == b'\n').count();
    match (crlf, lf) {
        (0, 0) => Newline::None,
        (0, _) => Newline::Lf,
        (c, l) if c == l => Newline::Crlf,
        _ => Newline::Mixed,
    }
}

pub fn line_count(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        return 0;
    }
    let newlines = bytes.iter().filter(|b| **b == b'\n').count() as u64;
    if bytes.ends_with(b"\n") {
        newlines
    } else {
        newlines + 1
    }
}

/// Temp file in the same directory, fsync, preserve mode, atomic replace.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    // Write through a symlink to its target; the link itself is preserved.
    let target = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => std::fs::canonicalize(path)?,
        _ => path.to_path_buf(),
    };
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let name = target.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = parent.join(format!(".{name}.zero-tmp-{}", std::process::id()));
    let existing_permissions = std::fs::metadata(&target).ok().map(|m| m.permissions());

    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    if let Some(permissions) = existing_permissions {
        // A read-only target cannot be replaced; fail before touching it.
        if permissions.readonly() {
            let _ = std::fs::remove_file(&tmp);
            return Err(ZeroError::new(
                ErrorCode::PermissionDenied,
                format!("{} is read-only; clear the attribute before writing", target.display()),
            ));
        }
        let _ = std::fs::set_permissions(&tmp, permissions);
    }
    replace(&tmp, &target)?;
    #[cfg(unix)]
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(unix)]
fn replace(from: &Path, to: &Path) -> Result<()> {
    std::fs::rename(from, to)?;
    Ok(())
}

#[cfg(windows)]
fn replace(from: &Path, to: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};
    let wide = |p: &Path| -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    };
    let from_w = wide(from);
    let to_w = wide(to);
    let ok = unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
    if ok == 0 {
        let _ = std::fs::remove_file(from);
        return Err(ZeroError::new(
            ErrorCode::Io,
            format!("atomic replace of {} failed: {}", to.display(), std::io::Error::last_os_error()),
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn replace(from: &Path, to: &Path) -> Result<()> {
    std::fs::rename(from, to)?;
    Ok(())
}

/// Poll-based external-change detection (FS-07, FS-13).
pub struct Watcher {
    root: PathBuf,
    known: BTreeMap<PathBuf, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Created,
    Modified,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub path: PathBuf,
    pub kind: ChangeKind,
}

impl Watcher {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self { root: root.as_ref().to_path_buf(), known: BTreeMap::new() }
    }

    fn scan(&self) -> Result<BTreeMap<PathBuf, String>> {
        let mut out = BTreeMap::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path)?;
                if meta.is_dir() {
                    if entry.file_name() != ".git" {
                        stack.push(path);
                    }
                } else if meta.is_file() {
                    if let Ok(bytes) = std::fs::read(&path) {
                        out.insert(path, blake3::hash(&bytes).to_hex().to_string());
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn prime(&mut self) -> Result<()> {
        self.known = self.scan()?;
        Ok(())
    }

    /// Compare the tree with the last snapshot.
    pub fn poll(&mut self) -> Result<Vec<Change>> {
        let current = self.scan()?;
        let mut changes = Vec::new();
        for (path, hash) in &current {
            match self.known.get(path) {
                Some(old) if old == hash => {}
                Some(_) => changes.push(Change { path: path.clone(), kind: ChangeKind::Modified }),
                None => changes.push(Change { path: path.clone(), kind: ChangeKind::Created }),
            }
        }
        for path in self.known.keys() {
            if !current.contains_key(path) {
                changes.push(Change { path: path.clone(), kind: ChangeKind::Removed });
            }
        }
        self.known = current;
        Ok(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trash::TrashService;
    use zero_types::paths::Platform;
    use zero_types::protected::ProtectedPaths;

    fn manager(dir: &Path) -> FileManager {
        let trash = TrashService::new(ProtectedPaths::new(
            dir,
            dir.join(".zero"),
            dir.join(".zero-config"),
            if cfg!(windows) { Platform::Windows } else { Platform::Linux },
        ));
        FileManager::new(dir, trash)
    }

    #[test]
    fn a_handle_records_hash_size_mtime_id_encoding_and_lines() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path());
        std::fs::write(dir.path().join("a.txt"), b"line one\nline two\n").unwrap();
        let handle = manager.open("a.txt").unwrap();
        assert_eq!(handle.line_count, 2);
        assert_eq!(handle.encoding, Encoding::Utf8);
        assert_eq!(handle.newline, Newline::Lf);
        assert_eq!(handle.version.size, 18);
        assert_eq!(handle.version.hash.len(), 64);
        assert!(!handle.version.file_id.is_empty());
        assert!(handle.version.mtime_ms > 0);

        std::fs::write(dir.path().join("bom.txt"), b"\xEF\xBB\xBFhi\r\n").unwrap();
        let bom = manager.open("bom.txt").unwrap();
        assert_eq!(bom.encoding, Encoding::Utf8Bom);
        assert_eq!(bom.newline, Newline::Crlf);

        std::fs::write(dir.path().join("bin"), [0u8, 159, 146, 150]).unwrap();
        assert_eq!(manager.open("bin").unwrap().encoding, Encoding::Binary);
    }

    #[test]
    fn an_external_edit_wins_and_the_managed_write_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path());
        let path = dir.path().join("a.txt");
        std::fs::write(&path, b"original\n").unwrap();
        let handle = manager.open("a.txt").unwrap();

        // A bash edit between open and write.
        std::fs::write(&path, b"edited by bash\n").unwrap();
        let err = manager.write(&handle, b"managed write\n").unwrap_err();
        assert_eq!(err.code(), ErrorCode::Stale);
        assert_eq!(std::fs::read(&path).unwrap(), b"edited by bash\n", "no corruption or overwrite");

        // Reopening and writing succeeds.
        let reopened = manager.open("a.txt").unwrap();
        manager.write(&reopened, b"managed write\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"managed write\n");
    }

    #[test]
    fn a_second_write_from_the_same_handle_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path());
        std::fs::write(dir.path().join("a.txt"), b"one").unwrap();
        let handle = manager.open("a.txt").unwrap();
        manager.write(&handle, b"two").unwrap();
        let err = manager.write(&handle, b"three").unwrap_err();
        assert_eq!(err.code(), ErrorCode::Stale);
        assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"two");
    }

    #[test]
    fn atomic_writes_preserve_bytes_mode_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path());

        // Encoding/newline matrix round-trips byte for byte.
        let cases: &[&[u8]] = &[
            b"plain\n",
            b"\xEF\xBB\xBFutf8 bom\r\n",
            &[0xFF, 0xFE, b'h', 0, b'i', 0],
            b"binary\x00\x01\x02",
            b"no newline at end",
        ];
        for (i, bytes) in cases.iter().enumerate() {
            let path = dir.path().join(format!("case-{i}"));
            manager.write_path(&path, bytes).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), *bytes, "case {i}");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let exec = dir.path().join("run.sh");
            std::fs::write(&exec, b"#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
            manager.write_path(&exec, b"#!/bin/sh\necho hi\n").unwrap();
            let mode = std::fs::metadata(&exec).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "mode preserved");

            let target = dir.path().join("target.txt");
            std::fs::write(&target, b"old").unwrap();
            let link = dir.path().join("link.txt");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            manager.write_path(&link, b"new").unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), b"new");
            assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        }

        #[cfg(windows)]
        {
            let readonly = dir.path().join("readonly.txt");
            std::fs::write(&readonly, b"old").unwrap();
            let mut permissions = std::fs::metadata(&readonly).unwrap().permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(&readonly, permissions).unwrap();
            let err = manager.write_path(&readonly, b"new").unwrap_err();
            assert_eq!(err.code(), ErrorCode::PermissionDenied);
            assert_eq!(std::fs::read(&readonly).unwrap(), b"old");
        }
    }

    #[test]
    fn the_watcher_reports_external_changes() {
        let dir = tempfile::tempdir().unwrap();
        let mut watcher = Watcher::new(dir.path());
        std::fs::write(dir.path().join("a.txt"), b"one").unwrap();
        watcher.prime().unwrap();
        assert!(watcher.poll().unwrap().is_empty());

        std::fs::write(dir.path().join("a.txt"), b"two").unwrap();
        std::fs::write(dir.path().join("new.txt"), b"new").unwrap();
        std::fs::remove_file(dir.path().join("new.txt")).unwrap();
        let changes = watcher.poll().unwrap();
        assert!(changes.iter().any(|c| c.path.ends_with("a.txt") && c.kind == ChangeKind::Modified));
    }

    #[test]
    fn delete_routes_to_trash_and_protected_paths_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path());
        let file = dir.path().join("old.txt");
        std::fs::write(&file, b"x").unwrap();
        let outcome = manager.delete("old.txt").unwrap();
        assert!(matches!(outcome, TrashOutcome::Trashed { .. }));
        assert!(!file.exists());

        let git = dir.path().join(".git");
        std::fs::create_dir_all(&git).unwrap();
        let outcome = manager.delete(".git").unwrap();
        assert!(matches!(outcome, TrashOutcome::Refused { .. }));
        assert!(git.exists());
    }
}
