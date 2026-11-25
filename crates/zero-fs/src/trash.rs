//! Native trash (DEL-06, DEL-07): Recycle Bin / `trashItemAtURL` / freedesktop.
//!
//! The trash crate delegates to the OS facility. Protected paths are refused
//! before any native call, and a native failure is typed with the original left
//! in place.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};
use zero_types::protected::{ProtectedPaths, Refusal};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrashOutcome {
    Trashed { path: PathBuf },
    Refused { path: PathBuf, reason: String, kind: String },
}

#[derive(Debug, Clone)]
pub struct TrashService {
    protected: ProtectedPaths,
}

impl TrashService {
    pub fn new(protected: ProtectedPaths) -> Self {
        Self { protected }
    }

    pub fn protected(&self) -> &ProtectedPaths {
        &self.protected
    }

    pub fn classify(&self, path: &Path) -> Option<Refusal> {
        self.protected.classify(path)
    }

    /// Move a path to the OS trash. Refused for protected paths.
    pub fn trash(&self, path: impl AsRef<Path>) -> Result<TrashOutcome> {
        let path = path.as_ref().to_path_buf();
        if let Some(refusal) = self.classify(&path) {
            return Ok(TrashOutcome::Refused {
                path,
                reason: refusal.reason,
                kind: format!("{:?}", refusal.kind),
            });
        }
        self.native_trash(&path)?;
        Ok(TrashOutcome::Trashed { path })
    }

    /// Zero-owned cleanup is the only exemption (DEL-09). The path must be inside
    /// `data_root`; anything else is refused.
    pub fn trash_zero_owned(&self, path: impl AsRef<Path>, data_root: &Path) -> Result<TrashOutcome> {
        let path = path.as_ref().to_path_buf();
        let root = std::fs::canonicalize(data_root).unwrap_or_else(|_| data_root.to_path_buf());
        let canonical = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if !canonical.starts_with(&root) || canonical == root {
            return Err(ZeroError::new(
                ErrorCode::RetentionScope,
                format!("{} is outside the Zero data root {}", path.display(), root.display()),
            ));
        }
        self.native_trash(&path)?;
        Ok(TrashOutcome::Trashed { path })
    }

    fn native_trash(&self, path: &Path) -> Result<()> {
        if !path.exists() && std::fs::symlink_metadata(path).is_err() {
            return Err(ZeroError::new(ErrorCode::NotFound, format!("{} does not exist", path.display())));
        }
        // A read-only file can still be trashed once the read-only bit is
        // cleared. On Unix the directory permission governs the rename.
        #[allow(clippy::permissions_set_readonly_false)]
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            let mut permissions = metadata.permissions();
            if permissions.readonly() {
                permissions.set_readonly(false);
                let _ = std::fs::set_permissions(path, permissions);
            }
        }
        // Long Windows paths need the extended prefix for the shell API.
        let target = long_path(path);
        trash::delete(&target).map_err(|e| {
            ZeroError::new(
                ErrorCode::TrashFailed,
                format!("could not move {} to the trash: {e}; the original was left in place", path.display()),
            )
        })
    }
}

#[cfg(windows)]
fn long_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text.len() >= 240 && !text.starts_with(r"\\?\") {
        PathBuf::from(format!(r"\\?\{}", text.replace('/', "\\")))
    } else {
        path.to_path_buf()
    }
}

#[cfg(not(windows))]
fn long_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_types::paths::Platform;

    fn service(home: &Path) -> TrashService {
        let data = home.join(".zero-data");
        let config = home.join(".zero-config");
        TrashService::new(ProtectedPaths::new(
            home,
            data,
            config,
            if cfg!(windows) { Platform::Windows } else { Platform::Linux },
        ))
    }

    #[test]
    fn a_project_file_goes_to_the_native_trash() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let file = dir.path().join("old.txt");
        std::fs::write(&file, b"content").unwrap();
        let outcome = service.trash(&file).unwrap();
        assert!(matches!(outcome, TrashOutcome::Trashed { .. }), "{outcome:?}");
        assert!(!file.exists());
    }

    #[test]
    fn protected_paths_are_refused_with_a_reason_and_remain() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let home = dir.path().to_path_buf();
        let outcome = service.trash(&home).unwrap();
        match outcome {
            TrashOutcome::Refused { reason, .. } => assert!(reason.contains("home")),
            other => panic!("{other:?}"),
        }
        assert!(home.exists());

        let git = dir.path().join("repo").join(".git");
        std::fs::create_dir_all(&git).unwrap();
        let outcome = service.trash(&git).unwrap();
        assert!(matches!(outcome, TrashOutcome::Refused { .. }));
        assert!(git.exists());
    }

    #[test]
    fn a_read_only_file_is_still_trashed() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let file = dir.path().join("readonly.txt");
        std::fs::write(&file, b"x").unwrap();
        let mut permissions = std::fs::metadata(&file).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&file, permissions).unwrap();

        let outcome = service.trash(&file).unwrap();
        assert!(matches!(outcome, TrashOutcome::Trashed { .. }), "{outcome:?}");
        assert!(!file.exists());
    }

    #[test]
    fn a_long_path_has_a_defined_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let mut path = dir.path().to_path_buf();
        for i in 0..12 {
            path.push(format!("directory-with-a-fairly-long-name-{i}"));
        }
        std::fs::create_dir_all(&path).unwrap();
        let file = path.join("deep.txt");
        std::fs::write(&file, b"deep").unwrap();
        match service.trash(&file) {
            Ok(TrashOutcome::Trashed { .. }) => assert!(!file.exists()),
            Ok(other) => panic!("unexpected refusal: {other:?}"),
            Err(e) => {
                assert_eq!(e.code(), ErrorCode::TrashFailed);
                assert!(file.exists(), "on failure the original stays in place");
            }
        }
    }

    #[test]
    fn an_open_file_has_a_defined_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let file = dir.path().join("open.txt");
        std::fs::write(&file, b"held").unwrap();
        let handle = std::fs::File::open(&file).unwrap();
        match service.trash(&file) {
            Ok(TrashOutcome::Trashed { .. }) => assert!(!file.exists()),
            Ok(other) => panic!("unexpected: {other:?}"),
            Err(e) => {
                assert_eq!(e.code(), ErrorCode::TrashFailed);
                assert!(file.exists(), "a failed trash leaves the original");
            }
        }
        drop(handle);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_trashed_without_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let target = dir.path().join("target.txt");
        std::fs::write(&target, b"keep").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        match service.trash(&link) {
            Ok(TrashOutcome::Trashed { .. }) => {
                assert!(!link.exists());
                assert!(target.exists(), "the target is untouched");
            }
            Err(e) => {
                assert_eq!(e.code(), ErrorCode::TrashFailed);
                assert!(target.exists());
            }
            Ok(other) => panic!("unexpected: {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_cross_device_file_has_a_defined_outcome() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        // A writable tmpfs that is not a protected system directory. /dev/shm is
        // refused by the guard (it is a system directory), which is correct; use
        // the runtime directory when it is a separate filesystem.
        let Some(base) = ["/run/user/1000"].iter().map(std::path::Path::new).find(|p| p.exists()) else {
            println!("skipped: no separate writable filesystem available");
            return;
        };
        let other = base.join(format!("zero-trash-{}", std::process::id()));
        std::fs::write(&other, b"cross").unwrap();
        if std::fs::metadata(dir.path()).unwrap().dev() == std::fs::metadata(&other).unwrap().dev() {
            let _ = std::fs::remove_file(&other);
            println!("skipped: the runtime directory is on the same device");
            return;
        }
        match service.trash(&other) {
            Ok(TrashOutcome::Trashed { .. }) => assert!(!other.exists()),
            Err(e) => {
                assert_eq!(e.code(), ErrorCode::TrashFailed);
                assert!(other.exists());
                let _ = std::fs::remove_file(&other);
            }
            Ok(extra) => panic!("unexpected: {extra:?}"),
        }
    }

    #[test]
    fn zero_owned_cleanup_is_limited_to_the_data_root() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let data_root = dir.path().join(".zero-data");
        std::fs::create_dir_all(data_root.join("cache")).unwrap();
        let inside = data_root.join("cache").join("expired.bin");
        std::fs::write(&inside, b"x").unwrap();
        let outside = dir.path().join("outside.bin");
        std::fs::write(&outside, b"keep").unwrap();

        let err = service.trash_zero_owned(&outside, &data_root).unwrap_err();
        assert_eq!(err.code(), ErrorCode::RetentionScope);
        assert!(outside.exists());

        let outcome = service.trash_zero_owned(&inside, &data_root).unwrap();
        assert!(matches!(outcome, TrashOutcome::Trashed { .. }));
        assert!(!inside.exists());
    }
}
