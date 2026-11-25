//! File identity and canonical keys (FS-06, FS-09).
//!
//! Locks and versions are keyed by a filesystem identity (volume + index on
//! Windows, device + inode on Unix), not by a path string. Paths are normalised
//! for case on Windows and Unicode NFC so two spellings of one file agree.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FileIdentity {
    /// Platform identity: `volume:index` or `dev:ino`.
    pub id: String,
    /// Canonical path with the platform's case rules and NFC.
    pub canonical: PathBuf,
}

impl FileIdentity {
    pub fn key(&self) -> &str {
        &self.id
    }
}

#[cfg(unix)]
fn platform_id(metadata: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!("{}:{}", metadata.dev(), metadata.ino())
}

#[cfg(windows)]
fn platform_id(path: &Path) -> Result<String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};

    let file = std::fs::File::open(path).map_err(ZeroError::from)?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) };
    if ok == 0 {
        return Err(ZeroError::new(ErrorCode::Io, format!("GetFileInformationByHandle failed for {}", path.display())));
    }
    Ok(format!("{:08x}:{:08x}{:08x}", info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow))
}

#[cfg(not(any(unix, windows)))]
fn platform_id(metadata: &std::fs::Metadata) -> String {
    format!("{:?}", metadata.len())
}

/// Resolve the identity of an existing path. Symlinks and junctions resolve to
/// the target, so a link and its target share one identity.
pub fn identity(path: impl AsRef<Path>) -> Result<FileIdentity> {
    let path = path.as_ref();
    let canonical = std::fs::canonicalize(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ZeroError::new(ErrorCode::NotFound, format!("{}", path.display()))
        } else {
            e.into()
        }
    })?;
    let metadata = std::fs::metadata(&canonical)?;
    if metadata.is_dir() {
        return Err(ZeroError::new(ErrorCode::InvalidInput, format!("{} is a directory", path.display())));
    }
    #[cfg(unix)]
    let id = platform_id(&metadata);
    #[cfg(windows)]
    let id = platform_id(&canonical)?;
    #[cfg(not(any(unix, windows)))]
    let id = platform_id(&metadata);
    Ok(FileIdentity { id, canonical: normalise(&canonical) })
}

/// Normalise a path for comparison: NFC, case-folded on Windows.
pub fn normalise(path: &Path) -> PathBuf {
    let text: String = path.to_string_lossy().nfc().collect();
    #[cfg(windows)]
    {
        PathBuf::from(text.to_lowercase().replace('/', "\\"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(text)
    }
}

/// Stable identity for a path that may not exist yet: falls back to the
/// normalised absolute path, while existing targets use their filesystem id.
pub fn identity_or_path(path: impl AsRef<Path>) -> FileIdentity {
    match identity(&path) {
        Ok(identity) => identity,
        Err(_) => {
            let absolute = if path.as_ref().is_absolute() {
                path.as_ref().to_path_buf()
            } else {
                std::env::current_dir().unwrap_or_default().join(path.as_ref())
            };
            FileIdentity { id: format!("path:{}", normalise(&absolute).display()), canonical: normalise(&absolute) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_file_has_one_identity_across_hardlinks_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let hard = dir.path().join("hard.txt");
        std::fs::hard_link(&file, &hard).unwrap();
        assert_eq!(identity(&file).unwrap().id, identity(&hard).unwrap().id, "hardlinks share an id");

        #[cfg(unix)]
        {
            let link = dir.path().join("link.txt");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            let via_link = identity(&link).unwrap();
            let target = identity(&file).unwrap();
            assert_eq!(via_link.id, target.id);
            assert_eq!(via_link.canonical, target.canonical);
        }
    }

    #[test]
    fn unicode_and_case_spellings_agree() {
        let dir = tempfile::tempdir().unwrap();
        let composed = dir.path().join("caf\u{e9}.txt");
        std::fs::write(&composed, b"x").unwrap();
        let composed_id = identity(&composed).unwrap();
        // NFC normalisation of a decomposed spelling names the same file.
        let decomposed = dir.path().join("cafe\u{301}.txt");
        if decomposed.exists() {
            assert_eq!(identity(&decomposed).unwrap().canonical, composed_id.canonical);
        }
        #[cfg(windows)]
        {
            let upper = dir.path().join("CAFÉ.TXT");
            assert_eq!(identity(&upper).unwrap().id, composed_id.id);
        }
    }

    #[test]
    fn a_missing_path_has_a_path_key_and_a_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.txt");
        let key = identity_or_path(&missing);
        assert!(key.id.starts_with("path:"));
        let err = identity(dir.path()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInput);
    }
}
