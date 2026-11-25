//! Zero-owned retention (DEL-09, OBS-03): garbage collection is limited to the
//! Zero data root under a retention policy, moves expired data to the trash, and
//! reports everything it touched. Anything outside the root is never examined.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::trash::{TrashOutcome, TrashService};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Files older than this are eligible.
    pub max_age_ms: i64,
    /// Report only; do not trash.
    pub dry_run: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self { max_age_ms: 30 * 24 * 60 * 60 * 1000, dry_run: false }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionReport {
    pub examined: u64,
    pub trashed: Vec<PathBuf>,
    pub would_trash: Vec<PathBuf>,
    pub skipped: Vec<(PathBuf, String)>,
    pub bytes: u64,
}

pub struct Retention {
    data_root: PathBuf,
    policy: RetentionPolicy,
}

impl Retention {
    pub fn new(data_root: impl AsRef<Path>, policy: RetentionPolicy) -> Result<Self> {
        let data_root = data_root.as_ref().to_path_buf();
        std::fs::create_dir_all(&data_root)?;
        Ok(Self { data_root, policy })
    }

    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    pub fn run(&self, now_ms: i64, trash: &TrashService) -> Result<RetentionReport> {
        let root = std::fs::canonicalize(&self.data_root)?;
        let mut report = RetentionReport::default();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path)?;
                if meta.file_type().is_symlink() {
                    report.skipped.push((path, "symlink not followed".into()));
                    continue;
                }
                if meta.is_dir() {
                    stack.push(path);
                    continue;
                }
                report.examined += 1;
                let canonical = match std::fs::canonicalize(&path) {
                    Ok(p) => p,
                    Err(_) => {
                        report.skipped.push((path, "unresolvable path".into()));
                        continue;
                    }
                };
                if !canonical.starts_with(&root) {
                    report.skipped.push((path, "outside the data root".into()));
                    continue;
                }
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(now_ms);
                if now_ms - modified < self.policy.max_age_ms {
                    continue;
                }
                if self.policy.dry_run {
                    report.would_trash.push(path);
                    continue;
                }
                match trash.trash_zero_owned(&path, &self.data_root) {
                    Ok(TrashOutcome::Trashed { .. }) => {
                        report.bytes += meta.len();
                        report.trashed.push(path);
                    }
                    Ok(TrashOutcome::Refused { reason, .. }) => report.skipped.push((path, reason)),
                    Err(e) if e.code() == ErrorCode::TrashFailed => report.skipped.push((path, e.message().to_string())),
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(report)
    }
}

/// Test and CLI helper: set a file's modification time.
pub fn set_age(path: &Path, age: Duration) -> Result<()> {
    let when = SystemTime::now()
        .checked_sub(age)
        .ok_or_else(|| ZeroError::new(ErrorCode::InvalidInput, "age is too large"))?;
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.set_times(std::fs::FileTimes::new().set_modified(when))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_types::paths::Platform;
    use zero_types::protected::ProtectedPaths;

    fn trash_for(home: &Path) -> TrashService {
        TrashService::new(ProtectedPaths::new(
            home,
            home.join("zero-data"),
            home.join("zero-config"),
            if cfg!(windows) { Platform::Windows } else { Platform::Linux },
        ))
    }

    #[test]
    fn gc_deletes_nothing_outside_the_data_root_and_trashes_expired_data() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let data_root = home.join("zero-data");
        std::fs::create_dir_all(data_root.join("cache")).unwrap();
        std::fs::create_dir_all(data_root.join("keep")).unwrap();

        let old = data_root.join("cache").join("expired.bin");
        let new = data_root.join("keep").join("fresh.bin");
        let outside = home.join("important.txt");
        std::fs::write(&old, b"old").unwrap();
        std::fs::write(&new, b"new").unwrap();
        std::fs::write(&outside, b"untouched").unwrap();
        set_age(&old, Duration::from_millis(48 * 60 * 60 * 1000)).unwrap();

        let retention = Retention::new(&data_root, RetentionPolicy { max_age_ms: 24 * 60 * 60 * 1000, dry_run: false }).unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        let report = retention.run(now, &trash_for(home)).unwrap();

        assert_eq!(report.trashed.len(), 1, "{report:?}");
        assert!(report.trashed[0].ends_with("expired.bin"));
        assert!(!old.exists());
        assert!(new.exists(), "fresh files are kept");
        assert!(outside.exists(), "nothing outside the data root is touched");
        assert_eq!(report.examined, 2);

        // The outside file was never even examined.
        assert!(!report.skipped.iter().any(|(p, _)| p == &outside));
    }

    #[test]
    fn dry_run_reports_without_trashing() {
        let dir = tempfile::tempdir().unwrap();
        let data_root = dir.path().join("zero-data");
        std::fs::create_dir_all(&data_root).unwrap();
        let file = data_root.join("old.log");
        std::fs::write(&file, b"x").unwrap();
        set_age(&file, Duration::from_millis(10_000)).unwrap();

        let retention = Retention::new(&data_root, RetentionPolicy { max_age_ms: 1_000, dry_run: true }).unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        let report = retention.run(now, &trash_for(dir.path())).unwrap();
        assert_eq!(report.would_trash.len(), 1, "{report:?}");
        assert!(report.would_trash[0].ends_with("old.log"));
        assert!(file.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_inside_the_data_root_never_reaches_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let data_root = dir.path().join("zero-data");
        std::fs::create_dir_all(&data_root).unwrap();
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, b"keep").unwrap();
        let link = data_root.join("escape");
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let retention = Retention::new(&data_root, RetentionPolicy { max_age_ms: 0, dry_run: false }).unwrap();
        let report = retention.run(10_000, &trash_for(dir.path())).unwrap();
        assert!(outside.exists());
        assert!(report.trashed.is_empty());
        assert!(report.skipped.iter().any(|(p, reason)| p == &link && reason.contains("symlink")));
    }
}
