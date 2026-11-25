//! Retention (OBS-03, OBS-06): documented, per-class retention under the Zero
//! data root, with every expired item moved to the OS trash.
//!
//! The sweep only examines the configured class subdirectories of one root. It
//! never follows a symlink and never deletes an item permanently: an expired
//! item is recoverable from the Recycle Bin, the macOS Trash, or the freedesktop
//! trash. A trash failure is reported and the original is left in place; one bad
//! item never stops the rest of the sweep.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zero_types::error::{ErrorCode, Result, ZeroError};
use zero_types::protected::ProtectedKind;

use crate::trash::{TrashOutcome, TrashService};

/// Milliseconds in one day, used to turn `max_age_days` into an age bound.
pub const DAY_MS: i64 = 86_400_000;
/// Largest accepted `max_age_days` (ten years).
pub const MAX_AGE_DAYS_LIMIT: u32 = 3650;
/// Largest accepted `keep_min`.
pub const KEEP_MIN_LIMIT: usize = 10_000;

/// A category of local observability or session data with its own policy.
///
/// Each class owns one directory directly under the retention root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    Traces,
    Metrics,
    Logs,
    Audits,
    Sessions,
    Artifacts,
    TeleportStaging,
}

impl RetentionClass {
    /// Every class, in declaration order.
    pub const ALL: [RetentionClass; 7] = [
        RetentionClass::Traces,
        RetentionClass::Metrics,
        RetentionClass::Logs,
        RetentionClass::Audits,
        RetentionClass::Sessions,
        RetentionClass::Artifacts,
        RetentionClass::TeleportStaging,
    ];

    /// The class directory name under the retention root.
    pub const fn directory(self) -> &'static str {
        match self {
            RetentionClass::Traces => "traces",
            RetentionClass::Metrics => "metrics",
            RetentionClass::Logs => "logs",
            RetentionClass::Audits => "audits",
            RetentionClass::Sessions => "sessions",
            RetentionClass::Artifacts => "artifacts",
            RetentionClass::TeleportStaging => "teleport-staging",
        }
    }

    /// The documented default policy for this class.
    pub const fn default_policy(self) -> RetentionPolicy {
        match self {
            RetentionClass::Traces => RetentionPolicy::new(30, Some(256 * 1024 * 1024), 20),
            RetentionClass::Metrics => RetentionPolicy::new(90, Some(64 * 1024 * 1024), 1440),
            RetentionClass::Logs => RetentionPolicy::new(14, Some(128 * 1024 * 1024), 100),
            RetentionClass::Audits => RetentionPolicy::new(365, Some(512 * 1024 * 1024), 1000),
            RetentionClass::Sessions => RetentionPolicy::new(90, Some(512 * 1024 * 1024), 20),
            RetentionClass::Artifacts => RetentionPolicy::new(30, Some(1024 * 1024 * 1024), 10),
            RetentionClass::TeleportStaging => RetentionPolicy::new(7, Some(256 * 1024 * 1024), 0),
        }
    }
}

impl fmt::Display for RetentionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.directory())
    }
}

/// Retention for one class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Items older than this many days are eligible for expiry. `1..=3650`.
    pub max_age_days: u32,
    /// Optional class byte quota. `None` means age and `keep_min` only.
    pub max_bytes: Option<u64>,
    /// Newest items that are always kept, whatever their age or size.
    pub keep_min: usize,
}

impl RetentionPolicy {
    pub const fn new(max_age_days: u32, max_bytes: Option<u64>, keep_min: usize) -> Self {
        Self { max_age_days, max_bytes, keep_min }
    }

    /// Reject an age outside `1..=3650` days or a `keep_min` above 10,000.
    pub fn validate(&self) -> Result<()> {
        if self.max_age_days == 0 || self.max_age_days > MAX_AGE_DAYS_LIMIT {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!("max_age_days {} must be between 1 and {MAX_AGE_DAYS_LIMIT}", self.max_age_days),
            ));
        }
        if self.keep_min > KEEP_MIN_LIMIT {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!("keep_min {} must not exceed {KEEP_MIN_LIMIT}", self.keep_min),
            ));
        }
        Ok(())
    }
}

/// A complete retention plan: one policy per class, plus the run mode.
///
/// `RetentionPlan::default()` is a **dry run** over every class. A destructive
/// run must be requested explicitly with `with_defaults(false)` or by setting
/// `dry_run` to `false`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPlan {
    pub classes: BTreeMap<RetentionClass, RetentionPolicy>,
    pub dry_run: bool,
}

impl Default for RetentionPlan {
    fn default() -> Self {
        Self::with_defaults(true)
    }
}

impl RetentionPlan {
    /// An empty plan for the given mode.
    pub fn new(dry_run: bool) -> Self {
        Self { classes: BTreeMap::new(), dry_run }
    }

    /// A plan covering every class with its documented default policy.
    pub fn with_defaults(dry_run: bool) -> Self {
        let mut classes = BTreeMap::new();
        for class in RetentionClass::ALL {
            classes.insert(class, class.default_policy());
        }
        Self { classes, dry_run }
    }

    /// Add or replace one class policy.
    pub fn set(&mut self, class: RetentionClass, policy: RetentionPolicy) {
        self.classes.insert(class, policy);
    }

    /// Builder form of [`RetentionPlan::set`].
    pub fn with_class(mut self, class: RetentionClass, policy: RetentionPolicy) -> Self {
        self.set(class, policy);
        self
    }

    /// Validate every policy in the plan.
    pub fn validate(&self) -> Result<()> {
        for (class, policy) in &self.classes {
            policy.validate().map_err(|e| {
                ZeroError::new(e.code(), format!("{}: {}", class.directory(), e.message()))
            })?;
        }
        Ok(())
    }
}

/// Why an item was selected for removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionReason {
    /// The item's modification time is past `max_age_days`.
    Expired,
    /// The class was over `max_bytes` after expiry.
    OverQuota,
}

impl RetentionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            RetentionReason::Expired => "expired",
            RetentionReason::OverQuota => "over_quota",
        }
    }
}

impl fmt::Display for RetentionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One item selected (or moved) to the trash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrashedItem {
    pub class: RetentionClass,
    pub path: PathBuf,
    pub reason: RetentionReason,
}

/// A non-fatal problem: a refused path, an unreadable directory, or a failed
/// trash. The item stays in place and the sweep continues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionError {
    pub class: RetentionClass,
    pub path: PathBuf,
    pub message: String,
}

/// What one sweep did. In a dry run `trashed` lists what *would* be moved,
/// `bytes_freed` is `0`, and nothing on disk changes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionReport {
    pub trashed: Vec<TrashedItem>,
    pub kept: usize,
    pub bytes_freed: u64,
    pub errors: Vec<RetentionError>,
    pub dry_run: bool,
}

#[derive(Debug)]
struct Item {
    path: PathBuf,
    size: u64,
    modified_ms: i64,
    /// A protected-path reason. Such an item is never selected.
    protected: Option<String>,
}

/// Apply `plan` under `root`.
///
/// `root` must exist. Class directories that do not exist are skipped; a class
/// directory that is a symlink, is not a directory, or resolves outside `root`
/// is reported as an error and skipped. Every removal goes through the
/// [`TrashService`]. `now_ms` is the caller's wall clock.
pub fn sweep(
    root: impl AsRef<Path>,
    plan: &RetentionPlan,
    trash: &TrashService,
    now_ms: i64,
) -> Result<RetentionReport> {
    plan.validate()?;
    let root = root.as_ref();
    let canonical_root = std::fs::canonicalize(root).map_err(|e| {
        ZeroError::new(
            ErrorCode::NotFound,
            format!("retention root {} cannot be resolved: {e}", root.display()),
        )
    })?;

    // A root that is the home directory, a filesystem root, or a system
    // directory is a configuration mistake, not a retention scope.
    if let Some(refusal) = trash.classify(&canonical_root) {
        if !is_zero_owned_kind(refusal.kind) {
            return Err(ZeroError::new(
                ErrorCode::ProtectedPath,
                format!("retention root {} is protected: {}", root.display(), refusal.reason),
            ));
        }
    }

    let mut report = RetentionReport { dry_run: plan.dry_run, ..RetentionReport::default() };
    for (class, policy) in &plan.classes {
        let class_dir = canonical_root.join(class.directory());
        match std::fs::symlink_metadata(&class_dir) {
            Ok(meta) if meta.file_type().is_symlink() => {
                report.errors.push(RetentionError {
                    class: *class,
                    path: class_dir,
                    message: "the class directory is a symlink and is not followed".into(),
                });
                continue;
            }
            Ok(meta) if !meta.is_dir() => {
                report.errors.push(RetentionError {
                    class: *class,
                    path: class_dir,
                    message: "the class path is not a directory".into(),
                });
                continue;
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                report.errors.push(RetentionError {
                    class: *class,
                    path: class_dir,
                    message: format!("cannot inspect the class directory: {e}"),
                });
                continue;
            }
        }

        let canonical_class = match std::fs::canonicalize(&class_dir) {
            Ok(path) => path,
            Err(e) => {
                report.errors.push(RetentionError {
                    class: *class,
                    path: class_dir,
                    message: format!("cannot resolve the class directory: {e}"),
                });
                continue;
            }
        };
        if canonical_class == canonical_root || !canonical_class.starts_with(&canonical_root) {
            report.errors.push(RetentionError {
                class: *class,
                path: class_dir,
                message: "the class directory resolves outside the retention root".into(),
            });
            continue;
        }

        let items = collect_items(*class, &canonical_class, trash, now_ms, &mut report);
        apply_class(*class, policy, items, trash, &canonical_root, now_ms, &mut report);
    }
    Ok(report)
}

/// Set a file's modification time to `age` before now. Test and operator helper.
pub fn set_age(path: &Path, age: Duration) -> Result<()> {
    let when = SystemTime::now()
        .checked_sub(age)
        .ok_or_else(|| ZeroError::new(ErrorCode::InvalidInput, "age is too large"))?;
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.set_times(std::fs::FileTimes::new().set_modified(when))?;
    Ok(())
}

fn collect_items(
    class: RetentionClass,
    dir: &Path,
    trash: &TrashService,
    now_ms: i64,
    report: &mut RetentionReport,
) -> Vec<Item> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            report.errors.push(RetentionError {
                class,
                path: dir.to_path_buf(),
                message: format!("cannot read the class directory: {e}"),
            });
            return Vec::new();
        }
    };

    let mut items = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                report.errors.push(RetentionError {
                    class,
                    path: dir.to_path_buf(),
                    message: format!("cannot read a directory entry: {e}"),
                });
                continue;
            }
        };
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) => {
                report.errors.push(RetentionError {
                    class,
                    path,
                    message: format!("cannot inspect the item: {e}"),
                });
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            report.errors.push(RetentionError {
                class,
                path,
                message: "a symlink is never followed or trashed".into(),
            });
            continue;
        }
        let protected = retention_protection(trash, &path);
        let modified_ms = meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|age| age.as_millis() as i64)
            .unwrap_or(now_ms);
        items.push(Item { size: item_size(&path), path, modified_ms, protected });
    }
    items
}

fn apply_class(
    class: RetentionClass,
    policy: &RetentionPolicy,
    mut items: Vec<Item>,
    trash: &TrashService,
    root: &Path,
    now_ms: i64,
    report: &mut RetentionReport,
) {
    // Oldest first, with the path as a deterministic tie-break.
    items.sort_by(|a, b| a.modified_ms.cmp(&b.modified_ms).then_with(|| a.path.cmp(&b.path)));
    let total = items.len();
    if total == 0 {
        return;
    }

    let floor = policy.keep_min.min(total);
    let floor_start = total - floor;
    let age_limit = i64::from(policy.max_age_days) * DAY_MS;
    let mut removed = vec![false; total];
    let mut blocked = vec![false; total];

    // Age pass: the newest `keep_min` items are outside the eligible range.
    for idx in 0..floor_start {
        let item = &items[idx];
        if now_ms.saturating_sub(item.modified_ms) <= age_limit {
            continue;
        }
        if let Some(reason) = &item.protected {
            report.errors.push(RetentionError {
                class,
                path: item.path.clone(),
                message: format!("protected path kept: {reason}"),
            });
            continue;
        }
        if remove_item(class, item, RetentionReason::Expired, trash, root, report) {
            removed[idx] = true;
        } else {
            blocked[idx] = true;
        }
    }

    // Quota pass: trim the oldest remaining items above `keep_min` until the
    // class fits. Protected items are not candidates but still count as bytes.
    if let Some(max_bytes) = policy.max_bytes {
        let mut remaining_bytes: u64 = items
            .iter()
            .enumerate()
            .filter(|(idx, _)| !removed[*idx])
            .map(|(_, item)| item.size)
            .sum();
        while remaining_bytes > max_bytes {
            let remaining_count = removed.iter().filter(|gone| !**gone).count();
            if remaining_count <= floor {
                break;
            }
            let candidate = (0..floor_start)
                .find(|idx| !removed[*idx] && !blocked[*idx] && items[*idx].protected.is_none());
            let Some(idx) = candidate else {
                break;
            };
            let item = &items[idx];
            if remove_item(class, item, RetentionReason::OverQuota, trash, root, report) {
                removed[idx] = true;
                remaining_bytes = remaining_bytes.saturating_sub(item.size);
            } else {
                blocked[idx] = true;
            }
        }
    }

    report.kept += removed.iter().filter(|gone| !**gone).count();
}

fn remove_item(
    class: RetentionClass,
    item: &Item,
    reason: RetentionReason,
    trash: &TrashService,
    root: &Path,
    report: &mut RetentionReport,
) -> bool {
    if report.dry_run {
        report.trashed.push(TrashedItem { class, path: item.path.clone(), reason });
        return true;
    }
    match move_to_trash(&item.path, root, trash) {
        Ok(TrashOutcome::Trashed { .. }) => {
            report.trashed.push(TrashedItem { class, path: item.path.clone(), reason });
            report.bytes_freed = report.bytes_freed.saturating_add(item.size);
            true
        }
        Ok(TrashOutcome::Refused { path, reason: why, .. }) => {
            report.errors.push(RetentionError {
                class,
                path,
                message: format!("trash refused: {why}"),
            });
            false
        }
        Err(e) => {
            report.errors.push(RetentionError {
                class,
                path: item.path.clone(),
                message: format!("trash failed: {}", e.message()),
            });
            false
        }
    }
}

/// Call [`TrashService::trash`] for every removal.
///
/// Zero's own data root is protected from agent deletion, so `trash` refuses
/// anything under it with a `ZeroDirectory` refusal. Retention is the documented
/// DEL-09 exemption; only that blanket refusal is retried through
/// `trash_zero_owned`. Name-based protection (journals, credentials, policy
/// files, `.git`, `.zero`) is never retried.
fn move_to_trash(path: &Path, root: &Path, trash: &TrashService) -> Result<TrashOutcome> {
    let zero_owned = matches!(trash.classify(path), Some(refusal) if is_zero_owned_kind(refusal.kind));
    match trash.trash(path)? {
        TrashOutcome::Refused { .. } if zero_owned => trash.trash_zero_owned(path, root),
        other => Ok(other),
    }
}

fn is_zero_owned_kind(kind: ProtectedKind) -> bool {
    // `ZeroDirectory` also covers a literal `.zero` component; the structural
    // check in `retention_protection` keeps that path protected.
    matches!(kind, ProtectedKind::ZeroDirectory | ProtectedKind::AuditLog)
}

/// A retention-level protection check.
///
/// The blanket Zero-owned data refusal is exempt (it is the retention scope
/// itself), but structural protections survive: a `.git` or `.zero` component,
/// a journal, a credential store, and a policy or trust file are never touched.
fn retention_protection(trash: &TrashService, path: &Path) -> Option<String> {
    let refusal = trash.classify(path)?;
    if is_zero_owned_kind(refusal.kind) && !is_structurally_protected(path) {
        return None;
    }
    Some(refusal.reason)
}

fn is_structurally_protected(path: &Path) -> bool {
    for component in path.components() {
        if let Component::Normal(part) = component {
            let lower = part.to_string_lossy().to_ascii_lowercase();
            if lower == ".git" || lower == ".zero" {
                return true;
            }
        }
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    name == "policy.toml"
        || name == "trust.json"
        || name == ".halcyon-mode"
        || name == "auth.json"
        || name.contains("credentials")
        || name.ends_with(".journal")
}

/// Best-effort recursive size. Symlinks are measured, never followed; an
/// unreadable subtree contributes what could be read.
fn item_size(path: &Path) -> u64 {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            let mut total = 0u64;
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    total = total.saturating_add(item_size(&entry.path()));
                }
            }
            total
        }
        Ok(meta) => meta.len(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    use std::ffi::OsString;
    use zero_types::paths::Platform;
    use zero_types::protected::ProtectedPaths;

    const MIB: u64 = 1024 * 1024;

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
        root: PathBuf,
        trash: TrashService,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().to_path_buf();
            std::fs::create_dir_all(home.join("zero-data")).unwrap();
            // The sweep reports resolved paths; build fixture paths the same way.
            let root = std::fs::canonicalize(home.join("zero-data")).unwrap();
            let platform = if cfg!(windows) { Platform::Windows } else { Platform::Linux };
            let trash = TrashService::new(ProtectedPaths::new(
                home.clone(),
                root.clone(),
                home.join("zero-config"),
                platform,
            ));
            Self { _dir: dir, home, root, trash }
        }

        fn class_dir(&self, class: RetentionClass) -> PathBuf {
            self.root.join(class.directory())
        }

        fn write(&self, class: RetentionClass, name: &str, bytes: &[u8], age_days: u64) -> PathBuf {
            let dir = self.class_dir(class);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            if age_days > 0 {
                set_age(&path, Duration::from_secs(age_days * 24 * 60 * 60)).unwrap();
            }
            path
        }

        fn sweep(&self, plan: &RetentionPlan) -> RetentionReport {
            sweep(&self.root, plan, &self.trash, now_ms()).unwrap()
        }
    }

    fn now_ms() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
    }

    fn plan(
        class: RetentionClass,
        max_age_days: u32,
        max_bytes: Option<u64>,
        keep_min: usize,
        dry_run: bool,
    ) -> RetentionPlan {
        RetentionPlan::new(dry_run)
            .with_class(class, RetentionPolicy::new(max_age_days, max_bytes, keep_min))
    }

    fn unique(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{prefix}-{}-{nanos}.log", std::process::id())
    }

    #[cfg(any(target_os = "windows", target_os = "linux"))]
    fn trash_ids() -> Option<Vec<OsString>> {
        trash::os_limited::list()
            .ok()
            .map(|items| items.into_iter().map(|item| item.id).collect())
    }

    #[test]
    fn an_expired_item_is_trashed_and_recoverable_not_deleted() {
        let fixture = Fixture::new();
        let name = unique("expired");
        let file = fixture.write(RetentionClass::Logs, &name, b"expired bytes", 10);

        #[cfg(any(target_os = "windows", target_os = "linux"))]
        let before = trash_ids();

        let report = fixture.sweep(&plan(RetentionClass::Logs, 1, None, 0, false));

        assert_eq!(report.trashed.len(), 1, "{report:?}");
        assert_eq!(report.trashed[0].class, RetentionClass::Logs);
        assert_eq!(report.trashed[0].reason, RetentionReason::Expired);
        assert_eq!(report.trashed[0].path, file);
        assert!(!file.exists(), "the item left the data root");
        assert!(report.errors.is_empty(), "{report:?}");

        // The Done criterion: the item is in the OS trash, not permanently
        // deleted. `list` is available on Windows and freedesktop Linux.
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        if let (Some(before), Ok(after)) = (before, trash::os_limited::list()) {
            let added: Vec<_> = after
                .into_iter()
                .filter(|item| !before.contains(&item.id))
                .collect();
            let ours: Vec<_> = added
                .into_iter()
                .filter(|item| item.name == OsString::from(&name))
                .collect();
            assert!(!ours.is_empty(), "the item is recoverable from the trash");
            let _ = trash::os_limited::purge_all(ours);
        }
    }

    #[test]
    fn a_fresh_item_is_kept() {
        let fixture = Fixture::new();
        let file = fixture.write(RetentionClass::Traces, "fresh.jsonl", b"fresh", 0);

        let report = fixture.sweep(&plan(RetentionClass::Traces, 1, None, 0, false));

        assert!(report.trashed.is_empty(), "{report:?}");
        assert_eq!(report.kept, 1);
        assert!(file.exists());
    }

    #[test]
    fn keep_min_protects_the_newest_items() {
        let fixture = Fixture::new();
        let oldest = fixture.write(RetentionClass::Logs, "oldest.log", b"1", 30);
        let middle = fixture.write(RetentionClass::Logs, "middle.log", b"2", 20);
        let newest = fixture.write(RetentionClass::Logs, "newest.log", b"3", 10);

        let report = fixture.sweep(&plan(RetentionClass::Logs, 1, None, 2, false));

        assert_eq!(report.trashed.len(), 1, "{report:?}");
        assert_eq!(report.trashed[0].path, oldest);
        assert!(!oldest.exists());
        assert!(middle.exists(), "the newest two are kept");
        assert!(newest.exists(), "the newest two are kept");
        assert_eq!(report.kept, 2);
    }

    #[test]
    fn a_byte_quota_trims_the_oldest_items() {
        let fixture = Fixture::new();
        let oldest = fixture.write(RetentionClass::Artifacts, "oldest.bin", &[b'a'; 6], 30);
        let middle = fixture.write(RetentionClass::Artifacts, "middle.bin", &[b'b'; 6], 20);
        let newest = fixture.write(RetentionClass::Artifacts, "newest.bin", &[b'c'; 6], 10);

        // Nothing is old enough to expire; the 10-byte quota trims 6 + 6 bytes.
        let report = fixture.sweep(&plan(RetentionClass::Artifacts, 3650, Some(10), 0, false));

        assert_eq!(report.trashed.len(), 2, "{report:?}");
        assert!(report.trashed.iter().all(|item| item.reason == RetentionReason::OverQuota));
        assert_eq!(report.bytes_freed, 12);
        assert!(!oldest.exists());
        assert!(!middle.exists());
        assert!(newest.exists(), "the newest item stays under quota");
        assert_eq!(report.kept, 1);
    }

    #[test]
    fn a_dry_run_reports_without_moving_anything() {
        let fixture = Fixture::new();
        let file = fixture.write(RetentionClass::Sessions, "expired.session", b"session", 20);

        let report = fixture.sweep(&plan(RetentionClass::Sessions, 1, None, 0, true));

        assert!(report.dry_run);
        assert_eq!(report.trashed.len(), 1, "{report:?}");
        assert_eq!(report.trashed[0].reason, RetentionReason::Expired);
        assert_eq!(report.bytes_freed, 0, "nothing was freed");
        assert_eq!(report.kept, 0, "the report shows what would remain");
        assert!(file.exists(), "a dry run changes nothing");

        // The same plan without dry-run executes the reported selection.
        let report = fixture.sweep(&plan(RetentionClass::Sessions, 1, None, 0, false));
        assert_eq!(report.trashed.len(), 1);
        assert!(!file.exists());
    }

    #[test]
    fn a_second_run_is_idempotent() {
        let fixture = Fixture::new();
        let expired = fixture.write(RetentionClass::Logs, "expired.log", b"old", 10);
        let fresh = fixture.write(RetentionClass::Logs, "fresh.log", b"new", 0);
        let plan = plan(RetentionClass::Logs, 1, None, 0, false);

        let first = fixture.sweep(&plan);
        assert_eq!(first.trashed.len(), 1, "{first:?}");
        assert!(!expired.exists());

        let second = fixture.sweep(&plan);
        assert!(second.trashed.is_empty(), "{second:?}");
        assert!(second.errors.is_empty(), "{second:?}");
        assert_eq!(second.kept, 1);
        assert!(fresh.exists());
    }

    #[test]
    fn protected_paths_are_never_touched() {
        let fixture = Fixture::new();
        let journal = fixture.write(RetentionClass::Logs, "turn.journal", b"journal", 10);
        let policy = fixture.write(RetentionClass::Logs, "policy.toml", b"policy", 10);
        let ordinary = fixture.write(RetentionClass::Logs, "ordinary.log", b"log", 10);

        let report = fixture.sweep(&plan(RetentionClass::Logs, 1, None, 0, false));

        assert_eq!(report.trashed.len(), 1, "{report:?}");
        assert_eq!(report.trashed[0].path, ordinary);
        assert!(!ordinary.exists());
        assert!(journal.exists(), "a journal is protected");
        assert!(policy.exists(), "a policy file is protected");
        assert_eq!(report.kept, 2);
        assert_eq!(report.errors.len(), 2, "{report:?}");
        assert!(report.errors.iter().all(|error| error.message.contains("protected")));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_class_directory_is_refused() {
        let fixture = Fixture::new();
        let outside = fixture.home.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("keep.txt");
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, fixture.class_dir(RetentionClass::Logs)).unwrap();

        let report = fixture.sweep(&plan(RetentionClass::Logs, 1, None, 0, false));

        assert!(report.trashed.is_empty(), "{report:?}");
        assert_eq!(report.errors.len(), 1, "{report:?}");
        assert!(report.errors[0].message.contains("symlink"));
        assert!(victim.exists(), "the symlink target is untouched");
    }

    #[cfg(windows)]
    #[test]
    fn a_trash_failure_is_reported_and_not_fatal() {
        use std::os::windows::fs::OpenOptionsExt;

        let fixture = Fixture::new();
        let file = fixture.write(RetentionClass::Logs, "held.log", b"held", 10);
        // No sharing, so the shell's move to the Recycle Bin fails.
        let _held = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&file)
            .unwrap();

        let report = fixture.sweep(&plan(RetentionClass::Logs, 1, None, 0, false));

        assert!(report.trashed.is_empty(), "{report:?}");
        assert_eq!(report.kept, 1);
        assert_eq!(report.errors.len(), 1, "{report:?}");
        assert!(report.errors[0].message.contains("trash failed"), "{report:?}");
        assert!(file.exists(), "a failed trash leaves the original in place");
    }

    #[test]
    fn an_empty_root_produces_an_empty_report() {
        let fixture = Fixture::new();

        let report = fixture.sweep(&RetentionPlan::with_defaults(false));

        assert!(report.trashed.is_empty());
        assert!(report.errors.is_empty());
        assert_eq!(report.kept, 0);
        assert_eq!(report.bytes_freed, 0);
        assert!(!report.dry_run);
    }

    #[test]
    fn the_report_totals_match_the_work_done() {
        let fixture = Fixture::new();
        let old_trace = fixture.write(RetentionClass::Traces, "old.jsonl", &[b'a'; 10], 10);
        let fresh_trace = fixture.write(RetentionClass::Traces, "fresh.jsonl", &[b'b'; 5], 0);
        let old_log = fixture.write(RetentionClass::Logs, "old.log", &[b'c'; 7], 10);
        let plan = RetentionPlan::new(false)
            .with_class(RetentionClass::Traces, RetentionPolicy::new(1, None, 0))
            .with_class(RetentionClass::Logs, RetentionPolicy::new(1, None, 0));

        let report = fixture.sweep(&plan);

        assert_eq!(report.trashed.len(), 2, "{report:?}");
        assert_eq!(report.bytes_freed, 17, "{report:?}");
        assert_eq!(report.kept, 1);
        assert!(!report.dry_run);
        assert!(report.errors.is_empty(), "{report:?}");
        assert!(report.trashed.iter().any(|item| item.path == old_trace));
        assert!(report.trashed.iter().any(|item| item.path == old_log));
        assert!(fresh_trace.exists());
    }

    #[test]
    fn invalid_policies_are_rejected_before_any_io() {
        let fixture = Fixture::new();
        let file = fixture.write(RetentionClass::Logs, "old.log", b"old", 10);

        for policy in [
            RetentionPolicy::new(0, None, 0),
            RetentionPolicy::new(MAX_AGE_DAYS_LIMIT + 1, None, 0),
            RetentionPolicy::new(30, None, KEEP_MIN_LIMIT + 1),
        ] {
            let plan = RetentionPlan::new(false).with_class(RetentionClass::Logs, policy.clone());
            let err = sweep(&fixture.root, &plan, &fixture.trash, now_ms()).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidInput, "{policy:?}");
        }
        assert!(file.exists(), "validation runs before the sweep");
    }

    #[test]
    fn the_default_plan_is_a_dry_run_with_every_class() {
        let plan = RetentionPlan::default();
        assert!(plan.dry_run, "the default plan never moves anything");
        assert_eq!(plan.classes.len(), RetentionClass::ALL.len());
        for class in RetentionClass::ALL {
            let policy = plan.classes.get(&class).unwrap();
            assert_eq!(*policy, class.default_policy());
            assert_eq!(class.directory(), class.to_string());
            policy.validate().unwrap();
        }
        assert_eq!(RetentionClass::Traces.default_policy().max_bytes, Some(256 * MIB));
    }

    #[test]
    fn a_missing_root_is_an_error() {
        let fixture = Fixture::new();
        let missing = fixture.home.join("absent");
        let err = sweep(&missing, &RetentionPlan::default(), &fixture.trash, now_ms()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[test]
    fn a_class_path_that_is_a_file_is_reported_and_skipped() {
        let fixture = Fixture::new();
        std::fs::create_dir_all(&fixture.root).unwrap();
        std::fs::write(fixture.class_dir(RetentionClass::Metrics), b"not a directory").unwrap();

        let report = fixture.sweep(&plan(RetentionClass::Metrics, 1, None, 0, false));

        assert!(report.trashed.is_empty());
        assert_eq!(report.errors.len(), 1, "{report:?}");
        assert!(report.errors[0].message.contains("not a directory"));
    }
}
