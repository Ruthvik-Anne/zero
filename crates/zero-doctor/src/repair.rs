//! Reversible repair plans (DOC-04, DOC-05, DOC-06, DOC-10).
//!
//! A repair is a [`RepairPlan`]: an ordered list of [`RepairAction`]s plus a
//! [`RepairPolicy`] that bounds where and how much the plan may touch. The
//! module never invents work: a plan is built by a caller (the CLI, a panel, or
//! an agent's `plan` step) from diagnosis findings, and every action is one of
//! the small, reviewable operations below.
//!
//! The guarantees are deliberately narrow and testable:
//!
//! - [`dry_run`] resolves every action without mutating the filesystem and
//!   returns what would change, rejecting policy violations first.
//! - [`apply`] validates the *whole* plan before touching anything, snapshots
//!   every affected existing file into a caller-supplied snapshot directory,
//!   applies actions in order, and records an inverse for each one. If an
//!   action fails, every inverse is undone in reverse order and the returned
//!   error says how many actions were rolled back.
//! - [`rollback`] performs the same reversal later, from the [`RepairReport`]
//!   returned by [`apply`].
//!
//! Paths are the security boundary. Every action path must be absolute, must
//! not contain `..` or `.` components, and must resolve inside one of the
//! policy's `allowed_roots`. Resolution canonicalises the nearest existing
//! ancestor, so a symlinked directory cannot be used to escape a root, and a
//! final-component symlink is refused outright. Deletions additionally require
//! `RepairPolicy::allow_delete`, and `max_actions` bounds the plan.
//!
//! Contents are deliberately bounded and scanned before use: a repair may not
//! write more than [`MAX_CONTENTS_BYTES`], may not carry control characters,
//! and may not embed secret-looking material. Contents never appear in a
//! preview, a report, or an error message; only paths do.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Component, Path, PathBuf, PrefixComponent};
use thiserror::Error;

use crate::validate_toml;

/// Largest file body a single repair action may write.
pub const MAX_CONTENTS_BYTES: usize = 64 * 1024;

/// Hard cap on plan length, independent of the caller's policy.
pub const MAX_PLAN_ACTIONS: usize = 1024;

/// One reviewable repair operation.
///
/// The variants are intentionally the smallest set that covers the doctor's
/// findings: creating a missing directory, writing or repairing a file,
/// moving stale data to the trash, removing a stale lock, and rotating a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairAction {
    /// Create a directory and any missing parents. A directory that already
    /// exists is reported as already applied.
    CreateDirectory { path: PathBuf },
    /// Write a file, replacing it only after snapshotting the old bytes.
    WriteFile { path: PathBuf, contents: String },
    /// Move a regular file to the snapshot directory's reversible trash.
    /// Requires [`RepairPolicy::allow_delete`].
    MoveToTrash { path: PathBuf },
    /// Remove a stale `.lock` file after snapshotting it. Requires
    /// [`RepairPolicy::allow_delete`].
    RemoveStaleLock { path: PathBuf },
    /// Rename a file to `<name>.1`, preserving its bytes. Refuses to clobber an
    /// existing rotation target.
    RotateFile { path: PathBuf },
    /// Replace a config file with TOML-validated contents, snapshotting the
    /// previous bytes first.
    RepairConfig { path: PathBuf, contents: String },
}

/// The stable action kind used in previews and reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairActionKind {
    CreateDirectory,
    WriteFile,
    MoveToTrash,
    RemoveStaleLock,
    RotateFile,
    RepairConfig,
}

impl RepairAction {
    /// The stable kind name for this action.
    pub fn kind(&self) -> RepairActionKind {
        match self {
            RepairAction::CreateDirectory { .. } => RepairActionKind::CreateDirectory,
            RepairAction::WriteFile { .. } => RepairActionKind::WriteFile,
            RepairAction::MoveToTrash { .. } => RepairActionKind::MoveToTrash,
            RepairAction::RemoveStaleLock { .. } => RepairActionKind::RemoveStaleLock,
            RepairAction::RotateFile { .. } => RepairActionKind::RotateFile,
            RepairAction::RepairConfig { .. } => RepairActionKind::RepairConfig,
        }
    }

    /// The path this action changes.
    pub fn path(&self) -> &Path {
        match self {
            RepairAction::CreateDirectory { path }
            | RepairAction::WriteFile { path, .. }
            | RepairAction::MoveToTrash { path }
            | RepairAction::RemoveStaleLock { path }
            | RepairAction::RotateFile { path }
            | RepairAction::RepairConfig { path, .. } => path,
        }
    }

    /// The body this action writes, for the two writing variants.
    pub fn contents(&self) -> Option<&str> {
        match self {
            RepairAction::WriteFile { contents, .. }
            | RepairAction::RepairConfig { contents, .. } => Some(contents),
            _ => None,
        }
    }

    /// Whether the action removes data from its original location. These
    /// actions require [`RepairPolicy::allow_delete`].
    pub fn deletes(&self) -> bool {
        matches!(
            self,
            RepairAction::MoveToTrash { .. } | RepairAction::RemoveStaleLock { .. }
        )
    }
}

/// An ordered repair, with a stable id for reports.
///
/// `dry_run` is a safety flag: a plan built for preview must not be handed to
/// [`apply`], which refuses it with [`RepairError::DryRunPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPlan {
    pub id: String,
    pub actions: Vec<RepairAction>,
    pub dry_run: bool,
}

impl RepairPlan {
    /// A plan that is allowed to be applied.
    pub fn new(id: impl Into<String>, actions: Vec<RepairAction>) -> Self {
        Self {
            id: id.into(),
            actions,
            dry_run: false,
        }
    }

    /// Preview this plan under `policy`. No filesystem mutation.
    pub fn preview(&self, policy: &RepairPolicy) -> Result<RepairPreview, RepairError> {
        crate::repair::dry_run(self, policy)
    }

    /// Apply this plan under `policy`, snapshotting into `snapshot_dir`.
    pub fn apply(
        &self,
        policy: &RepairPolicy,
        snapshot_dir: impl AsRef<Path>,
    ) -> Result<RepairReport, RepairError> {
        crate::repair::apply(self, policy, snapshot_dir)
    }
}

/// The bound on what a plan may touch (DOC-10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPolicy {
    /// Canonicalisable directories every action path must resolve inside.
    /// An empty list refuses every plan.
    pub allowed_roots: Vec<PathBuf>,
    /// Maximum number of actions. Zero permits only an empty plan.
    pub max_actions: usize,
    /// Whether [`RepairAction::MoveToTrash`] and
    /// [`RepairAction::RemoveStaleLock`] are permitted.
    pub allow_delete: bool,
}

/// What one action would do, as seen by [`dry_run`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PreviewEffect {
    /// The target does not exist and would be created.
    Create { bytes: u64 },
    /// The target exists and would be replaced.
    Overwrite { bytes: u64 },
    /// The target would leave its original location.
    Remove { bytes: u64 },
    /// The target would be renamed to this path.
    Rotate { to: PathBuf },
    /// The desired end state already holds; nothing would be written.
    AlreadyApplied,
    /// The target exists in a shape the action cannot repair. The preview
    /// reports it instead of failing, so the caller can see every action.
    Conflict { reason: String },
}

impl PreviewEffect {
    fn snapshots(&self) -> bool {
        matches!(
            self,
            PreviewEffect::Overwrite { .. }
                | PreviewEffect::Remove { .. }
                | PreviewEffect::Rotate { .. }
        )
    }
}

/// One action's predicted effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewChange {
    /// Stable id: `a1`, `a2`, ... in plan order.
    pub action_id: String,
    pub action: RepairActionKind,
    pub path: PathBuf,
    pub effect: PreviewEffect,
}

/// The result of [`dry_run`]: what would change, with no mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairPreview {
    pub plan_id: String,
    pub dry_run: bool,
    pub actions: usize,
    pub changes: Vec<PreviewChange>,
    /// Action ids whose desired end state already holds.
    pub already_applied: Vec<String>,
    /// Existing files that [`apply`] would snapshot, in plan order.
    pub would_snapshot: Vec<PathBuf>,
}

/// One applied action, as listed in a [`RepairReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedAction {
    /// Stable id: `a1`, `a2`, ... in plan order.
    pub id: String,
    pub kind: RepairActionKind,
    pub path: PathBuf,
}

/// A snapshot taken before an action changed a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRef {
    pub action_id: String,
    /// The original path.
    pub path: PathBuf,
    /// The copy under the caller's snapshot directory.
    pub snapshot: PathBuf,
}

/// The outcome of [`apply`]: applied ids plus snapshot paths, never contents.
///
/// The inverse log is process-local and deliberately omitted from serialization.
/// A report rebuilt from JSON can still be inspected, but [`rollback`] refuses
/// it rather than pretending it can reverse changes it no longer remembers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairReport {
    pub plan_id: String,
    pub applied: Vec<AppliedAction>,
    pub already_applied: Vec<String>,
    pub snapshots: Vec<SnapshotRef>,
    #[serde(skip)]
    inverse: Vec<Inverse>,
}

impl RepairReport {
    /// Number of reverse operations recorded. Zero after a deserialized report.
    pub fn inverse_len(&self) -> usize {
        self.inverse.len()
    }
}

/// Typed repair failure. Policy and validation errors are returned before any
/// mutation; [`RepairError::Apply`] proves the plan's earlier effects were
/// rolled back.
#[derive(Debug, Error)]
pub enum RepairError {
    /// The plan is marked preview-only and must not be applied.
    #[error("repair plan `{plan_id}` is marked dry-run; call dry_run() to preview it")]
    DryRunPlan { plan_id: String },
    /// The plan itself is structurally unusable.
    #[error("repair plan is invalid: {reason}")]
    InvalidPlan { reason: String },
    /// The policy refused the plan before any mutation.
    #[error("repair policy rejected plan `{plan_id}`: {reason}")]
    Policy { plan_id: String, reason: String },
    /// The plan is longer than the policy (or the hard cap) allows.
    #[error("repair plan `{plan_id}` has {actions} actions; the limit is {max}")]
    TooManyActions {
        plan_id: String,
        actions: usize,
        max: usize,
    },
    /// One action is malformed.
    #[error("repair action `{action_id}` is invalid: {reason}")]
    InvalidAction { action_id: String, reason: String },
    /// An action failed during execution. `rolled_back` counts the earlier
    /// actions whose effects were successfully undone.
    #[error(
        "repair plan `{plan_id}`: action `{action_id}` failed: {source}; \
         {rolled_back} earlier action(s) were rolled back"
    )]
    Apply {
        plan_id: String,
        action_id: String,
        #[source]
        source: io::Error,
        rolled_back: usize,
    },
    /// An action failed and at least one inverse also failed. `restored` counts
    /// the earlier actions that were successfully undone before the failure.
    #[error(
        "repair plan `{plan_id}`: action `{action_id}` failed: {source}; \
         rollback failed after restoring {restored} action(s): {rollback_error}"
    )]
    ApplyRollbackFailed {
        plan_id: String,
        action_id: String,
        #[source]
        source: io::Error,
        restored: usize,
        rollback_error: String,
    },
    /// An explicit [`rollback`] could not finish.
    #[error("rollback failed: {reason}")]
    Rollback { reason: String },
}

/// Reverse operation recorded for one applied action.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Inverse {
    /// Put a snapshot back over the original path, restoring its permission
    /// bits on Unix.
    RestoreFile {
        path: PathBuf,
        snapshot: PathBuf,
        mode: Option<u32>,
    },
    /// Remove a file this plan created.
    RemoveFile { path: PathBuf },
    /// Remove directories this plan created, shallowest first.
    RemoveDirs { paths: Vec<PathBuf> },
    /// Move a trashed or rotated file back.
    MoveBack { from: PathBuf, to: PathBuf },
}

/// A per-action inverse and snapshot log. It is merged into the report only
/// after the action succeeds, so a failed action's partial effects can be
/// undone without counting it as an earlier rolled-back action.
#[derive(Default)]
struct ActionLog {
    inverse: Vec<Inverse>,
    snapshots: Vec<SnapshotRef>,
}

enum Applied {
    Applied(PathBuf),
    Already,
}

struct ValidatedPlan {
    roots: Vec<PathBuf>,
    paths: Vec<PathBuf>,
}

/// Resolve what a plan would change without touching the filesystem.
///
/// Policy and structural violations are returned as errors. State-dependent
/// problems (for example a target that is a directory) appear as
/// [`PreviewEffect::Conflict`] so the caller can see the rest of the plan.
pub fn dry_run(plan: &RepairPlan, policy: &RepairPolicy) -> Result<RepairPreview, RepairError> {
    let validated = validate_plan(plan, policy)?;
    let mut preview = RepairPreview {
        plan_id: plan.id.clone(),
        dry_run: true,
        actions: plan.actions.len(),
        changes: Vec::with_capacity(plan.actions.len()),
        already_applied: Vec::new(),
        would_snapshot: Vec::new(),
    };

    for (index, action) in plan.actions.iter().enumerate() {
        let action_id = action_id(index);
        let path = validated.paths[index].clone();
        let effect = preview_effect(&path, action);
        if effect == PreviewEffect::AlreadyApplied {
            preview.already_applied.push(action_id.clone());
        }
        if effect.snapshots() && !preview.would_snapshot.contains(&path) {
            preview.would_snapshot.push(path.clone());
        }
        preview.changes.push(PreviewChange {
            action_id,
            action: action.kind(),
            path,
            effect,
        });
    }

    Ok(preview)
}

/// Apply a plan, snapshotting first and rolling back on any failure.
///
/// The whole plan is validated against the policy before the first mutation.
/// `snapshot_dir` must resolve inside an allowed root and must not be an
/// allowed root itself; it is created lazily, only when a snapshot or a trash
/// move is needed.
pub fn apply(
    plan: &RepairPlan,
    policy: &RepairPolicy,
    snapshot_dir: impl AsRef<Path>,
) -> Result<RepairReport, RepairError> {
    if plan.dry_run {
        return Err(RepairError::DryRunPlan {
            plan_id: plan.id.clone(),
        });
    }

    let validated = validate_plan(plan, policy)?;
    let snapshot_root = validate_snapshot_dir(plan, snapshot_dir.as_ref(), &validated.roots)?;
    reject_snapshot_overlap(plan, &snapshot_root, &validated.paths)?;

    let mut report = RepairReport {
        plan_id: plan.id.clone(),
        applied: Vec::new(),
        already_applied: Vec::new(),
        snapshots: Vec::new(),
        inverse: Vec::new(),
    };

    for (index, action) in plan.actions.iter().enumerate() {
        let id = action_id(index);
        let mut log = ActionLog::default();
        match apply_one(
            &id,
            index,
            action,
            &validated.roots,
            &snapshot_root,
            &mut log,
        ) {
            Ok(Applied::Applied(path)) => {
                report.inverse.append(&mut log.inverse);
                report.snapshots.append(&mut log.snapshots);
                report.applied.push(AppliedAction {
                    id,
                    kind: action.kind(),
                    path,
                });
            }
            Ok(Applied::Already) => report.already_applied.push(id),
            Err(source) => {
                // Undo this action's partial effects first; they are not
                // "earlier actions" and must not inflate the count.
                let (_, local_error) = rollback_inverse(&log.inverse);
                let (rolled_back, earlier_error) = rollback_inverse(&report.inverse);
                let rollback_error = combine_errors(local_error, earlier_error);
                return Err(match rollback_error {
                    Some(rollback_error) => RepairError::ApplyRollbackFailed {
                        plan_id: plan.id.clone(),
                        action_id: id,
                        source,
                        restored: rolled_back,
                        rollback_error,
                    },
                    None => RepairError::Apply {
                        plan_id: plan.id.clone(),
                        action_id: id,
                        source,
                        rolled_back,
                    },
                });
            }
        }
    }

    Ok(report)
}

/// Reverse every action recorded by [`apply`], newest first.
///
/// A report produced by [`apply`] carries an in-process inverse log. A report
/// that round-tripped through JSON does not, so this returns
/// [`RepairError::Rollback`] instead of silently doing nothing.
pub fn rollback(report: &RepairReport) -> Result<(), RepairError> {
    if report.inverse.is_empty() {
        if report.applied.is_empty() {
            return Ok(());
        }
        return Err(RepairError::Rollback {
            reason: "the report carries no inverse log; rollback is only available for a \
                     report returned by apply()"
                .to_string(),
        });
    }

    let (restored, error) = rollback_inverse(&report.inverse);
    match error {
        None => Ok(()),
        Some(reason) => Err(RepairError::Rollback {
            reason: format!(
                "restored {restored} of {} recorded action(s): {reason}",
                report.inverse.len()
            ),
        }),
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_plan(plan: &RepairPlan, policy: &RepairPolicy) -> Result<ValidatedPlan, RepairError> {
    if plan.id.trim().is_empty() {
        return Err(RepairError::InvalidPlan {
            reason: "the plan id is empty".to_string(),
        });
    }
    if plan.actions.len() > MAX_PLAN_ACTIONS {
        return Err(RepairError::TooManyActions {
            plan_id: plan.id.clone(),
            actions: plan.actions.len(),
            max: MAX_PLAN_ACTIONS,
        });
    }
    if plan.actions.len() > policy.max_actions {
        return Err(RepairError::TooManyActions {
            plan_id: plan.id.clone(),
            actions: plan.actions.len(),
            max: policy.max_actions,
        });
    }

    let roots = canonical_roots(plan, policy)?;
    let mut paths = Vec::with_capacity(plan.actions.len());

    for (index, action) in plan.actions.iter().enumerate() {
        let id = action_id(index);
        validate_action(&id, action)?;
        if action.deletes() && !policy.allow_delete {
            return Err(RepairError::Policy {
                plan_id: plan.id.clone(),
                reason: format!(
                    "action {id} ({}) removes {} and the policy does not allow deletion",
                    action.kind_name(),
                    action.path().display()
                ),
            });
        }
        let path = resolve_within(action.path(), &roots).map_err(|reason| RepairError::Policy {
            plan_id: plan.id.clone(),
            reason: format!(
                "action {id} ({}) targets {}: {reason}",
                action.kind_name(),
                action.path().display()
            ),
        })?;
        paths.push(path);
    }

    Ok(ValidatedPlan { roots, paths })
}

fn canonical_roots(plan: &RepairPlan, policy: &RepairPolicy) -> Result<Vec<PathBuf>, RepairError> {
    if policy.allowed_roots.is_empty() {
        return Err(RepairError::Policy {
            plan_id: plan.id.clone(),
            reason: "no allowed roots are configured".to_string(),
        });
    }

    let mut roots = Vec::with_capacity(policy.allowed_roots.len());
    for root in &policy.allowed_roots {
        let canonical = std::fs::canonicalize(root).map_err(|error| RepairError::Policy {
            plan_id: plan.id.clone(),
            reason: format!("allowed root {} is not usable: {error}", root.display()),
        })?;
        if !canonical.is_dir() {
            return Err(RepairError::Policy {
                plan_id: plan.id.clone(),
                reason: format!("allowed root {} is not a directory", root.display()),
            });
        }
        roots.push(canonical);
    }
    Ok(roots)
}

fn validate_action(id: &str, action: &RepairAction) -> Result<(), RepairError> {
    match action {
        RepairAction::WriteFile { contents, .. } | RepairAction::RepairConfig { contents, .. } => {
            validate_contents(id, contents)?;
            if matches!(action, RepairAction::RepairConfig { .. })
                && validate_toml(contents).is_err()
            {
                return Err(RepairError::InvalidAction {
                    action_id: id.to_string(),
                    reason: "config contents are not valid TOML".to_string(),
                });
            }
        }
        RepairAction::RemoveStaleLock { path } => {
            let is_lock = path
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|extension| extension.eq_ignore_ascii_case("lock"));
            if !is_lock {
                return Err(RepairError::InvalidAction {
                    action_id: id.to_string(),
                    reason: format!(
                        "RemoveStaleLock only accepts a `.lock` path, got {}",
                        path.display()
                    ),
                });
            }
        }
        RepairAction::CreateDirectory { .. }
        | RepairAction::MoveToTrash { .. }
        | RepairAction::RotateFile { .. } => {}
    }

    Ok(())
}

fn validate_contents(action_id: &str, contents: &str) -> Result<(), RepairError> {
    if contents.len() > MAX_CONTENTS_BYTES {
        return Err(RepairError::InvalidAction {
            action_id: action_id.to_string(),
            reason: format!(
                "contents are {} bytes; the limit is {MAX_CONTENTS_BYTES}",
                contents.len()
            ),
        });
    }
    if contents
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        return Err(RepairError::InvalidAction {
            action_id: action_id.to_string(),
            reason: "contents contain a control character".to_string(),
        });
    }
    if let Some(marker) = secret_marker(contents) {
        return Err(RepairError::InvalidAction {
            action_id: action_id.to_string(),
            reason: format!(
                "contents look like a secret ({marker}); repairs must never carry secrets"
            ),
        });
    }
    Ok(())
}

/// Strong, low-false-positive markers of embedded credential material.
fn secret_marker(contents: &str) -> Option<&'static str> {
    const MARKERS: [&str; 8] = [
        "-----BEGIN ",
        "PRIVATE KEY",
        "sk-",
        "ghp_",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "Bearer ",
    ];
    MARKERS.into_iter().find(|marker| contents.contains(marker))
}

// ---------------------------------------------------------------------------
// Path policy
// ---------------------------------------------------------------------------

/// Resolve `path`, rejecting lexical escapes and any result outside `roots`.
///
/// The resolved path must be a strict descendant of a root; an action may not
/// name a root itself.
fn resolve_within(path: &Path, roots: &[PathBuf]) -> Result<PathBuf, String> {
    reject_lexical(path)?;
    let resolved = canonical_target(path)?;
    if roots.contains(&resolved) {
        return Err("the path is an allowed root and may not be modified".to_string());
    }
    if !roots.iter().any(|root| resolved.starts_with(root)) {
        return Err(format!(
            "{} resolves outside the allowed roots",
            path.display()
        ));
    }
    Ok(resolved)
}

fn reject_lexical(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("the path is empty".to_string());
    }
    if !path.is_absolute() {
        return Err(format!("{} is not absolute", path.display()));
    }
    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err(format!("{} contains a `..` component", path.display()));
            }
            Component::CurDir => {
                return Err(format!("{} contains a `.` component", path.display()));
            }
            Component::Prefix(prefix) => reject_prefix(prefix, path)?,
            Component::RootDir | Component::Normal(_) => {}
        }
    }
    Ok(())
}

#[cfg(windows)]
fn reject_prefix(prefix: PrefixComponent<'_>, path: &Path) -> Result<(), String> {
    use std::path::Prefix;
    match prefix.kind() {
        Prefix::UNC(..) | Prefix::VerbatimUNC(..) | Prefix::DeviceNS(..) | Prefix::Verbatim(..) => {
            Err(format!(
                "{} is a UNC, device, or verbatim path and is refused",
                path.display()
            ))
        }
        Prefix::Disk(_) | Prefix::VerbatimDisk(_) => Ok(()),
    }
}

#[cfg(not(windows))]
fn reject_prefix(_prefix: PrefixComponent<'_>, _path: &Path) -> Result<(), String> {
    Ok(())
}

/// Canonical form of a path that may not exist yet.
///
/// An existing path is canonicalised directly. For a missing path, the nearest
/// existing ancestor is canonicalised and the missing names are appended, so a
/// symlinked ancestor is followed and checked by the caller.
fn canonical_target(path: &Path) -> Result<PathBuf, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "{} is a symlink; repairs do not follow symlinks",
                    path.display()
                ));
            }
            std::fs::canonicalize(path)
                .map_err(|error| format!("cannot resolve {}: {error}", path.display()))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut missing = Vec::new();
            let mut current = path;
            loop {
                match std::fs::symlink_metadata(current) {
                    Ok(_) => break,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        let Some(name) = current.file_name() else {
                            return Err(format!(
                                "{} has no existing ancestor to resolve",
                                path.display()
                            ));
                        };
                        missing.push(name.to_os_string());
                        let Some(parent) = current.parent() else {
                            return Err(format!(
                                "{} has no existing ancestor to resolve",
                                path.display()
                            ));
                        };
                        current = parent;
                    }
                    Err(error) => {
                        return Err(format!("cannot inspect {}: {error}", current.display()));
                    }
                }
            }
            let mut resolved = std::fs::canonicalize(current)
                .map_err(|error| format!("cannot resolve {}: {error}", current.display()))?;
            for name in missing.iter().rev() {
                resolved.push(name);
            }
            Ok(resolved)
        }
        Err(error) => Err(format!("cannot inspect {}: {error}", path.display())),
    }
}

fn validate_snapshot_dir(
    plan: &RepairPlan,
    snapshot_dir: &Path,
    roots: &[PathBuf],
) -> Result<PathBuf, RepairError> {
    let resolved = resolve_within(snapshot_dir, roots).map_err(|reason| RepairError::Policy {
        plan_id: plan.id.clone(),
        reason: format!("snapshot directory {}: {reason}", snapshot_dir.display()),
    })?;
    if let Ok(metadata) = std::fs::symlink_metadata(&resolved) {
        if !metadata.is_dir() {
            return Err(RepairError::Policy {
                plan_id: plan.id.clone(),
                reason: format!(
                    "snapshot directory {} exists and is not a directory",
                    snapshot_dir.display()
                ),
            });
        }
    }
    Ok(resolved)
}

/// Refuse a plan that would move or rotate away a directory containing the
/// snapshot destination, which would strand the very evidence rollback needs.
fn reject_snapshot_overlap(
    plan: &RepairPlan,
    snapshot_root: &Path,
    paths: &[PathBuf],
) -> Result<(), RepairError> {
    for (index, action) in plan.actions.iter().enumerate() {
        if !matches!(
            action,
            RepairAction::MoveToTrash { .. }
                | RepairAction::RemoveStaleLock { .. }
                | RepairAction::RotateFile { .. }
        ) {
            continue;
        }
        let path = &paths[index];
        if snapshot_root.starts_with(path) {
            return Err(RepairError::Policy {
                plan_id: plan.id.clone(),
                reason: format!(
                    "action {} ({}) targets {}, which contains the snapshot directory",
                    action_id(index),
                    action.kind_name(),
                    action.path().display()
                ),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Preview
// ---------------------------------------------------------------------------

fn preview_effect(path: &Path, action: &RepairAction) -> PreviewEffect {
    match action {
        RepairAction::CreateDirectory { .. } => match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() => PreviewEffect::AlreadyApplied,
            Ok(_) => PreviewEffect::Conflict {
                reason: format!("{} exists and is not a directory", path.display()),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                PreviewEffect::Create { bytes: 0 }
            }
            Err(error) => PreviewEffect::Conflict {
                reason: format!("cannot inspect {}: {error}", path.display()),
            },
        },
        RepairAction::WriteFile { contents, .. } | RepairAction::RepairConfig { contents, .. } => {
            preview_write(path, contents.as_bytes())
        }
        RepairAction::MoveToTrash { .. } | RepairAction::RemoveStaleLock { .. } => {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.is_file() => PreviewEffect::Remove {
                    bytes: metadata.len(),
                },
                Ok(metadata) if metadata.is_dir() => PreviewEffect::Conflict {
                    reason: format!("{} is a directory, not a file", path.display()),
                },
                Ok(_) => PreviewEffect::Conflict {
                    reason: format!("{} is not a regular file", path.display()),
                },
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    PreviewEffect::AlreadyApplied
                }
                Err(error) => PreviewEffect::Conflict {
                    reason: format!("cannot inspect {}: {error}", path.display()),
                },
            }
        }
        RepairAction::RotateFile { .. } => preview_rotate(path),
    }
}

fn preview_write(path: &Path, contents: &[u8]) -> PreviewEffect {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            if metadata.len() == contents.len() as u64 {
                match std::fs::read(path) {
                    Ok(existing) if existing == contents => return PreviewEffect::AlreadyApplied,
                    Ok(_) => {}
                    Err(error) => {
                        return PreviewEffect::Conflict {
                            reason: format!("cannot read {}: {error}", path.display()),
                        };
                    }
                }
            }
            PreviewEffect::Overwrite {
                bytes: metadata.len(),
            }
        }
        Ok(metadata) if metadata.is_dir() => PreviewEffect::Conflict {
            reason: format!("{} is a directory, not a file", path.display()),
        },
        Ok(_) => PreviewEffect::Conflict {
            reason: format!("{} is not a regular file", path.display()),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => PreviewEffect::Create {
            bytes: contents.len() as u64,
        },
        Err(error) => PreviewEffect::Conflict {
            reason: format!("cannot inspect {}: {error}", path.display()),
        },
    }
}

fn preview_rotate(path: &Path) -> PreviewEffect {
    let rotated = rotated_path(path);
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            if path_exists(&rotated) {
                PreviewEffect::Conflict {
                    reason: format!("rotation target {} already exists", rotated.display()),
                }
            } else {
                PreviewEffect::Rotate { to: rotated }
            }
        }
        Ok(metadata) if metadata.is_dir() => PreviewEffect::Conflict {
            reason: format!("{} is a directory, not a file", path.display()),
        },
        Ok(_) => PreviewEffect::Conflict {
            reason: format!("{} is not a regular file", path.display()),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if rotated.is_file() {
                PreviewEffect::AlreadyApplied
            } else {
                PreviewEffect::Conflict {
                    reason: format!(
                        "{} is absent and no rotated copy exists at {}",
                        path.display(),
                        rotated.display()
                    ),
                }
            }
        }
        Err(error) => PreviewEffect::Conflict {
            reason: format!("cannot inspect {}: {error}", path.display()),
        },
    }
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

fn apply_one(
    action_id: &str,
    index: usize,
    action: &RepairAction,
    roots: &[PathBuf],
    snapshot_root: &Path,
    log: &mut ActionLog,
) -> io::Result<Applied> {
    let path = resolve_within(action.path(), roots)
        .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason))?;

    match action {
        RepairAction::CreateDirectory { .. } => apply_create_dir(&path, log),
        RepairAction::WriteFile { contents, .. } | RepairAction::RepairConfig { contents, .. } => {
            apply_write(
                action_id,
                index,
                &path,
                contents.as_bytes(),
                snapshot_root,
                log,
            )
        }
        RepairAction::MoveToTrash { .. } => {
            apply_trash(action_id, index, &path, snapshot_root, log)
        }
        RepairAction::RemoveStaleLock { .. } => {
            apply_remove_lock(action_id, index, &path, snapshot_root, log)
        }
        RepairAction::RotateFile { .. } => {
            apply_rotate(action_id, index, &path, snapshot_root, log)
        }
    }
}

fn apply_create_dir(path: &Path, log: &mut ActionLog) -> io::Result<Applied> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(Applied::Already),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a directory", path.display()),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut missing = Vec::new();
    let mut current = path;
    loop {
        match std::fs::symlink_metadata(current) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(current.to_path_buf());
                let Some(parent) = current.parent() else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("{} has no existing ancestor", path.display()),
                    ));
                };
                current = parent;
            }
            Err(error) => return Err(error),
        }
    }
    if !std::fs::metadata(current)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("{} is not a directory", current.display()),
        ));
    }

    missing.reverse();
    log.inverse.push(Inverse::RemoveDirs {
        paths: missing.clone(),
    });
    std::fs::create_dir_all(path)?;
    Ok(Applied::Applied(path.to_path_buf()))
}

fn apply_write(
    action_id: &str,
    index: usize,
    path: &Path,
    contents: &[u8],
    snapshot_root: &Path,
    log: &mut ActionLog,
) -> io::Result<Applied> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            if metadata.len() == contents.len() as u64 && std::fs::read(path)? == contents {
                return Ok(Applied::Already);
            }
            let snapshot = take_snapshot(action_id, index, path, snapshot_root)?;
            log.snapshots.push(SnapshotRef {
                action_id: action_id.to_string(),
                path: path.to_path_buf(),
                snapshot: snapshot.clone(),
            });
            log.inverse.push(Inverse::RestoreFile {
                path: path.to_path_buf(),
                snapshot,
                mode: file_mode(&metadata),
            });
        }
        Ok(metadata) if metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} is a directory, not a file", path.display()),
            ));
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", path.display()),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} has no parent directory", path.display()),
                )
            })?;
            if !std::fs::metadata(parent).is_ok_and(|metadata| metadata.is_dir()) {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("parent of {} is not a directory", path.display()),
                ));
            }
            log.inverse.push(Inverse::RemoveFile {
                path: path.to_path_buf(),
            });
        }
        Err(error) => return Err(error),
    }

    std::fs::write(path, contents)?;
    Ok(Applied::Applied(path.to_path_buf()))
}

fn apply_trash(
    action_id: &str,
    index: usize,
    path: &Path,
    snapshot_root: &Path,
    log: &mut ActionLog,
) -> io::Result<Applied> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };

    let trash_root = snapshot_root.join("trash");
    let base_name = trash_file_name(action_id, index, path);

    let Some(metadata) = metadata else {
        // The desired end state (the path is gone) already holds when a
        // trashed copy from an earlier apply is present.
        if trash_root.join(&base_name).is_file() {
            return Ok(Applied::Already);
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} does not exist", path.display()),
        ));
    };
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }

    let snapshot = take_snapshot(action_id, index, path, snapshot_root)?;
    log.snapshots.push(SnapshotRef {
        action_id: action_id.to_string(),
        path: path.to_path_buf(),
        snapshot,
    });

    ensure_private_dir(&trash_root)?;
    let trash = unique_path(&trash_root, &base_name);
    log.inverse.push(Inverse::MoveBack {
        from: trash.clone(),
        to: path.to_path_buf(),
    });
    move_file(path, &trash)?;
    Ok(Applied::Applied(path.to_path_buf()))
}

fn apply_remove_lock(
    action_id: &str,
    index: usize,
    path: &Path,
    snapshot_root: &Path,
    log: &mut ActionLog,
) -> io::Result<Applied> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Applied::Already),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }

    let snapshot = take_snapshot(action_id, index, path, snapshot_root)?;
    log.snapshots.push(SnapshotRef {
        action_id: action_id.to_string(),
        path: path.to_path_buf(),
        snapshot: snapshot.clone(),
    });
    log.inverse.push(Inverse::RestoreFile {
        path: path.to_path_buf(),
        snapshot,
        mode: file_mode(&metadata),
    });
    std::fs::remove_file(path)?;
    Ok(Applied::Applied(path.to_path_buf()))
}

fn apply_rotate(
    action_id: &str,
    index: usize,
    path: &Path,
    snapshot_root: &Path,
    log: &mut ActionLog,
) -> io::Result<Applied> {
    let rotated = rotated_path(path);
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return if rotated.is_file() {
                Ok(Applied::Already)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "{} is absent and no rotated copy exists at {}",
                        path.display(),
                        rotated.display()
                    ),
                ))
            };
        }
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if path_exists(&rotated) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("rotation target {} already exists", rotated.display()),
        ));
    }

    // Snapshot for evidence and for a copy-based fallback restore.
    let snapshot = take_snapshot(action_id, index, path, snapshot_root)?;
    log.snapshots.push(SnapshotRef {
        action_id: action_id.to_string(),
        path: path.to_path_buf(),
        snapshot: snapshot.clone(),
    });
    log.inverse.push(Inverse::MoveBack {
        from: rotated.clone(),
        to: path.to_path_buf(),
    });
    std::fs::rename(path, &rotated)?;
    Ok(Applied::Applied(path.to_path_buf()))
}

fn rollback_inverse(inverse: &[Inverse]) -> (usize, Option<String>) {
    let mut restored = 0;
    for item in inverse.iter().rev() {
        if let Err(error) = undo(item) {
            return (restored, Some(error.to_string()));
        }
        restored += 1;
    }
    (restored, None)
}

fn undo(inverse: &Inverse) -> io::Result<()> {
    match inverse {
        Inverse::RestoreFile {
            path,
            snapshot,
            mode,
        } => {
            if !snapshot.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("snapshot {} is missing", snapshot.display()),
                ));
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(snapshot, path)?;
            restore_mode(path, *mode);
            Ok(())
        }
        Inverse::RemoveFile { path } => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        },
        Inverse::RemoveDirs { paths } => {
            for path in paths.iter().rev() {
                match std::fs::remove_dir(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(io::Error::new(
                            error.kind(),
                            format!("could not remove directory {}: {error}", path.display()),
                        ));
                    }
                }
            }
            Ok(())
        }
        Inverse::MoveBack { from, to } => {
            if path_exists(from) {
                if let Some(parent) = to.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                move_file(from, to)
            } else if path_exists(to) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "cannot restore {}: both {} and its backup are missing",
                        to.display(),
                        from.display()
                    ),
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

fn take_snapshot(
    action_id: &str,
    index: usize,
    source: &Path,
    snapshot_root: &Path,
) -> io::Result<PathBuf> {
    ensure_private_dir(snapshot_root)?;
    let base_name = snapshot_file_name(action_id, index, source);
    let target = unique_path(snapshot_root, &base_name);
    std::fs::copy(source, &target)?;
    restrict_file_permissions(&target);
    Ok(target)
}

fn snapshot_file_name(action_id: &str, index: usize, source: &Path) -> String {
    let leaf = source
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    format!(
        "{:04}-{}-{}.snapshot",
        index + 1,
        sanitize(action_id, 24),
        sanitize(&leaf, 80)
    )
}

fn trash_file_name(action_id: &str, index: usize, source: &Path) -> String {
    let leaf = source
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    format!(
        "{:04}-{}-{}.trashed",
        index + 1,
        sanitize(action_id, 24),
        sanitize(&leaf, 80)
    )
}

fn sanitize(text: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if out.chars().count() >= max {
            break;
        }
        out.push(
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            },
        );
    }
    if out.is_empty() {
        "item".to_string()
    } else {
        out
    }
}

fn unique_path(dir: &Path, base_name: &str) -> PathBuf {
    let mut target = dir.join(base_name);
    let mut counter = 1_usize;
    while path_exists(&target) {
        target = dir.join(format!("{base_name}.{counter}"));
        counter += 1;
    }
    target
}

/// True for any directory entry, including a dangling symlink.
fn path_exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

fn rotated_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".1");
    path.with_file_name(name)
}

fn ensure_private_dir(path: &Path) -> io::Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} exists and is not a directory", path.display()),
            ));
        }
    }
    let existed = path.is_dir();
    std::fs::create_dir_all(path)?;
    if !existed {
        restrict_dir_permissions(path);
    }
    Ok(())
}

fn move_file(from: &Path, to: &Path) -> io::Result<()> {
    if path_exists(to) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to overwrite existing {}", to.display()),
        ));
    }
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(rename_error) => {
            // A snapshot directory may sit on another volume. Fall back to a
            // copy-and-remove, and leave the original in place if either half
            // fails.
            match std::fs::copy(from, to) {
                Ok(_) => match std::fs::remove_file(from) {
                    Ok(()) => Ok(()),
                    Err(remove_error) => {
                        let _ = std::fs::remove_file(to);
                        Err(remove_error)
                    }
                },
                Err(_) => Err(rename_error),
            }
        }
    }
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) {}

#[cfg(unix)]
fn file_mode(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn file_mode(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

#[cfg(unix)]
fn restore_mode(path: &Path, mode: Option<u32>) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = mode {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
}

#[cfg(not(unix))]
fn restore_mode(_path: &Path, _mode: Option<u32>) {}

#[cfg(unix)]
fn restrict_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir_permissions(_path: &Path) {}

fn combine_errors(first: Option<String>, second: Option<String>) -> Option<String> {
    match (first, second) {
        (None, None) => None,
        (Some(first), None) => Some(first),
        (None, Some(second)) => Some(second),
        (Some(first), Some(second)) => Some(format!("{first}; {second}")),
    }
}

fn action_id(index: usize) -> String {
    format!("a{}", index + 1)
}

impl RepairAction {
    /// A short lowercase name for messages, matching [`RepairActionKind`].
    fn kind_name(&self) -> &'static str {
        match self.kind() {
            RepairActionKind::CreateDirectory => "create_directory",
            RepairActionKind::WriteFile => "write_file",
            RepairActionKind::MoveToTrash => "move_to_trash",
            RepairActionKind::RemoveStaleLock => "remove_stale_lock",
            RepairActionKind::RotateFile => "rotate_file",
            RepairActionKind::RepairConfig => "repair_config",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn policy(root: &Path, max_actions: usize, allow_delete: bool) -> RepairPolicy {
        RepairPolicy {
            allowed_roots: vec![root.to_path_buf()],
            max_actions,
            allow_delete,
        }
    }

    fn plan(id: &str, actions: Vec<RepairAction>) -> RepairPlan {
        RepairPlan {
            id: id.to_string(),
            actions,
            dry_run: false,
        }
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    fn read(path: &Path) -> Vec<u8> {
        std::fs::read(path).unwrap()
    }

    /// Files and directories under `root`, keyed by relative path. `None`
    /// marks a directory. Used to prove a dry run changed nothing.
    fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        let mut out = BTreeMap::new();
        walk(root, root, &mut out);
        out
    }

    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                out.insert(relative, None);
                walk(root, &path, out);
            } else {
                out.insert(relative, Some(std::fs::read(&path).unwrap()));
            }
        }
    }

    // -- dry run ----------------------------------------------------------

    #[test]
    fn dry_run_previews_every_action_and_leaves_the_tree_byte_identical() {
        let dir = dir();
        let root = dir.path();
        let config = root.join("config.toml");
        let log = root.join("daemon.log");
        let old = root.join("old.txt");
        let cache = root.join("cache");
        write(&config, b"[core]\nmodel = \"local\"\n");
        write(&log, b"log line\n");
        write(&old, b"old\n");

        let before = tree(root);
        let plan = plan(
            "preview",
            vec![
                RepairAction::CreateDirectory {
                    path: cache.clone(),
                },
                RepairAction::WriteFile {
                    path: cache.join("new.txt"),
                    contents: "new\n".to_string(),
                },
                RepairAction::WriteFile {
                    path: config.clone(),
                    contents: "[core]\nmodel = \"local\"\nfixed = true\n".to_string(),
                },
                RepairAction::RotateFile { path: log.clone() },
                RepairAction::MoveToTrash { path: old.clone() },
                RepairAction::RemoveStaleLock {
                    path: root.join("missing.lock"),
                },
            ],
        );

        let preview = dry_run(&plan, &policy(root, 16, true)).unwrap();
        assert_eq!(preview.plan_id, "preview");
        assert!(preview.dry_run);
        assert_eq!(preview.actions, 6);
        assert_eq!(preview.changes.len(), 6);
        assert_eq!(preview.changes[0].action_id, "a1");
        assert!(matches!(
            preview.changes[0].effect,
            PreviewEffect::Create { bytes: 0 }
        ));
        assert!(matches!(
            preview.changes[2].effect,
            PreviewEffect::Overwrite { .. }
        ));
        assert!(matches!(
            preview.changes[3].effect,
            PreviewEffect::Rotate { .. }
        ));
        assert!(matches!(
            preview.changes[4].effect,
            PreviewEffect::Remove { .. }
        ));
        assert_eq!(preview.already_applied, vec!["a6".to_string()]);
        assert!(preview
            .would_snapshot
            .iter()
            .any(|path| path.ends_with("config.toml")));
        assert!(preview
            .would_snapshot
            .iter()
            .any(|path| path.ends_with("old.txt")));
        assert!(preview
            .would_snapshot
            .iter()
            .any(|path| path.ends_with("daemon.log")));

        // Byte-identical, including directory entries: the preview created
        // nothing.
        assert_eq!(tree(root), before);
        assert!(!cache.exists());
    }

    #[test]
    fn dry_run_reports_a_conflict_without_failing_the_rest() {
        let dir = dir();
        let root = dir.path();
        let adir = root.join("adir");
        std::fs::create_dir_all(&adir).unwrap();
        let target = root.join("target.txt");
        write(&target, b"keep\n");

        let plan = plan(
            "conflict",
            vec![
                RepairAction::WriteFile {
                    path: adir,
                    contents: "x".to_string(),
                },
                RepairAction::WriteFile {
                    path: target,
                    contents: "changed\n".to_string(),
                },
            ],
        );
        let preview = dry_run(&plan, &policy(root, 16, false)).unwrap();
        assert!(matches!(
            preview.changes[0].effect,
            PreviewEffect::Conflict { .. }
        ));
        assert!(matches!(
            preview.changes[1].effect,
            PreviewEffect::Overwrite { .. }
        ));
    }

    // -- apply ------------------------------------------------------------

    #[test]
    fn apply_writes_moves_and_records_snapshot_paths() {
        let dir = dir();
        let root = dir.path();
        let config = root.join("config.toml");
        let log = root.join("daemon.log");
        let old = root.join("old.txt");
        let cache = root.join("cache");
        let snapshots = root.join("snapshots");
        write(&config, b"[core]\nmodel = \"local\"\n");
        write(&log, b"log line\n");
        write(&old, b"old\n");

        let plan = plan(
            "apply",
            vec![
                RepairAction::CreateDirectory {
                    path: cache.clone(),
                },
                RepairAction::WriteFile {
                    path: cache.join("new.txt"),
                    contents: "new\n".to_string(),
                },
                RepairAction::RepairConfig {
                    path: config.clone(),
                    contents: "[core]\nmodel = \"local\"\nfixed = true\n".to_string(),
                },
                RepairAction::RotateFile { path: log.clone() },
                RepairAction::MoveToTrash { path: old.clone() },
            ],
        );

        let report = apply(&plan, &policy(root, 16, true), &snapshots).unwrap();
        assert_eq!(report.plan_id, "apply");
        assert_eq!(report.applied.len(), 5);
        assert!(report.already_applied.is_empty());
        assert!(!report.snapshots.is_empty());
        assert_eq!(report.applied[0].id, "a1");
        assert_eq!(report.applied[0].kind, RepairActionKind::CreateDirectory);

        assert_eq!(read(&cache.join("new.txt")), b"new\n");
        assert_eq!(read(&config), b"[core]\nmodel = \"local\"\nfixed = true\n");
        assert_eq!(read(&root.join("daemon.log.1")), b"log line\n");
        assert!(!log.exists());
        assert!(!old.exists());

        let snapshot_root = std::fs::canonicalize(&snapshots).unwrap();
        for snapshot in &report.snapshots {
            assert!(snapshot.snapshot.is_file(), "{snapshot:?}");
            assert!(
                snapshot.snapshot.starts_with(&snapshot_root),
                "{snapshot:?}"
            );
        }
        let config_snapshot = report
            .snapshots
            .iter()
            .find(|snapshot| snapshot.path.ends_with("config.toml"))
            .expect("config snapshot");
        assert_eq!(
            read(&config_snapshot.snapshot),
            b"[core]\nmodel = \"local\"\n"
        );

        // Reports carry paths only, never file bodies.
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("fixed = true"), "{json}");
        assert!(!json.contains("log line"), "{json}");
    }

    #[test]
    fn a_failed_action_rolls_back_the_earlier_write_byte_for_byte() {
        let dir = dir();
        let root = dir.path();
        let target = root.join("target.txt");
        let blocker = root.join("blocker");
        let snapshots = root.join("snapshots");
        write(&target, b"original bytes\n");
        write(&blocker, b"not a directory\n");

        let plan = plan(
            "fail",
            vec![
                RepairAction::WriteFile {
                    path: target.clone(),
                    contents: "changed\n".to_string(),
                },
                RepairAction::WriteFile {
                    path: blocker.join("child.txt"),
                    contents: "x".to_string(),
                },
            ],
        );

        let error = apply(&plan, &policy(root, 16, false), &snapshots).unwrap_err();
        match &error {
            RepairError::Apply { rolled_back, .. } => assert_eq!(*rolled_back, 1, "{error}"),
            other => panic!("unexpected error: {other}"),
        }
        assert!(error.to_string().contains("rolled back"), "{error}");
        assert_eq!(read(&target), b"original bytes\n");
        assert!(blocker.is_file());
        assert!(!blocker.join("child.txt").exists());
    }

    #[test]
    fn a_target_that_became_a_directory_rolls_back_the_earlier_write() {
        let dir = dir();
        let root = dir.path();
        let target = root.join("target.txt");
        let became_dir = root.join("became-dir");
        let snapshots = root.join("snapshots");
        write(&target, b"original\n");
        std::fs::create_dir_all(&became_dir).unwrap();

        let plan = plan(
            "fail-dir",
            vec![
                RepairAction::WriteFile {
                    path: target.clone(),
                    contents: "changed\n".to_string(),
                },
                RepairAction::WriteFile {
                    path: became_dir.clone(),
                    contents: "x".to_string(),
                },
            ],
        );

        let error = apply(&plan, &policy(root, 16, false), &snapshots).unwrap_err();
        assert!(matches!(error, RepairError::Apply { .. }), "{error}");
        assert_eq!(read(&target), b"original\n");
        assert!(became_dir.is_dir());
    }

    #[test]
    fn repeated_apply_reports_already_applied_without_corruption() {
        let dir = dir();
        let root = dir.path();
        let config = root.join("config.toml");
        let log = root.join("daemon.log");
        let old = root.join("old.txt");
        let lock = root.join("stale.lock");
        let cache = root.join("cache");
        let snapshots = root.join("snapshots");
        write(&config, b"[core]\nmodel = \"local\"\n");
        write(&log, b"log line\n");
        write(&old, b"old\n");
        write(&lock, b"lock\n");

        let plan = plan(
            "idempotent",
            vec![
                RepairAction::CreateDirectory {
                    path: cache.clone(),
                },
                RepairAction::WriteFile {
                    path: cache.join("new.txt"),
                    contents: "new\n".to_string(),
                },
                RepairAction::RepairConfig {
                    path: config.clone(),
                    contents: "[core]\nmodel = \"local\"\nfixed = true\n".to_string(),
                },
                RepairAction::RotateFile { path: log.clone() },
                RepairAction::MoveToTrash { path: old.clone() },
                RepairAction::RemoveStaleLock { path: lock.clone() },
            ],
        );

        let first = apply(&plan, &policy(root, 16, true), &snapshots).unwrap();
        assert_eq!(first.applied.len(), 6);
        assert!(!lock.exists());
        let after_first = tree(root);

        let second = apply(&plan, &policy(root, 16, true), &snapshots).unwrap();
        assert!(second.applied.is_empty(), "{second:?}");
        assert_eq!(
            second.already_applied,
            vec![
                "a1".to_string(),
                "a2".to_string(),
                "a3".to_string(),
                "a4".to_string(),
                "a5".to_string(),
                "a6".to_string(),
            ]
        );
        assert_eq!(tree(root), after_first);
        assert_eq!(read(&cache.join("new.txt")), b"new\n");
        assert_eq!(read(&config), b"[core]\nmodel = \"local\"\nfixed = true\n");
        assert_eq!(read(&root.join("daemon.log.1")), b"log line\n");
        assert!(!old.exists());
        assert!(!lock.exists());
    }

    // -- rollback ---------------------------------------------------------

    #[test]
    fn explicit_rollback_restores_every_action() {
        let dir = dir();
        let root = dir.path();
        let config = root.join("config.toml");
        let old = root.join("old.txt");
        let lock = root.join("stale.lock");
        let log = root.join("daemon.log");
        let newdir = root.join("newdir");
        let snapshots = root.join("snapshots");
        write(&config, b"[core]\nmodel = \"local\"\n");
        write(&old, b"old\n");
        write(&lock, b"lock\n");
        write(&log, b"log line\n");

        let plan = plan(
            "rollback",
            vec![
                RepairAction::CreateDirectory {
                    path: newdir.clone(),
                },
                RepairAction::WriteFile {
                    path: newdir.join("a.txt"),
                    contents: "a\n".to_string(),
                },
                RepairAction::RepairConfig {
                    path: config.clone(),
                    contents: "[core]\nmodel = \"local\"\nfixed = true\n".to_string(),
                },
                RepairAction::MoveToTrash { path: old.clone() },
                RepairAction::RemoveStaleLock { path: lock.clone() },
                RepairAction::RotateFile { path: log.clone() },
            ],
        );

        let report = apply(&plan, &policy(root, 16, true), &snapshots).unwrap();
        assert_eq!(report.applied.len(), 6);
        assert_eq!(report.inverse_len(), 6);
        assert!(!old.exists());
        assert!(!lock.exists());
        assert!(!log.exists());

        rollback(&report).unwrap();
        assert!(!newdir.exists(), "created directory removed");
        assert_eq!(read(&config), b"[core]\nmodel = \"local\"\n");
        assert_eq!(read(&old), b"old\n");
        assert_eq!(read(&lock), b"lock\n");
        assert_eq!(read(&log), b"log line\n");
        assert!(!root.join("daemon.log.1").exists());
        assert!(snapshots.is_dir(), "snapshots are evidence and stay");
    }

    #[cfg(unix)]
    #[test]
    fn rollback_restores_the_original_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = dir();
        let root = dir.path();
        let key = root.join("key");
        write(&key, b"key-material");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();

        let plan = plan(
            "mode",
            vec![RepairAction::WriteFile {
                path: key.clone(),
                contents: "replacement".to_string(),
            }],
        );
        let report = apply(&plan, &policy(root, 4, false), root.join("snapshots")).unwrap();
        rollback(&report).unwrap();

        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "the snapshot copy must not leak its own mode");
        assert_eq!(read(&key), b"key-material");
    }

    #[test]
    fn rollback_refuses_a_report_without_its_inverse_log() {
        let dir = dir();
        let root = dir.path();
        let target = root.join("target.txt");
        let snapshots = root.join("snapshots");
        write(&target, b"original\n");

        let plan = plan(
            "serde",
            vec![RepairAction::WriteFile {
                path: target,
                contents: "changed\n".to_string(),
            }],
        );
        let report = apply(&plan, &policy(root, 16, false), &snapshots).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let rebuilt: RepairReport = serde_json::from_str(&json).unwrap();
        assert!(rebuilt.inverse_len() == 0);
        let error = rollback(&rebuilt).unwrap_err();
        assert!(matches!(error, RepairError::Rollback { .. }), "{error}");
    }

    #[test]
    fn rollback_reports_a_missing_snapshot() {
        let dir = dir();
        let root = dir.path();
        let target = root.join("target.txt");
        let snapshots = root.join("snapshots");
        write(&target, b"original\n");

        let plan = plan(
            "missing-snapshot",
            vec![RepairAction::WriteFile {
                path: target.clone(),
                contents: "changed\n".to_string(),
            }],
        );
        let report = apply(&plan, &policy(root, 16, false), &snapshots).unwrap();
        let snapshot = report.snapshots[0].snapshot.clone();
        std::fs::remove_file(&snapshot).unwrap();

        let error = rollback(&report).unwrap_err();
        assert!(matches!(error, RepairError::Rollback { .. }), "{error}");
        assert_eq!(read(&target), b"changed\n");
    }

    // -- policy -----------------------------------------------------------

    #[test]
    fn a_path_outside_the_allowed_roots_is_refused_before_any_mutation() {
        let dir = dir();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let target = root.join("target.txt");
        write(&target, b"keep\n");

        let plan = plan(
            "escape",
            vec![
                RepairAction::WriteFile {
                    path: target.clone(),
                    contents: "changed\n".to_string(),
                },
                RepairAction::WriteFile {
                    path: outside.join("file.txt"),
                    contents: "x".to_string(),
                },
            ],
        );

        let error = apply(&plan, &policy(&root, 16, false), root.join("snapshots")).unwrap_err();
        assert!(matches!(error, RepairError::Policy { .. }), "{error}");
        assert_eq!(
            read(&target),
            b"keep\n",
            "pre-flight refused the whole plan"
        );
        assert!(!outside.join("file.txt").exists());
    }

    #[test]
    fn a_parent_directory_escape_is_refused() {
        let dir = dir();
        let root = dir.path();
        let escape = root.join("sub").join("..").join("..").join("escape.txt");
        let plan = plan(
            "dotdot",
            vec![RepairAction::WriteFile {
                path: escape,
                contents: "x".to_string(),
            }],
        );

        let error = dry_run(&plan, &policy(root, 16, false)).unwrap_err();
        assert!(matches!(error, RepairError::Policy { .. }), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_escape_is_refused() {
        use std::os::unix::fs::symlink;

        let dir = dir();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        write(&outside.join("secret.txt"), b"secret\n");
        symlink(&outside, root.join("link")).unwrap();

        let through_dir = plan(
            "symlink-dir",
            vec![RepairAction::WriteFile {
                path: root.join("link").join("new.txt"),
                contents: "x".to_string(),
            }],
        );
        let error = dry_run(&through_dir, &policy(&root, 16, false)).unwrap_err();
        assert!(matches!(error, RepairError::Policy { .. }), "{error}");
        assert!(!outside.join("new.txt").exists());

        symlink(outside.join("secret.txt"), root.join("file.txt")).unwrap();
        let through_file = plan(
            "symlink-file",
            vec![RepairAction::WriteFile {
                path: root.join("file.txt"),
                contents: "x".to_string(),
            }],
        );
        let error = dry_run(&through_file, &policy(&root, 16, false)).unwrap_err();
        assert!(matches!(error, RepairError::Policy { .. }), "{error}");
        assert_eq!(read(&outside.join("secret.txt")), b"secret\n");
    }

    #[test]
    fn deletion_requires_allow_delete() {
        let dir = dir();
        let root = dir.path();
        let old = root.join("old.txt");
        let lock = root.join("stale.lock");
        write(&old, b"old\n");
        write(&lock, b"lock\n");

        let plan = plan(
            "delete",
            vec![
                RepairAction::MoveToTrash { path: old.clone() },
                RepairAction::RemoveStaleLock { path: lock.clone() },
            ],
        );
        let error = apply(&plan, &policy(root, 16, false), root.join("snapshots")).unwrap_err();
        assert!(matches!(error, RepairError::Policy { .. }), "{error}");
        assert!(old.is_file(), "a refused plan mutates nothing");
        assert!(lock.is_file());

        let report = apply(&plan, &policy(root, 16, true), root.join("snapshots")).unwrap();
        assert_eq!(report.applied.len(), 2);
        assert!(!old.exists());
        assert!(!lock.exists());
    }

    #[test]
    fn max_actions_bounds_the_plan() {
        let dir = dir();
        let root = dir.path();
        let target = root.join("target.txt");
        write(&target, b"keep\n");

        let plan = plan(
            "too-many",
            vec![
                RepairAction::WriteFile {
                    path: target.clone(),
                    contents: "changed\n".to_string(),
                },
                RepairAction::CreateDirectory {
                    path: root.join("cache"),
                },
            ],
        );
        let error = apply(&plan, &policy(root, 1, false), root.join("snapshots")).unwrap_err();
        assert!(
            matches!(error, RepairError::TooManyActions { max: 1, .. }),
            "{error}"
        );
        assert_eq!(read(&target), b"keep\n");
        assert!(!root.join("cache").exists());
    }

    #[test]
    fn the_snapshot_directory_must_be_inside_an_allowed_root() {
        let dir = dir();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let target = root.join("target.txt");
        write(&target, b"keep\n");

        let plan = plan(
            "snapshot-escape",
            vec![RepairAction::WriteFile {
                path: target.clone(),
                contents: "changed\n".to_string(),
            }],
        );
        let error = apply(&plan, &policy(&root, 16, false), outside.join("snapshots")).unwrap_err();
        assert!(matches!(error, RepairError::Policy { .. }), "{error}");
        assert_eq!(read(&target), b"keep\n");
        assert!(!outside.join("snapshots").exists());
    }

    #[test]
    fn an_action_may_not_remove_the_snapshot_directory() {
        let dir = dir();
        let root = dir.path();
        let snapshots = root.join("snapshots");
        std::fs::create_dir_all(&snapshots).unwrap();
        write(&snapshots.join("keep.txt"), b"keep\n");

        let plan = plan(
            "overlap",
            vec![RepairAction::MoveToTrash {
                path: snapshots.clone(),
            }],
        );
        let error = apply(&plan, &policy(root, 16, true), &snapshots).unwrap_err();
        assert!(matches!(error, RepairError::Policy { .. }), "{error}");
        assert!(snapshots.is_dir());
    }

    #[test]
    fn an_empty_allowed_root_list_refuses_every_plan() {
        let dir = dir();
        let root = dir.path();
        let plan = plan(
            "no-roots",
            vec![RepairAction::CreateDirectory {
                path: root.join("cache"),
            }],
        );
        let policy = RepairPolicy {
            allowed_roots: Vec::new(),
            max_actions: 16,
            allow_delete: false,
        };
        let error = dry_run(&plan, &policy).unwrap_err();
        assert!(matches!(error, RepairError::Policy { .. }), "{error}");
    }

    #[test]
    fn apply_refuses_a_plan_marked_dry_run() {
        let dir = dir();
        let root = dir.path();
        let target = root.join("target.txt");
        write(&target, b"keep\n");

        let mut plan = plan(
            "dry",
            vec![RepairAction::WriteFile {
                path: target.clone(),
                contents: "changed\n".to_string(),
            }],
        );
        plan.dry_run = true;

        let error = apply(&plan, &policy(root, 16, false), root.join("snapshots")).unwrap_err();
        assert!(matches!(error, RepairError::DryRunPlan { .. }), "{error}");
        assert_eq!(read(&target), b"keep\n");
    }

    #[test]
    fn contents_are_bounded_and_may_not_carry_secrets() {
        let dir = dir();
        let root = dir.path();
        let oversized = "x".repeat(MAX_CONTENTS_BYTES + 1);
        let big = plan(
            "big",
            vec![RepairAction::WriteFile {
                path: root.join("big.txt"),
                contents: oversized,
            }],
        );
        let error = dry_run(&big, &policy(root, 16, false)).unwrap_err();
        assert!(
            matches!(error, RepairError::InvalidAction { .. }),
            "{error}"
        );

        for secret in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "sk-live-abcdef",
            "ghp_abcdef",
            "Bearer abcdef",
        ] {
            let plan = plan(
                "secret",
                vec![RepairAction::WriteFile {
                    path: root.join("secret.txt"),
                    contents: secret.to_string(),
                }],
            );
            let error = dry_run(&plan, &policy(root, 16, false)).unwrap_err();
            assert!(
                matches!(error, RepairError::InvalidAction { .. }),
                "{secret}: {error}"
            );
        }
        assert!(!root.join("big.txt").exists());
        assert!(!root.join("secret.txt").exists());
    }

    #[test]
    fn repaired_config_must_parse_as_toml_before_anything_changes() {
        let dir = dir();
        let root = dir.path();
        let config = root.join("config.toml");
        write(&config, b"[core]\nmodel = \"local\"\n");

        let plan = plan(
            "bad-config",
            vec![RepairAction::RepairConfig {
                path: config.clone(),
                contents: "[core\n".to_string(),
            }],
        );
        let error = apply(&plan, &policy(root, 16, false), root.join("snapshots")).unwrap_err();
        assert!(
            matches!(error, RepairError::InvalidAction { .. }),
            "{error}"
        );
        assert_eq!(read(&config), b"[core]\nmodel = \"local\"\n");
    }

    #[test]
    fn remove_stale_lock_only_accepts_lock_paths() {
        let dir = dir();
        let root = dir.path();
        let plan = plan(
            "not-a-lock",
            vec![RepairAction::RemoveStaleLock {
                path: root.join("not-a-lock.txt"),
            }],
        );
        let error = dry_run(&plan, &policy(root, 16, true)).unwrap_err();
        assert!(
            matches!(error, RepairError::InvalidAction { .. }),
            "{error}"
        );
    }
}
