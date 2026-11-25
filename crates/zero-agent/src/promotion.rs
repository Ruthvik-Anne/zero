//! Promotion and rollback (SI-03, SI-06, SI-07, SI-09; T-SI-03).
//!
//! The self-improvement loop ends at a [`crate::self_improve::Promotion`] value;
//! this module is the only path from that value to a changed tree:
//!
//! ```text
//! LoopDecision::Accepted -> immutable-core check -> render diff -> human gate
//!                        -> apply (snapshot) -> rollback
//! ```
//!
//! Four properties are enforced here, not documented elsewhere:
//!
//! - **Immutable core (SI-06).** [`ImmutableCore`] refuses any candidate whose
//!   change set names a protected path. Paths are normalized with
//!   [`crate::eval_suite::safe_relative_path`] first, so `..`, absolute paths,
//!   drive prefixes, empty components, and NUL are refused before the protected
//!   list is consulted. A target root is required to follow symlinks, which is
//!   why [`ImmutableCore::check_under`] exists next to
//!   [`ImmutableCore::check`].
//! - **Human gate (SI-07).** [`approve_promotion`] takes a [`HumanGate`] seam
//!   and an accepted [`LoopState`]. The gate is handed the exact diff hash and
//!   returns an [`Approval`] bound to it. No caller can mint an
//!   [`ApprovedPromotion`] without that seam, so the agent has no self-approval
//!   route: [`apply_promotion`] only accepts the sealed value.
//! - **Diff (SI-03, SI-09).** [`render_diff`] is a deterministic unified-style
//!   diff over the candidate files only, bounded in size and free of
//!   timestamps, prompts, and proposal prose.
//! - **Reversibility (SI-09).** [`apply_promotion`] snapshots every existing
//!   file before it writes, rolls the whole batch back on any failure, and
//!   [`rollback`] restores the snapshots and removes files the promotion
//!   created. A rollback refuses to overwrite a tree that changed after the
//!   promotion unless the caller passes [`rollback_forced`].
//!
//! # Offline
//!
//! The module performs filesystem work only. It holds no provider, router, or
//! socket type; a test scans its source for those names.
//!
//! # Naming
//!
//! [`crate::self_improve::HumanGate`] is the loop's *record* of the decision a
//! human still owes. The trait here is the *seam* that produces that decision.
//! The crate root re-exports this one as `HumanApprovalGate` to keep both names
//! unambiguous.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::eval_suite::safe_relative_path;
use crate::self_improve::{
    promote, validate_proposal, ChangeSet, LoopLimits, LoopState, MAX_CHANGE_BYTES,
    MAX_CHANGE_FILE_BYTES,
};

/// Domain separator mixed into the diff bytes before hashing.
pub const DIFF_HASH_PREFIX: &str = "zero.si-diff.v1";
/// Upper bound on a rendered diff, in bytes. A truncated diff ends with a
/// marker line and is still hashed as-is.
pub const MAX_DIFF_BYTES: usize = 1_048_576;
/// Upper bound on the bytes snapshotted into a backup, in total.
pub const MAX_BACKUP_BYTES: u64 = 1_048_576;
/// Upper bound on snapshotted files in one promotion.
pub const MAX_BACKUP_FILES: usize = crate::self_improve::MAX_CHANGE_FILES;
/// Upper bound on a human denial reason retained in an error.
pub const MAX_REASON_BYTES: usize = 1_024;

/// Paths a candidate may never touch (SI-06).
///
/// A trailing `/` marks a directory subtree; every other entry is one file.
/// The list covers the evaluator and its harness, the promotion rules
/// themselves, policy (mode, deletion, protected paths, approvals, the
/// regulator), the audit log, and credential handling.
pub const DEFAULT_PROTECTED_PATHS: &[&str] = &[
    "crates/zero-agent/src/eval_suite.rs",
    "crates/zero-agent/src/self_improve.rs",
    "crates/zero-agent/src/promotion.rs",
    "crates/zero-agent/src/audit.rs",
    "crates/zero-policy/src/",
    "crates/zero-secrets/src/",
];

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn need_approval(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyAskRequired, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn tampered(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::TamperDetected, message)
}

// ---------------------------------------------------------------------------
// Immutable core (SI-06)
// ---------------------------------------------------------------------------

/// The set of paths a self-improvement candidate may not change.
///
/// The protected list is private: there is no accessor that hands out a
/// mutable slice, so in-process callers cannot widen the core without building
/// a new value through [`ImmutableCore::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableCore {
    protected: Vec<String>,
}

impl Default for ImmutableCore {
    fn default() -> Self {
        Self::new(
            DEFAULT_PROTECTED_PATHS
                .iter()
                .map(|path| (*path).to_string()),
        )
        .expect("the default protected paths are valid relative paths")
    }
}

impl ImmutableCore {
    /// Build a core from validated relative paths. A trailing `/` (or `\`)
    /// marks a directory subtree.
    pub fn new(protected: impl IntoIterator<Item = String>) -> Result<Self> {
        let protected: Vec<String> = protected.into_iter().collect();
        if protected.is_empty() {
            return Err(invalid("an immutable core protects at least one path"));
        }
        for entry in &protected {
            normalize_protected_entry(entry)?;
        }
        Ok(Self { protected })
    }

    /// The protected entries as configured. Read-only.
    pub fn protected(&self) -> &[String] {
        &self.protected
    }

    /// True when `relative` is protected. The path is compared with `/`
    /// separators and ASCII case folded, so Windows paths cannot slip past an
    /// exact-case entry.
    pub fn is_protected(&self, relative: &Path) -> bool {
        let key = relative_key(relative);
        self.protected.iter().any(|entry| {
            let Ok((protected, is_dir)) = normalize_protected_entry(entry) else {
                return false;
            };
            if is_dir {
                key == protected || key.starts_with(&format!("{protected}/"))
            } else {
                key == protected
            }
        })
    }

    /// Refuse a change set that touches the core (SI-06).
    ///
    /// Every path is normalized first: `..`, absolute paths, drive prefixes,
    /// empty components, and NUL are `InvalidInput`; a normalized path that is
    /// protected is `zero.pol.denied`. This is the Done criterion for T-SI-03:
    /// a candidate touching the evaluator is refused.
    pub fn check(&self, change: &ChangeSet) -> Result<()> {
        for path in change.files.keys() {
            let relative = safe_change_path(path)?;
            if self.is_protected(&relative) {
                return Err(denied(format!(
                    "change `{path}` touches the immutable core; promotion is refused (SI-06)"
                )));
            }
        }
        Ok(())
    }

    /// [`ImmutableCore::check`] plus symlink resolution under `root`.
    ///
    /// A path component that already exists and is a symlink, and an existing
    /// target that is a symlink, are both refused with `zero.pol.denied`. A
    /// component that does not exist yet stops the walk: promotion creates it
    /// later and re-checks each step.
    pub fn check_under(&self, change: &ChangeSet, root: &Path) -> Result<()> {
        self.check(change)?;
        let root = canonical_dir(root, "promotion target root")?;
        for path in change.files.keys() {
            let relative = safe_change_path(path)?;
            let mut current = root.clone();
            for component in relative.components() {
                let Component::Normal(name) = component else {
                    return Err(invalid(format!("change path `{path}` is not relative")));
                };
                current.push(name);
                match std::fs::symlink_metadata(&current) {
                    Ok(metadata) => {
                        if metadata.file_type().is_symlink() {
                            return Err(denied(format!(
                                "change path `{path}` passes through a symlink; promotion is refused"
                            )));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(())
    }
}

fn normalize_protected_entry(entry: &str) -> Result<(String, bool)> {
    let is_dir = entry.ends_with('/') || entry.ends_with('\\');
    let trimmed = entry.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        return Err(invalid("a protected path entry is not empty"));
    }
    let relative = safe_relative_path(trimmed)?;
    Ok((relative_key(&relative), is_dir))
}

/// Canonical comparison key: `/` separators, ASCII lower case.
fn relative_key(relative: &Path) -> String {
    relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// A candidate path: [`safe_relative_path`] plus a control-character refusal so
/// a path can never inject a line into the rendered diff.
fn safe_change_path(path: &str) -> Result<PathBuf> {
    let relative = safe_relative_path(path)?;
    for component in relative.components() {
        if let Component::Normal(name) = component {
            if name.to_string_lossy().chars().any(char::is_control) {
                return Err(invalid(format!(
                    "change path `{path}` contains a control character"
                )));
            }
        }
    }
    Ok(relative)
}

// ---------------------------------------------------------------------------
// Diff (SI-03, SI-09)
// ---------------------------------------------------------------------------

/// Render a deterministic unified-style diff for `change`.
///
/// The old side is empty: a [`ChangeSet`] carries only the candidate contents,
/// so every line is an addition from `/dev/null`. The header lines are
/// `--- a/<path>` and `+++ b/<path>` with no timestamps. Only file paths and
/// file contents are emitted; the change description and proposal prose never
/// reach the diff.
///
/// Output is bounded by [`MAX_DIFF_BYTES`]. When the cap is hit the diff ends
/// with a marker line and nothing after it.
pub fn render_diff(change: &ChangeSet) -> String {
    let mut out = String::new();
    let mut truncated = false;
    for (path, contents) in &change.files {
        let mut block = String::new();
        let header_path: String = path
            .chars()
            .map(|character| {
                if character.is_control() {
                    '?'
                } else {
                    character
                }
            })
            .collect();
        block.push_str(&format!("--- a/{header_path}\n+++ b/{header_path}\n"));
        let lines = contents.split_inclusive('\n').count();
        if lines == 0 {
            block.push_str("@@ -0,0 +0,0 @@\n");
        } else {
            block.push_str(&format!("@@ -0,0 +1,{lines} @@\n"));
        }
        for chunk in contents.split_inclusive('\n') {
            block.push('+');
            block.push_str(chunk);
            if !chunk.ends_with('\n') {
                block.push_str("\n\\ No newline at end of file\n");
            }
        }
        if out.len() + block.len() > MAX_DIFF_BYTES {
            truncated = true;
            break;
        }
        out.push_str(&block);
    }
    if truncated {
        let marker = "--- diff truncated at the byte cap ---\n";
        if out.len() + marker.len() <= MAX_DIFF_BYTES {
            out.push_str(marker);
        }
    }
    out
}

/// BLAKE3 over the versioned diff bytes, lowercase hex. The human approval is
/// bound to this value.
pub fn diff_hash(change: &ChangeSet) -> String {
    let mut bytes = Vec::with_capacity(4_096);
    bytes.extend_from_slice(DIFF_HASH_PREFIX.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(render_diff(change).as_bytes());
    blake3::hash(&bytes).to_hex().to_string()
}

// ---------------------------------------------------------------------------
// Human gate (SI-07)
// ---------------------------------------------------------------------------

/// The human decision for one proposal and one exact diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Approval {
    /// A named human approved the diff identified by `diff_hash`.
    Approved {
        by: String,
        at_ms: i64,
        /// The diff the approval is bound to. A value other than the current
        /// diff hash is refused, so an old approval cannot be replayed.
        diff_hash: String,
    },
    /// The human refused; `reason` is bounded and recorded.
    Denied { reason: String },
}

/// The human-approval seam.
///
/// An implementation lives in the host surface (TUI modal, daemon, or headless
/// queue). The agent has no implementation it can reach: it can call
/// [`approve_promotion`] only with a gate supplied by its caller.
pub trait HumanGate {
    fn approve(&self, proposal_id: &str, diff_hash: &str) -> Approval;
}

mod seal {
    /// A zero-sized token no external module can name, which seals
    /// [`super::ApprovedPromotion`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct ApprovalToken;
}

/// The only value [`apply_promotion`] accepts.
///
/// Fields are private and the constructor is private to this module, so the
/// type can be minted only by [`approve_promotion`] after the gate, the
/// immutable-core check, and the diff binding all pass. A loop
/// [`crate::self_improve::Promotion`] with `approved: true` is not this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedPromotion {
    proposal_id: String,
    change: ChangeSet,
    diff: String,
    diff_hash: String,
    approved_by: String,
    approved_at_ms: i64,
    _token: seal::ApprovalToken,
}

impl ApprovedPromotion {
    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }

    pub fn change(&self) -> &ChangeSet {
        &self.change
    }

    pub fn diff(&self) -> &str {
        &self.diff
    }

    pub fn diff_hash(&self) -> &str {
        &self.diff_hash
    }

    pub fn approved_by(&self) -> &str {
        &self.approved_by
    }

    pub fn approved_at_ms(&self) -> i64 {
        self.approved_at_ms
    }
}

/// Turn an accepted loop state into an [`ApprovedPromotion`], or refuse.
///
/// Order of refusal:
///
/// 1. the proposal must be internally consistent (`zero.fnd.tamper`/invalid);
/// 2. the immutable-core check (SI-06) — `zero.pol.denied`;
/// 3. the decision must be `Accepted` with both evaluation reports
///    (`zero.pol.denied`);
/// 4. the gate must return `Approved` for this proposal and this diff hash.
///    `Denied` is `zero.pol.denied`; an approval bound to a different diff, or
///    one that names no approver, is `zero.pol.ask` because a fresh human
///    decision is required.
pub fn approve_promotion(state: &LoopState, gate: &dyn HumanGate) -> Result<ApprovedPromotion> {
    validate_proposal(&state.proposal, LoopLimits::default())?;
    let change = &state.proposal.change;

    ImmutableCore::default().check(change)?;

    if !promote(state).approved {
        return Err(denied(
            "only an accepted candidate with both evaluation reports may be promoted",
        ));
    }

    let diff = render_diff(change);
    let hash = diff_hash(change);
    match gate.approve(&state.proposal.id, &hash) {
        Approval::Denied { reason } => Err(denied(format!(
            "the human gate denied the promotion: {}",
            bounded(&reason, MAX_REASON_BYTES)
        ))),
        Approval::Approved {
            by,
            at_ms,
            diff_hash,
        } => {
            if diff_hash != hash {
                return Err(need_approval(
                    "the human approval is bound to a different diff; request a fresh approval",
                ));
            }
            let by = by.trim();
            if by.is_empty() {
                return Err(need_approval(
                    "the human approval names no approver; request a fresh approval",
                ));
            }
            Ok(ApprovedPromotion {
                proposal_id: state.proposal.id.clone(),
                change: change.clone(),
                diff,
                diff_hash: hash,
                approved_by: by.to_string(),
                approved_at_ms: at_ms,
                _token: seal::ApprovalToken,
            })
        }
    }
}

fn bounded(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

// ---------------------------------------------------------------------------
// Apply and rollback (SI-09)
// ---------------------------------------------------------------------------

/// One file the promotion wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedFile {
    /// Relative path inside the target root.
    pub path: String,
    /// True when a file existed before the promotion and was snapshotted.
    pub existed: bool,
    /// BLAKE3 of the previous content, when it existed.
    pub previous_hash: Option<String>,
    /// BLAKE3 of the content the promotion wrote.
    pub promoted_hash: String,
    /// Bytes written.
    pub bytes: u64,
    /// Snapshot file name inside the backup directory, when it existed.
    pub backup_file: Option<String>,
}

/// A successful promotion. Fields are private and the type is deliberately not
/// `Deserialize`, so the record can only be produced by [`apply_promotion`];
/// read it through the accessors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppliedPromotion {
    proposal_id: String,
    files: Vec<AppliedFile>,
    backup_dir: PathBuf,
    diff_hash: String,
    target_root: PathBuf,
    applied_at_ms: i64,
}

impl AppliedPromotion {
    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }

    pub fn files(&self) -> &[AppliedFile] {
        &self.files
    }

    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    pub fn diff_hash(&self) -> &str {
        &self.diff_hash
    }

    pub fn target_root(&self) -> &Path {
        &self.target_root
    }

    pub fn applied_at_ms(&self) -> i64 {
        self.applied_at_ms
    }
}

/// What a rollback changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReport {
    pub proposal_id: String,
    /// Files restored from their snapshot, in reverse promotion order.
    pub restored: Vec<String>,
    /// Files removed because the promotion created them.
    pub removed: Vec<String>,
    /// True when `force` allowed a changed target to be overwritten.
    pub forced: bool,
}

/// Apply an approved promotion under `target_root`, snapshotting into
/// `backup_root`.
///
/// Every path is validated with [`safe_relative_path`], the immutable core is
/// re-checked under the canonical root, and each existing file is snapshotted
/// before it is replaced. New files are written with `create_new`; replacements
/// use a same-directory temp file and an atomic rename.
///
/// On any failure the applied files are restored and the created files are
/// removed in reverse order; the returned error names the rollback outcome and
/// keeps the original error code.
pub fn apply_promotion(
    approved: &ApprovedPromotion,
    target_root: &Path,
    backup_root: &Path,
    now_ms: i64,
) -> Result<AppliedPromotion> {
    if diff_hash(&approved.change) != approved.diff_hash {
        return Err(tampered(
            "the approved diff hash does not match the change set; refusing to apply",
        ));
    }
    let root = canonical_dir(target_root, "promotion target root")?;
    let core = ImmutableCore::default();
    core.check_under(&approved.change, &root)?;
    validate_apply_bounds(&approved.change)?;

    std::fs::create_dir_all(backup_root)?;
    let backup_root = canonical_dir(backup_root, "promotion backup root")?;
    if backup_root.starts_with(&root) {
        return Err(invalid(
            "the backup root must be outside the promotion target root",
        ));
    }
    let backup_dir = backup_root.join(format!(
        "promotion-{}-{now_ms}",
        short_id(&approved.proposal_id)?
    ));
    match std::fs::symlink_metadata(&backup_dir) {
        Ok(_) => {
            return Err(ZeroError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "promotion backup `{}` already exists; pass a fresh backup root",
                    backup_dir.display()
                ),
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    std::fs::create_dir(&backup_dir)?;

    let mut applied: Vec<AppliedFile> = Vec::with_capacity(approved.change.files.len());
    let mut backup_bytes: u64 = 0;
    for (index, (path, contents)) in approved.change.files.iter().enumerate() {
        match apply_one(&root, &backup_dir, index, path, contents, &mut backup_bytes) {
            Ok(file) => applied.push(file),
            Err(error) => {
                let note = match restore_detailed(&applied, &root, &backup_dir, true) {
                    Ok((restored, removed)) => format!(
                        "rolled back: {} restored, {} removed",
                        restored.len(),
                        removed.len()
                    ),
                    Err(rollback_error) => {
                        format!("rollback incomplete: {}", rollback_error.message())
                    }
                };
                return Err(ZeroError::new(
                    error.code(),
                    format!("promotion failed: {}; {note}", error.message()),
                ));
            }
        }
    }

    Ok(AppliedPromotion {
        proposal_id: approved.proposal_id.clone(),
        files: applied,
        backup_dir,
        diff_hash: approved.diff_hash.clone(),
        target_root: root,
        applied_at_ms: now_ms,
    })
}

fn validate_apply_bounds(change: &ChangeSet) -> Result<()> {
    if change.files.is_empty() {
        return Err(invalid("a promotion needs at least one file"));
    }
    if change.files.len() > MAX_BACKUP_FILES {
        return Err(limit(format!(
            "a promotion has {} files; the cap is {MAX_BACKUP_FILES}",
            change.files.len()
        )));
    }
    let mut total = 0usize;
    for (path, contents) in &change.files {
        safe_change_path(path)?;
        if contents.len() > MAX_CHANGE_FILE_BYTES {
            return Err(limit(format!(
                "promotion file `{path}` is {} bytes; the cap is {MAX_CHANGE_FILE_BYTES}",
                contents.len()
            )));
        }
        total += contents.len();
    }
    if total > MAX_CHANGE_BYTES {
        return Err(limit(format!(
            "a promotion is {total} bytes; the cap is {MAX_CHANGE_BYTES}"
        )));
    }
    Ok(())
}

fn apply_one(
    root: &Path,
    backup_dir: &Path,
    index: usize,
    path: &str,
    contents: &str,
    backup_bytes: &mut u64,
) -> Result<AppliedFile> {
    let relative = safe_change_path(path)?;
    let parent = ensure_dir_chain(root, relative.parent())?;
    let name = relative
        .file_name()
        .ok_or_else(|| invalid(format!("promotion path `{path}` has no file name")))?;
    let target = parent.join(name);

    let (existed, previous_hash, backup_file) = match std::fs::symlink_metadata(&target) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(denied(format!(
                    "promotion target `{path}` is a symlink; refusing to replace it"
                )));
            }
            if !metadata.is_file() {
                return Err(denied(format!(
                    "promotion target `{path}` is not a regular file"
                )));
            }
            if metadata.len() > MAX_BACKUP_BYTES {
                return Err(limit(format!(
                    "promotion target `{path}` is {} bytes; the backup cap is {MAX_BACKUP_BYTES}",
                    metadata.len()
                )));
            }
            let previous = read_bounded(&target, MAX_BACKUP_BYTES)?;
            *backup_bytes = backup_bytes.saturating_add(previous.len() as u64);
            if *backup_bytes > MAX_BACKUP_BYTES {
                return Err(limit(format!(
                    "the promotion snapshots {} bytes; the cap is {MAX_BACKUP_BYTES}",
                    *backup_bytes
                )));
            }
            let name = format!("{index:04}.bak");
            write_new(&backup_dir.join(&name), &previous)?;
            (
                true,
                Some(blake3::hash(&previous).to_hex().to_string()),
                Some(name),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (false, None, None),
        Err(error) => return Err(error.into()),
    };

    write_replace(&target, contents.as_bytes())?;

    Ok(AppliedFile {
        path: path.to_string(),
        existed,
        previous_hash,
        promoted_hash: blake3::hash(contents.as_bytes()).to_hex().to_string(),
        bytes: contents.len() as u64,
        backup_file,
    })
}

/// Walk and create just the directory components of `relative` under `root`.
/// Every existing component must be a real directory, never a symlink.
fn ensure_dir_chain(root: &Path, relative: Option<&Path>) -> Result<PathBuf> {
    let mut current = root.to_path_buf();
    if let Some(relative) = relative {
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(invalid("a promotion directory component is not relative"));
            };
            current.push(name);
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(denied(format!(
                            "promotion parent `{}` is a symlink",
                            current.display()
                        )));
                    }
                    if !metadata.is_dir() {
                        return Err(denied(format!(
                            "promotion parent `{}` is not a directory",
                            current.display()
                        )));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::create_dir(&current)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(current)
}

/// Write a brand-new file; an existing path is refused. Used for snapshots.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.flush()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error.into());
    }
    Ok(())
}

/// Replace `target` through a same-directory temp file and a rename.
fn write_replace(target: &Path, bytes: &[u8]) -> Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| invalid("a promotion target has no parent directory"))?;
    let name = target
        .file_name()
        .ok_or_else(|| invalid("a promotion target has no file name"))?;
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(".zero-tmp");
    let temp = parent.join(temp_name);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.flush()) {
        drop(file);
        let _ = std::fs::remove_file(&temp);
        return Err(error.into());
    }
    drop(file);
    if let Err(error) = std::fs::rename(&temp, target) {
        let _ = std::fs::remove_file(&temp);
        return Err(error.into());
    }
    Ok(())
}

fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(limit(format!(
            "`{}` grew past the {max}-byte read cap",
            path.display()
        )));
    }
    Ok(bytes)
}

fn short_id(proposal_id: &str) -> Result<String> {
    if proposal_id.len() < 16
        || !proposal_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        return Err(invalid(
            "a promotion id is at least 16 ASCII alphanumeric characters",
        ));
    }
    Ok(proposal_id[..16].to_ascii_lowercase())
}

/// Undo a promotion, refusing a target that changed since it was applied.
///
/// Restores snapshots and removes created files in reverse promotion order. A
/// file whose current content no longer matches the promoted hash is
/// `zero.fnd.tamper`; use [`rollback_forced`] to overwrite it anyway.
pub fn rollback(applied: &AppliedPromotion, target_root: &Path) -> Result<RollbackReport> {
    rollback_inner(applied, target_root, false)
}

/// [`rollback`] with an explicit `force`, which overwrites a target that changed
/// after the promotion. Only a human decision should pass this.
pub fn rollback_forced(applied: &AppliedPromotion, target_root: &Path) -> Result<RollbackReport> {
    rollback_inner(applied, target_root, true)
}

fn rollback_inner(
    applied: &AppliedPromotion,
    target_root: &Path,
    force: bool,
) -> Result<RollbackReport> {
    let root = canonical_dir(target_root, "rollback target root")?;
    if root != applied.target_root {
        return Err(denied(format!(
            "rollback target `{}` is not the promotion target `{}`",
            target_root.display(),
            applied.target_root.display()
        )));
    }
    let core = ImmutableCore::default();
    for file in &applied.files {
        let relative = safe_change_path(&file.path)?;
        if core.is_protected(&relative) {
            return Err(denied(format!(
                "rollback path `{}` is in the immutable core",
                file.path
            )));
        }
    }

    let (restored, removed) = restore_detailed(&applied.files, &root, &applied.backup_dir, force)?;
    Ok(RollbackReport {
        proposal_id: applied.proposal_id.clone(),
        restored,
        removed,
        forced: force,
    })
}

/// Best-effort inverse used after a failed apply. The caller already has the
/// original error; a failed restore is reported in the message instead of
/// hiding the original failure.
fn restore_detailed(
    files: &[AppliedFile],
    root: &Path,
    backup_dir: &Path,
    force: bool,
) -> Result<(Vec<String>, Vec<String>)> {
    // Preflight: verify every target and snapshot before the first write, so a
    // refused rollback leaves the tree exactly as it was.
    let mut plan: Vec<(&AppliedFile, PathBuf, bool, Option<Vec<u8>>)> =
        Vec::with_capacity(files.len());
    for file in files.iter().rev() {
        let relative = safe_change_path(&file.path)?;
        let target = root.join(&relative);
        match std::fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(denied(format!(
                    "rollback target `{}` is a symlink",
                    file.path
                )));
            }
            Ok(metadata) if file.existed && !metadata.is_file() => {
                return Err(denied(format!(
                    "rollback target `{}` is not a regular file",
                    file.path
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let current = match std::fs::metadata(&target) {
            Ok(_) => Some(
                blake3::hash(&read_bounded(&target, MAX_BACKUP_BYTES)?)
                    .to_hex()
                    .to_string(),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if !force && current.as_deref() != Some(file.promoted_hash.as_str()) {
            return Err(tampered(format!(
                "rollback refused: `{}` changed after the promotion; pass force to overwrite it",
                file.path
            )));
        }

        let backup = if file.existed {
            let backup_name = file
                .backup_file
                .as_ref()
                .ok_or_else(|| tampered(format!("`{}` has no snapshot to restore", file.path)))?;
            let bytes = read_bounded(&backup_dir.join(backup_name), MAX_BACKUP_BYTES)?;
            let expected = file
                .previous_hash
                .as_ref()
                .ok_or_else(|| tampered(format!("`{}` has no previous hash", file.path)))?;
            if blake3::hash(&bytes).to_hex().to_string() != *expected {
                return Err(tampered(format!(
                    "snapshot for `{}` does not match its recorded hash",
                    file.path
                )));
            }
            Some(bytes)
        } else {
            None
        };
        plan.push((file, target, current.is_some(), backup));
    }

    // Apply the verified plan.
    let mut restored = Vec::new();
    let mut removed = Vec::new();
    for (file, target, had_target, backup) in plan {
        if file.existed {
            let bytes = backup.expect("an existing file has a verified snapshot");
            write_replace(&target, &bytes)?;
            restored.push(file.path.clone());
        } else if had_target {
            std::fs::remove_file(&target)?;
            removed.push(file.path.clone());
        }
    }
    Ok((restored, removed))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn canonical_dir(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = path.canonicalize().map_err(|error| {
        invalid(format!(
            "{label} `{}` cannot be resolved: {error}",
            path.display()
        ))
    })?;
    if !canonical.is_dir() {
        return Err(invalid(format!(
            "{label} `{}` is not a directory",
            path.display()
        )));
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval_suite::EvalReport;
    use crate::self_improve::{LoopDecision, Proposal, Stage, Target};
    use std::collections::BTreeMap;

    const NOW: i64 = 1_700_000_000_000;

    struct ApproveWith {
        by: &'static str,
        hash: Option<String>,
    }

    impl ApproveWith {
        fn new(by: &'static str) -> Self {
            Self { by, hash: None }
        }

        fn stale(by: &'static str) -> Self {
            Self {
                by,
                hash: Some("0".repeat(64)),
            }
        }
    }

    impl HumanGate for ApproveWith {
        fn approve(&self, _proposal_id: &str, diff_hash: &str) -> Approval {
            Approval::Approved {
                by: self.by.to_string(),
                at_ms: NOW,
                diff_hash: self.hash.clone().unwrap_or_else(|| diff_hash.to_string()),
            }
        }
    }

    struct Deny;

    impl HumanGate for Deny {
        fn approve(&self, _proposal_id: &str, _diff_hash: &str) -> Approval {
            Approval::Denied {
                reason: "the reviewer is not available".to_string(),
            }
        }
    }

    fn report() -> EvalReport {
        EvalReport {
            suite_version: "si-fixture-1".to_string(),
            passed: 1,
            failed: 0,
            task_results: Vec::new(),
            started: NOW,
            finished: NOW,
        }
    }

    fn change(files: &[(&str, &str)]) -> ChangeSet {
        let mut map = BTreeMap::new();
        for (path, contents) in files {
            map.insert((*path).to_string(), (*contents).to_string());
        }
        ChangeSet {
            files: map,
            description: "one bounded change".to_string(),
        }
    }

    fn accepted_state(files: &[(&str, &str)]) -> LoopState {
        let proposal = Proposal::new(
            NOW,
            "promotion fixture",
            "diagnosis: the held-out task failed twice",
            change(files),
            Target::AgentPrompt,
            vec!["audit:run-1/finding-1".to_string()],
        )
        .expect("valid proposal");
        LoopState {
            proposal,
            stage: Stage::Evaluate,
            attempts: 1,
            eval_baseline: Some(report()),
            eval_candidate: Some(report()),
            decision: Some(LoopDecision::Accepted {
                improvements: vec!["second".to_string()],
                baseline_version: "si-fixture-1".to_string(),
            }),
            history: Vec::new(),
        }
    }

    fn approved(state: &LoopState) -> ApprovedPromotion {
        approve_promotion(state, &ApproveWith::new("reviewer")).expect("approved promotion")
    }

    /// Build an [`ApprovedPromotion`] directly so path defenses can be tested.
    /// Only reachable inside this module's tests: the token is module-private.
    fn forge(files: &[(&str, &str)]) -> ApprovedPromotion {
        let change = change(files);
        let diff = render_diff(&change);
        let hash = diff_hash(&change);
        ApprovedPromotion {
            proposal_id: "a".repeat(64),
            change,
            diff,
            diff_hash: hash,
            approved_by: "reviewer".to_string(),
            approved_at_ms: NOW,
            _token: seal::ApprovalToken,
        }
    }

    fn target_root(dir: &tempfile::TempDir) -> PathBuf {
        let root = dir.path().join("target");
        std::fs::create_dir_all(&root).expect("target root");
        root
    }

    fn backup_root(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("backups")
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).expect("read file")
    }

    // ----- Done criterion ----------------------------------------------------

    #[test]
    fn candidate_touching_the_evaluator_is_refused() {
        let state = accepted_state(&[("crates/zero-agent/src/eval_suite.rs", "// weakened\n")]);
        let error = approve_promotion(&state, &ApproveWith::new("reviewer"))
            .expect_err("the evaluator is immutable");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(
            error.message().contains("immutable core"),
            "{}",
            error.message()
        );

        let state = accepted_state(&[("crates/zero-policy/src/mode.rs", "// weakened\n")]);
        assert_eq!(
            approve_promotion(&state, &ApproveWith::new("reviewer"))
                .expect_err("policy is immutable")
                .code(),
            ErrorCode::PolicyDenied
        );

        let state = accepted_state(&[("crates/zero-agent/src/promotion.rs", "// rules\n")]);
        assert_eq!(
            approve_promotion(&state, &ApproveWith::new("reviewer"))
                .expect_err("promotion rules are immutable")
                .code(),
            ErrorCode::PolicyDenied
        );

        ImmutableCore::default()
            .check(&change(&[("prompts/system.md", "allowed\n")]))
            .expect("a prompt is not in the core");
    }

    // ----- apply and rollback ------------------------------------------------

    #[test]
    fn approved_candidate_applies_and_is_reversible() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = target_root(&dir);
        std::fs::write(root.join("existing.txt"), "old bytes\n").expect("seed");

        let state = accepted_state(&[
            ("existing.txt", "new bytes\n"),
            ("created/child.txt", "fresh\n"),
        ]);
        let approved = approved(&state);
        assert_eq!(approved.approved_by(), "reviewer");
        assert_eq!(approved.proposal_id(), state.proposal.id);
        assert_eq!(approved.diff_hash(), diff_hash(&state.proposal.change));

        let applied = apply_promotion(&approved, &root, &backup_root(&dir), NOW).expect("apply");
        assert_eq!(applied.proposal_id(), state.proposal.id);
        assert_eq!(applied.files().len(), 2);
        assert_eq!(applied.diff_hash(), approved.diff_hash());
        assert_eq!(read(&root.join("existing.txt")), "new bytes\n");
        assert_eq!(read(&root.join("created/child.txt")), "fresh\n");
        assert!(applied.backup_dir().is_dir(), "the snapshot is durable");

        let rollback_report = rollback(&applied, &root).expect("rollback");
        assert_eq!(rollback_report.restored, vec!["existing.txt".to_string()]);
        assert_eq!(
            rollback_report.removed,
            vec!["created/child.txt".to_string()]
        );
        assert!(!rollback_report.forced);
        assert_eq!(read(&root.join("existing.txt")), "old bytes\n");
        assert!(!root.join("created/child.txt").exists());
    }

    #[test]
    fn gate_missing_denied_and_diff_hash_mismatch_are_refused() {
        let state = accepted_state(&[("prompts/system.md", "change\n")]);

        let error = approve_promotion(&state, &Deny).expect_err("denied gate");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("denied"), "{}", error.message());

        let error =
            approve_promotion(&state, &ApproveWith::stale("reviewer")).expect_err("stale approval");
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);
        assert!(
            error.message().contains("different diff"),
            "{}",
            error.message()
        );

        let error = approve_promotion(&state, &ApproveWith::new("  "))
            .expect_err("an unnamed approver is not an approval");
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);

        let mut rejected = state.clone();
        rejected.decision = Some(LoopDecision::Rejected {
            regressions: Vec::new(),
            reason: "no measurable improvement".to_string(),
        });
        let error = approve_promotion(&rejected, &ApproveWith::new("reviewer"))
            .expect_err("only an accepted candidate is promoted");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);

        let mut incomplete = state;
        incomplete.eval_candidate = None;
        let error = approve_promotion(&incomplete, &ApproveWith::new("reviewer"))
            .expect_err("an accepted label without reports is not evidence");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
    }

    #[test]
    fn self_approval_is_impossible_by_type() {
        let state = accepted_state(&[("prompts/system.md", "change\n")]);

        // The loop's own gate value is not an approval: the only successful
        // path goes through `approve_promotion` with an external seam.
        let denied = approve_promotion(&state, &Deny).expect_err("no self-approval");
        assert_eq!(denied.code(), ErrorCode::PolicyDenied);

        // `apply_promotion` takes `&ApprovedPromotion`; a
        // `crate::self_improve::Promotion { approved: true }` and a bare diff
        // hash do not satisfy that type, so a caller cannot apply without the
        // gate. The seal token makes the struct literal unnameable outside
        // this module.
        let loop_value = crate::self_improve::promote(&state);
        assert!(loop_value.approved);
        let sealed = approved(&state);
        assert_eq!(sealed.diff_hash(), diff_hash(&state.proposal.change));
        assert_eq!(sealed.approved_by(), "reviewer");
        assert_eq!(sealed.proposal_id(), loop_value.proposal_id);
    }

    #[test]
    fn rollback_restores_bytes_and_removes_created_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = target_root(&dir);
        let old = vec![0u8, 1, 2, 3, 0xff, 0xfe, b'\n'];
        std::fs::write(root.join("binary.dat"), &old).expect("seed");

        let state = accepted_state(&[
            ("binary.dat", "replacement\n"),
            ("nested/created.bin", "made\n"),
        ]);
        let applied =
            apply_promotion(&approved(&state), &root, &backup_root(&dir), NOW).expect("apply");
        assert_eq!(
            applied.files().iter().filter(|file| file.existed).count(),
            1
        );
        assert_eq!(
            applied
                .files()
                .iter()
                .filter(|file| file.backup_file.is_some())
                .count(),
            1
        );

        let report = rollback(&applied, &root).expect("rollback");
        assert_eq!(report.restored, vec!["binary.dat".to_string()]);
        assert_eq!(report.removed, vec!["nested/created.bin".to_string()]);
        assert_eq!(std::fs::read(root.join("binary.dat")).expect("bytes"), old);
        assert!(!root.join("nested/created.bin").exists());
    }

    #[test]
    fn rollback_refuses_a_target_changed_after_promotion() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = target_root(&dir);
        std::fs::write(root.join("a.txt"), "old a\n").expect("seed a");
        std::fs::write(root.join("b.txt"), "old b\n").expect("seed b");

        let state = accepted_state(&[("a.txt", "promoted a\n"), ("b.txt", "promoted b\n")]);
        let applied =
            apply_promotion(&approved(&state), &root, &backup_root(&dir), NOW).expect("apply");
        std::fs::write(root.join("a.txt"), "edited after promotion\n").expect("edit");

        let error = rollback(&applied, &root).expect_err("changed target is refused");
        assert_eq!(error.code(), ErrorCode::TamperDetected);
        assert!(
            error.message().contains("changed after"),
            "{}",
            error.message()
        );
        assert_eq!(read(&root.join("a.txt")), "edited after promotion\n");
        assert_eq!(
            read(&root.join("b.txt")),
            "promoted b\n",
            "the refusal must not partially restore another file"
        );

        let forced = rollback_forced(&applied, &root).expect("forced rollback");
        assert!(forced.forced);
        assert_eq!(
            forced.restored,
            vec!["b.txt".to_string(), "a.txt".to_string()]
        );
        assert_eq!(read(&root.join("a.txt")), "old a\n");
        assert_eq!(read(&root.join("b.txt")), "old b\n");
    }

    #[test]
    fn apply_failure_rolls_back() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = target_root(&dir);
        std::fs::write(root.join("a.txt"), "old a\n").expect("seed");
        std::fs::write(root.join("zblocked"), "not a directory\n").expect("blocker");

        let state = accepted_state(&[
            ("a.txt", "new a\n"),
            ("zblocked/second.txt", "cannot land\n"),
        ]);
        let error = apply_promotion(&approved(&state), &root, &backup_root(&dir), NOW)
            .expect_err("the second file cannot be created");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(
            error.message().contains("rolled back: 1 restored"),
            "{}",
            error.message()
        );
        assert_eq!(read(&root.join("a.txt")), "old a\n");
        assert!(!root.join("zblocked/second.txt").exists());
    }

    #[test]
    fn backup_is_bounded() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = target_root(&dir);
        let oversized = vec![b'x'; MAX_BACKUP_BYTES as usize + 1];
        std::fs::write(root.join("big.txt"), &oversized).expect("seed");

        let state = accepted_state(&[("big.txt", "small replacement\n")]);
        let error = apply_promotion(&approved(&state), &root, &backup_root(&dir), NOW)
            .expect_err("an oversized snapshot is refused");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert_eq!(
            std::fs::read(root.join("big.txt")).expect("untouched"),
            oversized
        );
    }

    // ----- diff --------------------------------------------------------------

    #[test]
    fn diff_is_deterministic_and_bounded() {
        let one = change(&[("b.txt", "second\n"), ("a.txt", "first\nline two\n")]);
        let two = change(&[("a.txt", "first\nline two\n"), ("b.txt", "second\n")]);
        assert_eq!(render_diff(&one), render_diff(&two), "BTreeMap order");
        assert_eq!(diff_hash(&one), diff_hash(&two));
        assert_eq!(render_diff(&one), render_diff(&one));

        let diff = render_diff(&one);
        assert!(diff.starts_with("--- a/a.txt\n+++ b/a.txt\n"), "{diff}");
        assert!(diff.contains("+first\n+line two\n"), "{diff}");
        assert!(diff.contains("--- a/b.txt"), "{diff}");
        assert!(
            !diff.contains("one bounded change"),
            "prose never enters the diff"
        );

        let mut files = BTreeMap::new();
        for index in 0..16 {
            files.insert(
                format!("f{index:02}.txt"),
                "x".repeat(MAX_CHANGE_FILE_BYTES),
            );
        }
        let huge = ChangeSet {
            files,
            description: "bounded".to_string(),
        };
        let rendered = render_diff(&huge);
        assert!(rendered.len() <= MAX_DIFF_BYTES, "{}", rendered.len());
        assert!(rendered.contains("diff truncated"), "the cap is visible");
        assert_ne!(diff_hash(&huge), diff_hash(&one));
    }

    // ----- path safety -------------------------------------------------------

    #[test]
    fn path_escapes_and_symlinks_are_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = target_root(&dir);
        let backups = backup_root(&dir);

        for escaped in ["../escape.txt", "..\\escape.txt", "/abs.txt", "C:\\abs.txt"] {
            let error = apply_promotion(&forge(&[(escaped, "x")]), &root, &backups, NOW)
                .expect_err(escaped);
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{escaped}");
        }
        assert!(!dir.path().join("escape.txt").exists());

        assert_eq!(
            ImmutableCore::default()
                .check(&change(&[("../escape.txt", "x")]))
                .expect_err("normalization runs before the protected list")
                .code(),
            ErrorCode::InvalidInput
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let outside = dir.path().join("outside.txt");
            std::fs::write(&outside, "outside\n").expect("outside");
            symlink(&outside, root.join("linked.txt")).expect("file symlink");
            let error = apply_promotion(&forge(&[("linked.txt", "x")]), &root, &backups, NOW)
                .expect_err("a symlink target is refused");
            assert_eq!(error.code(), ErrorCode::PolicyDenied);

            symlink(dir.path(), root.join("linked-dir")).expect("dir symlink");
            let error = apply_promotion(
                &forge(&[("linked-dir/inside.txt", "x")]),
                &root,
                &backups,
                NOW,
            )
            .expect_err("a symlink parent is refused");
            assert_eq!(error.code(), ErrorCode::PolicyDenied);
            assert!(!dir.path().join("inside.txt").exists());
        }
    }

    #[test]
    fn rollback_refuses_a_different_target_root() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = target_root(&dir);
        std::fs::write(root.join("a.txt"), "old\n").expect("seed");
        let state = accepted_state(&[("a.txt", "new\n")]);
        let applied =
            apply_promotion(&approved(&state), &root, &backup_root(&dir), NOW).expect("apply");

        let other = dir.path().join("other");
        std::fs::create_dir_all(&other).expect("other root");
        let error = rollback(&applied, &other).expect_err("wrong tree");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(read(&root.join("a.txt")), "new\n");
    }

    #[test]
    fn the_module_holds_no_network_or_router_api() {
        let source = include_str!("promotion.rs");
        let banned = [
            ["std::", "net"].concat(),
            ["Tcp", "Stream"].concat(),
            ["Udp", "Socket"].concat(),
            ["req", "west"].concat(),
            ["hyper", "::"].concat(),
            ["http", "://"].concat(),
            ["zero_model", "::", "router"].concat(),
        ];
        for token in banned {
            assert!(
                !source.contains(&token),
                "promotion must stay offline; found `{token}`"
            );
        }
    }
}
