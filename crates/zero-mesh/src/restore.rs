//! Conflict-safe full restore (T-TEL-04, TEL-04, TEL-07, TEL-08).
//!
//! A [`RestorePlan`] is derived from a **verified** [`Bundle`] plus the opaque
//! session components: every workspace file and recorded symlink with its type,
//! size, blake3, Unix mode, and content, plus the transcript, kernel, artifact
//! index, goals, schedules, ledger, and child-registry blobs.
//!
//! [`restore`] never overwrites by default. It validates the whole plan and
//! inspects every target path **before writing anything**, then applies the
//! plan. A target that already holds different content, a file/directory type
//! mismatch, a destination symlink, or a blocked parent directory is *staged*
//! under `target_root/.zero/restore-staging/<bundle_id>/<path>` and reported in
//! [`RestoreReport::staged`] instead of being replaced. Identical files are
//! skipped. The T-TEL-04 done criterion is
//! `a_conflicting_file_is_staged_and_not_overwritten`: **restore into a
//! conflicting directory stages instead of overwriting**.
//!
//! [`RestoreOptions::overwrite_existing`] is the explicit, per-path opt-in. It
//! replaces a conflicting regular file (or a recorded symlink with a different
//! target) and still records the conflict. A type change is never performed,
//! even with the flag.
//!
//! [`adopt`] is the second half of TEL-08's "stage or reconcile explicitly": it
//! moves one reviewed staged conflict into place, but only while the target
//! still has the recorded existing hash. A directory is never removed by
//! adoption.
//!
//! Components are written atomically under
//! `target_root/.zero/teleport/<bundle_id>/components/`. Workspace files and
//! symlinks are written through a hidden temporary file or link plus a rename,
//! with Unix modes applied. Symlink targets must be relative and stay inside the
//! restore root; an unrecorded symlink at a destination is staged, never
//! followed. Symlink creation is Unix-only; on Windows a plan that records one
//! is refused during preflight, before any write.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, Metadata, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::bundle::{
    self, verify_bundle, Bundle, FileEntry, MAX_BUNDLE_BYTES, MAX_FILES, MAX_PATH_BYTES,
};
use crate::snapshot::{Component, MAX_COMPONENT_BYTES, MAX_SNAPSHOT_BYTES, TELEPORT_DIR};

/// Directory under the target root that holds staged conflicts.
pub const RESTORE_STAGING_DIR: &str = ".zero/restore-staging";

/// Directory under `.zero/teleport/<bundle_id>` that holds restored components.
pub const COMPONENTS_DIR: &str = "components";

/// Component-file name for the optional child-registry blob.
pub const CHILDREN_FILE: &str = "children";

/// Most workspace entries one plan may carry.
pub const MAX_RESTORE_ENTRIES: usize = MAX_FILES;

/// Largest accepted Unix mode value (all permission and special bits).
pub const MAX_MODE_BITS: u32 = 0o7777;

/// The kind of one restored workspace path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreKind {
    /// A regular file whose bytes are in [`RestorePlan::contents`].
    File,
    /// A directory with no content.
    Dir,
    /// A recorded symlink. `target` is relative and must stay inside the root.
    Symlink {
        /// Link target, always a relative forward-slash path.
        target: String,
    },
}

/// One path in a restore plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreEntry {
    /// Safe, relative, forward-slash workspace path.
    pub path: String,
    /// File, directory, or recorded symlink.
    pub kind: RestoreKind,
    /// Logical length: file bytes, symlink-target bytes, or zero for a directory.
    pub bytes: u64,
    /// Lower-case hex blake3 of the content (the empty digest for a directory).
    pub hash: String,
    /// Unix permission bits; ignored on Windows.
    pub mode: Option<u32>,
    /// Provenance when the entry came from a teleport component rather than the
    /// workspace. Restore writes every entry under the target root either way.
    pub component: Option<Component>,
}

/// A verified restore plan.
///
/// `contents` maps every file and symlink path to its exact bytes; it is the
/// verified payload from the bundle, not a second source of truth. `components`
/// carries the state blobs (session/transcript, kernel, artifacts, goals,
/// schedules, ledger), and `children` is the optional child-registry blob that
/// is rebound on the target. `Debug` prints counts and ids, never file or
/// component bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct RestorePlan {
    /// Bundle id this plan restores.
    pub bundle_id: String,
    /// Workspace entries, in caller order; restore sorts them by path.
    pub entries: Vec<RestoreEntry>,
    /// Exact bytes for every file and symlink entry, keyed by path.
    pub contents: BTreeMap<String, Vec<u8>>,
    /// Opaque teleport components, keyed by component.
    pub components: BTreeMap<Component, Vec<u8>>,
    /// Optional child-registry blob.
    pub children: Option<Vec<u8>>,
}

impl fmt::Debug for RestorePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RestorePlan")
            .field("bundle_id", &self.bundle_id)
            .field("entries", &self.entries.len())
            .field(
                "bytes",
                &self.contents.values().map(Vec::len).sum::<usize>(),
            )
            .field("components", &self.components.keys().collect::<Vec<_>>())
            .field("children", &self.children.as_ref().map(Vec::len))
            .finish()
    }
}

impl RestorePlan {
    /// Build and validate a plan from a verified bundle and component blobs.
    ///
    /// The bundle is verified first, so a missing or corrupt chunk is refused
    /// before a plan exists. Every file is reassembled in memory, hashed, and
    /// recorded with its mode and recorded symlink target.
    pub fn from_bundle(
        bundle: &Bundle,
        components: BTreeMap<Component, Vec<u8>>,
        children: Option<Vec<u8>>,
    ) -> Result<Self> {
        verify_bundle(bundle)?;

        let mut entries = Vec::with_capacity(bundle.manifest.files.len());
        let mut contents = BTreeMap::new();
        for (path, entry) in &bundle.manifest.files {
            let bytes = assemble_file(bundle, path, entry)?;
            let hash = hash_hex(&bytes);
            let kind = if entry.symlink {
                let target = std::str::from_utf8(&bytes)
                    .map_err(|_| invalid(format!("symlink `{path}` target is not UTF-8")))?
                    .to_string();
                RestoreKind::Symlink { target }
            } else {
                RestoreKind::File
            };
            entries.push(RestoreEntry {
                path: path.clone(),
                kind,
                bytes: bytes.len() as u64,
                hash,
                mode: entry.mode,
                component: None,
            });
            contents.insert(path.clone(), bytes);
        }

        let plan = Self {
            bundle_id: bundle.manifest.bundle_id.clone(),
            entries,
            contents,
            components,
            children,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Validate paths, hashes, modes, symlink targets, and the component set.
    ///
    /// Every check runs before a restore touches the target. A plan with an
    /// unsafe path, a duplicate path, a hash or size that does not match its
    /// content, a symlink target outside the root, a mode outside `0o7777`, a
    /// workspace-manifest component, or an oversized blob is refused.
    pub fn validate(&self) -> Result<()> {
        validate_hex64(&self.bundle_id, "bundle id")?;
        if self.entries.len() > MAX_RESTORE_ENTRIES {
            return Err(limit(format!(
                "restore plan has {} entries; the limit is {MAX_RESTORE_ENTRIES}",
                self.entries.len()
            )));
        }

        let mut paths = BTreeSet::new();
        let mut payload_paths = BTreeSet::new();
        let mut entry_bytes = 0u64;
        for entry in &self.entries {
            bundle::validate_relative_path(&entry.path)?;
            if entry.path.split('/').next() == Some(".zero") {
                return Err(denied(format!(
                    "`{}` is inside `.zero`; restore never writes internal state as a workspace entry",
                    entry.path
                )));
            }
            if !paths.insert(entry.path.clone()) {
                return Err(invalid(format!(
                    "restore path `{}` appears more than once",
                    entry.path
                )));
            }
            if entry.bytes > MAX_BUNDLE_BYTES {
                return Err(limit(format!(
                    "`{}` declares {} bytes; the limit is {MAX_BUNDLE_BYTES}",
                    entry.path, entry.bytes
                )));
            }
            entry_bytes = entry_bytes
                .checked_add(entry.bytes)
                .ok_or_else(|| limit("restore entry sizes overflow their counter"))?;
            if entry_bytes > MAX_BUNDLE_BYTES {
                return Err(limit(format!(
                    "restore entries total {entry_bytes} bytes; the limit is {MAX_BUNDLE_BYTES}"
                )));
            }
            validate_hex64(&entry.hash, "entry hash")?;
            if let Some(mode) = entry.mode {
                if mode > MAX_MODE_BITS {
                    return Err(invalid(format!(
                        "`{}` has mode {mode:#o}; modes are bounded by {MAX_MODE_BITS:#o}",
                        entry.path
                    )));
                }
            }
            if let Some(component) = entry.component {
                if !component_allowed(component) {
                    return Err(denied(format!(
                        "`{}` names the workspace-manifest component; workspace files travel as entries",
                        entry.path
                    )));
                }
            }

            match &entry.kind {
                RestoreKind::File => {
                    let content = self.contents.get(&entry.path).ok_or_else(|| {
                        invalid(format!("`{}` has no content in the plan", entry.path))
                    })?;
                    if content.len() as u64 != entry.bytes {
                        return Err(invalid(format!(
                            "`{}` declares {} bytes but the content is {}",
                            entry.path,
                            entry.bytes,
                            content.len()
                        )));
                    }
                    if hash_hex(content) != entry.hash {
                        return Err(tamper(format!(
                            "`{}` content does not match its recorded hash",
                            entry.path
                        )));
                    }
                    payload_paths.insert(entry.path.clone());
                }
                RestoreKind::Symlink { target } => {
                    validate_symlink_target(&entry.path, target)?;
                    if !symlink_stays_inside(&entry.path, target) {
                        return Err(invalid(format!(
                            "symlink `{}` target `{target}` escapes the restore root",
                            entry.path
                        )));
                    }
                    let content = self.contents.get(&entry.path).ok_or_else(|| {
                        invalid(format!("symlink `{}` has no recorded target", entry.path))
                    })?;
                    if content != target.as_bytes() {
                        return Err(invalid(format!(
                            "symlink `{}` target does not match its content",
                            entry.path
                        )));
                    }
                    if content.len() as u64 != entry.bytes || hash_hex(content) != entry.hash {
                        return Err(tamper(format!(
                            "symlink `{}` target does not match its recorded size or hash",
                            entry.path
                        )));
                    }
                    payload_paths.insert(entry.path.clone());
                }
                RestoreKind::Dir => {
                    if entry.bytes != 0 || entry.hash != hash_hex(b"") {
                        return Err(invalid(format!(
                            "directory `{}` must have zero bytes and the empty digest",
                            entry.path
                        )));
                    }
                    if self.contents.contains_key(&entry.path) {
                        return Err(invalid(format!(
                            "directory `{}` must not carry file content",
                            entry.path
                        )));
                    }
                }
            }
        }

        for path in &paths {
            let mut components: Vec<&str> = path.split('/').collect();
            components.pop();
            let mut ancestor = String::new();
            for component in components {
                if !ancestor.is_empty() {
                    ancestor.push('/');
                }
                ancestor.push_str(component);
                if payload_paths.contains(&ancestor) {
                    return Err(invalid(format!(
                        "`{path}` is nested under the file `{ancestor}`"
                    )));
                }
            }
        }

        for path in self.contents.keys() {
            if !payload_paths.contains(path) {
                return Err(invalid(format!(
                    "restore plan carries content for `{path}` with no matching entry"
                )));
            }
        }

        let mut total = 0usize;
        for (component, bytes) in &self.components {
            if !component_allowed(*component) {
                return Err(denied(format!(
                    "component `{}` is the workspace manifest; it is restored from entries",
                    component.as_str()
                )));
            }
            total = total
                .checked_add(check_component_size(component.as_str(), bytes.len())?)
                .ok_or_else(|| limit("restore component size overflows its counter"))?;
        }
        if let Some(children) = &self.children {
            total = total
                .checked_add(check_component_size(CHILDREN_FILE, children.len())?)
                .ok_or_else(|| limit("restore component size overflows its counter"))?;
        }
        if total > MAX_SNAPSHOT_BYTES {
            return Err(limit(format!(
                "restore components total {total} bytes; the limit is {MAX_SNAPSHOT_BYTES}"
            )));
        }
        Ok(())
    }
}

/// Restore policy. The default never overwrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RestoreOptions {
    /// Explicit per-path opt-in: replace a conflicting regular file or a
    /// recorded symlink with a different target. Conflicts are still recorded,
    /// and a file/directory type change is still staged or refused.
    pub overwrite_existing: bool,
}

/// One conflict whose incoming content was staged instead of written in place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedConflict {
    /// Workspace-relative path that conflicted.
    pub path: String,
    /// Lower-case hex blake3 of what was already there, when it was a file or
    /// symlink; `None` for a directory or anything else without a content hash.
    pub existing_hash: Option<String>,
    /// Lower-case hex blake3 of the incoming content.
    pub incoming_hash: String,
    /// `target_root/.zero/restore-staging/<bundle_id>/<path>`.
    pub staged_path: PathBuf,
}

/// What one restore did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReport {
    /// Bundle id restored.
    pub bundle_id: String,
    /// Target root.
    pub root: PathBuf,
    /// Paths created or replaced by this restore.
    pub restored: Vec<PathBuf>,
    /// Paths replaced because `overwrite_existing` was set.
    pub overwritten: Vec<PathBuf>,
    /// Entries whose existing content was identical and was left alone.
    pub skipped_identical: u64,
    /// Component files that were already identical and were left alone.
    pub skipped_components: u64,
    /// Conflicts staged for review.
    pub staged: Vec<StagedConflict>,
    /// Number of staged conflicts (`staged.len()`).
    pub conflicts: u64,
    /// Restored component files, keyed by component.
    pub components: BTreeMap<Component, PathBuf>,
    /// Restored child-registry file, when the plan carried one.
    pub children: Option<PathBuf>,
}

impl RestoreReport {
    /// The staged conflict for one path, if any.
    pub fn staged_conflict(&self, path: &str) -> Option<&StagedConflict> {
        self.staged.iter().find(|conflict| conflict.path == path)
    }
}

/// Build a validated plan from a verified bundle and its components.
///
/// This is the ordinary entry point; [`RestorePlan::from_bundle`] is the same
/// operation as a method.
pub fn build_plan(
    bundle: &Bundle,
    components: BTreeMap<Component, Vec<u8>>,
    children: Option<Vec<u8>>,
) -> Result<RestorePlan> {
    RestorePlan::from_bundle(bundle, components, children)
}

/// Restore a validated plan under `target_root` without overwriting by default.
///
/// Validation and target inspection happen before the first write. A conflict
/// is staged under `.zero/restore-staging/<bundle_id>/` and reported; identical
/// content is skipped. On an I/O failure during apply, paths created by this
/// call are removed again (or named in the error when rollback itself fails).
/// Pre-existing conflicting files are never touched.
pub fn restore(
    plan: &RestorePlan,
    target_root: &Path,
    options: RestoreOptions,
) -> Result<RestoreReport> {
    plan.validate()?;
    if target_root.as_os_str().is_empty() {
        return Err(invalid("restore target root must not be empty"));
    }
    #[cfg(not(unix))]
    if plan
        .entries
        .iter()
        .any(|entry| matches!(entry.kind, RestoreKind::Symlink { .. }))
    {
        return Err(denied(
            "recorded symlinks cannot be restored on this platform; restore refuses the plan before writing anything",
        ));
    }

    preflight_internal(target_root, &plan.bundle_id)?;
    let preflight = preflight(plan, target_root, options)?;

    apply(plan, target_root, options, preflight)
}

/// Apply one reviewed staged conflict in place.
///
/// The target must still be absent or still match the `existing_hash` recorded
/// when the conflict was staged; otherwise the call refuses rather than
/// clobbering a file that changed after review. A staged directory is never
/// adopted, and a directory in the target is never removed. On success the
/// conflict is removed from the report and the target is added to `restored`.
pub fn adopt(report: &mut RestoreReport, path: &str) -> Result<PathBuf> {
    bundle::validate_relative_path(path)?;
    let index = report
        .staged
        .iter()
        .position(|conflict| conflict.path == path)
        .ok_or_else(|| invalid(format!("`{path}` has no staged conflict to adopt")))?;
    let conflict = report.staged[index].clone();
    let staged = &conflict.staged_path;
    let metadata = fs::symlink_metadata(staged).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            tamper(format!(
                "the staged conflict `{path}` is missing from `{}`",
                staged.display()
            ))
        } else {
            io_error(format!("cannot inspect `{}`", staged.display()), error)
        }
    })?;
    if !metadata.file_type().is_symlink() && !metadata.is_file() {
        return Err(denied(format!(
            "staged `{path}` is a directory; adopt cannot replace a directory"
        )));
    }

    ensure_parent_dirs_adopt(&report.root, path)?;
    let target = join_relative(&report.root, path);
    match fs::symlink_metadata(&target) {
        Ok(existing) => {
            if existing.file_type().is_symlink() {
                // A symlink is a replaceable link, not a directory.
            } else if existing.is_dir() {
                return Err(denied(format!(
                    "`{}` is a directory; adopt never removes a directory",
                    target.display()
                )));
            }
            let current_hash = hash_existing(&target, &existing)?.ok_or_else(|| {
                denied(format!(
                    "`{}` is not a file or symlink; adopt refuses it",
                    target.display()
                ))
            })?;
            if conflict.existing_hash.as_deref() != Some(current_hash.as_str()) {
                return Err(denied(format!(
                    "`{}` changed after the conflict was staged; review it again",
                    target.display()
                )));
            }
            fs::remove_file(&target).map_err(|error| {
                io_error(format!("cannot remove `{}`", target.display()), error)
            })?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(io_error(
                format!("cannot inspect `{}`", target.display()),
                error,
            ))
        }
    }

    if metadata.file_type().is_symlink() {
        let link_target = fs::read_link(staged)
            .map_err(|error| io_error(format!("cannot read `{}`", staged.display()), error))?;
        let link_target = link_target
            .to_str()
            .ok_or_else(|| invalid(format!("staged symlink `{path}` target is not UTF-8")))?;
        validate_symlink_target(path, link_target)?;
        if !symlink_stays_inside(path, link_target) {
            return Err(invalid(format!(
                "staged symlink `{path}` target escapes the restore root"
            )));
        }
        if hash_hex(link_target.as_bytes()) != conflict.incoming_hash {
            return Err(tamper(format!(
                "staged symlink `{path}` no longer matches its incoming hash"
            )));
        }
        create_symlink(link_target, &target)?;
        let _ = fs::remove_file(staged);
    } else {
        let bytes = fs::read(staged)
            .map_err(|error| io_error(format!("cannot read `{}`", staged.display()), error))?;
        if hash_hex(&bytes) != conflict.incoming_hash {
            return Err(tamper(format!(
                "staged file `{path}` no longer matches its incoming hash"
            )));
        }
        if let Err(error) = fs::rename(staged, &target) {
            return Err(io_error(
                format!(
                    "cannot move the staged conflict `{}` into `{}`",
                    staged.display(),
                    target.display()
                ),
                error,
            ));
        }
    }

    report.staged.remove(index);
    report.conflicts = report.staged.len() as u64;
    report.restored.push(target.clone());
    Ok(target)
}

#[derive(Debug, Clone)]
enum Action {
    Create,
    Skip,
    Conflict {
        existing_hash: Option<String>,
        allow_overwrite: bool,
    },
}

#[derive(Debug, Clone, Copy)]
enum ComponentAction {
    Create,
    Skip,
}

struct Preflight {
    entries: BTreeMap<String, Action>,
    components: BTreeMap<String, ComponentAction>,
    children: Option<ComponentAction>,
}

fn preflight(plan: &RestorePlan, root: &Path, options: RestoreOptions) -> Result<Preflight> {
    let mut entries = BTreeMap::new();
    for entry in &plan.entries {
        entries.insert(
            entry.path.clone(),
            classify_entry(entry, root, options.overwrite_existing)?,
        );
    }

    let components_root = components_root(root, &plan.bundle_id);
    let mut components = BTreeMap::new();
    for (component, bytes) in &plan.components {
        let path = components_root.join(component.file_name());
        components.insert(
            component.file_name().to_string(),
            classify_component_file(&path, bytes)?,
        );
    }
    let children = match &plan.children {
        Some(bytes) => {
            let path = components_root.join(CHILDREN_FILE);
            Some(classify_component_file(&path, bytes)?)
        }
        None => None,
    };

    Ok(Preflight {
        entries,
        components,
        children,
    })
}

fn classify_entry(entry: &RestoreEntry, root: &Path, overwrite_existing: bool) -> Result<Action> {
    if let Some(blocker) = blocking_ancestor(root, &entry.path)? {
        let metadata = fs::symlink_metadata(&blocker)
            .map_err(|error| io_error(format!("cannot inspect `{}`", blocker.display()), error))?;
        return Ok(Action::Conflict {
            existing_hash: hash_existing(&blocker, &metadata)?,
            allow_overwrite: false,
        });
    }

    let destination = join_relative(root, &entry.path);
    let metadata = match fs::symlink_metadata(&destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Action::Create),
        Err(error) => {
            return Err(io_error(
                format!("cannot inspect `{}`", destination.display()),
                error,
            ))
        }
    };

    match &entry.kind {
        RestoreKind::File => {
            if metadata.file_type().is_symlink() {
                return Ok(Action::Conflict {
                    existing_hash: hash_existing(&destination, &metadata)?,
                    allow_overwrite: false,
                });
            }
            if metadata.is_dir() {
                return Ok(Action::Conflict {
                    existing_hash: None,
                    allow_overwrite: false,
                });
            }
            if metadata.is_file() {
                let existing = fs::read(&destination).map_err(|error| {
                    io_error(format!("cannot read `{}`", destination.display()), error)
                })?;
                if existing.len() as u64 == entry.bytes && hash_hex(&existing) == entry.hash {
                    return Ok(Action::Skip);
                }
                return Ok(Action::Conflict {
                    existing_hash: Some(hash_hex(&existing)),
                    allow_overwrite: overwrite_existing,
                });
            }
            Ok(Action::Conflict {
                existing_hash: None,
                allow_overwrite: false,
            })
        }
        RestoreKind::Symlink { target } => {
            if metadata.file_type().is_symlink() {
                let existing = fs::read_link(&destination).map_err(|error| {
                    io_error(format!("cannot read `{}`", destination.display()), error)
                })?;
                if existing == Path::new(target) {
                    return Ok(Action::Skip);
                }
                return Ok(Action::Conflict {
                    existing_hash: Some(hash_hex(existing.to_string_lossy().as_bytes())),
                    allow_overwrite: overwrite_existing,
                });
            }
            Ok(Action::Conflict {
                existing_hash: hash_existing(&destination, &metadata)?,
                allow_overwrite: false,
            })
        }
        RestoreKind::Dir => {
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Ok(Action::Skip)
            } else {
                Ok(Action::Conflict {
                    existing_hash: hash_existing(&destination, &metadata)?,
                    allow_overwrite: false,
                })
            }
        }
    }
}

fn classify_component_file(path: &Path, bytes: &[u8]) -> Result<ComponentAction> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(denied(format!(
                    "`{}` is a symlink; restore refuses to replace a component link",
                    path.display()
                )));
            }
            if !metadata.is_file() {
                return Err(denied(format!(
                    "`{}` exists and is not a component file",
                    path.display()
                )));
            }
            let existing = fs::read(path)
                .map_err(|error| io_error(format!("cannot read `{}`", path.display()), error))?;
            if existing == bytes {
                Ok(ComponentAction::Skip)
            } else {
                Err(tamper(format!(
                    "`{}` already holds different component content; restore does not overwrite it",
                    path.display()
                )))
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ComponentAction::Create),
        Err(error) => Err(io_error(
            format!("cannot inspect `{}`", path.display()),
            error,
        )),
    }
}

fn apply(
    plan: &RestorePlan,
    root: &Path,
    options: RestoreOptions,
    preflight: Preflight,
) -> Result<RestoreReport> {
    let mut rollback = Rollback::default();
    let mut report = RestoreReport {
        bundle_id: plan.bundle_id.clone(),
        root: root.to_path_buf(),
        restored: Vec::new(),
        overwritten: Vec::new(),
        skipped_identical: 0,
        skipped_components: 0,
        staged: Vec::new(),
        conflicts: 0,
        components: BTreeMap::new(),
        children: None,
    };

    let result = (|| -> Result<()> {
        ensure_root(root, &mut rollback)?;
        let zero = root.join(".zero");
        ensure_directory(&zero, &mut rollback)?;
        let teleport = root.join(TELEPORT_DIR);
        ensure_directory(&teleport, &mut rollback)?;
        let bundle_dir = teleport.join(&plan.bundle_id);
        ensure_directory(&bundle_dir, &mut rollback)?;
        let components_dir = bundle_dir.join(COMPONENTS_DIR);
        ensure_directory(&components_dir, &mut rollback)?;

        let mut entries: Vec<&RestoreEntry> = plan.entries.iter().collect();
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        for entry in entries {
            let action = preflight
                .entries
                .get(&entry.path)
                .ok_or_else(|| internal(format!("no preflight decision for `{}`", entry.path)))?
                .clone();
            match action {
                Action::Create => {
                    let path = create_entry(plan, entry, root, &mut rollback)?;
                    report.restored.push(path);
                }
                Action::Skip => report.skipped_identical += 1,
                Action::Conflict {
                    existing_hash,
                    allow_overwrite,
                } => {
                    let conflict = stage_conflict(plan, entry, root, existing_hash, &mut rollback)?;
                    report.staged.push(conflict);
                    if allow_overwrite && options.overwrite_existing {
                        let path = overwrite_entry(
                            plan,
                            entry,
                            root,
                            report.staged.last().expect("just pushed"),
                            &mut rollback,
                        )?;
                        report.overwritten.push(path.clone());
                        report.restored.push(path);
                    }
                }
            }
        }

        for component in Component::ALL {
            let Some(bytes) = plan.components.get(&component) else {
                continue;
            };
            let action = preflight
                .components
                .get(component.file_name())
                .ok_or_else(|| internal("no preflight decision for a component"))?;
            let path = components_dir.join(component.file_name());
            match action {
                ComponentAction::Create => {
                    write_atomic(&path, bytes, None, false)?;
                    rollback.file(&path);
                }
                ComponentAction::Skip => report.skipped_components += 1,
            }
            report.components.insert(component, path);
        }

        if let Some(children) = &plan.children {
            let action = preflight
                .children
                .as_ref()
                .ok_or_else(|| internal("no preflight decision for the child registry"))?;
            let path = components_dir.join(CHILDREN_FILE);
            match action {
                ComponentAction::Create => {
                    write_atomic(&path, children, None, false)?;
                    rollback.file(&path);
                }
                ComponentAction::Skip => report.skipped_components += 1,
            }
            report.children = Some(path);
        }

        Ok(())
    })();

    match result {
        Ok(()) => {
            report.conflicts = report.staged.len() as u64;
            Ok(report)
        }
        Err(error) => {
            let leftovers = rollback.run();
            if leftovers.is_empty() {
                Err(error)
            } else {
                Err(internal(format!(
                    "restore failed: {}; rollback left: {}",
                    error.message(),
                    leftovers.join(", ")
                )))
            }
        }
    }
}

fn create_entry(
    plan: &RestorePlan,
    entry: &RestoreEntry,
    root: &Path,
    rollback: &mut Rollback,
) -> Result<PathBuf> {
    ensure_parent_dirs(root, &entry.path, rollback)?;
    let destination = join_relative(root, &entry.path);
    match &entry.kind {
        RestoreKind::File => {
            let bytes = plan
                .contents
                .get(&entry.path)
                .ok_or_else(|| invalid(format!("`{}` has no content", entry.path)))?;
            write_atomic(&destination, bytes, entry.mode, false)?;
            rollback.file(&destination);
        }
        RestoreKind::Symlink { target } => {
            create_symlink(target, &destination)?;
            rollback.file(&destination);
        }
        RestoreKind::Dir => {
            fs::create_dir(&destination).map_err(|error| {
                io_error(
                    format!("cannot create directory `{}`", destination.display()),
                    error,
                )
            })?;
            rollback.dir(&destination);
            set_mode(&destination, entry.mode)?;
        }
    }
    Ok(destination)
}

fn stage_conflict(
    plan: &RestorePlan,
    entry: &RestoreEntry,
    root: &Path,
    existing_hash: Option<String>,
    rollback: &mut Rollback,
) -> Result<StagedConflict> {
    let staging_base = join_relative(root, RESTORE_STAGING_DIR);
    ensure_directory(&staging_base, rollback)?;
    let staging_root = staging_root(root, &plan.bundle_id);
    ensure_directory(&staging_root, rollback)?;
    ensure_parent_dirs(&staging_root, &entry.path, rollback)?;
    let staged = join_relative(&staging_root, &entry.path);

    match &entry.kind {
        RestoreKind::File => {
            let bytes = plan
                .contents
                .get(&entry.path)
                .ok_or_else(|| invalid(format!("`{}` has no content", entry.path)))?;
            stage_file(&staged, bytes, entry.hash.as_str(), entry.mode, rollback)?;
        }
        RestoreKind::Symlink { target } => {
            stage_symlink(&staged, target, rollback)?;
        }
        RestoreKind::Dir => {
            stage_dir(&staged, rollback)?;
        }
    }

    Ok(StagedConflict {
        path: entry.path.clone(),
        existing_hash,
        incoming_hash: entry.hash.clone(),
        staged_path: staged,
    })
}

fn stage_file(
    staged: &Path,
    bytes: &[u8],
    incoming_hash: &str,
    mode: Option<u32>,
    rollback: &mut Rollback,
) -> Result<()> {
    match fs::symlink_metadata(staged) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(denied(format!(
                    "staged path `{}` is not a regular file",
                    staged.display()
                )));
            }
            let existing = fs::read(staged)
                .map_err(|error| io_error(format!("cannot read `{}`", staged.display()), error))?;
            if hash_hex(&existing) == incoming_hash {
                return Ok(());
            }
            write_atomic(staged, bytes, mode, true)?;
            rollback.file(staged);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            write_atomic(staged, bytes, mode, false)?;
            rollback.file(staged);
        }
        Err(error) => {
            return Err(io_error(
                format!("cannot inspect `{}`", staged.display()),
                error,
            ))
        }
    }
    Ok(())
}

fn stage_symlink(staged: &Path, target: &str, rollback: &mut Rollback) -> Result<()> {
    match fs::symlink_metadata(staged) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                && fs::read_link(staged).ok().as_deref() == Some(Path::new(target))
            {
                return Ok(());
            }
            return Err(denied(format!(
                "staged path `{}` already holds something else",
                staged.display()
            )));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_symlink(target, staged)?;
            rollback.file(staged);
        }
        Err(error) => {
            return Err(io_error(
                format!("cannot inspect `{}`", staged.display()),
                error,
            ))
        }
    }
    Ok(())
}

fn stage_dir(staged: &Path, rollback: &mut Rollback) -> Result<()> {
    match fs::symlink_metadata(staged) {
        Ok(metadata) => {
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                return Ok(());
            }
            Err(denied(format!(
                "staged path `{}` already holds something else",
                staged.display()
            )))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(staged).map_err(|error| {
                io_error(
                    format!("cannot create staged directory `{}`", staged.display()),
                    error,
                )
            })?;
            rollback.dir(staged);
            Ok(())
        }
        Err(error) => Err(io_error(
            format!("cannot inspect `{}`", staged.display()),
            error,
        )),
    }
}

fn overwrite_entry(
    plan: &RestorePlan,
    entry: &RestoreEntry,
    root: &Path,
    conflict: &StagedConflict,
    rollback: &mut Rollback,
) -> Result<PathBuf> {
    let destination = join_relative(root, &entry.path);
    let metadata = fs::symlink_metadata(&destination)
        .map_err(|error| io_error(format!("cannot inspect `{}`", destination.display()), error))?;

    match &entry.kind {
        RestoreKind::File => {
            let current = fs::read(&destination).map_err(|error| {
                io_error(format!("cannot read `{}`", destination.display()), error)
            })?;
            if conflict.existing_hash.as_deref() != Some(hash_hex(&current).as_str()) {
                return Err(denied(format!(
                    "`{}` changed after preflight; restore does not overwrite it",
                    destination.display()
                )));
            }
            let bytes = plan
                .contents
                .get(&entry.path)
                .ok_or_else(|| invalid(format!("`{}` has no content", entry.path)))?;
            write_atomic(&destination, bytes, entry.mode, true)?;
        }
        RestoreKind::Symlink { target } => {
            if !metadata.file_type().is_symlink() {
                return Err(denied(format!(
                    "`{}` is no longer a symlink; restore does not overwrite it",
                    destination.display()
                )));
            }
            let current = fs::read_link(&destination).map_err(|error| {
                io_error(format!("cannot read `{}`", destination.display()), error)
            })?;
            if conflict.existing_hash.as_deref()
                != Some(hash_hex(current.to_string_lossy().as_bytes()).as_str())
            {
                return Err(denied(format!(
                    "`{}` changed after preflight; restore does not overwrite it",
                    destination.display()
                )));
            }
            fs::remove_file(&destination).map_err(|error| {
                io_error(format!("cannot remove `{}`", destination.display()), error)
            })?;
            create_symlink(target, &destination)?;
        }
        RestoreKind::Dir => {
            return Err(denied(format!(
                "`{}` is a directory conflict; restore never replaces a directory",
                destination.display()
            )))
        }
    }

    // The old bytes are not kept: this path was replaced by explicit opt-in.
    rollback.overwritten(&destination);
    Ok(destination)
}

fn blocking_ancestor(root: &Path, path: &str) -> Result<Option<PathBuf>> {
    let components: Vec<&str> = path.split('/').collect();
    let Some((_, parents)) = components.split_last() else {
        return Err(invalid("a restore path must not be empty"));
    };
    let mut current = root.to_path_buf();
    for component in parents {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => continue,
            Ok(_) => return Ok(Some(current)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(io_error(
                    format!("cannot inspect `{}`", current.display()),
                    error,
                ))
            }
        }
    }
    Ok(None)
}

fn preflight_internal(root: &Path, bundle_id: &str) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(denied(format!(
                    "`{}` is a symlink; restore requires a real target directory",
                    root.display()
                )));
            }
            if !metadata.is_dir() {
                return Err(invalid(format!(
                    "`{}` exists and is not a directory",
                    root.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(io_error(
                format!("cannot inspect `{}`", root.display()),
                error,
            ))
        }
    }

    let internal = [
        root.join(".zero"),
        root.join(RESTORE_STAGING_DIR),
        staging_root(root, bundle_id),
        root.join(TELEPORT_DIR),
        root.join(TELEPORT_DIR).join(bundle_id),
        components_root(root, bundle_id),
    ];
    for path in internal {
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(denied(format!(
                        "`{}` exists and is not a real directory; restore refuses internal state paths",
                        path.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io_error(
                    format!("cannot inspect `{}`", path.display()),
                    error,
                ))
            }
        }
    }
    Ok(())
}

fn ensure_root(root: &Path, rollback: &mut Rollback) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(root)
                .map_err(|error| io_error(format!("cannot create `{}`", root.display()), error))?;
            rollback.dir(root);
            let metadata = fs::symlink_metadata(root)
                .map_err(|error| io_error(format!("cannot inspect `{}`", root.display()), error))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(denied(format!(
                    "`{}` was replaced while it was created",
                    root.display()
                )));
            }
            Ok(())
        }
        Err(error) => Err(io_error(
            format!("cannot inspect `{}`", root.display()),
            error,
        )),
    }
}

fn ensure_directory(path: &Path, rollback: &mut Rollback) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(denied(format!(
                    "`{}` is a symlink; restore refuses to follow it",
                    path.display()
                )));
            }
            if !metadata.is_dir() {
                return Err(invalid(format!(
                    "`{}` exists and is not a directory",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|error| io_error(format!("cannot create `{}`", path.display()), error))?;
            rollback.dir(path);
            let metadata = fs::symlink_metadata(path)
                .map_err(|error| io_error(format!("cannot inspect `{}`", path.display()), error))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(denied(format!(
                    "`{}` was replaced while it was created",
                    path.display()
                )));
            }
        }
        Err(error) => {
            return Err(io_error(
                format!("cannot inspect `{}`", path.display()),
                error,
            ))
        }
    }
    Ok(())
}

fn ensure_parent_dirs(root: &Path, path: &str, rollback: &mut Rollback) -> Result<()> {
    let components: Vec<&str> = path.split('/').collect();
    let Some((_, parents)) = components.split_last() else {
        return Err(invalid("a restore path must not be empty"));
    };
    let mut current = root.to_path_buf();
    for component in parents {
        current.push(component);
        ensure_directory(&current, rollback)?;
    }
    Ok(())
}

fn ensure_parent_dirs_adopt(root: &Path, path: &str) -> Result<()> {
    let components: Vec<&str> = path.split('/').collect();
    let Some((_, parents)) = components.split_last() else {
        return Err(invalid("a restore path must not be empty"));
    };
    let mut current = root.to_path_buf();
    for component in parents {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(denied(format!(
                        "`{}` blocks the adopted path",
                        current.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    io_error(format!("cannot create `{}`", current.display()), error)
                })?;
            }
            Err(error) => {
                return Err(io_error(
                    format!("cannot inspect `{}`", current.display()),
                    error,
                ))
            }
        }
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8], mode: Option<u32>, replace: bool) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("a restore file name is not valid UTF-8"))?;
    let suffix = random_u64()?;
    let partial = path.with_file_name(format!(".{file_name}.{suffix:016x}.partial"));

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| io_error(format!("cannot create `{}`", partial.display()), error))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&partial);
        return Err(io_error(
            format!("cannot write `{}`", partial.display()),
            error,
        ));
    }
    drop(file);
    if let Err(error) = set_mode(&partial, mode) {
        let _ = fs::remove_file(&partial);
        return Err(error);
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) if replace => {
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                let _ = fs::remove_file(&partial);
                return Err(denied(format!(
                    "`{}` is a directory; restore never replaces it with a file",
                    path.display()
                )));
            }
            if let Err(error) = fs::remove_file(path) {
                let _ = fs::remove_file(&partial);
                return Err(io_error(
                    format!("cannot remove `{}`", path.display()),
                    error,
                ));
            }
        }
        Ok(_) => {
            let _ = fs::remove_file(&partial);
            return Err(denied(format!(
                "`{}` appeared during restore; it was not overwritten",
                path.display()
            )));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            let _ = fs::remove_file(&partial);
            return Err(io_error(
                format!("cannot inspect `{}`", path.display()),
                error,
            ));
        }
    }

    if let Err(error) = fs::rename(&partial, path) {
        let _ = fs::remove_file(&partial);
        return Err(io_error(
            format!("cannot move `{}` into place", partial.display()),
            error,
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: Option<u32>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode & MAX_MODE_BITS)).map_err(
            |error| {
                io_error(
                    format!("cannot set the mode of `{}`", path.display()),
                    error,
                )
            },
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(path: &Path, mode: Option<u32>) -> Result<()> {
    let _ = (path, mode);
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &str, link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link)
        .map_err(|error| io_error(format!("cannot create `{}`", link.display()), error))
}

#[cfg(not(unix))]
fn create_symlink(_target: &str, link: &Path) -> Result<()> {
    Err(denied(format!(
        "cannot create symlink `{}`: symlinks are not supported on this platform",
        link.display()
    )))
}

fn validate_symlink_target(path: &str, target: &str) -> Result<()> {
    if target.is_empty() {
        return Err(invalid(format!(
            "symlink `{path}` target must not be empty"
        )));
    }
    if target.len() > MAX_PATH_BYTES {
        return Err(limit(format!(
            "symlink `{path}` target is {} bytes; the limit is {MAX_PATH_BYTES}",
            target.len()
        )));
    }
    if target.chars().any(char::is_control) {
        return Err(invalid(format!(
            "symlink `{path}` target must not contain control characters"
        )));
    }
    if target.starts_with('/') || target.starts_with('\\') {
        return Err(invalid(format!(
            "symlink `{path}` target must be relative, not absolute"
        )));
    }
    if target.contains('\\') {
        return Err(invalid(format!(
            "symlink `{path}` target must use forward slashes"
        )));
    }
    let bytes = target.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(invalid(format!(
            "symlink `{path}` target must not carry a drive letter"
        )));
    }
    for component in target.split('/') {
        if component.is_empty() || component == "." {
            return Err(invalid(format!(
                "symlink `{path}` target has an empty or current-directory component"
            )));
        }
        if component.ends_with('.') || component.ends_with(' ') {
            return Err(invalid(format!(
                "symlink `{path}` target has a component ending with a dot or space"
            )));
        }
    }
    Ok(())
}

fn symlink_stays_inside(path: &str, target: &str) -> bool {
    let mut stack: Vec<&str> = path.split('/').collect();
    if stack.pop().is_none() {
        return false;
    }
    for component in target.split('/') {
        if component == ".." {
            if stack.pop().is_none() {
                return false;
            }
        } else {
            stack.push(component);
        }
    }
    true
}

fn assemble_file(bundle: &Bundle, path: &str, entry: &FileEntry) -> Result<Vec<u8>> {
    let capacity = usize::try_from(entry.bytes)
        .map_err(|_| limit(format!("`{path}` is too large to restore here")))?;
    let mut out = Vec::with_capacity(capacity);
    for chunk in &entry.chunks {
        let bytes = bundle
            .chunks
            .get(&chunk.hash)
            .ok_or_else(|| tamper(format!("chunk `{}` is missing from the bundle", chunk.hash)))?;
        if bytes.len() as u64 != chunk.bytes {
            return Err(tamper(format!(
                "`{path}` chunk `{}` is {} bytes but the manifest declares {}",
                chunk.hash,
                bytes.len(),
                chunk.bytes
            )));
        }
        out.extend_from_slice(bytes);
    }
    if out.len() as u64 != entry.bytes {
        return Err(tamper(format!(
            "`{path}` reassembles to {} bytes but the manifest declares {}",
            out.len(),
            entry.bytes
        )));
    }
    Ok(out)
}

fn check_component_size(label: &str, bytes: usize) -> Result<usize> {
    if bytes > MAX_COMPONENT_BYTES {
        return Err(limit(format!(
            "component `{label}` is {bytes} bytes; the per-component limit is {MAX_COMPONENT_BYTES}"
        )));
    }
    Ok(bytes)
}

fn component_allowed(component: Component) -> bool {
    component != Component::Manifest
}

fn components_root(root: &Path, bundle_id: &str) -> PathBuf {
    root.join(TELEPORT_DIR).join(bundle_id).join(COMPONENTS_DIR)
}

fn staging_root(root: &Path, bundle_id: &str) -> PathBuf {
    join_relative(root, RESTORE_STAGING_DIR).join(bundle_id)
}

fn join_relative(root: &Path, path: &str) -> PathBuf {
    let mut destination = root.to_path_buf();
    for component in path.split('/') {
        destination.push(component);
    }
    destination
}

fn hash_existing(path: &Path, metadata: &Metadata) -> Result<Option<String>> {
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)
            .map_err(|error| io_error(format!("cannot read `{}`", path.display()), error))?;
        return Ok(Some(hash_hex(target.to_string_lossy().as_bytes())));
    }
    if metadata.is_file() {
        let bytes = fs::read(path)
            .map_err(|error| io_error(format!("cannot read `{}`", path.display()), error))?;
        return Ok(Some(hash_hex(&bytes)));
    }
    Ok(None)
}

fn hash_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn validate_hex64(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{label} must be 64 lower-case hex characters"
        )));
    }
    Ok(())
}

fn random_u64() -> Result<u64> {
    let mut random = [0u8; 8];
    getrandom::getrandom(&mut random)
        .map_err(|error| internal(format!("cannot read random bytes: {error}")))?;
    Ok(u64::from_be_bytes(random))
}

#[derive(Default)]
struct Rollback {
    created: Vec<(PathBuf, Created)>,
    overwritten: Vec<PathBuf>,
}

enum Created {
    File,
    Dir,
}

impl Rollback {
    fn file(&mut self, path: &Path) {
        self.created.push((path.to_path_buf(), Created::File));
    }

    fn dir(&mut self, path: &Path) {
        self.created.push((path.to_path_buf(), Created::Dir));
    }

    fn overwritten(&mut self, path: &Path) {
        self.overwritten.push(path.to_path_buf());
    }

    fn run(self) -> Vec<String> {
        let mut problems = Vec::new();
        for (path, kind) in self.created.into_iter().rev() {
            let result = match kind {
                Created::File => fs::remove_file(&path),
                Created::Dir => fs::remove_dir(&path),
            };
            match result {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => problems.push(format!("`{}`: {error}", path.display())),
            }
        }
        for path in self.overwritten {
            problems.push(format!("`{}` was overwritten", path.display()));
        }
        problems
    }
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn tamper(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::TamperDetected, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn internal(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Internal, message)
}

fn io_error(message: impl Into<String>, error: io::Error) -> ZeroError {
    ZeroError::new(ErrorCode::Internal, format!("{}: {error}", message.into()))
}

type Result<T, E = ZeroError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{build, ChunkConfig, Excluded};
    #[cfg(unix)]
    use crate::bundle::{build_files, BundleFile};
    use tempfile::TempDir;

    const NOW: i64 = 1_700_000_000_000;

    fn config() -> ChunkConfig {
        ChunkConfig::new(1024, 256).expect("chunk config")
    }

    fn bundle_with(entries: &[(&str, &[u8])]) -> Bundle {
        let files: BTreeMap<String, Vec<u8>> = entries
            .iter()
            .map(|(path, bytes)| ((*path).to_string(), bytes.to_vec()))
            .collect();
        build(files, Vec::<Excluded>::new(), config(), NOW).expect("bundle")
    }

    fn component_blobs() -> BTreeMap<Component, Vec<u8>> {
        let mut components = BTreeMap::new();
        components.insert(Component::Session, b"{\"entries\":1}".to_vec());
        components.insert(Component::Kernel, b"kernel".to_vec());
        components.insert(Component::Artifacts, b"artifacts".to_vec());
        components.insert(Component::Goals, b"goals".to_vec());
        components.insert(Component::Schedules, b"schedules".to_vec());
        components.insert(Component::Ledger, b"ledger".to_vec());
        components
    }

    fn plan_for(bundle: &Bundle) -> RestorePlan {
        RestorePlan::from_bundle(
            bundle,
            component_blobs(),
            Some(b"children-registry".to_vec()),
        )
        .expect("plan")
    }

    fn manual_plan() -> RestorePlan {
        RestorePlan {
            bundle_id: "a".repeat(64),
            entries: Vec::new(),
            contents: BTreeMap::new(),
            components: BTreeMap::new(),
            children: None,
        }
    }

    fn add_file(plan: &mut RestorePlan, path: &str, bytes: &[u8], mode: Option<u32>) {
        plan.entries.push(RestoreEntry {
            path: path.to_string(),
            kind: RestoreKind::File,
            bytes: bytes.len() as u64,
            hash: hash_hex(bytes),
            mode,
            component: None,
        });
        plan.contents.insert(path.to_string(), bytes.to_vec());
    }

    fn add_dir(plan: &mut RestorePlan, path: &str, mode: Option<u32>) {
        plan.entries.push(RestoreEntry {
            path: path.to_string(),
            kind: RestoreKind::Dir,
            bytes: 0,
            hash: hash_hex(b""),
            mode,
            component: None,
        });
    }

    fn add_symlink(plan: &mut RestorePlan, path: &str, target: &str) {
        plan.entries.push(RestoreEntry {
            path: path.to_string(),
            kind: RestoreKind::Symlink {
                target: target.to_string(),
            },
            bytes: target.len() as u64,
            hash: hash_hex(target.as_bytes()),
            mode: None,
            component: None,
        });
        plan.contents
            .insert(path.to_string(), target.as_bytes().to_vec());
    }

    fn read(path: &Path) -> Vec<u8> {
        fs::read(path).expect("read restored path")
    }

    #[test]
    fn a_clean_restore_writes_entries_and_components() {
        let bundle = bundle_with(&[
            ("a.txt", b"alpha"),
            ("dir/b.bin", &[0x01, 0x02, 0x03, 0x00]),
        ]);
        let plan = plan_for(&bundle);
        let target = TempDir::new().expect("tempdir");

        let report = restore(&plan, target.path(), RestoreOptions::default()).expect("restore");

        assert_eq!(report.bundle_id, bundle.manifest.bundle_id);
        assert_eq!(report.restored.len(), 2);
        assert_eq!(report.skipped_identical, 0);
        assert_eq!(report.conflicts, 0);
        assert!(report.staged.is_empty());
        assert!(report.overwritten.is_empty());
        assert_eq!(read(&target.path().join("a.txt")), b"alpha");
        assert_eq!(
            read(&target.path().join("dir").join("b.bin")),
            [0x01, 0x02, 0x03, 0x00]
        );
        assert!(target.path().join("dir").is_dir());

        let components_dir = target
            .path()
            .join(TELEPORT_DIR)
            .join(&bundle.manifest.bundle_id)
            .join(COMPONENTS_DIR);
        assert_eq!(report.components.len(), 6);
        for (component, bytes) in component_blobs() {
            let path = report.components.get(&component).expect("component path");
            assert_eq!(path, &components_dir.join(component.file_name()));
            assert_eq!(read(path), bytes);
        }
        let children = report.children.as_ref().expect("child registry");
        assert_eq!(children, &components_dir.join(CHILDREN_FILE));
        assert_eq!(read(children), b"children-registry");
        assert!(!target.path().join(RESTORE_STAGING_DIR).exists());
    }

    #[test]
    fn a_conflicting_file_is_staged_and_not_overwritten() {
        let bundle = bundle_with(&[("notes.txt", b"incoming")]);
        let plan = plan_for(&bundle);
        let target = TempDir::new().expect("tempdir");
        fs::write(target.path().join("notes.txt"), b"existing").expect("existing file");

        let report = restore(&plan, target.path(), RestoreOptions::default()).expect("restore");

        assert_eq!(read(&target.path().join("notes.txt")), b"existing");
        assert!(report.restored.is_empty());
        assert_eq!(report.conflicts, 1);
        assert_eq!(report.staged.len(), 1);

        let conflict = &report.staged[0];
        assert_eq!(conflict.path, "notes.txt");
        assert_eq!(
            conflict.existing_hash.as_deref(),
            Some(hash_hex(b"existing").as_str())
        );
        assert_eq!(conflict.incoming_hash, hash_hex(b"incoming"));
        assert_eq!(read(&conflict.staged_path), b"incoming");
        assert_eq!(
            conflict.staged_path,
            target
                .path()
                .join(RESTORE_STAGING_DIR)
                .join(&bundle.manifest.bundle_id)
                .join("notes.txt")
        );
    }

    #[test]
    fn identical_files_are_skipped_and_not_staged() {
        let bundle = bundle_with(&[("notes.txt", b"same")]);
        let plan = plan_for(&bundle);
        let target = TempDir::new().expect("tempdir");
        fs::write(target.path().join("notes.txt"), b"same").expect("existing file");

        let report = restore(&plan, target.path(), RestoreOptions::default()).expect("restore");

        assert_eq!(report.skipped_identical, 1);
        assert!(report.restored.is_empty());
        assert!(report.staged.is_empty());
        assert_eq!(report.conflicts, 0);
        assert_eq!(read(&target.path().join("notes.txt")), b"same");
    }

    #[test]
    fn a_file_directory_type_conflict_is_staged_and_never_replaced() {
        let bundle = bundle_with(&[("a.txt", b"incoming")]);
        let plan = plan_for(&bundle);
        let target = TempDir::new().expect("tempdir");
        fs::create_dir(target.path().join("a.txt")).expect("directory in the way");

        let mut report = restore(&plan, target.path(), RestoreOptions::default()).expect("restore");

        assert!(target.path().join("a.txt").is_dir());
        assert_eq!(report.staged.len(), 1);
        assert!(report.staged[0].existing_hash.is_none());
        assert_eq!(read(&report.staged[0].staged_path), b"incoming");
        assert_eq!(
            adopt(&mut report, "a.txt")
                .expect_err("a directory is never adopted")
                .code(),
            ErrorCode::PolicyDenied
        );
        assert!(target.path().join("a.txt").is_dir());
    }

    #[test]
    fn overwrite_existing_replaces_per_path_and_records_it() {
        let bundle = bundle_with(&[("a.txt", b"incoming")]);
        let plan = plan_for(&bundle);
        let target = TempDir::new().expect("tempdir");
        fs::write(target.path().join("a.txt"), b"existing").expect("existing file");

        let report = restore(
            &plan,
            target.path(),
            RestoreOptions {
                overwrite_existing: true,
            },
        )
        .expect("restore");

        assert_eq!(read(&target.path().join("a.txt")), b"incoming");
        assert_eq!(report.overwritten.len(), 1);
        assert_eq!(report.overwritten[0], target.path().join("a.txt"));
        assert_eq!(report.restored.len(), 1);
        assert_eq!(report.staged.len(), 1);
        assert_eq!(report.staged[0].path, "a.txt");
        assert_eq!(read(&report.staged[0].staged_path), b"incoming");
    }

    #[cfg(unix)]
    #[test]
    fn modes_are_applied_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let mut files = BTreeMap::new();
        files.insert(
            "bin/run.sh".to_string(),
            BundleFile::file(b"#!/bin/sh\n".to_vec()).with_mode(0o640),
        );
        let bundle = build_files(files, Vec::<Excluded>::new(), config(), NOW).expect("bundle");
        let plan = RestorePlan::from_bundle(&bundle, BTreeMap::new(), None).expect("plan");
        let target = TempDir::new().expect("tempdir");

        restore(&plan, target.path(), RestoreOptions::default()).expect("restore");

        let mode = fs::metadata(target.path().join("bin").join("run.sh"))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640);
        assert_eq!(
            read(&target.path().join("bin").join("run.sh")),
            b"#!/bin/sh\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_recorded_symlink_inside_the_root_is_created() {
        let mut files = BTreeMap::new();
        files.insert("real.txt".to_string(), BundleFile::file(b"real".to_vec()));
        files.insert(
            "link.txt".to_string(),
            BundleFile::symlink(b"real.txt".to_vec()),
        );
        let bundle = build_files(files, Vec::<Excluded>::new(), config(), NOW).expect("bundle");
        let plan = RestorePlan::from_bundle(&bundle, BTreeMap::new(), None).expect("plan");
        let target = TempDir::new().expect("tempdir");

        let report = restore(&plan, target.path(), RestoreOptions::default()).expect("restore");

        assert_eq!(report.restored.len(), 2);
        assert_eq!(read(&target.path().join("real.txt")), b"real");
        assert_eq!(
            fs::read_link(target.path().join("link.txt")).expect("read link"),
            PathBuf::from("real.txt")
        );
    }

    #[test]
    fn a_symlink_target_outside_the_root_is_refused_before_any_write() {
        let mut plan = manual_plan();
        add_file(&mut plan, "real.txt", b"real", None);
        add_symlink(&mut plan, "bad", "../escape");
        let target = TempDir::new().expect("tempdir");

        let error = restore(&plan, target.path(), RestoreOptions::default())
            .expect_err("an escaping symlink must be refused");

        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(!target.path().join(".zero").exists());
        assert!(!target.path().join("real.txt").exists());
    }

    #[test]
    fn unsafe_entry_paths_are_refused_before_any_write() {
        for path in [
            "../escape.txt",
            "/absolute.txt",
            "a\\b.txt",
            "C:/windows.txt",
        ] {
            let mut plan = manual_plan();
            add_file(&mut plan, path, b"value", None);
            let target = TempDir::new().expect("tempdir");

            let error = restore(&plan, target.path(), RestoreOptions::default())
                .expect_err("an unsafe path must be refused");
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{path}");
            assert!(!target.path().join(".zero").exists(), "{path}");
        }
    }

    #[test]
    fn preflight_prevents_a_partial_restore_on_an_invalid_plan() {
        let mut plan = manual_plan();
        add_file(&mut plan, "ok.txt", b"ok", None);
        let duplicate = plan.entries[0].clone();
        plan.entries.push(duplicate);
        let target = TempDir::new().expect("tempdir");

        let error = restore(&plan, target.path(), RestoreOptions::default())
            .expect_err("a duplicate path invalidates the whole plan");

        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(!target.path().join("ok.txt").exists());
        assert!(!target.path().join(".zero").exists());

        let mut nested = manual_plan();
        add_file(&mut nested, "a", b"file", None);
        add_file(&mut nested, "a/b.txt", b"nested", None);
        let nested_target = TempDir::new().expect("tempdir");
        let error = restore(&nested, nested_target.path(), RestoreOptions::default())
            .expect_err("a file cannot be a parent of another entry");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(!nested_target.path().join("a").exists());
        assert!(!nested_target.path().join(".zero").exists());
    }

    #[test]
    fn adopt_moves_a_staged_file_into_place() {
        let bundle = bundle_with(&[("notes.txt", b"incoming")]);
        let plan = plan_for(&bundle);
        let target = TempDir::new().expect("tempdir");
        fs::write(target.path().join("notes.txt"), b"existing").expect("existing file");
        let mut report = restore(&plan, target.path(), RestoreOptions::default()).expect("restore");
        let staged = report.staged[0].staged_path.clone();

        let adopted = adopt(&mut report, "notes.txt").expect("adopt");

        assert_eq!(adopted, target.path().join("notes.txt"));
        assert_eq!(read(&target.path().join("notes.txt")), b"incoming");
        assert!(!staged.exists());
        assert!(report.staged.is_empty());
        assert_eq!(report.conflicts, 0);
        assert_eq!(report.restored, vec![target.path().join("notes.txt")]);
    }

    #[test]
    fn a_second_restore_stages_nothing_new() {
        let bundle = bundle_with(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let plan = plan_for(&bundle);
        let target = TempDir::new().expect("tempdir");
        let first = restore(&plan, target.path(), RestoreOptions::default()).expect("first");
        assert_eq!(first.restored.len(), 2);

        let second = restore(&plan, target.path(), RestoreOptions::default()).expect("second");

        assert!(second.restored.is_empty());
        assert!(second.staged.is_empty());
        assert_eq!(second.conflicts, 0);
        assert_eq!(second.skipped_identical, 2);
        assert_eq!(second.skipped_components, 7);
        assert_eq!(second.components, first.components);
        assert_eq!(second.children, first.children);
        assert!(!target.path().join(RESTORE_STAGING_DIR).exists());
    }

    #[test]
    fn the_component_set_and_modes_are_validated() {
        let bundle = bundle_with(&[("a.txt", b"alpha")]);
        let plan = plan_for(&bundle);
        let target = TempDir::new().expect("tempdir");

        let mut with_manifest = plan.clone();
        with_manifest
            .components
            .insert(Component::Manifest, b"workspace".to_vec());
        assert_eq!(
            restore(&with_manifest, target.path(), RestoreOptions::default())
                .expect_err("the workspace manifest is not a component")
                .code(),
            ErrorCode::PolicyDenied
        );

        let mut bad_mode = plan.clone();
        bad_mode.entries[0].mode = Some(0o10000);
        assert_eq!(
            restore(&bad_mode, target.path(), RestoreOptions::default())
                .expect_err("a mode outside 0o7777 is refused")
                .code(),
            ErrorCode::InvalidInput
        );
        assert!(!target.path().join(".zero").exists());
        assert!(!target.path().join("a.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_unrecorded_symlink_is_staged_and_never_followed() {
        let bundle = bundle_with(&[("notes.txt", b"incoming")]);
        let plan = plan_for(&bundle);
        let target = TempDir::new().expect("tempdir");
        let outside = TempDir::new().expect("outside");
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, b"secret").expect("outside secret");
        std::os::unix::fs::symlink(&secret, target.path().join("notes.txt"))
            .expect("unrecorded symlink");

        let report = restore(&plan, target.path(), RestoreOptions::default()).expect("restore");

        assert_eq!(
            fs::read_link(target.path().join("notes.txt")).expect("link still there"),
            secret
        );
        assert_eq!(read(&secret), b"secret");
        assert_eq!(report.staged.len(), 1);
        assert_eq!(read(&report.staged[0].staged_path), b"incoming");
    }

    #[test]
    fn directory_entries_are_created_inside_the_root() {
        let mut plan = manual_plan();
        add_dir(&mut plan, "empty", Some(0o750));
        add_file(&mut plan, "empty/nested.txt", b"nested", None);
        let target = TempDir::new().expect("tempdir");

        let report = restore(&plan, target.path(), RestoreOptions::default()).expect("restore");

        assert_eq!(report.restored.len(), 2);
        assert!(target.path().join("empty").is_dir());
        assert_eq!(
            read(&target.path().join("empty").join("nested.txt")),
            b"nested"
        );
    }
}
