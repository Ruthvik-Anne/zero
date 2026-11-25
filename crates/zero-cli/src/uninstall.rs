//! Uninstall (T-INST-07, INST-07, INST-12).
//!
//! The module plans and executes one uninstall. It never deletes user data with
//! a raw filesystem call: data and config go through [`TrashService`], services
//! go through [`ServiceManager`], and the PATH entry is removed by exact match
//! from the injected environment vector.
//!
//! Execution order is fixed so a failure can never leave an installed service
//! pointing at removed binaries:
//!
//! 1. refuse unless a matching, unexpired [`Confirmation`] is presented;
//! 2. stop and uninstall the service;
//! 3. remove the exact PATH entry;
//! 4. move config and/or data to the trash according to the scope;
//! 5. remove the binaries last.
//!
//! A failure stops the sequence at the failed step. The returned
//! [`UninstallReport`] still describes what was removed, what remains, and
//! whether orphaned state survives; a non-empty `remaining` or `orphaned` means
//! the uninstall is incomplete. Success always has an empty `remaining` and
//! `orphaned == false`.

use crate::service::ServiceManager;
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zero_fs::{TrashOutcome, TrashService};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// How much of the installation an uninstall removes.
/// The trash operation an uninstall needs. Implemented by the real
/// [`TrashService`]; tests inject a deterministic trash.
pub trait TrashSink {
    /// Move one path to the trash. A refusal leaves the original in place.
    fn trash(&self, path: &Path) -> Result<TrashOutcome>;
}

impl TrashSink for TrashService {
    fn trash(&self, path: &Path) -> Result<TrashOutcome> {
        TrashService::trash(self, path)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninstallScope {
    /// Remove the binaries, the service, and the PATH entry. Keep config and
    /// all user data.
    BinaryOnly,
    /// Also move config to the trash. Keep user data.
    KeepData,
    /// Also move user data to the trash. Nothing the installation created
    /// remains.
    Everything,
}

impl UninstallScope {
    /// Stable scope string, e.g. `keep_data`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BinaryOnly => "binary_only",
            Self::KeepData => "keep_data",
            Self::Everything => "everything",
        }
    }

    /// Whether this scope moves user data to the trash.
    pub const fn trashes_data(self) -> bool {
        matches!(self, Self::Everything)
    }

    /// Whether this scope moves config to the trash.
    pub const fn trashes_config(self) -> bool {
        matches!(self, Self::KeepData | Self::Everything)
    }
}

/// Upper bound on one planned path.
pub const MAX_UNINSTALL_PATH_BYTES: usize = 512;

/// Upper bound on a PATH entry recorded in a plan.
pub const MAX_PATH_ENTRY_BYTES: usize = 4096;

/// Upper bound on a service name.
pub const MAX_SERVICE_NAME_BYTES: usize = 64;

/// How long a confirmation stays valid.
pub const CONFIRMATION_TTL_MS: u64 = 5 * 60 * 1000;

const CONFIRMATION_TAG: &[u8] = b"zero.uninstall.confirmation\0v1\0";
const PLAN_TAG: &[u8] = b"zero.uninstall.plan\0v1\0";

static CONFIRMATION_NONCE: AtomicU64 = AtomicU64::new(0);

/// One validated uninstall plan.
///
/// Build it with [`plan_uninstall`] and validate it with
/// [`UninstallPlan::validate`]. The planner stores the roots it was given; a
/// hand-built plan is still revalidated before a confirmation is minted and
/// before anything is removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallPlan {
    /// What to remove.
    pub scope: UninstallScope,
    /// Absolute directory holding the installed binaries.
    pub binary_dir: PathBuf,
    /// Absolute user-data root.
    pub data_dir: PathBuf,
    /// Absolute config root.
    pub config_dir: PathBuf,
    /// The service to stop and uninstall, when the installation registered one.
    pub service_name: Option<String>,
    /// The exact PATH entry to remove.
    pub path_entry: Option<String>,
    /// Whether the PATH entry should be removed. A missing entry with this set
    /// is refused by validation.
    pub remove_path_entry: bool,
}

impl UninstallPlan {
    /// Validate every field.
    ///
    /// Paths must be absolute, bounded, valid UTF-8, free of `.` and `..`
    /// components, and not the filesystem root. Data, config, and binaries must
    /// be three disjoint directories: none may equal or contain another, so a
    /// plan can never trash the install root or one root through another.
    pub fn validate(&self) -> Result<()> {
        validate_dir(&self.binary_dir, "binary_dir")?;
        validate_dir(&self.data_dir, "data_dir")?;
        validate_dir(&self.config_dir, "config_dir")?;
        ensure_disjoint(&self.binary_dir, &self.data_dir, "binary_dir", "data_dir")?;
        ensure_disjoint(
            &self.binary_dir,
            &self.config_dir,
            "binary_dir",
            "config_dir",
        )?;
        ensure_disjoint(&self.data_dir, &self.config_dir, "data_dir", "config_dir")?;
        if let Some(name) = &self.service_name {
            validate_service_name(name)?;
        }
        match (&self.path_entry, self.remove_path_entry) {
            (Some(entry), _) => validate_path_entry(entry)?,
            (None, true) => {
                return Err(invalid(
                    "remove_path_entry is set but the plan has no path_entry to remove",
                ))
            }
            (None, false) => {}
        }
        Ok(())
    }
}

/// The directories this plan moves to the trash, in execution order.
fn trash_targets(plan: &UninstallPlan) -> Vec<&PathBuf> {
    let mut targets = Vec::new();
    if plan.scope.trashes_data() {
        targets.push(&plan.data_dir);
    }
    if plan.scope.trashes_config() {
        targets.push(&plan.config_dir);
    }
    targets
}

/// Build a plan from the installer roots.
///
/// `install_root` is the directory that holds the binaries; it is also the PATH
/// entry the installer added. Validation is separate so a caller can build and
/// preview a plan before asking for confirmation.
pub fn plan_uninstall(
    scope: UninstallScope,
    install_root: impl Into<PathBuf>,
    data_root: impl Into<PathBuf>,
    config_root: impl Into<PathBuf>,
    service: Option<String>,
) -> UninstallPlan {
    let binary_dir = install_root.into();
    let path_entry = binary_dir.to_str().map(ToString::to_string);
    UninstallPlan {
        scope,
        binary_dir,
        data_dir: data_root.into(),
        config_dir: config_root.into(),
        service_name: service,
        remove_path_entry: path_entry.is_some(),
        path_entry,
    }
}

/// Describe exactly what the plan would remove or trash.
///
/// The preview contains paths and a service name only; it never contains
/// environment values, credentials, or file contents. The order matches the
/// execution order.
pub fn preview(plan: &UninstallPlan) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(name) = &plan.service_name {
        lines.push(format!("stop and uninstall service `{name}`"));
    }
    if plan.remove_path_entry {
        if let Some(entry) = &plan.path_entry {
            lines.push(format!("remove PATH entry `{entry}`"));
        }
    }
    for target in trash_targets(plan) {
        lines.push(format!("move `{}` to the trash", target.display()));
    }
    for binary in binary_files(&plan.binary_dir) {
        lines.push(format!("remove binary `{}`", binary.display()));
    }
    lines
}

/// Proof that the user approved this exact plan.
///
/// A confirmation is minted by [`request_confirmation`] with a short TTL and a
/// fingerprint of the plan. It cannot be reused for a different plan, and it
/// expires. The token is opaque; it carries no user data or secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    /// The opaque approval token.
    pub token: String,
    plan_hash: String,
    issued_ms: u64,
    expires_ms: u64,
}

impl Confirmation {
    /// When the confirmation stops being valid, in Unix milliseconds.
    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }

    /// The fingerprint of the plan this confirmation approves.
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }
}

/// Mint a confirmation for one validated plan.
///
/// The TTL is [`CONFIRMATION_TTL_MS`]. The token is derived from the plan
/// fingerprint, `now_ms`, the process id, and a monotonic nonce; it is not a
/// secret and is not reused across calls.
pub fn request_confirmation(plan: &UninstallPlan, now_ms: u64) -> Result<Confirmation> {
    plan.validate()?;
    let plan_hash = plan_hash(plan);
    let nonce = CONFIRMATION_NONCE.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(CONFIRMATION_TAG);
    hasher.update(plan_hash.as_bytes());
    hasher.update(now_ms.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    let token = hex(&hasher.finalize());
    Ok(Confirmation {
        token,
        plan_hash,
        issued_ms: now_ms,
        expires_ms: now_ms.saturating_add(CONFIRMATION_TTL_MS),
    })
}

/// What one uninstall attempt removed and what remains.
///
/// `service_removed` and `binaries_removed` are vacuously true when the plan
/// had no such target. `trashed` names only paths the trash service confirmed
/// it moved. `remaining` lists targets the plan meant to remove that still
/// exist; it is empty on success and excludes data/config a scope deliberately
/// keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallReport {
    /// True when the planned service is no longer installed.
    pub service_removed: bool,
    /// True when the planned exact PATH entry is no longer present.
    pub path_entry_removed: bool,
    /// Paths the trash service moved, in trash order.
    pub trashed: Vec<PathBuf>,
    /// True when every planned binary file is gone.
    pub binaries_removed: bool,
    /// Planned removals that still exist.
    pub remaining: Vec<PathBuf>,
    /// True when any service, PATH entry, binary, or data the plan meant to
    /// remove survives.
    pub orphaned: bool,
}

impl UninstallReport {
    /// True when nothing the plan meant to remove survives.
    pub fn is_complete(&self) -> bool {
        self.remaining.is_empty() && !self.orphaned
    }
}

/// Execute a confirmed uninstall.
///
/// Refusals before any mutation (invalid plan, missing/expired/mismatched
/// confirmation) return a `zero.pol.ask` or `zero.fnd.invalid_input` error.
/// Failures during execution stop the sequence and return an `Ok` report whose
/// `remaining` and `orphaned` fields describe the surviving state, so a caller
/// can never mistake a partial uninstall for success.
///
/// The service is stopped and uninstalled first, and binaries are removed last.
/// If the service step fails, nothing later is touched: an installed service is
/// never left pointing at a missing binary.
pub fn uninstall(
    plan: &UninstallPlan,
    confirmation: &Confirmation,
    now_ms: u64,
    trash: &dyn TrashSink,
    services: &dyn ServiceManager,
    path_env: &mut Vec<String>,
) -> Result<UninstallReport> {
    plan.validate()?;
    verify_confirmation(plan, confirmation, now_ms)?;

    let mut report = UninstallReport {
        service_removed: plan.service_name.is_none(),
        path_entry_removed: !plan.remove_path_entry,
        trashed: Vec::new(),
        binaries_removed: false,
        remaining: Vec::new(),
        orphaned: false,
    };
    let mut blocked = false;

    // 1. Service first. Never remove binaries while a service may reference
    //    them.
    if let Some(name) = &plan.service_name {
        let stopped = services.stop(name).is_ok();
        let uninstalled = services.uninstall(name).is_ok();
        report.service_removed = stopped && uninstalled;
        blocked = !report.service_removed;
    }

    // 2. PATH entry, by exact match only.
    if !blocked && plan.remove_path_entry {
        if let Some(entry) = &plan.path_entry {
            path_env.retain(|candidate| candidate != entry);
            report.path_entry_removed = !path_env.iter().any(|candidate| candidate == entry);
        } else {
            report.path_entry_removed = true;
        }
    }

    // 3. Data and config through the trash, according to the scope.
    if !blocked {
        for target in trash_targets(plan) {
            if !target.exists() {
                continue;
            }
            match trash.trash(target) {
                Ok(TrashOutcome::Trashed { path }) => report.trashed.push(path),
                // A refusal leaves the original in place. Treat it as a failure
                // and stop before the binaries.
                Ok(TrashOutcome::Refused { .. }) | Err(_) => {
                    blocked = true;
                    break;
                }
            }
        }
    }

    // 4. Binaries last.
    if !blocked {
        for binary in binary_files(&plan.binary_dir) {
            if binary.exists() || std::fs::symlink_metadata(&binary).is_ok() {
                let _ = std::fs::remove_file(&binary);
            }
        }
        // Remove the install directory only when it is empty. Unrelated files
        // are left alone rather than deleted.
        if plan.binary_dir.exists() {
            let empty = std::fs::read_dir(&plan.binary_dir)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false);
            if empty {
                let _ = std::fs::remove_dir(&plan.binary_dir);
            }
        }
        report.binaries_removed = binary_files(&plan.binary_dir)
            .iter()
            .all(|binary| !binary.exists() && std::fs::symlink_metadata(binary).is_err());
    }

    report.remaining = remaining_paths(plan);
    let path_entry_survives = plan.remove_path_entry
        && plan
            .path_entry
            .as_ref()
            .is_some_and(|entry| path_env.iter().any(|candidate| candidate == entry));
    report.orphaned = !report.remaining.is_empty()
        || (plan.service_name.is_some() && !report.service_removed)
        || path_entry_survives;
    Ok(report)
}

/// Planned targets that still exist, in execution order.
fn remaining_paths(plan: &UninstallPlan) -> Vec<PathBuf> {
    let mut remaining = Vec::new();
    for target in trash_targets(plan) {
        if target.exists() {
            remaining.push(target.clone());
        }
    }
    for binary in binary_files(&plan.binary_dir) {
        if binary.exists() {
            remaining.push(binary);
        }
    }
    remaining
}

/// The executable names an installation may have written into `binary_dir`.
fn binary_files(binary_dir: &Path) -> Vec<PathBuf> {
    ["zero", "zero.exe"]
        .iter()
        .map(|name| binary_dir.join(name))
        .collect()
}

fn verify_confirmation(
    plan: &UninstallPlan,
    confirmation: &Confirmation,
    now_ms: u64,
) -> Result<()> {
    if confirmation.token.is_empty() {
        return Err(ask("the uninstall confirmation token is empty"));
    }
    if confirmation.plan_hash != plan_hash(plan) {
        return Err(ask(
            "the confirmation was issued for a different uninstall plan",
        ));
    }
    if now_ms < confirmation.issued_ms || now_ms > confirmation.expires_ms {
        return Err(ask(
            "the uninstall confirmation has expired; request a fresh confirmation",
        ));
    }
    Ok(())
}

fn plan_hash(plan: &UninstallPlan) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_TAG);
    hash_text(&mut hasher, plan.scope.as_str());
    hash_text(&mut hasher, &plan.binary_dir.to_string_lossy());
    hash_text(&mut hasher, &plan.data_dir.to_string_lossy());
    hash_text(&mut hasher, &plan.config_dir.to_string_lossy());
    match &plan.service_name {
        Some(name) => {
            hasher.update([1]);
            hash_text(&mut hasher, name);
        }
        None => hasher.update([0]),
    }
    match &plan.path_entry {
        Some(entry) => {
            hasher.update([1]);
            hash_text(&mut hasher, entry);
        }
        None => hasher.update([0]),
    }
    hasher.update([u8::from(plan.remove_path_entry)]);
    hex(&hasher.finalize())
}

fn hash_text(hasher: &mut Sha256, text: &str) {
    hasher.update((text.len() as u64).to_le_bytes());
    hasher.update(text.as_bytes());
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn validate_dir(path: &Path, field: &str) -> Result<()> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid(format!("{field} is not valid UTF-8")))?;
    if !path.is_absolute() {
        return Err(invalid(format!("{field} must be absolute: `{text}`")));
    }
    if text.len() > MAX_UNINSTALL_PATH_BYTES {
        return Err(invalid(format!(
            "{field} is {} bytes, above the {MAX_UNINSTALL_PATH_BYTES} byte limit",
            text.len()
        )));
    }
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{field} is empty or contains a control character"
        )));
    }
    let mut normal_components = 0usize;
    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err(invalid(format!(
                    "{field} contains a `..` component: `{text}`"
                )))
            }
            Component::CurDir => {
                return Err(invalid(format!(
                    "{field} contains a `.` component: `{text}`"
                )))
            }
            Component::Normal(_) => normal_components += 1,
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    if normal_components == 0 {
        return Err(invalid(format!("{field} is the filesystem root: `{text}`")));
    }
    Ok(())
}

fn ensure_disjoint(a: &Path, b: &Path, a_name: &str, b_name: &str) -> Result<()> {
    if a == b {
        return Err(invalid(format!(
            "{a_name} and {b_name} are the same directory: `{}`",
            a.display()
        )));
    }
    if a.starts_with(b) || b.starts_with(a) {
        return Err(invalid(format!(
            "{a_name} and {b_name} must not contain one another: `{}` and `{}`",
            a.display(),
            b.display()
        )));
    }
    Ok(())
}

fn validate_service_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(invalid("service_name is empty"));
    }
    if name.len() > MAX_SERVICE_NAME_BYTES {
        return Err(invalid(format!(
            "service_name is {} bytes, above the {MAX_SERVICE_NAME_BYTES} byte limit",
            name.len()
        )));
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => {
            return Err(invalid(
                "service_name must start with an ASCII letter or digit",
            ))
        }
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@')) {
        return Err(invalid(format!(
            "service_name `{name}` may contain only letters, digits, `.`, `_`, `-`, and `@`"
        )));
    }
    Ok(())
}

fn validate_path_entry(entry: &str) -> Result<()> {
    if entry.is_empty() {
        return Err(invalid("path_entry is empty"));
    }
    if entry.len() > MAX_PATH_ENTRY_BYTES {
        return Err(invalid(format!(
            "path_entry is {} bytes, above the {MAX_PATH_ENTRY_BYTES} byte limit",
            entry.len()
        )));
    }
    if entry.chars().any(char::is_control) {
        return Err(invalid("path_entry contains a control character"));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn ask(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyAskRequired, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{ServiceError, ServiceErrorKind, ServiceStatus};
    use std::cell::{Cell, RefCell};
    use tempfile::TempDir;

    fn exe_name() -> &'static str {
        if cfg!(windows) {
            "zero.exe"
        } else {
            "zero"
        }
    }

    struct RecordingManager {
        calls: RefCell<Vec<String>>,
        fail_stop: bool,
        fail_uninstall: bool,
        binary: PathBuf,
        binary_present_at_uninstall: Cell<bool>,
    }

    impl RecordingManager {
        fn new(binary: PathBuf) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail_stop: false,
                fail_uninstall: false,
                binary,
                binary_present_at_uninstall: Cell::new(false),
            }
        }

        fn failing_uninstall(binary: PathBuf) -> Self {
            Self {
                fail_uninstall: true,
                ..Self::new(binary)
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl ServiceManager for RecordingManager {
        fn start(&self, _name: &str) -> crate::service::ServiceResult<()> {
            self.calls.borrow_mut().push("start".to_string());
            Ok(())
        }

        fn stop(&self, name: &str) -> crate::service::ServiceResult<()> {
            self.calls.borrow_mut().push(format!("stop:{name}"));
            if self.fail_stop {
                return Err(ServiceError::new(ServiceErrorKind::Manager, "stop failed"));
            }
            Ok(())
        }

        fn status(&self, _name: &str) -> crate::service::ServiceResult<ServiceStatus> {
            Ok(ServiceStatus::Stopped)
        }

        fn install(&self, _unit_path: &Path) -> crate::service::ServiceResult<()> {
            self.calls.borrow_mut().push("install".to_string());
            Ok(())
        }

        fn uninstall(&self, name: &str) -> crate::service::ServiceResult<()> {
            self.calls.borrow_mut().push(format!("uninstall:{name}"));
            self.binary_present_at_uninstall.set(self.binary.exists());
            if self.fail_uninstall {
                return Err(ServiceError::new(
                    ServiceErrorKind::Manager,
                    "uninstall failed",
                ));
            }
            Ok(())
        }
    }

    struct Fixture {
        _dir: TempDir,
        bin: PathBuf,
        data: PathBuf,
        config: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path();
            let bin = home.join("bin");
            let data = home.join("data");
            let config = home.join("config");
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::create_dir_all(&data).unwrap();
            std::fs::create_dir_all(&config).unwrap();
            std::fs::write(bin.join(exe_name()), b"binary").unwrap();
            std::fs::write(data.join("session.log"), b"user data").unwrap();
            std::fs::write(config.join("settings.json"), b"{}").unwrap();
            Self {
                _dir: dir,
                bin,
                data,
                config,
            }
        }

        fn home(&self) -> &Path {
            self._dir.path()
        }

        fn trash(&self) -> RecordingTrash {
            RecordingTrash::new(self.home().join("test-trash"))
        }
    }

    struct RecordingTrash {
        root: PathBuf,
        refuse: Option<PathBuf>,
    }

    impl RecordingTrash {
        fn new(root: PathBuf) -> Self {
            Self { root, refuse: None }
        }

        fn refusing(root: PathBuf, refuse: PathBuf) -> Self {
            Self { root, refuse: Some(refuse) }
        }
    }

    impl TrashSink for RecordingTrash {
        fn trash(&self, path: &Path) -> Result<TrashOutcome> {
            if self.refuse.as_deref() == Some(path) {
                return Ok(TrashOutcome::Refused {
                    path: path.to_path_buf(),
                    reason: "test refusal".into(),
                    kind: "Test".into(),
                });
            }
            std::fs::create_dir_all(&self.root)?;
            let name = path.file_name().ok_or_else(|| {
                zero_types::error::ZeroError::new(
                    zero_types::error::ErrorCode::InvalidInput,
                    "test path has no file name",
                )
            })?;
            std::fs::rename(path, self.root.join(name))?;
            Ok(TrashOutcome::Trashed { path: path.to_path_buf() })
        }
    }

    fn path_env_for(fixture: &Fixture) -> Vec<String> {
        let entry = fixture.bin.to_str().unwrap().to_string();
        vec![
            "C:\\Windows\\System32".to_string(),
            entry.clone(),
            format!("{entry}-old"),
            "C:\\Other".to_string(),
        ]
    }

    #[test]
    fn confirmation_is_required_unexpired_and_bound_to_one_plan() {
        let fixture = Fixture::new();
        let plan = plan_uninstall(
            UninstallScope::KeepData,
            fixture.bin.clone(),
            fixture.data.clone(),
            fixture.config.clone(),
            Some("zero".to_string()),
        );
        let confirmation = request_confirmation(&plan, 1_000).unwrap();
        let manager = RecordingManager::new(fixture.bin.join(exe_name()));
        let trash = fixture.trash();
        let mut path_env = path_env_for(&fixture);

        let mut blank = confirmation.clone();
        blank.token.clear();
        let error = uninstall(&plan, &blank, 2_000, &trash, &manager, &mut path_env).unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);
        assert_eq!(error.code().as_str(), "zero.pol.ask");

        let other = plan_uninstall(
            UninstallScope::Everything,
            fixture.home().join("other-bin"),
            fixture.home().join("other-data"),
            fixture.home().join("other-config"),
            Some("zero".to_string()),
        );
        let error = uninstall(
            &other,
            &confirmation,
            2_000,
            &trash,
            &manager,
            &mut path_env,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);

        let expired = 1_000 + CONFIRMATION_TTL_MS + 1;
        let error = uninstall(
            &plan,
            &confirmation,
            expired,
            &trash,
            &manager,
            &mut path_env,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);

        assert!(manager.calls().is_empty(), "no manager call before consent");
        assert!(fixture.bin.join(exe_name()).exists());
        assert!(fixture.data.exists());
        assert!(fixture.config.exists());
        assert_eq!(path_env, path_env_for(&fixture));
    }

    #[test]
    fn everything_trashes_data_and_config_and_removes_service_path_and_binaries() {
        let fixture = Fixture::new();
        let plan = plan_uninstall(
            UninstallScope::Everything,
            fixture.bin.clone(),
            fixture.data.clone(),
            fixture.config.clone(),
            Some("zero".to_string()),
        );
        let confirmation = request_confirmation(&plan, 1_000).unwrap();
        let manager = RecordingManager::new(fixture.bin.join(exe_name()));
        let trash = fixture.trash();
        let mut path_env = path_env_for(&fixture);
        let entry = plan.path_entry.clone().unwrap();

        let report =
            uninstall(&plan, &confirmation, 2_000, &trash, &manager, &mut path_env).unwrap();

        assert!(report.service_removed);
        assert!(report.path_entry_removed);
        assert!(report.binaries_removed);
        assert!(report.remaining.is_empty(), "{:?}", report.remaining);
        assert!(!report.orphaned);
        assert!(report.is_complete());
        assert_eq!(
            report.trashed,
            vec![fixture.data.clone(), fixture.config.clone()]
        );
        assert!(!fixture.data.exists());
        assert!(!fixture.config.exists());
        assert!(!fixture.bin.join(exe_name()).exists());
        assert!(!fixture.bin.exists());

        assert_eq!(
            manager.calls(),
            vec!["stop:zero".to_string(), "uninstall:zero".to_string()]
        );
        assert!(
            manager.binary_present_at_uninstall.get(),
            "the binary must still exist while the service is removed"
        );

        assert!(path_env.contains(&"C:\\Windows\\System32".to_string()));
        assert!(path_env.contains(&"C:\\Other".to_string()));
        assert!(path_env.contains(&format!("{entry}-old")));
        assert!(!path_env.contains(&entry));
    }

    #[test]
    fn keep_data_trashes_only_config() {
        let fixture = Fixture::new();
        let plan = plan_uninstall(
            UninstallScope::KeepData,
            fixture.bin.clone(),
            fixture.data.clone(),
            fixture.config.clone(),
            Some("zero".to_string()),
        );
        let confirmation = request_confirmation(&plan, 1_000).unwrap();
        let manager = RecordingManager::new(fixture.bin.join(exe_name()));
        let trash = fixture.trash();
        let mut path_env = path_env_for(&fixture);

        let report =
            uninstall(&plan, &confirmation, 2_000, &trash, &manager, &mut path_env).unwrap();

        assert!(report.is_complete());
        assert_eq!(report.trashed, vec![fixture.config.clone()]);
        assert!(fixture.data.exists(), "KeepData must keep user data");
        assert!(!fixture.config.exists());
        assert!(!fixture.bin.join(exe_name()).exists());
        assert!(!report.orphaned);
    }

    #[test]
    fn binary_only_keeps_all_data_and_config() {
        let fixture = Fixture::new();
        let plan = plan_uninstall(
            UninstallScope::BinaryOnly,
            fixture.bin.clone(),
            fixture.data.clone(),
            fixture.config.clone(),
            Some("zero".to_string()),
        );
        let confirmation = request_confirmation(&plan, 1_000).unwrap();
        let manager = RecordingManager::new(fixture.bin.join(exe_name()));
        let trash = fixture.trash();
        let mut path_env = path_env_for(&fixture);

        let report =
            uninstall(&plan, &confirmation, 2_000, &trash, &manager, &mut path_env).unwrap();

        assert!(report.is_complete());
        assert!(report.trashed.is_empty());
        assert!(fixture.data.exists());
        assert!(fixture.config.exists());
        assert!(!fixture.bin.join(exe_name()).exists());
        assert!(report.service_removed);
        assert!(report.path_entry_removed);
        assert!(report.binaries_removed);
        assert!(!report.orphaned);
    }

    #[test]
    fn a_path_entry_prefix_is_not_removed() {
        let fixture = Fixture::new();
        let plan = plan_uninstall(
            UninstallScope::KeepData,
            fixture.bin.clone(),
            fixture.data.clone(),
            fixture.config.clone(),
            None,
        );
        let confirmation = request_confirmation(&plan, 1_000).unwrap();
        let manager = RecordingManager::new(fixture.bin.join(exe_name()));
        let trash = fixture.trash();
        let entry = plan.path_entry.clone().unwrap();
        let prefix = format!("{entry}-old");
        let suffix = format!("old-{entry}");
        let mut path_env = vec![prefix.clone(), entry.clone(), suffix.clone()];

        let report =
            uninstall(&plan, &confirmation, 2_000, &trash, &manager, &mut path_env).unwrap();

        assert!(report.path_entry_removed);
        assert_eq!(path_env, vec![prefix, suffix]);
    }

    #[test]
    fn a_service_failure_stops_before_binaries_and_reports_remaining() {
        let fixture = Fixture::new();
        let plan = plan_uninstall(
            UninstallScope::Everything,
            fixture.bin.clone(),
            fixture.data.clone(),
            fixture.config.clone(),
            Some("zero".to_string()),
        );
        let confirmation = request_confirmation(&plan, 1_000).unwrap();
        let manager = RecordingManager::failing_uninstall(fixture.bin.join(exe_name()));
        let trash = fixture.trash();
        let mut path_env = path_env_for(&fixture);

        let report =
            uninstall(&plan, &confirmation, 2_000, &trash, &manager, &mut path_env).unwrap();

        assert!(!report.service_removed);
        assert!(!report.binaries_removed);
        assert!(!report.path_entry_removed);
        assert!(report.trashed.is_empty());
        assert!(report.orphaned);
        assert!(!report.is_complete());
        assert!(report.remaining.contains(&fixture.bin.join(exe_name())));
        assert!(report.remaining.contains(&fixture.data));
        assert!(report.remaining.contains(&fixture.config));
        assert!(fixture.bin.join(exe_name()).exists());
        assert!(fixture.data.exists());
        assert!(fixture.config.exists());
        assert_eq!(
            manager.calls(),
            vec!["stop:zero".to_string(), "uninstall:zero".to_string()]
        );
        assert_eq!(path_env, path_env_for(&fixture));
    }

    #[test]
    fn a_trash_failure_reports_remaining_and_keeps_the_binaries() {
        let fixture = Fixture::new();
        let plan = plan_uninstall(
            UninstallScope::Everything,
            fixture.bin.clone(),
            fixture.data.clone(),
            fixture.config.clone(),
            Some("zero".to_string()),
        );
        let confirmation = request_confirmation(&plan, 1_000).unwrap();
        let manager = RecordingManager::new(fixture.bin.join(exe_name()));
        // Refuse the config root after data has been trashed.
        let trash = RecordingTrash::refusing(
            fixture.home().join("test-trash"),
            fixture.config.clone(),
        );
        let mut path_env = path_env_for(&fixture);

        let report =
            uninstall(&plan, &confirmation, 2_000, &trash, &manager, &mut path_env).unwrap();

        assert!(report.service_removed);
        assert!(report.path_entry_removed);
        assert!(!report.binaries_removed);
        assert_eq!(report.trashed, vec![fixture.data.clone()]);
        assert!(!fixture.data.exists());
        assert!(fixture.config.exists());
        assert!(fixture.bin.join(exe_name()).exists());
        assert!(report.remaining.contains(&fixture.config));
        assert!(report.remaining.contains(&fixture.bin.join(exe_name())));
        assert!(report.orphaned);
        assert!(!report.is_complete());
        // The service and PATH entry were removed before the failure; binaries
        // stay so no service can point at a missing executable.
        assert_eq!(
            manager.calls(),
            vec!["stop:zero".to_string(), "uninstall:zero".to_string()]
        );
    }

    #[test]
    fn preview_lists_the_scope_only_and_has_no_secrets() {
        let fixture = Fixture::new();
        let everything = plan_uninstall(
            UninstallScope::Everything,
            fixture.bin.clone(),
            fixture.data.clone(),
            fixture.config.clone(),
            Some("zero".to_string()),
        );
        let keep_data = plan_uninstall(
            UninstallScope::KeepData,
            fixture.bin.clone(),
            fixture.data.clone(),
            fixture.config.clone(),
            Some("zero".to_string()),
        );
        let binary_only = plan_uninstall(
            UninstallScope::BinaryOnly,
            fixture.bin.clone(),
            fixture.data.clone(),
            fixture.config.clone(),
            Some("zero".to_string()),
        );

        let everything_lines = preview(&everything);
        assert!(everything_lines.iter().any(|line| line.contains("zero")));
        assert!(everything_lines
            .iter()
            .any(|line| line.contains(&fixture.data.display().to_string())));
        assert!(everything_lines
            .iter()
            .any(|line| line.contains(&fixture.config.display().to_string())));
        assert!(everything_lines
            .iter()
            .any(|line| line.contains("zero.exe") || line.contains("zero`")));

        let keep_lines = preview(&keep_data);
        assert!(keep_lines
            .iter()
            .any(|line| line.contains(&fixture.config.display().to_string())));
        assert!(!keep_lines
            .iter()
            .any(|line| line.contains(&fixture.data.display().to_string())));

        let binary_lines = preview(&binary_only);
        assert!(!binary_lines
            .iter()
            .any(|line| line.contains(&fixture.data.display().to_string())));
        assert!(!binary_lines
            .iter()
            .any(|line| line.contains(&fixture.config.display().to_string())));
        assert!(binary_lines
            .iter()
            .any(|line| line.contains("remove binary")));

        for line in everything_lines
            .iter()
            .chain(keep_lines.iter())
            .chain(binary_lines.iter())
        {
            let lower = line.to_lowercase();
            assert!(!lower.contains("secret"));
            assert!(!lower.contains("token"));
            assert!(!lower.contains("password"));
        }
    }

    #[test]
    fn invalid_plans_are_refused_before_confirmation() {
        let fixture = Fixture::new();

        let relative = UninstallPlan {
            scope: UninstallScope::Everything,
            binary_dir: PathBuf::from("bin"),
            data_dir: fixture.data.clone(),
            config_dir: fixture.config.clone(),
            service_name: None,
            path_entry: None,
            remove_path_entry: false,
        };
        assert_eq!(
            request_confirmation(&relative, 1_000).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let parent = UninstallPlan {
            scope: UninstallScope::Everything,
            binary_dir: fixture.home().join("bin").join("..").join("bin2"),
            data_dir: fixture.data.clone(),
            config_dir: fixture.config.clone(),
            service_name: None,
            path_entry: None,
            remove_path_entry: false,
        };
        assert_eq!(
            request_confirmation(&parent, 1_000).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let same = UninstallPlan {
            scope: UninstallScope::Everything,
            binary_dir: fixture.bin.clone(),
            data_dir: fixture.bin.clone(),
            config_dir: fixture.config.clone(),
            service_name: None,
            path_entry: None,
            remove_path_entry: false,
        };
        assert_eq!(
            request_confirmation(&same, 1_000).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let nested = UninstallPlan {
            scope: UninstallScope::Everything,
            binary_dir: fixture.home().join("root"),
            data_dir: fixture.home().join("root").join("data"),
            config_dir: fixture.config.clone(),
            service_name: None,
            path_entry: None,
            remove_path_entry: false,
        };
        assert_eq!(
            request_confirmation(&nested, 1_000).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let bad_service = UninstallPlan {
            scope: UninstallScope::BinaryOnly,
            binary_dir: fixture.bin.clone(),
            data_dir: fixture.data.clone(),
            config_dir: fixture.config.clone(),
            service_name: Some("zero service".to_string()),
            path_entry: None,
            remove_path_entry: false,
        };
        assert_eq!(
            request_confirmation(&bad_service, 1_000)
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );

        let missing_entry = UninstallPlan {
            scope: UninstallScope::BinaryOnly,
            binary_dir: fixture.bin.clone(),
            data_dir: fixture.data.clone(),
            config_dir: fixture.config.clone(),
            service_name: None,
            path_entry: None,
            remove_path_entry: true,
        };
        assert_eq!(
            request_confirmation(&missing_entry, 1_000)
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
    }
}
