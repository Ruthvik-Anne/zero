//! T-MM-03 sandboxed computer use.
//!
//! A sandbox is a VM or a virtual display that runs computer actions without
//! the live host desktop. [`SandboxSpec`] is the contract: a backend, an
//! optional display size, an exact `host:port` network allowlist, a scratch
//! root, and a bounded runtime. The spec refuses host mounts and host device
//! access, so the guest has no host filesystem and no host hardware.
//!
//! [`launch`] validates the spec and asks an injected [`SandboxRunner`] to start
//! the backend; the runner is the seam a real VM driver or virtual display
//! implements, and tests script it. [`execute`] runs one [`ComputerAction`]
//! through the `computer_use` policy first: a deny is refused, an ask is
//! surfaced as [`ErrorCode::PolicyAskRequired`] so a destructive action still
//! needs a person, and only an allow reaches the runner.
//!
//! [`check_escape`] is the boundary check. A host path read or write, a network
//! destination outside the allowlist, host device access, a mount request, and
//! a host clipboard read are all blocked, recorded as a [`BlockedAttempt`], and
//! returned as [`ErrorCode::PolicyDenied`]. An escape attempt is data only: it
//! never reaches the runner because the check has no runner to call. An exact
//! allowlisted `host:port` is permitted and counted, so a report distinguishes
//! allowed sandbox traffic from blocked escapes.
//!
//! Wildcards are refused by validation. The allowlist is a fixed set of exact
//! endpoints; there is no API that appends to or widens it at run time.
//!
//! This module never creates a VM, opens a socket, launches a process, or
//! touches a display or clipboard. The backend is the injected runner, and the
//! only filesystem work here is resolving the scratch root and a requested
//! scratch path (MM-03, MM-05, MM-06, MM-10).

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, Result, ZeroError};

use crate::computer_use::{authorize, ComputerAction, Decision, PolicyMode, Target};

/// Largest accepted scratch-root display edge, in pixels.
pub const MAX_SANDBOX_DISPLAY_EDGE: u32 = 8192;
/// Largest accepted sandbox runtime: 30 minutes.
pub const MAX_SANDBOX_RUNTIME_MS: u64 = 30 * 60 * 1000;
/// Smallest accepted sandbox runtime: one second.
pub const MIN_SANDBOX_RUNTIME_MS: u64 = 1_000;
/// Largest number of network allowlist entries.
pub const MAX_NETWORK_ALLOWLIST_ENTRIES: usize = 64;
/// Largest number of characters in one network allowlist entry.
pub const MAX_NETWORK_ENDPOINT_CHARS: usize = 255;

/// The isolation backend that runs the computer actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxBackend {
    /// A virtual display with no host desktop behind it.
    VirtualDisplay,
    /// A virtual machine.
    Vm,
}

impl SandboxBackend {
    /// Every backend in deterministic order.
    pub const ALL: [SandboxBackend; 2] = [SandboxBackend::VirtualDisplay, SandboxBackend::Vm];

    /// Stable lowercase name used in JSON and error messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            SandboxBackend::VirtualDisplay => "virtual-display",
            SandboxBackend::Vm => "vm",
        }
    }

    /// Whether this backend needs an explicit display size.
    pub const fn requires_display(self) -> bool {
        matches!(self, SandboxBackend::VirtualDisplay)
    }
}

impl fmt::Display for SandboxBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The validated contract for one sandbox.
///
/// `host_mounts` and `device_access` exist so a caller can express a request
/// that is then rejected: a computer-use sandbox has neither. `scratch_root` is
/// the only filesystem the guest sees, and it must be an existing directory
/// that is not a filesystem root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxSpec {
    pub backend: SandboxBackend,
    pub display: Option<(u32, u32)>,
    pub network_allowlist: Vec<String>,
    pub scratch_root: PathBuf,
    pub host_mounts: Vec<PathBuf>,
    pub device_access: bool,
    pub max_runtime_ms: u64,
}

impl SandboxSpec {
    /// Validate the whole spec.
    ///
    /// A host mount or host device access is [`ErrorCode::PolicyDenied`]; a
    /// malformed value is [`ErrorCode::InvalidInput`]; an oversized value is
    /// [`ErrorCode::LimitExceeded`]; a missing scratch directory is
    /// [`ErrorCode::NotFound`]. This checks that the scratch root exists, is a
    /// directory, is absolute, and is not a filesystem root. Use
    /// [`SandboxSpec::validate_scratch_under`] when a caller also owns the
    /// root that the scratch directory must live inside.
    pub fn validate(&self) -> Result<()> {
        if !self.host_mounts.is_empty() {
            return Err(policy_denied(format!(
                "a computer-use sandbox cannot mount a host path: {}",
                clean(&self.host_mounts[0].to_string_lossy())
            )));
        }
        if self.device_access {
            return Err(policy_denied(
                "a computer-use sandbox cannot access host devices",
            ));
        }
        if self.max_runtime_ms < MIN_SANDBOX_RUNTIME_MS {
            return Err(invalid(format!(
                "sandbox runtime {} ms is shorter than the {MIN_SANDBOX_RUNTIME_MS} ms minimum",
                self.max_runtime_ms
            )));
        }
        if self.max_runtime_ms > MAX_SANDBOX_RUNTIME_MS {
            return Err(limit(format!(
                "sandbox runtime {} ms exceeds the documented maximum of {MAX_SANDBOX_RUNTIME_MS} ms",
                self.max_runtime_ms
            )));
        }

        match self.display {
            Some((width, height)) => {
                if width == 0 || height == 0 {
                    return Err(invalid("a sandbox display cannot have a zero edge"));
                }
                if width > MAX_SANDBOX_DISPLAY_EDGE || height > MAX_SANDBOX_DISPLAY_EDGE {
                    return Err(limit(format!(
                        "a sandbox display edge cannot exceed {MAX_SANDBOX_DISPLAY_EDGE} pixels"
                    )));
                }
            }
            None => {
                if self.backend.requires_display() {
                    return Err(invalid(
                        "a virtual display backend needs an explicit display size",
                    ));
                }
            }
        }

        self.validate_scratch_root()?;
        self.validate_network_allowlist()?;
        Ok(())
    }

    /// Require the scratch root to live inside `root`.
    ///
    /// Both paths are canonicalised first, so a symbolic link cannot point the
    /// scratch root outside the root that the caller owns.
    pub fn validate_scratch_under(&self, root: &Path) -> Result<()> {
        self.validate()?;
        let canonical_root = canonical_dir(root, "sandbox root")?;
        let canonical_scratch = canonical_dir(&self.scratch_root, "sandbox scratch root")?;
        if !canonical_scratch.starts_with(&canonical_root) {
            return Err(policy_denied(format!(
                "sandbox scratch root `{}` is not inside the sandbox root `{}`",
                clean(&canonical_scratch.to_string_lossy()),
                clean(&canonical_root.to_string_lossy())
            )));
        }
        Ok(())
    }

    /// Whether an exact host and port pair is on the allowlist.
    ///
    /// Host comparison is ASCII case-insensitive because DNS names are; the
    /// port is an exact integer. There is no prefix, suffix, or wildcard match.
    pub fn network_allowed(&self, host: &str, port: u16) -> bool {
        self.network_allowlist.iter().any(|entry| {
            parse_endpoint(entry)
                .map(|(allowed_host, allowed_port)| {
                    allowed_port == port && allowed_host.eq_ignore_ascii_case(host)
                })
                .unwrap_or(false)
        })
    }

    fn validate_scratch_root(&self) -> Result<()> {
        let path = &self.scratch_root;
        if path.as_os_str().is_empty() {
            return Err(invalid("a sandbox scratch root cannot be empty"));
        }
        if !path.is_absolute() {
            return Err(invalid(format!(
                "sandbox scratch root `{}` must be an absolute path",
                clean(&path.to_string_lossy())
            )));
        }
        if !path.exists() {
            return Err(not_found(format!(
                "sandbox scratch root `{}` does not exist",
                clean(&path.to_string_lossy())
            )));
        }
        if !path.is_dir() {
            return Err(invalid(format!(
                "sandbox scratch root `{}` is not a directory",
                clean(&path.to_string_lossy())
            )));
        }
        if path.parent().is_none() {
            return Err(policy_denied(format!(
                "sandbox scratch root `{}` is a filesystem root; use a directory inside it",
                clean(&path.to_string_lossy())
            )));
        }
        Ok(())
    }

    fn validate_network_allowlist(&self) -> Result<()> {
        if self.network_allowlist.len() > MAX_NETWORK_ALLOWLIST_ENTRIES {
            return Err(limit(format!(
                "a sandbox allowlist cannot exceed {MAX_NETWORK_ALLOWLIST_ENTRIES} entries"
            )));
        }
        for entry in &self.network_allowlist {
            parse_endpoint(entry)?;
        }
        Ok(())
    }
}

/// The lifecycle state of one sandbox session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxState {
    Starting,
    Running,
    Stopped,
    Failed,
}

impl SandboxState {
    /// Every state in deterministic order.
    pub const ALL: [SandboxState; 4] = [
        SandboxState::Starting,
        SandboxState::Running,
        SandboxState::Stopped,
        SandboxState::Failed,
    ];

    /// Stable lowercase name used in JSON and error messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            SandboxState::Starting => "starting",
            SandboxState::Running => "running",
            SandboxState::Stopped => "stopped",
            SandboxState::Failed => "failed",
        }
    }
}

impl fmt::Display for SandboxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What happened when the runner performed one allowed action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ActionOutcome {
    /// The backend performed the action.
    Completed,
    /// The backend refused or failed; the message is the typed error text.
    Failed { message: String },
}

impl ActionOutcome {
    /// Whether the backend completed the action.
    pub fn is_completed(&self) -> bool {
        matches!(self, ActionOutcome::Completed)
    }
}

/// One action that passed policy and was handed to the runner.
///
/// `decision` is always [`Decision::Allow`] because a deny or an ask never
/// produces a record. A failed record still keeps the action, so the session
/// log distinguishes an attempted action from an executed one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRecord {
    pub action: ComputerAction,
    pub decision: Decision,
    pub outcome: ActionOutcome,
}

/// The kind of escape channel that was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeKind {
    HostPath,
    Network,
    DeviceAccess,
    MountRequest,
    ClipboardFromHost,
}

impl EscapeKind {
    /// Every escape kind in deterministic order.
    pub const ALL: [EscapeKind; 5] = [
        EscapeKind::HostPath,
        EscapeKind::Network,
        EscapeKind::DeviceAccess,
        EscapeKind::MountRequest,
        EscapeKind::ClipboardFromHost,
    ];

    /// Stable lowercase name used in JSON and reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            EscapeKind::HostPath => "host-path",
            EscapeKind::Network => "network",
            EscapeKind::DeviceAccess => "device-access",
            EscapeKind::MountRequest => "mount-request",
            EscapeKind::ClipboardFromHost => "clipboard-from-host",
        }
    }
}

impl fmt::Display for EscapeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One escape attempt to check against the sandbox boundary.
///
/// A [`EscapeAttempt::HostPath`] is any host path read or write, including one
/// that names the scratch root: the scratch root is addressed through
/// [`check_scratch_write`], not through the host path channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeAttempt {
    HostPath(PathBuf),
    Network { host: String, port: u16 },
    DeviceAccess,
    MountRequest,
    ClipboardFromHost,
}

impl EscapeAttempt {
    /// The channel this attempt uses.
    pub const fn kind(&self) -> EscapeKind {
        match self {
            EscapeAttempt::HostPath(_) => EscapeKind::HostPath,
            EscapeAttempt::Network { .. } => EscapeKind::Network,
            EscapeAttempt::DeviceAccess => EscapeKind::DeviceAccess,
            EscapeAttempt::MountRequest => EscapeKind::MountRequest,
            EscapeAttempt::ClipboardFromHost => EscapeKind::ClipboardFromHost,
        }
    }

    /// A sanitised description with no control characters.
    fn detail(&self) -> String {
        match self {
            EscapeAttempt::HostPath(path) => {
                format!("host path `{}`", clean(&path.to_string_lossy()))
            }
            EscapeAttempt::Network { host, port } => {
                format!("network destination `{}:{port}`", clean(host))
            }
            EscapeAttempt::DeviceAccess => "host device access".to_string(),
            EscapeAttempt::MountRequest => "host mount request".to_string(),
            EscapeAttempt::ClipboardFromHost => "host clipboard read".to_string(),
        }
    }
}

/// One blocked escape attempt kept in the session log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedAttempt {
    pub kind: EscapeKind,
    pub detail: String,
    pub reason: String,
}

impl BlockedAttempt {
    /// Render the record as one fixed line.
    pub fn render(&self) -> String {
        format!(
            "{} blocked: {} ({})",
            self.kind.as_str(),
            self.reason,
            self.detail
        )
    }
}

/// The sandbox boundary report.
///
/// `blocked` is every recorded escape attempt in order. `allowed` counts the
/// checked requests that the boundary permitted: an exact allowlisted network
/// endpoint and a scratch write inside the scratch root.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscapeReport {
    pub blocked: Vec<BlockedAttempt>,
    pub allowed: usize,
}

impl EscapeReport {
    /// Whether the boundary blocked nothing.
    pub fn is_clean(&self) -> bool {
        self.blocked.is_empty()
    }

    /// The number of blocked attempts.
    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }

    /// The blocked kinds in order, one line each.
    pub fn render(&self) -> String {
        if self.blocked.is_empty() {
            return format!("{} attempt(s) allowed; no escape attempt was blocked", self.allowed);
        }
        let mut lines = self
            .blocked
            .iter()
            .map(BlockedAttempt::render)
            .collect::<Vec<_>>();
        lines.push(format!("{} attempt(s) allowed", self.allowed));
        lines.join("\n")
    }
}

/// The injectable backend seam.
///
/// A real driver starts a VM or a virtual display; the test double records the
/// calls and can fail on demand. Every method returns a [`zero_types::ZeroError`]
/// so a backend failure keeps its stable code.
pub trait SandboxRunner {
    /// Start the backend for this spec.
    fn launch(&self, spec: &SandboxSpec) -> Result<()>;
    /// Perform one action that already passed policy.
    fn perform(&self, action: &ComputerAction) -> Result<()>;
    /// Stop the backend.
    fn stop(&self) -> Result<()>;
}

/// One live sandbox session.
///
/// [`SandboxSession::actions`] holds allowed actions that reached the runner;
/// [`SandboxSession::attempts`] holds blocked escapes. The two logs never mix,
/// so a caller cannot mistake a blocked escape for an executed action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxSession {
    pub id: String,
    pub spec: SandboxSpec,
    pub state: SandboxState,
    pub actions: Vec<ActionRecord>,
    pub attempts: Vec<BlockedAttempt>,
    pub allowed_attempts: usize,
    pub scratch_writes: Vec<PathBuf>,
}

impl SandboxSession {
    /// Whether the session is running and can accept an action.
    pub fn is_running(&self) -> bool {
        self.state == SandboxState::Running
    }

    /// Build the boundary report for this session.
    pub fn escape_report(&self) -> EscapeReport {
        EscapeReport {
            blocked: self.attempts.clone(),
            allowed: self.allowed_attempts,
        }
    }
}

/// Validate a spec and ask the runner to start it.
///
/// The returned session is [`SandboxState::Running`] only after the runner
/// returns `Ok`. A validation failure never calls the runner. A runner failure
/// keeps the backend's error code and is prefixed with the sandbox context.
pub fn launch(spec: SandboxSpec, runner: &dyn SandboxRunner) -> Result<SandboxSession> {
    spec.validate()?;
    let mut session = SandboxSession {
        id: session_id(&spec),
        spec,
        state: SandboxState::Starting,
        actions: Vec::new(),
        attempts: Vec::new(),
        allowed_attempts: 0,
        scratch_writes: Vec::new(),
    };
    if let Err(error) = runner.launch(&session.spec) {
        session.state = SandboxState::Failed;
        return Err(ZeroError::new(
            error.code(),
            format!("sandbox backend failed to launch: {}", error.message()),
        ));
    }
    session.state = SandboxState::Running;
    Ok(session)
}

/// Run one action through the computer use policy, then the runner.
///
/// The action must target [`Target::Sandbox`]; a live host action is refused
/// with [`ErrorCode::PolicyDenied`]. The policy matrix decides:
///
/// - `Deny` returns [`ErrorCode::PolicyDenied`];
/// - `Ask` returns [`ErrorCode::PolicyAskRequired`], because a person must
///   answer and this layer must not bypass that prompt;
/// - `Allow` calls the runner and records the action.
///
/// A runner failure is recorded as [`ActionOutcome::Failed`] and returned with
/// the backend's code. A stopped session refuses every action.
pub fn execute(
    session: &mut SandboxSession,
    action: &ComputerAction,
    mode: PolicyMode,
    allowlist: &[String],
    runner: &dyn SandboxRunner,
) -> Result<ActionRecord> {
    require_running(session)?;
    if action.target != Target::Sandbox {
        return Err(policy_denied(format!(
            "a {} action cannot run in the sandbox session",
            action.target.as_str()
        )));
    }

    let decision = authorize(action, mode, allowlist);
    match &decision {
        Decision::Allow => {}
        Decision::Ask { reason } => {
            return Err(ZeroError::new(
                ErrorCode::PolicyAskRequired,
                format!("the sandbox action needs an answer before it can run: {reason}"),
            ));
        }
        Decision::Deny { reason } => {
            return Err(policy_denied(format!(
                "the sandbox action was denied: {reason}"
            )));
        }
    }

    let record = match runner.perform(action) {
        Ok(()) => ActionRecord {
            action: action.clone(),
            decision,
            outcome: ActionOutcome::Completed,
        },
        Err(error) => {
            session.actions.push(ActionRecord {
                action: action.clone(),
                decision,
                outcome: ActionOutcome::Failed {
                    message: error.message().to_string(),
                },
            });
            return Err(error);
        }
    };
    session.actions.push(record.clone());
    Ok(record)
}

/// Check one escape attempt against the sandbox boundary.
///
/// An exact allowlisted network endpoint is permitted and counted. Every other
/// attempt is recorded in [`SandboxSession::attempts`] and returned as
/// [`ErrorCode::PolicyDenied`]. The check has no runner parameter, so a blocked
/// attempt cannot reach the backend.
pub fn check_escape(session: &mut SandboxSession, attempt: EscapeAttempt) -> Result<()> {
    require_running(session)?;
    if let EscapeAttempt::Network { host, port } = &attempt {
        if session.spec.network_allowed(host, *port) {
            session.allowed_attempts += 1;
            return Ok(());
        }
    }

    let reason = escape_reason(attempt.kind());
    let detail = attempt.detail();
    session.attempts.push(BlockedAttempt {
        kind: attempt.kind(),
        detail: detail.clone(),
        reason: reason.to_string(),
    });
    Err(policy_denied(format!(
        "sandbox escape blocked: {reason} ({detail})"
    )))
}

/// Record a scratch write and require it to stay inside the scratch root.
///
/// A path inside the scratch root is allowed and counted even when the file
/// does not exist yet; its parent must exist. A path outside the root, or a
/// symbolic link that resolves outside it, is recorded as a blocked host path
/// and returned as [`ErrorCode::PolicyDenied`]. A missing parent outside that
/// rule is [`ErrorCode::InvalidInput`] and is not an escape attempt.
pub fn check_scratch_write(session: &mut SandboxSession, path: &Path) -> Result<()> {
    require_running(session)?;
    match resolve_scratch_path(&session.spec.scratch_root, path) {
        Ok(resolved) => {
            session.allowed_attempts += 1;
            session.scratch_writes.push(resolved);
            Ok(())
        }
        Err(ScratchPathError::Outside(detail)) => {
            session.attempts.push(BlockedAttempt {
                kind: EscapeKind::HostPath,
                detail: detail.clone(),
                reason: escape_reason(EscapeKind::HostPath).to_string(),
            });
            Err(policy_denied(format!(
                "sandbox escape blocked: scratch write `{}` leaves the scratch root",
                detail
            )))
        }
        Err(ScratchPathError::Invalid(message)) => Err(invalid(message)),
    }
}

/// Stop the backend.
///
/// A second stop is [`ErrorCode::InvalidInput`]. A backend failure moves the
/// session to [`SandboxState::Failed`] and keeps the backend's code.
pub fn stop(session: &mut SandboxSession, runner: &dyn SandboxRunner) -> Result<()> {
    if session.state == SandboxState::Stopped {
        return Err(invalid("the sandbox session is already stopped"));
    }
    if session.state == SandboxState::Starting {
        return Err(invalid("the sandbox session never started"));
    }
    if let Err(error) = runner.stop() {
        session.state = SandboxState::Failed;
        return Err(ZeroError::new(
            error.code(),
            format!("sandbox backend failed to stop: {}", error.message()),
        ));
    }
    session.state = SandboxState::Stopped;
    Ok(())
}

fn require_running(session: &SandboxSession) -> Result<()> {
    if session.is_running() {
        Ok(())
    } else {
        Err(invalid(format!(
            "the sandbox session is {}; an action needs a running session",
            session.state
        )))
    }
}

fn escape_reason(kind: EscapeKind) -> &'static str {
    match kind {
        EscapeKind::HostPath => {
            "the sandbox has no host filesystem; a host path read or write is denied"
        }
        EscapeKind::Network => {
            "the destination is not an exact allowlisted host:port in the sandbox network allowlist"
        }
        EscapeKind::DeviceAccess => "the sandbox cannot access host devices",
        EscapeKind::MountRequest => "the sandbox cannot mount a host path",
        EscapeKind::ClipboardFromHost => "the sandbox cannot read the host clipboard",
    }
}

enum ScratchPathError {
    /// The path resolves outside the scratch root.
    Outside(String),
    /// The request is malformed but is not an escape.
    Invalid(String),
}

/// Resolve a requested scratch path and prove it stays inside the root.
///
/// Both sides are canonicalised, so `..` and symbolic links cannot escape. A
/// path that does not exist yet is allowed when its parent exists and resolves
/// inside the root.
fn resolve_scratch_path(scratch_root: &Path, candidate: &Path) -> std::result::Result<PathBuf, ScratchPathError> {
    if candidate.as_os_str().is_empty() {
        return Err(ScratchPathError::Invalid(
            "a scratch path cannot be empty".to_string(),
        ));
    }
    if !candidate.is_absolute() {
        return Err(ScratchPathError::Invalid(format!(
            "a scratch path must be absolute: `{}`",
            clean(&candidate.to_string_lossy())
        )));
    }
    let root = scratch_root
        .canonicalize()
        .map_err(|error| ScratchPathError::Invalid(format!("the scratch root is unusable: {error}")))?;

    if candidate.exists() {
        let resolved = candidate.canonicalize().map_err(|error| {
            ScratchPathError::Invalid(format!(
                "the scratch path `{}` cannot be resolved: {error}",
                clean(&candidate.to_string_lossy())
            ))
        })?;
        if resolved.starts_with(&root) {
            return Ok(resolved);
        }
        return Err(ScratchPathError::Outside(clean(
            &resolved.to_string_lossy(),
        )));
    }

    let parent = candidate.parent().ok_or_else(|| {
        ScratchPathError::Invalid(format!(
            "the scratch path `{}` has no parent directory",
            clean(&candidate.to_string_lossy())
        ))
    })?;
    let file_name = candidate.file_name().ok_or_else(|| {
        ScratchPathError::Invalid(format!(
            "the scratch path `{}` has no file name",
            clean(&candidate.to_string_lossy())
        ))
    })?;
    if file_name == std::ffi::OsStr::new("..") {
        return Err(ScratchPathError::Outside(clean(
            &candidate.to_string_lossy(),
        )));
    }
    let parent = parent.canonicalize().map_err(|error| {
        ScratchPathError::Invalid(format!(
            "the scratch path parent `{}` does not exist or cannot be resolved: {error}",
            clean(&parent.to_string_lossy())
        ))
    })?;
    if parent.starts_with(&root) {
        return Ok(parent.join(file_name));
    }
    Err(ScratchPathError::Outside(clean(
        &parent.join(file_name).to_string_lossy(),
    )))
}

/// Parse a `host:port` allowlist entry.
///
/// Forms: `host:port`, or `[address]:port` for an IPv6 address. Wildcards,
/// whitespace, control characters, a scheme, userinfo, and port zero are
/// rejected. The host is returned lowercased for comparison.
fn parse_endpoint(entry: &str) -> Result<(String, u16)> {
    if entry.is_empty() {
        return Err(invalid("a sandbox network entry cannot be empty"));
    }
    if entry.chars().count() > MAX_NETWORK_ENDPOINT_CHARS {
        return Err(limit(format!(
            "a sandbox network entry is longer than {MAX_NETWORK_ENDPOINT_CHARS} characters"
        )));
    }
    if entry.chars().any(|character| character.is_control() || character.is_whitespace()) {
        return Err(invalid(
            "a sandbox network entry cannot contain whitespace or a control character",
        ));
    }
    if entry.contains('*') || entry.contains('?') {
        return Err(policy_denied(format!(
            "sandbox network allowlist entry `{entry}` uses a wildcard; only an exact host:port is allowed"
        )));
    }
    if entry.contains("://") {
        return Err(invalid(format!(
            "sandbox network allowlist entry `{entry}` must be host:port, not a URL"
        )));
    }

    let (host, port_text) = if let Some(rest) = entry.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| invalid(format!("sandbox network allowlist entry `{entry}` has no closing `]`")))?;
        let port_text = tail
            .strip_prefix(':')
            .ok_or_else(|| invalid(format!("sandbox network allowlist entry `{entry}` has no port")))?;
        (host, port_text)
    } else {
        let (host, port_text) = entry
            .rsplit_once(':')
            .ok_or_else(|| invalid(format!("sandbox network allowlist entry `{entry}` has no port")))?;
        if host.contains(':') {
            return Err(invalid(format!(
                "sandbox network allowlist entry `{entry}` must bracket an IPv6 host"
            )));
        }
        (host, port_text)
    };

    if host.is_empty() {
        return Err(invalid(format!(
            "sandbox network allowlist entry `{entry}` has no host"
        )));
    }
    if host.contains(['[', ']', '/', '\\', '@', '#']) {
        return Err(invalid(format!(
            "sandbox network allowlist entry `{entry}` has an invalid host"
        )));
    }
    let port = port_text.parse::<u16>().map_err(|_| {
        invalid(format!(
            "sandbox network allowlist entry `{entry}` has an invalid port"
        ))
    })?;
    if port == 0 {
        return Err(invalid(format!(
            "sandbox network allowlist entry `{entry}` uses port zero"
        )));
    }
    Ok((host.to_ascii_lowercase(), port))
}

/// A deterministic session id derived from the spec.
///
/// The id is a content hash, not a secret and not a random value: the same spec
/// always produces the same id, which keeps logs and tests reproducible.
fn session_id(spec: &SandboxSpec) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    };
    feed(spec.backend.as_str().as_bytes());
    match spec.display {
        Some((width, height)) => {
            feed(&width.to_le_bytes());
            feed(&height.to_le_bytes());
        }
        None => feed(b"none"),
    }
    for entry in &spec.network_allowlist {
        feed(entry.as_bytes());
    }
    feed(spec.scratch_root.to_string_lossy().as_bytes());
    for mount in &spec.host_mounts {
        feed(mount.to_string_lossy().as_bytes());
    }
    feed(&[u8::from(spec.device_access)]);
    feed(&spec.max_runtime_ms.to_le_bytes());
    format!("sandbox-{hash:016x}")
}

fn canonical_dir(path: &Path, label: &str) -> Result<PathBuf> {
    path.canonicalize().map_err(|error| {
        not_found(format!(
            "{label} `{}` cannot be resolved: {error}",
            clean(&path.to_string_lossy())
        ))
    })
}

/// Replace control characters so a path or host cannot break a log line.
fn clean(text: &str) -> String {
    text.chars()
        .map(|character| if character.is_control() { '?' } else { character })
        .collect()
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn not_found(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::NotFound, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn policy_denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;
    use crate::computer_use::ActionKind;
    use tempfile::TempDir;

    /// A scripted backend. It records every call and can fail on demand.
    #[derive(Default)]
    struct ScriptedRunner {
        launched: RefCell<Vec<SandboxSpec>>,
        performed: RefCell<Vec<ComputerAction>>,
        stops: Cell<usize>,
        fail_launch: Option<(ErrorCode, &'static str)>,
        fail_perform: Option<(ErrorCode, &'static str)>,
        fail_stop: Option<(ErrorCode, &'static str)>,
    }

    impl SandboxRunner for ScriptedRunner {
        fn launch(&self, spec: &SandboxSpec) -> Result<()> {
            self.launched.borrow_mut().push(spec.clone());
            match self.fail_launch {
                Some((code, message)) => Err(ZeroError::new(code, message)),
                None => Ok(()),
            }
        }

        fn perform(&self, action: &ComputerAction) -> Result<()> {
            self.performed.borrow_mut().push(action.clone());
            match self.fail_perform {
                Some((code, message)) => Err(ZeroError::new(code, message)),
                None => Ok(()),
            }
        }

        fn stop(&self) -> Result<()> {
            self.stops.set(self.stops.get() + 1);
            match self.fail_stop {
                Some((code, message)) => Err(ZeroError::new(code, message)),
                None => Ok(()),
            }
        }
    }

    fn scratch() -> (TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("guest");
        std::fs::create_dir_all(&root).expect("scratch root");
        (temp, root)
    }

    fn spec_for(root: &Path) -> SandboxSpec {
        SandboxSpec {
            backend: SandboxBackend::Vm,
            display: Some((1280, 720)),
            network_allowlist: vec!["api.example.com:443".to_string()],
            scratch_root: root.to_path_buf(),
            host_mounts: Vec::new(),
            device_access: false,
            max_runtime_ms: 60_000,
        }
    }

    fn running(root: &Path) -> (SandboxSession, ScriptedRunner) {
        let runner = ScriptedRunner::default();
        let session = launch(spec_for(root), &runner).expect("launch");
        assert_eq!(session.state, SandboxState::Running);
        (session, runner)
    }

    fn sandbox_action(kind: ActionKind) -> ComputerAction {
        ComputerAction {
            kind,
            target: Target::Sandbox,
            app: Some("com.example.app".to_string()),
            text_len: None,
            destructive: false,
        }
    }

    #[test]
    fn host_filesystem_access_is_blocked() {
        // T-MM-03 Done: a host filesystem escape attempt is blocked, recorded,
        // and never reaches the runner.
        let (_temp, root) = scratch();
        let (mut session, runner) = running(&root);

        let error = check_escape(
            &mut session,
            EscapeAttempt::HostPath(PathBuf::from("C:\\Windows\\System32\\config\\SAM")),
        )
        .expect_err("a host path is blocked");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(error.code().as_str(), "zero.pol.denied");
        assert_eq!(session.attempts.len(), 1);
        assert_eq!(session.attempts[0].kind, EscapeKind::HostPath);
        assert!(session.attempts[0].detail.contains("SAM"));
        assert!(session.actions.is_empty());
        assert!(runner.performed.borrow().is_empty());
        assert_eq!(session.state, SandboxState::Running);

        let report = session.escape_report();
        assert!(!report.is_clean());
        assert_eq!(report.blocked_count(), 1);
        assert_eq!(report.allowed, 0);
    }

    #[test]
    fn network_allowlist_allows_only_the_exact_host_and_port() {
        let (_temp, root) = scratch();
        let (mut session, runner) = running(&root);

        check_escape(
            &mut session,
            EscapeAttempt::Network {
                host: "api.example.com".to_string(),
                port: 443,
            },
        )
        .expect("an exact allowlisted endpoint is permitted");
        assert_eq!(session.allowed_attempts, 1);
        assert!(session.attempts.is_empty());

        // A different port, a different host, and a suffix host are all blocked.
        for (host, port) in [
            ("api.example.com", 80),
            ("api.example.org", 443),
            ("example.com", 443),
            ("api.example.com.evil.test", 443),
        ] {
            let error = check_escape(
                &mut session,
                EscapeAttempt::Network {
                    host: host.to_string(),
                    port,
                },
            )
            .expect_err("a non-allowlisted endpoint is blocked");
            assert_eq!(error.code(), ErrorCode::PolicyDenied);
        }
        assert_eq!(session.attempts.len(), 4);
        assert!(session
            .attempts
            .iter()
            .all(|attempt| attempt.kind == EscapeKind::Network));
        assert!(runner.performed.borrow().is_empty());

        let report = session.escape_report();
        assert_eq!(report.allowed, 1);
        assert_eq!(report.blocked_count(), 4);
    }

    #[test]
    fn device_access_is_blocked() {
        let (_temp, root) = scratch();
        let (mut session, _runner) = running(&root);
        let error = check_escape(&mut session, EscapeAttempt::DeviceAccess)
            .expect_err("host device access is blocked");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(session.attempts[0].kind, EscapeKind::DeviceAccess);
    }

    #[test]
    fn mount_request_is_blocked() {
        let (_temp, root) = scratch();
        let (mut session, _runner) = running(&root);
        let error = check_escape(&mut session, EscapeAttempt::MountRequest)
            .expect_err("a mount request is blocked");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(session.attempts[0].kind, EscapeKind::MountRequest);
    }

    #[test]
    fn clipboard_from_host_is_blocked() {
        let (_temp, root) = scratch();
        let (mut session, _runner) = running(&root);
        let error = check_escape(&mut session, EscapeAttempt::ClipboardFromHost)
            .expect_err("a host clipboard read is blocked");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(session.attempts[0].kind, EscapeKind::ClipboardFromHost);
    }

    #[test]
    fn escape_attempts_are_not_forwarded_to_the_runner() {
        let (_temp, root) = scratch();
        let (mut session, runner) = running(&root);

        let attempts = vec![
            EscapeAttempt::HostPath(PathBuf::from("/etc/shadow")),
            EscapeAttempt::Network {
                host: "exfil.example".to_string(),
                port: 4444,
            },
            EscapeAttempt::DeviceAccess,
            EscapeAttempt::MountRequest,
            EscapeAttempt::ClipboardFromHost,
        ];
        for attempt in attempts {
            assert!(check_escape(&mut session, attempt).is_err());
        }

        assert!(runner.performed.borrow().is_empty());
        assert!(session.actions.is_empty());
        assert_eq!(session.attempts.len(), EscapeKind::ALL.len());
        let kinds = session
            .attempts
            .iter()
            .map(|attempt| attempt.kind)
            .collect::<Vec<_>>();
        assert_eq!(kinds, EscapeKind::ALL.to_vec());

        // Every blocked record renders as one line and rounds through serde.
        let report = session.escape_report();
        assert_eq!(report.render().lines().count(), EscapeKind::ALL.len() + 1);
        let json = serde_json::to_string(&report).expect("serialize report");
        let restored: EscapeReport = serde_json::from_str(&json).expect("deserialize report");
        assert_eq!(restored, report);
    }

    #[test]
    fn scratch_writes_are_allowed_and_escapes_are_blocked() {
        let (_temp, root) = scratch();
        std::fs::create_dir_all(root.join("out")).expect("scratch subdir");
        let (mut session, runner) = running(&root);

        check_scratch_write(&mut session, &root.join("out").join("shot.png"))
            .expect("a write inside the scratch root is allowed");
        assert_eq!(session.scratch_writes.len(), 1);
        assert_eq!(session.allowed_attempts, 1);
        assert!(session.attempts.is_empty());
        assert!(runner.performed.borrow().is_empty());

        let outside = tempfile::tempdir().expect("outside tempdir");
        let error = check_scratch_write(&mut session, &outside.path().join("stolen.txt"))
            .expect_err("a write outside the scratch root is blocked");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(session.attempts.len(), 1);
        assert_eq!(session.attempts[0].kind, EscapeKind::HostPath);
        assert_eq!(session.allowed_attempts, 1);

        // A dot-dot path that resolves out of the root is blocked too.
        let dot_dot = root.join("..").join("escape.txt");
        let error = check_scratch_write(&mut session, &dot_dot)
            .expect_err("a dot-dot escape is blocked");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(session.attempts.len(), 2);
    }

    #[test]
    fn sandbox_session_lifecycle() {
        let (_temp, root) = scratch();
        let runner = ScriptedRunner::default();

        let mut session = launch(spec_for(&root), &runner).expect("launch");
        assert_eq!(session.state, SandboxState::Running);
        assert_eq!(runner.launched.borrow().len(), 1);
        assert!(session.is_running());
        assert_eq!(session.id, launch(spec_for(&root), &runner).expect("relaunch").id);
        assert_eq!(session.id, session_id(&spec_for(&root)));
        assert!(session.id.starts_with("sandbox-"));

        stop(&mut session, &runner).expect("stop");
        assert_eq!(session.state, SandboxState::Stopped);
        assert_eq!(runner.stops.get(), 1);
        assert!(stop(&mut session, &runner).is_err());

        let action = sandbox_action(ActionKind::Screenshot);
        let error = execute(&mut session, &action, PolicyMode::Auto, &[], &runner)
            .expect_err("a stopped session refuses an action");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(runner.performed.borrow().is_empty());
    }

    #[test]
    fn host_mounts_make_the_spec_invalid() {
        let (_temp, root) = scratch();
        let mut spec = spec_for(&root);
        spec.host_mounts = vec![PathBuf::from("C:\\Users")];
        let error = spec.validate().expect_err("a host mount is refused");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("cannot mount a host path"));

        let runner = ScriptedRunner::default();
        assert!(launch(spec, &runner).is_err());
        assert!(
            runner.launched.borrow().is_empty(),
            "an invalid spec must not start the backend"
        );
    }

    #[test]
    fn device_access_makes_the_spec_invalid() {
        let (_temp, root) = scratch();
        let mut spec = spec_for(&root);
        spec.device_access = true;
        let error = spec.validate().expect_err("host device access is refused");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("host devices"));
    }

    #[test]
    fn wildcard_network_entries_are_rejected() {
        let (_temp, root) = scratch();
        for entry in ["*:443", "*.example.com:443", "api.*:443", "api.example.com:*"] {
            let mut spec = spec_for(&root);
            spec.network_allowlist = vec![entry.to_string()];
            let error = spec
                .validate()
                .expect_err("a wildcard allowlist entry is refused");
            assert_eq!(error.code(), ErrorCode::PolicyDenied, "entry `{entry}`");
            assert!(error.message().contains("wildcard"), "entry `{entry}`");

            let runner = ScriptedRunner::default();
            assert!(launch(spec, &runner).is_err());
            assert!(runner.launched.borrow().is_empty());
        }

        let mut spec = spec_for(&root);
        spec.network_allowlist = vec!["api.example.com".to_string()];
        assert_eq!(
            spec.validate().expect_err("a missing port").code(),
            ErrorCode::InvalidInput
        );
        spec.network_allowlist = vec!["api.example.com:0".to_string()];
        assert!(spec.validate().is_err());
        spec.network_allowlist = vec!["https://api.example.com:443".to_string()];
        assert!(spec.validate().is_err());
    }

    #[test]
    fn invalid_specs_are_rejected() {
        let (_temp, root) = scratch();
        let base = spec_for(&root);

        let mut zero_runtime = base.clone();
        zero_runtime.max_runtime_ms = 0;
        assert_eq!(
            zero_runtime.validate().expect_err("zero runtime").code(),
            ErrorCode::InvalidInput
        );

        let mut long_runtime = base.clone();
        long_runtime.max_runtime_ms = MAX_SANDBOX_RUNTIME_MS + 1;
        assert_eq!(
            long_runtime.validate().expect_err("oversize runtime").code(),
            ErrorCode::LimitExceeded
        );

        let mut zero_display = base.clone();
        zero_display.display = Some((0, 720));
        assert!(zero_display.validate().is_err());

        let mut huge_display = base.clone();
        huge_display.display = Some((MAX_SANDBOX_DISPLAY_EDGE + 1, 720));
        assert_eq!(
            huge_display.validate().expect_err("oversize display").code(),
            ErrorCode::LimitExceeded
        );

        let mut missing_display = base.clone();
        missing_display.backend = SandboxBackend::VirtualDisplay;
        missing_display.display = None;
        assert_eq!(
            missing_display
                .validate()
                .expect_err("a virtual display needs a size")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut missing_scratch = base.clone();
        missing_scratch.scratch_root = root.join("missing");
        assert_eq!(
            missing_scratch
                .validate()
                .expect_err("a missing scratch root")
                .code(),
            ErrorCode::NotFound
        );

        let mut relative_scratch = base.clone();
        relative_scratch.scratch_root = PathBuf::from("relative/scratch");
        assert_eq!(
            relative_scratch
                .validate()
                .expect_err("a relative scratch root")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut too_many = base.clone();
        too_many.network_allowlist = (0..=MAX_NETWORK_ALLOWLIST_ENTRIES)
            .map(|index| format!("host{index}.example.com:443"))
            .collect();
        assert_eq!(
            too_many.validate().expect_err("too many entries").code(),
            ErrorCode::LimitExceeded
        );
    }

    #[test]
    fn scratch_root_must_live_under_the_owned_root() {
        let (temp, root) = scratch();
        let spec = spec_for(&root);
        spec.validate_scratch_under(temp.path())
            .expect("the scratch root is inside the temp root");

        let other = tempfile::tempdir().expect("other tempdir");
        let error = spec
            .validate_scratch_under(other.path())
            .expect_err("a scratch root outside the owned root is refused");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
    }

    #[test]
    fn runner_failure_is_typed() {
        let (_temp, root) = scratch();

        let launch_runner = ScriptedRunner {
            fail_launch: Some((ErrorCode::Unavailable, "no hypervisor")),
            ..ScriptedRunner::default()
        };
        let error = launch(spec_for(&root), &launch_runner)
            .expect_err("a backend launch failure is an error");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains("failed to launch"));
        assert!(error.message().contains("no hypervisor"));

        let perform_runner = ScriptedRunner {
            fail_perform: Some((ErrorCode::Io, "frame dropped")),
            ..ScriptedRunner::default()
        };
        let mut session = launch(spec_for(&root), &perform_runner).expect("launch");
        let action = sandbox_action(ActionKind::Screenshot);
        let error = execute(&mut session, &action, PolicyMode::Auto, &[], &perform_runner)
            .expect_err("a backend action failure is an error");
        assert_eq!(error.code(), ErrorCode::Io);
        assert_eq!(session.state, SandboxState::Running);
        assert_eq!(session.actions.len(), 1);
        assert!(!session.actions[0].outcome.is_completed());
        assert!(matches!(
            session.actions[0].outcome,
            ActionOutcome::Failed { .. }
        ));

        let stop_runner = ScriptedRunner {
            fail_stop: Some((ErrorCode::Timeout, "stop timed out")),
            ..ScriptedRunner::default()
        };
        let mut session = launch(spec_for(&root), &stop_runner).expect("launch");
        let error = stop(&mut session, &stop_runner).expect_err("a stop failure is an error");
        assert_eq!(error.code(), ErrorCode::Timeout);
        assert_eq!(session.state, SandboxState::Failed);
    }

    #[test]
    fn actions_route_through_policy_and_destructive_actions_ask() {
        let (_temp, root) = scratch();
        let (mut session, runner) = running(&root);

        let shot = sandbox_action(ActionKind::Screenshot);
        let record = execute(&mut session, &shot, PolicyMode::Auto, &[], &runner)
            .expect("a screenshot is allowed");
        assert!(record.decision.is_allow());
        assert!(record.outcome.is_completed());
        assert_eq!(session.actions.len(), 1);
        assert_eq!(runner.performed.borrow().len(), 1);

        let mut destructive = sandbox_action(ActionKind::CloseWindow);
        destructive.destructive = true;
        let error = execute(
            &mut session,
            &destructive,
            PolicyMode::Auto,
            &[],
            &runner,
        )
        .expect_err("a destructive action asks and must not run");
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);
        assert_eq!(runner.performed.borrow().len(), 1);
        assert_eq!(session.actions.len(), 1);

        let mut live_host = sandbox_action(ActionKind::Click);
        live_host.target = Target::LiveHost;
        let error = execute(&mut session, &live_host, PolicyMode::Auto, &[], &runner)
            .expect_err("a live host action cannot run in the sandbox");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(runner.performed.borrow().len(), 1);

        let error = execute(
            &mut session,
            &sandbox_action(ActionKind::Click),
            PolicyMode::Plan,
            &[],
            &runner,
        )
        .expect_err("plan mode denies a sandbox side effect");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(runner.performed.borrow().len(), 1);
    }

    #[test]
    fn session_id_and_report_are_deterministic() {
        let (_temp, root) = scratch();
        let spec = spec_for(&root);
        assert_eq!(session_id(&spec), session_id(&spec.clone()));

        let mut other = spec.clone();
        other.network_allowlist = vec!["api.example.com:8443".to_string()];
        assert_ne!(session_id(&spec), session_id(&other));

        let (mut session, _runner) = running(&root);
        assert!(check_escape(&mut session, EscapeAttempt::DeviceAccess).is_err());
        let first = session.escape_report();
        let second = session.escape_report();
        assert_eq!(first, second);
        let json = serde_json::to_string(&first).expect("serialize report");
        assert_eq!(
            serde_json::from_str::<EscapeReport>(&json).expect("deserialize report"),
            first
        );
    }

    #[test]
    fn no_host_code_execution_path_exists() {
        // The production half is data and boundary checks only. A real backend
        // supplies execution through `SandboxRunner`; this module cannot start a
        // process, open a socket, or reach a hypervisor on its own.
        let source = include_str!("sandboxed.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("sandboxed.rs has a production half");
        for needle in [
            "std::process",
            "Command::new",
            "std::net",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "hyper",
            "ureq",
            "isahc",
            "OpenProcess",
            "CreateProcess",
            "ShellExecute",
            "execve",
            "vmrun",
            "qemu",
            "VBoxManage",
            "WScript.Shell",
        ] {
            assert!(
                !production.contains(needle),
                "`{needle}` must not appear in the sandboxed module; it is a boundary, not a driver"
            );
        }
    }
}
