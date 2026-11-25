//! Sandbox gate, command policy, scratch isolation, and promotion
//! (SR-05, SR-09, SR-10, TRU-07).
//!
//! This module supplies the *gate*, the *policy*, and the *seam*:
//!
//! - [`detect`] reports a platform mechanism only when one is really present.
//!   [`Sandbox::new`] refuses to construct a sandbox when detection is
//!   unavailable, and [`Sandbox::execute`] refuses to invoke a runner. Target
//!   code is never run unconfined by this module.
//! - [`SandboxPolicy`] fixes the read-only target, the scratch root, an empty
//!   environment allowlist, no network, and explicit resource limits.
//! - [`Sandbox::build_plan`] resolves a [`SandboxCommand`] into a
//!   [`SandboxPlan`] or a typed `zero.pol.denied` refusal. Every refusal is
//!   recorded in a [`SandboxReport`]; nothing is silently dropped.
//! - [`Scratch`] gives each agent its own directory and [`Scratch::promote`]
//!   copies one regular file, as trusted parent code, into a promotion root
//!   after path, symlink, type, and size checks.
//!
//! The OS-specific runner is injected through [`SandboxRunner`]. The runner is
//! responsible for applying the plan's limits, read-only target, network flag,
//! and scratch-only writes with the platform mechanism named by
//! [`SandboxAvailability`]. This slice does not implement those kernel calls:
//! it supplies the availability gate, the policy, the escape checks, and the
//! test seam. A real runner must kill the child at `timeout_ms`; [`execute`]
//! records a timeout it observes, but without a child handle it cannot kill.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, Result, ZeroError};

/// Default per-command wall-clock budget in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// Default per-command memory cap in MiB.
pub const DEFAULT_MEMORY_MB: u64 = 256;
/// Default cap on child processes.
pub const DEFAULT_PROCESSES: u32 = 8;
/// Default cap on one promoted file in bytes.
pub const DEFAULT_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Default cap on captured stdout and stderr, each, in bytes.
pub const DEFAULT_OUTPUT_BYTES: u64 = 1024 * 1024;

/// Environment names carried into every plan even when they are not listed.
///
/// The allowlist is otherwise empty. A name that looks secret is still refused.
pub const BASELINE_ENV: [&str; 4] = ["PATH", "HOME", "LANG", "TZ"];

/// Longest detail kept in a report entry or refusal message.
pub const MAX_DETAIL_CHARS: usize = 240;

// ---------------------------------------------------------------------------
// Availability (SR-09)
// ---------------------------------------------------------------------------

/// Whether a real platform sandbox mechanism is present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum SandboxAvailability {
    /// A mechanism was observed and is named.
    Available { mechanism: String },
    /// No mechanism is present, so target code must not run.
    Unavailable { reason: String },
}

/// A platform probe hook.
///
/// A production integration performs the real OS check (for example creating a
/// Windows job object or an AppContainer profile, or finding `bwrap` on
/// `PATH`) and returns [`SandboxAvailability::Available`] only when the
/// mechanism exists. The default [`detect`] uses the platform implementation;
/// [`detect_with`] exists so tests and embedders can inject a probe.
pub trait SandboxProbe {
    fn probe(&self) -> SandboxAvailability;
}

/// Probe for a Windows job object.
///
/// Creating and closing an unnamed job object proves that the job-object API is
/// present. Assigning the child to the job and setting its limits is the
/// runner's job, not the probe's.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsJobObjectProbe;

#[cfg(windows)]
impl SandboxProbe for WindowsJobObjectProbe {
    fn probe(&self) -> SandboxAvailability {
        windows_job_object::probe()
    }
}

#[cfg(windows)]
mod windows_job_object {
    use std::ffi::c_void;

    use super::SandboxAvailability;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> *mut c_void;
        fn CloseHandle(object: *mut c_void) -> i32;
    }

    pub(super) fn probe() -> SandboxAvailability {
        // SAFETY: null security attributes and a null name request an unnamed
        // job object owned by this process. No borrowed memory is passed.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return SandboxAvailability::Unavailable {
                reason: format!(
                    "CreateJobObjectW failed: {}",
                    std::io::Error::last_os_error()
                ),
            };
        }
        // SAFETY: `handle` came from CreateJobObjectW and is closed once here.
        unsafe {
            CloseHandle(handle);
        }
        SandboxAvailability::Available {
            mechanism: "windows-job-object".to_string(),
        }
    }
}

/// Detect the platform mechanism, if any.
///
/// - Linux: `bwrap` (bubblewrap) or `unshare` on `PATH`.
/// - macOS: `sandbox-exec` on `PATH`.
/// - Windows: a job-object probe.
/// - Anything else: unavailable.
///
/// A probe that claims availability without naming a mechanism is downgraded to
/// unavailable.
pub fn detect() -> SandboxAvailability {
    normalize(detect_platform())
}

/// Detect through an injected probe. The result is normalized exactly like
/// [`detect`]: an unnamed mechanism is unavailable.
pub fn detect_with(probe: &dyn SandboxProbe) -> SandboxAvailability {
    normalize(probe.probe())
}

fn normalize(availability: SandboxAvailability) -> SandboxAvailability {
    match availability {
        SandboxAvailability::Available { mechanism } if !mechanism.trim().is_empty() => {
            SandboxAvailability::Available { mechanism }
        }
        SandboxAvailability::Available { .. } => SandboxAvailability::Unavailable {
            reason: "probe claimed availability without naming a mechanism".to_string(),
        },
        SandboxAvailability::Unavailable { reason } if reason.trim().is_empty() => {
            SandboxAvailability::Unavailable {
                reason: "no sandbox mechanism is available".to_string(),
            }
        }
        other => other,
    }
}

#[cfg(target_os = "linux")]
fn detect_platform() -> SandboxAvailability {
    for (program, mechanism) in [("bwrap", "bubblewrap"), ("unshare", "unshare-namespaces")] {
        if find_on_path(program).is_some() {
            return SandboxAvailability::Available {
                mechanism: mechanism.to_string(),
            };
        }
    }
    SandboxAvailability::Unavailable {
        reason: "neither `bwrap` nor `unshare` is on PATH".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn detect_platform() -> SandboxAvailability {
    if find_on_path("sandbox-exec").is_some() {
        SandboxAvailability::Available {
            mechanism: "sandbox-exec".to_string(),
        }
    } else {
        SandboxAvailability::Unavailable {
            reason: "`sandbox-exec` is not on PATH".to_string(),
        }
    }
}

#[cfg(windows)]
fn detect_platform() -> SandboxAvailability {
    WindowsJobObjectProbe.probe()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn detect_platform() -> SandboxAvailability {
    SandboxAvailability::Unavailable {
        reason: "no sandbox mechanism is implemented for this platform".to_string(),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn find_on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

// ---------------------------------------------------------------------------
// Policy and limits (SR-09)
// ---------------------------------------------------------------------------

/// Resource caps for one sandboxed command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxLimits {
    /// Wall-clock budget. A runner with a child handle must kill on expiry.
    pub timeout_ms: u64,
    /// Memory cap in MiB.
    pub memory_mb: u64,
    /// Cap on concurrent child processes.
    pub processes: u32,
    /// Largest file a promotion may copy, in bytes.
    pub file_bytes: u64,
    /// Cap on captured stdout and stderr, each, in bytes.
    pub output_bytes: u64,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_TIMEOUT_MS,
            memory_mb: DEFAULT_MEMORY_MB,
            processes: DEFAULT_PROCESSES,
            file_bytes: DEFAULT_FILE_BYTES,
            output_bytes: DEFAULT_OUTPUT_BYTES,
        }
    }
}

impl SandboxLimits {
    fn validate(&self) -> Result<()> {
        if self.timeout_ms == 0
            || self.memory_mb == 0
            || self.processes == 0
            || self.file_bytes == 0
            || self.output_bytes == 0
        {
            return Err(invalid("sandbox limits must all be greater than zero"));
        }
        Ok(())
    }
}

/// The policy a sandbox runs under.
///
/// [`SandboxPolicy::new`] is the secure default: an empty environment
/// allowlist, no network, and a read-only target. Fields are public so a
/// trusted parent can adjust them; the SR-09 production policy is
/// `network = false` and `read_only_target = true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPolicy {
    /// The review target. It is readable but never writable by target code.
    pub target_root: PathBuf,
    /// The only directory tree target code may write inside.
    pub scratch_root: PathBuf,
    /// Extra environment names to carry, beyond [`BASELINE_ENV`].
    pub env_allowlist: Vec<String>,
    /// Whether network-shaped arguments are allowed. SR-09 requires `false`.
    pub network: bool,
    /// Whether the target is mounted read-only. SR-09 requires `true`.
    pub read_only_target: bool,
    pub limits: SandboxLimits,
}

impl SandboxPolicy {
    /// A secure default policy for `target_root` and `scratch_root`.
    pub fn new(target_root: impl AsRef<Path>, scratch_root: impl AsRef<Path>) -> Self {
        Self {
            target_root: target_root.as_ref().to_path_buf(),
            scratch_root: scratch_root.as_ref().to_path_buf(),
            env_allowlist: Vec::new(),
            network: false,
            read_only_target: true,
            limits: SandboxLimits::default(),
        }
    }

    /// Replace the environment allowlist.
    pub fn with_env_allowlist<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.env_allowlist = names.into_iter().map(Into::into).collect();
        self
    }

    /// Allow or refuse network-shaped arguments.
    pub fn with_network(mut self, allowed: bool) -> Self {
        self.network = allowed;
        self
    }

    /// Mark the target writable. SR-09 never does this in production.
    pub fn with_read_only_target(mut self, read_only: bool) -> Self {
        self.read_only_target = read_only;
        self
    }

    /// Replace the resource limits.
    pub fn with_limits(mut self, limits: SandboxLimits) -> Self {
        self.limits = limits;
        self
    }

    fn validated(mut self) -> Result<Self> {
        self.target_root = canonical_dir(&self.target_root, "target root")?;
        self.scratch_root = canonical_dir(&self.scratch_root, "scratch root")?;
        // A scratch that contains the target would make the read-only claim
        // meaningless. A scratch inside the target is allowed as an explicit
        // carve-out; a scratch equal to or above the target is not.
        if self.target_root.starts_with(&self.scratch_root) {
            return Err(invalid(
                "the scratch root must not be the target root or contain it",
            ));
        }
        for name in &self.env_allowlist {
            validate_env_name(name)?;
        }
        self.env_allowlist.sort();
        self.env_allowlist.dedup();
        self.limits.validate()?;
        Ok(self)
    }
}

/// One command the sandbox may run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCommand {
    /// Absolute path to an existing regular file.
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Working directory, inside the target or the scratch.
    pub cwd: PathBuf,
}

/// A resolved command handed to a [`SandboxRunner`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    /// The filtered environment. Values never come from a secret-looking name.
    pub env: BTreeMap<String, String>,
    pub limits: SandboxLimits,
    pub read_only_target: bool,
    pub network: bool,
    pub target_root: PathBuf,
    pub scratch_root: PathBuf,
}

/// Result of one sandboxed command.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// Set by a runner that killed the child at the timeout.
    pub timed_out: bool,
    /// True when this module cut `stdout` at the byte cap.
    pub stdout_truncated: bool,
    /// True when this module cut `stderr` at the byte cap.
    pub stderr_truncated: bool,
}

/// Why a command was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxDenialKind {
    Unavailable,
    Program,
    Cwd,
    Path,
    Network,
    Env,
}

impl SandboxDenialKind {
    /// Stable wire name used in refusal messages and report entries.
    pub const fn as_str(self) -> &'static str {
        match self {
            SandboxDenialKind::Unavailable => "unavailable",
            SandboxDenialKind::Program => "program",
            SandboxDenialKind::Cwd => "cwd",
            SandboxDenialKind::Path => "path",
            SandboxDenialKind::Network => "network",
            SandboxDenialKind::Env => "env",
        }
    }
}

/// One refused attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxDenial {
    pub kind: SandboxDenialKind,
    /// Bounded detail. It never carries environment values or file contents.
    pub detail: String,
}

impl SandboxDenial {
    fn new(kind: SandboxDenialKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: bounded(detail.into()),
        }
    }
}

/// What happened to one command: what was attempted, what was blocked, and
/// whether the runner ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxReport {
    pub availability: SandboxAvailability,
    /// Every refusal detected while resolving the command.
    pub attempted: Vec<SandboxDenial>,
    /// What enforcement stopped. It mirrors `attempted` in this slice; a
    /// future OS mechanism may add entries the policy layer cannot see.
    pub blocked: Vec<SandboxDenial>,
    /// True when the runner was invoked.
    pub executed: bool,
    /// True when the runner reported a timeout or exceeded the budget.
    pub timed_out: bool,
    /// True when either captured stream was cut at the byte cap.
    pub output_truncated: bool,
    pub notes: Vec<String>,
}

impl SandboxReport {
    fn new(availability: SandboxAvailability) -> Self {
        Self {
            availability,
            attempted: Vec::new(),
            blocked: Vec::new(),
            executed: false,
            timed_out: false,
            output_truncated: false,
            notes: Vec::new(),
        }
    }

    /// True when at least one attempt was refused.
    pub fn is_blocked(&self) -> bool {
        !self.blocked.is_empty()
    }
}

/// The OS-specific execution seam.
///
/// A runner applies `plan.read_only_target`, `plan.network`,
/// `plan.scratch_root`, and `plan.limits` with the platform mechanism named by
/// the sandbox's availability. It must not widen them. It must kill the child
/// at `plan.limits.timeout_ms` and set [`SandboxOutput::timed_out`]; a runner
/// that cannot enforce a limit must return an error rather than run anyway.
///
/// The trait stays deliberately simple: no child handle is exposed, so
/// [`Sandbox::execute`] can cap output and record timeouts but cannot kill a
/// runner that fails to enforce its own budget.
pub trait SandboxRunner {
    fn run(&self, plan: &SandboxPlan) -> Result<SandboxOutput>;
}

// ---------------------------------------------------------------------------
// Sandbox gate and execution
// ---------------------------------------------------------------------------

/// A sandbox bound to one policy and one availability result.
#[derive(Debug, Clone)]
pub struct Sandbox {
    policy: SandboxPolicy,
    availability: SandboxAvailability,
}

impl Sandbox {
    /// Build a sandbox only when a real mechanism is available.
    ///
    /// Returns `zero.fnd.unsupported` when [`detect`] is unavailable; target
    /// code must not run in that case.
    pub fn new(policy: SandboxPolicy) -> Result<Self> {
        Self::gated(policy, detect())
    }

    /// Build a sandbox through an injected probe, with the same gate as
    /// [`Sandbox::new`].
    pub fn new_with_probe(policy: SandboxPolicy, probe: &dyn SandboxProbe) -> Result<Self> {
        Self::gated(policy, detect_with(probe))
    }

    /// Build a sandbox with an explicit availability result.
    ///
    /// This is the test and platform-integration seam. It does not bypass the
    /// gate: [`Sandbox::execute`] still refuses to run when the availability is
    /// `Unavailable`.
    pub fn with_availability(
        policy: SandboxPolicy,
        availability: SandboxAvailability,
    ) -> Result<Self> {
        Ok(Self {
            policy: policy.validated()?,
            availability: normalize(availability),
        })
    }

    fn gated(policy: SandboxPolicy, availability: SandboxAvailability) -> Result<Self> {
        let availability = normalize(availability);
        if let SandboxAvailability::Unavailable { reason } = &availability {
            return Err(ZeroError::new(
                ErrorCode::Unsupported,
                format!("target code will not run without a sandbox mechanism ({reason})"),
            ));
        }
        Self::with_availability(policy, availability)
    }

    /// The probed mechanism, or the reason none exists.
    pub fn availability(&self) -> &SandboxAvailability {
        &self.availability
    }

    /// The normalized policy. Roots are canonical.
    pub fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    /// Resolve a command to a plan, or refuse it.
    ///
    /// An unavailable sandbox returns `zero.fnd.unsupported`: a plan is a
    /// runnable instruction, so it is not produced without a mechanism.
    pub fn build_plan(&self, command: &SandboxCommand) -> Result<SandboxPlan> {
        if let SandboxAvailability::Unavailable { reason } = &self.availability {
            return Err(ZeroError::new(
                ErrorCode::Unsupported,
                format!("target code will not run without a sandbox mechanism ({reason})"),
            ));
        }
        let resolved = self.resolve_plan(command);
        match resolved.plan {
            Some(plan) => Ok(plan),
            None => Err(refusal(&resolved.denials)),
        }
    }

    /// Execute a command through `runner`, returning only the result.
    pub fn execute(
        &self,
        command: &SandboxCommand,
        runner: &dyn SandboxRunner,
    ) -> Result<SandboxOutput> {
        self.execute_reported(command, runner).0
    }

    /// Execute a command and return the report with the result.
    ///
    /// The report is available on both success and refusal, so a blocked
    /// escape attempt is never invisible.
    pub fn execute_reported(
        &self,
        command: &SandboxCommand,
        runner: &dyn SandboxRunner,
    ) -> (Result<SandboxOutput>, SandboxReport) {
        let mut report = SandboxReport::new(self.availability.clone());

        if let SandboxAvailability::Unavailable { reason } = &self.availability {
            let denial = SandboxDenial::new(
                SandboxDenialKind::Unavailable,
                format!("no sandbox mechanism: {reason}"),
            );
            report.attempted.push(denial.clone());
            report.blocked.push(denial);
            report
                .notes
                .push("target code was not run; confinement is unavailable".to_string());
            return (
                Err(ZeroError::new(
                    ErrorCode::Unsupported,
                    format!("target code will not run without a sandbox mechanism ({reason})"),
                )),
                report,
            );
        }

        let resolved = self.resolve_plan(command);
        if !resolved.denials.is_empty() {
            report.attempted.extend(resolved.denials.iter().cloned());
            report.blocked.extend(resolved.denials.iter().cloned());
            return (Err(refusal(&resolved.denials)), report);
        }
        let Some(plan) = resolved.plan else {
            // `resolve_plan` always produces one or the other.
            let denial = SandboxDenial::new(
                SandboxDenialKind::Program,
                "the command could not be resolved into a plan",
            );
            report.attempted.push(denial.clone());
            report.blocked.push(denial);
            return (Err(refusal(&report.blocked)), report);
        };

        let started = Instant::now();
        let result = runner.run(&plan);
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        report.executed = true;

        match result {
            Ok(output) => {
                let capped = cap_output(output, plan.limits.output_bytes);
                report.output_truncated = capped.stdout_truncated || capped.stderr_truncated;
                report.timed_out = capped.timed_out || elapsed_ms > plan.limits.timeout_ms;
                if capped.stdout_truncated {
                    report.notes.push(format!(
                        "stdout truncated at {} bytes",
                        plan.limits.output_bytes
                    ));
                }
                if capped.stderr_truncated {
                    report.notes.push(format!(
                        "stderr truncated at {} bytes",
                        plan.limits.output_bytes
                    ));
                }
                if capped.timed_out {
                    report.notes.push(format!(
                        "runner reported a timeout at {} ms",
                        plan.limits.timeout_ms
                    ));
                } else if report.timed_out {
                    report.notes.push(format!(
                        "runner exceeded the {} ms budget; a runner with a child handle must kill it",
                        plan.limits.timeout_ms
                    ));
                }
                (Ok(capped), report)
            }
            Err(error) => {
                report
                    .notes
                    .push(bounded(format!("runner failed: {}", error.message())));
                (Err(error), report)
            }
        }
    }

    fn resolve_plan(&self, command: &SandboxCommand) -> ResolvedPlan {
        let mut denials = Vec::new();

        let cwd = match self.resolve_cwd(&command.cwd) {
            Ok(cwd) => Some(cwd),
            Err(denial) => {
                denials.push(denial);
                None
            }
        };
        if let Some(denial) = self.check_program(&command.program) {
            denials.push(denial);
        }
        for (index, argument) in command.args.iter().enumerate() {
            self.check_argument(index, argument, &mut denials);
        }
        let env = self.resolve_env(&mut denials);

        if !denials.is_empty() {
            return ResolvedPlan {
                plan: None,
                denials,
            };
        }
        let Some(cwd) = cwd else {
            return ResolvedPlan {
                plan: None,
                denials: vec![SandboxDenial::new(
                    SandboxDenialKind::Cwd,
                    "the working directory could not be resolved",
                )],
            };
        };

        ResolvedPlan {
            plan: Some(SandboxPlan {
                program: command.program.clone(),
                args: command.args.clone(),
                cwd,
                env,
                limits: self.policy.limits,
                read_only_target: self.policy.read_only_target,
                network: self.policy.network,
                target_root: self.policy.target_root.clone(),
                scratch_root: self.policy.scratch_root.clone(),
            }),
            denials,
        }
    }

    fn resolve_cwd(&self, cwd: &Path) -> std::result::Result<PathBuf, SandboxDenial> {
        if has_parent_component(cwd) {
            return Err(SandboxDenial::new(
                SandboxDenialKind::Cwd,
                "the working directory contains a `..` component",
            ));
        }
        let canonical = cwd.canonicalize().map_err(|_| {
            SandboxDenial::new(
                SandboxDenialKind::Cwd,
                "the working directory does not exist or cannot be resolved",
            )
        })?;
        if !canonical.is_dir() {
            return Err(SandboxDenial::new(
                SandboxDenialKind::Cwd,
                "the working directory is not a directory",
            ));
        }
        if !canonical.starts_with(&self.policy.target_root)
            && !canonical.starts_with(&self.policy.scratch_root)
        {
            return Err(SandboxDenial::new(
                SandboxDenialKind::Cwd,
                "the working directory is outside the target and scratch roots",
            ));
        }
        Ok(canonical)
    }

    fn check_program(&self, program: &Path) -> Option<SandboxDenial> {
        match std::fs::metadata(program) {
            Ok(metadata) if metadata.is_file() => None,
            Ok(_) => Some(SandboxDenial::new(
                SandboxDenialKind::Program,
                format!("program `{}` is not a regular file", bounded_path(program)),
            )),
            Err(_) => Some(SandboxDenial::new(
                SandboxDenialKind::Program,
                format!(
                    "program `{}` does not exist or is unreadable",
                    bounded_path(program)
                ),
            )),
        }
    }

    fn check_argument(&self, index: usize, argument: &str, denials: &mut Vec<SandboxDenial>) {
        if !self.policy.network {
            let lower = argument.to_ascii_lowercase();
            if lower.contains("http://") || lower.contains("https://") || lower.contains("git@") {
                // The argument is not echoed: a URL can carry a credential.
                denials.push(SandboxDenial::new(
                    SandboxDenialKind::Network,
                    format!(
                        "argument {index} resembles a network URL while network access is disabled"
                    ),
                ));
            }
        }

        let path = Path::new(argument);
        if has_parent_component(path) {
            denials.push(SandboxDenial::new(
                SandboxDenialKind::Path,
                format!("argument {index} contains a `..` path component"),
            ));
            return;
        }
        if path.is_absolute() || path.has_root() {
            let candidate = canonical_candidate(path);
            if !candidate.starts_with(&self.policy.target_root)
                && !candidate.starts_with(&self.policy.scratch_root)
            {
                denials.push(SandboxDenial::new(
                    SandboxDenialKind::Path,
                    format!(
                        "argument {index} is an absolute path outside the target and scratch roots"
                    ),
                ));
            }
        }
    }

    fn resolve_env(&self, denials: &mut Vec<SandboxDenial>) -> BTreeMap<String, String> {
        let mut names: BTreeSet<&str> = BASELINE_ENV.iter().copied().collect();
        for name in &self.policy.env_allowlist {
            if is_secret_name(name) {
                denials.push(SandboxDenial::new(
                    SandboxDenialKind::Env,
                    format!("environment name `{name}` looks secret and is refused"),
                ));
                continue;
            }
            names.insert(name.as_str());
        }

        let mut env = BTreeMap::new();
        for name in names {
            if is_secret_name(name) {
                continue;
            }
            if let Ok(value) = std::env::var(name) {
                env.insert(name.to_string(), value);
            }
        }
        env
    }
}

struct ResolvedPlan {
    plan: Option<SandboxPlan>,
    denials: Vec<SandboxDenial>,
}

/// Execute one command under a fresh default-detected sandbox.
///
/// This is the module-level convenience form. It refuses with
/// `zero.fnd.unsupported` when the platform has no mechanism.
pub fn execute(
    command: &SandboxCommand,
    policy: &SandboxPolicy,
    runner: &dyn SandboxRunner,
) -> Result<SandboxOutput> {
    Sandbox::new(policy.clone())?.execute(command, runner)
}

// ---------------------------------------------------------------------------
// Scratch and promotion (SR-10)
// ---------------------------------------------------------------------------

/// Why a promotion was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionDenialKind {
    Path,
    Symlink,
    Type,
    Size,
    Overwrite,
    Parent,
}

impl PromotionDenialKind {
    /// Stable wire name used in refusal messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            PromotionDenialKind::Path => "path",
            PromotionDenialKind::Symlink => "symlink",
            PromotionDenialKind::Type => "type",
            PromotionDenialKind::Size => "size",
            PromotionDenialKind::Overwrite => "overwrite",
            PromotionDenialKind::Parent => "parent",
        }
    }
}

/// Promotion bounds supplied by trusted parent code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionLimits {
    /// The only directory tree a promoted file may land in.
    pub root: PathBuf,
    /// Largest promoted file in bytes.
    pub max_bytes: u64,
}

impl PromotionLimits {
    pub fn new(root: impl AsRef<Path>, max_bytes: u64) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            max_bytes,
        }
    }
}

/// One promoted file. Paths and size only; never file contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotedFile {
    pub agent_id: String,
    pub source: PathBuf,
    pub dest: PathBuf,
    pub bytes: u64,
}

/// A per-agent scratch directory.
#[derive(Debug)]
pub struct Scratch {
    root: PathBuf,
    dir: PathBuf,
    agent_id: String,
}

impl Scratch {
    /// Create (or reuse) `root/<agent_id>`.
    ///
    /// Agent ids are restricted to ASCII alphanumerics, `.`, `_`, and `-`, so
    /// an id can never climb out of `root`. An existing agent directory that is
    /// a symlink is refused.
    pub fn create(root: impl AsRef<Path>, agent_id: &str) -> Result<Self> {
        validate_agent_id(agent_id)?;
        let root = root.as_ref();
        std::fs::create_dir_all(root)?;
        let root = root.canonicalize()?;
        if !root.is_dir() {
            return Err(invalid("the scratch root is not a directory"));
        }

        let dir = root.join(agent_id);
        match std::fs::symlink_metadata(&dir) {
            Ok(metadata) => {
                if is_link_like(&metadata) {
                    return Err(promotion_denied(
                        PromotionDenialKind::Symlink,
                        format!(
                            "scratch `{}` is a symlink or reparse point",
                            bounded_path(&dir)
                        ),
                    ));
                }
                if !metadata.is_dir() {
                    return Err(invalid(format!(
                        "scratch `{}` exists and is not a directory",
                        bounded_path(&dir)
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&dir)?;
            }
            Err(error) => return Err(error.into()),
        }

        let dir = dir.canonicalize()?;
        if !dir.starts_with(&root) {
            return Err(promotion_denied(
                PromotionDenialKind::Path,
                "the agent scratch escapes the scratch root",
            ));
        }
        Ok(Self {
            root,
            dir,
            agent_id: agent_id.to_string(),
        })
    }

    /// The canonical scratch root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// This agent's canonical directory.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// The agent id this scratch belongs to.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Promote one regular file from this scratch into `limits.root`.
    ///
    /// Checks, in order: no `..` in either path; the source is not a symlink
    /// and is a regular file below this agent's scratch; the size fits; the
    /// destination parent exists, is not a symlink, and is under the promotion
    /// root; the destination does not exist. A partial copy is removed on
    /// failure.
    pub fn promote(
        &self,
        source: &Path,
        dest: &Path,
        limits: &PromotionLimits,
    ) -> Result<PromotedFile> {
        if limits.max_bytes == 0 {
            return Err(invalid("a promotion limit must be greater than zero"));
        }
        if has_parent_component(source) {
            return Err(promotion_denied(
                PromotionDenialKind::Path,
                "the source path contains a `..` component",
            ));
        }
        if has_parent_component(dest) {
            return Err(promotion_denied(
                PromotionDenialKind::Path,
                "the destination path contains a `..` component",
            ));
        }

        let source = if source.is_relative() {
            self.dir.join(source)
        } else {
            source.to_path_buf()
        };
        if !source.starts_with(&self.dir) {
            return Err(promotion_denied(
                PromotionDenialKind::Path,
                "the source is outside this agent's scratch",
            ));
        }
        let source_metadata = std::fs::symlink_metadata(&source)?;
        if is_link_like(&source_metadata) {
            return Err(promotion_denied(
                PromotionDenialKind::Symlink,
                "the source is a symlink or reparse point",
            ));
        }
        if !source_metadata.is_file() {
            return Err(promotion_denied(
                PromotionDenialKind::Type,
                "the source is not a regular file",
            ));
        }
        let source = source.canonicalize()?;
        if !source.starts_with(&self.dir) {
            return Err(promotion_denied(
                PromotionDenialKind::Path,
                "the canonical source is outside this agent's scratch",
            ));
        }

        let root = canonical_dir(&limits.root, "promotion root")?;
        let dest = if dest.is_relative() {
            root.join(dest)
        } else {
            dest.to_path_buf()
        };
        let Some(name) = dest.file_name() else {
            return Err(promotion_denied(
                PromotionDenialKind::Path,
                "the destination has no file name",
            ));
        };
        let Some(parent) = dest.parent() else {
            return Err(promotion_denied(
                PromotionDenialKind::Path,
                "the destination has no parent directory",
            ));
        };
        let parent_metadata = match std::fs::symlink_metadata(parent) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(promotion_denied(
                    PromotionDenialKind::Parent,
                    "the destination parent does not exist",
                ))
            }
            Err(error) => return Err(error.into()),
        };
        if is_link_like(&parent_metadata) {
            return Err(promotion_denied(
                PromotionDenialKind::Parent,
                "the destination parent is a symlink or reparse point",
            ));
        }
        if !parent_metadata.is_dir() {
            return Err(promotion_denied(
                PromotionDenialKind::Parent,
                "the destination parent is not a directory",
            ));
        }
        let parent = parent.canonicalize()?;
        if !parent.starts_with(&root) {
            return Err(promotion_denied(
                PromotionDenialKind::Path,
                "the destination parent is outside the promotion root",
            ));
        }
        let dest = parent.join(name);

        match std::fs::symlink_metadata(&dest) {
            Ok(_) => {
                return Err(promotion_denied(
                    PromotionDenialKind::Overwrite,
                    "the destination already exists",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let mut input = std::fs::File::open(&source)?;
        let metadata = input.metadata()?;
        if !metadata.is_file() {
            return Err(promotion_denied(
                PromotionDenialKind::Type,
                "the source changed type while being promoted",
            ));
        }
        if metadata.len() > limits.max_bytes {
            return Err(promotion_denied(
                PromotionDenialKind::Size,
                format!("the source exceeds {} bytes", limits.max_bytes),
            ));
        }

        let copied = copy_new_file(&mut input, &dest, limits.max_bytes);
        let copied = match copied {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = std::fs::remove_file(&dest);
                return Err(error);
            }
        };

        Ok(PromotedFile {
            agent_id: self.agent_id.clone(),
            source,
            dest,
            bytes: copied,
        })
    }
}

fn copy_new_file(input: &mut std::fs::File, dest: &Path, max_bytes: u64) -> Result<u64> {
    use std::io::{Read as _, Write as _};

    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                promotion_denied(
                    PromotionDenialKind::Overwrite,
                    "the destination already exists",
                )
            } else {
                ZeroError::from(error)
            }
        })?;
    let copied = std::io::copy(&mut input.take(max_bytes.saturating_add(1)), &mut output)?;
    output.flush()?;
    drop(output);
    if copied > max_bytes {
        let _ = std::fs::remove_file(dest);
        return Err(promotion_denied(
            PromotionDenialKind::Size,
            format!("the source grew past {max_bytes} bytes during promotion"),
        ));
    }
    Ok(copied)
}

fn validate_agent_id(agent_id: &str) -> Result<()> {
    if agent_id.is_empty() {
        return Err(invalid("an agent id must not be empty"));
    }
    if agent_id.len() > 128 {
        return Err(invalid("an agent id must be at most 128 characters"));
    }
    if agent_id == "." || agent_id == ".." {
        return Err(invalid("an agent id must not be `.` or `..`"));
    }
    if !agent_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(invalid(
            "an agent id may only contain ASCII letters, digits, `.`, `_`, and `-`",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn refusal(denials: &[SandboxDenial]) -> ZeroError {
    if denials.is_empty() {
        return ZeroError::new(ErrorCode::PolicyDenied, "sandbox denied the command");
    }
    let mut kinds: Vec<&str> = denials.iter().map(|denial| denial.kind.as_str()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    ZeroError::new(
        ErrorCode::PolicyDenied,
        format!(
            "sandbox denied ({}): {} attempt(s) refused; first: {}",
            kinds.join(", "),
            denials.len(),
            denials[0].detail
        ),
    )
}

fn promotion_denied(kind: PromotionDenialKind, detail: impl Into<String>) -> ZeroError {
    ZeroError::new(
        ErrorCode::PolicyDenied,
        format!(
            "promotion denied ({}): {}",
            kind.as_str(),
            bounded(detail.into())
        ),
    )
}

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

fn validate_env_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(invalid("an environment allowlist entry must not be empty"));
    }
    if name.contains('=') || name.contains('\0') {
        return Err(invalid(format!(
            "environment name `{}` is not a valid name",
            bounded(name.to_string())
        )));
    }
    Ok(())
}

/// A conservative secret-name heuristic over the *name*, never the value.
///
/// `PATH`, `HOME`, `LANG`, and `TZ` do not match. A name such as
/// `OPENAI_API_KEY`, `GITHUB_TOKEN`, or `DB_PASSWORD` does.
fn is_secret_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "key",
        "secret",
        "token",
        "passwd",
        "password",
        "credential",
        "authorization",
        "bearer",
        "cookie",
        "session",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

/// True for a symlink, or on Windows any reparse point (including a junction).
///
/// A junction is not reported by `FileType::is_symlink` in the standard
/// library, but it redirects a path just as effectively, so promotion rejects
/// both.
fn is_link_like(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}

/// Canonicalize an existing path, or walk up to the first existing ancestor,
/// canonicalize it, and append the remaining names. This lets a not-yet-existing
/// argument under a real root compare correctly with a canonical root.
fn canonical_candidate(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut current = path.to_path_buf();
    while let (Some(parent), Some(name)) = (current.parent(), current.file_name()) {
        tail.push(name.to_os_string());
        if let Ok(canonical_parent) = parent.canonicalize() {
            let mut resolved = canonical_parent;
            for name in tail.iter().rev() {
                resolved.push(name);
            }
            return resolved;
        }
        if parent.as_os_str().is_empty() {
            break;
        }
        current = parent.to_path_buf();
    }
    path.to_path_buf()
}

fn cap_output(mut output: SandboxOutput, limit: u64) -> SandboxOutput {
    let cap = usize::try_from(limit).unwrap_or(usize::MAX);
    let (stdout, stdout_truncated) = cap_text(&output.stdout, cap);
    let (stderr, stderr_truncated) = cap_text(&output.stderr, cap);
    output.stdout = stdout;
    output.stderr = stderr;
    output.stdout_truncated |= stdout_truncated;
    output.stderr_truncated |= stderr_truncated;
    output
}

/// Cut `text` at `cap` bytes, preferring a whole-line boundary. A partial UTF-8
/// sequence is never split.
fn cap_text(text: &str, cap: usize) -> (String, bool) {
    if text.len() <= cap {
        return (text.to_string(), false);
    }
    let mut end = cap;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let slice = &text[..end];
    let cut = slice.rfind('\n').map_or(end, |index| index + 1);
    (text[..cut].to_string(), true)
}

fn bounded(text: String) -> String {
    if text.chars().count() <= MAX_DETAIL_CHARS {
        return text;
    }
    let mut clipped: String = text.chars().take(MAX_DETAIL_CHARS - 3).collect();
    clipped.push_str("...");
    clipped
}

fn bounded_path(path: &Path) -> String {
    bounded(path.display().to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::time::Duration;

    use super::*;

    struct FixedProbe(SandboxAvailability);

    impl SandboxProbe for FixedProbe {
        fn probe(&self) -> SandboxAvailability {
            self.0.clone()
        }
    }

    #[derive(Default)]
    struct CaptureRunner {
        calls: Cell<usize>,
        seen: RefCell<Option<SandboxPlan>>,
        output: SandboxOutput,
        delay: Option<Duration>,
    }

    impl CaptureRunner {
        fn returning(stdout: &str) -> Self {
            Self {
                output: SandboxOutput {
                    stdout: stdout.to_string(),
                    ..SandboxOutput::default()
                },
                ..Self::default()
            }
        }

        fn slow(stdout: &str, delay_ms: u64) -> Self {
            let mut runner = Self::returning(stdout);
            runner.delay = Some(Duration::from_millis(delay_ms));
            runner
        }
    }

    impl SandboxRunner for CaptureRunner {
        fn run(&self, plan: &SandboxPlan) -> Result<SandboxOutput> {
            self.calls.set(self.calls.get() + 1);
            *self.seen.borrow_mut() = Some(plan.clone());
            if let Some(delay) = self.delay {
                std::thread::sleep(delay);
            }
            Ok(self.output.clone())
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
        target: PathBuf,
        scratch: PathBuf,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        let target = root.join("target");
        let scratch = root.join("scratch");
        std::fs::create_dir_all(&target).expect("target");
        std::fs::create_dir_all(&scratch).expect("scratch");
        Fixture {
            _dir: dir,
            root,
            target,
            scratch,
        }
    }

    fn sandbox_policy(fixture: &Fixture) -> SandboxPolicy {
        SandboxPolicy::new(&fixture.target, &fixture.scratch)
    }

    fn available(fixture: &Fixture) -> Sandbox {
        Sandbox::with_availability(
            sandbox_policy(fixture),
            SandboxAvailability::Available {
                mechanism: "scripted-test-mechanism".to_string(),
            },
        )
        .expect("sandbox")
    }

    fn command(cwd: &Path, args: &[&str]) -> SandboxCommand {
        SandboxCommand {
            program: std::env::current_exe().expect("current executable"),
            args: args
                .iter()
                .map(|argument| (*argument).to_string())
                .collect(),
            cwd: cwd.to_path_buf(),
        }
    }

    #[test]
    fn an_unavailable_mechanism_refuses_execution_without_invoking_the_runner() {
        let fixture = fixture();
        let probe = FixedProbe(SandboxAvailability::Unavailable {
            reason: "no mechanism for this test".to_string(),
        });
        let error = Sandbox::new_with_probe(sandbox_policy(&fixture), &probe)
            .expect_err("the gate must refuse");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert!(error.message().contains("no mechanism for this test"));

        let sandbox = Sandbox::with_availability(
            sandbox_policy(&fixture),
            SandboxAvailability::Unavailable {
                reason: "no mechanism for this test".to_string(),
            },
        )
        .expect("an unavailable sandbox can be inspected");
        let runner = CaptureRunner::returning("must not run");
        let (result, report) = sandbox.execute_reported(&command(&fixture.scratch, &[]), &runner);
        let error = result.expect_err("execution must be refused");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(
            sandbox
                .build_plan(&command(&fixture.scratch, &[]))
                .expect_err("a plan is not produced without a mechanism")
                .code(),
            ErrorCode::Unsupported
        );
        assert_eq!(runner.calls.get(), 0, "no process may run");
        assert!(!report.executed);
        assert!(report.is_blocked());
        assert!(report
            .blocked
            .iter()
            .any(|denial| denial.kind == SandboxDenialKind::Unavailable));
        assert!(report.notes.iter().any(|note| note.contains("not run")));
    }

    #[test]
    fn detection_is_honest_about_the_platform() {
        match detect() {
            SandboxAvailability::Available { mechanism } => {
                assert!(!mechanism.trim().is_empty());
            }
            SandboxAvailability::Unavailable { reason } => {
                assert!(!reason.trim().is_empty());
            }
        }
    }

    #[test]
    fn a_probe_must_name_a_mechanism_to_claim_availability() {
        let unnamed = FixedProbe(SandboxAvailability::Available {
            mechanism: "   ".to_string(),
        });
        assert!(matches!(
            detect_with(&unnamed),
            SandboxAvailability::Unavailable { .. }
        ));

        let named = FixedProbe(SandboxAvailability::Available {
            mechanism: "test-mechanism".to_string(),
        });
        assert_eq!(
            detect_with(&named),
            SandboxAvailability::Available {
                mechanism: "test-mechanism".to_string()
            }
        );
    }

    #[test]
    fn the_plan_env_is_filtered_to_the_allowlist_and_never_carries_secrets() {
        std::env::set_var("OPENAI_API_KEY", "sk-test-must-not-leak");
        std::env::set_var("ZERO_SANDBOX_TEST_VALUE", "benign-value");

        let fixture = fixture();
        let policy =
            sandbox_policy(&fixture).with_env_allowlist(["ZERO_SANDBOX_TEST_VALUE".to_string()]);
        let sandbox = Sandbox::with_availability(
            policy,
            SandboxAvailability::Available {
                mechanism: "scripted-test-mechanism".to_string(),
            },
        )
        .expect("sandbox");

        let plan = sandbox
            .build_plan(&command(&fixture.scratch, &["script.txt"]))
            .expect("a clean command resolves");
        assert_eq!(
            plan.env.get("ZERO_SANDBOX_TEST_VALUE").map(String::as_str),
            Some("benign-value")
        );
        assert!(!plan.env.contains_key("OPENAI_API_KEY"));
        assert!(!plan.env.values().any(|value| value.contains("sk-test")));
    }

    #[test]
    fn a_secret_shaped_env_name_in_the_allowlist_is_refused_and_reported() {
        let fixture = fixture();
        let policy = sandbox_policy(&fixture).with_env_allowlist(["OPENAI_API_KEY".to_string()]);
        let sandbox = Sandbox::with_availability(
            policy,
            SandboxAvailability::Available {
                mechanism: "scripted-test-mechanism".to_string(),
            },
        )
        .expect("sandbox");
        let runner = CaptureRunner::returning("must not run");
        let (result, report) = sandbox.execute_reported(&command(&fixture.scratch, &[]), &runner);

        let error = result.expect_err("a secret-shaped allowlist is an escape attempt");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("env"));
        assert_eq!(runner.calls.get(), 0);
        assert!(report
            .blocked
            .iter()
            .any(|denial| denial.kind == SandboxDenialKind::Env));
    }

    #[test]
    fn escape_attempts_are_refused_and_reported() {
        let fixture = fixture();
        let sandbox = available(&fixture);
        let runner = CaptureRunner::returning("must not run");
        let outside_absolute = fixture.root.join("outside.txt");
        let cases = [
            (
                command(&fixture.scratch.join("..").join("outside"), &[]),
                SandboxDenialKind::Cwd,
            ),
            (
                command(&fixture.scratch, &[&outside_absolute.to_string_lossy()]),
                SandboxDenialKind::Path,
            ),
            (
                command(&fixture.scratch, &["../escape"]),
                SandboxDenialKind::Path,
            ),
            (
                command(&fixture.scratch, &["https://example.invalid/probe"]),
                SandboxDenialKind::Network,
            ),
        ];

        for (command, kind) in cases {
            let (result, report) = sandbox.execute_reported(&command, &runner);
            let error = result.expect_err("the escape attempt must be refused");
            assert_eq!(error.code(), ErrorCode::PolicyDenied);
            assert!(
                error.message().contains(kind.as_str()),
                "message `{}` must name `{}`",
                error.message(),
                kind.as_str()
            );
            assert!(
                report.blocked.iter().any(|denial| denial.kind == kind),
                "the report must list `{}`",
                kind.as_str()
            );
            assert!(report.attempted.iter().any(|denial| denial.kind == kind));
        }
        assert_eq!(runner.calls.get(), 0, "no refused command may run");
    }

    #[test]
    fn a_clean_command_inside_scratch_runs_with_a_read_only_target_plan() {
        let fixture = fixture();
        std::fs::write(fixture.scratch.join("script.txt"), "echo clean").expect("script");
        let sandbox = available(&fixture);

        // An absolute path under the scratch is allowed even before it exists.
        let inside = fixture.scratch.join("not-yet-created.txt");
        let inside = inside.to_string_lossy().to_string();
        let plan = sandbox
            .build_plan(&command(&fixture.scratch, &[inside.as_str()]))
            .expect("an absolute scratch argument is allowed");
        assert!(plan.cwd.starts_with(&sandbox.policy().scratch_root));

        let runner = CaptureRunner::returning("clean output");
        let (result, report) =
            sandbox.execute_reported(&command(&fixture.scratch, &["script.txt"]), &runner);

        let output = result.expect("a clean command runs");
        assert_eq!(output.stdout, "clean output");
        assert_eq!(runner.calls.get(), 1);
        assert!(report.executed);
        assert!(!report.is_blocked());

        let plan = runner.seen.borrow().clone().expect("the runner saw a plan");
        assert!(plan.read_only_target);
        assert!(!plan.network);
        assert_eq!(plan.limits, SandboxLimits::default());
        assert!(plan.cwd.starts_with(&sandbox.policy().scratch_root));
        assert_eq!(plan.target_root, sandbox.policy().target_root);
        assert_eq!(plan.scratch_root, sandbox.policy().scratch_root);
    }

    #[test]
    fn output_and_time_limits_are_capped_and_reported() {
        let fixture = fixture();
        let limits = SandboxLimits {
            timeout_ms: 1,
            output_bytes: 16,
            ..SandboxLimits::default()
        };
        let policy = sandbox_policy(&fixture).with_limits(limits);
        let sandbox = Sandbox::with_availability(
            policy,
            SandboxAvailability::Available {
                mechanism: "scripted-test-mechanism".to_string(),
            },
        )
        .expect("sandbox");
        let runner = CaptureRunner::slow(&"x".repeat(64), 20);
        let (result, report) = sandbox.execute_reported(&command(&fixture.scratch, &[]), &runner);

        let output = result.expect("the runner returns");
        assert_eq!(output.stdout.len(), 16);
        assert!(output.stdout_truncated);
        assert!(report.output_truncated);
        assert!(report.timed_out, "the elapsed time exceeds the budget");
        assert!(report
            .notes
            .iter()
            .any(|note| note.contains("16 bytes") || note.contains("budget")));
        let plan = runner.seen.borrow().clone().expect("plan");
        assert_eq!(plan.limits.output_bytes, 16);
        assert_eq!(plan.limits.timeout_ms, 1);
    }

    #[test]
    fn a_regular_file_in_the_scratch_promotes_without_contents_in_the_report() {
        let fixture = fixture();
        let scratch =
            Scratch::create(fixture.root.join("agent-scratch"), "agent-a").expect("scratch");
        let source = scratch.path().join("finding.txt");
        std::fs::write(&source, b"finding-body").expect("source");

        let promotion_root = fixture.root.join("promoted");
        std::fs::create_dir_all(&promotion_root).expect("promotion root");
        let limits = PromotionLimits::new(&promotion_root, 1024);
        let promoted = scratch
            .promote(&source, Path::new("finding.txt"), &limits)
            .expect("promotion");

        assert_eq!(promoted.agent_id, "agent-a");
        assert_eq!(promoted.bytes, 12);
        assert_eq!(
            std::fs::read(&promoted.dest).expect("promoted file"),
            b"finding-body"
        );
        assert!(promoted
            .dest
            .starts_with(promotion_root.canonicalize().expect("canonical root")));
        let json = serde_json::to_string(&promoted).expect("report json");
        assert!(
            !json.contains("finding-body"),
            "contents must not be reported"
        );
    }

    #[test]
    fn promotion_refuses_paths_oversize_files_and_overwrites() {
        let fixture = fixture();
        let scratch =
            Scratch::create(fixture.root.join("agent-scratch"), "agent-a").expect("scratch");
        let source = scratch.path().join("finding.txt");
        std::fs::write(&source, b"0123456789").expect("source");
        let promotion_root = fixture.root.join("promoted");
        std::fs::create_dir_all(&promotion_root).expect("promotion root");

        let outside_source = fixture.target.join("outside.txt");
        std::fs::write(&outside_source, b"outside").expect("outside source");
        let error = scratch
            .promote(
                &outside_source,
                Path::new("outside.txt"),
                &PromotionLimits::new(&promotion_root, 1024),
            )
            .expect_err("an outside source is refused");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("path"));

        let error = scratch
            .promote(
                &source,
                Path::new("../escape.txt"),
                &PromotionLimits::new(&promotion_root, 1024),
            )
            .expect_err("a `..` destination is refused");
        assert!(error.message().contains("path"));

        let outside_dest = fixture.target.join("promoted.txt");
        let error = scratch
            .promote(
                &source,
                &outside_dest,
                &PromotionLimits::new(&promotion_root, 1024),
            )
            .expect_err("a destination outside the promotion root is refused");
        assert!(error.message().contains("path"));

        let error = scratch
            .promote(
                &source,
                Path::new("big.txt"),
                &PromotionLimits::new(&promotion_root, 4),
            )
            .expect_err("an oversize file is refused");
        assert!(error.message().contains("size"));
        assert!(!promotion_root.join("big.txt").exists());

        std::fs::write(promotion_root.join("existing.txt"), b"keep").expect("existing");
        let error = scratch
            .promote(
                &source,
                Path::new("existing.txt"),
                &PromotionLimits::new(&promotion_root, 1024),
            )
            .expect_err("an existing destination is not overwritten");
        assert!(error.message().contains("overwrite"));
        assert_eq!(
            std::fs::read(promotion_root.join("existing.txt")).expect("existing"),
            b"keep"
        );
    }

    #[test]
    fn symlink_sources_and_symlink_destination_parents_are_refused() {
        let fixture = fixture();
        let scratch =
            Scratch::create(fixture.root.join("agent-scratch"), "agent-a").expect("scratch");
        let real = scratch.path().join("real.txt");
        std::fs::write(&real, b"real-body").expect("real");
        let promotion_root = fixture.root.join("promoted");
        std::fs::create_dir_all(&promotion_root).expect("promotion root");
        let limits = PromotionLimits::new(&promotion_root, 1024);

        let link = scratch.path().join("link.txt");
        if try_symlink_file(&real, &link) {
            let error = scratch
                .promote(&link, Path::new("link.txt"), &limits)
                .expect_err("a symlink source is refused");
            assert_eq!(error.code(), ErrorCode::PolicyDenied);
            assert!(error.message().contains("symlink"));
        }

        let real_dir = promotion_root.join("real-dir");
        std::fs::create_dir_all(&real_dir).expect("real directory");
        let link_dir = promotion_root.join("link-dir");
        if try_symlink_dir(&real_dir, &link_dir) {
            let error = scratch
                .promote(&real, Path::new("link-dir/file.txt"), &limits)
                .expect_err("a symlink parent is refused");
            assert_eq!(error.code(), ErrorCode::PolicyDenied);
            assert!(error.message().contains("symlink"));
        }

        // Windows refuses symlinks without privilege but allows a directory
        // junction, which is another reparse point. Both must be refused.
        let junction_dir = promotion_root.join("junction-dir");
        if try_junction_dir(&real_dir, &junction_dir) {
            let error = scratch
                .promote(&real, Path::new("junction-dir/file.txt"), &limits)
                .expect_err("a junction parent is refused");
            assert_eq!(error.code(), ErrorCode::PolicyDenied);
            assert!(error.message().contains("symlink"));
        }
    }

    #[test]
    fn two_agents_have_isolated_scratches() {
        let fixture = fixture();
        let root = fixture.root.join("agent-scratch");
        let alpha = Scratch::create(&root, "agent-a").expect("alpha");
        let beta = Scratch::create(&root, "agent-b").expect("beta");
        assert_ne!(alpha.path(), beta.path());

        let source = alpha.path().join("finding.txt");
        std::fs::write(&source, b"alpha-only").expect("source");
        let promotion_root = fixture.root.join("promoted");
        std::fs::create_dir_all(&promotion_root).expect("promotion root");
        let limits = PromotionLimits::new(&promotion_root, 1024);

        let error = beta
            .promote(&source, Path::new("stolen.txt"), &limits)
            .expect_err("one agent cannot promote another agent's file");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("path"));
        assert!(!promotion_root.join("stolen.txt").exists());

        alpha
            .promote(&source, Path::new("own.txt"), &limits)
            .expect("the owner promotes its own file");
    }

    #[test]
    fn agent_ids_cannot_escape_the_scratch_root() {
        let fixture = fixture();
        let root = fixture.root.join("agent-scratch");
        for bad in ["", ".", "..", "../escape", "a/b", "a\\b"] {
            assert!(
                Scratch::create(&root, bad).is_err(),
                "`{bad}` must be refused"
            );
        }
    }

    #[cfg(unix)]
    fn try_symlink_file(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(unix)]
    fn try_symlink_dir(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn try_symlink_file(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }

    #[cfg(windows)]
    fn try_symlink_dir(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_dir(target, link).is_ok()
    }

    #[cfg(windows)]
    fn try_junction_dir(target: &Path, link: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success() && link.exists())
            .unwrap_or(false)
    }

    #[cfg(not(any(unix, windows)))]
    fn try_symlink_file(_target: &Path, _link: &Path) -> bool {
        false
    }

    #[cfg(not(any(unix, windows)))]
    fn try_symlink_dir(_target: &Path, _link: &Path) -> bool {
        false
    }

    #[cfg(not(windows))]
    fn try_junction_dir(_target: &Path, _link: &Path) -> bool {
        false
    }
}
