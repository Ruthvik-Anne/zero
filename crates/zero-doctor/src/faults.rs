//! Fault injection for every stable error code (TST-06, DOC-11).
//!
//! A fault is data: a stable id, the [`ErrorCode`] it produces, a short
//! description, and a [`FaultFixture`] that names the realistic path used to
//! exercise it. The catalogue is exhaustive by construction — [`fault_for`]
//! matches every variant of [`ErrorCode`], so adding a code without adding a
//! fault fails to compile.
//!
//! [`run_all`] walks [`ErrorCode::ALL`]: it injects the fault, checks that the
//! injected error carries the exact code, confirms the playbook and remediation
//! agree, and, for fault fixtures that map to a doctor check, runs that check
//! against an isolated context and confirms it reports a problem. The done
//! criterion is `report.exercised == ErrorCode::ALL.len()` with no missing,
//! mismatched, or failed entries.
//!
//! File fixtures live under a unique scratch directory in the system temp
//! directory. The suite never writes into the caller's [`DoctorContext::root`],
//! so [`diagnose_faults`] is safe to run against a real installation snapshot.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zero_types::{ErrorCode, ZeroError};

use crate::playbook;
use crate::{
    check_auth, check_config, check_disk, check_journals, check_keys, check_locks, check_ports,
    check_workers, CheckResult, CheckStatus, CredentialBackend, DiskSnapshot, DoctorContext,
    FileSnapshot, LockEntry, LocksSnapshot, PortsSnapshot,
};

/// The realistic path that produces a fault.
///
/// Eight fixtures map one-to-one onto a doctor check. Every other code uses
/// [`FaultFixture::Unknown`]: the fault is still injected and triaged, but no
/// dedicated check fixture exists for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FaultFixture {
    /// A malformed config file; exercises the `config` check (`ConfigInvalid`).
    MessyConfig,
    /// An absent project key; exercises the `keys` check (`NotFound`).
    MissingKey,
    /// A lock older than its threshold; exercises the `locks` check (`Locked`).
    StaleLock,
    /// A journal with an unparseable JSONL line; exercises `journals`
    /// (`SessionCorrupt`).
    CorruptJournal,
    /// Free space below the failure floor; exercises `disk`
    /// (`ResourceExhausted`).
    DiskLow,
    /// An expected port that is not listening; exercises `ports` (`Io`).
    PortBusy,
    /// A malformed workers journal; exercises `workers` (`Serialization`).
    BrokenJournal,
    /// No usable credential backend; exercises `auth` (`ProviderAuth`).
    AuthExpired,
    /// A code without a dedicated fixture. `true` keeps the generic injection
    /// enabled; `false` disables it so the suite reports the code as missing.
    Unknown(bool),
}

impl FaultFixture {
    /// Whether this fixture is injected by the suite.
    ///
    /// Every catalogue entry is enabled. A deliberately disabled
    /// `Unknown(false)` makes [`run_all`] list its code in
    /// [`FaultReport::missing`] instead of silently passing.
    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::Unknown(false))
    }

    /// The doctor check this fixture drives, when one exists.
    pub const fn doctor_check(self) -> Option<&'static str> {
        match self {
            Self::MessyConfig => Some("config"),
            Self::MissingKey => Some("keys"),
            Self::StaleLock => Some("locks"),
            Self::CorruptJournal => Some("journals"),
            Self::DiskLow => Some("disk"),
            Self::PortBusy => Some("ports"),
            Self::BrokenJournal => Some("workers"),
            Self::AuthExpired => Some("auth"),
            Self::Unknown(_) => None,
        }
    }

    /// Stable label used in reports. Safe to show: no paths or values.
    pub const fn label(self) -> &'static str {
        match self {
            Self::MessyConfig => "messy-config",
            Self::MissingKey => "missing-key",
            Self::StaleLock => "stale-lock",
            Self::CorruptJournal => "corrupt-journal",
            Self::DiskLow => "disk-low",
            Self::PortBusy => "port-busy",
            Self::BrokenJournal => "broken-journal",
            Self::AuthExpired => "auth-expired",
            Self::Unknown(_) => "generic",
        }
    }
}

/// One injectable fault.
///
/// `id` is the stable wire code, so fault ids are unique exactly when error
/// codes are unique. `description` is short, redaction-safe prose; `fixture`
/// records how the error is produced through a realistic path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    pub id: &'static str,
    pub code: ErrorCode,
    pub description: &'static str,
    pub fixture: FaultFixture,
}

macro_rules! catalogue {
    ($( $variant:ident => $fixture:expr, $description:literal; )*) => {
        $(
            #[allow(non_upper_case_globals)]
            const $variant: Fault = Fault {
                id: ErrorCode::$variant.as_str(),
                code: ErrorCode::$variant,
                description: $description,
                fixture: $fixture,
            };
        )*

        /// The fault for one stable code.
        ///
        /// Exhaustive: a new [`ErrorCode`] variant without a fault fails to
        /// compile here.
        pub fn fault_for(code: ErrorCode) -> &'static Fault {
            match code {
                $( ErrorCode::$variant => &$variant, )*
            }
        }

        /// Every fault, in [`ErrorCode::ALL`] order.
        pub fn all() -> &'static [Fault] {
            &[ $( $variant ),* ]
        }
    };
}

catalogue! {
    // -----------------------------------------------------------------------
    // Foundations
    // -----------------------------------------------------------------------
    Internal => FaultFixture::Unknown(true), "unexpected internal error";
    InvalidInput => FaultFixture::Unknown(true), "input rejected as invalid";
    NotFound => FaultFixture::MissingKey, "project key is missing";
    AlreadyExists => FaultFixture::Unknown(true), "name is already taken";
    PermissionDenied => FaultFixture::Unknown(true), "permission denied on a path";
    Io => FaultFixture::PortBusy, "expected port is not listening";
    Serialization => FaultFixture::BrokenJournal, "workers journal is malformed";
    SchemaVersion => FaultFixture::Unknown(true), "stored schema does not match this build";
    MigrationFailed => FaultFixture::Unknown(true), "migration aborted part-way";
    ConfigInvalid => FaultFixture::MessyConfig, "configuration file is malformed";
    LimitExceeded => FaultFixture::Unknown(true), "a configured limit was reached";
    ResourceExhausted => FaultFixture::DiskLow, "free disk space is below the safe threshold";
    Offline => FaultFixture::Unknown(true), "network operation attempted while offline";
    Unavailable => FaultFixture::Unknown(true), "required feature or prerequisite is missing";
    Cancelled => FaultFixture::Unknown(true), "operation was cancelled";
    Timeout => FaultFixture::Unknown(true), "operation exceeded its deadline";
    Unsupported => FaultFixture::Unknown(true), "unsupported platform or option";
    Corrupt => FaultFixture::Unknown(true), "stored state is corrupt";

    // -----------------------------------------------------------------------
    // Sessions
    // -----------------------------------------------------------------------
    SessionNotFound => FaultFixture::Unknown(true), "session id does not exist";
    SessionClosed => FaultFixture::Unknown(true), "session is closed";
    SessionLeaseHeld => FaultFixture::Unknown(true), "another worker holds the session lease";
    SessionCorrupt => FaultFixture::CorruptJournal, "journal has an unparseable record";
    ForkFailed => FaultFixture::Unknown(true), "fork from a session entry failed";
    CompactionFailed => FaultFixture::Unknown(true), "context compaction failed";
    SummaryInvalid => FaultFixture::Unknown(true), "branch summary is missing a section";
    ContextTooLarge => FaultFixture::Unknown(true), "context exceeds the size cap";
    AttachCursorExpired => FaultFixture::Unknown(true), "attach cursor is from an older generation";
    CommandUncertain => FaultFixture::Unknown(true), "side effect outcome is unknown";
    ImportIncompatible => FaultFixture::Unknown(true), "imported bundle is not compatible";

    // -----------------------------------------------------------------------
    // Providers
    // -----------------------------------------------------------------------
    ProviderUnavailable => FaultFixture::Unknown(true), "provider endpoint is unreachable";
    ProviderAuth => FaultFixture::AuthExpired, "provider credential expired";
    ProviderRateLimited => FaultFixture::Unknown(true), "provider rate limit reached";
    ProviderOverloaded => FaultFixture::Unknown(true), "provider is overloaded";
    ProviderBadRequest => FaultFixture::Unknown(true), "provider rejected the request parameters";
    ProviderContextLength => FaultFixture::Unknown(true), "prompt exceeds the model context window";
    ProviderContentFilter => FaultFixture::Unknown(true), "provider blocked the content";
    ProviderStreamBroken => FaultFixture::Unknown(true), "provider stream ended mid-response";
    ProviderProtocol => FaultFixture::Unknown(true), "provider response shape changed";
    ProviderTimeout => FaultFixture::Unknown(true), "provider call exceeded the timeout";
    ProviderNoTools => FaultFixture::Unknown(true), "model does not support tool calls";

    // -----------------------------------------------------------------------
    // Queue and steering
    // -----------------------------------------------------------------------
    QueueFull => FaultFixture::Unknown(true), "message queue is full";
    QueueItemMissing => FaultFixture::Unknown(true), "queued item no longer exists";
    SteerTooLate => FaultFixture::Unknown(true), "steering arrived after the turn committed";

    // -----------------------------------------------------------------------
    // Auto-resume
    // -----------------------------------------------------------------------
    ResumeRefused => FaultFixture::Unknown(true), "automatic resume refused";
    ResumeBudget => FaultFixture::Unknown(true), "auto-resume budget exhausted";

    // -----------------------------------------------------------------------
    // Artifacts and export
    // -----------------------------------------------------------------------
    ArtifactMissing => FaultFixture::Unknown(true), "referenced artifact is missing";
    ExportFailed => FaultFixture::Unknown(true), "export did not complete";

    // -----------------------------------------------------------------------
    // Policy
    // -----------------------------------------------------------------------
    PolicyDenied => FaultFixture::Unknown(true), "policy denied the action";
    PolicyAskRequired => FaultFixture::Unknown(true), "action needs explicit approval";
    ApprovalExpired => FaultFixture::Unknown(true), "approval prompt expired";
    ApprovalResolved => FaultFixture::Unknown(true), "approval was decided elsewhere";
    SelfEscalation => FaultFixture::Unknown(true), "agent attempted to raise its own authority";
    RegulatorUnavailable => FaultFixture::Unknown(true), "policy regulator is unavailable";
    InvalidTransition => FaultFixture::Unknown(true), "state transition is not allowed";
    RuleViolation => FaultFixture::Unknown(true), "action violates a declared rule";
    ProtectedPath => FaultFixture::Unknown(true), "path is protected from agent writes";

    // -----------------------------------------------------------------------
    // Deletion safety
    // -----------------------------------------------------------------------
    DeletionBlocked => FaultFixture::Unknown(true), "permanent deletion is blocked";
    TrashFailed => FaultFixture::Unknown(true), "moving to trash failed";
    SnapshotMissing => FaultFixture::Unknown(true), "no snapshot exists for the overwrite";
    PurgeDenied => FaultFixture::Unknown(true), "permanent purge needs human confirmation";
    RetentionScope => FaultFixture::Unknown(true), "garbage collection refused outside the data root";

    // -----------------------------------------------------------------------
    // File manager and edit tool
    // -----------------------------------------------------------------------
    Stale => FaultFixture::Unknown(true), "file changed outside the session";
    Locked => FaultFixture::StaleLock, "file is locked by another holder";
    BatchFailed => FaultFixture::Unknown(true), "batch operation rolled back";
    Conflict => FaultFixture::Unknown(true), "write conflict detected";
    AnchorDrift => FaultFixture::Unknown(true), "edit anchor no longer matches";
    TooLarge => FaultFixture::Unknown(true), "edit range exceeds the size limit";
    TodoConfirmation => FaultFixture::Unknown(true), "user-created todo needs confirmation";

    // -----------------------------------------------------------------------
    // Locks and scheduling
    // -----------------------------------------------------------------------
    PoolMaxima => FaultFixture::Unknown(true), "worker exceeded its pool maximum";
    UnsafePreemption => FaultFixture::Unknown(true), "preemption attempted at an unsafe point";
    NoQuorum => FaultFixture::Unknown(true), "cluster partition has no quorum";

    // -----------------------------------------------------------------------
    // Trust and audit
    // -----------------------------------------------------------------------
    TrustRequired => FaultFixture::Unknown(true), "project must be trusted before use";
    Untrusted => FaultFixture::Unknown(true), "project configuration is untrusted";
    AuditBroken => FaultFixture::Unknown(true), "audit chain failed verification";
    TamperDetected => FaultFixture::Unknown(true), "audit chain does not match its record";
}

/// Produce the error for one fault with a short, fixture-appropriate message.
///
/// The message is fixed text: no key bytes, tokens, paths, or config values.
pub fn inject(fault: &Fault) -> ZeroError {
    let detail = match fault.fixture {
        FaultFixture::MessyConfig => "config file is malformed at line 1",
        FaultFixture::MissingKey => "project key is missing",
        FaultFixture::StaleLock => "lock file is older than its threshold",
        FaultFixture::CorruptJournal => "journal has an unparseable record",
        FaultFixture::DiskLow => "free space is 512 MiB, below 1 GiB",
        FaultFixture::PortBusy => "expected port 7100 is not listening",
        FaultFixture::BrokenJournal => "workers journal is malformed",
        FaultFixture::AuthExpired => "provider credential is unavailable or expired",
        FaultFixture::Unknown(_) => fault.description,
    };
    ZeroError::new(fault.code, format!("injected fault {}: {detail}", fault.id))
}

/// One fault that could not be exercised, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultFailure {
    pub id: &'static str,
    pub code: ErrorCode,
    pub reason: String,
}

/// The result of one fault-suite run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FaultReport {
    /// Codes whose injection, playbook, and fixture check all passed.
    pub exercised: usize,
    /// Codes reported missing, such as a deliberately disabled fixture.
    pub missing: Vec<String>,
    /// Codes whose injected error or catalogue entry carried a different code.
    pub mismatched: Vec<String>,
    /// Codes that injected correctly but failed a playbook or fixture assertion.
    pub failures: Vec<FaultFailure>,
}

impl FaultReport {
    /// The number of stable codes the suite must exercise.
    pub fn total(&self) -> usize {
        ErrorCode::ALL.len()
    }

    /// True when every code was exercised with no missing, mismatched, or
    /// failed entries.
    pub fn is_complete(&self) -> bool {
        self.exercised == ErrorCode::ALL.len()
            && self.missing.is_empty()
            && self.mismatched.is_empty()
            && self.failures.is_empty()
    }
}

/// Typed error returned by [`assert_all_codes_exercised`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultSuiteError {
    pub exercised: usize,
    pub total: usize,
    pub missing: Vec<String>,
    pub mismatched: Vec<String>,
    pub failures: Vec<String>,
}

impl FaultSuiteError {
    fn from_report(report: &FaultReport) -> Self {
        Self {
            exercised: report.exercised,
            total: report.total(),
            missing: report.missing.clone(),
            mismatched: report.mismatched.clone(),
            failures: report
                .failures
                .iter()
                .map(|failure| {
                    format!(
                        "{} ({}): {}",
                        failure.id,
                        failure.code.as_str(),
                        failure.reason
                    )
                })
                .collect(),
        }
    }
}

impl fmt::Display for FaultSuiteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fault suite incomplete: {}/{} codes exercised",
            self.exercised, self.total
        )?;
        if !self.missing.is_empty() {
            write!(f, "; missing: {}", self.missing.join(", "))?;
        }
        if !self.mismatched.is_empty() {
            write!(f, "; mismatched: {}", self.mismatched.join(", "))?;
        }
        if !self.failures.is_empty() {
            write!(f, "; failures: {}", self.failures.join("; "))?;
        }
        Ok(())
    }
}

impl std::error::Error for FaultSuiteError {}

/// Run every fault in the catalogue against an optional base context.
///
/// `ctx` supplies realistic non-fixture inputs (versions, kernel, network);
/// every fixture overrides only the fields it needs. File fixtures are written
/// under a unique scratch directory in the system temp directory, never under
/// `ctx.root`.
pub fn run_all(ctx: Option<&DoctorContext>) -> FaultReport {
    let base = match ctx {
        Some(ctx) => ctx.clone(),
        None => DoctorContext::default(),
    };
    let scratch = ScratchDir::create();
    let mut report = FaultReport::default();

    for code in ErrorCode::ALL {
        let fault = fault_for(*code);

        if !fault.fixture.is_enabled() {
            report.missing.push(code.as_str().to_string());
            continue;
        }
        if fault.code != *code {
            report.mismatched.push(code.as_str().to_string());
            continue;
        }

        let injected = inject(fault);
        if injected.code() != *code {
            report.mismatched.push(code.as_str().to_string());
            continue;
        }

        let mut passed = true;
        let book = playbook::playbook(*code);
        if book.code != *code {
            report.failures.push(FaultFailure {
                id: fault.id,
                code: *code,
                reason: format!(
                    "playbook carries {} instead of {}",
                    book.code.as_str(),
                    code.as_str()
                ),
            });
            passed = false;
        }
        let triaged = playbook::triage(&injected);
        if triaged.code != *code {
            report.failures.push(FaultFailure {
                id: fault.id,
                code: *code,
                reason: format!(
                    "triage selected {} instead of {}",
                    triaged.code.as_str(),
                    code.as_str()
                ),
            });
            passed = false;
        }
        if book.remediation != code.remediation() || triaged.remediation != code.remediation() {
            report.failures.push(FaultFailure {
                id: fault.id,
                code: *code,
                reason: "playbook remediation does not match the stable code line".to_string(),
            });
            passed = false;
        }

        if let Some(scratch) = scratch.as_ref() {
            if let Err(reason) = exercise_fixture(&base, scratch.path(), fault) {
                report.failures.push(FaultFailure {
                    id: fault.id,
                    code: *code,
                    reason,
                });
                passed = false;
            }
        } else if fault.fixture.doctor_check().is_some() {
            report.failures.push(FaultFailure {
                id: fault.id,
                code: *code,
                reason: "fixture scratch directory could not be created".to_string(),
            });
            passed = false;
        }

        if passed {
            report.exercised += 1;
        }
    }

    report
}

/// Run the fault suite with the default doctor context.
///
/// The done criterion for TST-06 is `report.exercised == ErrorCode::ALL.len()`.
pub fn diagnose_faults(ctx: &DoctorContext) -> FaultReport {
    run_all(Some(ctx))
}

/// Run the suite and turn any shortfall into a typed error.
///
/// The error lists every missing, mismatched, or failed code so a caller can
/// report exactly which fault injection is broken.
pub fn assert_all_codes_exercised() -> Result<FaultReport, FaultSuiteError> {
    let report = run_all(None);
    if report.is_complete() {
        Ok(report)
    } else {
        Err(FaultSuiteError::from_report(&report))
    }
}

/// Build the context for one fixture and run its doctor check.
fn exercise_fixture(base: &DoctorContext, scratch: &Path, fault: &Fault) -> Result<(), String> {
    let Some((check_name, ctx)) = fixture_context(base, scratch, fault.fixture)? else {
        return Ok(());
    };
    // The fixture proves the error is reachable through the named check. The
    // agent gate's `check_code` mapping is separate: most fixtures agree with
    // it, but a malformed workers journal yields `Serialization` while the gate
    // maps `workers` to `Unavailable`.
    let result = run_check(&ctx, check_name)
        .ok_or_else(|| format!("no doctor check is wired for `{check_name}`"))?;
    if result.status == CheckStatus::Ok {
        return Err(format!(
            "`{check_name}` passed for the {} fixture",
            fault.fixture.label()
        ));
    }
    if result.detail.trim().is_empty() {
        return Err(format!("`{check_name}` reported no detail"));
    }
    Ok(())
}

fn run_check(ctx: &DoctorContext, name: &str) -> Option<CheckResult> {
    Some(match name {
        "config" => check_config(ctx),
        "keys" => check_keys(ctx),
        "workers" => check_workers(ctx),
        "auth" => check_auth(ctx),
        "ports" => check_ports(ctx),
        "disk" => check_disk(ctx),
        "locks" => check_locks(ctx),
        "journals" => check_journals(ctx),
        _ => return None,
    })
}

fn fixture_context(
    base: &DoctorContext,
    scratch: &Path,
    fixture: FaultFixture,
) -> Result<Option<(&'static str, DoctorContext)>, String> {
    let mut ctx = base.clone();
    let check = match fixture {
        FaultFixture::MessyConfig => {
            ctx.config = FileSnapshot::with_text(
                scratch.join("config.toml"),
                "[core\nbroken = \"unterminated\n",
            );
            "config"
        }
        FaultFixture::MissingKey => {
            ctx.project_key_path = scratch.join("missing-key");
            "keys"
        }
        FaultFixture::StaleLock => {
            let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
            ctx.locks = LocksSnapshot {
                entries: vec![LockEntry {
                    path: scratch.join("stale.lock"),
                    modified: Some(now - Duration::from_secs(2 * 60 * 60)),
                }],
                stale_after: Duration::from_secs(60 * 60),
                now,
            };
            "locks"
        }
        FaultFixture::CorruptJournal => {
            let path = scratch.join("journals").join("corrupt.jsonl");
            let parent = path
                .parent()
                .ok_or_else(|| "journal fixture path has no parent".to_string())?;
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create journal fixture directory: {error}"))?;
            std::fs::write(&path, "{\"turn\":1}\nnot-json\n")
                .map_err(|error| format!("cannot write journal fixture: {error}"))?;
            ctx.journals = vec![path];
            "journals"
        }
        FaultFixture::DiskLow => {
            ctx.disk = Some(DiskSnapshot {
                free_bytes: 512 * 1024 * 1024,
                total_bytes: 100 * 1024 * 1024 * 1024,
            });
            "disk"
        }
        FaultFixture::PortBusy => {
            ctx.ports = PortsSnapshot {
                expected: vec![7100],
                listening: Vec::new(),
            };
            "ports"
        }
        FaultFixture::BrokenJournal => {
            ctx.workers_journal = FileSnapshot::with_text(scratch.join("workers.json"), "not json");
            "workers"
        }
        FaultFixture::AuthExpired => {
            ctx.credential_backend = CredentialBackend::Unavailable;
            "auth"
        }
        FaultFixture::Unknown(_) => return Ok(None),
    };
    Ok(Some((check, ctx)))
}

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

/// A unique scratch directory that removes itself on drop.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn create() -> Option<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "zero-doctor-faults-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        match std::fs::create_dir_all(&path) {
            Ok(()) => Some(Self { path }),
            Err(_) => None,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn every_error_code_has_exactly_one_fault() {
        let faults = all();
        assert_eq!(faults.len(), ErrorCode::ALL.len(), "one fault per code");

        let mut by_code: BTreeMap<ErrorCode, &Fault> = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for fault in faults {
            assert!(ids.insert(fault.id), "duplicate fault id {}", fault.id);
            assert_eq!(
                fault.id,
                fault.code.as_str(),
                "fault id must be the stable code"
            );
            assert!(
                by_code.insert(fault.code, fault).is_none(),
                "duplicate fault for {}",
                fault.code.as_str()
            );
        }

        for code in ErrorCode::ALL {
            let fault = by_code
                .get(code)
                .unwrap_or_else(|| panic!("no fault for {}", code.as_str()));
            assert_eq!(*fault, fault_for(*code), "lookup returned another fault");
            assert_eq!(fault_for(*code).code, *code);
            assert!(
                !fault.description.trim().is_empty(),
                "{} has no description",
                code.as_str()
            );

            let book = playbook::playbook(*code);
            assert_eq!(book.code, *code);
            assert_eq!(book.remediation, code.remediation());
            assert!(
                !book.remediation.trim().is_empty(),
                "{} has no remediation",
                code.as_str()
            );
        }
        assert_eq!(by_code.len(), ErrorCode::ALL.len());
    }

    #[test]
    fn injection_is_deterministic_and_carries_the_exact_code() {
        for code in ErrorCode::ALL {
            let first = inject(fault_for(*code));
            let second = inject(fault_for(*code));
            assert_eq!(
                first,
                second,
                "{} injection is not deterministic",
                code.as_str()
            );
            assert_eq!(
                first.code(),
                *code,
                "{} injected the wrong code",
                code.as_str()
            );
            assert_eq!(first.remediation(), code.remediation());

            let message = first.message();
            assert!(
                !message.trim().is_empty(),
                "{} has an empty message",
                code.as_str()
            );
            assert!(
                message.chars().count() <= 160,
                "{} message is too long: {message:?}",
                code.as_str()
            );
            assert!(
                !message.contains('\n'),
                "{} message has a newline",
                code.as_str()
            );
            for needle in ["TOPSECRET", "sk-", "ghp_", "bearer ", "password="] {
                assert!(
                    !message.contains(needle),
                    "{} message looks secret-bearing: {message:?}",
                    code.as_str()
                );
            }
        }
    }

    #[test]
    fn suite_exercises_every_error_code() {
        let report = run_all(None);
        assert_eq!(
            report.exercised,
            ErrorCode::ALL.len(),
            "only {}/{} codes exercised: {report:?}",
            report.exercised,
            ErrorCode::ALL.len()
        );
        assert!(report.missing.is_empty(), "missing: {report:?}");
        assert!(report.mismatched.is_empty(), "mismatched: {report:?}");
        assert!(report.failures.is_empty(), "failures: {report:?}");
        assert!(report.is_complete());

        let report = assert_all_codes_exercised().expect("every code must be exercised");
        assert_eq!(report.exercised, ErrorCode::ALL.len());
    }

    #[test]
    fn diagnose_faults_uses_a_tempdir_context_without_writing_into_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ctx = DoctorContext::from_root(dir.path());
        let report = diagnose_faults(&ctx);
        assert_eq!(report.exercised, ErrorCode::ALL.len(), "{report:?}");
        assert!(report.failures.is_empty(), "{report:?}");
        assert!(
            std::fs::read_dir(dir.path())
                .expect("read tempdir")
                .next()
                .is_none(),
            "the fault suite wrote into the caller's root"
        );
    }

    #[test]
    fn fixture_faults_drive_a_failing_doctor_check() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = DoctorContext::from_root(dir.path());
        let scratch = ScratchDir::create().expect("scratch directory");

        let mut bound = BTreeSet::new();
        for fault in all() {
            let Some(check) = fault.fixture.doctor_check() else {
                continue;
            };
            assert!(
                bound.insert(fault.fixture),
                "{} fixtures map to more than one check",
                fault.id
            );
            assert!(
                crate::CHECK_NAMES.contains(&check),
                "{} names unknown check `{check}`",
                fault.id
            );
            exercise_fixture(&base, scratch.path(), fault)
                .unwrap_or_else(|reason| panic!("{} fixture failed: {reason}", fault.id));
        }
        assert_eq!(bound.len(), 8, "expected eight fixture-bound checks");
    }
}
