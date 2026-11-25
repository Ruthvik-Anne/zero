//! Zero integration for security review (SR-08, SR-15, SR-16).
//!
//! A review run is a local artifact, never a network operation. Each run writes
//! the canonical five-file report set under `.zero/audits/run-N/` and seeds one
//! task per ledger unit into the project's zero-tasks store. The task store is
//! the only integration point with the task panel: a unit is visible exactly
//! when its task carries the run's plan id.
//!
//! Project configuration is inert. A project may not lower the evidence bar,
//! pick a shallower profile, or skip a phase (SR-16); only the caller's profile
//! is ever used.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zero_review::ledger::validate as validate_ledger;
use zero_review::report::{assert_consistent, derive, BudgetReport, ReportBundle, ReportInputs};
use zero_review::schema::{validate_findings, validate_refs};
use zero_review::{
    CoverageLedger, Findings, LedgerUnit, Phase, ReviewProfile, FINDINGS_DETAIL_FILE, FINDINGS_FILE,
    LEDGER_FILE, NEEDS_VALIDATION_FILE, REPORT_FILE,
};
use zero_tasks::{PlanTask, Task, TaskLimits, TaskState, TaskStore};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Project metadata directory.
pub const ZERO_DIR: &str = ".zero";
/// Audit artifact directory name below `.zero`.
pub const AUDITS_DIR_NAME: &str = "audits";
/// Run directory prefix. Only `<prefix><digits>` names participate in numbering.
pub const RUN_PREFIX: &str = "run-";
/// Project task journal. Kept beside the layout files so the panel and the audit
/// share one store.
pub const TASK_STORE_FILE: &str = "tasks.jsonl";
/// Optional project audit configuration. Never allowed to relax the run.
pub const PROJECT_PROFILE_FILE: &str = "audit-profile.json";
/// The task-store text used for a fresh unit task, before any claim.
pub const TASK_STATUS_PENDING: &str = "pending";
/// Canonical refs required by the SR-05 evidence bar. A project cannot lower it.
pub const MIN_EVIDENCE_REFS: usize = 1;
/// Bound on the run-number scan.
pub const MAX_RUN_SCAN: usize = 100_000;
/// The canonical report set. All five must exist before a run is published.
pub const RUN_FILES: [&str; 5] = [
    LEDGER_FILE,
    FINDINGS_FILE,
    REPORT_FILE,
    FINDINGS_DETAIL_FILE,
    NEEDS_VALIDATION_FILE,
];

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

/// One published audit run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRun {
    /// `run-<n>`.
    pub run_id: String,
    /// Absolute path of the published run directory.
    pub dir: PathBuf,
    /// Task ids created (or reused) for this run, in ledger order.
    pub task_ids: Vec<String>,
    /// Ledger unit ids, in ledger order.
    pub units: Vec<String>,
}

/// Structured metadata carried by an audit task title.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskMetadata {
    pub audit_run: String,
    pub unit_id: String,
    pub fingerprint: String,
    pub status: String,
    pub surface: String,
    pub boundary: String,
    pub subsystem: String,
    pub attack_class: String,
    pub refs: Vec<String>,
}

/// One row of the task panel for a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelEntry {
    pub task_id: String,
    pub state: TaskState,
    pub metadata: TaskMetadata,
}

/// A project-supplied audit request. Every field is optional and none of them
/// is applied; the type exists so relaxation attempts can be named and refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectAuditProfile {
    #[serde(default)]
    pub profile: Option<ReviewProfile>,
    #[serde(default)]
    pub phases: Option<Vec<Phase>>,
    #[serde(default)]
    pub min_evidence_refs: Option<usize>,
}

/// The profile a run actually uses. Project configuration may be seen, but it
/// is never effective.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveProfile {
    pub profile: ReviewProfile,
    pub phases: Vec<Phase>,
    pub min_evidence_refs: usize,
    /// True when a project profile file was present. Its requests are ignored.
    pub project_profile_ignored: bool,
    /// Human-readable descriptions of the project requests that were ignored.
    pub ignored: Vec<String>,
}

// ---------------------------------------------------------------------------
// Project root and run paths
// ---------------------------------------------------------------------------

fn canonical_project_root(project_root: &Path) -> Result<PathBuf> {
    let root = project_root.canonicalize().map_err(|_| {
        invalid(format!(
            "project root `{}` does not exist",
            project_root.display()
        ))
    })?;
    if !root.is_dir() {
        return Err(invalid(format!(
            "project root `{}` is not a directory",
            root.display()
        )));
    }
    let zero = root.join(ZERO_DIR);
    if !zero.is_dir() {
        return Err(invalid(format!(
            "`{}` is not a project root: `{ZERO_DIR}` is missing",
            root.display()
        )));
    }
    let canonical_zero = zero.canonicalize()?;
    if !canonical_zero.starts_with(&root) {
        return Err(denied(format!(
            "`{ZERO_DIR}` under `{}` escapes the project root",
            root.display()
        )));
    }
    Ok(root)
}

fn check_audits_dir(audits: &Path, canonical_zero: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(audits)?;
    if metadata.file_type().is_symlink() {
        return Err(denied(format!(
            "audits path `{}` is a symlink; refusing to follow it",
            audits.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(invalid(format!(
            "audits path `{}` is not a directory",
            audits.display()
        )));
    }
    let resolved = audits.canonicalize()?;
    if !resolved.starts_with(canonical_zero) {
        return Err(denied(format!(
            "audits path `{}` escapes `{ZERO_DIR}`",
            audits.display()
        )));
    }
    Ok(())
}

/// Resolve `.zero/audits`, creating it when requested. A symlink anywhere on
/// that path that leaves `.zero` is refused before anything is written.
fn resolve_audits_dir(root: &Path, create: bool) -> Result<PathBuf> {
    let zero = root.join(ZERO_DIR);
    let canonical_zero = zero.canonicalize()?;
    let audits = zero.join(AUDITS_DIR_NAME);
    match std::fs::symlink_metadata(&audits) {
        Ok(_) => check_audits_dir(&audits, &canonical_zero)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Ok(audits);
            }
            std::fs::create_dir_all(&audits)?;
            // Re-check after creation so a racing symlink cannot slip in.
            check_audits_dir(&audits, &canonical_zero)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(audits)
}

/// Next free run number. Only directories named `run-<digits>` count; anything
/// else, including traversal-shaped names, is ignored. The scan is bounded.
fn next_run_number(audits: &Path) -> Result<u64> {
    let mut max = 0u64;
    let mut seen = 0usize;
    for entry in std::fs::read_dir(audits)? {
        seen += 1;
        if seen > MAX_RUN_SCAN {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "audits directory `{}` has more than {MAX_RUN_SCAN} entries",
                    audits.display()
                ),
            ));
        }
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(digits) = name.strip_prefix(RUN_PREFIX) else {
            continue;
        };
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        if let Ok(number) = digits.parse::<u64>() {
            max = max.max(number);
        }
    }
    Ok(max.saturating_add(1).max(1))
}

// ---------------------------------------------------------------------------
// Profile immutability (SR-16)
// ---------------------------------------------------------------------------

/// Check a project-supplied request against the caller's explicit profile.
///
/// A project may not pick a shallower profile, remove a phase, or lower the
/// evidence bar. Stronger requests are accepted but never applied: the returned
/// [`EffectiveProfile`] is always the caller's.
pub fn check_profile(
    caller: ReviewProfile,
    project: Option<&ProjectAuditProfile>,
) -> Result<EffectiveProfile> {
    let phases = caller.phases().to_vec();
    let mut ignored = Vec::new();
    if let Some(project) = project {
        if let Some(profile) = project.profile {
            if profile < caller {
                return Err(denied(format!(
                    "project audit profile `{}` is below the caller's `{}`; the evidence bar and phases cannot be relaxed",
                    profile.as_str(),
                    caller.as_str()
                )));
            }
            ignored.push(format!("profile `{}`", profile.as_str()));
        }
        if let Some(requested) = &project.phases {
            let mut unique: BTreeSet<Phase> = BTreeSet::new();
            for phase in requested {
                if !unique.insert(*phase) {
                    return Err(invalid(format!(
                        "project audit profile lists the `{}` phase twice",
                        phase.as_str()
                    )));
                }
            }
            if let Some(missing) = phases.iter().find(|phase| !unique.contains(phase)) {
                return Err(denied(format!(
                    "project audit profile skips the `{}` phase; phases cannot be skipped",
                    missing.as_str()
                )));
            }
            ignored.push("phases".to_string());
        }
        if let Some(min) = project.min_evidence_refs {
            if min < MIN_EVIDENCE_REFS {
                return Err(denied(format!(
                    "project audit profile lowers the evidence bar to {min}; at least {MIN_EVIDENCE_REFS} canonical ref(s) are required"
                )));
            }
            ignored.push(format!("min_evidence_refs {min}"));
        }
    }
    Ok(EffectiveProfile {
        profile: caller,
        phases,
        min_evidence_refs: MIN_EVIDENCE_REFS,
        project_profile_ignored: project.is_some(),
        ignored,
    })
}

fn load_project_profile(root: &Path) -> Result<Option<ProjectAuditProfile>> {
    let path = root.join(ZERO_DIR).join(PROJECT_PROFILE_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).map(Some).map_err(|error| {
            ZeroError::new(
                ErrorCode::ConfigInvalid,
                format!("`{}` is not a valid audit profile: {error}", path.display()),
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

// ---------------------------------------------------------------------------
// Report publication
// ---------------------------------------------------------------------------

fn publish_report(
    root: &Path,
    audits: &Path,
    ledger: &CoverageLedger,
    findings: &Findings,
    budget: &BudgetReport,
    profile: ReviewProfile,
    now_ms: i64,
) -> Result<(String, PathBuf)> {
    for _ in 0..8 {
        let number = next_run_number(audits)?;
        let run_id = format!("{RUN_PREFIX}{number}");
        let staging = audits.join(format!(
            ".staging-{run_id}-{}-{}",
            std::process::id(),
            STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&staging);

        let inputs = ReportInputs {
            ledger: ledger.clone(),
            findings: findings.clone(),
            budget: budget.clone(),
            profile,
            run_id: run_id.clone(),
            created_at_ms: now_ms,
        };
        let bundle = match derive(inputs, &staging) {
            Ok(bundle) => bundle,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(error);
            }
        };
        if let Err(error) = verify_published(&staging, root, ledger, &bundle) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(error);
        }

        let dir = audits.join(&run_id);
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&staging);
            continue;
        }
        match std::fs::rename(&staging, &dir) {
            Ok(()) => return Ok((run_id, dir)),
            Err(error) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(error.into());
            }
        }
    }
    Err(ZeroError::new(
        ErrorCode::Conflict,
        "could not claim a run directory after eight attempts",
    ))
}

/// Re-read the staged copies and prove that the published records are valid and
/// that the prose agrees with them before the directory is renamed.
fn verify_published(
    dir: &Path,
    root: &Path,
    ledger: &CoverageLedger,
    bundle: &ReportBundle,
) -> Result<()> {
    for name in RUN_FILES {
        if !dir.join(name).is_file() {
            return Err(invalid(format!(
                "staged run `{}` is missing `{name}`",
                dir.display()
            )));
        }
    }
    let findings_text = std::fs::read_to_string(dir.join(FINDINGS_FILE))?;
    let findings_value: serde_json::Value = serde_json::from_str(&findings_text)?;
    zero_review::schema::validate_findings_json_with_ledger(&findings_value, ledger)?;
    let ledger_text = std::fs::read_to_string(dir.join(LEDGER_FILE))?;
    let ledger_value: serde_json::Value = serde_json::from_str(&ledger_text)?;
    zero_review::schema::validate_coverage_ledger_json(&ledger_value, Some(root))?;
    assert_consistent(bundle)
}

// ---------------------------------------------------------------------------
// Tasks and the panel
// ---------------------------------------------------------------------------

/// The task journal the panel and audit share.
pub fn task_store_path(project_root: &Path) -> PathBuf {
    project_root.join(ZERO_DIR).join(TASK_STORE_FILE)
}

/// Open (or create) the project task store.
pub fn open_project_task_store(project_root: &Path) -> Result<TaskStore> {
    TaskStore::open(task_store_path(project_root), TaskLimits::default())
}

fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .replace(" :: ", " / ")
        .trim()
        .to_string()
}

/// Task title: the one text field zero-tasks exposes. It carries every unit
/// fact the panel needs plus machine-readable metadata for [`task_metadata`].
pub fn task_title_for_unit(run_id: &str, unit: &LedgerUnit) -> String {
    let refs = serde_json::to_string(&unit.refs).unwrap_or_else(|_| "[]".to_string());
    format!(
        "AUDIT :: run={} :: unit={} :: fp={} :: surface={} :: boundary={} :: subsystem={} :: class={} :: status={} :: refs={refs}",
        clean(run_id),
        clean(&unit.id),
        clean(&unit.fingerprint),
        clean(&unit.surface),
        clean(&unit.boundary),
        clean(&unit.subsystem),
        clean(&unit.attack_class),
        TASK_STATUS_PENDING,
    )
}

/// Parse the metadata carried by a task title.
pub fn task_metadata(task: &Task) -> Option<TaskMetadata> {
    let mut parts = task.title.split(" :: ");
    if parts.next()? != "AUDIT" {
        return None;
    }
    let mut run = None;
    let mut unit = None;
    let mut fingerprint = None;
    let mut surface = None;
    let mut boundary = None;
    let mut subsystem = None;
    let mut attack_class = None;
    let mut status = None;
    let mut refs = Vec::new();
    for part in parts {
        let (key, value) = part.split_once('=')?;
        match key {
            "run" => run = Some(value.to_string()),
            "unit" => unit = Some(value.to_string()),
            "fp" => fingerprint = Some(value.to_string()),
            "surface" => surface = Some(value.to_string()),
            "boundary" => boundary = Some(value.to_string()),
            "subsystem" => subsystem = Some(value.to_string()),
            "class" => attack_class = Some(value.to_string()),
            "status" => status = Some(value.to_string()),
            "refs" => refs = serde_json::from_str(value).unwrap_or_default(),
            _ => {}
        }
    }
    Some(TaskMetadata {
        audit_run: run?,
        unit_id: unit?,
        fingerprint: fingerprint?,
        status: status.unwrap_or_else(|| TASK_STATUS_PENDING.to_string()),
        surface: surface.unwrap_or_default(),
        boundary: boundary.unwrap_or_default(),
        subsystem: subsystem.unwrap_or_default(),
        attack_class: attack_class.unwrap_or_default(),
        refs,
    })
}

/// Seed one task per ledger unit under the run's plan id.
///
/// Idempotent on the run id and on the unit id inside the run: calling it again
/// returns the same task ids and writes nothing. Ledger validation already
/// guarantees unit ids are unique.
pub fn seed_audit_tasks(
    store: &mut TaskStore,
    run_id: &str,
    units: &[LedgerUnit],
    now_ms: i64,
) -> Result<Vec<String>> {
    if run_id.trim().is_empty() || run_id.chars().any(char::is_control) {
        return Err(invalid("audit run id must be non-empty and printable"));
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut plan = Vec::with_capacity(units.len());
    for unit in units {
        if !seen.insert(unit.id.as_str()) {
            return Err(invalid(format!(
                "audit run `{run_id}` has duplicate unit id `{}`",
                unit.id
            )));
        }
        plan.push(PlanTask {
            key: unit.id.clone(),
            title: task_title_for_unit(run_id, unit),
            depends_on: Vec::new(),
            priority: 0,
        });
    }
    let ids = store.seed_plan(run_id, &plan, now_ms)?;
    Ok(ids)
}

/// Tasks that belong to one run, in creation order.
pub fn audit_tasks(store: &TaskStore, run_id: &str) -> Vec<Task> {
    let mut tasks: Vec<Task> = store
        .tasks()
        .filter(|task| task.plan.as_deref() == Some(run_id))
        .cloned()
        .collect();
    tasks.sort_by(|left, right| {
        (left.sequence, &left.id).cmp(&(right.sequence, &right.id))
    });
    tasks
}

/// Panel rows for one run. A row carries the unit facts needed to render and to
/// look the task up again.
pub fn panel_entries(store: &TaskStore, run_id: &str) -> Vec<PanelEntry> {
    audit_tasks(store, run_id)
        .into_iter()
        .filter_map(|task| {
            let metadata = task_metadata(&task)?;
            Some(PanelEntry {
                task_id: task.id,
                state: task.state,
                metadata,
            })
        })
        .collect()
}

/// Look one unit's task up from the panel.
pub fn panel_task_for_unit(store: &TaskStore, run_id: &str, unit_id: &str) -> Option<Task> {
    audit_tasks(store, run_id)
        .into_iter()
        .find(|task| task_metadata(task).is_some_and(|meta| meta.unit_id == unit_id))
}

// ---------------------------------------------------------------------------
// Audit run
// ---------------------------------------------------------------------------

/// Start a review run with the default caller profile.
pub fn start_audit(
    project_root: &Path,
    ledger: &CoverageLedger,
    findings: &Findings,
    budget: BudgetReport,
    now_ms: i64,
) -> Result<AuditRun> {
    start_audit_with_profile(
        project_root,
        ledger,
        findings,
        budget,
        ReviewProfile::Standard,
        now_ms,
    )
}

/// Start a review run with an explicit caller profile.
///
/// Everything is validated before a directory is created: the root marker, the
/// ledger, the refs against the root, the findings, their unit links, and the
/// project profile. The report set is derived into a staging directory,
/// re-read, verified, and only then renamed into `.zero/audits/run-N/`.
pub fn start_audit_with_profile(
    project_root: &Path,
    ledger: &CoverageLedger,
    findings: &Findings,
    budget: BudgetReport,
    caller_profile: ReviewProfile,
    now_ms: i64,
) -> Result<AuditRun> {
    let root = canonical_project_root(project_root)?;
    validate_ledger(ledger)?;
    validate_refs(&ledger.units, Some(&root))?;
    validate_findings(findings)?;
    let unit_ids: BTreeSet<&str> = ledger.units.iter().map(|unit| unit.id.as_str()).collect();
    for finding in &findings.findings {
        if !unit_ids.contains(finding.unit_id.as_str()) {
            return Err(invalid(format!(
                "finding `{}` names unit `{}`, which is not in the ledger",
                finding.id, finding.unit_id
            )));
        }
    }

    let project = load_project_profile(&root)?;
    let effective = check_profile(caller_profile, project.as_ref())?;

    let audits = resolve_audits_dir(&root, true)?;
    let (run_id, dir) = publish_report(
        &root,
        &audits,
        ledger,
        findings,
        &budget,
        effective.profile,
        now_ms,
    )?;

    let mut store = open_project_task_store(&root)?;
    let task_ids = seed_audit_tasks(&mut store, &run_id, &ledger.units, now_ms)?;

    Ok(AuditRun {
        run_id,
        dir,
        task_ids,
        units: ledger.units.iter().map(|unit| unit.id.clone()).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;
    use zero_review::{
        CanonicalRef, Finding, FindingStatus, LedgerSummary, Severity, DEFAULT_MAX_DEPTH,
        DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_BYTES, FINDINGS_SCHEMA_VERSION, LEDGER_SCHEMA_VERSION,
    };

    const NOW_MS: i64 = 1_700_000_000_000;

    struct Fixture {
        dir: TempDir,
        ledger: CoverageLedger,
        findings: Findings,
        budget: BudgetReport,
    }

    impl Fixture {
        fn root(&self) -> &Path {
            self.dir.path()
        }
    }

    fn write_file(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn unit(
        id: &str,
        surface: &str,
        boundary: &str,
        subsystem: &str,
        attack_class: &str,
        fingerprint: &str,
    ) -> LedgerUnit {
        LedgerUnit {
            id: id.to_string(),
            surface: surface.to_string(),
            boundary: boundary.to_string(),
            subsystem: subsystem.to_string(),
            attack_class: attack_class.to_string(),
            refs: vec![format!("{subsystem}:1")],
            starting_paths: vec![subsystem.to_string()],
            selected_companions: Vec::new(),
            excluded_companions: Vec::new(),
            status: zero_review::UnitStatus::Pending,
            history: Vec::new(),
            owner: String::new(),
            reviewed_paths: Vec::new(),
            checks: vec![format!("{attack_class}: check the boundary")],
            fingerprint: fingerprint.to_string(),
            content_fingerprint: None,
        }
    }

    fn fixture() -> Fixture {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(ZERO_DIR)).unwrap();
        for (path, contents) in [
            ("src/shell.rs", "fn run() { std::process::Command::new(\"sh\"); }\n"),
            ("src/net.rs", "fn fetch() { let _ = \"https\"; }\n"),
            ("src/parse.rs", "fn parse() { let _: u32 = 1; }\n"),
        ] {
            write_file(root, path, contents);
        }

        let units = vec![
            unit(
                "unit-1",
                "process",
                "process-exec",
                "src/shell.rs",
                "command_injection",
                "0000000000000001",
            ),
            unit(
                "unit-2",
                "network",
                "network-egress",
                "src/net.rs",
                "ssrf_egress",
                "0000000000000002",
            ),
            unit(
                "unit-3",
                "parser",
                "untrusted-input",
                "src/parse.rs",
                "unsafe_deserialization",
                "0000000000000003",
            ),
        ];
        let summary = LedgerSummary {
            units: 3,
            pending: 3,
            assigned: 0,
            reviewed: 0,
            confirmed: 0,
            refuted: 0,
            out_of_scope: 0,
            deferred: 0,
            blocked: 0,
            surfaces: 3,
            boundaries: 3,
            subsystems: 3,
            attack_classes: 3,
            files_scanned: 3,
            files_excluded: 0,
            files_size_capped: 0,
            walk_truncated: false,
            truncation: Vec::new(),
            max_files: DEFAULT_MAX_FILES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
        };
        let ledger = CoverageLedger {
            schema_version: LEDGER_SCHEMA_VERSION,
            units,
            summary,
        };
        let findings = Findings {
            schema_version: FINDINGS_SCHEMA_VERSION,
            findings: vec![
                Finding {
                    id: "FND-1".to_string(),
                    unit_id: "unit-1".to_string(),
                    title: "Command injection through the shell".to_string(),
                    severity: Severity::High,
                    status: FindingStatus::Confirmed,
                    evidence_refs: vec![CanonicalRef::parse("src/shell.rs:1").unwrap()],
                    confirmed: true,
                },
                Finding {
                    id: "FND-2".to_string(),
                    unit_id: "unit-2".to_string(),
                    title: "Egress to an attacker-chosen host".to_string(),
                    severity: Severity::Info,
                    status: FindingStatus::NeedsValidation,
                    evidence_refs: vec![CanonicalRef::parse("src/net.rs:1").unwrap()],
                    confirmed: false,
                },
            ],
        };
        let budget = BudgetReport {
            reserved_agents: 4,
            used_agents: 2,
            reserved_units: 3,
            used_units: 3,
            incomplete: false,
            reasons: Vec::new(),
        };
        Fixture {
            dir,
            ledger,
            findings,
            budget,
        }
    }

    fn start(fixture: &Fixture) -> Result<AuditRun> {
        start_audit(
            fixture.root(),
            &fixture.ledger,
            &fixture.findings,
            fixture.budget.clone(),
            NOW_MS,
        )
    }

    fn audits_dir(fixture: &Fixture) -> PathBuf {
        fixture.root().join(ZERO_DIR).join(AUDITS_DIR_NAME)
    }

    fn write_profile(fixture: &Fixture, value: serde_json::Value) {
        let path = fixture
            .root()
            .join(ZERO_DIR)
            .join(PROJECT_PROFILE_FILE);
        std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    #[test]
    fn a_valid_ledger_creates_run_one_with_the_report_set_and_three_tasks() {
        let fixture = fixture();
        let run = start(&fixture).unwrap();

        assert_eq!(run.run_id, "run-1");
        assert_eq!(
            run.dir,
            fixture
                .root()
                .canonicalize()
                .unwrap()
                .join(ZERO_DIR)
                .join(AUDITS_DIR_NAME)
                .join("run-1")
        );
        for name in RUN_FILES {
            assert!(run.dir.join(name).is_file(), "missing {name}");
        }
        assert_eq!(run.units, vec!["unit-1", "unit-2", "unit-3"]);
        assert_eq!(run.task_ids.len(), 3);

        let root = fixture.root().canonicalize().unwrap();
        let ledger_value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(run.dir.join(LEDGER_FILE)).unwrap())
                .unwrap();
        zero_review::schema::validate_coverage_ledger_json(&ledger_value, Some(&root)).unwrap();
        let findings_value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(run.dir.join(FINDINGS_FILE)).unwrap())
                .unwrap();
        zero_review::schema::validate_findings_json_with_ledger(&findings_value, &fixture.ledger)
            .unwrap();

        let store = open_project_task_store(fixture.root()).unwrap();
        assert_eq!(audit_tasks(&store, "run-1").len(), 3);
        let panel = panel_entries(&store, "run-1");
        assert_eq!(panel.len(), 3);
        for unit in &fixture.ledger.units {
            let entry = panel
                .iter()
                .find(|entry| entry.metadata.unit_id == unit.id)
                .unwrap_or_else(|| panic!("unit {} is not on the panel", unit.id));
            assert_eq!(entry.metadata.audit_run, "run-1");
            assert_eq!(entry.metadata.fingerprint, unit.fingerprint);
            assert_eq!(entry.metadata.status, TASK_STATUS_PENDING);
            assert_eq!(entry.state, TaskState::Queued);
            assert_eq!(entry.metadata.refs, unit.refs);
            assert_eq!(entry.metadata.surface, unit.surface);
            assert_eq!(entry.metadata.boundary, unit.boundary);
            assert_eq!(entry.metadata.subsystem, unit.subsystem);
            assert_eq!(entry.metadata.attack_class, unit.attack_class);
            let task = store.get(&entry.task_id).expect("task is in the store");
            assert!(task.title.contains("run-1"));
            assert!(task.title.contains(&unit.id));
            assert!(task.title.contains(&unit.surface));
            assert!(task.title.contains(&unit.boundary));
            assert!(task.title.contains(&unit.attack_class));
            assert_eq!(
                panel_task_for_unit(&store, "run-1", &unit.id)
                    .unwrap()
                    .id,
                entry.task_id
            );
        }
    }

    #[test]
    fn re_running_is_idempotent_for_tasks_and_picks_run_two() {
        let fixture = fixture();
        let first = start(&fixture).unwrap();
        assert_eq!(first.run_id, "run-1");

        // Seeding the same run again returns the same tasks and writes nothing.
        let mut store = open_project_task_store(fixture.root()).unwrap();
        let again = seed_audit_tasks(&mut store, "run-1", &fixture.ledger.units, NOW_MS + 1).unwrap();
        assert_eq!(again, first.task_ids);
        assert_eq!(audit_tasks(&store, "run-1").len(), 3);

        let second = start(&fixture).unwrap();
        assert_eq!(second.run_id, "run-2");
        assert!(second.dir.is_dir());
        assert_ne!(second.task_ids, first.task_ids);

        let store = open_project_task_store(fixture.root()).unwrap();
        assert_eq!(store.tasks().count(), 6);
        let mut pairs: BTreeSet<(String, String)> = BTreeSet::new();
        for task in store.tasks() {
            let metadata = task_metadata(task).expect("audit task metadata");
            assert!(
                pairs.insert((metadata.audit_run.clone(), metadata.unit_id.clone())),
                "duplicate task for {} / {}",
                metadata.audit_run,
                metadata.unit_id
            );
        }
        assert_eq!(audit_tasks(&store, "run-1").len(), 3);
        assert_eq!(audit_tasks(&store, "run-2").len(), 3);
    }

    #[test]
    fn an_invalid_ledger_is_refused_before_any_directory_is_created() {
        let fixture = fixture();
        let mut ledger = fixture.ledger.clone();
        ledger.units[0].fingerprint = "NOT-A-FINGERPRINT".to_string();

        let error = start_audit(
            fixture.root(),
            &ledger,
            &fixture.findings,
            fixture.budget.clone(),
            NOW_MS,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(!audits_dir(&fixture).exists());
    }

    #[test]
    fn invalid_findings_are_refused_before_any_directory_is_created() {
        let fixture = fixture();
        let mut findings = fixture.findings.clone();
        // An unconfirmed finding may not carry more than `info` (SR-07).
        findings.findings[1].severity = Severity::High;

        let error = start_audit(
            fixture.root(),
            &fixture.ledger,
            &findings,
            fixture.budget.clone(),
            NOW_MS,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(!audits_dir(&fixture).exists());
    }

    #[test]
    fn a_root_without_zero_is_not_a_project_root() {
        let dir = TempDir::new().unwrap();
        let fixture = fixture();
        let error = start_audit(
            dir.path(),
            &fixture.ledger,
            &fixture.findings,
            fixture.budget.clone(),
            NOW_MS,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(!dir.path().join(ZERO_DIR).exists());
    }

    #[test]
    fn a_symlinked_audits_directory_that_escapes_is_refused() {
        let fixture = fixture();
        let target = fixture.root().join("escape-target");
        std::fs::create_dir_all(&target).unwrap();
        let link = audits_dir(&fixture);
        if !link_dir(&target, &link) {
            eprintln!("skipping: this host cannot create a directory symlink or junction");
            return;
        }

        let error = start(&fixture).unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(!target.join("run-1").exists());
    }

    #[test]
    fn only_numeric_run_directories_are_counted() {
        let fixture = fixture();
        let audits = audits_dir(&fixture);
        std::fs::create_dir_all(&audits).unwrap();
        std::fs::create_dir_all(audits.join("run-7")).unwrap();
        std::fs::create_dir_all(audits.join("run-evil")).unwrap();
        std::fs::create_dir_all(audits.join("run-../escape")).unwrap_or_default();
        std::fs::create_dir_all(audits.join("run-0002")).unwrap();
        std::fs::write(audits.join("run-99"), "not a directory").unwrap();

        let run = start(&fixture).unwrap();
        assert_eq!(run.run_id, "run-8");
    }

    #[test]
    fn a_project_profile_cannot_lower_the_bar_or_skip_phases() {
        let fixture = fixture();
        write_profile(
            &fixture,
            json!({
                "profile": "quick",
                "phases": ["recon", "output"],
                "min_evidence_refs": 0
            }),
        );

        let error = start(&fixture).unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(!audits_dir(&fixture).exists());

        let relaxed = ProjectAuditProfile {
            profile: Some(ReviewProfile::Quick),
            phases: Some(vec![Phase::Recon, Phase::Output]),
            min_evidence_refs: Some(0),
        };
        assert_eq!(
            check_profile(ReviewProfile::Standard, Some(&relaxed))
                .unwrap_err()
                .code(),
            ErrorCode::PolicyDenied
        );
        let skipped = ProjectAuditProfile {
            phases: Some(vec![Phase::Recon, Phase::Output]),
            ..ProjectAuditProfile::default()
        };
        assert_eq!(
            check_profile(ReviewProfile::Standard, Some(&skipped))
                .unwrap_err()
                .code(),
            ErrorCode::PolicyDenied
        );
        let low_bar = ProjectAuditProfile {
            min_evidence_refs: Some(0),
            ..ProjectAuditProfile::default()
        };
        assert_eq!(
            check_profile(ReviewProfile::Standard, Some(&low_bar))
                .unwrap_err()
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn a_stronger_project_profile_is_ignored_and_the_caller_wins() {
        let fixture = fixture();
        write_profile(
            &fixture,
            json!({
                "profile": "deep",
                "phases": [
                    "recon",
                    "coverage_hunt",
                    "validation",
                    "output",
                    "record_verification",
                    "report"
                ],
                "min_evidence_refs": 4
            }),
        );

        let project: ProjectAuditProfile = serde_json::from_value(json!({
            "profile": "deep",
            "phases": [
                "recon",
                "coverage_hunt",
                "validation",
                "output",
                "record_verification",
                "report"
            ],
            "min_evidence_refs": 4
        }))
        .unwrap();
        let effective = check_profile(ReviewProfile::Standard, Some(&project)).unwrap();
        assert_eq!(effective.profile, ReviewProfile::Standard);
        assert_eq!(effective.phases, ReviewProfile::Standard.phases().to_vec());
        assert_eq!(effective.min_evidence_refs, MIN_EVIDENCE_REFS);
        assert!(effective.project_profile_ignored);
        assert!(!effective.ignored.is_empty());
        assert_eq!(
            check_profile(ReviewProfile::Quick, Some(&project))
                .unwrap()
                .profile,
            ReviewProfile::Quick
        );

        let run = start(&fixture).unwrap();
        assert_eq!(run.run_id, "run-1");
        assert!(run.dir.join(REPORT_FILE).is_file());
    }

    #[test]
    fn an_invalid_project_profile_is_refused_before_any_directory_is_created() {
        let fixture = fixture();
        std::fs::write(
            fixture
                .root()
                .join(ZERO_DIR)
                .join(PROJECT_PROFILE_FILE),
            "{ not json",
        )
        .unwrap();
        let error = start(&fixture).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ConfigInvalid);
        assert!(!audits_dir(&fixture).exists());
    }

    #[test]
    fn the_audit_path_is_offline_by_construction() {
        // The module may not even name a network client. Results are local files.
        // The needles are assembled so this assertion does not match itself.
        const SOURCE: &str = include_str!("audit.rs");
        let needles = [
            ["re", "qwest"].concat(),
            ["Tcp", "Stream"].concat(),
            ["Udp", "Socket"].concat(),
            ["std", "::net"].concat(),
            ["tokio", "::net"].concat(),
            ["hy", "per"].concat(),
            ["url", "::Url"].concat(),
        ];
        for forbidden in needles {
            assert!(
                !SOURCE.contains(&forbidden),
                "audit.rs must not reference `{forbidden}`"
            );
        }
    }

    #[cfg(unix)]
    fn link_dir(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn link_dir(target: &Path, link: &Path) -> bool {
        if std::os::windows::fs::symlink_dir(target, link).is_ok() {
            return true;
        }
        // A junction needs no elevation and is resolved by `canonicalize`.
        std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
            && link.exists()
    }

    #[cfg(not(any(unix, windows)))]
    fn link_dir(_target: &Path, _link: &Path) -> bool {
        false
    }
}
