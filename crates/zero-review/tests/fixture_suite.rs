//! End-to-end fixture suite (T-SR-07, SR-07, SR-11, SR-12).
//!
//! Three tiny repositories are created at runtime under a temporary directory:
//!
//! - `vulnerable`: a command-injection sink, a path-traversal join, and a
//!   hardcoded API key.
//! - `clean`: the same shapes written safely (allowlist, canonicalization, and
//!   an environment lookup), so every seeded unit is refuted.
//! - `partial`: one vulnerable file, one agent-blocked unit, one unit the unit
//!   budget trims, and an excluded `vendor`/`generated` payload.
//!
//! Each repository runs the same pipeline:
//!
//! 1. seed a coverage ledger and validate every canonical reference;
//! 2. run a [`HuntWave`] with deterministic scripted agents;
//! 3. screen candidates with an evidence-gated critic;
//! 4. run a [`ValidationWave`] with two independent [`EvidenceVerifier`]s using
//!    a sink-text matcher;
//! 5. derive the report set with [`zero_review::derive`].
//!
//! The stable projection of each run is compared with a checked-in golden file
//! under `tests/fixtures/golden/`. Set `UPDATE_REVIEW_GOLDEN=1` to rewrite them.
//!
//! The hunt critic forwards evidence-backed candidates as `NeedsEvidence`
//! instead of `Accept` because a hunt-stage `Accept` confirms the unit and the
//! validation preflight refuses confirmed units. The independent verifiers are
//! therefore the authority that records a finding, which is what SR-04 and
//! SR-07 describe.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use zero_review::{
    assert_consistent, check_fingerprints, derive, seed, validate, validate_refs, AgentPool,
    BudgetReport, CandidateFinding, CanonicalRef, CoverageLedger, Critic, CriticVerdict,
    EvidenceVerifier, Finding, FindingStatus, Findings, HuntAgent, HuntWave, LedgerUnit, LineMatcher,
    ReportBundle, ReportInputs, ReviewProfile, Severity, UnitStatus, ValidationReport,
    ValidationWave, Verifier, WaveLimits, WaveReport, FINDINGS_SCHEMA_VERSION, LEDGER_SCHEMA_VERSION,
};
use zero_types::error::Result as ZeroResult;
use zero_types::{ErrorCode, ZeroError};

// ---------------------------------------------------------------------------
// Fixture repositories (written at runtime, a few hundred bytes each)
// ---------------------------------------------------------------------------

const VULNERABLE_AGENT: &str = "use std::process::Command;

pub fn run(user_input: &str) {
    let _ = Command::new(user_input).spawn();
}
";

const VULNERABLE_READER: &str = "use std::path::{Path, PathBuf};

pub fn read_user_file(root: &Path, user_path: &str) -> Vec<u8> {
    let target = PathBuf::from(root).join(user_path);
    std::fs::read(target).unwrap_or_default()
}
";

const VULNERABLE_AUTH: &str = "pub const API_KEY: &str = \"sk-live-fixture-value\";

pub fn header() -> String {
    format!(\"Authorization: Bearer {API_KEY}\")
}
";

const CLEAN_AGENT: &str = "use std::process::Command;

const ALLOWED: &[&str] = &[\"status\", \"version\"];

pub fn run(requested: &str) -> bool {
    if !ALLOWED.contains(&requested) {
        return false;
    }
    Command::new(requested).spawn().is_ok()
}
";

const CLEAN_READER: &str = "use std::path::{Path, PathBuf};

pub fn read_user_file(root: &Path, user_path: &str) -> Option<Vec<u8>> {
    let root = root.canonicalize().ok()?;
    let target = root.join(user_path).canonicalize().ok()?;
    if !target.starts_with(&root) {
        return None;
    }
    std::fs::read(target).ok()
}
";

const CLEAN_AUTH: &str = "pub fn api_key() -> Option<String> {
    std::env::var(\"ZERO_API_KEY\").ok()
}

pub fn header(key: &str) -> String {
    format!(\"Authorization: Bearer {key}\")
}
";

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("fixture directory");
    }
    std::fs::write(path, contents).expect("fixture file");
}

fn build_vulnerable(root: &Path) {
    write(root, "src/process/agent.rs", VULNERABLE_AGENT);
    write(root, "src/files/reader.rs", VULNERABLE_READER);
    write(root, "src/auth/mod.rs", VULNERABLE_AUTH);
    write(
        root,
        "src/lib.rs",
        "pub mod auth;\npub mod files;\npub mod process;\n\npub const CRATE: &str = \"fixture-vulnerable\";\n",
    );
}

fn build_clean(root: &Path) {
    write(root, "src/process/agent.rs", CLEAN_AGENT);
    write(root, "src/files/reader.rs", CLEAN_READER);
    write(root, "src/auth/mod.rs", CLEAN_AUTH);
    write(
        root,
        "src/lib.rs",
        "pub mod auth;\npub mod files;\npub mod process;\n\npub const CRATE: &str = \"fixture-clean\";\n",
    );
}

fn build_partial(root: &Path) {
    write(root, "src/process/agent.rs", VULNERABLE_AGENT);
    write(root, "src/files/reader.rs", VULNERABLE_READER);
    write(root, "src/auth/mod.rs", VULNERABLE_AUTH);
    write(
        root,
        "src/lib.rs",
        "pub mod auth;\npub mod files;\npub mod process;\n\npub const CRATE: &str = \"fixture-partial\";\n",
    );
    // A vendored copy of the same sink is excluded from the walk.
    write(
        root,
        "vendor/airflow_exec.rs",
        "pub fn vendored(user_input: &str) {\n    let _ = std::process::Command::new(user_input).spawn();\n}\n",
    );
    // A generated binding is excluded as a generated file.
    write(
        root,
        "generated/bindings.rs",
        "pub fn generated(user_input: &str) {\n    let _ = std::process::Command::new(user_input).spawn();\n}\n",
    );
}

// ---------------------------------------------------------------------------
// Scripted agents
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum Response {
    Candidates(Vec<CandidateFinding>),
    Fail(String),
}

struct ScriptedAgent {
    label: String,
    responses: BTreeMap<String, Response>,
}

impl HuntAgent for ScriptedAgent {
    fn label(&self) -> &str {
        &self.label
    }

    fn hunt(&self, unit: &LedgerUnit) -> ZeroResult<Vec<CandidateFinding>> {
        match self.responses.get(&unit.id) {
            Some(Response::Candidates(candidates)) => Ok(candidates.clone()),
            Some(Response::Fail(reason)) => {
                Err(ZeroError::new(ErrorCode::Internal, reason.clone()))
            }
            // A unit with no scripted answer produces no candidate, which is
            // the clean-repository case.
            None => Ok(Vec::new()),
        }
    }
}

struct SingleAgentPool {
    agent: ScriptedAgent,
}

impl AgentPool for SingleAgentPool {
    fn label(&self) -> &str {
        self.agent.label()
    }

    fn agent(&self, _unit: &LedgerUnit) -> &dyn HuntAgent {
        &self.agent
    }
}

/// A critic that gates on evidence: it re-reads every cited line and rejects a
/// candidate that does not show the expected sink.
///
/// An evidence-backed candidate is forwarded with `NeedsEvidence` so the
/// independent validation pass is what records the finding.
struct EvidenceGatedCritic {
    label: String,
    root: PathBuf,
    sinks: BTreeMap<String, String>,
}

impl Critic for EvidenceGatedCritic {
    fn label(&self) -> &str {
        &self.label
    }

    fn review(&self, candidate: &CandidateFinding, unit: &LedgerUnit) -> CriticVerdict {
        let Some(marker) = self.sinks.get(&unit.id) else {
            return CriticVerdict::Reject {
                reason: "the unit has no recorded sink to check".to_string(),
            };
        };
        if cited_line_contains(&self.root, candidate, marker) {
            CriticVerdict::NeedsEvidence {
                reason: "the cited line contains the sink; independent validation is required before a finding"
                    .to_string(),
            }
        } else {
            CriticVerdict::Reject {
                reason: "no cited line contains the expected sink text".to_string(),
            }
        }
    }
}

fn cited_line_contains(root: &Path, candidate: &CandidateFinding, marker: &str) -> bool {
    candidate.evidence_refs.iter().any(|reference| {
        let Some((path, line, _column)) = reference.path_parts() else {
            return false;
        };
        let file = root.join(path.replace('/', std::path::MAIN_SEPARATOR_STR));
        let Ok(text) = std::fs::read_to_string(file) else {
            return false;
        };
        text.lines()
            .nth(line as usize - 1)
            .is_some_and(|text| text.contains(marker))
    })
}

/// The sink text a validated finding must demonstrate, keyed by unit id.
fn sink_matcher(sinks: BTreeMap<String, String>) -> LineMatcher {
    LineMatcher::Custom(Box::new(move |line, candidate| {
        sinks
            .get(&candidate.unit_id)
            .is_some_and(|marker| line.contains(marker.as_str()))
    }))
}

// ---------------------------------------------------------------------------
// Fixture plans
// ---------------------------------------------------------------------------

struct Plan {
    responses: BTreeMap<String, Response>,
    sinks: BTreeMap<String, String>,
    order: Vec<String>,
    limits: WaveLimits,
    budget: BudgetReport,
    run_id: &'static str,
}

fn unit(ledger: &CoverageLedger, attack_class: &str, subsystem: &str) -> LedgerUnit {
    ledger
        .units
        .iter()
        .find(|unit| unit.attack_class == attack_class && unit.subsystem == subsystem)
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "fixture has no `{attack_class}` unit in `{subsystem}`; units: {:?}",
                ledger
                    .units
                    .iter()
                    .map(|unit| (&unit.attack_class, &unit.subsystem))
                    .collect::<Vec<_>>()
            )
        })
}

fn candidate(
    unit: &LedgerUnit,
    id: &str,
    title: &str,
    severity: Severity,
    principal: &str,
    concrete_result: &str,
    evidence: &str,
) -> CandidateFinding {
    CandidateFinding {
        id: id.to_string(),
        unit_id: unit.id.clone(),
        title: title.to_string(),
        severity,
        lower_trust_principal: principal.to_string(),
        boundary: unit.boundary.clone(),
        concrete_result: concrete_result.to_string(),
        evidence_refs: vec![CanonicalRef::parse(evidence).expect("fixture evidence ref")],
        checks: unit.checks.clone(),
        notes: None,
    }
}

fn vulnerable_plan(ledger: &CoverageLedger) -> Plan {
    let command = unit(ledger, "command_injection", "src/process");
    let path = unit(ledger, "path_traversal", "src/files");
    let credential = unit(ledger, "credential_exposure", "src/auth");

    let mut responses = BTreeMap::new();
    responses.insert(
        command.id.clone(),
        Response::Candidates(vec![candidate(
            &command,
            "FND-V1",
            "user input selects the executable that is spawned",
            Severity::High,
            "repository content or model output",
            "the caller-supplied string becomes argv[0] of Command::new",
            "src/process/agent.rs:4",
        )]),
    );
    responses.insert(
        path.id.clone(),
        Response::Candidates(vec![candidate(
            &path,
            "FND-V2",
            "user path escapes the review root and is read",
            Severity::High,
            "untrusted path component",
            "a relative user path is joined without confinement, so a parent component escapes the root",
            "src/files/reader.rs:4",
        )]),
    );
    responses.insert(
        credential.id.clone(),
        Response::Candidates(vec![candidate(
            &credential,
            "FND-V3",
            "a live API key is hardcoded in the source",
            Severity::Medium,
            "repository or configuration file",
            "the literal key is embedded in the binary and returned in an Authorization header",
            "src/auth/mod.rs:1",
        )]),
    );

    let mut sinks = BTreeMap::new();
    sinks.insert(command.id.clone(), "Command::new".to_string());
    sinks.insert(path.id.clone(), "PathBuf::from".to_string());
    sinks.insert(credential.id.clone(), "API_KEY".to_string());

    Plan {
        responses,
        sinks,
        order: vec![command.id, path.id, credential.id],
        limits: WaveLimits::default(),
        budget: BudgetReport {
            reserved_agents: 8,
            used_agents: 1,
            reserved_units: 32,
            used_units: 3,
            incomplete: false,
            reasons: Vec::new(),
        },
        run_id: "run-fixture-vulnerable",
    }
}

fn clean_plan(ledger: &CoverageLedger) -> Plan {
    let command = unit(ledger, "command_injection", "src/process");
    let path = unit(ledger, "path_traversal", "src/files");
    let credential = unit(ledger, "credential_exposure", "src/auth");

    Plan {
        // Every marker exists, but no agent returns a candidate: the safe shape
        // must not become a false positive.
        responses: BTreeMap::new(),
        sinks: BTreeMap::new(),
        order: vec![command.id, credential.id, path.id],
        limits: WaveLimits::default(),
        budget: BudgetReport {
            reserved_agents: 8,
            used_agents: 1,
            reserved_units: 32,
            used_units: 3,
            incomplete: false,
            reasons: Vec::new(),
        },
        run_id: "run-fixture-clean",
    }
}

fn partial_plan(ledger: &CoverageLedger) -> Plan {
    let command = unit(ledger, "command_injection", "src/process");
    let path = unit(ledger, "path_traversal", "src/files");
    let credential = unit(ledger, "credential_exposure", "src/auth");

    let mut responses = BTreeMap::new();
    responses.insert(
        command.id.clone(),
        Response::Candidates(vec![candidate(
            &command,
            "FND-P1",
            "user input selects the executable that is spawned",
            Severity::High,
            "repository content or model output",
            "the caller-supplied string becomes argv[0] of Command::new",
            "src/process/agent.rs:4",
        )]),
    );
    responses.insert(
        credential.id.clone(),
        Response::Fail("fixture agent could not read the credential store".to_string()),
    );

    let mut sinks = BTreeMap::new();
    sinks.insert(command.id.clone(), "Command::new".to_string());

    Plan {
        responses,
        sinks,
        // The unit budget keeps the first two units; `src/files` is never
        // assigned and must surface as a coverage gap.
        order: vec![command.id, credential.id, path.id],
        limits: WaveLimits {
            max_units: 2,
            max_agents: 4,
        },
        budget: BudgetReport {
            reserved_agents: 4,
            used_agents: 1,
            reserved_units: 2,
            used_units: 2,
            incomplete: true,
            reasons: vec![
                "the unit budget trimmed 3 unit(s) to 2; 1 unit remains for a later run".to_string(),
            ],
        },
        run_id: "run-fixture-partial",
    }
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

struct Outcome {
    ledger: CoverageLedger,
    findings: Findings,
    bundle: ReportBundle,
    hunt: WaveReport,
    validation: ValidationReport,
    budget: BudgetReport,
}

fn run_fixture(
    root: &Path,
    plan_for: impl FnOnce(&CoverageLedger) -> Plan,
    out: &Path,
    profile: ReviewProfile,
) -> Outcome {
    let mut ledger = seed(root).expect("seed");
    validate(&ledger).expect("the seeded ledger validates");
    validate_refs(&ledger.units, Some(root)).expect("every seeded ref resolves");

    let plan = plan_for(&ledger);
    let candidates: Vec<CandidateFinding> = plan
        .responses
        .values()
        .filter_map(|response| match response {
            Response::Candidates(items) => Some(items.clone()),
            Response::Fail(_) => None,
        })
        .flatten()
        .collect();

    let pool = SingleAgentPool {
        agent: ScriptedAgent {
            label: "fixture-hunter".to_string(),
            responses: plan.responses,
        },
    };
    let critic = EvidenceGatedCritic {
        label: "fixture-critic".to_string(),
        root: root.to_path_buf(),
        sinks: plan.sinks.clone(),
    };
    let hunt = HuntWave {
        wave_id: "fixture-wave".to_string(),
        units: plan.order,
        agent_cap: 4,
    }
    .run(&mut ledger, &pool, &critic, &plan.limits)
    .expect("hunt wave");

    let checks = [
        EvidenceVerifier::new("verifier-one").with_matcher(sink_matcher(plan.sinks.clone())),
        EvidenceVerifier::new("verifier-two").with_matcher(sink_matcher(plan.sinks.clone())),
    ];
    let verifiers: Vec<&dyn Verifier> = checks.iter().map(|check| check as &dyn Verifier).collect();
    let validation = ValidationWave::new(checks.len())
        .run(&mut ledger, &candidates, &verifiers, root)
        .expect("validation wave");

    let findings = Findings {
        schema_version: FINDINGS_SCHEMA_VERSION,
        findings: validation.findings.clone(),
    };
    let budget = plan.budget;
    let inputs = ReportInputs {
        ledger: ledger.clone(),
        findings: findings.clone(),
        budget: budget.clone(),
        profile,
        run_id: plan.run_id.to_string(),
        created_at_ms: 1_700_000_000_000,
    };
    let bundle = derive(inputs, out).expect("derive the report set");
    assert_consistent(&bundle).expect("prose and records agree");

    Outcome {
        ledger,
        findings,
        bundle,
        hunt,
        validation,
        budget,
    }
}

fn count(ledger: &CoverageLedger, status: UnitStatus) -> usize {
    ledger
        .units
        .iter()
        .filter(|unit| unit.status == status)
        .count()
}

// ---------------------------------------------------------------------------
// Stable golden projection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StableFinding {
    id: String,
    unit_id: String,
    title: String,
    severity: String,
}

/// The part of a run that must not drift: schema versions, counts, confirmed
/// finding identity and severity, the partial flag, and the coverage gaps.
///
/// Timestamps, absolute paths, run ids, and history notes are deliberately
/// absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StableProjection {
    ledger_schema_version: u32,
    findings_schema_version: u32,
    units: usize,
    findings: usize,
    status_counts: BTreeMap<String, usize>,
    confirmed_findings: Vec<StableFinding>,
    rejected_candidates: usize,
    deferred_units: usize,
    blocked_units: usize,
    partial: bool,
    coverage_gap_unit_ids: Vec<String>,
    needs_validation_unit_ids: Vec<String>,
}

fn project(outcome: &Outcome) -> StableProjection {
    let statuses = [
        UnitStatus::Pending,
        UnitStatus::Assigned,
        UnitStatus::Reviewed,
        UnitStatus::Confirmed,
        UnitStatus::Refuted,
        UnitStatus::OutOfScope,
        UnitStatus::Deferred,
        UnitStatus::Blocked,
    ];
    let status_counts = statuses
        .into_iter()
        .map(|status| (status.as_str().to_string(), count(&outcome.ledger, status)))
        .collect();

    let mut confirmed_findings: Vec<StableFinding> = outcome
        .findings
        .findings
        .iter()
        .filter(|finding| finding.confirmed)
        .map(|finding| StableFinding {
            id: finding.id.clone(),
            unit_id: finding.unit_id.clone(),
            title: finding.title.clone(),
            severity: finding.severity.as_str().to_string(),
        })
        .collect();
    confirmed_findings.sort_by(|left, right| left.id.cmp(&right.id));

    let mut coverage_gap_unit_ids: Vec<String> = outcome
        .ledger
        .units
        .iter()
        .filter(|unit| {
            matches!(
                unit.status,
                UnitStatus::Pending
                    | UnitStatus::Assigned
                    | UnitStatus::Deferred
                    | UnitStatus::Blocked
            )
        })
        .map(|unit| unit.id.clone())
        .collect();
    coverage_gap_unit_ids.sort();

    let mut needs_validation_unit_ids: Vec<String> = outcome
        .ledger
        .units
        .iter()
        .filter(|unit| unit.status != UnitStatus::Confirmed)
        .map(|unit| unit.id.clone())
        .collect();
    needs_validation_unit_ids.sort();

    StableProjection {
        ledger_schema_version: LEDGER_SCHEMA_VERSION,
        findings_schema_version: FINDINGS_SCHEMA_VERSION,
        units: outcome.ledger.units.len(),
        findings: outcome.findings.findings.len(),
        status_counts,
        confirmed_findings,
        rejected_candidates: outcome.validation.rejected.len(),
        deferred_units: count(&outcome.ledger, UnitStatus::Deferred),
        blocked_units: count(&outcome.ledger, UnitStatus::Blocked),
        partial: outcome.bundle.partial,
        coverage_gap_unit_ids,
        needs_validation_unit_ids,
    }
}

const UPDATE_FLAG: &str = "UPDATE_REVIEW_GOLDEN";
const GOLDEN_DIR: &str = "tests/fixtures/golden";

fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(GOLDEN_DIR)
        .join(format!("{name}.json"))
}

fn assert_golden(name: &str, actual: &StableProjection) {
    let rendered = serde_json::to_string_pretty(actual).expect("projection serializes") + "\n";
    let path = golden_path(name);
    if std::env::var(UPDATE_FLAG).as_deref() == Ok("1") {
        let parent = path.parent().expect("golden directory");
        std::fs::create_dir_all(parent).expect("create golden directory");
        std::fs::write(&path, &rendered).expect("write golden");
        eprintln!("updated golden {}", path.display());
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing golden `{}` ({error}); rerun with {UPDATE_FLAG}=1",
            path.display()
        )
    });
    // A CRLF checkout must compare equal to the LF golden.
    let expected = expected.replace("\r\n", "\n");
    assert_eq!(
        rendered, expected,
        "the stable projection for `{name}` drifted; if the change is intended, rerun with {UPDATE_FLAG}=1"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn vulnerable_repo_confirms_only_the_demonstrated_findings() {
    let repo = tempfile::tempdir().expect("repo");
    let out = tempfile::tempdir().expect("out");
    build_vulnerable(repo.path());
    let outcome = run_fixture(
        repo.path(),
        vulnerable_plan,
        out.path(),
        ReviewProfile::Standard,
    );

    assert_eq!(outcome.hunt.units_run, 3, "three seeded units are hunted");
    assert_eq!(outcome.hunt.candidates, 3);
    assert!(
        outcome.hunt.found.is_empty(),
        "the evidence-gated critic forwards candidates to validation instead of confirming them"
    );
    assert_eq!(outcome.hunt.deferred.len(), 3);

    assert_eq!(outcome.validation.findings.len(), 3);
    assert!(outcome.validation.rejected.is_empty());
    assert!(outcome.validation.deferred.is_empty());

    let expected = [
        (
            "FND-V1",
            "command_injection",
            "src/process",
            Severity::High,
            Severity::High,
        ),
        (
            "FND-V2",
            "path_traversal",
            "src/files",
            Severity::High,
            Severity::High,
        ),
        (
            "FND-V3",
            "credential_exposure",
            "src/auth",
            Severity::Medium,
            Severity::Medium,
        ),
    ];
    for (id, attack_class, subsystem, severity, demonstrated) in expected {
        let unit = unit(&outcome.ledger, attack_class, subsystem);
        let finding = outcome
            .findings
            .findings
            .iter()
            .find(|finding| finding.id == id)
            .unwrap_or_else(|| panic!("expected confirmed finding `{id}`"));
        assert_eq!(finding.unit_id, unit.id, "`{id}` belongs to its unit");
        assert_eq!(finding.severity, severity, "`{id}` keeps its claim");
        assert!(
            finding.severity <= demonstrated,
            "`{id}` severity {} exceeds the demonstrated impact {}",
            finding.severity.as_str(),
            demonstrated.as_str()
        );
        assert!(finding.confirmed);
        assert_eq!(finding.status, FindingStatus::Confirmed);
        assert_eq!(unit.status, UnitStatus::Confirmed);
        assert!(
            unit.content_fingerprint.is_some(),
            "a confirmed unit records its content baseline"
        );
    }

    assert_eq!(count(&outcome.ledger, UnitStatus::Confirmed), 3);
    assert_eq!(count(&outcome.ledger, UnitStatus::Pending), 0);
    assert_eq!(count(&outcome.ledger, UnitStatus::Blocked), 0);
    assert_eq!(count(&outcome.ledger, UnitStatus::Deferred), 0);
    assert!(!outcome.bundle.partial);
    for name in &outcome.bundle.files {
        assert!(
            out.path().join(name).is_file(),
            "the derived artifact `{name}` is on disk"
        );
    }
    assert!(outcome
        .bundle
        .findings_detail_md
        .contains("src/process/agent.rs:4"));
    assert!(outcome.bundle.needs_validation_md.contains("- None."));

    assert_golden("vulnerable", &project(&outcome));
}

#[test]
fn clean_repo_confirms_nothing_and_raises_no_false_positive() {
    let repo = tempfile::tempdir().expect("repo");
    let out = tempfile::tempdir().expect("out");
    build_clean(repo.path());
    let outcome = run_fixture(repo.path(), clean_plan, out.path(), ReviewProfile::Standard);

    assert_eq!(outcome.hunt.units_run, 3);
    assert_eq!(outcome.hunt.candidates, 0);
    assert!(outcome.hunt.found.is_empty());
    assert_eq!(outcome.hunt.deferred.len(), 0);

    assert!(
        outcome.validation.findings.is_empty(),
        "a clean repo produces no finding"
    );
    assert!(outcome.findings.findings.is_empty());
    assert_eq!(count(&outcome.ledger, UnitStatus::Confirmed), 0);
    assert_eq!(
        count(&outcome.ledger, UnitStatus::Refuted),
        3,
        "every seeded unit is reviewed and refuted"
    );
    assert!(!outcome.bundle.partial);
    assert!(outcome
        .bundle
        .report_md
        .contains("## Confirmed findings\n\n- None."));

    let projection = project(&outcome);
    assert!(projection.confirmed_findings.is_empty());
    assert!(projection.coverage_gap_unit_ids.is_empty());
    for id in &projection.needs_validation_unit_ids {
        assert!(
            outcome.bundle.needs_validation_md.contains(id),
            "refuted unit `{id}` is still listed in NEEDS-VALIDATION"
        );
    }

    assert_golden("clean", &projection);
}

#[test]
fn partial_run_is_marked_partial_and_lists_the_unreviewed_units() {
    let repo = tempfile::tempdir().expect("repo");
    let out = tempfile::tempdir().expect("out");
    build_partial(repo.path());
    let outcome = run_fixture(
        repo.path(),
        partial_plan,
        out.path(),
        ReviewProfile::Standard,
    );

    assert_eq!(outcome.hunt.units_run, 2, "the unit budget keeps two units");
    assert_eq!(outcome.hunt.blocked.len(), 1);
    assert_eq!(outcome.validation.findings.len(), 1);

    let command = unit(&outcome.ledger, "command_injection", "src/process");
    let path = unit(&outcome.ledger, "path_traversal", "src/files");
    let credential = unit(&outcome.ledger, "credential_exposure", "src/auth");

    assert_eq!(command.status, UnitStatus::Confirmed);
    assert_eq!(
        path.status,
        UnitStatus::Pending,
        "the trimmed unit is never assigned"
    );
    assert_eq!(
        credential.status,
        UnitStatus::Blocked,
        "the failed agent blocks only its own unit"
    );

    assert!(outcome.bundle.partial, "an incomplete run is partial");
    assert!(outcome.bundle.report_md.contains("Partial: yes"));
    assert!(outcome.bundle.report_md.contains("Incomplete: yes"));
    assert!(outcome.bundle.report_md.contains("Partial reason:"));
    assert!(outcome
        .bundle
        .report_md
        .contains("Reason: the unit budget trimmed"));

    let projection = project(&outcome);
    assert!(!projection.coverage_gap_unit_ids.is_empty());
    assert_eq!(projection.blocked_units, 1);
    assert!(projection.coverage_gap_unit_ids.contains(&path.id));
    assert!(projection.coverage_gap_unit_ids.contains(&credential.id));
    for id in &projection.coverage_gap_unit_ids {
        assert!(
            outcome.bundle.needs_validation_md.contains(id),
            "unreviewed unit `{id}` appears in NEEDS-VALIDATION"
        );
        assert!(
            outcome.bundle.report_md.contains(id),
            "unreviewed unit `{id}` appears in the coverage gaps"
        );
    }

    // The excluded vendor and generated payloads are recorded, not silently
    // dropped.
    let excluded: BTreeSet<String> = outcome
        .ledger
        .units
        .iter()
        .flat_map(|unit| {
            unit.excluded_companions
                .iter()
                .map(|excluded| excluded.path.clone())
        })
        .collect();
    assert!(excluded.contains("vendor"));
    assert!(excluded.contains("generated/bindings.rs"));

    assert_golden("partial", &projection);
}

#[test]
fn a_carried_confirmation_is_reverified_and_deferred_when_the_target_changes() {
    let repo = tempfile::tempdir().expect("repo");
    let out = tempfile::tempdir().expect("out");
    build_vulnerable(repo.path());
    let outcome = run_fixture(
        repo.path(),
        vulnerable_plan,
        out.path(),
        ReviewProfile::Standard,
    );
    let command = unit(&outcome.ledger, "command_injection", "src/process");
    assert_eq!(command.status, UnitStatus::Confirmed);

    let mut ledger = outcome.ledger.clone();
    let stable = check_fingerprints(&mut ledger, repo.path()).expect("fingerprint check");
    assert!(stable.stable, "an untouched target keeps every confirmation");

    // Change the bytes of the cited file so the carried fingerprint no longer
    // matches, while the sink line stays readable.
    let drifted = format!("{}\n// drift after the carried run\n", VULNERABLE_AGENT.trim_end());
    write(repo.path(), "src/process/agent.rs", &drifted);

    let changed = check_fingerprints(&mut ledger, repo.path()).expect("fingerprint check");
    assert!(!changed.stable);
    assert_eq!(changed.changed, vec![command.id.clone()]);

    let recorded = ledger
        .units
        .iter()
        .find(|unit| unit.id == command.id)
        .expect("command unit");
    assert_eq!(
        recorded.status,
        UnitStatus::Deferred,
        "a changed confirmation is current work again"
    );
    assert!(recorded.content_fingerprint.is_none());
    let last = recorded.history.last().expect("history");
    assert_eq!(last.from, UnitStatus::Confirmed);
    assert_eq!(last.to, UnitStatus::Deferred);
    assert_eq!(last.actor, "fingerprint-check");
    assert!(
        last.note
            .as_deref()
            .unwrap_or_default()
            .contains("re-review"),
        "the deferral names re-review"
    );

    // The next report must not publish the invalidated confirmation. The
    // carried finding becomes needs_validation, capped at info (SR-07).
    let findings = Findings {
        schema_version: FINDINGS_SCHEMA_VERSION,
        findings: outcome
            .findings
            .findings
            .iter()
            .map(|finding| {
                if finding.unit_id == command.id {
                    Finding {
                        status: FindingStatus::NeedsValidation,
                        confirmed: false,
                        severity: Severity::Info,
                        ..finding.clone()
                    }
                } else {
                    finding.clone()
                }
            })
            .collect(),
    };
    let out2 = tempfile::tempdir().expect("out");
    let second = derive(
        ReportInputs {
            ledger: ledger.clone(),
            findings,
            budget: outcome.budget.clone(),
            profile: ReviewProfile::Standard,
            run_id: "run-fixture-reverify".to_string(),
            created_at_ms: 1_700_000_100_000,
        },
        out2.path(),
    )
    .expect("derive the follow-up report");

    assert!(
        second.needs_validation_md.contains(&command.id),
        "the deferred unit is listed for validation"
    );
    assert!(
        second.needs_validation_md.contains("FND-V1"),
        "the invalidated finding is listed as unconfirmed"
    );
    assert!(
        !second.report_md.contains("`FND-V1`"),
        "an invalidated confirmation is not published as a confirmed finding"
    );
    assert!(second.report_md.contains("`FND-V2`"));
    assert!(second.report_md.contains("`FND-V3`"));
    assert_consistent(&second).expect("the follow-up report is consistent");
}
