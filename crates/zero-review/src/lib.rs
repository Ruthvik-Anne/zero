//! `zero-review` — see `architecture.md` section 5 for the module contract.
//!
//! Security review is checklist-first (SR-02). [`ledger`] implements the SR-01
//! mode gate, the SR-03 trust-boundary summary and coverage ledger, and the
//! validation pass that must succeed before any unit is assigned. [`schema`]
//! adds canonical references, append-only status history, review profiles, and
//! the validators for `coverage-ledger.json` and `findings.json` (SR-06, SR-13).
//! [`report`] derives `REPORT.md`, `FINDINGS-DETAIL.md`, and
//! `NEEDS-VALIDATION.md` from the final records and checks that prose and JSON
//! agree (SR-14). [`hunt`] runs coverage-led hunting waves: per-unit agents,
//! the SR-05 evidence bar, and the independent critic pass (SR-04). [`validate`]
//! re-reads the target with independent verifiers, requires a quorum, checks
//! fingerprint stability, and applies the SR-07 severity rule. [`sandbox`]
//! gates target-code execution on a real platform mechanism, resolves a
//! command into a read-only, no-network, scratch-only plan with resource
//! limits, refuses escape attempts with a report, and promotes one regular
//! file per agent under path, symlink, type, and size checks (SR-09, SR-10).

pub mod hunt;
pub mod ledger;
pub mod report;
pub mod sandbox;
pub mod schema;
pub mod validate;

pub use hunt::{
    validate_candidate, AgentPool, BlockedUnit, CandidateFinding, Critic, CriticVerdict,
    DeferredUnit, HuntAgent, HuntWave, RejectedCandidate, WaveLimits, WaveReport, MAX_REASON_CHARS,
};
pub use ledger::{
    gate, seed, seed_report, seed_report_with_limits, seed_with_limits, validate, AttackClass,
    CoverageLedger, ExcludedCompanion, LedgerSummary, LedgerUnit, Phase, ReviewMode, ReviewPlan,
    ReviewRequest, SeedLimits, SeedReport, Surface, TrustBoundary, UnitStatus,
    ValidationReport as LedgerValidationReport, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILES,
    DEFAULT_MAX_FILE_BYTES, LEDGER_FILE, LEDGER_SCHEMA_VERSION, MAX_BOUNDARY_EVIDENCE,
    MAX_COMPANIONS_PER_UNIT, MAX_EXCLUSIONS_PER_UNIT, MAX_REFS_PER_UNIT,
};
pub use report::{
    assert_consistent, consistency_report, derive, BudgetReport, ConsistencyReport, ReportBundle,
    ReportInputs, FINDINGS_DETAIL_FILE, NEEDS_VALIDATION_FILE, REPORT_FILE,
};
pub use sandbox::{
    detect, detect_with, execute, PromotedFile, PromotionDenialKind, PromotionLimits, Sandbox,
    SandboxAvailability, SandboxCommand, SandboxDenial, SandboxDenialKind, SandboxLimits,
    SandboxOutput, SandboxPlan, SandboxPolicy, SandboxProbe, SandboxReport, SandboxRunner, Scratch,
    BASELINE_ENV, DEFAULT_FILE_BYTES, DEFAULT_MEMORY_MB, DEFAULT_OUTPUT_BYTES, DEFAULT_PROCESSES,
    DEFAULT_TIMEOUT_MS, MAX_DETAIL_CHARS,
};
pub use schema::{
    advance, allowed_transitions, canonicalize_ref, scope, scope_all, transition_allowed,
    transition_requires_note, validate_coverage_ledger_json, validate_findings,
    validate_findings_json, validate_findings_json_with_ledger, validate_history, validate_refs,
    CanonicalRef, Finding, FindingStatus, Findings, ProfileBudget, ReviewProfile, ScopePlan,
    Severity, UnitEvent, FINDINGS_FILE, FINDINGS_SCHEMA_VERSION,
};
pub use validate::{
    check_fingerprints, fingerprint_unit, severity_decision, validate_severity,
    CandidateVerification, EvidenceVerifier, FingerprintReport, LineMatcher, LinePredicate,
    SeverityDecision, ValidationDisposition, ValidationReport, ValidationWave, VerificationVerdict,
    Verifier, DEFAULT_QUORUM, MAX_EVIDENCE_BYTES, MAX_FINGERPRINT_BYTES,
};
