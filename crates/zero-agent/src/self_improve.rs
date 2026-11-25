//! Self-improvement loop (SI-01..SI-04, SI-08; T-SI-02, SR-17).
//!
//! One bounded change is carried through seven stages:
//!
//! ```text
//! Execute -> Verify -> Capture -> Distil -> Evaluate -> Promote -> Reenter
//! ```
//!
//! Each stage has a seam so the loop can be exercised without a real build, a
//! real model, or a network:
//!
//! - [`ProposalExecutor`] applies the change inside a fresh scratch workspace.
//!   The loop creates the workspace under the executor's scratch root, refuses
//!   to reuse a directory, validates every change path with
//!   [`crate::eval_suite::safe_relative_path`], and refuses a reported path that
//!   resolves outside the workspace.
//! - [`Verifier`] builds and tests the candidate. The loop treats a failed or
//!   errored verification as a stage failure and never reaches evaluation.
//! - [`Evaluator`] runs the held-out suite twice: once for the baseline and once
//!   for the candidate. The acceptance rule is the [`crate::eval_suite::compare`]
//!   delta: no regressions and at least one improvement.
//!
//! # Verification is not self-report (SI-02)
//!
//! A [`Proposal`] must carry at least one evidence reference. Acceptance is
//! decided by a held-out [`crate::eval_suite::EvalReport`] pair, never by text
//! the candidate (or its executor) produced. Both reports must name the same
//! suite version; a mismatch fails the Evaluate stage.
//!
//! # Promotion (SI-03)
//!
//! [`promote`] never mutates the real agent, a policy file, or the evaluator. It
//! returns a [`Promotion`] that says whether the automated gate would allow the
//! change and which human decision is still required. T-SI-03 owns the human
//! promotion, the diff, and the rollback; this module only supplies the gate
//! input.
//!
//! # Offline (SI-01, FND-13)
//!
//! The module holds no provider, no router, and no socket API. A test asserts
//! the source names none of them (needles are assembled at run time so the test
//! does not match itself).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};
use zero_types::id::{Clock, SystemClock};

use crate::eval_suite::{compare, safe_relative_path, EvalReport};

/// Domain separator mixed into a proposal's canonical bytes before hashing.
pub const PROPOSAL_HASH_PREFIX: &str = "zero.si-proposal.v1";
/// Upper bound on the re-entry budget a caller may request.
pub const MAX_ATTEMPTS: u32 = 8;
/// Upper bound on files in one change set.
pub const MAX_CHANGE_FILES: usize = 16;
/// Upper bound on one change file, in bytes.
pub const MAX_CHANGE_FILE_BYTES: usize = 65_536;
/// Upper bound on all change files together, in bytes.
pub const MAX_CHANGE_BYTES: usize = 262_144;
/// Upper bound on a proposal title, in bytes.
pub const MAX_TITLE_BYTES: usize = 256;
/// Upper bound on a proposal rationale, in bytes.
pub const MAX_RATIONALE_BYTES: usize = 4_096;
/// Upper bound on a change description, in bytes.
pub const MAX_DESCRIPTION_BYTES: usize = 4_096;
/// Upper bound on evidence references in one proposal.
pub const MAX_EVIDENCE_REFS: usize = 32;
/// Upper bound on one evidence reference, in bytes.
pub const MAX_EVIDENCE_REF_BYTES: usize = 512;
/// Upper bound on a distilled summary, in bytes.
pub const MAX_SUMMARY_BYTES: usize = 2_048;
/// Upper bound on a verification detail or stage failure reason, in bytes.
pub const MAX_DETAIL_BYTES: usize = 1_024;
/// Upper bound on executor output retained in a report, in bytes.
pub const MAX_OUTPUT_BYTES: usize = 4_096;

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

/// Truncate to `max` bytes on a character boundary.
fn bounded(text: &str, max: usize) -> (String, bool) {
    if text.len() <= max {
        return (text.to_string(), false);
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

// ---------------------------------------------------------------------------
// Proposal
// ---------------------------------------------------------------------------

/// The kind of unit a change is allowed to touch (SI-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// A system or skill prompt.
    AgentPrompt,
    /// A skill description or body.
    Skill,
    /// A tool description or routing rule.
    ToolPolicy,
    /// Source code.
    Code,
}

impl Target {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentPrompt => "agent_prompt",
            Self::Skill => "skill",
            Self::ToolPolicy => "tool_policy",
            Self::Code => "code",
        }
    }
}

/// The bounded contents of one candidate change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSet {
    /// Relative path to full contents. The map keeps the order canonical.
    pub files: BTreeMap<String, String>,
    /// What the change does, in one bounded paragraph.
    pub description: String,
}

/// One bounded candidate change with the evidence that motivated it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    /// BLAKE3 over the other fields; see [`Proposal::fingerprint`].
    pub id: String,
    pub created_ms: i64,
    pub title: String,
    pub rationale: String,
    pub change: ChangeSet,
    pub target: Target,
    /// Evidence for the change (SI-02). At least one is required.
    pub evidence_refs: Vec<String>,
}

impl Proposal {
    /// Build and validate a proposal, then derive its id.
    pub fn new(
        created_ms: i64,
        title: impl Into<String>,
        rationale: impl Into<String>,
        change: ChangeSet,
        target: Target,
        evidence_refs: Vec<String>,
    ) -> Result<Self> {
        let mut proposal = Self {
            id: String::new(),
            created_ms,
            title: title.into(),
            rationale: rationale.into(),
            change,
            target,
            evidence_refs,
        };
        validate_proposal_content(&proposal, LoopLimits::default())?;
        proposal.id = proposal.fingerprint();
        Ok(proposal)
    }

    /// BLAKE3 over the versioned canonical bytes of every field except `id`.
    pub fn fingerprint(&self) -> String {
        #[derive(Serialize)]
        struct Digest<'a> {
            created_ms: i64,
            title: &'a str,
            rationale: &'a str,
            change: &'a ChangeSet,
            target: Target,
            evidence_refs: &'a [String],
        }

        let digest = Digest {
            created_ms: self.created_ms,
            title: &self.title,
            rationale: &self.rationale,
            change: &self.change,
            target: self.target,
            evidence_refs: &self.evidence_refs,
        };
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(PROPOSAL_HASH_PREFIX.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(
            &serde_json::to_vec(&digest).expect("a proposal has no unserializable value"),
        );
        blake3::hash(&bytes).to_hex().to_string()
    }
}

/// Validate a proposal against `limits`, including its derived id.
pub fn validate_proposal(proposal: &Proposal, limits: LoopLimits) -> Result<()> {
    let limits = limits.capped();
    validate_proposal_content(proposal, limits)?;
    if proposal.id.len() != 64 || !proposal.id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid("a proposal id is 64 hexadecimal characters"));
    }
    if proposal.id.to_ascii_lowercase() != proposal.fingerprint() {
        return Err(ZeroError::new(
            ErrorCode::TamperDetected,
            "proposal id does not match its content",
        ));
    }
    Ok(())
}

fn validate_proposal_content(proposal: &Proposal, limits: LoopLimits) -> Result<()> {
    if proposal.title.trim().is_empty() {
        return Err(invalid("a proposal title is not empty"));
    }
    if proposal.title.len() > MAX_TITLE_BYTES {
        return Err(limit(format!(
            "a proposal title is {} bytes; the cap is {MAX_TITLE_BYTES}",
            proposal.title.len()
        )));
    }
    if proposal.rationale.trim().is_empty() {
        return Err(invalid("a proposal rationale is not empty"));
    }
    if proposal.rationale.len() > MAX_RATIONALE_BYTES {
        return Err(limit(format!(
            "a proposal rationale is {} bytes; the cap is {MAX_RATIONALE_BYTES}",
            proposal.rationale.len()
        )));
    }
    validate_change(
        &proposal.change,
        limits.max_change_files,
        limits.max_change_bytes,
    )?;
    if proposal.evidence_refs.is_empty() {
        return Err(invalid(
            "a proposal needs at least one evidence ref; self-report is not evidence (SI-02)",
        ));
    }
    if proposal.evidence_refs.len() > limits.max_evidence_refs {
        return Err(limit(format!(
            "a proposal has {} evidence refs; the cap is {}",
            proposal.evidence_refs.len(),
            limits.max_evidence_refs
        )));
    }
    for reference in &proposal.evidence_refs {
        if reference.trim().is_empty() {
            return Err(invalid("an evidence ref is not empty"));
        }
        if reference.len() > MAX_EVIDENCE_REF_BYTES {
            return Err(limit(format!(
                "an evidence ref is {} bytes; the cap is {MAX_EVIDENCE_REF_BYTES}",
                reference.len()
            )));
        }
        if reference.contains('\0') {
            return Err(invalid("an evidence ref contains a NUL byte"));
        }
    }
    Ok(())
}

fn validate_change(change: &ChangeSet, max_files: usize, max_bytes: usize) -> Result<()> {
    if change.files.is_empty() {
        return Err(invalid("a change set needs at least one file"));
    }
    if change.files.len() > max_files {
        return Err(limit(format!(
            "a change set has {} files; the cap is {max_files}",
            change.files.len()
        )));
    }
    if change.description.trim().is_empty() {
        return Err(invalid("a change set description is not empty"));
    }
    if change.description.len() > MAX_DESCRIPTION_BYTES {
        return Err(limit(format!(
            "a change description is {} bytes; the cap is {MAX_DESCRIPTION_BYTES}",
            change.description.len()
        )));
    }
    let mut total = 0usize;
    for (path, contents) in &change.files {
        safe_relative_path(path)?;
        if contents.len() > MAX_CHANGE_FILE_BYTES {
            return Err(limit(format!(
                "change file `{path}` is {} bytes; the cap is {MAX_CHANGE_FILE_BYTES}",
                contents.len()
            )));
        }
        total += contents.len();
    }
    if total > max_bytes {
        return Err(limit(format!(
            "a change set is {total} bytes; the cap is {max_bytes}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Run-time bounds for one loop pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopLimits {
    /// Re-entry budget. One `run_loop` call consumes exactly one attempt.
    pub max_attempts: u32,
    /// Number of files the change and the executor may touch.
    pub max_change_files: usize,
    /// Total bytes the change may write.
    pub max_change_bytes: usize,
    /// Evidence references a proposal may carry.
    pub max_evidence_refs: usize,
}

impl Default for LoopLimits {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            max_change_files: MAX_CHANGE_FILES,
            max_change_bytes: MAX_CHANGE_BYTES,
            max_evidence_refs: MAX_EVIDENCE_REFS,
        }
    }
}

impl LoopLimits {
    /// Clamp every field to the module maximum, so no caller can ask for an
    /// unbounded loop or an unbounded change.
    pub fn capped(self) -> Self {
        Self {
            max_attempts: self.max_attempts.min(MAX_ATTEMPTS),
            max_change_files: self.max_change_files.min(MAX_CHANGE_FILES),
            max_change_bytes: self.max_change_bytes.min(MAX_CHANGE_BYTES),
            max_evidence_refs: self.max_evidence_refs.min(MAX_EVIDENCE_REFS),
        }
    }
}

// ---------------------------------------------------------------------------
// Seams
// ---------------------------------------------------------------------------

/// What the executor did inside the scratch workspace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRecord {
    /// Paths written, relative to the scratch workspace.
    pub files_written: Vec<String>,
    /// Bounded executor output. Never treated as evidence.
    pub output: String,
}

/// Applies a change inside a scratch workspace.
///
/// The loop creates a fresh workspace under [`scratch_root`](Self::scratch_root)
/// for every attempt and validates the reported paths. An executor is trusted
/// in-process code: this boundary does not sandbox a trait implementation that
/// ignores the workspace argument, which is T-SI-03/T-TRU-03's job.
pub trait ProposalExecutor {
    /// Base directory for scratch workspaces. It must already exist.
    fn scratch_root(&self) -> &Path;
    /// Apply the proposal's change inside `workspace` and report what it wrote.
    fn execute(&self, proposal: &Proposal, workspace: &Path) -> Result<ExecutionRecord>;
}

/// The result of building and testing the candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRecord {
    /// True only when the injected verifier ran its checks and they passed.
    pub passed: bool,
    /// Bounded detail for the record; never accepted as evidence on its own.
    pub detail: String,
}

/// Builds and tests a candidate workspace.
pub trait Verifier {
    fn verify(&self, workspace: &Path) -> Result<VerifyRecord>;
}

/// Runs the held-out suite for the baseline and the candidate.
///
/// Both reports must use the same pinned suite version. Implementations reuse
/// [`crate::eval_suite::run_suite`] or an equivalent trusted evaluator.
pub trait Evaluator {
    /// Score the unmodified baseline.
    fn baseline(&self) -> Result<EvalReport>;
    /// Score the candidate that was applied in `workspace`.
    fn candidate(&self, proposal: &Proposal, workspace: &Path) -> Result<EvalReport>;
}

/// Write a change set under `workspace`, refusing any path that escapes it.
///
/// Every key goes through [`safe_relative_path`], parent directories are
/// created inside the canonical workspace, and nothing is written when a path
/// is refused.
pub fn apply_change_set(change: &ChangeSet, workspace: &Path) -> Result<Vec<String>> {
    let root = workspace.canonicalize().map_err(|error| {
        ZeroError::new(
            ErrorCode::NotFound,
            format!(
                "scratch workspace `{}` is not available: {error}",
                workspace.display()
            ),
        )
    })?;
    if !root.is_dir() {
        return Err(invalid(format!(
            "scratch workspace `{}` is not a directory",
            workspace.display()
        )));
    }

    let mut written = Vec::with_capacity(change.files.len());
    for (path, contents) in &change.files {
        let relative = safe_relative_path(path)?;
        let target = root.join(&relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
            let canonical_parent = parent.canonicalize()?;
            if !canonical_parent.starts_with(&root) {
                return Err(ZeroError::new(
                    ErrorCode::PermissionDenied,
                    format!("change path `{path}` escapes the scratch workspace"),
                ));
            }
        }
        std::fs::write(&target, contents.as_bytes())?;
        written.push(path.clone());
    }
    Ok(written)
}

fn check_recorded_files(files: &[String], workspace: &Path) -> Result<()> {
    let root = workspace.canonicalize()?;
    for path in files {
        let relative = safe_relative_path(path)?;
        let target = root.join(&relative);
        let canonical = target.canonicalize().map_err(|_| {
            invalid(format!(
                "executor reported `{path}` but the file does not exist"
            ))
        })?;
        if !canonical.starts_with(&root) {
            return Err(invalid(format!(
                "executor reported `{path}` outside the scratch workspace"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// One captured file: relative path, size, and BLAKE3 digest of its contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedFile {
    pub path: String,
    pub bytes: u64,
    pub hash: String,
}

/// The evidence captured from the scratch workspace after verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureRecord {
    pub files: Vec<CapturedFile>,
    pub total_bytes: u64,
}

/// One bounded summary of the candidate and its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistilRecord {
    pub summary: String,
    pub truncated: bool,
}

/// The seed for the next iteration. It carries no authority; a caller starts a
/// new proposal from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReentrySeed {
    pub proposal_id: String,
    /// 1-based attempt this seed would start.
    pub next_attempt: u32,
    pub objective: String,
    pub evidence_refs: Vec<String>,
    /// True when the attempt budget is spent and no further pass is allowed.
    pub exhausted: bool,
}

// ---------------------------------------------------------------------------
// Decision and promotion
// ---------------------------------------------------------------------------

/// What the loop decided for one proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum LoopDecision {
    /// No regressions and at least one improvement on the held-out suite.
    Accepted {
        improvements: Vec<String>,
        baseline_version: String,
    },
    /// No promotion; the reason names the regression or the missing gain.
    Rejected {
        regressions: Vec<String>,
        reason: String,
    },
    /// A stage failed and the loop stopped before a promotion.
    Failed { stage: Stage, reason: String },
}

/// The human decision still required before anything reaches the real agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanGate {
    /// True when a human must approve before the change is applied.
    pub required: bool,
    /// Who decides and why.
    pub reason: String,
}

/// The loop's promotion input for T-SI-03.
///
/// `approved` is the automated gate: true only for an [`LoopDecision::Accepted`]
/// with both evaluation reports present. It never applies the change; the human
/// gate and the rollback plan belong to T-SI-03.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Promotion {
    pub proposal_id: String,
    pub approved: bool,
    pub gate: HumanGate,
}

/// Compute the promotion input for a finished loop state.
///
/// This function is pure: it reads the state and returns a [`Promotion`]. It
/// never writes a file, changes a prompt, or touches the evaluator.
pub fn promote(state: &LoopState) -> Promotion {
    let accepted = matches!(state.decision.as_ref(), Some(LoopDecision::Accepted { .. }))
        && state.eval_baseline.is_some()
        && state.eval_candidate.is_some();
    let (approved, gate) = if accepted {
        (
            true,
            HumanGate {
                required: true,
                reason:
                    "SI-03 human promotion: review the diff and the rollback plan, then approve"
                        .to_string(),
            },
        )
    } else {
        (
            false,
            HumanGate {
                required: false,
                reason: "no promotion is proposed".to_string(),
            },
        )
    };
    Promotion {
        proposal_id: state.proposal.id.clone(),
        approved,
        gate,
    }
}

// ---------------------------------------------------------------------------
// State and report
// ---------------------------------------------------------------------------

/// The loop stage. The declaration order is the execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Execute,
    Verify,
    Capture,
    Distil,
    Evaluate,
    Promote,
    Reenter,
}

impl Stage {
    /// Every stage in execution order.
    pub const ALL: [Stage; 7] = [
        Stage::Execute,
        Stage::Verify,
        Stage::Capture,
        Stage::Distil,
        Stage::Evaluate,
        Stage::Promote,
        Stage::Reenter,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::Verify => "verify",
            Self::Capture => "capture",
            Self::Distil => "distil",
            Self::Evaluate => "evaluate",
            Self::Promote => "promote",
            Self::Reenter => "reenter",
        }
    }
}

/// One stage outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum StageOutcome {
    Passed,
    Failed { reason: String },
}

/// One entry in the stage history, in execution order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageEvent {
    pub stage: Stage,
    pub outcome: StageOutcome,
    pub at_ms: i64,
}

/// Everything the loop knows about one proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopState {
    pub proposal: Proposal,
    /// The last stage reached; the stage that failed when the loop stopped.
    pub stage: Stage,
    /// Attempts consumed. One `run_loop` call consumes exactly one attempt.
    pub attempts: u32,
    pub eval_baseline: Option<EvalReport>,
    pub eval_candidate: Option<EvalReport>,
    pub decision: Option<LoopDecision>,
    pub history: Vec<StageEvent>,
}

/// The report of one loop pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopReport {
    pub state: LoopState,
    pub execution: Option<ExecutionRecord>,
    pub verification: Option<VerifyRecord>,
    pub capture: Option<CaptureRecord>,
    pub distil: Option<DistilRecord>,
    /// Always present; `approved` is false for a rejected or failed candidate.
    pub promotion: Option<Promotion>,
    /// Present after Reenter; absent when a stage failed.
    pub reentry: Option<ReentrySeed>,
}

impl LoopReport {
    /// The decision, once the loop has stopped.
    pub fn decision(&self) -> Option<&LoopDecision> {
        self.state.decision.as_ref()
    }

    /// True only for an accepted candidate.
    pub fn accepted(&self) -> bool {
        matches!(
            self.state.decision.as_ref(),
            Some(LoopDecision::Accepted { .. })
        )
    }
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

struct LoopRun {
    state: LoopState,
    execution: Option<ExecutionRecord>,
    verification: Option<VerifyRecord>,
    capture: Option<CaptureRecord>,
    distil: Option<DistilRecord>,
    reentry: Option<ReentrySeed>,
}

impl LoopRun {
    fn fail(mut self, stage: Stage, reason: String, clock: &dyn Clock) -> LoopReport {
        let (reason, _) = bounded(&reason, MAX_DETAIL_BYTES);
        self.state.stage = stage;
        self.state.history.push(StageEvent {
            stage,
            outcome: StageOutcome::Failed {
                reason: reason.clone(),
            },
            at_ms: clock.now().0,
        });
        self.state.decision = Some(LoopDecision::Failed { stage, reason });
        self.finish()
    }

    fn pass(&mut self, stage: Stage, clock: &dyn Clock) {
        self.state.stage = stage;
        self.state.history.push(StageEvent {
            stage,
            outcome: StageOutcome::Passed,
            at_ms: clock.now().0,
        });
    }

    fn finish(self) -> LoopReport {
        let promotion = promote(&self.state);
        LoopReport {
            state: self.state,
            execution: self.execution,
            verification: self.verification,
            capture: self.capture,
            distil: self.distil,
            promotion: Some(promotion),
            reentry: self.reentry,
        }
    }
}

/// Run one pass of the loop with the system clock.
///
/// A structurally invalid proposal or limit is an `Err`; a stage failure is a
/// [`LoopDecision::Failed`] inside the report. The loop never touches the real
/// agent: the only writes are inside the executor's scratch workspace.
pub fn run_loop(
    proposal: Proposal,
    executor: &dyn ProposalExecutor,
    verifier: &dyn Verifier,
    evaluator: &dyn Evaluator,
    limits: LoopLimits,
) -> Result<LoopReport> {
    run_loop_with_clock(
        proposal,
        executor,
        verifier,
        evaluator,
        limits,
        &SystemClock,
    )
}

/// [`run_loop`] with an injected clock, so a test can produce an identical
/// report twice.
pub fn run_loop_with_clock(
    proposal: Proposal,
    executor: &dyn ProposalExecutor,
    verifier: &dyn Verifier,
    evaluator: &dyn Evaluator,
    limits: LoopLimits,
    clock: &dyn Clock,
) -> Result<LoopReport> {
    let limits = limits.capped();
    validate_proposal(&proposal, limits)?;

    let state = LoopState {
        proposal,
        stage: Stage::Execute,
        attempts: 0,
        eval_baseline: None,
        eval_candidate: None,
        decision: None,
        history: Vec::new(),
    };
    let mut run = LoopRun {
        state,
        execution: None,
        verification: None,
        capture: None,
        distil: None,
        reentry: None,
    };

    if limits.max_attempts == 0 {
        return Ok(run.fail(
            Stage::Execute,
            "the attempt budget is zero".to_string(),
            clock,
        ));
    }
    run.state.attempts = 1;

    // Execute: a fresh workspace, a validated change, and a path check on what
    // the executor reports.
    let workspace = match create_scratch(
        executor.scratch_root(),
        &run.state.proposal,
        run.state.attempts,
    ) {
        Ok(workspace) => workspace,
        Err(error) => return Ok(run.fail(Stage::Execute, error.message().to_string(), clock)),
    };
    let execution = match executor.execute(&run.state.proposal, &workspace) {
        Ok(execution) => execution,
        Err(error) => {
            return Ok(run.fail(
                Stage::Execute,
                format!("executor failed: {}", error.code()),
                clock,
            ))
        }
    };
    let mut files = execution.files_written;
    files.sort();
    files.dedup();
    if files.is_empty() {
        return Ok(run.fail(
            Stage::Execute,
            "the executor wrote no files".to_string(),
            clock,
        ));
    }
    if files.len() > limits.max_change_files {
        return Ok(run.fail(
            Stage::Execute,
            format!(
                "the executor wrote {} files; the cap is {}",
                files.len(),
                limits.max_change_files
            ),
            clock,
        ));
    }
    if let Err(error) = check_recorded_files(&files, &workspace) {
        return Ok(run.fail(Stage::Execute, error.message().to_string(), clock));
    }
    let (output, _) = bounded(&execution.output, MAX_OUTPUT_BYTES);
    run.execution = Some(ExecutionRecord {
        files_written: files.clone(),
        output,
    });
    run.pass(Stage::Execute, clock);

    // Verify: a failed or errored verification stops the loop before any
    // evaluation, so a broken candidate can never be promoted.
    let mut verification = match verifier.verify(&workspace) {
        Ok(verification) => verification,
        Err(error) => {
            return Ok(run.fail(
                Stage::Verify,
                format!("verifier failed: {}", error.code()),
                clock,
            ))
        }
    };
    let (detail, _) = bounded(&verification.detail, MAX_DETAIL_BYTES);
    verification.detail = detail;
    if !verification.passed {
        return Ok(run.fail(Stage::Verify, verification.detail, clock));
    }
    run.verification = Some(verification);
    run.pass(Stage::Verify, clock);

    // Capture: hash every file the executor reported, inside the workspace.
    let capture = match capture_workspace(&workspace, &files) {
        Ok(capture) => capture,
        Err(error) => return Ok(run.fail(Stage::Capture, error.message().to_string(), clock)),
    };
    run.capture = Some(capture);
    run.pass(Stage::Capture, clock);

    // Distil: one bounded summary, deterministic from the record.
    let distil = distil(
        &run.state.proposal,
        run.verification
            .as_ref()
            .expect("verification passed before distil"),
        run.capture.as_ref().expect("capture passed before distil"),
    );
    run.distil = Some(distil);
    run.pass(Stage::Distil, clock);

    // Evaluate: baseline and candidate on the same suite version.
    let baseline = match evaluator.baseline() {
        Ok(report) => report,
        Err(error) => {
            return Ok(run.fail(
                Stage::Evaluate,
                format!("baseline evaluation failed: {}", error.code()),
                clock,
            ))
        }
    };
    let candidate = match evaluator.candidate(&run.state.proposal, &workspace) {
        Ok(report) => report,
        Err(error) => {
            return Ok(run.fail(
                Stage::Evaluate,
                format!("candidate evaluation failed: {}", error.code()),
                clock,
            ))
        }
    };
    if baseline.suite_version != candidate.suite_version {
        return Ok(run.fail(
            Stage::Evaluate,
            format!(
                "baseline suite `{}` and candidate suite `{}` are not the same version",
                baseline.suite_version, candidate.suite_version
            ),
            clock,
        ));
    }

    let delta = compare(&baseline, &candidate);
    run.state.eval_baseline = Some(baseline.clone());
    run.state.eval_candidate = Some(candidate);
    run.pass(Stage::Evaluate, clock);

    let decision = if !delta.regressions.is_empty() {
        LoopDecision::Rejected {
            regressions: delta.regressions,
            reason: "the candidate regressed a held-out task".to_string(),
        }
    } else if delta.improvements.is_empty() {
        LoopDecision::Rejected {
            regressions: Vec::new(),
            reason: "the candidate has no measurable improvement".to_string(),
        }
    } else {
        LoopDecision::Accepted {
            improvements: delta.improvements,
            baseline_version: baseline.suite_version,
        }
    };
    let accepted = matches!(decision, LoopDecision::Accepted { .. });
    run.state.decision = Some(decision);

    if accepted {
        run.pass(Stage::Promote, clock);
    }

    // Re-enter: record the seed for the next pass. It carries no authority.
    let reentry = reentry_seed(&run.state, limits);
    run.reentry = Some(reentry);
    run.pass(Stage::Reenter, clock);

    Ok(run.finish())
}

fn create_scratch(root: &Path, proposal: &Proposal, attempt: u32) -> Result<PathBuf> {
    if !root.is_dir() {
        return Err(invalid(format!(
            "executor scratch root `{}` is not a directory",
            root.display()
        )));
    }
    let workspace = root.join(format!("attempt-{attempt:04}-{}", proposal.id));
    match std::fs::symlink_metadata(&workspace) {
        Ok(_) => {
            return Err(ZeroError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "scratch workspace `{}` already exists; pass a fresh root",
                    workspace.display()
                ),
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    std::fs::create_dir_all(&workspace)?;
    Ok(workspace)
}

fn capture_workspace(workspace: &Path, files: &[String]) -> Result<CaptureRecord> {
    let root = workspace.canonicalize()?;
    let mut captured = Vec::with_capacity(files.len());
    let mut total_bytes = 0u64;
    for path in files {
        let relative = safe_relative_path(path)?;
        let target = root.join(&relative);
        let canonical = target.canonicalize().map_err(|_| {
            invalid(format!(
                "captured file `{path}` is missing from the scratch workspace"
            ))
        })?;
        if !canonical.starts_with(&root) {
            return Err(invalid(format!(
                "captured file `{path}` escapes the scratch workspace"
            )));
        }
        let file = std::fs::File::open(&canonical)?;
        let mut bytes = Vec::new();
        file.take((MAX_CHANGE_FILE_BYTES as u64) + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_CHANGE_FILE_BYTES {
            return Err(limit(format!(
                "captured file `{path}` grew past {MAX_CHANGE_FILE_BYTES} bytes"
            )));
        }
        total_bytes += bytes.len() as u64;
        captured.push(CapturedFile {
            path: path.clone(),
            bytes: bytes.len() as u64,
            hash: blake3::hash(&bytes).to_hex().to_string(),
        });
    }
    Ok(CaptureRecord {
        files: captured,
        total_bytes,
    })
}

fn distil(
    proposal: &Proposal,
    verification: &VerifyRecord,
    capture: &CaptureRecord,
) -> DistilRecord {
    let summary = format!(
        "{}: {} change. {} ({} file(s), {} bytes). Verification: {}.",
        proposal.title,
        proposal.target.as_str(),
        proposal.change.description,
        capture.files.len(),
        capture.total_bytes,
        verification.detail
    );
    let (summary, truncated) = bounded(&summary, MAX_SUMMARY_BYTES);
    DistilRecord { summary, truncated }
}

fn reentry_seed(state: &LoopState, limits: LoopLimits) -> ReentrySeed {
    let objective = match &state.decision {
        Some(LoopDecision::Accepted { improvements, .. }) => format!(
            "keep the accepted change and extend it to the next failing task: {}",
            improvements.join(", ")
        ),
        Some(LoopDecision::Rejected {
            regressions,
            reason,
        }) if !regressions.is_empty() => {
            format!(
                "repair the regression in {}: {reason}",
                regressions.join(", ")
            )
        }
        Some(LoopDecision::Rejected { reason, .. }) => {
            format!("try a different bounded change: {reason}")
        }
        Some(LoopDecision::Failed { stage, reason }) => {
            format!("retry after the {} stage: {reason}", stage.as_str())
        }
        None => "retry the loop".to_string(),
    };
    let (objective, _) = bounded(&objective, MAX_SUMMARY_BYTES);
    ReentrySeed {
        proposal_id: state.proposal.id.clone(),
        next_attempt: state.attempts.saturating_add(1),
        objective,
        evidence_refs: state.proposal.evidence_refs.clone(),
        exhausted: state.attempts >= limits.max_attempts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval_suite::{
        run_suite_with_clock, CandidateOutput, CandidateRunner, Check, EvalSuite, EvalTask,
        Fixture, PublicTask, EVAL_SUITE_SCHEMA_VERSION,
    };
    use std::cell::Cell;
    use std::collections::BTreeSet;
    use zero_types::id::FakeClock;

    const NOW: i64 = 1_700_000_000_000;

    struct ScratchExecutor {
        root: PathBuf,
        calls: Cell<usize>,
    }

    impl ScratchExecutor {
        fn new(root: PathBuf) -> Self {
            Self {
                root,
                calls: Cell::new(0),
            }
        }
    }

    impl ProposalExecutor for ScratchExecutor {
        fn scratch_root(&self) -> &Path {
            &self.root
        }

        fn execute(&self, proposal: &Proposal, workspace: &Path) -> Result<ExecutionRecord> {
            self.calls.set(self.calls.get() + 1);
            let files = apply_change_set(&proposal.change, workspace)?;
            Ok(ExecutionRecord {
                files_written: files,
                output: "applied".to_string(),
            })
        }
    }

    struct OutsideExecutor {
        root: PathBuf,
    }

    impl ProposalExecutor for OutsideExecutor {
        fn scratch_root(&self) -> &Path {
            &self.root
        }

        fn execute(&self, _proposal: &Proposal, _workspace: &Path) -> Result<ExecutionRecord> {
            Ok(ExecutionRecord {
                files_written: vec!["../escape.txt".to_string()],
                output: String::new(),
            })
        }
    }

    struct FixedVerifier {
        passed: bool,
        calls: Cell<usize>,
    }

    impl FixedVerifier {
        fn new(passed: bool) -> Self {
            Self {
                passed,
                calls: Cell::new(0),
            }
        }
    }

    impl Verifier for FixedVerifier {
        fn verify(&self, _workspace: &Path) -> Result<VerifyRecord> {
            self.calls.set(self.calls.get() + 1);
            Ok(VerifyRecord {
                passed: self.passed,
                detail: if self.passed {
                    "build and tests passed".to_string()
                } else {
                    "build failed".to_string()
                },
            })
        }
    }

    struct FailingRunner {
        failing: BTreeSet<String>,
    }

    impl CandidateRunner for FailingRunner {
        fn run(&self, task: &PublicTask, workspace: &Path) -> Result<CandidateOutput> {
            if self.failing.contains(&task.id) {
                Ok(CandidateOutput::new(1, "failed\n", ""))
            } else {
                std::fs::write(workspace.join("answer.txt"), "42\n")?;
                Ok(CandidateOutput::new(0, "done\n", ""))
            }
        }
    }

    struct FixtureEvaluator {
        suite: EvalSuite,
        baseline_failing: BTreeSet<String>,
        candidate_failing: BTreeSet<String>,
        baseline_scratch: PathBuf,
        candidate_scratch: PathBuf,
        baseline_calls: Cell<usize>,
        candidate_calls: Cell<usize>,
    }

    impl FixtureEvaluator {
        fn new(
            suite: EvalSuite,
            baseline_failing: &[&str],
            candidate_failing: &[&str],
            base: &Path,
        ) -> Self {
            Self {
                suite,
                baseline_failing: baseline_failing
                    .iter()
                    .map(|id| (*id).to_string())
                    .collect(),
                candidate_failing: candidate_failing
                    .iter()
                    .map(|id| (*id).to_string())
                    .collect(),
                baseline_scratch: base.join("baseline"),
                candidate_scratch: base.join("candidate"),
                baseline_calls: Cell::new(0),
                candidate_calls: Cell::new(0),
            }
        }
    }

    impl Evaluator for FixtureEvaluator {
        fn baseline(&self) -> Result<EvalReport> {
            self.baseline_calls.set(self.baseline_calls.get() + 1);
            run_suite_with_clock(
                &self.suite,
                &FailingRunner {
                    failing: self.baseline_failing.clone(),
                },
                &self.baseline_scratch,
                &FakeClock::at(NOW),
            )
        }

        fn candidate(&self, _proposal: &Proposal, _workspace: &Path) -> Result<EvalReport> {
            self.candidate_calls.set(self.candidate_calls.get() + 1);
            run_suite_with_clock(
                &self.suite,
                &FailingRunner {
                    failing: self.candidate_failing.clone(),
                },
                &self.candidate_scratch,
                &FakeClock::at(NOW),
            )
        }
    }

    fn fixture_suite() -> EvalSuite {
        let task = |id: &str| EvalTask {
            id: id.to_string(),
            prompt: format!("solve {id}"),
            fixture: Fixture::default(),
            checks: vec![
                Check::ExitCode { code: 0 },
                Check::FileContains {
                    path: "answer.txt".to_string(),
                    needle: "42".to_string(),
                },
            ],
        };
        EvalSuite {
            schema_version: EVAL_SUITE_SCHEMA_VERSION,
            suite_version: "si-fixture-1".to_string(),
            created_ms: NOW,
            tasks: vec![task("write-answer"), task("second")],
        }
    }

    fn proposal(title: &str) -> Proposal {
        let mut files = BTreeMap::new();
        files.insert("prompt/system.md".to_string(), format!("{title}\n"));
        Proposal::new(
            NOW,
            title,
            "diagnosis: the same task failed twice in the audit fixture",
            ChangeSet {
                files,
                description: "one bounded prompt fix plus its regression note".to_string(),
            },
            Target::AgentPrompt,
            vec!["audit:run-1/finding-1".to_string()],
        )
        .expect("valid proposal")
    }

    fn stages(report: &LoopReport) -> Vec<Stage> {
        report
            .state
            .history
            .iter()
            .map(|event| event.stage)
            .collect()
    }

    fn scratch_base(dir: &tempfile::TempDir) -> PathBuf {
        let root = dir.path().join("scratch");
        std::fs::create_dir_all(&root).expect("scratch root");
        root
    }

    #[test]
    fn fixture_accepts_a_candidate_that_passes_both_tasks() {
        let dir = tempfile::tempdir().expect("temp dir");
        let executor = ScratchExecutor::new(scratch_base(&dir));
        let evaluator = FixtureEvaluator::new(fixture_suite(), &["second"], &[], dir.path());

        let report = run_loop_with_clock(
            proposal("fix the second task"),
            &executor,
            &FixedVerifier::new(true),
            &evaluator,
            LoopLimits::default(),
            &FakeClock::at(NOW),
        )
        .expect("loop");

        assert_eq!(
            stages(&report),
            vec![
                Stage::Execute,
                Stage::Verify,
                Stage::Capture,
                Stage::Distil,
                Stage::Evaluate,
                Stage::Promote,
                Stage::Reenter,
            ]
        );
        match report.decision() {
            Some(LoopDecision::Accepted {
                improvements,
                baseline_version,
            }) => {
                assert_eq!(improvements, &vec!["second".to_string()]);
                assert_eq!(baseline_version, "si-fixture-1");
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
        assert!(report.accepted());
        assert_eq!(report.state.attempts, 1);
        assert_eq!(evaluator.baseline_calls.get(), 1);
        assert_eq!(evaluator.candidate_calls.get(), 1);

        let promotion = report.promotion.as_ref().expect("promotion input");
        assert!(promotion.approved, "the automated gate accepts");
        assert!(promotion.gate.required, "SI-03 still requires a human");
        assert_eq!(promotion.proposal_id, report.state.proposal.id);

        let reentry = report.reentry.as_ref().expect("reentry seed");
        assert_eq!(reentry.next_attempt, 2);
        assert!(!reentry.exhausted);
        assert!(
            reentry.objective.contains("second"),
            "{}",
            reentry.objective
        );
        assert_eq!(reentry.evidence_refs, vec!["audit:run-1/finding-1"]);
    }

    #[test]
    fn fixture_rejects_a_candidate_that_regresses_a_task() {
        let dir = tempfile::tempdir().expect("temp dir");
        let executor = ScratchExecutor::new(scratch_base(&dir));
        let evaluator = FixtureEvaluator::new(fixture_suite(), &[], &["second"], dir.path());

        let report = run_loop_with_clock(
            proposal("regressing change"),
            &executor,
            &FixedVerifier::new(true),
            &evaluator,
            LoopLimits::default(),
            &FakeClock::at(NOW),
        )
        .expect("loop");

        assert_eq!(
            stages(&report),
            vec![
                Stage::Execute,
                Stage::Verify,
                Stage::Capture,
                Stage::Distil,
                Stage::Evaluate,
                Stage::Reenter,
            ],
            "a rejected candidate never reaches Promote"
        );
        match report.decision() {
            Some(LoopDecision::Rejected {
                regressions,
                reason,
            }) => {
                assert_eq!(regressions, &vec!["second".to_string()]);
                assert!(reason.contains("regressed"), "{reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert!(!report.accepted());
        let promotion = report.promotion.as_ref().expect("promotion input");
        assert!(!promotion.approved, "a rejected candidate is not promoted");
        assert!(!promotion.gate.required);
        let reentry = report.reentry.as_ref().expect("reentry seed");
        assert!(
            reentry.objective.contains("second"),
            "{}",
            reentry.objective
        );
    }

    #[test]
    fn stage_history_is_the_documented_order() {
        assert_eq!(
            Stage::ALL,
            [
                Stage::Execute,
                Stage::Verify,
                Stage::Capture,
                Stage::Distil,
                Stage::Evaluate,
                Stage::Promote,
                Stage::Reenter,
            ]
        );
        assert_eq!(Stage::ALL.len(), 7);
        assert_eq!(
            Stage::ALL.map(Stage::as_str),
            ["execute", "verify", "capture", "distil", "evaluate", "promote", "reenter"]
        );

        let dir = tempfile::tempdir().expect("temp dir");
        let executor = ScratchExecutor::new(scratch_base(&dir));
        let evaluator = FixtureEvaluator::new(fixture_suite(), &["second"], &[], dir.path());
        let accepted = run_loop_with_clock(
            proposal("accepted"),
            &executor,
            &FixedVerifier::new(true),
            &evaluator,
            LoopLimits::default(),
            &FakeClock::at(NOW),
        )
        .expect("loop");
        let positions: Vec<usize> = stages(&accepted)
            .iter()
            .map(|stage| {
                Stage::ALL
                    .iter()
                    .position(|candidate| candidate == stage)
                    .expect("known")
            })
            .collect();
        let mut sorted = positions.clone();
        sorted.sort_unstable();
        assert_eq!(positions, sorted, "history follows Stage::ALL");
    }

    #[test]
    fn a_failed_verification_stops_before_evaluate() {
        let dir = tempfile::tempdir().expect("temp dir");
        let executor = ScratchExecutor::new(scratch_base(&dir));
        let verifier = FixedVerifier::new(false);
        let evaluator = FixtureEvaluator::new(fixture_suite(), &[], &[], dir.path());

        let report = run_loop_with_clock(
            proposal("broken build"),
            &executor,
            &verifier,
            &evaluator,
            LoopLimits::default(),
            &FakeClock::at(NOW),
        )
        .expect("loop");

        assert_eq!(stages(&report), vec![Stage::Execute, Stage::Verify]);
        assert_eq!(verifier.calls.get(), 1);
        assert_eq!(evaluator.baseline_calls.get(), 0);
        assert_eq!(evaluator.candidate_calls.get(), 0);
        assert!(report.state.eval_baseline.is_none());
        assert!(report.state.eval_candidate.is_none());
        assert!(report.reentry.is_none(), "a failed loop does not re-enter");
        assert!(matches!(
            report.decision(),
            Some(LoopDecision::Failed {
                stage: Stage::Verify,
                ..
            })
        ));
        let promotion = report.promotion.as_ref().expect("promotion input");
        assert!(!promotion.approved);
    }

    #[test]
    fn promotion_requires_both_evaluation_reports() {
        let mut state = LoopState {
            proposal: proposal("promotion"),
            stage: Stage::Evaluate,
            attempts: 1,
            eval_baseline: None,
            eval_candidate: None,
            decision: Some(LoopDecision::Accepted {
                improvements: vec!["second".to_string()],
                baseline_version: "si-fixture-1".to_string(),
            }),
            history: Vec::new(),
        };
        assert!(
            !promote(&state).approved,
            "an accepted label without reports is not promotion evidence"
        );
        assert!(!promote(&state).gate.required);

        state.eval_baseline = Some(EvalReport {
            suite_version: "si-fixture-1".to_string(),
            passed: 1,
            failed: 1,
            task_results: Vec::new(),
            started: NOW,
            finished: NOW,
        });
        assert!(
            !promote(&state).approved,
            "a candidate report is still missing"
        );
        state.eval_candidate = state.eval_baseline.clone();
        let promotion = promote(&state);
        assert!(promotion.approved);
        assert!(promotion.gate.required);
        assert!(promotion.gate.reason.contains("SI-03"));
    }

    #[test]
    fn attempts_are_bounded() {
        let dir = tempfile::tempdir().expect("temp dir");
        let executor = ScratchExecutor::new(scratch_base(&dir));
        let evaluator = FixtureEvaluator::new(fixture_suite(), &[], &[], dir.path());
        let report = run_loop_with_clock(
            proposal("no budget"),
            &executor,
            &FixedVerifier::new(true),
            &evaluator,
            LoopLimits {
                max_attempts: 0,
                ..LoopLimits::default()
            },
            &FakeClock::at(NOW),
        )
        .expect("loop");

        assert_eq!(report.state.attempts, 0);
        assert_eq!(
            report.state.history,
            vec![StageEvent {
                stage: Stage::Execute,
                outcome: StageOutcome::Failed {
                    reason: "the attempt budget is zero".to_string(),
                },
                at_ms: NOW,
            }]
        );
        assert_eq!(executor.calls.get(), 0, "no executor work without budget");
        assert!(matches!(
            report.decision(),
            Some(LoopDecision::Failed {
                stage: Stage::Execute,
                ..
            })
        ));
        assert!(report.reentry.is_none());

        assert_eq!(
            LoopLimits {
                max_attempts: u32::MAX,
                ..LoopLimits::default()
            }
            .capped()
            .max_attempts,
            MAX_ATTEMPTS,
            "the caller cannot ask for an unbounded loop"
        );
    }

    #[test]
    fn evidence_refs_are_required() {
        let error = Proposal::new(
            NOW,
            "no evidence",
            "a diagnosis without a reference",
            ChangeSet {
                files: BTreeMap::from([("prompt/system.md".to_string(), "x\n".to_string())]),
                description: "bounded".to_string(),
            },
            Target::AgentPrompt,
            Vec::new(),
        )
        .expect_err("no evidence is refused");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("evidence"), "{}", error.message());

        let mut unchecked = proposal("evidence");
        unchecked.evidence_refs.clear();
        unchecked.id = unchecked.fingerprint();
        let dir = tempfile::tempdir().expect("temp dir");
        let executor = ScratchExecutor::new(scratch_base(&dir));
        let evaluator = FixtureEvaluator::new(fixture_suite(), &[], &[], dir.path());
        let error = run_loop_with_clock(
            unchecked,
            &executor,
            &FixedVerifier::new(true),
            &evaluator,
            LoopLimits::default(),
            &FakeClock::at(NOW),
        )
        .expect_err("the loop refuses a proposal without evidence");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert_eq!(executor.calls.get(), 0);
    }

    #[test]
    fn change_paths_cannot_escape_the_scratch_workspace() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = scratch_base(&dir);
        let change = ChangeSet {
            files: BTreeMap::from([("../escape.txt".to_string(), "x".to_string())]),
            description: "escape".to_string(),
        };
        let error = apply_change_set(&change, &root).expect_err("escape is refused");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(!dir.path().join("escape.txt").exists());

        let mut raw = proposal("escape proposal");
        raw.change
            .files
            .insert("../escape.txt".to_string(), "x".to_string());
        raw.id = raw.fingerprint();
        let executor = ScratchExecutor::new(root);
        let evaluator = FixtureEvaluator::new(fixture_suite(), &[], &[], dir.path());
        let error = run_loop_with_clock(
            raw,
            &executor,
            &FixedVerifier::new(true),
            &evaluator,
            LoopLimits::default(),
            &FakeClock::at(NOW),
        )
        .expect_err("an unsafe change path fails validation");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert_eq!(executor.calls.get(), 0);
    }

    #[test]
    fn an_executor_reporting_an_outside_path_stops_the_loop() {
        let dir = tempfile::tempdir().expect("temp dir");
        let executor = OutsideExecutor {
            root: scratch_base(&dir),
        };
        let verifier = FixedVerifier::new(true);
        let evaluator = FixtureEvaluator::new(fixture_suite(), &[], &[], dir.path());

        let report = run_loop_with_clock(
            proposal("outside path"),
            &executor,
            &verifier,
            &evaluator,
            LoopLimits::default(),
            &FakeClock::at(NOW),
        )
        .expect("loop");

        assert_eq!(stages(&report), vec![Stage::Execute]);
        assert_eq!(verifier.calls.get(), 0);
        assert_eq!(evaluator.baseline_calls.get(), 0);
        assert!(matches!(
            report.decision(),
            Some(LoopDecision::Failed {
                stage: Stage::Execute,
                ..
            })
        ));
        assert!(!report.promotion.as_ref().expect("promotion input").approved);
    }

    #[test]
    fn ids_and_reports_are_deterministic() {
        let left_proposal = proposal("same content");
        let right_proposal = proposal("same content");
        let other = proposal("different content");
        assert_eq!(left_proposal.id, right_proposal.id);
        assert_ne!(left_proposal.id, other.id);
        assert_eq!(left_proposal.id.len(), 64);

        let left_dir = tempfile::tempdir().expect("left dir");
        let right_dir = tempfile::tempdir().expect("right dir");
        let left = run_loop_with_clock(
            left_proposal,
            &ScratchExecutor::new(scratch_base(&left_dir)),
            &FixedVerifier::new(true),
            &FixtureEvaluator::new(fixture_suite(), &["second"], &[], left_dir.path()),
            LoopLimits::default(),
            &FakeClock::at(NOW),
        )
        .expect("left loop");
        let right = run_loop_with_clock(
            right_proposal,
            &ScratchExecutor::new(scratch_base(&right_dir)),
            &FixedVerifier::new(true),
            &FixtureEvaluator::new(fixture_suite(), &["second"], &[], right_dir.path()),
            LoopLimits::default(),
            &FakeClock::at(NOW),
        )
        .expect("right loop");

        assert_eq!(left, right);
        assert_eq!(
            serde_json::to_string(&left).expect("left json"),
            serde_json::to_string(&right).expect("right json")
        );
    }

    #[test]
    fn reenter_seeds_the_next_iteration() {
        let dir = tempfile::tempdir().expect("temp dir");
        let executor = ScratchExecutor::new(scratch_base(&dir));
        let evaluator = FixtureEvaluator::new(fixture_suite(), &["second"], &[], dir.path());
        let report = run_loop_with_clock(
            proposal("reentry"),
            &executor,
            &FixedVerifier::new(true),
            &evaluator,
            LoopLimits {
                max_attempts: 1,
                ..LoopLimits::default()
            },
            &FakeClock::at(NOW),
        )
        .expect("loop");

        let reentry = report.reentry.as_ref().expect("seed");
        assert_eq!(reentry.next_attempt, 2);
        assert!(reentry.exhausted, "the budget of one attempt is spent");
        assert_eq!(reentry.proposal_id, report.state.proposal.id);
        assert_eq!(reentry.evidence_refs, report.state.proposal.evidence_refs);
        assert!(!reentry.objective.is_empty());
        assert!(reentry.objective.len() <= MAX_SUMMARY_BYTES);
    }

    #[test]
    fn proposal_bounds_are_enforced() {
        let mut files = BTreeMap::new();
        for index in 0..=MAX_CHANGE_FILES {
            files.insert(format!("prompt/{index}.md"), "x".to_string());
        }
        let error = Proposal::new(
            NOW,
            "too many files",
            "rationale",
            ChangeSet {
                files,
                description: "bounded".to_string(),
            },
            Target::Skill,
            vec!["audit:run-1/finding-1".to_string()],
        )
        .expect_err("file cap");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);

        let error = Proposal::new(
            NOW,
            "too many bytes",
            "rationale",
            ChangeSet {
                files: BTreeMap::from([(
                    "prompt/big.md".to_string(),
                    "x".repeat(MAX_CHANGE_FILE_BYTES + 1),
                )]),
                description: "bounded".to_string(),
            },
            Target::ToolPolicy,
            vec!["audit:run-1/finding-1".to_string()],
        )
        .expect_err("file byte cap");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);

        let mut tampered = proposal("tampered");
        tampered.title.push_str(" edited");
        let error = validate_proposal(&tampered, LoopLimits::default())
            .expect_err("an edited title invalidates the id");
        assert_eq!(error.code(), ErrorCode::TamperDetected);
    }

    #[test]
    fn the_module_holds_no_network_or_router_api() {
        let source = include_str!("self_improve.rs");
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
                "self_improve must stay offline; found `{token}`"
            );
        }
    }
}
