//! Coverage-led hunting waves (SR-04, SR-05).
//!
//! A wave assigns ledger units to hunting agents, collects their
//! [`CandidateFinding`]s, applies the evidence bar, and hands each surviving
//! candidate to an independent [`Critic`]. Only an accepting critic turns a
//! candidate into a confirmed [`Finding`]; rejection refutes the unit and
//! `needs_evidence` defers it.
//!
//! The module is deliberately structural: a candidate must name a lower-trust
//! principal, the crossed boundary, at least one canonical reference inside the
//! unit's starting or reviewed paths, and a concrete result. Rejections are
//! typed `zero.fnd.invalid_input` errors that name the candidate and the failed
//! field; scanned file text is never repeated.
//!
//! Agents and critics are seams, not implementations: [`HuntAgent`] and
//! [`AgentPool`] are injected per wave, and [`Critic`] is a separate object. A
//! wave refuses to start when the critic carries the same label as the hunter,
//! so validation cannot collapse into the pass that produced the candidate.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use zero_types::error::Result;

use crate::ledger::{invalid, validate, CoverageLedger, LedgerUnit, UnitStatus};
use crate::schema::{unix_now_ms, CanonicalRef, Finding, FindingStatus, ReviewProfile, Severity};

/// Longest reason string copied from an agent or critic into a report.
pub const MAX_REASON_CHARS: usize = 240;

/// One candidate produced by a hunting agent, before the evidence bar and the
/// critic pass.
///
/// Field order mirrors the documented schema. `evidence_refs` are parsed
/// canonical references, so an invalid reference cannot reach a wave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateFinding {
    pub id: String,
    pub unit_id: String,
    pub title: String,
    pub severity: Severity,
    /// The principal on the untrusted side of the crossed boundary.
    pub lower_trust_principal: String,
    /// The boundary the candidate claims to cross; must match the unit.
    pub boundary: String,
    /// What happens when the input is attacker-controlled.
    pub concrete_result: String,
    pub evidence_refs: Vec<CanonicalRef>,
    #[serde(default)]
    pub checks: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

/// Apply the SR-05 evidence bar to one candidate against its unit.
///
/// Rejects, with `zero.fnd.invalid_input` naming the candidate and the failed
/// field:
///
/// - an empty `id`, `title`, `lower_trust_principal`, `boundary`, or
///   `concrete_result`;
/// - a `unit_id` that does not name `unit`;
/// - a boundary that does not match the unit's boundary (the message lists
///   both sides of the mismatch);
/// - a severity above `info` with no concrete result, so a `critical` claim
///   can never rest on impact text that is absent;
/// - no evidence ref inside the unit's starting or reviewed paths, an empty
///   evidence list, or a duplicate reference;
/// - an empty entry in `checks`.
///
/// Requirement references are legal evidence but do not satisfy the in-unit
/// path rule on their own.
pub fn validate_candidate(candidate: &CandidateFinding, unit: &LedgerUnit) -> Result<()> {
    if candidate.id.trim().is_empty() {
        return Err(invalid("candidate has an empty `id`"));
    }
    if candidate.unit_id != unit.id {
        return Err(invalid(format!(
            "candidate `{}` field `unit_id` names `{}` but the unit is `{}`",
            candidate.id, candidate.unit_id, unit.id
        )));
    }
    if candidate.title.trim().is_empty() {
        return Err(invalid(format!(
            "candidate `{}` has an empty `title`",
            candidate.id
        )));
    }
    if candidate.lower_trust_principal.trim().is_empty() {
        return Err(invalid(format!(
            "candidate `{}` field `lower_trust_principal` is empty; the evidence bar needs a named lower-trust principal",
            candidate.id
        )));
    }

    let boundary = candidate.boundary.trim();
    if boundary.is_empty() {
        return Err(invalid(format!(
            "candidate `{}` field `boundary` is empty",
            candidate.id
        )));
    }
    if boundary != unit.boundary {
        return Err(invalid(format!(
            "candidate `{}` field `boundary` is `{boundary}` but unit `{}` crosses `{}`",
            candidate.id, unit.id, unit.boundary
        )));
    }

    let has_result = !candidate.concrete_result.trim().is_empty();
    if candidate.severity > Severity::Info && !has_result {
        return Err(invalid(format!(
            "candidate `{}` field `concrete_result` is empty; severity {} cannot exceed the demonstrated impact",
            candidate.id,
            candidate.severity.as_str()
        )));
    }
    if !has_result {
        return Err(invalid(format!(
            "candidate `{}` field `concrete_result` is empty; a candidate must name a concrete result",
            candidate.id
        )));
    }

    if candidate.evidence_refs.is_empty() {
        return Err(invalid(format!(
            "candidate `{}` field `evidence_refs` is empty",
            candidate.id
        )));
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for reference in &candidate.evidence_refs {
        if !seen.insert(reference.canonical()) {
            return Err(invalid(format!(
                "candidate `{}` field `evidence_refs` lists duplicate ref `{reference}`",
                candidate.id
            )));
        }
    }
    if !evidence_inside_unit(candidate, unit) {
        return Err(invalid(format!(
            "candidate `{}` field `evidence_refs` has no ref inside unit `{}`'s starting or reviewed paths",
            candidate.id, unit.id
        )));
    }

    if candidate.checks.iter().any(|check| check.trim().is_empty()) {
        return Err(invalid(format!(
            "candidate `{}` field `checks` has an empty entry",
            candidate.id
        )));
    }
    Ok(())
}

fn evidence_inside_unit(candidate: &CandidateFinding, unit: &LedgerUnit) -> bool {
    let mut allowed: BTreeSet<&str> = unit.starting_paths.iter().map(String::as_str).collect();
    allowed.extend(unit.reviewed_paths.iter().map(String::as_str));
    candidate.evidence_refs.iter().any(|reference| {
        reference
            .path_parts()
            .is_some_and(|(path, _, _)| allowed.contains(path))
    })
}

// ---------------------------------------------------------------------------
// Agent and critic seams
// ---------------------------------------------------------------------------

/// One hunting agent. Tests script it; production code injects a model-backed
/// implementation.
///
/// The label is the unit owner recorded in the ledger and the identity compared
/// with the critic's label.
pub trait HuntAgent {
    fn label(&self) -> &str;
    fn hunt(&self, unit: &LedgerUnit) -> Result<Vec<CandidateFinding>>;
}

/// Supplies the hunting agent for a unit.
///
/// A pool may return a distinct agent per unit or one shared scripted agent.
/// The pool label names the hunter family for the critic-identity check.
pub trait AgentPool {
    fn label(&self) -> &str;
    fn agent(&self, unit: &LedgerUnit) -> &dyn HuntAgent;
}

/// The critic's decision on one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CriticVerdict {
    /// The candidate becomes a confirmed finding.
    Accept,
    /// The candidate is refuted and the reason is kept.
    Reject { reason: String },
    /// The candidate needs more evidence and the unit is deferred.
    NeedsEvidence { reason: String },
}

/// Independent validation of one candidate (SR-04).
///
/// The critic is a different object from the hunter. This module enforces that
/// structurally by comparing labels before a wave starts; a critic that accepts
/// without inspecting the evidence refs is still structurally accepted, because
/// [`validate_candidate`] already ran on every ref before this call.
pub trait Critic {
    fn label(&self) -> &str;
    fn review(&self, candidate: &CandidateFinding, unit: &LedgerUnit) -> CriticVerdict;
}

// ---------------------------------------------------------------------------
// Waves
// ---------------------------------------------------------------------------

/// One hunting wave: a bounded list of units and an agent cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HuntWave {
    pub wave_id: String,
    /// Unit ids in request order; duplicates are collapsed, keeping the first.
    pub units: Vec<String>,
    /// Maximum distinct agents this wave may borrow.
    pub agent_cap: usize,
}

/// Caps applied to one wave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaveLimits {
    /// Units this wave may run. Units past the cap are not run at all.
    pub max_units: usize,
    /// Distinct agents the wave may borrow.
    pub max_agents: usize,
}

impl WaveLimits {
    /// Take the unit and agent caps from a review profile.
    pub fn for_profile(profile: ReviewProfile) -> Self {
        let budget = profile.budget();
        Self {
            max_units: budget.max_units,
            max_agents: budget.max_agents,
        }
    }
}

impl Default for WaveLimits {
    fn default() -> Self {
        Self::for_profile(ReviewProfile::Standard)
    }
}

/// A candidate the evidence bar or the critic refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedCandidate {
    pub candidate: CandidateFinding,
    pub reason: String,
}

/// A unit listed for `NEEDS-VALIDATION`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredUnit {
    pub unit_id: String,
    pub reason: String,
}

/// A unit whose agent could not run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedUnit {
    pub unit_id: String,
    pub reason: String,
}

/// Everything one wave produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaveReport {
    pub wave_id: String,
    /// Candidates the critic accepted, with confirmed finding records.
    pub found: Vec<Finding>,
    /// Candidates the evidence bar or the critic refused.
    pub rejected: Vec<RejectedCandidate>,
    /// Units deferred for missing evidence or an exhausted agent cap.
    pub deferred: Vec<DeferredUnit>,
    /// Units whose agent failed.
    pub blocked: Vec<BlockedUnit>,
    /// Units actually assigned and hunted, including agent failures.
    pub units_run: usize,
    /// Candidates returned by agents, including refused ones.
    pub candidates: usize,
}

impl HuntWave {
    /// Run this wave against `ledger`.
    ///
    /// Every assignment and verdict is an append-only history transition. An
    /// agent failure blocks only its own unit; the wave still returns a report.
    /// A structural problem (an unknown unit, an already settled unit, an empty
    /// label, a critic that is also the hunter) fails before any mutation.
    ///
    /// Units past the effective unit cap are not run and are not mutated; the
    /// caller schedules a later wave (SR-12 reports the run as incomplete).
    /// Execution is sequential, so the agent cap bounds the number of distinct
    /// agents borrowed rather than in-flight work.
    pub fn run(
        &self,
        ledger: &mut CoverageLedger,
        agents: &dyn AgentPool,
        critic: &dyn Critic,
        limits: &WaveLimits,
    ) -> Result<WaveReport> {
        if self.wave_id.trim().is_empty() {
            return Err(invalid("wave id must not be empty"));
        }
        if self.agent_cap == 0 {
            return Err(invalid(format!(
                "wave `{}` agent cap must be greater than zero",
                self.wave_id
            )));
        }
        if limits.max_units == 0 || limits.max_agents == 0 {
            return Err(invalid("wave limits must be greater than zero"));
        }
        if agents.label().trim().is_empty() {
            return Err(invalid("the agent pool must have a non-empty label"));
        }
        let critic_label = critic.label().trim();
        if critic_label.is_empty() {
            return Err(invalid("the critic must have a non-empty label"));
        }
        if agents.label().trim() == critic_label {
            return Err(invalid(format!(
                "critic `{critic_label}` must be a different agent than the hunter pool `{}`",
                agents.label().trim()
            )));
        }
        validate(ledger)?;

        let requested = dedupe_units(&self.units, &self.wave_id)?;
        for unit_id in &requested {
            if !ledger.units.iter().any(|unit| &unit.id == unit_id) {
                return Err(invalid(format!(
                    "wave `{}` names unknown unit `{unit_id}`",
                    self.wave_id
                )));
            }
        }

        let limit = limits.max_units.min(requested.len());
        let selected: Vec<String> = requested.iter().take(limit).cloned().collect();

        // Preflight every unit and agent before the first mutation.
        for unit_id in &selected {
            let unit = ledger
                .units
                .iter()
                .find(|unit| &unit.id == unit_id)
                .expect("selected units exist");
            if !matches!(
                unit.status,
                UnitStatus::Pending
                    | UnitStatus::Assigned
                    | UnitStatus::Deferred
                    | UnitStatus::Blocked
            ) {
                return Err(invalid(format!(
                    "wave `{}` cannot hunt unit `{unit_id}` because it is {}",
                    self.wave_id,
                    unit.status.as_str()
                )));
            }
            let agent_label = agents.agent(unit).label().trim();
            if agent_label.is_empty() {
                return Err(invalid(format!(
                    "the hunt agent for unit `{unit_id}` has an empty label"
                )));
            }
            if agent_label == critic_label {
                return Err(invalid(format!(
                    "critic `{critic_label}` must be a different agent than the hunter of unit `{unit_id}`"
                )));
            }
        }

        let now_ms = unix_now_ms();
        let agent_cap = self.agent_cap.min(limits.max_agents);
        let mut used_agents: BTreeSet<String> = BTreeSet::new();
        let mut seen_candidate_ids: BTreeSet<String> = BTreeSet::new();
        let mut found: Vec<Finding> = Vec::new();
        let mut rejected: Vec<RejectedCandidate> = Vec::new();
        let mut deferred: Vec<DeferredUnit> = Vec::new();
        let mut blocked: Vec<BlockedUnit> = Vec::new();
        let mut units_run = 0usize;
        let mut candidates = 0usize;

        for unit_id in &selected {
            let unit = ledger
                .units
                .iter()
                .find(|unit| &unit.id == unit_id)
                .cloned()
                .expect("selected units exist");
            let agent = agents.agent(&unit);
            let agent_label = agent.label().trim().to_string();

            if !used_agents.contains(&agent_label) && used_agents.len() >= agent_cap {
                let reason = bounded_reason(&format!(
                    "agent cap {agent_cap} reached; unit deferred to a later wave"
                ));
                defer(ledger, unit_id, &self.wave_id, &reason, now_ms)?;
                deferred.push(DeferredUnit {
                    unit_id: unit_id.clone(),
                    reason,
                });
                continue;
            }
            used_agents.insert(agent_label.clone());

            // Assignment is recorded before the agent runs, so an agent that
            // hangs or fails still leaves an owner and a history entry.
            ledger.assign(unit_id, &agent_label)?;
            // `assign` stamps its own clock; keep this unit's later transitions
            // at or after that event so a millisecond tick cannot fail them.
            let now_ms = now_ms.max(
                ledger
                    .units
                    .iter()
                    .find(|unit| unit.id == *unit_id)
                    .and_then(|unit| unit.history.last())
                    .map_or(0, |event| event.at_ms),
            );

            units_run += 1;
            let candidates_out = match agent.hunt(&unit) {
                Ok(candidates_out) => candidates_out,
                Err(error) => {
                    let reason = bounded_reason(&format!(
                        "hunt agent `{agent_label}` failed: {}",
                        error.message()
                    ));
                    ledger.advance(
                        unit_id,
                        UnitStatus::Blocked,
                        &agent_label,
                        Some(&reason),
                        now_ms,
                    )?;
                    blocked.push(BlockedUnit {
                        unit_id: unit_id.clone(),
                        reason,
                    });
                    continue;
                }
            };

            let mut accepted = 0usize;
            let mut needs_evidence: Option<String> = None;
            let mut refusal: Option<String> = None;
            for candidate in candidates_out {
                candidates += 1;
                if let Err(error) = validate_candidate(&candidate, &unit) {
                    let reason = bounded_reason(error.message());
                    rejected.push(RejectedCandidate {
                        candidate,
                        reason: reason.clone(),
                    });
                    refusal = Some(reason);
                    continue;
                }
                if !seen_candidate_ids.insert(candidate.id.clone()) {
                    let reason = bounded_reason(&format!(
                        "candidate id `{}` was already used by this wave",
                        candidate.id
                    ));
                    rejected.push(RejectedCandidate {
                        candidate,
                        reason: reason.clone(),
                    });
                    refusal = Some(reason);
                    continue;
                }
                match critic.review(&candidate, &unit) {
                    CriticVerdict::Accept => {
                        found.push(confirmed_finding(candidate));
                        accepted += 1;
                    }
                    CriticVerdict::Reject { reason } => {
                        let reason =
                            bounded_reason_or(&reason, "the critic rejected the candidate");
                        rejected.push(RejectedCandidate {
                            candidate,
                            reason: reason.clone(),
                        });
                        refusal = Some(reason);
                    }
                    CriticVerdict::NeedsEvidence { reason } => {
                        let reason = bounded_reason_or(&reason, "the critic needs more evidence");
                        if needs_evidence.is_none() {
                            needs_evidence = Some(reason);
                        }
                    }
                }
            }

            {
                let entry = ledger
                    .units
                    .iter_mut()
                    .find(|unit| &unit.id == unit_id)
                    .expect("selected units exist");
                if entry.reviewed_paths.is_empty() {
                    entry.reviewed_paths = entry.starting_paths.clone();
                }
            }
            ledger.advance(unit_id, UnitStatus::Reviewed, critic_label, None, now_ms)?;

            if accepted > 0 {
                ledger.advance(unit_id, UnitStatus::Confirmed, critic_label, None, now_ms)?;
            } else if let Some(reason) = needs_evidence {
                ledger.advance(
                    unit_id,
                    UnitStatus::Deferred,
                    critic_label,
                    Some(&reason),
                    now_ms,
                )?;
                deferred.push(DeferredUnit {
                    unit_id: unit_id.clone(),
                    reason,
                });
            } else {
                let reason =
                    refusal.unwrap_or_else(|| "the hunt produced no candidate".to_string());
                ledger.advance(
                    unit_id,
                    UnitStatus::Refuted,
                    critic_label,
                    Some(&reason),
                    now_ms,
                )?;
            }
        }

        validate(ledger)?;
        Ok(WaveReport {
            wave_id: self.wave_id.clone(),
            found,
            rejected,
            deferred,
            blocked,
            units_run,
            candidates,
        })
    }
}

fn dedupe_units(units: &[String], wave_id: &str) -> Result<Vec<String>> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut out = Vec::new();
    for unit_id in units {
        if unit_id.trim().is_empty() {
            return Err(invalid(format!("wave `{wave_id}` lists an empty unit id")));
        }
        if seen.insert(unit_id.as_str()) {
            out.push(unit_id.clone());
        }
    }
    Ok(out)
}

fn defer(
    ledger: &mut CoverageLedger,
    unit_id: &str,
    actor: &str,
    reason: &str,
    now_ms: u64,
) -> Result<()> {
    let status = ledger
        .units
        .iter()
        .find(|unit| unit.id == unit_id)
        .map(|unit| unit.status)
        .ok_or_else(|| invalid(format!("unknown unit id `{unit_id}`")))?;
    if status == UnitStatus::Deferred {
        return Ok(());
    }
    ledger.advance(unit_id, UnitStatus::Deferred, actor, Some(reason), now_ms)
}

fn confirmed_finding(candidate: CandidateFinding) -> Finding {
    Finding {
        id: candidate.id,
        unit_id: candidate.unit_id,
        title: candidate.title,
        severity: candidate.severity,
        status: FindingStatus::Confirmed,
        evidence_refs: candidate.evidence_refs,
        confirmed: true,
    }
}

fn bounded_reason_or(text: &str, fallback: &str) -> String {
    let reason = bounded_reason(text);
    if reason.is_empty() {
        fallback.to_string()
    } else {
        reason
    }
}

/// Collapse whitespace and control characters, then bound the length.
///
/// Reasons are printed in derived reports, so an agent or critic cannot inject
/// a second line or an unbounded blob into prose.
pub(crate) fn bounded_reason(text: &str) -> String {
    let flattened = text
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    let flattened = flattened.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = flattened.chars();
    let bounded: String = chars.by_ref().take(MAX_REASON_CHARS).collect();
    if chars.next().is_some() {
        format!("{bounded}\u{2026}")
    } else {
        bounded
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, MAIN_SEPARATOR_STR};

    use zero_types::{ErrorCode, ZeroError};

    use super::*;
    use crate::ledger::seed;
    use crate::report::{consistency_report, derive, BudgetReport, ReportInputs};
    use crate::schema::{Findings, FINDINGS_SCHEMA_VERSION};

    fn write(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel.replace('/', MAIN_SEPARATOR_STR));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn planted_repo() -> (tempfile::TempDir, CoverageLedger, LedgerUnit) {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "src/agent.rs",
            "use std::process::Command;\n\npub fn run(user_input: &str) {\n    let _ = Command::new(user_input).spawn();\n}\n",
        );
        let ledger = seed(dir.path()).expect("seed");
        let unit = ledger
            .units
            .iter()
            .find(|unit| unit.attack_class == "command_injection")
            .cloned()
            .expect("planted command-injection unit");
        (dir, ledger, unit)
    }

    fn multi_unit_repo() -> (tempfile::TempDir, CoverageLedger) {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["a", "b", "c"] {
            write(
                dir.path(),
                &format!("src/{name}/run.rs"),
                "pub fn run(user_input: &str) {\n    let _ = std::process::Command::new(user_input).spawn();\n}\n",
            );
        }
        let ledger = seed(dir.path()).expect("seed");
        assert_eq!(
            ledger.units.len(),
            3,
            "fixture yields one unit per subsystem"
        );
        (dir, ledger)
    }

    fn planted_candidate(unit: &LedgerUnit) -> CandidateFinding {
        CandidateFinding {
            id: "FND-1".to_string(),
            unit_id: unit.id.clone(),
            title: "user input reaches the process sink".to_string(),
            severity: Severity::High,
            lower_trust_principal: "repository content or model output".to_string(),
            boundary: unit.boundary.clone(),
            concrete_result:
                "the caller-supplied string becomes the executable path handed to exec".to_string(),
            evidence_refs: vec![CanonicalRef::parse("src/agent.rs:4").expect("evidence ref")],
            checks: unit.checks.clone(),
            notes: None,
        }
    }

    #[derive(Clone)]
    enum ScriptedResponse {
        Candidates(Vec<CandidateFinding>),
        Fail(String),
    }

    #[derive(Clone)]
    struct ScriptedAgent {
        label: String,
        responses: BTreeMap<String, ScriptedResponse>,
    }

    impl ScriptedAgent {
        fn new(label: &str) -> Self {
            Self {
                label: label.to_string(),
                responses: BTreeMap::new(),
            }
        }

        fn answer(mut self, unit_id: &str, candidates: Vec<CandidateFinding>) -> Self {
            self.responses.insert(
                unit_id.to_string(),
                ScriptedResponse::Candidates(candidates),
            );
            self
        }

        fn fail(mut self, unit_id: &str, reason: &str) -> Self {
            self.responses.insert(
                unit_id.to_string(),
                ScriptedResponse::Fail(reason.to_string()),
            );
            self
        }
    }

    impl HuntAgent for ScriptedAgent {
        fn label(&self) -> &str {
            &self.label
        }

        fn hunt(&self, unit: &LedgerUnit) -> Result<Vec<CandidateFinding>> {
            match self.responses.get(&unit.id) {
                Some(ScriptedResponse::Candidates(candidates)) => Ok(candidates.clone()),
                Some(ScriptedResponse::Fail(reason)) => {
                    Err(ZeroError::new(ErrorCode::Internal, reason.clone()))
                }
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

    struct PerUnitPool {
        label: String,
        agents: BTreeMap<String, ScriptedAgent>,
    }

    impl AgentPool for PerUnitPool {
        fn label(&self) -> &str {
            &self.label
        }

        fn agent(&self, unit: &LedgerUnit) -> &dyn HuntAgent {
            self.agents
                .get(&unit.id)
                .map(|agent| agent as &dyn HuntAgent)
                .or_else(|| {
                    self.agents
                        .values()
                        .next()
                        .map(|agent| agent as &dyn HuntAgent)
                })
                .expect("pool has at least one agent")
        }
    }

    struct AcceptingCritic;

    impl Critic for AcceptingCritic {
        fn label(&self) -> &str {
            "scripted-critic"
        }

        fn review(&self, _candidate: &CandidateFinding, _unit: &LedgerUnit) -> CriticVerdict {
            CriticVerdict::Accept
        }
    }

    struct NamedAcceptingCritic {
        label: String,
    }

    impl Critic for NamedAcceptingCritic {
        fn label(&self) -> &str {
            &self.label
        }

        fn review(&self, _candidate: &CandidateFinding, _unit: &LedgerUnit) -> CriticVerdict {
            CriticVerdict::Accept
        }
    }

    struct RejectingCritic {
        reason: String,
    }

    impl Critic for RejectingCritic {
        fn label(&self) -> &str {
            "scripted-critic"
        }

        fn review(&self, _candidate: &CandidateFinding, _unit: &LedgerUnit) -> CriticVerdict {
            CriticVerdict::Reject {
                reason: self.reason.clone(),
            }
        }
    }

    struct NeedsEvidenceCritic {
        reason: String,
    }

    impl Critic for NeedsEvidenceCritic {
        fn label(&self) -> &str {
            "scripted-critic"
        }

        fn review(&self, _candidate: &CandidateFinding, _unit: &LedgerUnit) -> CriticVerdict {
            CriticVerdict::NeedsEvidence {
                reason: self.reason.clone(),
            }
        }
    }

    fn wave(unit_ids: &[String], agent_cap: usize) -> HuntWave {
        HuntWave {
            wave_id: "wave-1".to_string(),
            units: unit_ids.to_vec(),
            agent_cap,
        }
    }

    fn status_of(ledger: &CoverageLedger, unit_id: &str) -> UnitStatus {
        ledger
            .units
            .iter()
            .find(|unit| unit.id == unit_id)
            .expect("unit")
            .status
    }

    #[test]
    fn a_planted_bug_is_found_by_its_unit() {
        let (_dir, mut ledger, unit) = planted_repo();
        let candidate = planted_candidate(&unit);
        let agent = ScriptedAgent::new("scripted-hunter").answer(&unit.id, vec![candidate]);
        let pool = SingleAgentPool { agent };
        let current = wave(std::slice::from_ref(&unit.id), 1);

        let report = current
            .run(&mut ledger, &pool, &AcceptingCritic, &WaveLimits::default())
            .expect("wave");

        assert_eq!(report.units_run, 1);
        assert_eq!(report.candidates, 1);
        assert_eq!(report.found.len(), 1);
        assert_eq!(report.found[0].id, "FND-1");
        assert_eq!(report.found[0].unit_id, unit.id);
        assert_eq!(report.found[0].severity, Severity::High);
        assert_eq!(report.found[0].status, FindingStatus::Confirmed);
        assert!(report.found[0].confirmed);
        assert!(report.rejected.is_empty());
        assert!(report.deferred.is_empty());
        assert!(report.blocked.is_empty());

        let recorded = ledger
            .units
            .iter()
            .find(|recorded| recorded.id == unit.id)
            .expect("unit");
        assert_eq!(recorded.status, UnitStatus::Confirmed);
        assert_eq!(recorded.owner, "scripted-hunter");
        assert_eq!(recorded.history.len(), 3);
        assert_eq!(recorded.history[0].from, UnitStatus::Pending);
        assert_eq!(recorded.history[0].to, UnitStatus::Assigned);
        assert_eq!(recorded.history[1].to, UnitStatus::Reviewed);
        assert_eq!(recorded.history[2].to, UnitStatus::Confirmed);
        validate(&ledger).expect("wave leaves a valid ledger");

        // The report set is derivable from the ledger and the findings alone.
        let findings = Findings {
            schema_version: FINDINGS_SCHEMA_VERSION,
            findings: report.found.clone(),
        };
        let out = tempfile::tempdir().expect("out");
        let inputs = ReportInputs {
            ledger,
            findings,
            budget: BudgetReport {
                reserved_agents: 8,
                used_agents: 2,
                reserved_units: 32,
                used_units: 1,
                incomplete: false,
                reasons: Vec::new(),
            },
            profile: ReviewProfile::Standard,
            run_id: "run-0001".to_string(),
            created_at_ms: 1_700_000_000_000,
        };
        let bundle = derive(inputs, out.path()).expect("derive");
        assert!(consistency_report(&bundle).ok, "prose and records agree");
        assert!(bundle.report_md.contains("`FND-1`"));
        assert!(bundle.findings_detail_md.contains("src/agent.rs:4"));
    }

    #[test]
    fn a_candidate_without_a_lower_trust_principal_is_rejected() {
        let (_dir, _ledger, unit) = planted_repo();
        let mut candidate = planted_candidate(&unit);
        candidate.lower_trust_principal = "   ".to_string();

        let error = validate_candidate(&candidate, &unit).expect_err("missing principal");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains(&candidate.id));
        assert!(error.message().contains("lower_trust_principal"));
    }

    #[test]
    fn a_candidate_with_off_unit_evidence_is_rejected() {
        let (_dir, _ledger, unit) = planted_repo();
        let mut candidate = planted_candidate(&unit);
        candidate.evidence_refs =
            vec![CanonicalRef::parse("src/other.rs:1").expect("out-of-unit ref")];

        let error = validate_candidate(&candidate, &unit).expect_err("off-unit evidence");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains(&candidate.id));
        assert!(error.message().contains("evidence_refs"));
    }

    #[test]
    fn a_candidate_with_a_mismatched_boundary_is_rejected_and_both_are_named() {
        let (_dir, _ledger, unit) = planted_repo();
        let mut candidate = planted_candidate(&unit);
        candidate.boundary = "network-egress".to_string();

        let error = validate_candidate(&candidate, &unit).expect_err("boundary mismatch");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains(&candidate.id));
        assert!(error.message().contains("network-egress"));
        assert!(error.message().contains(&unit.boundary));
    }

    #[test]
    fn a_critical_candidate_without_a_concrete_result_is_rejected() {
        let (_dir, _ledger, unit) = planted_repo();
        let mut candidate = planted_candidate(&unit);
        candidate.severity = Severity::Critical;
        candidate.concrete_result = "  ".to_string();

        let error = validate_candidate(&candidate, &unit).expect_err("critical without impact");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains(&candidate.id));
        assert!(error.message().contains("concrete_result"));
        assert!(error.message().contains("critical"));
    }

    #[test]
    fn a_critic_reject_marks_the_unit_refuted() {
        let (_dir, mut ledger, unit) = planted_repo();
        let agent =
            ScriptedAgent::new("scripted-hunter").answer(&unit.id, vec![planted_candidate(&unit)]);
        let pool = SingleAgentPool { agent };
        let critic = RejectingCritic {
            reason: "the argument is allowlisted before the sink".to_string(),
        };
        let report = wave(std::slice::from_ref(&unit.id), 1)
            .run(&mut ledger, &pool, &critic, &WaveLimits::default())
            .expect("wave");

        assert!(report.found.is_empty());
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(
            report.rejected[0].reason,
            "the argument is allowlisted before the sink"
        );
        assert_eq!(status_of(&ledger, &unit.id), UnitStatus::Refuted);
        let recorded = ledger
            .units
            .iter()
            .find(|recorded| recorded.id == unit.id)
            .expect("unit");
        assert_eq!(
            recorded.history.last().expect("history").to,
            UnitStatus::Refuted
        );
        assert_eq!(
            recorded.history.last().expect("history").note.as_deref(),
            Some("the argument is allowlisted before the sink")
        );
        validate(&ledger).expect("valid ledger");
    }

    #[test]
    fn a_critic_needs_evidence_defers_the_unit() {
        let (_dir, mut ledger, unit) = planted_repo();
        let agent =
            ScriptedAgent::new("scripted-hunter").answer(&unit.id, vec![planted_candidate(&unit)]);
        let pool = SingleAgentPool { agent };
        let critic = NeedsEvidenceCritic {
            reason: "the allowlist check is outside the reviewed files".to_string(),
        };
        let report = wave(std::slice::from_ref(&unit.id), 1)
            .run(&mut ledger, &pool, &critic, &WaveLimits::default())
            .expect("wave");

        assert!(report.found.is_empty());
        assert_eq!(report.deferred.len(), 1);
        assert_eq!(report.deferred[0].unit_id, unit.id);
        assert_eq!(
            report.deferred[0].reason,
            "the allowlist check is outside the reviewed files"
        );
        assert_eq!(status_of(&ledger, &unit.id), UnitStatus::Deferred);
        let recorded = ledger
            .units
            .iter()
            .find(|recorded| recorded.id == unit.id)
            .expect("unit");
        assert_eq!(
            recorded.history.last().expect("history").note.as_deref(),
            Some("the allowlist check is outside the reviewed files")
        );
        validate(&ledger).expect("valid ledger");
    }

    #[test]
    fn an_agent_error_blocks_the_unit_without_failing_the_wave() {
        let (_dir, mut ledger, unit) = planted_repo();
        let agent = ScriptedAgent::new("scripted-hunter").fail(&unit.id, "agent timed out");
        let pool = SingleAgentPool { agent };
        let report = wave(std::slice::from_ref(&unit.id), 1)
            .run(&mut ledger, &pool, &AcceptingCritic, &WaveLimits::default())
            .expect("wave survives an agent failure");

        assert!(report.found.is_empty());
        assert_eq!(report.blocked.len(), 1);
        assert_eq!(report.blocked[0].unit_id, unit.id);
        assert!(report.blocked[0].reason.contains("agent timed out"));
        assert_eq!(status_of(&ledger, &unit.id), UnitStatus::Blocked);
        assert_eq!(report.units_run, 1);
        validate(&ledger).expect("valid ledger");
    }

    #[test]
    fn the_budget_stops_before_exceeding_the_unit_cap() {
        let (_dir, mut ledger) = multi_unit_repo();
        let ids: Vec<String> = ledger.units.iter().map(|unit| unit.id.clone()).collect();
        assert_eq!(ids.len(), 3);
        let agent = ScriptedAgent::new("scripted-hunter");
        let pool = SingleAgentPool { agent };
        let limits = WaveLimits {
            max_units: 2,
            max_agents: 8,
        };

        let report = wave(&ids, 4)
            .run(&mut ledger, &pool, &AcceptingCritic, &limits)
            .expect("wave");

        assert_eq!(report.units_run, 2);
        assert_eq!(report.candidates, 0);
        assert_eq!(
            ledger
                .units
                .iter()
                .filter(|unit| unit.status == UnitStatus::Pending)
                .count(),
            1,
            "the third unit is never assigned"
        );
        assert_eq!(
            ledger
                .units
                .iter()
                .filter(|unit| unit.status == UnitStatus::Refuted)
                .count(),
            2
        );
        validate(&ledger).expect("valid ledger");
    }

    #[test]
    fn the_agent_cap_defers_units_instead_of_exceeding_the_cap() {
        let (_dir, mut ledger) = multi_unit_repo();
        let ids: Vec<String> = ledger.units.iter().map(|unit| unit.id.clone()).collect();
        let mut agents = BTreeMap::new();
        for (index, id) in ids.iter().enumerate() {
            agents.insert(
                id.clone(),
                ScriptedAgent::new(&format!("scripted-hunter-{index}")),
            );
        }
        let pool = PerUnitPool {
            label: "scripted-pool".to_string(),
            agents,
        };

        let report = wave(&ids, 1)
            .run(&mut ledger, &pool, &AcceptingCritic, &WaveLimits::default())
            .expect("wave");

        assert_eq!(report.units_run, 1);
        assert_eq!(report.deferred.len(), 2);
        assert!(report
            .deferred
            .iter()
            .all(|deferred| deferred.reason.contains("agent cap 1")));
        assert_eq!(
            ledger
                .units
                .iter()
                .filter(|unit| unit.status == UnitStatus::Deferred)
                .count(),
            2
        );
        validate(&ledger).expect("valid ledger");
    }

    #[test]
    fn the_critic_must_not_be_the_hunter() {
        let (_dir, mut ledger, unit) = planted_repo();
        let agent = ScriptedAgent::new("shared-label");
        let pool = SingleAgentPool { agent };
        let critic = NamedAcceptingCritic {
            label: "shared-label".to_string(),
        };
        let error = wave(std::slice::from_ref(&unit.id), 1)
            .run(&mut ledger, &pool, &critic, &WaveLimits::default())
            .expect_err("the critic cannot be the hunter");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("different agent"));
        assert_eq!(status_of(&ledger, &unit.id), UnitStatus::Pending);
        assert!(
            ledger
                .units
                .iter()
                .find(|recorded| recorded.id == unit.id)
                .expect("unit")
                .history
                .is_empty(),
            "a refused wave mutates nothing"
        );
    }
}
