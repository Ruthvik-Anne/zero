//! Independent validation of hunting candidates (SR-04, SR-05, SR-07, SR-11).
//!
//! A hunting wave produces candidates; a candidate is not a finding. This module
//! re-reads the target read-only, checks the candidate's evidence against the
//! unit's own paths, and requires a quorum of independent verifiers before a
//! confirmation is recorded. A candidate whose cited lines do not support it is
//! rejected, the unit is refuted, and no finding is written.
//!
//! Two further rules live here:
//!
//! - **Fingerprint stability (SR-04, SR-11).** [`fingerprint_unit`] hashes the
//!   canonical refs and the bounded bytes of every reviewed file. A confirmation
//!   records that fingerprint; [`check_fingerprints`] re-reads the target and
//!   turns a changed unit back into `deferred` work instead of carrying the
//!   confirmation forward.
//! - **Severity (SR-07).** [`validate_severity`] only keeps a severity for a
//!   confirmed candidate, caps an unconfirmed candidate at `info`, and reduces a
//!   claim above the demonstrated impact with a recorded reason.
//!
//! Verifiers are seams: [`Verifier`] is injected, [`EvidenceVerifier`] is the
//! deterministic implementation used by tests and by the default path. A
//! verifier label may not equal the unit's hunter, critic, or another verifier,
//! so validation cannot collapse into the pass that produced the candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use zero_types::error::Result;

use crate::hunt::{
    bounded_reason, validate_candidate, CandidateFinding, DeferredUnit, RejectedCandidate,
};
use crate::ledger::{invalid, validate as validate_ledger, CoverageLedger, LedgerUnit, UnitStatus};
use crate::schema::{CanonicalRef, Finding, FindingStatus, Severity};

/// Independent verifier results required before a candidate is confirmed.
pub const DEFAULT_QUORUM: usize = 2;

/// Bytes read from one file while checking evidence or a fingerprint.
pub const MAX_EVIDENCE_BYTES: u64 = 64 * 1024;

/// Bytes hashed per file when recomputing a unit fingerprint.
pub const MAX_FINGERPRINT_BYTES: u64 = 64 * 1024;

/// Longest line examined by [`EvidenceVerifier`].
pub const MAX_LINE_BYTES: usize = 4 * 1024;

/// Actor recorded for validation transitions.
const VALIDATION_ACTOR: &str = "validation-wave";

/// Actor recorded when a changed fingerprint invalidates a confirmation.
const FINGERPRINT_ACTOR: &str = "fingerprint-check";

// ---------------------------------------------------------------------------
// Verifier seam
// ---------------------------------------------------------------------------

/// One independent verifier's decision on one candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
    /// The cited evidence supports the candidate as written.
    Confirmed,
    /// The candidate is contradicted by the target and must not become a
    /// finding.
    Rejected { reason: String },
    /// The target does not settle the candidate; the unit is deferred.
    NeedsEvidence { reason: String },
}

/// Independent validation of one candidate (SR-04).
///
/// A verifier is a separate object from the hunter and the critic. Labels are
/// compared before a wave mutates the ledger; a verifier with the same label as
/// the unit's owner or a recorded actor refuses the whole wave.
pub trait Verifier {
    /// Stable identity used for the independence checks.
    fn label(&self) -> &str;

    /// Re-read `target` and decide whether `candidate` is supported by `unit`.
    ///
    /// An `Err` means the verifier itself failed; the wave treats that result as
    /// `NeedsEvidence` rather than as a confirmation.
    fn verify(
        &self,
        candidate: &CandidateFinding,
        unit: &LedgerUnit,
        target: &Path,
    ) -> Result<VerificationVerdict>;
}

/// A test-supplied predicate over a cited line and the candidate.
pub type LinePredicate = Box<dyn Fn(&str, &CandidateFinding) -> bool + Send + Sync>;

/// How a cited line is matched against the concrete result.
pub enum LineMatcher {
    /// Any non-blank cited line supports the candidate.
    NonEmpty,
    /// The line must contain this marker (for example the sink `Command::new`).
    Contains(String),
    /// A test-supplied predicate over the line and the candidate.
    Custom(LinePredicate),
}

impl LineMatcher {
    fn matches(&self, line: &str, candidate: &CandidateFinding) -> bool {
        match self {
            Self::NonEmpty => !line.trim().is_empty(),
            Self::Contains(marker) => line.contains(marker),
            Self::Custom(predicate) => predicate(line, candidate),
        }
    }
}

impl fmt::Debug for LineMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonEmpty => formatter.write_str("NonEmpty"),
            Self::Contains(marker) => formatter.debug_tuple("Contains").field(marker).finish(),
            Self::Custom(_) => formatter.write_str("Custom(..)"),
        }
    }
}

/// Deterministic verifier that re-reads the target with no network and no
/// target execution.
///
/// It applies the SR-05 evidence bar first, then checks every path reference:
///
/// - the ref must name a file inside the unit's `starting_paths` or
///   `reviewed_paths`;
/// - the file must exist, be a regular file, and resolve under `target`;
/// - the cited line must exist inside the bounded read (a column, when present,
///   must be inside the line);
/// - at least one cited line must satisfy the matcher. A candidate whose cited
///   lines do not contain the expected marker is rejected: this is the
///   false-positive path.
///
/// Requirement references are legal supporting evidence and are not read from
/// disk. File text is never copied into a reason.
#[derive(Debug)]
pub struct EvidenceVerifier {
    label: String,
    matcher: LineMatcher,
    max_bytes: u64,
}

impl EvidenceVerifier {
    /// A verifier that accepts any non-blank cited line.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            matcher: LineMatcher::NonEmpty,
            max_bytes: MAX_EVIDENCE_BYTES,
        }
    }

    /// A verifier that requires a cited line to contain `marker`.
    pub fn requiring_marker(label: impl Into<String>, marker: impl Into<String>) -> Self {
        Self {
            matcher: LineMatcher::Contains(marker.into()),
            ..Self::new(label)
        }
    }

    /// Replace the line matcher (a test-supplied closure is accepted).
    pub fn with_matcher(mut self, matcher: LineMatcher) -> Self {
        self.matcher = matcher;
        self
    }

    /// Bound the bytes read from each file.
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes.max(1);
        self
    }
}

impl Verifier for EvidenceVerifier {
    fn label(&self) -> &str {
        &self.label
    }

    fn verify(
        &self,
        candidate: &CandidateFinding,
        unit: &LedgerUnit,
        target: &Path,
    ) -> Result<VerificationVerdict> {
        if let Err(error) = validate_candidate(candidate, unit) {
            return Ok(VerificationVerdict::Rejected {
                reason: bounded_reason(error.message()),
            });
        }

        let mut allowed: BTreeSet<&str> = unit.starting_paths.iter().map(String::as_str).collect();
        allowed.extend(unit.reviewed_paths.iter().map(String::as_str));

        let mut path_refs = 0usize;
        let mut matched = false;
        for reference in &candidate.evidence_refs {
            let Some((path, line, column)) = reference.path_parts() else {
                continue;
            };
            if !allowed.contains(path) {
                return Ok(VerificationVerdict::Rejected {
                    reason: bounded_reason(&format!(
                        "evidence ref `{reference}` is outside unit `{}`'s starting or reviewed paths",
                        unit.id
                    )),
                });
            }

            let full = resolve(target, path);
            let bytes = match read_bounded_file(&full, self.max_bytes) {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    return Ok(VerificationVerdict::Rejected {
                        reason: bounded_reason(&format!(
                            "evidence ref `{reference}` points at `{path}`, which is missing or not a regular file"
                        )),
                    });
                }
                Err(error) => {
                    return Ok(VerificationVerdict::NeedsEvidence {
                        reason: bounded_reason(&format!(
                            "verifier `{}` could not read `{path}`: {error}",
                            self.label
                        )),
                    });
                }
            };

            if !inside_target(target, &full) {
                return Ok(VerificationVerdict::Rejected {
                    reason: bounded_reason(&format!(
                        "evidence ref `{reference}` resolves outside the review target"
                    )),
                });
            }

            let Some(text) = line_text(&bytes, line) else {
                return Ok(VerificationVerdict::NeedsEvidence {
                    reason: bounded_reason(&format!(
                        "evidence ref `{reference}` is beyond the bounded read of `{path}`"
                    )),
                });
            };
            path_refs += 1;
            if let Some(column) = column {
                if text.chars().count() < column as usize {
                    return Ok(VerificationVerdict::Rejected {
                        reason: bounded_reason(&format!(
                            "evidence ref `{reference}` cites column {column} but line {line} of `{path}` is shorter"
                        )),
                    });
                }
            }
            if self.matcher.matches(&text, candidate) {
                matched = true;
            }
        }

        if path_refs == 0 {
            return Ok(VerificationVerdict::Rejected {
                reason: bounded_reason(&format!(
                    "candidate `{}` has no path evidence inside unit `{}`",
                    candidate.id, unit.id
                )),
            });
        }
        if !matched {
            return Ok(VerificationVerdict::Rejected {
                reason: bounded_reason(&format!(
                    "the cited lines for candidate `{}` do not contain the expected marker",
                    candidate.id
                )),
            });
        }
        Ok(VerificationVerdict::Confirmed)
    }
}

// ---------------------------------------------------------------------------
// Validation wave
// ---------------------------------------------------------------------------

/// Which verdict a candidate settled on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationDisposition {
    Confirmed,
    Rejected,
    NeedsEvidence,
}

impl ValidationDisposition {
    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Rejected => "rejected",
            Self::NeedsEvidence => "needs_evidence",
        }
    }
}

/// One candidate's verifier tally and severity decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateVerification {
    pub candidate_id: String,
    pub unit_id: String,
    pub disposition: ValidationDisposition,
    pub confirmations: usize,
    pub rejections: usize,
    pub needs_evidence: usize,
    pub severity: Severity,
    /// Present when the claimed severity was reduced, never silently.
    #[serde(default)]
    pub severity_reason: Option<String>,
}

/// Everything one validation pass produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationReport {
    /// Units that had at least one candidate to validate.
    pub units: usize,
    /// Candidates seen, including refused ones.
    pub candidates: usize,
    /// Candidates that reached quorum and became confirmed findings.
    pub findings: Vec<Finding>,
    /// Candidates the verifiers or the evidence bar rejected.
    pub rejected: Vec<RejectedCandidate>,
    /// Units deferred for missing evidence, disagreement, or an unmet quorum.
    pub deferred: Vec<DeferredUnit>,
    /// One tally per candidate, in input order.
    pub verifications: Vec<CandidateVerification>,
}

/// A bounded validation pass.
///
/// `quorum` independent `Confirmed` verdicts are required, no verifier may
/// reject the candidate, and no verifier may ask for more evidence. Anything
/// else is a disagreement and defers the unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationWave {
    /// Maximum verifiers asked about one candidate.
    pub max_verifiers: usize,
    /// Independent confirmations required for a finding.
    pub quorum: usize,
}

impl Default for ValidationWave {
    fn default() -> Self {
        Self {
            max_verifiers: DEFAULT_QUORUM + 1,
            quorum: DEFAULT_QUORUM,
        }
    }
}

impl ValidationWave {
    /// A wave that asks at most `max_verifiers` verifiers and requires the
    /// default quorum.
    pub const fn new(max_verifiers: usize) -> Self {
        Self {
            max_verifiers,
            quorum: DEFAULT_QUORUM,
        }
    }

    /// Override the quorum. It must stay between one and `max_verifiers`.
    pub const fn with_quorum(mut self, quorum: usize) -> Self {
        self.quorum = quorum;
        self
    }

    /// Validate `candidates` against `ledger` and settle each unit.
    ///
    /// Preflight is structural: an unknown unit, a unit that is not `assigned`
    /// or `reviewed`, a duplicate or empty verifier label, a verifier that
    /// shares a label with the unit's hunter or critic, or an impossible quorum
    /// fails before any mutation.
    ///
    /// A confirmed candidate records the unit as `confirmed` and stores the
    /// content fingerprint; a rejected candidate refutes the unit; an
    /// unresolved candidate defers it. `confirmed` is terminal except for the
    /// SR-11 re-review transition to `deferred` used by
    /// [`check_fingerprints`].
    pub fn run(
        &self,
        ledger: &mut CoverageLedger,
        candidates: &[CandidateFinding],
        verifiers: &[&dyn Verifier],
        target: &Path,
    ) -> Result<ValidationReport> {
        if self.max_verifiers == 0 {
            return Err(invalid("validation wave needs at least one verifier slot"));
        }
        if self.quorum == 0 || self.quorum > self.max_verifiers {
            return Err(invalid(format!(
                "validation quorum {} must be between 1 and the verifier cap {}",
                self.quorum, self.max_verifiers
            )));
        }
        if verifiers.is_empty() {
            return Err(invalid("validation wave needs at least one verifier"));
        }

        let mut labels: BTreeSet<&str> = BTreeSet::new();
        for verifier in verifiers {
            let label = verifier.label().trim();
            if label.is_empty() {
                return Err(invalid("a verifier must have a non-empty label"));
            }
            if !labels.insert(label) {
                return Err(invalid(format!(
                    "verifier label `{label}` is used more than once; verifiers must be independent"
                )));
            }
        }

        validate_ledger(ledger)?;

        let mut by_unit: BTreeMap<&str, Vec<&CandidateFinding>> = BTreeMap::new();
        for candidate in candidates {
            by_unit
                .entry(candidate.unit_id.as_str())
                .or_default()
                .push(candidate);
        }

        // Preflight every touched unit and every verifier before the first
        // mutation.
        for unit_id in by_unit.keys() {
            let unit = ledger
                .units
                .iter()
                .find(|unit| unit.id == *unit_id)
                .ok_or_else(|| invalid(format!("validation names unknown unit `{unit_id}`")))?;
            if !matches!(
                unit.status,
                UnitStatus::Pending
                    | UnitStatus::Assigned
                    | UnitStatus::Deferred
                    | UnitStatus::Blocked
                    | UnitStatus::Reviewed
            ) {
                return Err(invalid(format!(
                    "unit `{unit_id}` is {} and cannot be validated",
                    unit.status.as_str()
                )));
            }
            let mut forbidden: BTreeSet<&str> = BTreeSet::new();
            forbidden.insert(VALIDATION_ACTOR);
            forbidden.insert(FINGERPRINT_ACTOR);
            let owner = unit.owner.trim();
            if !owner.is_empty() {
                forbidden.insert(owner);
            }
            for event in &unit.history {
                let actor = event.actor.trim();
                if !actor.is_empty() {
                    forbidden.insert(actor);
                }
            }
            for verifier in verifiers {
                let label = verifier.label().trim();
                if forbidden.contains(label) {
                    return Err(invalid(format!(
                        "verifier `{label}` already produced or reviewed unit `{unit_id}`; validation must be independent"
                    )));
                }
            }
        }

        let mut seen_ids: BTreeSet<&str> = BTreeSet::new();
        let mut findings = Vec::new();
        let mut rejected = Vec::new();
        let mut deferred = Vec::new();
        let mut verifications = Vec::new();
        let mut units_run = 0usize;
        let mut candidate_count = 0usize;

        for (unit_id, unit_candidates) in by_unit {
            let unit = ledger
                .units
                .iter()
                .find(|unit| unit.id == unit_id)
                .cloned()
                .expect("preflighted unit exists");
            units_run += 1;

            let mut any_confirmed = false;
            let mut any_rejected = false;
            let mut first_needs: Option<String> = None;
            let mut first_reject = None;

            for candidate in unit_candidates {
                candidate_count += 1;
                if !seen_ids.insert(candidate.id.as_str()) {
                    let reason = bounded_reason(&format!(
                        "candidate id `{}` appears more than once in this validation pass",
                        candidate.id
                    ));
                    rejected.push(RejectedCandidate {
                        candidate: candidate.clone(),
                        reason: reason.clone(),
                    });
                    any_rejected = true;
                    first_reject.get_or_insert(reason);
                    continue;
                }

                if let Err(error) = validate_candidate(candidate, &unit) {
                    let reason = bounded_reason(error.message());
                    rejected.push(RejectedCandidate {
                        candidate: candidate.clone(),
                        reason: reason.clone(),
                    });
                    any_rejected = true;
                    first_reject.get_or_insert(reason);
                    continue;
                }

                let mut confirmations = 0usize;
                let mut rejections = 0usize;
                let mut needs_evidence = 0usize;
                let mut reject_reason: Option<String> = None;
                let mut needs_reason: Option<String> = None;

                for verifier in verifiers.iter().take(self.max_verifiers) {
                    let verdict = match verifier.verify(candidate, &unit, target) {
                        Ok(verdict) => verdict,
                        Err(error) => VerificationVerdict::NeedsEvidence {
                            reason: bounded_reason(&format!(
                                "verifier `{}` failed: {}",
                                verifier.label().trim(),
                                error.message()
                            )),
                        },
                    };
                    match verdict {
                        VerificationVerdict::Confirmed => confirmations += 1,
                        VerificationVerdict::Rejected { reason } => {
                            rejections += 1;
                            reject_reason.get_or_insert(bounded_reason_or(
                                &reason,
                                "a verifier rejected the candidate",
                            ));
                        }
                        VerificationVerdict::NeedsEvidence { reason } => {
                            needs_evidence += 1;
                            needs_reason.get_or_insert(bounded_reason_or(
                                &reason,
                                "a verifier needs more evidence",
                            ));
                        }
                    }
                }

                let verdict = settle(
                    confirmations,
                    rejections,
                    needs_evidence,
                    self.quorum,
                    reject_reason,
                    needs_reason,
                );
                let decision = severity_decision(candidate, &verdict, candidate.severity);
                let disposition = match &verdict {
                    VerificationVerdict::Confirmed => ValidationDisposition::Confirmed,
                    VerificationVerdict::Rejected { .. } => ValidationDisposition::Rejected,
                    VerificationVerdict::NeedsEvidence { .. } => {
                        ValidationDisposition::NeedsEvidence
                    }
                };
                verifications.push(CandidateVerification {
                    candidate_id: candidate.id.clone(),
                    unit_id: candidate.unit_id.clone(),
                    disposition,
                    confirmations,
                    rejections,
                    needs_evidence,
                    severity: decision.severity,
                    severity_reason: decision.reason,
                });

                match verdict {
                    VerificationVerdict::Confirmed => {
                        any_confirmed = true;
                        findings.push(Finding {
                            id: candidate.id.clone(),
                            unit_id: candidate.unit_id.clone(),
                            title: candidate.title.clone(),
                            severity: decision.severity,
                            status: FindingStatus::Confirmed,
                            evidence_refs: candidate.evidence_refs.clone(),
                            confirmed: true,
                        });
                    }
                    VerificationVerdict::Rejected { reason } => {
                        any_rejected = true;
                        first_reject.get_or_insert(reason.clone());
                        rejected.push(RejectedCandidate {
                            candidate: candidate.clone(),
                            reason,
                        });
                    }
                    VerificationVerdict::NeedsEvidence { reason } => {
                        first_needs.get_or_insert(reason);
                    }
                }
            }

            let mut now_ms = advance_time(ledger, &unit.id);
            if matches!(
                unit.status,
                UnitStatus::Pending | UnitStatus::Deferred | UnitStatus::Blocked
            ) {
                ledger.assign(&unit.id, VALIDATION_ACTOR)?;
                now_ms = advance_time(ledger, &unit.id);
            }
            {
                let entry = ledger
                    .units
                    .iter_mut()
                    .find(|entry| entry.id == unit.id)
                    .expect("unit exists");
                if entry.reviewed_paths.is_empty() {
                    entry.reviewed_paths = entry.starting_paths.clone();
                }
            }
            if ledger
                .units
                .iter()
                .find(|entry| entry.id == unit.id)
                .is_some_and(|entry| entry.status == UnitStatus::Assigned)
            {
                ledger.advance(
                    &unit.id,
                    UnitStatus::Reviewed,
                    VALIDATION_ACTOR,
                    None,
                    now_ms,
                )?;
            }

            if any_confirmed {
                let fingerprint = {
                    let entry = ledger
                        .units
                        .iter()
                        .find(|entry| entry.id == unit.id)
                        .expect("unit exists");
                    fingerprint_unit(entry, target)?
                };
                if let Some(entry) = ledger.units.iter_mut().find(|entry| entry.id == unit.id) {
                    entry.content_fingerprint = Some(fingerprint);
                }
                ledger.advance(
                    &unit.id,
                    UnitStatus::Confirmed,
                    VALIDATION_ACTOR,
                    None,
                    now_ms,
                )?;
            } else if let Some(reason) = first_needs {
                ledger.advance(
                    &unit.id,
                    UnitStatus::Deferred,
                    VALIDATION_ACTOR,
                    Some(&reason),
                    now_ms,
                )?;
                deferred.push(DeferredUnit {
                    unit_id: unit.id.clone(),
                    reason,
                });
            } else if any_rejected {
                let reason =
                    first_reject.unwrap_or_else(|| "the candidate was rejected".to_string());
                ledger.advance(
                    &unit.id,
                    UnitStatus::Refuted,
                    VALIDATION_ACTOR,
                    Some(&reason),
                    now_ms,
                )?;
            }
        }

        validate_ledger(ledger)?;
        Ok(ValidationReport {
            units: units_run,
            candidates: candidate_count,
            findings,
            rejected,
            deferred,
            verifications,
        })
    }
}

fn settle(
    confirmations: usize,
    rejections: usize,
    needs_evidence: usize,
    quorum: usize,
    reject_reason: Option<String>,
    needs_reason: Option<String>,
) -> VerificationVerdict {
    if confirmations >= quorum && rejections == 0 && needs_evidence == 0 {
        return VerificationVerdict::Confirmed;
    }
    if confirmations == 0 && rejections > 0 && needs_evidence == 0 {
        return VerificationVerdict::Rejected {
            reason: reject_reason.unwrap_or_else(|| "the candidate was rejected".to_string()),
        };
    }
    let reason = if needs_evidence > 0 && rejections == 0 && confirmations < quorum {
        needs_reason.unwrap_or_else(|| "the verifiers need more evidence".to_string())
    } else if confirmations < quorum && rejections == 0 {
        format!("quorum {quorum} not met: {confirmations} confirmation(s)")
    } else {
        format!(
            "verifiers disagree: {confirmations} confirmed, {rejections} rejected, {needs_evidence} need evidence (quorum {quorum})"
        )
    };
    VerificationVerdict::NeedsEvidence {
        reason: bounded_reason(&reason),
    }
}

/// Timestamp for a transition, never before the unit's last event.
fn advance_time(ledger: &CoverageLedger, unit_id: &str) -> u64 {
    let now = crate::schema::unix_now_ms();
    ledger
        .units
        .iter()
        .find(|unit| unit.id == unit_id)
        .and_then(|unit| unit.history.last())
        .map_or(now, |event| now.max(event.at_ms))
}

fn bounded_reason_or(text: &str, fallback: &str) -> String {
    let reason = bounded_reason(text);
    if reason.is_empty() {
        fallback.to_string()
    } else {
        reason
    }
}

// ---------------------------------------------------------------------------
// Fingerprint stability (SR-04, SR-11)
// ---------------------------------------------------------------------------

/// The result of re-reading every carried confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FingerprintReport {
    /// True when every carried confirmation still matches the target.
    pub stable: bool,
    /// Unit ids that changed and were deferred for re-review.
    pub changed: Vec<String>,
}

/// Recompute a unit's content fingerprint from the current target files.
///
/// The hash covers the unit's canonical refs (sorted, deduplicated) and, for
/// every path in the refs, starting paths, and reviewed paths, the full file
/// length plus the first [`MAX_FINGERPRINT_BYTES`] bytes. A missing file hashes
/// as a missing marker instead of failing the check: deleting a reviewed file
/// is a change, not an error.
pub fn fingerprint_unit(unit: &LedgerUnit, target: &Path) -> Result<String> {
    let mut refs: Vec<String> = unit
        .refs
        .iter()
        .map(|reference| {
            CanonicalRef::parse(reference)
                .map_or_else(|_| reference.clone(), |parsed| parsed.canonical())
        })
        .collect();
    refs.sort();
    refs.dedup();

    let mut files: BTreeSet<String> = BTreeSet::new();
    for reference in &unit.refs {
        if let Ok(parsed) = CanonicalRef::parse(reference) {
            if let Some((path, _, _)) = parsed.path_parts() {
                files.insert(path.to_string());
            }
        }
    }
    files.extend(unit.starting_paths.iter().cloned());
    files.extend(unit.reviewed_paths.iter().cloned());

    let mut canonical: Vec<u8> = b"zero-review/content-fingerprint/v1".to_vec();
    canonical.push(0x1e);
    for reference in &refs {
        push_blob(&mut canonical, reference.as_bytes());
    }
    canonical.push(0x1e);
    for path in &files {
        push_blob(&mut canonical, path.as_bytes());
        let full = resolve(target, path);
        match read_bounded_file(&full, MAX_FINGERPRINT_BYTES) {
            Ok(Some(bytes)) => {
                let length = std::fs::metadata(&full)
                    .map(|metadata| metadata.len())
                    .unwrap_or(bytes.len() as u64);
                push_blob(&mut canonical, length.to_string().as_bytes());
                push_blob(&mut canonical, &bytes);
            }
            Ok(None) => push_blob(&mut canonical, b"<missing>"),
            Err(_) => push_blob(&mut canonical, b"<unreadable>"),
        }
    }
    Ok(format!("{:016x}", crate::ledger::fnv1a64(&canonical)))
}

/// Re-read the target and invalidate every carried confirmation whose
/// fingerprint changed (SR-11).
///
/// A confirmed unit with a different fingerprint is moved to `deferred` with a
/// recorded reason and its baseline is cleared, so it becomes current work
/// again. A confirmed unit without a baseline cannot be shown to be unchanged
/// and is deferred as well. Units that are not confirmed are untouched.
pub fn check_fingerprints(ledger: &mut CoverageLedger, target: &Path) -> Result<FingerprintReport> {
    validate_ledger(ledger)?;

    let mut changed = Vec::new();
    let mut to_defer: Vec<(String, String)> = Vec::new();
    for unit in &ledger.units {
        if unit.status != UnitStatus::Confirmed {
            continue;
        }
        let current = fingerprint_unit(unit, target)?;
        match &unit.content_fingerprint {
            Some(stored) if stored == &current => {}
            stored => {
                changed.push(unit.id.clone());
                let reason = match stored {
                    Some(stored) => format!(
                        "target changed since the confirmation was carried (`{stored}` -> `{current}`); re-review required"
                    ),
                    None => {
                        "confirmed unit carries no content fingerprint; re-review required".to_string()
                    }
                };
                to_defer.push((unit.id.clone(), bounded_reason(&reason)));
            }
        }
    }

    for (unit_id, reason) in to_defer {
        let now_ms = advance_time(ledger, &unit_id);
        ledger.advance(
            &unit_id,
            UnitStatus::Deferred,
            FINGERPRINT_ACTOR,
            Some(&reason),
            now_ms,
        )?;
        if let Some(unit) = ledger.units.iter_mut().find(|unit| unit.id == unit_id) {
            unit.content_fingerprint = None;
        }
    }

    Ok(FingerprintReport {
        stable: changed.is_empty(),
        changed,
    })
}

// ---------------------------------------------------------------------------
// Severity (SR-07)
// ---------------------------------------------------------------------------

/// A severity plus the reason it changed, when it did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityDecision {
    pub severity: Severity,
    /// Present when a claim was reduced; never a silent downgrade.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Decide the severity for a candidate at a verdict.
///
/// Only a confirmed candidate keeps a severity. A rejected or needs-evidence
/// candidate is capped at `info`, and a confirmed claim above
/// `demonstrated_impact` is reduced to that impact with a recorded reason.
pub fn severity_decision(
    candidate: &CandidateFinding,
    verdict: &VerificationVerdict,
    demonstrated_impact: Severity,
) -> SeverityDecision {
    match verdict {
        VerificationVerdict::Confirmed => {
            if candidate.severity > demonstrated_impact {
                SeverityDecision {
                    severity: demonstrated_impact,
                    reason: Some(bounded_reason(&format!(
                        "claimed severity {} exceeds the demonstrated impact {}; reduced to {}",
                        candidate.severity.as_str(),
                        demonstrated_impact.as_str(),
                        demonstrated_impact.as_str()
                    ))),
                }
            } else {
                SeverityDecision {
                    severity: candidate.severity,
                    reason: None,
                }
            }
        }
        VerificationVerdict::Rejected { .. } | VerificationVerdict::NeedsEvidence { .. } => {
            SeverityDecision {
                severity: Severity::Info,
                reason: Some(bounded_reason(&format!(
                    "candidate is unconfirmed; claimed severity {} is capped at info",
                    candidate.severity.as_str()
                ))),
            }
        }
    }
}

/// The SR-07 severity rule: confirmed claims keep a severity, everything else
/// is `info`, and no claim exceeds the demonstrated impact.
pub fn validate_severity(
    candidate: &CandidateFinding,
    verdict: &VerificationVerdict,
    demonstrated_impact: Severity,
) -> Result<Severity> {
    Ok(severity_decision(candidate, verdict, demonstrated_impact).severity)
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

/// Resolve a root-relative POSIX path under `target`.
fn resolve(target: &Path, relative: &str) -> PathBuf {
    let mut path = target.to_path_buf();
    for segment in relative.split('/') {
        path.push(segment);
    }
    path
}

/// Read at most `max_bytes` from a regular file. A missing file or a directory
/// is `Ok(None)`; an I/O failure is returned so the caller can ask for evidence.
fn read_bounded_file(path: &Path, max_bytes: u64) -> std::io::Result<Option<Vec<u8>>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(max_bytes)
        .read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

/// True when `path` canonicalizes under `target`.
fn inside_target(target: &Path, path: &Path) -> bool {
    match (target.canonicalize(), path.canonicalize()) {
        (Ok(root), Ok(path)) => path.starts_with(root),
        _ => false,
    }
}

/// The bounded text of a 1-based line, or `None` when the bounded read does
/// not contain it.
fn line_text(bytes: &[u8], line: u32) -> Option<String> {
    let wanted = usize::try_from(line).ok()?;
    if wanted == 0 {
        return None;
    }
    for (index, chunk) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if index + 1 == wanted {
            let trimmed = chunk.strip_suffix(b"\r").unwrap_or(chunk);
            let capped = &trimmed[..trimmed.len().min(MAX_LINE_BYTES)];
            return Some(String::from_utf8_lossy(capped).into_owned());
        }
    }
    None
}

/// Length-prefix one blob so adjacent fields cannot collide.
fn push_blob(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(value.len().to_string().as_bytes());
    buffer.push(b':');
    buffer.extend_from_slice(value);
    buffer.push(b';');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::MAIN_SEPARATOR_STR;

    use zero_types::ErrorCode;

    use super::*;

    const PLANTED: &str = "use std::process::Command;\n\npub fn run(user_input: &str) {\n    let _ = Command::new(user_input).spawn();\n}\n";

    fn write(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel.replace('/', MAIN_SEPARATOR_STR));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn planted() -> (tempfile::TempDir, CoverageLedger, LedgerUnit) {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "src/agent.rs", PLANTED);
        let ledger = crate::ledger::seed(dir.path()).expect("seed");
        let unit = ledger
            .units
            .iter()
            .find(|unit| unit.attack_class == "command_injection")
            .cloned()
            .expect("planted command-injection unit");
        (dir, ledger, unit)
    }

    fn mark_reviewed(ledger: &mut CoverageLedger, unit: &LedgerUnit) {
        ledger.assign(&unit.id, "hunter-alpha").expect("assign");
        let now_ms = ledger
            .units
            .iter()
            .find(|entry| entry.id == unit.id)
            .and_then(|entry| entry.history.last())
            .map_or_else(crate::schema::unix_now_ms, |event| {
                crate::schema::unix_now_ms().max(event.at_ms)
            });
        if let Some(entry) = ledger.units.iter_mut().find(|entry| entry.id == unit.id) {
            entry.reviewed_paths = entry.starting_paths.clone();
        }
        ledger
            .advance(&unit.id, UnitStatus::Reviewed, "critic-beta", None, now_ms)
            .expect("review");
    }

    fn candidate(unit: &LedgerUnit, id: &str, evidence: &str) -> CandidateFinding {
        CandidateFinding {
            id: id.to_string(),
            unit_id: unit.id.clone(),
            title: "user input reaches the process sink".to_string(),
            severity: Severity::High,
            lower_trust_principal: "repository content or model output".to_string(),
            boundary: unit.boundary.clone(),
            concrete_result:
                "the caller-supplied string becomes the executable path handed to exec".to_string(),
            evidence_refs: vec![CanonicalRef::parse(evidence).expect("evidence ref")],
            checks: unit.checks.clone(),
            notes: None,
        }
    }

    fn verifiers(items: &[EvidenceVerifier]) -> Vec<&dyn Verifier> {
        items.iter().map(|item| item as &dyn Verifier).collect()
    }

    fn unit_status(ledger: &CoverageLedger, unit_id: &str) -> UnitStatus {
        ledger
            .units
            .iter()
            .find(|unit| unit.id == unit_id)
            .expect("unit")
            .status
    }

    fn history_len(ledger: &CoverageLedger, unit_id: &str) -> usize {
        ledger
            .units
            .iter()
            .find(|unit| unit.id == unit_id)
            .expect("unit")
            .history
            .len()
    }

    #[test]
    fn true_positive_is_confirmed_by_two_verifiers_and_keeps_its_severity() {
        let (dir, mut ledger, unit) = planted();
        // The seeded unit is still `pending`; validation brings it through
        // assignment and review itself.
        let item = candidate(&unit, "FND-1", "src/agent.rs:4");

        let checks = [
            EvidenceVerifier::requiring_marker("verifier-one", "Command::new"),
            EvidenceVerifier::requiring_marker("verifier-two", "spawn("),
        ];
        let report = ValidationWave::new(3)
            .run(&mut ledger, &[item], &verifiers(&checks), dir.path())
            .expect("wave");

        assert_eq!(report.units, 1);
        assert_eq!(report.candidates, 1);
        assert_eq!(
            report.findings.len(),
            1,
            "the candidate becomes one finding"
        );
        assert_eq!(report.findings[0].id, "FND-1");
        assert_eq!(report.findings[0].severity, Severity::High);
        assert_eq!(report.findings[0].status, FindingStatus::Confirmed);
        assert!(report.rejected.is_empty());
        assert!(report.deferred.is_empty());
        assert_eq!(report.verifications.len(), 1);
        assert_eq!(
            report.verifications[0].disposition,
            ValidationDisposition::Confirmed
        );
        assert_eq!(report.verifications[0].confirmations, 2);
        assert!(report.verifications[0].severity_reason.is_none());

        let recorded = ledger
            .units
            .iter()
            .find(|entry| entry.id == unit.id)
            .expect("unit");
        assert_eq!(recorded.status, UnitStatus::Confirmed);
        assert!(
            recorded.content_fingerprint.is_some(),
            "a confirmation records the content baseline"
        );
        assert_eq!(recorded.owner, VALIDATION_ACTOR);
        assert_eq!(
            recorded.history.first().expect("history").from,
            UnitStatus::Pending
        );
        assert_eq!(
            recorded.history.last().expect("history").to,
            UnitStatus::Confirmed
        );
        crate::ledger::validate(&ledger).expect("valid ledger");
    }

    #[test]
    fn false_positive_is_rejected_and_refutes_the_unit_without_a_finding() {
        let (dir, mut ledger, unit) = planted();
        mark_reviewed(&mut ledger, &unit);
        // Line 1 contains `Command` but not the claimed sink `Command::new`.
        let item = candidate(&unit, "FND-FALSE", "src/agent.rs:1");

        let checks = [
            EvidenceVerifier::requiring_marker("verifier-one", "Command::new"),
            EvidenceVerifier::requiring_marker("verifier-two", "Command::new"),
        ];
        let report = ValidationWave::new(3)
            .run(&mut ledger, &[item], &verifiers(&checks), dir.path())
            .expect("wave");

        assert!(
            report.findings.is_empty(),
            "a false positive is not a finding"
        );
        assert_eq!(report.rejected.len(), 1);
        assert!(
            report.rejected[0].reason.contains("marker"),
            "the reason names the failed marker check: {}",
            report.rejected[0].reason
        );
        assert_eq!(
            report.verifications[0].disposition,
            ValidationDisposition::Rejected
        );
        assert_eq!(report.verifications[0].severity, Severity::Info);
        assert_eq!(unit_status(&ledger, &unit.id), UnitStatus::Refuted);
        let recorded = ledger
            .units
            .iter()
            .find(|entry| entry.id == unit.id)
            .expect("unit");
        assert!(recorded.content_fingerprint.is_none());
        assert_eq!(
            recorded.history.last().expect("history").to,
            UnitStatus::Refuted
        );
        crate::ledger::validate(&ledger).expect("valid ledger");
    }

    #[test]
    fn verifier_disagreement_defers_the_unit() {
        let (dir, mut ledger, unit) = planted();
        mark_reviewed(&mut ledger, &unit);
        let item = candidate(&unit, "FND-2", "src/agent.rs:4");

        let checks = [
            EvidenceVerifier::requiring_marker("verifier-one", "Command::new"),
            EvidenceVerifier::requiring_marker("verifier-two", "marker-that-does-not-exist"),
        ];
        let report = ValidationWave::new(3)
            .run(&mut ledger, &[item], &verifiers(&checks), dir.path())
            .expect("wave");

        assert!(report.findings.is_empty());
        assert_eq!(report.deferred.len(), 1);
        assert!(report.deferred[0].reason.contains("disagree"));
        assert_eq!(
            report.verifications[0].disposition,
            ValidationDisposition::NeedsEvidence
        );
        assert_eq!(report.verifications[0].confirmations, 1);
        assert_eq!(report.verifications[0].rejections, 1);
        assert_eq!(unit_status(&ledger, &unit.id), UnitStatus::Deferred);
        crate::ledger::validate(&ledger).expect("valid ledger");
    }

    #[test]
    fn fewer_than_quorum_is_not_confirmed() {
        let (dir, mut ledger, unit) = planted();
        mark_reviewed(&mut ledger, &unit);
        let item = candidate(&unit, "FND-3", "src/agent.rs:4");

        let checks = [EvidenceVerifier::requiring_marker(
            "verifier-one",
            "Command::new",
        )];
        let report = ValidationWave::new(3)
            .with_quorum(2)
            .run(&mut ledger, &[item], &verifiers(&checks), dir.path())
            .expect("wave");

        assert!(
            report.findings.is_empty(),
            "one confirmation is not a quorum"
        );
        assert_eq!(report.deferred.len(), 1);
        assert!(report.deferred[0].reason.contains("quorum 2"));
        assert_eq!(unit_status(&ledger, &unit.id), UnitStatus::Deferred);
        crate::ledger::validate(&ledger).expect("valid ledger");
    }

    #[test]
    fn a_verifier_sharing_the_hunter_label_is_refused() {
        let (dir, mut ledger, unit) = planted();
        mark_reviewed(&mut ledger, &unit);
        let item = candidate(&unit, "FND-4", "src/agent.rs:4");
        let before = history_len(&ledger, &unit.id);

        let checks = [
            EvidenceVerifier::requiring_marker("hunter-alpha", "Command::new"),
            EvidenceVerifier::requiring_marker("verifier-two", "spawn("),
        ];
        let error = ValidationWave::new(3)
            .run(&mut ledger, &[item], &verifiers(&checks), dir.path())
            .expect_err("the verifier is the hunter");

        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("hunter-alpha"));
        assert_eq!(unit_status(&ledger, &unit.id), UnitStatus::Reviewed);
        assert_eq!(
            history_len(&ledger, &unit.id),
            before,
            "nothing was written"
        );
    }

    #[test]
    fn off_unit_or_missing_evidence_is_rejected() {
        let (dir, ledger, unit) = planted();
        let verifier = EvidenceVerifier::new("verifier-one");

        let off_unit = candidate(&unit, "FND-5", "src/other.rs:1");
        let verdict = verifier
            .verify(&off_unit, &unit, dir.path())
            .expect("verify");
        assert!(matches!(verdict, VerificationVerdict::Rejected { .. }));
        if let VerificationVerdict::Rejected { reason } = verdict {
            assert!(reason.contains("evidence_refs"));
        }

        std::fs::remove_file(dir.path().join("src").join("agent.rs")).expect("remove");
        let missing = candidate(&unit, "FND-6", "src/agent.rs:4");
        let verdict = verifier
            .verify(&missing, &unit, dir.path())
            .expect("verify");
        match verdict {
            VerificationVerdict::Rejected { reason } => {
                assert!(reason.contains("missing"), "reason: {reason}");
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
        crate::ledger::validate(&ledger).expect("the fixture ledger is untouched");
    }

    #[test]
    fn fingerprint_is_stable_until_a_byte_changes_and_then_the_confirmation_is_deferred() {
        let (dir, mut ledger, unit) = planted();
        mark_reviewed(&mut ledger, &unit);
        let item = candidate(&unit, "FND-7", "src/agent.rs:4");

        let checks = [
            EvidenceVerifier::requiring_marker("verifier-one", "Command::new"),
            EvidenceVerifier::requiring_marker("verifier-two", "spawn("),
        ];
        ValidationWave::new(3)
            .run(&mut ledger, &[item], &verifiers(&checks), dir.path())
            .expect("wave");
        assert_eq!(unit_status(&ledger, &unit.id), UnitStatus::Confirmed);

        let confirmed = ledger
            .units
            .iter()
            .find(|entry| entry.id == unit.id)
            .cloned()
            .expect("unit");
        let first = fingerprint_unit(&confirmed, dir.path()).expect("fingerprint");
        let second = fingerprint_unit(&confirmed, dir.path()).expect("fingerprint");
        assert_eq!(first, second, "an unchanged target keeps its fingerprint");

        let stable = check_fingerprints(&mut ledger, dir.path()).expect("check");
        assert!(stable.stable);
        assert!(stable.changed.is_empty());
        assert_eq!(unit_status(&ledger, &unit.id), UnitStatus::Confirmed);

        write(
            dir.path(),
            "src/agent.rs",
            "use std::process::Command;\n\npub fn run(user_input: &str) {\n    let _ = Command::new(user_input).spawn(); // drifted\n}\n",
        );

        let changed = check_fingerprints(&mut ledger, dir.path()).expect("check");
        assert!(!changed.stable);
        assert_eq!(changed.changed, vec![unit.id.clone()]);
        let recorded = ledger
            .units
            .iter()
            .find(|entry| entry.id == unit.id)
            .expect("unit");
        assert_eq!(
            recorded.status,
            UnitStatus::Deferred,
            "never keep it confirmed"
        );
        assert!(recorded.content_fingerprint.is_none());
        let last = recorded.history.last().expect("history");
        assert_eq!(last.from, UnitStatus::Confirmed);
        assert_eq!(last.to, UnitStatus::Deferred);
        assert!(last
            .note
            .as_deref()
            .is_some_and(|note| note.contains("re-review required")));
        crate::ledger::validate(&ledger).expect("valid ledger after invalidation");
    }

    #[test]
    fn severity_above_demonstrated_impact_is_reduced_with_a_reason() {
        let (_dir, _ledger, unit) = planted();
        let mut item = candidate(&unit, "FND-8", "src/agent.rs:4");
        item.severity = Severity::Critical;

        let decision = severity_decision(&item, &VerificationVerdict::Confirmed, Severity::Medium);
        assert_eq!(decision.severity, Severity::Medium);
        assert!(decision
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("demonstrated impact")));
        assert_eq!(
            validate_severity(&item, &VerificationVerdict::Confirmed, Severity::Medium)
                .expect("severity"),
            Severity::Medium
        );

        item.severity = Severity::Low;
        assert_eq!(
            validate_severity(&item, &VerificationVerdict::Confirmed, Severity::High)
                .expect("severity"),
            Severity::Low,
            "a claim below the demonstrated impact is kept"
        );
    }

    #[test]
    fn unconfirmed_severity_is_capped_at_info() {
        let (_dir, _ledger, unit) = planted();
        let mut item = candidate(&unit, "FND-9", "src/agent.rs:4");
        item.severity = Severity::Critical;

        for verdict in [
            VerificationVerdict::Rejected {
                reason: "contradicted".to_string(),
            },
            VerificationVerdict::NeedsEvidence {
                reason: "unsettled".to_string(),
            },
        ] {
            let decision = severity_decision(&item, &verdict, Severity::Critical);
            assert_eq!(decision.severity, Severity::Info);
            assert!(decision
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("capped at info")));
            assert_eq!(
                validate_severity(&item, &verdict, Severity::Critical).expect("severity"),
                Severity::Info
            );
        }
    }

    #[test]
    fn duplicate_verifier_labels_are_refused() {
        let (dir, mut ledger, unit) = planted();
        mark_reviewed(&mut ledger, &unit);
        let item = candidate(&unit, "FND-10", "src/agent.rs:4");

        let checks = [
            EvidenceVerifier::requiring_marker("same-label", "Command::new"),
            EvidenceVerifier::requiring_marker("same-label", "spawn("),
        ];
        let error = ValidationWave::new(3)
            .run(&mut ledger, &[item], &verifiers(&checks), dir.path())
            .expect_err("labels must differ");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("more than once"));
        assert_eq!(unit_status(&ledger, &unit.id), UnitStatus::Reviewed);
    }
}
