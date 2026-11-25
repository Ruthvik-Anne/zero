//! Halcyon behaviour rules (HAL-05, HAL-08, HAL-09).
//!
//! This module encodes the mode's workflow natively instead of reading
//! Halcyon's own instructions: gaps are recorded as typed evidence, gates run
//! only through `joker`, endpoints route only through `epb`, and a run cannot
//! finish until a `tkb check` result and a handover exist.
//!
//! [`HalcyonRun`] is the evidence a host collects while the mode is active:
//! the latest `tkb check` record, gaps, the handover, and every gate and
//! endpoint request with the route it took. The collection functions refuse
//! work after [`finish`] has succeeded, so a finished run's evidence cannot
//! change afterwards.
//!
//! Routing is the enforcement point (HAL-08, HAL-09). [`request_gate`] accepts
//! only [`Route::Joker`] and [`request_endpoint`] only [`Route::Epb`]; any other
//! route is refused with `zero.pol.denied` **and recorded**, so a caller that
//! ignores the error still fails [`can_finish`]. A refused attempt is never
//! silently dropped and never becomes a stand-in backend: there is no
//! direct-test path and no mock endpoint path.
//!
//! [`can_finish`] is the completion gate: a missing check, a failed latest
//! check, an unresolved gap that is not an explicitly waived info gap, a
//! missing handover, or a non-adapter route on record all refuse. [`finish`]
//! marks the run only after that gate passes and is idempotent: a second call
//! returns the same report and leaves `finished_ms` unchanged.
//!
//! All refusal messages name the rule and the documentation anchor
//! [`BEHAVIOUR_DOCS_ANCHOR`]; none of them contains evidence content beyond the
//! identifier or summary the caller supplied.

use zero_types::{ErrorCode, ZeroError};

/// Documentation anchor referenced by refusal messages.
pub const BEHAVIOUR_DOCS_ANCHOR: &str = "docs/halcyon.md#behaviour-t-hal-05";

/// Upper bound on a run id, gate name, or endpoint name.
pub const MAX_NAME_BYTES: usize = 128;

/// Upper bound on a `tkb check` summary.
pub const MAX_CHECK_SUMMARY_BYTES: usize = 1024;

/// Upper bound on one gap description.
pub const MAX_GAP_DESCRIPTION_BYTES: usize = 1024;

/// Upper bound on a handover summary.
pub const MAX_HANDOVER_SUMMARY_BYTES: usize = 4096;

/// Upper bound on the number of evidence lines in one handover.
pub const MAX_EVIDENCE_ITEMS: usize = 64;

/// Upper bound on one handover evidence line.
pub const MAX_EVIDENCE_BYTES: usize = 512;

/// How a gate or endpoint request reached the run.
///
/// [`Route::Direct`] exists so a refused direct call leaves evidence behind
/// instead of vanishing; it is never an accepted route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Route {
    /// The request came through the `joker` gate runner. The only route a gate
    /// may take.
    Joker,
    /// The request came through the `epb` endpoint bridge. The only route an
    /// endpoint may take.
    Epb,
    /// A caller tried to run the work itself. Refused and recorded.
    Direct,
}

impl Route {
    /// Stable lower-case name used in evidence and messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Joker => "joker",
            Self::Epb => "epb",
            Self::Direct => "direct",
        }
    }
}

/// How serious a recorded gap is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GapSeverity {
    /// Informational. May be waived; only info gaps may be waived.
    Info,
    /// Worth fixing, but not a completion blocker on its own.
    Warn,
    /// Blocks completion until resolved.
    High,
}

impl GapSeverity {
    /// Stable lower-case name used in evidence and messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::High => "high",
        }
    }

    /// True for [`GapSeverity::Info`], the only waivable severity.
    pub const fn is_info(self) -> bool {
        matches!(self, Self::Info)
    }
}

/// The latest `tkb check` result recorded on a run.
///
/// The run keeps one record: a later check replaces it, so a failed check is
/// cleared only by a later successful check, exactly as `tkb check` is re-run
/// after a fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRecord {
    /// When the check was recorded, in milliseconds since the Unix epoch.
    pub at_ms: i64,
    /// Whether `tkb check` reported zero errors.
    pub ok: bool,
    /// The check's own summary line.
    pub summary: String,
}

/// A gap discovered during a run (HAL-08: "a gap named only in prose is not
/// recorded").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// Run-local identifier, assigned by [`record_gap`].
    pub id: String,
    /// When the gap was recorded, in milliseconds since the Unix epoch.
    pub at_ms: i64,
    /// What is missing or wrong.
    pub description: String,
    /// How serious it is.
    pub severity: GapSeverity,
    /// Set by [`resolve_gap`] once the gap is fixed.
    pub resolved: bool,
    /// Set by [`waive_gap`]; only honoured for [`GapSeverity::Info`].
    pub waived: bool,
}

impl Gap {
    /// True when this gap stops [`can_finish`].
    ///
    /// A resolved gap never blocks. An unresolved info gap is waived only when
    /// `waived` is set; a waiver on a warn or high gap is ignored rather than
    /// trusted, so tampering with the field cannot bypass the gate.
    pub fn is_blocking(&self) -> bool {
        !self.resolved && !(self.severity.is_info() && self.waived)
    }
}

/// The handover written before a run may finish (`tkb handover write`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handover {
    /// When the handover was recorded, in milliseconds since the Unix epoch.
    pub at_ms: i64,
    /// Free-text summary of what the run did and left behind.
    pub summary: String,
    /// Evidence lines, each one a command, test name, or artifact a reviewer
    /// can check.
    pub evidence: Vec<String>,
}

/// One gate request and the route it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateRecord {
    /// Gate name, as the caller supplied it.
    pub gate: String,
    /// Route the request used. Only [`Route::Joker`] is accepted.
    pub via: Route,
}

/// One endpoint request and the route it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRecord {
    /// Endpoint name, as the caller supplied it.
    pub endpoint: String,
    /// Route the request used. Only [`Route::Epb`] is accepted.
    pub via: Route,
}

/// The evidence collected for one Halcyon run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HalcyonRun {
    /// Caller-supplied run identifier.
    pub run_id: String,
    /// When the run started, in milliseconds since the Unix epoch.
    pub started_ms: i64,
    /// Latest `tkb check` record, if one has been recorded.
    pub check: Option<CheckRecord>,
    /// Every recorded gap, in discovery order.
    pub gaps: Vec<Gap>,
    /// The handover, once written.
    pub handover: Option<Handover>,
    /// Every gate request, including refused ones.
    pub gates: Vec<GateRecord>,
    /// Every endpoint request, including refused ones.
    pub endpoints: Vec<EndpointRecord>,
    /// When [`finish`] succeeded. `None` until then, and never moved by a
    /// second `finish`.
    pub finished_ms: Option<i64>,
}

impl HalcyonRun {
    /// Start a run with no evidence.
    pub fn new(run_id: impl Into<String>, started_ms: i64) -> Result<Self, ZeroError> {
        let run_id = run_id.into();
        validate_identifier("run id", &run_id)?;
        Ok(Self {
            run_id,
            started_ms,
            check: None,
            gaps: Vec::new(),
            handover: None,
            gates: Vec::new(),
            endpoints: Vec::new(),
            finished_ms: None,
        })
    }

    /// True after [`finish`] succeeded.
    pub fn is_finished(&self) -> bool {
        self.finished_ms.is_some()
    }
}

/// The report [`can_finish`] and [`finish`] return on success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishReport {
    /// The run this report describes.
    pub run_id: String,
    /// The check that satisfied the gate.
    pub check: CheckRecord,
    /// The handover that satisfied the gate.
    pub handover: Handover,
    /// Every gap on record, resolved, waived, or not.
    pub gaps: Vec<Gap>,
    /// Every gate request on record, with its route.
    pub gates: Vec<GateRecord>,
    /// Every endpoint request on record, with its route.
    pub endpoints: Vec<EndpointRecord>,
}

impl FinishReport {
    /// The handover evidence lines.
    pub fn evidence(&self) -> &[String] {
        &self.handover.evidence
    }
}

/// Record the latest `tkb check` result, replacing any earlier one.
///
/// A failed record stays until a later successful check replaces it, which is
/// what makes "failed check, then a fix, then a green check" a valid path and
/// "failed check with no retry" a refusal.
pub fn record_check(
    run: &mut HalcyonRun,
    ok: bool,
    summary: &str,
    now_ms: i64,
) -> Result<(), ZeroError> {
    ensure_open(run)?;
    validate_text("tkb check summary", summary, MAX_CHECK_SUMMARY_BYTES)?;
    run.check = Some(CheckRecord {
        at_ms: now_ms,
        ok,
        summary: summary.to_string(),
    });
    Ok(())
}

/// Record a discovered gap and return its new identifier.
pub fn record_gap(
    run: &mut HalcyonRun,
    description: &str,
    severity: GapSeverity,
    now_ms: i64,
) -> Result<String, ZeroError> {
    ensure_open(run)?;
    validate_text("gap description", description, MAX_GAP_DESCRIPTION_BYTES)?;
    let id = format!("gap-{}", run.gaps.len() + 1);
    run.gaps.push(Gap {
        id: id.clone(),
        at_ms: now_ms,
        description: description.to_string(),
        severity,
        resolved: false,
        waived: false,
    });
    Ok(id)
}

/// Mark a gap resolved. Resolving an already resolved gap is a no-op.
pub fn resolve_gap(run: &mut HalcyonRun, gap_id: &str) -> Result<(), ZeroError> {
    ensure_open(run)?;
    let gap = run
        .gaps
        .iter_mut()
        .find(|gap| gap.id == gap_id)
        .ok_or_else(|| not_found(format!("no gap `{gap_id}` exists on this run")))?;
    gap.resolved = true;
    Ok(())
}

/// Explicitly waive an info gap. Warn and high gaps cannot be waived.
pub fn waive_gap(run: &mut HalcyonRun, gap_id: &str) -> Result<(), ZeroError> {
    ensure_open(run)?;
    let gap = run
        .gaps
        .iter_mut()
        .find(|gap| gap.id == gap_id)
        .ok_or_else(|| not_found(format!("no gap `{gap_id}` exists on this run")))?;
    if !gap.severity.is_info() {
        return Err(denied(format!(
            "gap `{gap_id}` is {} severity; only info gaps can be waived. Resolve it instead (see {BEHAVIOUR_DOCS_ANCHOR})",
            gap.severity.as_str()
        )));
    }
    gap.waived = true;
    Ok(())
}

/// Submit one gate request. Only [`Route::Joker`] is accepted.
///
/// A refused request is still recorded, so the run carries the violation into
/// [`can_finish`]. The error names the rule: gates run only through `joker`.
pub fn request_gate(run: &mut HalcyonRun, gate: &str, route: Route) -> Result<(), ZeroError> {
    ensure_open(run)?;
    validate_identifier("gate", gate)?;
    run.gates.push(GateRecord {
        gate: gate.to_string(),
        via: route,
    });
    if route != Route::Joker {
        return Err(denied(format!(
            "gates run only through joker; `{gate}` was requested through {} and is refused and recorded (see {BEHAVIOUR_DOCS_ANCHOR})",
            route.as_str()
        )));
    }
    Ok(())
}

/// Submit one endpoint request. Only [`Route::Epb`] is accepted.
///
/// A refused request is still recorded, so a direct call cannot be hidden. The
/// error names the rule: endpoints route only through `epb`.
pub fn request_endpoint(
    run: &mut HalcyonRun,
    endpoint: &str,
    route: Route,
) -> Result<(), ZeroError> {
    ensure_open(run)?;
    validate_identifier("endpoint", endpoint)?;
    run.endpoints.push(EndpointRecord {
        endpoint: endpoint.to_string(),
        via: route,
    });
    if route != Route::Epb {
        return Err(denied(format!(
            "endpoints route only through epb; `{endpoint}` was requested through {} and is refused and recorded (see {BEHAVIOUR_DOCS_ANCHOR})",
            route.as_str()
        )));
    }
    Ok(())
}

/// The seam a host binds to the real `joker` binary.
///
/// Implementations only record the request; running the gate is the adapter's
/// job. The trait exists so the host can inject its own binding without this
/// crate compiling against `joker`, and so a caller has a route that cannot be
/// [`Route::Direct`].
pub trait JokerAdapter {
    /// Submit one gate through joker.
    fn gate(&self, run: &mut HalcyonRun, gate: &str) -> Result<(), ZeroError>;
}

/// The default `joker` route: records the gate as requested through joker.
#[derive(Debug, Clone, Copy, Default)]
pub struct JokerRoute;

impl JokerAdapter for JokerRoute {
    fn gate(&self, run: &mut HalcyonRun, gate: &str) -> Result<(), ZeroError> {
        request_gate(run, gate, Route::Joker)
    }
}

/// The seam a host binds to the real `epb` binary.
pub trait EpbAdapter {
    /// Submit one endpoint through epb.
    fn endpoint(&self, run: &mut HalcyonRun, endpoint: &str) -> Result<(), ZeroError>;
}

/// The default `epb` route: records the endpoint as requested through epb.
#[derive(Debug, Clone, Copy, Default)]
pub struct EpbRoute;

impl EpbAdapter for EpbRoute {
    fn endpoint(&self, run: &mut HalcyonRun, endpoint: &str) -> Result<(), ZeroError> {
        request_endpoint(run, endpoint, Route::Epb)
    }
}

/// Write the handover evidence required before finishing.
///
/// The summary and every evidence line are bounded and must not contain control
/// characters other than newline and tab, so terminal escapes and NUL bytes
/// cannot reach a transcript or a log through this path.
pub fn handover(
    run: &mut HalcyonRun,
    summary: &str,
    evidence: Vec<String>,
    now_ms: i64,
) -> Result<Handover, ZeroError> {
    ensure_open(run)?;
    validate_text("handover summary", summary, MAX_HANDOVER_SUMMARY_BYTES)?;
    if evidence.len() > MAX_EVIDENCE_ITEMS {
        return Err(limit(format!(
            "handover has {} evidence lines, above the {MAX_EVIDENCE_ITEMS} line limit",
            evidence.len()
        )));
    }
    for line in &evidence {
        validate_text("handover evidence line", line, MAX_EVIDENCE_BYTES)?;
        if line.chars().any(|character| character.is_control()) {
            return Err(invalid(
                "handover evidence lines must be one line each, with no control characters",
            ));
        }
    }
    let record = Handover {
        at_ms: now_ms,
        summary: summary.to_string(),
        evidence,
    };
    run.handover = Some(record.clone());
    Ok(record)
}

/// Evaluate the completion gate without changing the run.
///
/// Refused when, in this order:
///
/// 1. no `tkb check` record exists (`tkb check required`);
/// 2. the latest check failed and no later success replaced it;
/// 3. an unresolved gap exists that is not an explicitly waived info gap;
/// 4. no handover exists;
/// 5. a gate was requested through a route other than `joker`, or an endpoint
///    through a route other than `epb`.
pub fn can_finish(run: &HalcyonRun) -> Result<FinishReport, ZeroError> {
    let Some(check) = run.check.as_ref() else {
        return Err(denied(format!(
            "tkb check required: record a `tkb check` result before finishing (see {BEHAVIOUR_DOCS_ANCHOR})"
        )));
    };
    if !check.ok {
        return Err(denied(format!(
            "the latest `tkb check` failed at {} ms ({}); fix the errors and run `tkb check` again (see {BEHAVIOUR_DOCS_ANCHOR})",
            check.at_ms, check.summary
        )));
    }
    let blocking: Vec<&Gap> = run.gaps.iter().filter(|gap| gap.is_blocking()).collect();
    if !blocking.is_empty() {
        let ids = blocking
            .iter()
            .take(3)
            .map(|gap| gap.id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let more = blocking.len().saturating_sub(3);
        let suffix = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        return Err(denied(format!(
            "{} unresolved gap(s) block the handover: {ids}{suffix}; resolve them, or waive info gaps explicitly (see {BEHAVIOUR_DOCS_ANCHOR})",
            blocking.len()
        )));
    }
    let Some(handover) = run.handover.as_ref() else {
        return Err(denied(format!(
            "handover required: write one with `tkb handover write` before finishing (see {BEHAVIOUR_DOCS_ANCHOR})"
        )));
    };
    if let Some(gate) = run.gates.iter().find(|gate| gate.via != Route::Joker) {
        return Err(denied(format!(
            "gate `{}` was requested through {}; gates run only through joker, so the run cannot finish (see {BEHAVIOUR_DOCS_ANCHOR})",
            gate.gate,
            gate.via.as_str()
        )));
    }
    if let Some(endpoint) = run
        .endpoints
        .iter()
        .find(|endpoint| endpoint.via != Route::Epb)
    {
        return Err(denied(format!(
            "endpoint `{}` was requested through {}; endpoints route only through epb, so the run cannot finish (see {BEHAVIOUR_DOCS_ANCHOR})",
            endpoint.endpoint,
            endpoint.via.as_str()
        )));
    }
    Ok(FinishReport {
        run_id: run.run_id.clone(),
        check: check.clone(),
        handover: handover.clone(),
        gaps: run.gaps.clone(),
        gates: run.gates.clone(),
        endpoints: run.endpoints.clone(),
    })
}

/// Finish a run, but only after [`can_finish`] passes.
///
/// The first successful call stamps `finished_ms` with `now_ms`. A second call
/// is idempotent: it re-evaluates the (unchanged) evidence, returns the same
/// report, and leaves `finished_ms` alone. A failed gate never stamps the run,
/// so a caller can fix the evidence and try again.
pub fn finish(run: &mut HalcyonRun, now_ms: i64) -> Result<FinishReport, ZeroError> {
    let report = can_finish(run)?;
    if run.finished_ms.is_none() {
        run.finished_ms = Some(now_ms);
    }
    Ok(report)
}

/// Refuse new evidence once a run has finished.
fn ensure_open(run: &HalcyonRun) -> Result<(), ZeroError> {
    if let Some(finished_ms) = run.finished_ms {
        return Err(denied(format!(
            "run `{}` finished at {finished_ms} ms; evidence cannot change after the handover (see {BEHAVIOUR_DOCS_ANCHOR})",
            run.run_id
        )));
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), ZeroError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must not be empty")));
    }
    if value.len() > MAX_NAME_BYTES {
        return Err(limit(format!(
            "{field} is {} bytes, above the {MAX_NAME_BYTES} byte limit",
            value.len()
        )));
    }
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(invalid(format!(
            "{field} must be non-empty visible ASCII without spaces"
        )));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, max_bytes: usize) -> Result<(), ZeroError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must not be empty")));
    }
    if value.len() > max_bytes {
        return Err(limit(format!(
            "{field} is {} bytes, above the {max_bytes} byte limit",
            value.len()
        )));
    }
    if value
        .chars()
        .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(invalid(format!(
            "{field} must not contain control characters other than newline and tab"
        )));
    }
    Ok(())
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn not_found(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::NotFound, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: i64 = 1_700_000_000_000;
    const EVIDENCE: &str = "cargo test -p zero-halcyon";

    fn new_run() -> HalcyonRun {
        HalcyonRun::new("run-1", START).expect("run")
    }

    fn passing_check(run: &mut HalcyonRun) {
        record_check(run, true, "0 errors", START + 1_000).expect("check");
    }

    fn written_handover(run: &mut HalcyonRun) {
        handover(
            run,
            "T-HAL-05 behaviour rules implemented",
            vec![EVIDENCE.to_string()],
            START + 2_000,
        )
        .expect("handover");
    }

    #[test]
    fn a_run_without_a_tkb_check_is_refused() {
        let mut run = new_run();
        written_handover(&mut run);

        let error = can_finish(&run).expect_err("no check must refuse");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(
            error.message().contains("tkb check required"),
            "{}",
            error.message()
        );

        assert!(finish(&mut run, START + 3_000).is_err());
        assert!(!run.is_finished());
        assert_eq!(run.finished_ms, None);
    }

    #[test]
    fn a_passing_check_and_a_handover_finish() {
        let mut run = new_run();
        passing_check(&mut run);
        written_handover(&mut run);

        let report = finish(&mut run, START + 3_000).expect("finish");

        assert_eq!(report.run_id, "run-1");
        assert_eq!(report.evidence().len(), 1);
        assert_eq!(report.evidence()[0], EVIDENCE);
        assert_eq!(report.check.summary, "0 errors");
        assert!(report.gaps.is_empty());
        assert!(report.gates.is_empty());
        assert!(report.endpoints.is_empty());
        assert!(run.is_finished());
        assert_eq!(run.finished_ms, Some(START + 3_000));
    }

    #[test]
    fn a_failed_check_then_a_success_is_allowed() {
        let mut run = new_run();
        record_check(&mut run, false, "2 errors", START + 500).expect("failed check");
        written_handover(&mut run);

        let error = can_finish(&run).expect_err("failed check must refuse");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("failed"), "{}", error.message());

        passing_check(&mut run);
        let report = finish(&mut run, START + 3_000).expect("later success");
        assert!(report.check.ok);
        assert_eq!(report.check.summary, "0 errors");
    }

    #[test]
    fn a_failed_check_with_no_retry_is_refused() {
        let mut run = new_run();
        record_check(&mut run, false, "1 error", START + 500).expect("failed check");
        written_handover(&mut run);

        let error = can_finish(&run).expect_err("no retry must refuse");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("failed"), "{}", error.message());
        assert!(finish(&mut run, START + 3_000).is_err());
        assert!(!run.is_finished());
    }

    #[test]
    fn an_unresolved_high_gap_is_refused() {
        let mut run = new_run();
        let gap = record_gap(
            &mut run,
            "endpoint /orders has no handler",
            GapSeverity::High,
            START + 10,
        )
        .expect("gap");
        passing_check(&mut run);
        written_handover(&mut run);

        let error = can_finish(&run).expect_err("high gap must refuse");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(
            error.message().contains(&gap),
            "the refusal names the gap: {}",
            error.message()
        );
    }

    #[test]
    fn only_info_gaps_can_be_waived() {
        let mut run = new_run();
        let warn =
            record_gap(&mut run, "naming drift", GapSeverity::Warn, START + 10).expect("gap");
        let high =
            record_gap(&mut run, "missing handler", GapSeverity::High, START + 20).expect("gap");

        let error = waive_gap(&mut run, &warn).expect_err("warn cannot be waived");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("info"), "{}", error.message());

        let error = waive_gap(&mut run, &high).expect_err("high cannot be waived");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);

        let info = record_gap(&mut run, "docs note", GapSeverity::Info, START + 30).expect("gap");
        waive_gap(&mut run, &info).expect("info waiver");
        resolve_gap(&mut run, &warn).expect("resolve warn");
        resolve_gap(&mut run, &high).expect("resolve high");
        passing_check(&mut run);
        written_handover(&mut run);

        let report = finish(&mut run, START + 3_000).expect("resolved and waived");
        assert_eq!(report.gaps.len(), 3);
    }

    #[test]
    fn a_resolved_gap_and_an_info_waiver_are_allowed() {
        let mut run = new_run();
        let high =
            record_gap(&mut run, "missing handler", GapSeverity::High, START + 10).expect("gap");
        let info = record_gap(&mut run, "spelling", GapSeverity::Info, START + 20).expect("gap");
        resolve_gap(&mut run, &high).expect("resolve");
        // Resolving twice is a no-op, not an error.
        resolve_gap(&mut run, &high).expect("idempotent resolve");
        waive_gap(&mut run, &info).expect("waive");
        passing_check(&mut run);
        written_handover(&mut run);

        finish(&mut run, START + 3_000).expect("allowed");
        assert!(run.gaps.iter().all(|gap| !gap.is_blocking()));
    }

    #[test]
    fn a_direct_gate_is_refused_and_recorded() {
        let mut run = new_run();
        passing_check(&mut run);
        written_handover(&mut run);

        let error = request_gate(&mut run, "unit", Route::Direct).expect_err("direct gate");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(
            error.message().contains("gates run only through joker"),
            "{}",
            error.message()
        );
        assert_eq!(run.gates.len(), 1, "the refusal is recorded");
        assert_eq!(run.gates[0].via, Route::Direct);

        // A cross-route call is refused and recorded the same way.
        let error = request_gate(&mut run, "vet", Route::Epb).expect_err("epb gate");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(run.gates.len(), 2);

        let error = can_finish(&run).expect_err("recorded violation blocks");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("joker"), "{}", error.message());
    }

    #[test]
    fn a_gate_through_joker_is_allowed() {
        let mut run = new_run();
        passing_check(&mut run);
        written_handover(&mut run);

        request_gate(&mut run, "unit", Route::Joker).expect("joker gate");
        JokerRoute.gate(&mut run, "build").expect("adapter seam");

        assert_eq!(run.gates.len(), 2);
        assert!(run.gates.iter().all(|gate| gate.via == Route::Joker));
        let report = can_finish(&run).expect("quiet routes");
        assert_eq!(report.gates.len(), 2);
    }

    #[test]
    fn a_direct_endpoint_is_refused_and_recorded() {
        let mut run = new_run();
        passing_check(&mut run);
        written_handover(&mut run);

        let error = request_endpoint(&mut run, "/orders", Route::Direct).expect_err("direct");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(
            error.message().contains("endpoints route only through epb"),
            "{}",
            error.message()
        );
        assert_eq!(run.endpoints.len(), 1);
        assert_eq!(run.endpoints[0].via, Route::Direct);

        let error = can_finish(&run).expect_err("recorded violation blocks");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("epb"), "{}", error.message());
    }

    #[test]
    fn an_endpoint_through_epb_is_allowed() {
        let mut run = new_run();
        passing_check(&mut run);
        written_handover(&mut run);

        request_endpoint(&mut run, "/orders", Route::Epb).expect("epb endpoint");
        EpbRoute.endpoint(&mut run, "/users").expect("adapter seam");

        assert!(run
            .endpoints
            .iter()
            .all(|endpoint| endpoint.via == Route::Epb));
        let report = can_finish(&run).expect("quiet routes");
        assert_eq!(report.endpoints.len(), 2);
    }

    #[test]
    fn a_missing_handover_is_refused() {
        let mut run = new_run();
        passing_check(&mut run);

        let error = can_finish(&run).expect_err("handover required");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("handover"), "{}", error.message());
        assert!(finish(&mut run, START + 3_000).is_err());
        assert!(!run.is_finished());
    }

    #[test]
    fn a_malformed_handover_is_refused() {
        let mut run = new_run();

        let error = handover(&mut run, "", Vec::new(), START).expect_err("empty summary");
        assert_eq!(error.code(), ErrorCode::InvalidInput);

        let error =
            handover(&mut run, "esc\u{1b}[31mred", Vec::new(), START).expect_err("terminal escape");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("control"), "{}", error.message());

        let error = handover(&mut run, "ok", vec!["line\u{0}break".to_string()], START)
            .expect_err("nul in evidence");
        assert_eq!(error.code(), ErrorCode::InvalidInput);

        let too_long = "a".repeat(MAX_HANDOVER_SUMMARY_BYTES + 1);
        let error = handover(&mut run, &too_long, Vec::new(), START).expect_err("oversized");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);

        assert_eq!(run.handover, None, "a refused handover stores nothing");
    }

    #[test]
    fn finish_is_idempotent() {
        let mut run = new_run();
        passing_check(&mut run);
        written_handover(&mut run);

        let first = finish(&mut run, START + 3_000).expect("first finish");
        let first_stamp = run.finished_ms;
        let second = finish(&mut run, START + 9_000).expect("second finish");

        assert_eq!(first, second);
        assert_eq!(run.finished_ms, first_stamp);
        assert_eq!(run.finished_ms, Some(START + 3_000));
    }

    #[test]
    fn a_finished_run_refuses_new_evidence() {
        let mut run = new_run();
        passing_check(&mut run);
        written_handover(&mut run);
        finish(&mut run, START + 3_000).expect("finish");

        let error = record_check(&mut run, false, "1 error", START + 4_000).expect_err("closed");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("finished"), "{}", error.message());

        assert!(record_gap(&mut run, "late gap", GapSeverity::High, START + 4_000).is_err());
        assert!(request_gate(&mut run, "unit", Route::Joker).is_err());
        assert!(request_endpoint(&mut run, "/orders", Route::Epb).is_err());
        assert!(handover(&mut run, "again", Vec::new(), START + 4_000).is_err());

        // The recorded evidence is untouched and the gate still passes.
        assert!(can_finish(&run).is_ok());
        assert_eq!(run.check.as_ref().map(|check| check.ok), Some(true));
    }
}
