//! Derived reports (T-SR-06 / SR-06, SR-14).
//!
//! [`derive`] turns the canonical records — a validated [`CoverageLedger`] and
//! [`Findings`] — into the three prose artifacts plus the two JSON copies:
//!
//! - `REPORT.md`: summary counts, scope/profile, partial flag, confirmed
//!   findings, coverage and budget gaps. No proposal or fix text.
//! - `FINDINGS-DETAIL.md`: one section per confirmed finding with the unit,
//!   severity, canonical evidence, checks, and the unit's validation history.
//! - `NEEDS-VALIDATION.md`: every unit without a confirmed verdict and every
//!   unconfirmed finding, each with its recorded status.
//!
//! Reports are derived, never authored: a renderer may only print fields that
//! exist in the records, ordered by finding id and unit id, with timestamps
//! derived from [`ReportInputs::created_at_ms`]. [`consistency_report`] parses
//! the generated Markdown back and compares it with the JSON copies, so prose
//! and records cannot drift silently.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, Result, ZeroError};

use crate::ledger::{invalid, validate as validate_ledger, CoverageLedger, LedgerUnit, UnitStatus};
use crate::schema::{
    validate_findings, validate_refs, Finding, FindingStatus, Findings, ReviewProfile, Severity,
};

/// Canonical report artifact name.
pub const REPORT_FILE: &str = "REPORT.md";
/// Canonical confirmed-findings artifact name.
pub const FINDINGS_DETAIL_FILE: &str = "FINDINGS-DETAIL.md";
/// Canonical needs-validation artifact name.
pub const NEEDS_VALIDATION_FILE: &str = "NEEDS-VALIDATION.md";

/// Budget accounting for one run (SR-12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetReport {
    /// Critic and validation agent slots reserved before hunting.
    pub reserved_agents: usize,
    /// Slots actually used.
    pub used_agents: usize,
    /// Unit slots reserved before hunting.
    pub reserved_units: usize,
    /// Unit slots actually used.
    pub used_units: usize,
    /// True when the run stopped short of its plan.
    pub incomplete: bool,
    /// Why the run is incomplete. Required and non-empty when `incomplete`.
    pub reasons: Vec<String>,
}

/// Everything a derived report is allowed to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportInputs {
    pub ledger: CoverageLedger,
    pub findings: Findings,
    pub budget: BudgetReport,
    pub profile: ReviewProfile,
    pub run_id: String,
    pub created_at_ms: i64,
}

/// The written report set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportBundle {
    pub out_dir: PathBuf,
    pub run_id: String,
    pub created_at_ms: i64,
    pub profile: ReviewProfile,
    /// True when the run is partial for profile, budget, or truncation reasons.
    pub partial: bool,
    pub report_md: String,
    pub findings_detail_md: String,
    pub needs_validation_md: String,
    pub findings_json: String,
    pub ledger_json: String,
    /// File names written, in stable order.
    pub files: Vec<String>,
}

/// Prose/JSON agreement for one bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyReport {
    /// Confirmed finding ids parsed from `REPORT.md`, sorted.
    pub report_ids: Vec<String>,
    /// Confirmed finding ids parsed from `FINDINGS-DETAIL.md`, sorted.
    pub detail_ids: Vec<String>,
    /// Unconfirmed finding ids parsed from `NEEDS-VALIDATION.md`, sorted.
    pub needs_validation_ids: Vec<String>,
    /// Every finding id in `findings.json`, sorted.
    pub json_ids: Vec<String>,
    pub ok: bool,
    pub mismatches: Vec<String>,
}

/// Derive and write the report set.
///
/// Every input is validated before the output directory is touched: an
/// invalid ledger, an invalid finding record, an orphan finding, a duplicate
/// id, or a contradictory budget is refused with `zero.fnd.invalid_input` and
/// no file is written.
pub fn derive(inputs: ReportInputs, out_dir: impl AsRef<Path>) -> Result<ReportBundle> {
    validate_inputs(&inputs)?;
    let out_dir = out_dir.as_ref();

    let (partial, partial_reasons) = partial_reasons(&inputs);
    let report_md = render_report(&inputs, partial, &partial_reasons);
    let findings_detail_md = render_findings_detail(&inputs);
    let needs_validation_md = render_needs_validation(&inputs);
    let findings_json = serde_json::to_string_pretty(&inputs.findings)?;
    let ledger_json = inputs.ledger.to_json_pretty()?;
    let files = [
        REPORT_FILE,
        FINDINGS_DETAIL_FILE,
        NEEDS_VALIDATION_FILE,
        crate::schema::FINDINGS_FILE,
        crate::ledger::LEDGER_FILE,
    ];

    // Prove the prose agrees with the records before anything is written, so an
    // inconsistent bundle is never published.
    let preview = ReportBundle {
        out_dir: out_dir.to_path_buf(),
        run_id: inputs.run_id.clone(),
        created_at_ms: inputs.created_at_ms,
        profile: inputs.profile,
        partial,
        report_md: report_md.clone(),
        findings_detail_md: findings_detail_md.clone(),
        needs_validation_md: needs_validation_md.clone(),
        findings_json: findings_json.clone(),
        ledger_json: ledger_json.clone(),
        files: files.iter().map(|name| (*name).to_string()).collect(),
    };
    let consistency = consistency_report(&preview);
    if !consistency.ok {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            format!(
                "derived reports are inconsistent: {}",
                consistency.mismatches.join("; ")
            ),
        ));
    }

    std::fs::create_dir_all(out_dir)?;
    for (name, contents) in [
        (REPORT_FILE, report_md.as_str()),
        (FINDINGS_DETAIL_FILE, findings_detail_md.as_str()),
        (NEEDS_VALIDATION_FILE, needs_validation_md.as_str()),
        (crate::schema::FINDINGS_FILE, findings_json.as_str()),
        (crate::ledger::LEDGER_FILE, ledger_json.as_str()),
    ] {
        std::fs::write(out_dir.join(name), contents)?;
    }

    // Read the copies back and validate them, so the bundle proves what landed
    // on disk rather than what was in memory.
    let findings_copy = std::fs::read_to_string(out_dir.join(crate::schema::FINDINGS_FILE))?;
    let ledger_copy = std::fs::read_to_string(out_dir.join(crate::ledger::LEDGER_FILE))?;
    let parsed_findings: Findings = serde_json::from_str(&findings_copy)?;
    validate_findings(&parsed_findings)?;
    let parsed_ledger = CoverageLedger::from_json_str(&ledger_copy)?;
    validate_ledger(&parsed_ledger)?;
    if parsed_findings != inputs.findings || parsed_ledger != inputs.ledger {
        return Err(invalid(
            "a written record copy does not match the record it was derived from",
        ));
    }
    for name in [REPORT_FILE, FINDINGS_DETAIL_FILE, NEEDS_VALIDATION_FILE] {
        let disk = std::fs::read_to_string(out_dir.join(name))?;
        let expected = match name {
            REPORT_FILE => &report_md,
            FINDINGS_DETAIL_FILE => &findings_detail_md,
            _ => &needs_validation_md,
        };
        if &disk != expected {
            return Err(invalid(format!(
                "`{name}` on disk does not match the generated report"
            )));
        }
    }

    Ok(ReportBundle {
        out_dir: out_dir.to_path_buf(),
        run_id: inputs.run_id,
        created_at_ms: inputs.created_at_ms,
        profile: inputs.profile,
        partial,
        report_md,
        findings_detail_md,
        needs_validation_md,
        findings_json: findings_copy,
        ledger_json: ledger_copy,
        files: files.iter().map(|name| (*name).to_string()).collect(),
    })
}

/// Parse the bundle's Markdown and compare it with the JSON copies.
///
/// `ok` is true only when the confirmed finding sets and severities agree, the
/// unconfirmed finding set appears only in `NEEDS-VALIDATION.md`, every unit
/// without a confirmed verdict appears there with its recorded status, and the
/// summary counts match the ledger and findings records.
pub fn consistency_report(bundle: &ReportBundle) -> ConsistencyReport {
    let mut mismatches: Vec<String> = Vec::new();
    let findings = match serde_json::from_str::<Findings>(&bundle.findings_json) {
        Ok(findings) => {
            if let Err(error) = validate_findings(&findings) {
                mismatches.push(format!(
                    "findings.json does not validate: {}",
                    error.message()
                ));
            }
            Some(findings)
        }
        Err(error) => {
            mismatches.push(format!("findings.json does not parse: {error}"));
            None
        }
    };
    let ledger = match CoverageLedger::from_json_str(&bundle.ledger_json) {
        Ok(ledger) => Some(ledger),
        Err(error) => {
            mismatches.push(format!(
                "coverage-ledger.json does not validate: {}",
                error.message()
            ));
            None
        }
    };
    let (Some(findings), Some(ledger)) = (findings, ledger) else {
        mismatches.sort();
        mismatches.dedup();
        return ConsistencyReport {
            report_ids: Vec::new(),
            detail_ids: Vec::new(),
            needs_validation_ids: Vec::new(),
            json_ids: Vec::new(),
            ok: false,
            mismatches,
        };
    };

    let report_findings = parse_report_findings(&bundle.report_md);
    let detail_findings = parse_detail_findings(&bundle.findings_detail_md);
    let needs_findings = parse_needs_findings(&bundle.needs_validation_md);
    let needs_units = parse_needs_units(&bundle.needs_validation_md);
    let counts = parse_summary_counts(&bundle.report_md);

    let json_by_id: BTreeMap<&str, &Finding> = findings
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect();
    let json_ids = sorted_ids(findings.findings.iter().map(|finding| finding.id.as_str()));
    let confirmed: BTreeSet<String> = findings
        .findings
        .iter()
        .filter(|finding| finding.confirmed)
        .map(|finding| finding.id.clone())
        .collect();
    let unconfirmed: BTreeSet<String> = findings
        .findings
        .iter()
        .filter(|finding| !finding.confirmed)
        .map(|finding| finding.id.clone())
        .collect();

    let report_raw: Vec<String> = report_findings
        .iter()
        .map(|entry| entry.id.clone())
        .collect();
    let detail_raw: Vec<String> = detail_findings
        .iter()
        .map(|entry| entry.id.clone())
        .collect();
    let needs_findings_raw: Vec<String> = needs_findings
        .iter()
        .map(|entry| entry.id.clone())
        .collect();
    let needs_units_raw: Vec<String> = needs_units.iter().map(|entry| entry.id.clone()).collect();

    report_duplicates("REPORT.md", &report_raw, &mut mismatches);
    report_duplicates("FINDINGS-DETAIL.md", &detail_raw, &mut mismatches);
    report_duplicates(
        "NEEDS-VALIDATION.md findings",
        &needs_findings_raw,
        &mut mismatches,
    );
    report_duplicates(
        "NEEDS-VALIDATION.md units",
        &needs_units_raw,
        &mut mismatches,
    );

    let report_ids = sorted_ids(report_raw.iter().map(String::as_str));
    let detail_ids = sorted_ids(detail_raw.iter().map(String::as_str));
    let needs_validation_ids = sorted_ids(needs_findings_raw.iter().map(String::as_str));

    compare_id_sets(
        "REPORT.md",
        &confirmed,
        &report_ids.iter().cloned().collect(),
        &mut mismatches,
    );
    compare_id_sets(
        "FINDINGS-DETAIL.md",
        &confirmed,
        &detail_ids.iter().cloned().collect(),
        &mut mismatches,
    );
    compare_id_sets(
        "NEEDS-VALIDATION.md findings",
        &unconfirmed,
        &needs_validation_ids.iter().cloned().collect(),
        &mut mismatches,
    );

    // Severity agreement for every confirmed finding shown in prose.
    for entry in &report_findings {
        if let Some(finding) = json_by_id.get(entry.id.as_str()) {
            if finding.severity != entry.severity {
                mismatches.push(format!(
                    "REPORT.md gives `{}` severity {} but findings.json says {}",
                    entry.id,
                    entry.severity.as_str(),
                    finding.severity.as_str()
                ));
            }
            if !finding.confirmed {
                mismatches.push(format!(
                    "REPORT.md lists unconfirmed finding `{}`",
                    entry.id
                ));
            }
        }
    }
    for entry in &detail_findings {
        let Some(finding) = json_by_id.get(entry.id.as_str()) else {
            continue;
        };
        if !finding.confirmed {
            mismatches.push(format!(
                "FINDINGS-DETAIL.md lists unconfirmed finding `{}`",
                entry.id
            ));
        }
        match entry.severity {
            Some(severity) if severity != finding.severity => mismatches.push(format!(
                "FINDINGS-DETAIL.md gives `{}` severity {} but findings.json says {}",
                entry.id,
                severity.as_str(),
                finding.severity.as_str()
            )),
            None => mismatches.push(format!(
                "FINDINGS-DETAIL.md has no severity for `{}`",
                entry.id
            )),
            _ => {}
        }
        match entry.unit_id.as_deref() {
            Some(unit_id) if unit_id != finding.unit_id => mismatches.push(format!(
                "FINDINGS-DETAIL.md gives `{}` unit `{unit_id}` but findings.json says `{}`",
                entry.id, finding.unit_id
            )),
            None => mismatches.push(format!("FINDINGS-DETAIL.md has no unit for `{}`", entry.id)),
            _ => {}
        }
    }
    for entry in &needs_findings {
        let Some(finding) = json_by_id.get(entry.id.as_str()) else {
            continue;
        };
        if finding.confirmed {
            mismatches.push(format!(
                "NEEDS-VALIDATION.md lists confirmed finding `{}`",
                entry.id
            ));
        }
        if finding.status != entry.status {
            mismatches.push(format!(
                "NEEDS-VALIDATION.md gives `{}` status {} but findings.json says {}",
                entry.id,
                entry.status.as_str(),
                finding.status.as_str()
            ));
        }
        if finding.severity != entry.severity {
            mismatches.push(format!(
                "NEEDS-VALIDATION.md gives `{}` severity {} but findings.json says {}",
                entry.id,
                entry.severity.as_str(),
                finding.severity.as_str()
            ));
        }
    }

    // Every unit without a confirmed verdict must be visible in the file that
    // promises to leave nothing out.
    let unit_status: BTreeMap<&str, UnitStatus> = ledger
        .units
        .iter()
        .map(|unit| (unit.id.as_str(), unit.status))
        .collect();
    let expected_units: BTreeSet<String> = ledger
        .units
        .iter()
        .filter(|unit| unit.status != UnitStatus::Confirmed)
        .map(|unit| unit.id.clone())
        .collect();
    let parsed_units: BTreeSet<String> = needs_units.iter().map(|entry| entry.id.clone()).collect();
    for id in expected_units.difference(&parsed_units) {
        mismatches.push(format!(
            "NEEDS-VALIDATION.md is missing unit `{id}` ({})",
            unit_status
                .get(id.as_str())
                .map_or("unknown", |status| status.as_str())
        ));
    }
    for id in parsed_units.difference(&expected_units) {
        mismatches.push(format!(
            "NEEDS-VALIDATION.md lists unit `{id}` that already has a confirmed verdict or is not in the ledger"
        ));
    }
    for entry in &needs_units {
        if let Some(status) = unit_status.get(entry.id.as_str()) {
            if *status != entry.status {
                mismatches.push(format!(
                    "NEEDS-VALIDATION.md gives unit `{}` status {} but coverage-ledger.json says {}",
                    entry.id,
                    entry.status.as_str(),
                    status.as_str()
                ));
            }
        }
    }

    // Summary counts.
    let unit_count = |status: UnitStatus| {
        ledger
            .units
            .iter()
            .filter(|unit| unit.status == status)
            .count()
    };
    let gaps = unit_count(UnitStatus::Pending)
        + unit_count(UnitStatus::Assigned)
        + unit_count(UnitStatus::Deferred)
        + unit_count(UnitStatus::Blocked);
    let expected_counts: [(&str, usize); 12] = [
        ("Units", ledger.units.len()),
        ("Findings", findings.findings.len()),
        ("Confirmed findings", confirmed.len()),
        ("Unconfirmed findings", unconfirmed.len()),
        ("Reviewed units", unit_count(UnitStatus::Reviewed)),
        ("Confirmed units", unit_count(UnitStatus::Confirmed)),
        ("Assigned units", unit_count(UnitStatus::Assigned)),
        ("Pending units", unit_count(UnitStatus::Pending)),
        ("Refuted units", unit_count(UnitStatus::Refuted)),
        ("Deferred units", unit_count(UnitStatus::Deferred)),
        ("Blocked units", unit_count(UnitStatus::Blocked)),
        ("Out of scope units", unit_count(UnitStatus::OutOfScope)),
    ];
    for (label, expected) in expected_counts {
        match counts.get(label) {
            None => mismatches.push(format!("REPORT.md has no `{label}` count")),
            Some(actual) if *actual != expected => mismatches.push(format!(
                "REPORT.md `{label}` is {actual} but the records have {expected}"
            )),
            _ => {}
        }
    }
    match counts.get("Coverage gaps") {
        None => mismatches.push("REPORT.md has no `Coverage gaps` count".to_string()),
        Some(actual) if *actual != gaps => mismatches.push(format!(
            "REPORT.md `Coverage gaps` is {actual} but the records have {gaps}"
        )),
        _ => {}
    }

    mismatches.sort();
    mismatches.dedup();
    let ok = mismatches.is_empty();
    ConsistencyReport {
        report_ids,
        detail_ids,
        needs_validation_ids,
        json_ids,
        ok,
        mismatches,
    }
}

/// Fail when the prose and the records disagree.
pub fn assert_consistent(bundle: &ReportBundle) -> Result<()> {
    let report = consistency_report(bundle);
    if report.ok {
        return Ok(());
    }
    Err(ZeroError::new(
        ErrorCode::InvalidInput,
        format!(
            "report consistency check failed: {}",
            report.mismatches.join("; ")
        ),
    ))
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_inputs(inputs: &ReportInputs) -> Result<()> {
    if !is_report_token(&inputs.run_id) {
        return Err(invalid(
            "run id must be non-empty and free of whitespace, control characters, backticks, and pipes",
        ));
    }
    if inputs.created_at_ms < 0 {
        return Err(invalid("created_at_ms must not be negative"));
    }
    validate_ledger(&inputs.ledger)?;
    validate_refs(&inputs.ledger.units, None)?;
    validate_findings(&inputs.findings)?;

    let unit_ids: BTreeSet<&str> = inputs
        .ledger
        .units
        .iter()
        .map(|unit| unit.id.as_str())
        .collect();
    for unit in &inputs.ledger.units {
        if !is_report_token(&unit.id) {
            return Err(invalid(format!(
                "unit id `{}` cannot be rendered safely in Markdown",
                unit.id
            )));
        }
    }
    for finding in &inputs.findings.findings {
        if !unit_ids.contains(finding.unit_id.as_str()) {
            return Err(invalid(format!(
                "finding `{}` names unit `{}`, which is not in the ledger",
                finding.id, finding.unit_id
            )));
        }
        if !is_report_token(&finding.id) {
            return Err(invalid(format!(
                "finding id `{}` cannot be rendered safely in Markdown",
                finding.id
            )));
        }
    }

    match (inputs.budget.incomplete, inputs.budget.reasons.is_empty()) {
        (true, true) => {
            return Err(invalid(
                "an incomplete run must name at least one budget reason",
            ))
        }
        (false, false) => return Err(invalid("a complete run must not carry incomplete reasons")),
        _ => {}
    }
    for reason in &inputs.budget.reasons {
        if reason.trim().is_empty() {
            return Err(invalid("a budget reason must not be blank"));
        }
    }
    Ok(())
}

fn is_report_token(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || ch == '`' || ch == '|')
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

fn partial_reasons(inputs: &ReportInputs) -> (bool, Vec<String>) {
    let mut reasons: Vec<String> = Vec::new();
    if inputs.budget.incomplete {
        reasons.extend(
            inputs
                .budget
                .reasons
                .iter()
                .map(|reason| flatten_text(reason)),
        );
    }
    let cap = inputs.profile.budget();
    if inputs.ledger.units.len() > cap.max_units {
        reasons.push(format!(
            "the ledger has {} unit(s), above the {} profile cap of {}",
            inputs.ledger.units.len(),
            inputs.profile.as_str(),
            cap.max_units
        ));
    }
    if inputs.ledger.summary.walk_truncated {
        for note in &inputs.ledger.summary.truncation {
            reasons.push(format!("seed walk truncated: {}", flatten_text(note)));
        }
    }
    if inputs.budget.used_agents > inputs.budget.reserved_agents {
        reasons.push(format!(
            "used agents {} exceed the reserved {}",
            inputs.budget.used_agents, inputs.budget.reserved_agents
        ));
    }
    if inputs.budget.used_units > inputs.budget.reserved_units {
        reasons.push(format!(
            "used units {} exceed the reserved {}",
            inputs.budget.used_units, inputs.budget.reserved_units
        ));
    }
    let partial = !reasons.is_empty();
    (partial, reasons)
}

fn render_report(inputs: &ReportInputs, partial: bool, partial_reasons: &[String]) -> String {
    let mut out = String::new();
    let confirmed: Vec<&Finding> = sorted_findings(inputs, true);
    let unconfirmed: Vec<&Finding> = sorted_findings(inputs, false);
    let units = sorted_units(&inputs.ledger);
    let count = |status: UnitStatus| {
        inputs
            .ledger
            .units
            .iter()
            .filter(|unit| unit.status == status)
            .count()
    };
    let gaps: Vec<&&LedgerUnit> = units
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
        .collect();

    let _ = writeln!(out, "# Security review report");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Run: `{}`", inputs.run_id);
    let _ = writeln!(
        out,
        "- Created: {}",
        format_timestamp_ms(inputs.created_at_ms)
    );
    let _ = writeln!(out, "- Profile: `{}`", inputs.profile.as_str());
    let _ = writeln!(out, "- Partial: {}", yes_no(partial));
    let _ = writeln!(out, "- Detail: [FINDINGS-DETAIL.md](FINDINGS-DETAIL.md)");
    let _ = writeln!(
        out,
        "- Needs validation: [NEEDS-VALIDATION.md](NEEDS-VALIDATION.md)"
    );
    let _ = writeln!(out, "- Records: `findings.json`, `coverage-ledger.json`");

    let _ = writeln!(out);
    let _ = writeln!(out, "## Summary");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Units: {}", inputs.ledger.units.len());
    let _ = writeln!(out, "- Findings: {}", inputs.findings.findings.len());
    let _ = writeln!(out, "- Confirmed findings: {}", confirmed.len());
    let _ = writeln!(out, "- Unconfirmed findings: {}", unconfirmed.len());

    let _ = writeln!(out);
    let _ = writeln!(out, "## Scope");
    let _ = writeln!(out);
    let cap = inputs.profile.budget();
    let _ = writeln!(out, "- Profile: `{}`", inputs.profile.as_str());
    let _ = writeln!(out, "- Profile max units: {}", cap.max_units);
    let _ = writeln!(out, "- Profile max agents: {}", cap.max_agents);
    let _ = writeln!(out, "- Profile max files: {}", cap.max_files);
    let _ = writeln!(out, "- Partial: {}", yes_no(partial));
    if partial_reasons.is_empty() {
        let _ = writeln!(out, "- Partial reason: none");
    } else {
        for reason in partial_reasons {
            let _ = writeln!(out, "- Partial reason: {reason}");
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "## Coverage summary");
    let _ = writeln!(out);
    for (label, status) in [
        ("Reviewed units", UnitStatus::Reviewed),
        ("Confirmed units", UnitStatus::Confirmed),
        ("Assigned units", UnitStatus::Assigned),
        ("Pending units", UnitStatus::Pending),
        ("Refuted units", UnitStatus::Refuted),
        ("Deferred units", UnitStatus::Deferred),
        ("Blocked units", UnitStatus::Blocked),
        ("Out of scope units", UnitStatus::OutOfScope),
    ] {
        let _ = writeln!(out, "- {label}: {}", count(status));
    }
    let _ = writeln!(out, "- Coverage gaps: {}", gaps.len());

    let _ = writeln!(out);
    let _ = writeln!(out, "## Coverage gaps");
    let _ = writeln!(out);
    if gaps.is_empty() {
        let _ = writeln!(out, "- None.");
    } else {
        for unit in gaps {
            let _ = writeln!(
                out,
                "- `{}` ({}): {}",
                unit.id,
                unit.status.as_str(),
                flatten_text(&unit_reason(unit))
            );
        }
    }
    if inputs.ledger.summary.walk_truncated {
        for note in &inputs.ledger.summary.truncation {
            let _ = writeln!(out, "- Walk truncated: {}", flatten_text(note));
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "## Budget");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Reserved agents: {}", inputs.budget.reserved_agents);
    let _ = writeln!(out, "- Used agents: {}", inputs.budget.used_agents);
    let _ = writeln!(out, "- Reserved units: {}", inputs.budget.reserved_units);
    let _ = writeln!(out, "- Used units: {}", inputs.budget.used_units);
    let _ = writeln!(out, "- Incomplete: {}", yes_no(inputs.budget.incomplete));
    let _ = writeln!(
        out,
        "- Agent gap: {}",
        inputs
            .budget
            .reserved_agents
            .saturating_sub(inputs.budget.used_agents)
    );
    let _ = writeln!(
        out,
        "- Unit gap: {}",
        inputs
            .budget
            .reserved_units
            .saturating_sub(inputs.budget.used_units)
    );
    let over_budget = inputs.budget.used_agents > inputs.budget.reserved_agents
        || inputs.budget.used_units > inputs.budget.reserved_units;
    let _ = writeln!(out, "- Over budget: {}", yes_no(over_budget));
    for reason in &inputs.budget.reasons {
        let _ = writeln!(out, "- Reason: {}", flatten_text(reason));
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "## Confirmed findings");
    let _ = writeln!(out);
    if confirmed.is_empty() {
        let _ = writeln!(out, "- None.");
    } else {
        for finding in confirmed {
            let _ = writeln!(
                out,
                "- `{}` severity={}: {}",
                finding.id,
                finding.severity.as_str(),
                flatten_text(&finding.title)
            );
        }
    }
    out
}

fn render_findings_detail(inputs: &ReportInputs) -> String {
    let mut out = String::new();
    let confirmed = sorted_findings(inputs, true);
    let unit_by_id: BTreeMap<&str, &LedgerUnit> = inputs
        .ledger
        .units
        .iter()
        .map(|unit| (unit.id.as_str(), unit))
        .collect();

    let _ = writeln!(out, "# Confirmed findings detail");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Run: `{}`", inputs.run_id);
    let _ = writeln!(
        out,
        "- Created: {}",
        format_timestamp_ms(inputs.created_at_ms)
    );
    let _ = writeln!(out, "- Confirmed findings: {}", confirmed.len());
    if confirmed.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "No confirmed findings.");
    }
    for finding in confirmed {
        let Some(unit) = unit_by_id.get(finding.unit_id.as_str()) else {
            continue;
        };
        let _ = writeln!(out);
        let _ = writeln!(out, "## `{}` {}", finding.id, flatten_text(&finding.title));
        let _ = writeln!(out);
        let _ = writeln!(out, "- Finding: `{}`", finding.id);
        let _ = writeln!(out, "- Unit: `{}`", unit.id);
        let _ = writeln!(out, "- Severity: {}", finding.severity.as_str());
        let _ = writeln!(out, "- Status: {}", finding.status.as_str());
        let _ = writeln!(out, "- Evidence:");
        for reference in &finding.evidence_refs {
            let _ = writeln!(out, "  - `{reference}`");
        }
        let _ = writeln!(out, "- Checks:");
        if unit.checks.is_empty() {
            let _ = writeln!(out, "  - None recorded.");
        } else {
            for check in &unit.checks {
                let _ = writeln!(out, "  - {}", flatten_text(check));
            }
        }
        let _ = writeln!(out, "- Validation history:");
        if unit.history.is_empty() {
            let _ = writeln!(out, "  - None recorded.");
        } else {
            for event in &unit.history {
                let mut line = format!(
                    "{}: {} -> {} by {}",
                    format_timestamp_ms(i64::try_from(event.at_ms).unwrap_or(i64::MAX)),
                    event.from.as_str(),
                    event.to.as_str(),
                    flatten_text(&event.actor)
                );
                if let Some(note) = &event.note {
                    let note = flatten_text(note);
                    if !note.is_empty() {
                        let _ = write!(line, " (note: {note})");
                    }
                }
                let _ = writeln!(out, "  - {line}");
            }
        }
    }
    out
}

fn render_needs_validation(inputs: &ReportInputs) -> String {
    let mut out = String::new();
    let units = sorted_units(&inputs.ledger);
    let open_units: Vec<&&LedgerUnit> = units
        .iter()
        .filter(|unit| unit.status != UnitStatus::Confirmed)
        .collect();
    let unconfirmed = sorted_findings(inputs, false);

    let _ = writeln!(out, "# Needs validation");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Run: `{}`", inputs.run_id);
    let _ = writeln!(
        out,
        "- Created: {}",
        format_timestamp_ms(inputs.created_at_ms)
    );
    let _ = writeln!(out, "- Profile: `{}`", inputs.profile.as_str());
    let _ = writeln!(
        out,
        "- Units without a confirmed verdict: {}",
        open_units.len()
    );
    let _ = writeln!(out, "- Unconfirmed findings: {}", unconfirmed.len());

    let _ = writeln!(out);
    let _ = writeln!(out, "## Units");
    let _ = writeln!(out);
    if open_units.is_empty() {
        let _ = writeln!(out, "- None.");
    } else {
        for unit in open_units {
            let _ = writeln!(
                out,
                "- `{}` status={}: {}",
                unit.id,
                unit.status.as_str(),
                flatten_text(&unit_reason(unit))
            );
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "## Findings");
    let _ = writeln!(out);
    if unconfirmed.is_empty() {
        let _ = writeln!(out, "- None.");
    } else {
        for finding in unconfirmed {
            let _ = writeln!(
                out,
                "- `{}` status={} severity={}: {}",
                finding.id,
                finding.status.as_str(),
                finding.severity.as_str(),
                flatten_text(&finding.title)
            );
        }
    }
    out
}

fn unit_reason(unit: &LedgerUnit) -> String {
    if let Some(note) = unit.history.iter().rev().find_map(|event| {
        event
            .note
            .as_deref()
            .map(str::trim)
            .filter(|note| !note.is_empty())
    }) {
        return note.to_string();
    }
    match unit.status {
        UnitStatus::Pending => "not started".to_string(),
        UnitStatus::Assigned => "assigned; review not finished".to_string(),
        UnitStatus::Reviewed => "reviewed; awaiting a verdict".to_string(),
        UnitStatus::Refuted => "refuted; no vulnerability found".to_string(),
        UnitStatus::OutOfScope => "out of scope; excluded from coverage".to_string(),
        UnitStatus::Deferred => "deferred to a later run".to_string(),
        UnitStatus::Blocked => "blocked on a missing fact".to_string(),
        UnitStatus::Confirmed => "confirmed".to_string(),
    }
}

fn sorted_findings(inputs: &ReportInputs, confirmed: bool) -> Vec<&Finding> {
    let mut findings: Vec<&Finding> = inputs
        .findings
        .findings
        .iter()
        .filter(|finding| finding.confirmed == confirmed)
        .collect();
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    findings
}

fn sorted_units(ledger: &CoverageLedger) -> Vec<&LedgerUnit> {
    let mut units: Vec<&LedgerUnit> = ledger.units.iter().collect();
    units.sort_by(|left, right| left.id.cmp(&right.id));
    units
}

// ---------------------------------------------------------------------------
// Parsing the generated Markdown
// ---------------------------------------------------------------------------

struct ParsedReportFinding {
    id: String,
    severity: Severity,
}

struct ParsedDetailFinding {
    id: String,
    unit_id: Option<String>,
    severity: Option<Severity>,
}

struct ParsedNeedsFinding {
    id: String,
    status: FindingStatus,
    severity: Severity,
}

struct ParsedNeedsUnit {
    id: String,
    status: UnitStatus,
}

fn parse_report_findings(text: &str) -> Vec<ParsedReportFinding> {
    text.lines()
        .filter_map(|line| {
            let (id, after) = bullet_id(line)?;
            let rest = after.strip_prefix(" severity=")?;
            let (severity, _) = rest.split_once(':')?;
            Some(ParsedReportFinding {
                id: id.to_string(),
                severity: parse_severity(severity)?,
            })
        })
        .collect()
}

fn parse_detail_findings(text: &str) -> Vec<ParsedDetailFinding> {
    let mut out: Vec<ParsedDetailFinding> = Vec::new();
    let mut current: Option<ParsedDetailFinding> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("## `") {
            if let Some(current) = current.take() {
                out.push(current);
            }
            if let Some((id, _title)) = rest.split_once('`') {
                current = Some(ParsedDetailFinding {
                    id: id.to_string(),
                    unit_id: None,
                    severity: None,
                });
            }
            continue;
        }
        let Some(detail) = current.as_mut() else {
            continue;
        };
        if let Some(rest) = line.strip_prefix("- Unit: `") {
            if let Some((unit_id, _)) = rest.split_once('`') {
                detail.unit_id = Some(unit_id.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("- Severity: ") {
            detail.severity = parse_severity(rest.trim());
        }
    }
    if let Some(current) = current {
        out.push(current);
    }
    out
}

fn parse_needs_findings(text: &str) -> Vec<ParsedNeedsFinding> {
    section_findings(text, "Findings")
}

fn parse_needs_units(text: &str) -> Vec<ParsedNeedsUnit> {
    let mut out = Vec::new();
    let mut section = "";
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            section = heading.trim();
            continue;
        }
        if section != "Units" {
            continue;
        }
        let Some((id, after)) = bullet_id(line) else {
            continue;
        };
        let Some(rest) = after.strip_prefix(" status=") else {
            continue;
        };
        let Some((status, _reason)) = rest.split_once(':') else {
            continue;
        };
        if let Some(status) = parse_unit_status(status) {
            out.push(ParsedNeedsUnit {
                id: id.to_string(),
                status,
            });
        }
    }
    out
}

fn section_findings(text: &str, wanted: &str) -> Vec<ParsedNeedsFinding> {
    let mut out = Vec::new();
    let mut section = "";
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            section = heading.trim();
            continue;
        }
        if section != wanted {
            continue;
        }
        let Some((id, after)) = bullet_id(line) else {
            continue;
        };
        let Some(rest) = after.strip_prefix(" status=") else {
            continue;
        };
        let Some((status, rest)) = rest.split_once(' ') else {
            continue;
        };
        let Some(rest) = rest.strip_prefix("severity=") else {
            continue;
        };
        let Some((severity, _title)) = rest.split_once(':') else {
            continue;
        };
        if let (Some(status), Some(severity)) =
            (parse_finding_status(status), parse_severity(severity))
        {
            out.push(ParsedNeedsFinding {
                id: id.to_string(),
                status,
                severity,
            });
        }
    }
    out
}

fn parse_summary_counts(text: &str) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("- ") else {
            continue;
        };
        let Some((label, value)) = rest.split_once(": ") else {
            continue;
        };
        if let Ok(value) = value.trim().parse::<usize>() {
            counts.insert(label.trim().to_string(), value);
        }
    }
    counts
}

fn bullet_id(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("- `")?;
    rest.split_once('`')
}

fn parse_severity(value: &str) -> Option<Severity> {
    match value {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

fn parse_finding_status(value: &str) -> Option<FindingStatus> {
    match value {
        "needs_validation" => Some(FindingStatus::NeedsValidation),
        "confirmed" => Some(FindingStatus::Confirmed),
        "rejected" => Some(FindingStatus::Rejected),
        _ => None,
    }
}

fn parse_unit_status(value: &str) -> Option<UnitStatus> {
    match value {
        "pending" => Some(UnitStatus::Pending),
        "assigned" => Some(UnitStatus::Assigned),
        "reviewed" => Some(UnitStatus::Reviewed),
        "confirmed" => Some(UnitStatus::Confirmed),
        "refuted" => Some(UnitStatus::Refuted),
        "out_of_scope" => Some(UnitStatus::OutOfScope),
        "deferred" => Some(UnitStatus::Deferred),
        "blocked" => Some(UnitStatus::Blocked),
        _ => None,
    }
}

fn sorted_ids<'a>(ids: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = ids.map(str::to_string).collect();
    out.sort();
    out.dedup();
    out
}

fn report_duplicates(label: &str, ids: &[String], mismatches: &mut Vec<String>) {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut duplicates: BTreeSet<&str> = BTreeSet::new();
    for id in ids {
        if !seen.insert(id.as_str()) {
            duplicates.insert(id.as_str());
        }
    }
    for id in duplicates {
        mismatches.push(format!("{label} lists `{id}` more than once"));
    }
}

fn compare_id_sets(
    label: &str,
    expected: &BTreeSet<String>,
    actual: &BTreeSet<String>,
    mismatches: &mut Vec<String>,
) {
    for id in expected.difference(actual) {
        mismatches.push(format!("{label} is missing `{id}`"));
    }
    for id in actual.difference(expected) {
        mismatches.push(format!("{label} lists `{id}`, which the records do not"));
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// Collapse every control or whitespace run to a single space and trim.
///
/// Record fields are data: a title or note can never inject a heading, a list
/// item, or a second line into a derived report.
fn flatten_text(text: &str) -> String {
    let mut out = String::new();
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_control() || ch.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        pending_space = false;
        out.push(ch);
    }
    out
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn format_timestamp_ms(ms: i64) -> String {
    let ms = ms.max(0);
    let days = ms / 86_400_000;
    let remainder = ms % 86_400_000;
    let (year, month, day) = civil_from_days(days);
    let hour = remainder / 3_600_000;
    let minute = (remainder % 3_600_000) / 60_000;
    let second = (remainder % 60_000) / 1_000;
    let milli = remainder % 1_000;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milli:03}Z")
}

/// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{advance, validate_coverage_ledger_json, validate_findings_json};
    use serde_json::Value;
    use std::collections::BTreeSet;

    fn fixture_unit(index: usize, subsystem: &str) -> LedgerUnit {
        LedgerUnit {
            id: format!("sr-unit-{index:02}"),
            surface: "process".to_string(),
            boundary: "process-exec".to_string(),
            subsystem: subsystem.to_string(),
            attack_class: "command_injection".to_string(),
            refs: vec![format!("src/{subsystem}.rs:1")],
            starting_paths: vec![format!("src/{subsystem}.rs")],
            selected_companions: Vec::new(),
            excluded_companions: Vec::new(),
            status: UnitStatus::Pending,
            history: Vec::new(),
            owner: String::new(),
            reviewed_paths: Vec::new(),
            checks: vec![
                "command_injection: untrusted input never reaches an argument list".to_string(),
            ],
            fingerprint: format!("{index:016x}"),
            content_fingerprint: None,
        }
    }

    fn summarize(units: &[LedgerUnit]) -> crate::ledger::LedgerSummary {
        let count = |status: UnitStatus| units.iter().filter(|unit| unit.status == status).count();
        crate::ledger::LedgerSummary {
            units: units.len(),
            pending: count(UnitStatus::Pending),
            assigned: count(UnitStatus::Assigned),
            reviewed: count(UnitStatus::Reviewed),
            confirmed: count(UnitStatus::Confirmed),
            refuted: count(UnitStatus::Refuted),
            out_of_scope: count(UnitStatus::OutOfScope),
            deferred: count(UnitStatus::Deferred),
            blocked: count(UnitStatus::Blocked),
            surfaces: units
                .iter()
                .map(|unit| unit.surface.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            boundaries: units
                .iter()
                .map(|unit| unit.boundary.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            subsystems: units
                .iter()
                .map(|unit| unit.subsystem.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            attack_classes: units
                .iter()
                .map(|unit| unit.attack_class.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            files_scanned: units.len(),
            files_excluded: 0,
            files_size_capped: 0,
            walk_truncated: false,
            truncation: Vec::new(),
            max_files: 512,
            max_depth: 8,
            max_file_bytes: 262_144,
        }
    }

    fn finding(
        id: &str,
        unit_id: &str,
        title: &str,
        severity: Severity,
        status: FindingStatus,
        evidence: &[&str],
    ) -> Finding {
        Finding {
            id: id.to_string(),
            unit_id: unit_id.to_string(),
            title: title.to_string(),
            severity,
            status,
            evidence_refs: evidence
                .iter()
                .map(|reference| crate::schema::CanonicalRef::parse(reference).expect("ref"))
                .collect(),
            confirmed: status == FindingStatus::Confirmed,
        }
    }

    fn fixture_inputs() -> ReportInputs {
        let mut units = vec![
            fixture_unit(0, "confirmed"),
            fixture_unit(1, "refuted"),
            fixture_unit(2, "pending"),
            fixture_unit(3, "deferred"),
            fixture_unit(4, "scope"),
            fixture_unit(5, "assigned"),
            fixture_unit(6, "blocked"),
            fixture_unit(7, "reviewed"),
        ];
        units[0].reviewed_paths = vec!["src/confirmed.rs".to_string()];
        advance(&mut units[0], UnitStatus::Assigned, "reviewer-a", None, 10).expect("assign");
        advance(&mut units[0], UnitStatus::Reviewed, "reviewer-a", None, 20).expect("review");
        advance(&mut units[0], UnitStatus::Confirmed, "reviewer-a", None, 30).expect("confirm");

        units[1].reviewed_paths = vec!["src/refuted.rs".to_string()];
        advance(&mut units[1], UnitStatus::Assigned, "reviewer-b", None, 40).expect("assign");
        advance(&mut units[1], UnitStatus::Reviewed, "reviewer-b", None, 50).expect("review");
        advance(&mut units[1], UnitStatus::Refuted, "reviewer-b", None, 60).expect("refute");

        advance(
            &mut units[3],
            UnitStatus::Deferred,
            "reviewer-c",
            Some("budget: deferred to a later run"),
            70,
        )
        .expect("defer");

        advance(
            &mut units[4],
            UnitStatus::OutOfScope,
            "reviewer-c",
            Some("vendored code"),
            80,
        )
        .expect("scope");

        advance(&mut units[5], UnitStatus::Assigned, "reviewer-d", None, 90).expect("assign");

        advance(
            &mut units[6],
            UnitStatus::Blocked,
            "reviewer-d",
            Some("needs credentials"),
            100,
        )
        .expect("block");

        units[7].reviewed_paths = vec!["src/reviewed.rs".to_string()];
        advance(&mut units[7], UnitStatus::Assigned, "reviewer-e", None, 110).expect("assign");
        advance(&mut units[7], UnitStatus::Reviewed, "reviewer-e", None, 120).expect("review");

        let used_units = units.len();
        let summary = summarize(&units);
        let ledger = CoverageLedger {
            schema_version: crate::ledger::LEDGER_SCHEMA_VERSION,
            units,
            summary,
        };
        let findings = Findings {
            schema_version: crate::schema::FINDINGS_SCHEMA_VERSION,
            // Deliberately unsorted: the report must order by id.
            findings: vec![
                finding(
                    "FND-3",
                    "sr-unit-01",
                    "the shell helper is safe",
                    Severity::Info,
                    FindingStatus::Rejected,
                    &["src/refuted.rs:1"],
                ),
                finding(
                    "FND-1",
                    "sr-unit-00",
                    "argv reaches the process sink",
                    Severity::High,
                    FindingStatus::Confirmed,
                    &["src/confirmed.rs:1", "SEC-01"],
                ),
                finding(
                    "FND-2",
                    "sr-unit-02",
                    "pending parser hypothesis",
                    Severity::Info,
                    FindingStatus::NeedsValidation,
                    &["src/pending.rs:1"],
                ),
            ],
        };
        ReportInputs {
            ledger,
            findings,
            budget: BudgetReport {
                reserved_agents: 8,
                used_agents: 4,
                reserved_units: 32,
                used_units,
                incomplete: false,
                reasons: Vec::new(),
            },
            profile: ReviewProfile::Standard,
            run_id: "run-0001".to_string(),
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn file_names(dir: &Path) -> BTreeSet<String> {
        std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn derive_writes_all_five_files_and_splits_confirmed_from_the_rest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = derive(fixture_inputs(), dir.path()).expect("derive");

        let expected: BTreeSet<String> = [
            REPORT_FILE,
            FINDINGS_DETAIL_FILE,
            NEEDS_VALIDATION_FILE,
            crate::schema::FINDINGS_FILE,
            crate::ledger::LEDGER_FILE,
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(file_names(dir.path()), expected);
        assert_eq!(bundle.files.len(), 5);
        assert!(!bundle.partial);

        assert!(bundle.report_md.contains("FND-1"));
        assert!(!bundle.report_md.contains("FND-2"));
        assert!(!bundle.report_md.contains("FND-3"));
        assert!(bundle.report_md.contains("- Pending units: 1"));
        assert!(bundle.report_md.contains("- Confirmed units: 1"));
        assert!(bundle.report_md.contains("- Reviewed units: 1"));
        assert!(bundle.report_md.contains("- Refuted units: 1"));
        assert!(bundle.report_md.contains("- Deferred units: 1"));
        assert!(bundle.report_md.contains("- Blocked units: 1"));
        assert!(bundle.report_md.contains("- Out of scope units: 1"));
        assert!(bundle.report_md.contains("- Coverage gaps: 4"));
        assert!(bundle.report_md.contains("(FINDINGS-DETAIL.md)"));
        assert!(bundle.report_md.contains("(NEEDS-VALIDATION.md)"));

        assert!(bundle.findings_detail_md.contains("## `FND-1`"));
        assert!(!bundle.findings_detail_md.contains("FND-2"));
        assert!(!bundle.findings_detail_md.contains("FND-3"));
        assert!(bundle.findings_detail_md.contains("- Unit: `sr-unit-00`"));
        assert!(bundle.findings_detail_md.contains("- Severity: high"));
        assert!(bundle.findings_detail_md.contains("`src/confirmed.rs:1`"));
        assert!(bundle.findings_detail_md.contains("`SEC-01`"));
        assert!(bundle
            .findings_detail_md
            .contains("command_injection: untrusted input never reaches an argument list"));
        assert!(bundle
            .findings_detail_md
            .contains("pending -> assigned by reviewer-a"));

        assert!(bundle.needs_validation_md.contains("FND-2"));
        assert!(bundle.needs_validation_md.contains("FND-3"));
        for index in 1..=7 {
            let id = format!("`sr-unit-{index:02}`");
            assert!(
                bundle.needs_validation_md.contains(&id),
                "needs-validation is missing {id}"
            );
        }
        assert!(!bundle.needs_validation_md.contains("`sr-unit-00`"));
        for status in [
            "status=pending",
            "status=assigned",
            "status=reviewed",
            "status=refuted",
            "status=out_of_scope",
            "status=deferred",
            "status=blocked",
        ] {
            assert!(
                bundle.needs_validation_md.contains(status),
                "needs-validation is missing {status}"
            );
        }

        // The JSON copies are the canonical records and still validate.
        let findings_value: Value =
            serde_json::from_str(&bundle.findings_json).expect("findings json");
        let parsed_findings = validate_findings_json(&findings_value).expect("findings validate");
        assert_eq!(parsed_findings.findings.len(), 3);
        let ledger_value: Value = serde_json::from_str(&bundle.ledger_json).expect("ledger json");
        let parsed_ledger =
            validate_coverage_ledger_json(&ledger_value, None).expect("ledger validate");
        assert_eq!(parsed_ledger.units.len(), 8);

        let consistency = consistency_report(&bundle);
        assert!(consistency.ok, "{:?}", consistency.mismatches);
        assert_eq!(consistency.report_ids, vec!["FND-1"]);
        assert_eq!(consistency.detail_ids, vec!["FND-1"]);
        assert_eq!(
            consistency.needs_validation_ids,
            vec!["FND-2".to_string(), "FND-3".to_string()]
        );
        assert_eq!(
            consistency.json_ids,
            vec![
                "FND-1".to_string(),
                "FND-2".to_string(),
                "FND-3".to_string()
            ]
        );
        assert_consistent(&bundle).expect("consistent");
    }

    #[test]
    fn a_dropped_finding_id_is_reported_as_a_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = derive(fixture_inputs(), dir.path()).expect("derive");
        assert!(consistency_report(&bundle).ok);

        let mut mutated = bundle.clone();
        mutated.report_md = mutated
            .report_md
            .lines()
            .filter(|line| !line.contains("`FND-1`"))
            .collect::<Vec<_>>()
            .join("\n");
        let report = consistency_report(&mutated);
        assert!(!report.ok);
        assert!(
            report
                .mismatches
                .iter()
                .any(|mismatch| mismatch.contains("FND-1")),
            "mismatches do not mention FND-1: {:?}",
            report.mismatches
        );
        let error = assert_consistent(&mutated).expect_err("inconsistent bundle");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("FND-1"));
    }

    #[test]
    fn invalid_inputs_are_refused_before_writing() {
        fn assert_refused(label: &str, inputs: ReportInputs) {
            let dir = tempfile::tempdir().expect("tempdir");
            let out = dir.path().join("reports");
            let error = derive(inputs, &out).expect_err(label);
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{label}");
            assert!(
                !out.exists(),
                "{label} created the output directory before validating"
            );
        }

        let mut bad_ref = fixture_inputs();
        bad_ref.ledger.units[2].refs = vec!["../escape.rs:1".to_string()];
        assert_refused("bad ref", bad_ref);

        let mut duplicate = fixture_inputs();
        let copy = duplicate.findings.findings[1].clone();
        duplicate.findings.findings.push(copy);
        assert_refused("duplicate finding id", duplicate);

        let mut severity = fixture_inputs();
        let index = severity
            .findings
            .findings
            .iter()
            .position(|finding| finding.id == "FND-2")
            .expect("FND-2");
        severity.findings.findings[index].severity = Severity::High;
        assert_refused("unconfirmed severity", severity);

        let mut orphan = fixture_inputs();
        let index = orphan
            .findings
            .findings
            .iter()
            .position(|finding| finding.id == "FND-2")
            .expect("FND-2");
        orphan.findings.findings[index].unit_id = "sr-missing".to_string();
        assert_refused("orphan finding", orphan);

        let mut backwards_clock = fixture_inputs();
        backwards_clock.created_at_ms = -1;
        assert_refused("negative created_at_ms", backwards_clock);

        let mut silent_incomplete = fixture_inputs();
        silent_incomplete.budget.incomplete = true;
        assert_refused("incomplete without a reason", silent_incomplete);

        let mut blank_reason = fixture_inputs();
        blank_reason.budget.incomplete = true;
        blank_reason.budget.reasons = vec!["   ".to_string()];
        assert_refused("blank budget reason", blank_reason);

        let mut stray_reason = fixture_inputs();
        stray_reason.budget.reasons = vec!["why".to_string()];
        assert_refused("complete run with a reason", stray_reason);
    }

    #[test]
    fn budget_incomplete_and_a_partial_profile_are_reported() {
        let mut inputs = fixture_inputs();
        inputs.profile = ReviewProfile::Quick;
        inputs.budget.incomplete = true;
        inputs.budget.reasons = vec!["critic pool exhausted".to_string()];
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = derive(inputs, dir.path()).expect("derive");

        assert!(bundle.partial);
        assert!(bundle.report_md.contains("- Profile: `quick`"));
        assert!(bundle.report_md.contains("- Partial: yes"));
        assert!(bundle.report_md.contains("- Incomplete: yes"));
        assert!(bundle.report_md.contains("- Reason: critic pool exhausted"));
        assert!(bundle
            .report_md
            .contains("- Partial reason: critic pool exhausted"));
        assert!(bundle.report_md.contains("- Profile max units: 8"));
        assert!(consistency_report(&bundle).ok);
    }

    #[test]
    fn two_runs_with_the_same_inputs_are_byte_identical() {
        let inputs = fixture_inputs();
        let first_dir = tempfile::tempdir().expect("tempdir");
        let second_dir = tempfile::tempdir().expect("tempdir");
        let first = derive(inputs.clone(), first_dir.path()).expect("derive");
        let second = derive(inputs, second_dir.path()).expect("derive");

        assert_eq!(first.report_md, second.report_md);
        assert_eq!(first.findings_detail_md, second.findings_detail_md);
        assert_eq!(first.needs_validation_md, second.needs_validation_md);
        assert_eq!(first.findings_json, second.findings_json);
        assert_eq!(first.ledger_json, second.ledger_json);

        for name in &first.files {
            let left = std::fs::read(first_dir.path().join(name)).expect("first file");
            let right = std::fs::read(second_dir.path().join(name)).expect("second file");
            assert_eq!(left, right, "{name} differs between runs");
        }
    }
}
