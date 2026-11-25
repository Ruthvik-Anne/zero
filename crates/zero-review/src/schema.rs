//! Ledger schema extensions (T-SR-02): canonical references, state history,
//! review profiles, and the structured-output validators for
//! `coverage-ledger.json` and `findings.json`.
//!
//! The types in this module are deliberately structural. A [`CanonicalRef`] is
//! either a root-relative `path:line[:col]` reference or an upper-case
//! requirement id; a [`UnitEvent`] is one append-only status transition; and a
//! [`Finding`] may only carry a severity above `info` when it is confirmed
//! (SR-07).
//!
//! Every rejection is typed: malformed artifacts and duplicate or escaping
//! references are `zero.fnd.invalid_input`, while a status transition the matrix
//! forbids is `zero.pol.denied`.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, MAIN_SEPARATOR_STR};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use zero_types::{ErrorCode, Result, ZeroError};

use crate::ledger::{invalid, validate, CoverageLedger, LedgerUnit, Phase, UnitStatus};

/// Schema version written by the structured-output writers (SR-06).
pub const FINDINGS_SCHEMA_VERSION: u32 = 1;

/// Canonical artifact name for the finding records (SR-06).
pub const FINDINGS_FILE: &str = "findings.json";

// ---------------------------------------------------------------------------
// Canonical references (SR-03)
// ---------------------------------------------------------------------------

/// A stable reference used by ledger units and finding evidence.
///
/// Either a root-relative `path/to/file.ext:line[:col]` reference or a
/// requirement id matching `^[A-Z]{2,4}-[0-9]{2,3}$` (for example `SEC-01` or
/// `MCP-13`). Requirement ids are case-sensitive and upper-case only.
///
/// Construction goes through [`CanonicalRef::parse`], so a value that exists is
/// always syntactically valid. It serializes as its canonical string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalRef {
    kind: RefKind,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum RefKind {
    Path {
        path: String,
        line: u32,
        column: Option<u32>,
    },
    Requirement {
        id: String,
    },
}

impl CanonicalRef {
    /// Parse a canonical reference.
    ///
    /// Rejects empty or absolute paths, drive and UNC paths, backslashes,
    /// control characters, empty segments, `.` and `..` components, trailing
    /// separators, zero lines or columns, a `:` inside the path, and malformed
    /// requirement ids.
    pub fn parse(value: &str) -> Result<Self> {
        Self::parse_inner(value).map_err(invalid)
    }

    /// True when this is a `path:line[:col]` reference.
    pub const fn is_path(&self) -> bool {
        matches!(self.kind, RefKind::Path { .. })
    }

    /// True when this is a requirement id.
    pub const fn is_requirement(&self) -> bool {
        matches!(self.kind, RefKind::Requirement { .. })
    }

    /// The `(path, line, column)` parts of a path reference.
    pub fn path_parts(&self) -> Option<(&str, u32, Option<u32>)> {
        match &self.kind {
            RefKind::Path { path, line, column } => Some((path, *line, *column)),
            RefKind::Requirement { .. } => None,
        }
    }

    /// The id of a requirement reference.
    pub fn requirement_id(&self) -> Option<&str> {
        match &self.kind {
            RefKind::Requirement { id } => Some(id),
            RefKind::Path { .. } => None,
        }
    }

    /// The stable, canonical string form used for comparison.
    pub fn canonical(&self) -> String {
        canonicalize_ref(self)
    }

    fn parse_inner(value: &str) -> std::result::Result<Self, String> {
        if value.is_empty() {
            return Err("ref is empty".to_string());
        }
        if value.chars().any(char::is_control) {
            return Err("ref contains a control character".to_string());
        }
        if let Some(id) = parse_requirement_id(value) {
            return Ok(Self {
                kind: RefKind::Requirement { id: id.to_string() },
            });
        }
        let (path, line, column) = split_path_ref(value)?;
        Ok(Self {
            kind: RefKind::Path {
                path: path.to_string(),
                line,
                column,
            },
        })
    }
}

impl FromStr for CanonicalRef {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse_inner(value)
    }
}

impl fmt::Display for CanonicalRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            RefKind::Path { path, line, column } => match column {
                Some(column) => write!(formatter, "{path}:{line}:{column}"),
                None => write!(formatter, "{path}:{line}"),
            },
            RefKind::Requirement { id } => formatter.write_str(id),
        }
    }
}

impl Serialize for CanonicalRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CanonicalRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        CanonicalRef::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Return the stable comparison form of a reference.
///
/// Parsing already normalizes the syntax, so the canonical form is the display
/// string. The filesystem is deliberately not consulted here; symlink and root
/// checks belong to [`validate_refs`].
pub fn canonicalize_ref(reference: &CanonicalRef) -> String {
    reference.to_string()
}

fn parse_requirement_id(value: &str) -> Option<&str> {
    let (prefix, suffix) = value.split_once('-')?;
    if suffix.contains('-') {
        return None;
    }
    if !(2..=4).contains(&prefix.len()) {
        return None;
    }
    if !prefix.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    if !(2..=3).contains(&suffix.len()) {
        return None;
    }
    if !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(value)
}

fn split_path_ref(value: &str) -> std::result::Result<(&str, u32, Option<u32>), String> {
    let (rest, last) = value.rsplit_once(':').ok_or_else(|| {
        "ref must be `path:line`, `path:line:col`, or a requirement id".to_string()
    })?;
    let last_number: u32 = last
        .parse()
        .map_err(|_| "ref line or column is not a positive integer".to_string())?;
    if last_number == 0 {
        return Err("ref line and column must be at least 1".to_string());
    }
    let (path, line, column) = match rest.rsplit_once(':') {
        Some((path, middle)) => {
            let middle_number: u32 = middle
                .parse()
                .map_err(|_| "ref path must not contain `:`".to_string())?;
            if middle_number == 0 {
                return Err("ref line must be at least 1".to_string());
            }
            (path, middle_number, Some(last_number))
        }
        None => (rest, last_number, None),
    };
    validate_ref_path(path)?;
    Ok((path, line, column))
}

fn validate_ref_path(path: &str) -> std::result::Result<(), String> {
    if path.is_empty() {
        return Err("ref path is empty".to_string());
    }
    if path.chars().any(char::is_control) {
        return Err("ref path contains a control character".to_string());
    }
    if path.contains('\\') {
        return Err("ref path must use forward slashes".to_string());
    }
    if path.contains(':') {
        return Err("ref path must not contain `:`".to_string());
    }
    if path.starts_with('/') {
        return Err("ref path must be relative".to_string());
    }
    if path.ends_with('/') {
        return Err("ref path must not end with a separator".to_string());
    }
    if path.contains("//") {
        return Err("ref path must not contain an empty segment".to_string());
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err("ref path must not contain `.` or `..`".to_string());
    }
    if Path::new(path).is_absolute() {
        return Err("ref path must be relative".to_string());
    }
    Ok(())
}

/// Validate every reference in `units`.
///
/// Duplicate references inside one unit are rejected; the same reference in two
/// different units is allowed. When `root` is supplied, every path reference
/// must resolve to an existing regular file that stays under the canonicalized
/// root. Requirement references need no file.
pub fn validate_refs(units: &[LedgerUnit], root: Option<&Path>) -> Result<()> {
    let canonical_root = root
        .map(|root| {
            root.canonicalize()
                .map_err(|_| invalid("review root does not exist and cannot be canonicalized"))
        })
        .transpose()?;

    for unit in units {
        let mut seen: BTreeSet<CanonicalRef> = BTreeSet::new();
        for reference in &unit.refs {
            let parsed = CanonicalRef::parse(reference).map_err(|error| {
                invalid(format!(
                    "unit `{}` has an invalid ref `{}`: {}",
                    unit.id,
                    reference,
                    error.message()
                ))
            })?;
            if !seen.insert(parsed.clone()) {
                return Err(invalid(format!(
                    "unit `{}` lists duplicate ref `{}`",
                    unit.id, reference
                )));
            }
            let Some(root) = canonical_root.as_deref() else {
                continue;
            };
            let Some((path, _, _)) = parsed.path_parts() else {
                continue;
            };
            let candidate = root.join(path.replace('/', MAIN_SEPARATOR_STR));
            let resolved = candidate.canonicalize().map_err(|_| {
                invalid(format!(
                    "unit `{}` ref `{}` does not point to an existing file",
                    unit.id, reference
                ))
            })?;
            if !resolved.starts_with(root) {
                return Err(invalid(format!(
                    "unit `{}` ref `{}` escapes the review root",
                    unit.id, reference
                )));
            }
            let metadata = std::fs::metadata(&resolved).map_err(|_| {
                invalid(format!(
                    "unit `{}` ref `{}` cannot be read",
                    unit.id, reference
                ))
            })?;
            if !metadata.is_file() {
                return Err(invalid(format!(
                    "unit `{}` ref `{}` does not point to a file",
                    unit.id, reference
                )));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// States and history (SR-03)
// ---------------------------------------------------------------------------

/// One append-only status transition on a ledger unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitEvent {
    /// Milliseconds since the Unix epoch; non-decreasing per unit.
    pub at_ms: u64,
    pub from: UnitStatus,
    pub to: UnitStatus,
    /// The reviewer or subsystem that performed the transition.
    pub actor: String,
    /// Required for `out_of_scope`, `deferred`, `blocked`, and a return to
    /// `pending`.
    pub note: Option<String>,
}

/// The statuses reachable from `from` in one transition.
pub const fn allowed_transitions(from: UnitStatus) -> &'static [UnitStatus] {
    match from {
        UnitStatus::Pending => &[
            UnitStatus::Assigned,
            UnitStatus::OutOfScope,
            UnitStatus::Deferred,
            UnitStatus::Blocked,
        ],
        UnitStatus::Assigned => &[
            UnitStatus::Pending,
            UnitStatus::Reviewed,
            UnitStatus::OutOfScope,
            UnitStatus::Deferred,
            UnitStatus::Blocked,
        ],
        UnitStatus::Reviewed => &[
            UnitStatus::Confirmed,
            UnitStatus::Refuted,
            UnitStatus::Deferred,
            UnitStatus::Blocked,
        ],
        UnitStatus::Deferred => &[
            UnitStatus::Assigned,
            UnitStatus::OutOfScope,
            UnitStatus::Blocked,
        ],
        UnitStatus::Blocked => &[
            UnitStatus::Assigned,
            UnitStatus::Deferred,
            UnitStatus::OutOfScope,
        ],
        // A carried confirmation that no longer matches the target is reopened
        // for re-review (SR-11); refuted and out-of-scope stay terminal.
        UnitStatus::Confirmed => &[UnitStatus::Deferred],
        UnitStatus::Refuted | UnitStatus::OutOfScope => &[],
    }
}

/// True when `from -> to` is one legal step in the matrix.
pub fn transition_allowed(from: UnitStatus, to: UnitStatus) -> bool {
    allowed_transitions(from).contains(&to)
}

/// True when a transition into `to` must carry a non-empty note.
pub const fn transition_requires_note(to: UnitStatus) -> bool {
    matches!(
        to,
        UnitStatus::Pending | UnitStatus::OutOfScope | UnitStatus::Deferred | UnitStatus::Blocked
    )
}

/// Apply one status transition, appending it to the unit's history.
///
/// Invalid transitions, missing required notes, and empty actors are
/// `zero.pol.denied`. A non-monotonic `now_ms` is `zero.fnd.invalid_input`.
/// When the target status requires an owner and the unit has none, the actor
/// becomes the owner; reviewed paths are left to the caller.
pub fn advance(
    unit: &mut LedgerUnit,
    to: UnitStatus,
    actor: &str,
    note: Option<&str>,
    now_ms: u64,
) -> Result<()> {
    let actor = actor.trim();
    if actor.is_empty() {
        return Err(denied("a status transition needs a non-empty actor"));
    }
    let from = unit.status;
    if !transition_allowed(from, to) {
        return Err(denied(format!(
            "unit `{}` cannot transition from {} to {}",
            unit.id,
            from.as_str(),
            to.as_str()
        )));
    }
    let note = note.map(str::trim).filter(|note| !note.is_empty());
    if transition_requires_note(to) && note.is_none() {
        return Err(denied(format!(
            "unit `{}` transition to {} requires a note",
            unit.id,
            to.as_str()
        )));
    }
    if let Some(last) = unit.history.last() {
        if now_ms < last.at_ms {
            return Err(invalid(format!(
                "unit `{}` transition time {now_ms} is before the last event at {}",
                unit.id, last.at_ms
            )));
        }
    }
    unit.history.push(UnitEvent {
        at_ms: now_ms,
        from,
        to,
        actor: actor.to_string(),
        note: note.map(str::to_string),
    });
    unit.status = to;
    if to.requires_owner() && unit.owner.trim().is_empty() {
        unit.owner = actor.to_string();
    }
    Ok(())
}

/// Validate an append-only history without touching the filesystem.
///
/// An empty history is accepted for seeded or adopted units. A non-empty history
/// must be chronological (`at_ms` non-decreasing), each event's `from` must
/// match the previous `to`, every event must be a legal matrix step with its
/// required note, and the unit's current status must equal the last `to`.
pub fn validate_history(unit: &LedgerUnit) -> Result<()> {
    let mut previous: Option<&UnitEvent> = None;
    for event in &unit.history {
        if event.actor.trim().is_empty() {
            return Err(invalid(format!(
                "unit `{}` has a history event without an actor",
                unit.id
            )));
        }
        if !transition_allowed(event.from, event.to) {
            return Err(invalid(format!(
                "unit `{}` history has an illegal transition from {} to {}",
                unit.id,
                event.from.as_str(),
                event.to.as_str()
            )));
        }
        if transition_requires_note(event.to)
            && !event
                .note
                .as_deref()
                .is_some_and(|note| !note.trim().is_empty())
        {
            return Err(invalid(format!(
                "unit `{}` history has a transition to {} without a note",
                unit.id,
                event.to.as_str()
            )));
        }
        if let Some(previous) = previous {
            if event.from != previous.to {
                return Err(invalid(format!(
                    "unit `{}` history jumps from {} to {} but the previous event ended at {}",
                    unit.id,
                    previous.to.as_str(),
                    event.from.as_str(),
                    previous.to.as_str()
                )));
            }
            if event.at_ms < previous.at_ms {
                return Err(invalid(format!(
                    "unit `{}` history is not chronological: {} is before {}",
                    unit.id, event.at_ms, previous.at_ms
                )));
            }
        }
        previous = Some(event);
    }
    if let Some(last) = unit.history.last() {
        if unit.status != last.to {
            return Err(invalid(format!(
                "unit `{}` status is {} but its history ends at {}",
                unit.id,
                unit.status.as_str(),
                last.to.as_str()
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Profiles and partial runs (SR-13)
// ---------------------------------------------------------------------------

/// Review depth selected by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewProfile {
    /// One wave with coarsened units and one merged verifier.
    Quick,
    /// The default profile.
    Standard,
    /// Per-subsystem units, critic waves, and separate validation and
    /// verification.
    Deep,
}

impl ReviewProfile {
    /// All profiles, shallowest first.
    pub const ALL: [ReviewProfile; 3] = [
        ReviewProfile::Quick,
        ReviewProfile::Standard,
        ReviewProfile::Deep,
    ];

    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            ReviewProfile::Quick => "quick",
            ReviewProfile::Standard => "standard",
            ReviewProfile::Deep => "deep",
        }
    }

    /// The ordered phases the profile runs.
    ///
    /// `quick` merges record verification into the validation phase; `standard`
    /// and `deep` run all five audit phases.
    pub const fn phases(self) -> &'static [Phase] {
        match self {
            ReviewProfile::Quick => &[
                Phase::Recon,
                Phase::CoverageHunt,
                Phase::Validation,
                Phase::Output,
            ],
            ReviewProfile::Standard | ReviewProfile::Deep => &[
                Phase::Recon,
                Phase::CoverageHunt,
                Phase::Validation,
                Phase::Output,
                Phase::RecordVerification,
            ],
        }
    }

    /// Conservative caps for one run.
    pub const fn budget(self) -> ProfileBudget {
        match self {
            ReviewProfile::Quick => ProfileBudget {
                max_units: 8,
                max_agents: 3,
                max_files: 64,
            },
            ReviewProfile::Standard => ProfileBudget {
                max_units: 32,
                max_agents: 8,
                max_files: 256,
            },
            ReviewProfile::Deep => ProfileBudget {
                max_units: 128,
                max_agents: 16,
                max_files: 1024,
            },
        }
    }
}

/// Caps applied to one run under a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileBudget {
    pub max_units: usize,
    pub max_agents: usize,
    pub max_files: usize,
}

/// The units a run will actually cover and whether that is a partial claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopePlan {
    pub profile: ReviewProfile,
    /// Unit ids in request order, deduplicated and trimmed to the budget.
    pub units: Vec<String>,
    /// True for any scoped run, and for a full run trimmed by its budget.
    pub partial: bool,
    /// Why the run is partial; `None` for a complete full run.
    pub reason: Option<String>,
}

/// Plan an explicitly scoped run over `requested_units`.
///
/// A non-empty request is always `partial: true`: the ledger is the coverage
/// claim, so a subset can never claim full coverage. Requests larger than the
/// profile budget are trimmed to `max_units` and the reason records both counts.
/// An empty request is a full run; use [`scope_all`] to plan a full run over a
/// known unit list.
pub fn scope(profile: ReviewProfile, requested_units: &[String]) -> ScopePlan {
    let requested = dedupe_units(requested_units);
    let requested_count = requested.len();
    let budget = profile.budget();
    let mut units = requested;
    let trimmed = units.len() > budget.max_units;
    if trimmed {
        units.truncate(budget.max_units);
    }

    if requested_count == 0 {
        return ScopePlan {
            profile,
            units,
            partial: false,
            reason: None,
        };
    }

    let reason = if trimmed {
        format!(
            "scoped run: {requested_count} unit(s) requested, budget ({}) trimmed the run to {}",
            profile.as_str(),
            units.len()
        )
    } else {
        format!("scoped run: {requested_count} unit(s) requested")
    };
    ScopePlan {
        profile,
        units,
        partial: true,
        reason: Some(reason),
    }
}

/// Plan a full run over every known unit.
///
/// The run is complete unless the profile budget trims the unit list; a trimmed
/// full run is `partial: true` and the reason reports both counts.
pub fn scope_all(profile: ReviewProfile, all_units: &[String]) -> ScopePlan {
    let mut units = dedupe_units(all_units);
    let total = units.len();
    let budget = profile.budget();
    if total > budget.max_units {
        units.truncate(budget.max_units);
        ScopePlan {
            profile,
            units,
            partial: true,
            reason: Some(format!(
                "budget ({}) trimmed {total} unit(s) to {}",
                profile.as_str(),
                budget.max_units
            )),
        }
    } else {
        ScopePlan {
            profile,
            units,
            partial: false,
            reason: None,
        }
    }
}

fn dedupe_units(units: &[String]) -> Vec<String> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut out = Vec::new();
    for unit in units {
        if seen.insert(unit.as_str()) {
            out.push(unit.clone());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Structured output (SR-06, SR-07)
// ---------------------------------------------------------------------------

/// Finding severity. Only confirmed findings may exceed `info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Lifecycle of one finding record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    /// A blocked hypothesis with a named missing fact.
    NeedsValidation,
    Confirmed,
    Rejected,
}

impl FindingStatus {
    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            FindingStatus::NeedsValidation => "needs_validation",
            FindingStatus::Confirmed => "confirmed",
            FindingStatus::Rejected => "rejected",
        }
    }
}

/// One finding record written to `findings.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub unit_id: String,
    pub title: String,
    pub severity: Severity,
    pub status: FindingStatus,
    /// At least one canonical ref; empty evidence is not a finding.
    pub evidence_refs: Vec<CanonicalRef>,
    pub confirmed: bool,
}

/// The `findings.json` artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Findings {
    pub schema_version: u32,
    pub findings: Vec<Finding>,
}

/// Validate a findings artifact structurally.
///
/// Rejects unknown schema versions, empty or duplicate finding ids, empty unit
/// ids or titles, empty or duplicate evidence refs, a `confirmed` flag that
/// disagrees with the status, and an unconfirmed finding with a severity above
/// `info` (SR-07).
pub fn validate_findings(findings: &Findings) -> Result<()> {
    if findings.schema_version != FINDINGS_SCHEMA_VERSION {
        return Err(invalid(format!(
            "findings schema version {} is not supported (expected {FINDINGS_SCHEMA_VERSION})",
            findings.schema_version
        )));
    }

    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for finding in &findings.findings {
        if finding.id.trim().is_empty() {
            return Err(invalid("findings artifact has a finding with an empty id"));
        }
        if !ids.insert(finding.id.as_str()) {
            return Err(invalid(format!("duplicate finding id `{}`", finding.id)));
        }
        if finding.unit_id.trim().is_empty() {
            return Err(invalid(format!(
                "finding `{}` has an empty unit id",
                finding.id
            )));
        }
        if finding.title.trim().is_empty() {
            return Err(invalid(format!(
                "finding `{}` has an empty title",
                finding.id
            )));
        }
        if finding.evidence_refs.is_empty() {
            return Err(invalid(format!(
                "finding `{}` has no evidence refs",
                finding.id
            )));
        }
        let mut refs: BTreeSet<String> = BTreeSet::new();
        for reference in &finding.evidence_refs {
            if !refs.insert(canonicalize_ref(reference)) {
                return Err(invalid(format!(
                    "finding `{}` lists duplicate evidence ref `{reference}`",
                    finding.id
                )));
            }
        }
        let confirmed_by_status = finding.status == FindingStatus::Confirmed;
        if finding.confirmed != confirmed_by_status {
            return Err(invalid(format!(
                "finding `{}` has confirmed={} but status {}",
                finding.id,
                finding.confirmed,
                finding.status.as_str()
            )));
        }
        if !finding.confirmed && finding.severity > Severity::Info {
            return Err(invalid(format!(
                "finding `{}` is {} but carries severity {}; only confirmed findings may exceed info",
                finding.id,
                finding.status.as_str(),
                finding.severity.as_str()
            )));
        }
    }
    Ok(())
}

/// Parse and validate a `findings.json` value.
pub fn validate_findings_json(value: &Value) -> Result<Findings> {
    let findings: Findings = serde_json::from_value(value.clone())?;
    validate_findings(&findings)?;
    Ok(findings)
}

/// Parse and validate `findings.json`, additionally requiring every finding's
/// `unit_id` to exist in `ledger`.
pub fn validate_findings_json_with_ledger(
    value: &Value,
    ledger: &CoverageLedger,
) -> Result<Findings> {
    let findings = validate_findings_json(value)?;
    let units: BTreeSet<&str> = ledger.units.iter().map(|unit| unit.id.as_str()).collect();
    for finding in &findings.findings {
        if !units.contains(finding.unit_id.as_str()) {
            return Err(invalid(format!(
                "finding `{}` names unit `{}`, which is not in the ledger",
                finding.id, finding.unit_id
            )));
        }
    }
    Ok(findings)
}

/// Parse and validate a `coverage-ledger.json` value.
///
/// The ledger invariants are checked first, then every reference. When `root` is
/// supplied, path refs must exist as regular files under it.
pub fn validate_coverage_ledger_json(value: &Value, root: Option<&Path>) -> Result<CoverageLedger> {
    let ledger: CoverageLedger = serde_json::from_value(value.clone())?;
    validate(&ledger)?;
    validate_refs(&ledger.units, root)?;
    Ok(ledger)
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

/// Current time in milliseconds since the Unix epoch, or 0 if the clock is
/// before the epoch.
pub(crate) fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{seed, LedgerUnit};
    use serde_json::json;

    fn write(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel.replace('/', MAIN_SEPARATOR_STR));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn unit(id: &str) -> LedgerUnit {
        LedgerUnit {
            id: id.to_string(),
            surface: "process".to_string(),
            boundary: "process-exec".to_string(),
            subsystem: "src".to_string(),
            attack_class: "command_injection".to_string(),
            refs: vec!["src/shell.rs:1".to_string()],
            starting_paths: vec!["src/shell.rs".to_string()],
            selected_companions: Vec::new(),
            excluded_companions: Vec::new(),
            status: UnitStatus::Pending,
            history: Vec::new(),
            owner: String::new(),
            reviewed_paths: Vec::new(),
            checks: vec!["command_injection: check".to_string()],
            fingerprint: "0123456789abcdef".to_string(),
            content_fingerprint: None,
        }
    }

    fn seeded_ledger() -> (tempfile::TempDir, CoverageLedger) {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "src/shell.rs",
            "pub fn run() {\n    let _ = std::process::Command::new(\"sh\");\n}\n",
        );
        let ledger = seed(dir.path()).expect("seed");
        (dir, ledger)
    }

    // -- canonical refs ---------------------------------------------------

    #[test]
    fn canonical_refs_parse_paths_and_requirement_ids() {
        let path = CanonicalRef::parse("src/net/client.rs:42").expect("path ref");
        assert!(path.is_path());
        assert!(!path.is_requirement());
        assert_eq!(path.path_parts(), Some(("src/net/client.rs", 42, None)));
        assert_eq!(path.requirement_id(), None);
        assert_eq!(path.to_string(), "src/net/client.rs:42");

        let with_column = CanonicalRef::parse("src/net/client.rs:42:7").expect("column ref");
        assert_eq!(
            with_column.path_parts(),
            Some(("src/net/client.rs", 42, Some(7)))
        );
        assert_eq!(canonicalize_ref(&with_column), "src/net/client.rs:42:7");

        for id in ["SEC-01", "MCP-13", "SR-02", "TRU-123"] {
            let reference = CanonicalRef::parse(id).expect("requirement ref");
            assert!(reference.is_requirement(), "{id}");
            assert_eq!(reference.requirement_id(), Some(id));
            assert_eq!(reference.canonical(), id);
        }

        // A leading zero is syntax, not identity: it canonicalizes away.
        assert_eq!(
            CanonicalRef::parse("src/shell.rs:01")
                .expect("leading zero")
                .to_string(),
            "src/shell.rs:1"
        );
    }

    #[test]
    fn canonical_refs_reject_bad_forms() {
        for bad in [
            "",
            ":1",
            "/etc/passwd:1",
            "C:/Windows/win.ini:1",
            "C:\\Windows\\win.ini:1",
            "\\\\server\\share\\file.rs:1",
            "//server/share/file.rs:1",
            "src\\shell.rs:1",
            "../escape.rs:1",
            "src/../../escape.rs:1",
            "./src/shell.rs:1",
            "src/./shell.rs:1",
            "src//shell.rs:1",
            "src/:1",
            "src/shell.rs:0",
            "src/shell.rs:1:0",
            "src/shell.rs:-1",
            "src/shell.rs:1:-1",
            "src/shell.rs:4294967296",
            "src/shell.rs:",
            "src/shell.rs",
            "src/shell.rs:1:2:3",
            "src/shell.rs:1\n",
            "src/a\tb.rs:1",
            "SEC-1",
            "SEC-0001",
            "sec-01",
            "SECURITY-01",
            "S-01",
            "SEC_01",
            "SEC-0a",
            "SEC-01-02",
        ] {
            assert!(
                CanonicalRef::parse(bad).is_err(),
                "accepted bad ref {bad:?}"
            );
        }
    }

    #[test]
    fn canonical_refs_round_trip_through_json_strings() {
        for text in ["src/shell.rs:3:4", "SEC-01"] {
            let reference = CanonicalRef::parse(text).expect("ref");
            let value = serde_json::to_value(&reference).expect("serialize");
            assert_eq!(value, json!(text));
            let parsed: CanonicalRef = serde_json::from_value(value).expect("parse");
            assert_eq!(parsed, reference);
        }
        assert!(serde_json::from_value::<CanonicalRef>(json!("src/shell.rs:0")).is_err());
        assert!(serde_json::from_value::<CanonicalRef>(json!(7)).is_err());
    }

    #[test]
    fn duplicate_refs_within_a_unit_are_rejected() {
        let mut duplicate = unit("dup");
        duplicate.refs = vec!["src/shell.rs:1".to_string(), "src/shell.rs:1".to_string()];
        let error = validate_refs(&[duplicate], None).expect_err("duplicate ref");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("duplicate ref"));

        // The canonical form is compared, not the raw text.
        let mut equivalent = unit("equivalent");
        equivalent.refs = vec!["src/shell.rs:1".to_string(), "src/shell.rs:01".to_string()];
        let error = validate_refs(&[equivalent], None).expect_err("canonical duplicate");
        assert_eq!(error.code(), ErrorCode::InvalidInput);

        let mut requirement = unit("requirement");
        requirement.refs = vec!["SEC-01".to_string(), "SEC-01".to_string()];
        assert!(validate_refs(&[requirement], None).is_err());
    }

    #[test]
    fn the_same_ref_may_appear_in_different_units() {
        let first = unit("first");
        let second = unit("second");
        validate_refs(&[first, second], None).expect("same ref across units is allowed");
    }

    #[test]
    fn path_refs_must_exist_as_files_under_the_root() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "src/shell.rs", "fn run() {}\n");
        std::fs::create_dir_all(dir.path().join("src/empty")).unwrap();

        let mut good = unit("good");
        good.refs = vec!["src/shell.rs:1".to_string()];
        validate_refs(&[good.clone()], Some(dir.path())).expect("existing file");

        let mut missing = unit("missing");
        missing.refs = vec!["src/missing.rs:1".to_string()];
        let error = validate_refs(&[missing], Some(dir.path())).expect_err("missing file");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("existing file"));

        let mut directory = unit("directory");
        directory.refs = vec!["src/empty:1".to_string()];
        let error = validate_refs(&[directory], Some(dir.path())).expect_err("directory ref");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("does not point to a file"));

        let missing_root = dir.path().join("not-a-root");
        assert!(validate_refs(&[good], Some(&missing_root)).is_err());
    }

    #[test]
    fn requirement_refs_do_not_need_files_and_root_is_optional() {
        let dir = tempfile::tempdir().unwrap();
        let mut requirement = unit("requirement");
        requirement.refs = vec!["SEC-01".to_string()];
        validate_refs(&[requirement.clone()], Some(dir.path())).expect("requirement ref");
        validate_refs(&[requirement], None).expect("no root, no existence check");

        let mut missing = unit("missing");
        missing.refs = vec!["src/missing.rs:1".to_string()];
        validate_refs(&[missing], None).expect("without a root existence is not checked");
    }

    // -- states and history ----------------------------------------------

    #[test]
    fn the_transition_matrix_allows_the_lifecycle() {
        let mut journal = unit("lifecycle");
        advance(&mut journal, UnitStatus::Assigned, "reviewer-1", None, 10).expect("assign");
        assert_eq!(journal.status, UnitStatus::Assigned);
        assert_eq!(journal.owner, "reviewer-1");

        journal.reviewed_paths = vec!["src/shell.rs".to_string()];
        advance(
            &mut journal,
            UnitStatus::Reviewed,
            "reviewer-1",
            Some("read the sink"),
            20,
        )
        .expect("review");
        advance(&mut journal, UnitStatus::Confirmed, "reviewer-1", None, 30).expect("confirm");

        assert_eq!(journal.status, UnitStatus::Confirmed);
        assert_eq!(journal.history.len(), 3);
        assert!(journal
            .history
            .windows(2)
            .all(|pair| pair[0].to == pair[1].from));
        validate_history(&journal).expect("chronological lifecycle");
    }

    #[test]
    fn the_transition_matrix_rejects_illegal_steps() {
        let mut journal = unit("illegal");
        let error = advance(&mut journal, UnitStatus::Reviewed, "reviewer-1", None, 1)
            .expect_err("cannot skip assignment");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(journal.history.is_empty());
        assert_eq!(journal.status, UnitStatus::Pending);

        let error =
            advance(&mut journal, UnitStatus::Assigned, "  ", None, 1).expect_err("empty actor");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
    }

    #[test]
    fn out_of_scope_deferred_and_blocked_require_a_note() {
        for target in [
            UnitStatus::OutOfScope,
            UnitStatus::Deferred,
            UnitStatus::Blocked,
        ] {
            let mut journal = unit("noted");
            let error =
                advance(&mut journal, target, "reviewer-1", None, 1).expect_err("missing note");
            assert_eq!(error.code(), ErrorCode::PolicyDenied);
            assert!(error.message().contains("requires a note"));

            let error = advance(&mut journal, target, "reviewer-1", Some("   "), 2)
                .expect_err("blank note");
            assert_eq!(error.code(), ErrorCode::PolicyDenied);

            advance(
                &mut journal,
                target,
                "reviewer-1",
                Some("bounded reason"),
                3,
            )
            .expect("noted transition");
            assert_eq!(journal.history[0].note.as_deref(), Some("bounded reason"));
        }
    }

    #[test]
    fn back_to_pending_is_only_from_assigned_and_needs_a_note() {
        let mut journal = unit("reopen");
        advance(&mut journal, UnitStatus::Assigned, "reviewer-1", None, 1).expect("assign");
        assert!(advance(&mut journal, UnitStatus::Pending, "reviewer-1", None, 2).is_err());
        advance(
            &mut journal,
            UnitStatus::Pending,
            "reviewer-1",
            Some("released"),
            3,
        )
        .expect("reopen");
        assert_eq!(journal.status, UnitStatus::Pending);

        let mut deferred = unit("deferred");
        advance(
            &mut deferred,
            UnitStatus::Deferred,
            "reviewer-1",
            Some("later"),
            1,
        )
        .expect("defer");
        let error = advance(
            &mut deferred,
            UnitStatus::Pending,
            "reviewer-1",
            Some("reopen"),
            2,
        )
        .expect_err("deferred cannot return to pending");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
    }

    #[test]
    fn confirmed_can_defer_for_re_review_and_refuted_is_terminal() {
        let all = [
            UnitStatus::Pending,
            UnitStatus::Assigned,
            UnitStatus::Reviewed,
            UnitStatus::Confirmed,
            UnitStatus::Refuted,
            UnitStatus::OutOfScope,
            UnitStatus::Deferred,
            UnitStatus::Blocked,
        ];
        let mut confirmed = unit("terminal");
        advance(&mut confirmed, UnitStatus::Assigned, "reviewer-1", None, 1).expect("assign");
        confirmed.reviewed_paths = vec!["src/shell.rs".to_string()];
        advance(&mut confirmed, UnitStatus::Reviewed, "reviewer-1", None, 2).expect("review");
        advance(&mut confirmed, UnitStatus::Confirmed, "reviewer-1", None, 3).expect("verdict");
        for target in all {
            if target == UnitStatus::Deferred {
                continue;
            }
            let mut candidate = confirmed.clone();
            let error = advance(&mut candidate, target, "reviewer-1", Some("again"), 4)
                .expect_err("a confirmed unit only reopens as deferred");
            assert_eq!(error.code(), ErrorCode::PolicyDenied);
        }
        advance(
            &mut confirmed,
            UnitStatus::Deferred,
            "fingerprint-check",
            Some("target changed"),
            4,
        )
        .expect("a changed fingerprint reopens the confirmation");

        let mut refuted = unit("refuted-terminal");
        advance(&mut refuted, UnitStatus::Assigned, "reviewer-1", None, 1).expect("assign");
        refuted.reviewed_paths = vec!["src/shell.rs".to_string()];
        advance(&mut refuted, UnitStatus::Reviewed, "reviewer-1", None, 2).expect("review");
        advance(&mut refuted, UnitStatus::Refuted, "reviewer-1", None, 3).expect("verdict");
        for target in all {
            let mut candidate = refuted.clone();
            let error = advance(&mut candidate, target, "reviewer-1", Some("again"), 4)
                .expect_err("refuted is terminal");
            assert_eq!(error.code(), ErrorCode::PolicyDenied);
        }
    }

    #[test]
    fn history_must_be_chronological() {
        let mut journal = unit("time");
        advance(&mut journal, UnitStatus::Assigned, "reviewer-1", None, 100).expect("assign");
        journal.reviewed_paths = vec!["src/shell.rs".to_string()];
        advance(&mut journal, UnitStatus::Reviewed, "reviewer-1", None, 200).expect("review");
        journal.history[1].at_ms = 50;
        let error = validate_history(&journal).expect_err("non-monotonic");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("chronological"));

        let mut backwards = unit("backwards");
        advance(
            &mut backwards,
            UnitStatus::Assigned,
            "reviewer-1",
            None,
            100,
        )
        .expect("assign");
        let error = advance(&mut backwards, UnitStatus::Reviewed, "reviewer-1", None, 99)
            .expect_err("advance refuses a backwards clock");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn history_from_must_match_the_previous_to() {
        let mut journal = unit("mismatch");
        advance(&mut journal, UnitStatus::Assigned, "reviewer-1", None, 1).expect("assign");
        journal.reviewed_paths = vec!["src/shell.rs".to_string()];
        advance(&mut journal, UnitStatus::Reviewed, "reviewer-1", None, 2).expect("review");
        // `reviewed -> confirmed` is a legal step, but the previous event ended
        // at `assigned`, so the chain is broken.
        journal.history[1].from = UnitStatus::Reviewed;
        journal.history[1].to = UnitStatus::Confirmed;
        journal.status = UnitStatus::Confirmed;
        let error = validate_history(&journal).expect_err("from/to mismatch");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("jumps"));
    }

    #[test]
    fn history_status_must_match_the_last_event() {
        let mut journal = unit("status");
        advance(&mut journal, UnitStatus::Assigned, "reviewer-1", None, 1).expect("assign");
        journal.status = UnitStatus::Confirmed;
        let error = validate_history(&journal).expect_err("status mismatch");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("history ends at"));
    }

    #[test]
    fn history_rejects_illegal_or_noteless_recorded_steps() {
        let mut illegal = unit("illegal");
        illegal.history.push(UnitEvent {
            at_ms: 1,
            from: UnitStatus::Pending,
            to: UnitStatus::Confirmed,
            actor: "reviewer-1".to_string(),
            note: None,
        });
        illegal.status = UnitStatus::Confirmed;
        let error = validate_history(&illegal).expect_err("illegal step");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("illegal transition"));

        let mut noteless = unit("noteless");
        noteless.history.push(UnitEvent {
            at_ms: 1,
            from: UnitStatus::Pending,
            to: UnitStatus::Deferred,
            actor: "reviewer-1".to_string(),
            note: None,
        });
        noteless.status = UnitStatus::Deferred;
        let error = validate_history(&noteless).expect_err("noteless step");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("without a note"));

        let mut anonymous = unit("anonymous");
        anonymous.history.push(UnitEvent {
            at_ms: 1,
            from: UnitStatus::Pending,
            to: UnitStatus::Assigned,
            actor: " ".to_string(),
            note: None,
        });
        anonymous.status = UnitStatus::Assigned;
        assert!(validate_history(&anonymous).is_err());
    }

    #[test]
    fn empty_history_is_allowed_for_adopted_units() {
        let mut adopted = unit("adopted");
        adopted.status = UnitStatus::Assigned;
        adopted.owner = "reviewer-1".to_string();
        validate_history(&adopted).expect("empty history is accepted");
    }

    #[test]
    fn ledger_validation_includes_history() {
        let (_dir, mut ledger) = seeded_ledger();
        let id = ledger.units[0].id.clone();
        ledger
            .advance(&id, UnitStatus::Assigned, "reviewer-1", None, 10)
            .expect("advance");
        validate(&ledger).expect("advanced ledger validates");

        ledger.units[0].status = UnitStatus::Pending;
        let error = validate(&ledger).expect_err("status disagrees with history");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("history ends at"));
    }

    #[test]
    fn assignment_records_history_and_stays_valid() {
        let (_dir, mut ledger) = seeded_ledger();
        let id = ledger.units[0].id.clone();
        ledger.assign(&id, "reviewer-1").expect("assign");
        let unit = ledger
            .units
            .iter()
            .find(|unit| unit.id == id)
            .expect("unit");
        assert_eq!(unit.status, UnitStatus::Assigned);
        assert_eq!(unit.history.len(), 1);
        assert_eq!(unit.history[0].from, UnitStatus::Pending);
        assert_eq!(unit.history[0].to, UnitStatus::Assigned);
        assert_eq!(unit.history[0].actor, "reviewer-1");
        validate(&ledger).expect("assigned ledger validates");
    }

    // -- profiles and partial runs ---------------------------------------

    #[test]
    fn profiles_scale_phase_sets_and_budgets() {
        let quick = ReviewProfile::Quick.budget();
        let standard = ReviewProfile::Standard.budget();
        let deep = ReviewProfile::Deep.budget();
        assert!(quick.max_units < standard.max_units);
        assert!(standard.max_units < deep.max_units);
        assert!(quick.max_agents < standard.max_agents);
        assert!(standard.max_agents < deep.max_agents);
        assert!(quick.max_files < standard.max_files);
        assert!(standard.max_files < deep.max_files);

        assert_eq!(ReviewProfile::Quick.as_str(), "quick");
        assert!(!ReviewProfile::Quick
            .phases()
            .contains(&Phase::RecordVerification));
        assert!(ReviewProfile::Standard
            .phases()
            .contains(&Phase::RecordVerification));
        assert!(ReviewProfile::Deep
            .phases()
            .contains(&Phase::RecordVerification));
        assert_eq!(
            ReviewProfile::Standard.phases(),
            ReviewProfile::Deep.phases()
        );
        for profile in ReviewProfile::ALL {
            assert_eq!(profile.phases()[0], Phase::Recon);
        }
    }

    #[test]
    fn scoped_runs_are_always_partial() {
        let requested: Vec<String> = (0..10).map(|index| format!("unit-{index}")).collect();
        let plan = scope(ReviewProfile::Deep, &requested);
        assert!(plan.partial);
        assert_eq!(plan.units.len(), 10);
        let reason = plan.reason.expect("reason");
        assert!(reason.contains("scoped run"));
        assert!(reason.contains("10"));

        let plan = scope(ReviewProfile::Standard, &[]);
        assert!(!plan.partial);
        assert!(plan.units.is_empty());
        assert!(plan.reason.is_none());

        let duplicates = vec![
            "unit-a".to_string(),
            "unit-a".to_string(),
            "unit-b".to_string(),
        ];
        let plan = scope(ReviewProfile::Standard, &duplicates);
        assert_eq!(plan.units, vec!["unit-a".to_string(), "unit-b".to_string()]);
        assert!(plan.partial);
        assert!(plan.reason.as_deref().unwrap().contains('2'));
    }

    #[test]
    fn budget_trimming_reports_counts_and_marks_runs_partial() {
        let requested: Vec<String> = (0..10).map(|index| format!("unit-{index}")).collect();

        let scoped = scope(ReviewProfile::Quick, &requested);
        assert!(scoped.partial);
        assert_eq!(scoped.units.len(), ReviewProfile::Quick.budget().max_units);
        let reason = scoped.reason.expect("reason");
        assert!(reason.contains("10"));
        assert!(reason.contains("8"));
        assert!(reason.contains("quick"));

        let full = scope_all(ReviewProfile::Deep, &requested);
        assert!(!full.partial);
        assert_eq!(full.units.len(), 10);
        assert!(full.reason.is_none());

        let trimmed = scope_all(ReviewProfile::Quick, &requested);
        assert!(trimmed.partial);
        assert_eq!(trimmed.units.len(), ReviewProfile::Quick.budget().max_units);
        let reason = trimmed.reason.expect("reason");
        assert!(reason.contains("10"));
        assert!(reason.contains("8"));

        assert!(!scope_all(ReviewProfile::Quick, &[]).partial);
    }

    // -- structured output -----------------------------------------------

    #[test]
    fn coverage_ledger_json_validates_schema_and_refs() {
        let (dir, ledger) = seeded_ledger();
        let value = serde_json::to_value(&ledger).expect("serialize");
        let parsed = validate_coverage_ledger_json(&value, Some(dir.path())).expect("valid json");
        assert_eq!(parsed, ledger);

        let mut bad_version = value.clone();
        bad_version["schema_version"] = json!(999);
        let error =
            validate_coverage_ledger_json(&bad_version, None).expect_err("unknown schema version");
        assert_eq!(error.code(), ErrorCode::InvalidInput);

        let mut bad_ref = value.clone();
        bad_ref["units"][0]["refs"] = json!(["../escape.rs:1"]);
        assert!(validate_coverage_ledger_json(&bad_ref, None).is_err());

        let mut missing_file = value;
        missing_file["units"][0]["refs"] = json!(["src/missing.rs:1"]);
        let error = validate_coverage_ledger_json(&missing_file, Some(dir.path()))
            .expect_err("missing file");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn coverage_ledger_json_defaults_missing_history() {
        let (_dir, ledger) = seeded_ledger();
        let mut value = serde_json::to_value(&ledger).expect("serialize");
        value["units"][0]
            .as_object_mut()
            .expect("unit object")
            .remove("history");
        let parsed = validate_coverage_ledger_json(&value, None).expect("history defaults");
        assert!(parsed.units[0].history.is_empty());
    }

    fn findings_value() -> Value {
        json!({
            "schema_version": FINDINGS_SCHEMA_VERSION,
            "findings": [{
                "id": "FND-1",
                "unit_id": "unit-1",
                "title": "argv reaches the process sink",
                "severity": "high",
                "status": "confirmed",
                "evidence_refs": ["src/shell.rs:3", "SEC-01"],
                "confirmed": true
            }]
        })
    }

    #[test]
    fn findings_json_validates_the_record_shape() {
        let value = findings_value();
        let findings = validate_findings_json(&value).expect("valid findings");
        assert_eq!(findings.schema_version, FINDINGS_SCHEMA_VERSION);
        assert_eq!(findings.findings.len(), 1);
        assert_eq!(findings.findings[0].status, FindingStatus::Confirmed);
        assert_eq!(
            findings.findings[0].evidence_refs[1].requirement_id(),
            Some("SEC-01")
        );
    }

    #[test]
    fn findings_json_rejects_duplicates_and_unknown_versions() {
        let value = findings_value();
        let mut duplicate = value.clone();
        let finding = duplicate["findings"][0].clone();
        duplicate["findings"]
            .as_array_mut()
            .expect("findings array")
            .push(finding);
        let error = validate_findings_json(&duplicate).expect_err("duplicate id");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("duplicate finding id"));

        let mut unknown = value;
        unknown["schema_version"] = json!(2);
        let error = validate_findings_json(&unknown).expect_err("unknown version");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("schema version 2"));
    }

    #[test]
    fn findings_json_rejects_orphan_units() {
        let (_dir, ledger) = seeded_ledger();
        let value = findings_value();
        let error = validate_findings_json_with_ledger(&value, &ledger)
            .expect_err("unknown unit in the ledger");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("not in the ledger"));

        let mut matching = value;
        matching["findings"][0]["unit_id"] = json!(ledger.units[0].id);
        validate_findings_json_with_ledger(&matching, &ledger).expect("matching unit");
    }

    #[test]
    fn findings_json_rejects_unconfirmed_severity_and_status_drift() {
        let value = findings_value();

        let mut unconfirmed = value.clone();
        unconfirmed["findings"][0]["confirmed"] = json!(false);
        unconfirmed["findings"][0]["status"] = json!("needs_validation");
        let error = validate_findings_json(&unconfirmed).expect_err("unconfirmed severity");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("only confirmed"));

        let mut drift = value;
        drift["findings"][0]["confirmed"] = json!(false);
        let error = validate_findings_json(&drift).expect_err("confirmed flag drift");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("confirmed=false"));
    }

    #[test]
    fn findings_json_rejects_empty_or_bad_evidence() {
        let value = findings_value();

        let mut empty = value.clone();
        empty["findings"][0]["evidence_refs"] = json!([]);
        let error = validate_findings_json(&empty).expect_err("empty evidence");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("no evidence refs"));

        let mut bad_ref = value.clone();
        bad_ref["findings"][0]["evidence_refs"] = json!(["src/shell.rs:0"]);
        assert!(validate_findings_json(&bad_ref).is_err());

        let mut duplicate_refs = value;
        duplicate_refs["findings"][0]["evidence_refs"] =
            json!(["src/shell.rs:3", "src/shell.rs:03"]);
        let error = validate_findings_json(&duplicate_refs).expect_err("duplicate evidence");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("duplicate evidence ref"));
    }

    #[test]
    fn ledger_with_history_round_trips() {
        let (_dir, mut ledger) = seeded_ledger();
        let id = ledger.units[0].id.clone();
        ledger
            .advance(&id, UnitStatus::Assigned, "reviewer-1", None, 10)
            .expect("advance");
        let text = ledger.to_json_pretty().expect("serialize");
        let parsed = CoverageLedger::from_json_str(&text).expect("parse and validate");
        assert_eq!(parsed, ledger);
        let unit = parsed
            .units
            .iter()
            .find(|unit| unit.id == id)
            .expect("unit");
        assert_eq!(unit.history.len(), 1);
        assert_eq!(unit.history[0].to, UnitStatus::Assigned);
        assert_eq!(unit.history[0].actor, "reviewer-1");
    }
}
