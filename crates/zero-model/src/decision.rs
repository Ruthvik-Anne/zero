//! Per-turn decision records, an append-only log, and audit reconstruction
//! (MDL-06, MDL-11, T-MDL-06).
//!
//! MDL-11 requires that every turn records the model, its version, the model
//! parameters, and the router reason. [`TurnRecord`] is that record and
//! [`DecisionLog`] is the append-only store. [`reconstruct`] rebuilds a
//! session's turns in order for an audit, [`verify_turn`] checks one record
//! against an expected model and parameter set, [`audit_line`] renders a
//! deterministic one-line summary, and [`compare_with_ledger`] reconciles the
//! records against usage events that carry the same turn id.
//!
//! ## No prompt or response text by design
//!
//! A [`TurnRecord`] has no field for prompt, response, message, tool output, or
//! transcript content. It stores only routing facts: model identity, version,
//! provider, parameters, class, role, reason, token counters, cost, and an
//! optional escalation. Both [`TurnRecord`] and [`ModelParameters`] use
//! `deny_unknown_fields`, so a line carrying a planted `prompt` key is not a
//! decision record; [`DecisionLog::read_all`] counts it malformed and
//! [`reconstruct`] refuses the audit.
//!
//! ## Unrepresentable values
//!
//! Token counts and costs are unsigned integers, and costs are integer micros.
//! A negative count or a non-finite cost therefore cannot be represented in the
//! type: such a JSON line fails to deserialize and is counted malformed. Float
//! parameters are validated for finiteness and range by
//! [`ModelParameters::validate`].
//!
//! ## Store contract
//!
//! The log is one JSON object per line. [`DecisionLog::append`] writes the whole
//! line, flushes, and fsyncs before returning, and restricts the file to `0600`
//! on Unix. It is append-only: there is no update or delete API, and a second
//! append with the same `(session, turn id)` is refused with
//! `zero.fnd.already_exists` rather than silently duplicated or overwritten.
//! The file is bounded by [`MAX_LOG_BYTES`]; an append that would cross the
//! bound is `zero.fnd.limit_exceeded` and writes nothing, and a log with a
//! malformed line or a torn tail is not extended. Single-writer coordination (a
//! session lease) belongs to the caller; the duplicate check is a safety net,
//! not a cross-process lock.
//!
//! [`read_all`](DecisionLog::read_all) is the lenient reader: it skips a
//! malformed complete line and counts it, flags an unterminated final line as a
//! torn tail, and deduplicates by `(session, turn id)` with the first record
//! winning. It refuses a file that is not JSONL at all with `zero.fnd.corrupt`.
//! [`reconstruct`] is the strict reader: a malformed line, a record that fails
//! validation, or a torn tail fails the audit instead of producing a partial
//! reconstruction.

use crate::classify::WorkClass;
use crate::provider::Usage;
use crate::router::{FailureEvidence, FailureKind, RouteDecision};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Hard upper bound for one decision log file.
///
/// A record is a few hundred bytes, so the bound leaves room for tens of
/// thousands of turns. It exists so a runaway caller cannot grow the log
/// without limit; rotating into a new per-session log is the documented way to
/// continue past it.
pub const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

/// The per-session turn number.
///
/// Turn ids are the monotonic turn counter the agent loop already uses. They are
/// only unique within a session, so the store and the audit key on
/// `(session, turn id)`. Keeping the id numeric is what makes a sequence gap
/// detectable instead of invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TurnId(u64);

impl TurnId {
    /// Wrap a turn number.
    pub const fn new(turn: u64) -> Self {
        Self(turn)
    }

    /// The raw turn number.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for TurnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How much reasoning effort the turn requested.
///
/// These are the provider-facing labels stored in the record. An unknown label
/// in a JSON line is rejected by deserialization, so a new provider value
/// cannot be recorded before it is added here.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    /// The provider's own default.
    #[default]
    None,
    /// The smallest explicit budget.
    Minimal,
    Low,
    Medium,
    High,
}

impl ReasoningEffort {
    /// Stable snake-case label used in records, summaries, and errors.
    pub const fn as_str(self) -> &'static str {
        match self {
            ReasoningEffort::None => "none",
            ReasoningEffort::Minimal => "minimal",
            ReasoningEffort::Low => "low",
            ReasoningEffort::Medium => "medium",
            ReasoningEffort::High => "high",
        }
    }
}

impl fmt::Display for ReasoningEffort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The model parameters that were sent with the turn.
///
/// `temperature` is `0.0..=2.0`, the union of the provider ranges this runtime
/// speaks (a provider that accepts only `0.0..=1.0` clamps at its adapter).
/// `top_p` is `0.0..=1.0`. `max_output_tokens` is at least one and at most
/// [`ModelParameters::MAX_OUTPUT_TOKENS`], a structural sanity bound rather than
/// any provider's limit. Every float must be finite. [`Self::new`] and
/// [`Self::validate`] enforce all of it; an unknown field or an unknown
/// `reasoning_effort` label is rejected by deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelParameters {
    pub temperature: f32,
    pub top_p: f32,
    pub max_output_tokens: u32,
    pub reasoning_effort: ReasoningEffort,
}

impl ModelParameters {
    /// Largest accepted temperature.
    pub const MAX_TEMPERATURE: f32 = 2.0;

    /// Largest accepted top-p.
    pub const MAX_TOP_P: f32 = 1.0;

    /// Largest accepted output-token budget. This is a sanity bound, not a
    /// claim about any provider.
    pub const MAX_OUTPUT_TOKENS: u32 = 4_194_304;

    /// Build and validate a parameter set.
    pub fn new(
        temperature: f32,
        top_p: f32,
        max_output_tokens: u32,
        reasoning_effort: ReasoningEffort,
    ) -> Result<Self> {
        let parameters = Self {
            temperature,
            top_p,
            max_output_tokens,
            reasoning_effort,
        };
        parameters.validate()?;
        Ok(parameters)
    }

    /// Reject a non-finite or out-of-range value.
    pub fn validate(&self) -> Result<()> {
        if !self.temperature.is_finite()
            || !(0.0..=Self::MAX_TEMPERATURE).contains(&self.temperature)
        {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!(
                    "temperature {} is outside the supported range 0.0..={}",
                    self.temperature,
                    Self::MAX_TEMPERATURE
                ),
            ));
        }
        if !self.top_p.is_finite() || !(0.0..=Self::MAX_TOP_P).contains(&self.top_p) {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!(
                    "top_p {} is outside the supported range 0.0..={}",
                    self.top_p,
                    Self::MAX_TOP_P
                ),
            ));
        }
        if self.max_output_tokens == 0 || self.max_output_tokens > Self::MAX_OUTPUT_TOKENS {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!(
                    "max_output_tokens {} is outside the supported range 1..={}",
                    self.max_output_tokens,
                    Self::MAX_OUTPUT_TOKENS
                ),
            ));
        }
        Ok(())
    }
}

impl Default for ModelParameters {
    /// A permissive, valid default: temperature 0.0 (the provider default),
    /// top-p 1.0, an 8,192-token output budget, and no explicit reasoning
    /// effort. A caller should always send the values it actually used.
    fn default() -> Self {
        Self {
            temperature: 0.0,
            top_p: 1.0,
            max_output_tokens: 8_192,
            reasoning_effort: ReasoningEffort::None,
        }
    }
}

impl fmt::Display for ModelParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "temperature={:.3} top_p={:.3} max_output_tokens={} reasoning_effort={}",
            self.temperature,
            self.top_p,
            self.max_output_tokens,
            self.reasoning_effort.as_str()
        )
    }
}

/// The escalation that produced a turn, with the evidence that caused it.
///
/// Only routing facts are kept: the failed model, the failure kind, and the
/// attempt count. The caller's bounded diagnostic summary stays in
/// [`FailureEvidence`] and is not copied into the durable record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationRecord {
    pub from_model: String,
    pub evidence_kind: FailureKind,
    pub attempts: u32,
}

impl EscalationRecord {
    /// Copy an escalation from router evidence.
    pub fn from_evidence(evidence: &FailureEvidence) -> Self {
        Self {
            from_model: evidence.model.clone(),
            evidence_kind: evidence.kind,
            attempts: evidence.attempts,
        }
    }
}

impl From<&FailureEvidence> for EscalationRecord {
    fn from(evidence: &FailureEvidence) -> Self {
        Self::from_evidence(evidence)
    }
}

/// One turn's routing and usage record (MDL-11).
///
/// Required fields: `session`, `model`, `model_version`, `provider`, and
/// `router_reason`. They are validated by [`Self::validate`]; there is no
/// default that can make a missing value look present. Token counts and costs
/// are unsigned integer micros, so a negative count or a non-finite cost is
/// unrepresentable and a JSON line carrying one is rejected.
///
/// There is deliberately no prompt, response, message, tool-output, or
/// transcript field. `deny_unknown_fields` rejects a line that tries to add one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnRecord {
    pub turn_id: TurnId,
    pub session: String,
    pub at_ms: i64,
    pub model: String,
    pub model_version: String,
    pub provider: String,
    pub parameters: ModelParameters,
    pub class: Option<WorkClass>,
    pub role: Option<String>,
    pub router_reason: String,
    pub assignment_source: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub estimated_cost_micros: u64,
    pub actual_cost_micros: u64,
    pub escalation: Option<EscalationRecord>,
}

/// The required fields for [`TurnRecord::new`].
///
/// A struct literal keeps the constructor readable while the optional routing
/// fields stay on the record's builder methods.
#[derive(Debug, Clone, PartialEq)]
pub struct TurnRecordInit {
    pub turn_id: TurnId,
    pub session: String,
    pub at_ms: i64,
    pub model: String,
    pub model_version: String,
    pub provider: String,
    pub parameters: ModelParameters,
    pub router_reason: String,
    pub estimated_cost_micros: u64,
    pub actual_cost_micros: u64,
}

impl TurnRecord {
    /// Build and validate a record. Token counts start at zero.
    pub fn new(init: TurnRecordInit) -> Result<Self> {
        let record = Self {
            turn_id: init.turn_id,
            session: init.session,
            at_ms: init.at_ms,
            model: init.model,
            model_version: init.model_version,
            provider: init.provider,
            parameters: init.parameters,
            class: None,
            role: None,
            router_reason: init.router_reason,
            assignment_source: None,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            estimated_cost_micros: init.estimated_cost_micros,
            actual_cost_micros: init.actual_cost_micros,
            escalation: None,
        };
        record.validate()?;
        Ok(record)
    }

    /// Build a record from a routing decision and the provider's usage.
    ///
    /// The model, provider, and router reason come from the decision. The class,
    /// role, model version, and assignment source are not carried by
    /// [`RouteDecision`], so the caller supplies them in [`DecisionContext`].
    /// The estimate is recomputed from the observed token count because the
    /// decision does not retain the pre-dispatch forecast; a caller with a
    /// forecast overwrites `estimated_cost_micros` afterwards. Usage supplies
    /// every token counter and the actual cost. An escalation, when present, is
    /// copied from its failure evidence without the diagnostic summary.
    pub fn from_decision(
        context: DecisionContext,
        decision: &RouteDecision,
        parameters: ModelParameters,
        usage: &Usage,
        evidence: Option<&FailureEvidence>,
    ) -> Result<Self> {
        let init = TurnRecordInit {
            turn_id: context.turn_id,
            session: context.session,
            at_ms: context.at_ms,
            model: decision.chosen.model.clone(),
            model_version: context.model_version,
            provider: decision.chosen.provider.clone(),
            parameters,
            router_reason: decision.reason.clone(),
            estimated_cost_micros: decision.chosen.estimated_cost_micros(usage.total_tokens()),
            actual_cost_micros: usage.cost_micros,
        };
        let mut record = Self::new(init)?;
        record.class = context.class;
        record.role = context.role;
        record.assignment_source = context.assignment_source;
        record.input_tokens = usage.input_tokens;
        record.output_tokens = usage.output_tokens;
        record.cache_read_tokens = usage.cache_read_tokens;
        record.cache_write_tokens = usage.cache_write_tokens;
        record.escalation = evidence.map(EscalationRecord::from_evidence);
        Ok(record)
    }

    /// Attach the work class the turn was routed as.
    pub fn with_class(mut self, class: WorkClass) -> Self {
        self.class = Some(class);
        self
    }

    /// Attach the agent role that ran the turn.
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    /// Attach where the model assignment came from (`default`, `user_pinned`,
    /// `upgrade_requested`, `fallback`, or a router label).
    pub fn with_assignment_source(mut self, source: impl Into<String>) -> Self {
        self.assignment_source = Some(source.into());
        self
    }

    /// Copy token counters and the actual cost from a provider usage sample.
    pub fn with_usage(mut self, usage: &Usage) -> Self {
        self.input_tokens = usage.input_tokens;
        self.output_tokens = usage.output_tokens;
        self.cache_read_tokens = usage.cache_read_tokens;
        self.cache_write_tokens = usage.cache_write_tokens;
        self.actual_cost_micros = usage.cost_micros;
        self
    }

    /// Attach the escalation that selected this turn's model.
    pub fn with_escalation(mut self, escalation: EscalationRecord) -> Self {
        self.escalation = Some(escalation);
        self
    }

    /// Reject a record that cannot identify its turn or its routing.
    ///
    /// Missing or blank `session`, `model`, `model_version`, `provider`, or
    /// `router_reason` is `zero.fnd.invalid_input`, as are a blank optional
    /// role/assignment source, an escalation with a blank model or zero
    /// attempts, and any out-of-range parameter.
    pub fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("session", self.session.as_str()),
            ("model", self.model.as_str()),
            ("model_version", self.model_version.as_str()),
            ("provider", self.provider.as_str()),
            ("router_reason", self.router_reason.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!("turn {} is missing its {field}", self.turn_id),
                ));
            }
        }
        if let Some(role) = &self.role {
            if role.trim().is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!("turn {} has a blank role", self.turn_id),
                ));
            }
        }
        if let Some(source) = &self.assignment_source {
            if source.trim().is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!("turn {} has a blank assignment source", self.turn_id),
                ));
            }
        }
        self.parameters.validate().map_err(|error| {
            ZeroError::new(
                ErrorCode::InvalidInput,
                format!("turn {}: {}", self.turn_id, error.message()),
            )
        })?;
        if let Some(escalation) = &self.escalation {
            if escalation.from_model.trim().is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "turn {} has an escalation with a blank from_model",
                        self.turn_id
                    ),
                ));
            }
            if escalation.attempts == 0 {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!("turn {} has an escalation with zero attempts", self.turn_id),
                ));
            }
        }
        Ok(())
    }
}

/// The fields [`TurnRecord::from_decision`] cannot take from a [`RouteDecision`].
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionContext {
    pub turn_id: TurnId,
    pub session: String,
    pub at_ms: i64,
    /// The exact model version or snapshot id the provider served.
    pub model_version: String,
    pub class: Option<WorkClass>,
    pub role: Option<String>,
    pub assignment_source: Option<String>,
}

/// What [`DecisionLog::read_all`] found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LogReport {
    /// Valid records, deduplicated by `(session, turn id)`, in file order with
    /// the first occurrence winning.
    pub records: Vec<TurnRecord>,
    /// Complete lines that did not deserialize or failed validation.
    pub malformed: usize,
    /// Valid records whose `(session, turn id)` was already seen.
    pub duplicates: usize,
    /// True when the final line had no terminating newline; it is not returned.
    pub torn_tail: bool,
}

/// An append-only decision log at one path.
///
/// The path may not exist yet; reading a missing file is an empty report and the
/// first append creates the parent directory and the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionLog {
    path: PathBuf,
}

impl DecisionLog {
    /// Point a log at a path. No I/O happens until [`Self::append`] or
    /// [`Self::read_all`].
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The backing path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record as one JSON line, fsync, and restrict the file mode.
    ///
    /// Refuses, in order: an invalid record (`zero.fnd.invalid_input`); an
    /// append that would exceed [`MAX_LOG_BYTES`] (`zero.fnd.limit_exceeded`,
    /// nothing written); a log that cannot be read as JSONL, or that has a
    /// malformed line or a torn tail (`zero.fnd.corrupt`); and a duplicate
    /// `(session, turn id)` (`zero.fnd.already_exists`). The file is created
    /// with mode `0600` on Unix when it does not exist.
    pub fn append(&self, record: &TurnRecord) -> Result<()> {
        record.validate()?;
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');

        let current = match std::fs::metadata(&self.path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        let next = current.saturating_add(line.len() as u64);
        if next > MAX_LOG_BYTES {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "{} would grow to {next} bytes, past the {MAX_LOG_BYTES}-byte decision log bound; rotate to a new log",
                    self.path.display()
                ),
            ));
        }

        // A duplicate is an error, not a silent second line, and a log that is
        // already damaged must not be extended.
        let report = self.read_all()?;
        if report.torn_tail || report.malformed > 0 {
            return Err(ZeroError::new(
                ErrorCode::Corrupt,
                format!(
                    "{}: decision log is damaged (torn_tail={}, {} malformed line(s)); rotate to a new log before appending",
                    self.path.display(),
                    report.torn_tail,
                    report.malformed
                ),
            ));
        }
        if report.records.iter().any(|existing| {
            existing.session == record.session && existing.turn_id == record.turn_id
        }) {
            return Err(ZeroError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "{} already has a record for session {:?} turn {}; decision appends are not idempotent",
                    self.path.display(),
                    record.session,
                    record.turn_id
                ),
            ));
        }

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.path)?;
        restrict_permissions(&self.path)?;
        file.write_all(&line)?;
        file.flush()?;
        file.sync_data()?;
        Ok(())
    }

    /// Read the log leniently: skip malformed lines, count them, flag a torn
    /// tail, and deduplicate by `(session, turn id)`.
    ///
    /// A missing file is an empty report. A file that is a JSON array, is not
    /// UTF-8, or whose lines are not JSON objects is `zero.fnd.corrupt`.
    pub fn read_all(&self) -> Result<LogReport> {
        read_log(&self.path)
    }
}

fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn read_log(path: &Path) -> Result<LogReport> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LogReport::default())
        }
        Err(error) => return Err(error.into()),
    };
    parse_bytes(path, &bytes)
}

fn parse_bytes(path: &Path, bytes: &[u8]) -> Result<LogReport> {
    if bytes.is_empty() {
        return Ok(LogReport::default());
    }
    let text = std::str::from_utf8(bytes).map_err(|error| {
        ZeroError::new(
            ErrorCode::Corrupt,
            format!(
                "{}: decision log is not UTF-8 JSONL: {error}",
                path.display()
            ),
        )
    })?;
    if text.trim_start().starts_with('[') {
        return Err(ZeroError::new(
            ErrorCode::Corrupt,
            format!(
                "{}: decision log is a JSON array, not JSONL",
                path.display()
            ),
        ));
    }

    let mut report = LogReport::default();
    let complete = if text.ends_with('\n') {
        text
    } else {
        report.torn_tail = true;
        match text.rfind('\n') {
            Some(index) => &text[..=index],
            None => "",
        }
    };

    let mut seen: BTreeSet<(String, TurnId)> = BTreeSet::new();
    let mut non_empty = 0usize;
    let mut object_like = 0usize;
    for line in complete.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        non_empty += 1;
        if line.trim_start().starts_with('{') {
            object_like += 1;
        }
        match serde_json::from_str::<TurnRecord>(line) {
            Ok(record) if record.validate().is_ok() => {
                if seen.insert((record.session.clone(), record.turn_id)) {
                    report.records.push(record);
                } else {
                    report.duplicates += 1;
                }
            }
            _ => report.malformed += 1,
        }
    }

    // Individual bad lines are skipped, but a file whose lines are not even
    // object-shaped (pretty-printed JSON, text, CSV) is not a decision log.
    if report.records.is_empty() && report.malformed > 0 && object_like < non_empty {
        return Err(ZeroError::new(
            ErrorCode::Corrupt,
            format!("{}: not a JSONL decision log", path.display()),
        ));
    }
    Ok(report)
}

/// One jump in a session's turn sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnGap {
    /// The last turn before the gap.
    pub after: TurnId,
    /// The first turn after the gap.
    pub before: TurnId,
    /// How many turn numbers are missing between them.
    pub missing: u64,
}

/// Summed usage for a reconstructed session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTotals {
    pub turns: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub estimated_cost_micros: u64,
    pub actual_cost_micros: u64,
}

/// A session's turns, ordered by turn id, with the gaps between them.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionAudit {
    pub session: String,
    pub turns: Vec<TurnRecord>,
    /// Jumps in the turn sequence inside the reconstructed range. A missing
    /// prefix (the first recorded turn is not turn 0) is not a gap.
    pub gaps: Vec<TurnGap>,
    pub totals: AuditTotals,
}

/// Reconstruct every recorded turn of one session (Done: audit reconstructs
/// each turn).
///
/// The audit is strict: a malformed line, a record that fails validation, or a
/// torn tail fails with `zero.fnd.corrupt` rather than reconstructing a partial
/// history. Valid records are deduplicated by `(session, turn id)` by
/// [`DecisionLog::read_all`] (first wins), filtered to `session`, sorted by turn
/// id, and summed. A sequence jump is reported in [`SessionAudit::gaps`], never
/// silently ignored. An unknown or empty session yields an empty audit with
/// zero totals, not an error.
pub fn reconstruct(session: &str, log: &DecisionLog) -> Result<SessionAudit> {
    let report = log.read_all()?;
    if report.torn_tail {
        return Err(ZeroError::new(
            ErrorCode::Corrupt,
            format!(
                "{}: decision log has a torn tail; the audit would be incomplete",
                log.path().display()
            ),
        ));
    }
    if report.malformed > 0 {
        return Err(ZeroError::new(
            ErrorCode::Corrupt,
            format!(
                "{}: {} malformed decision line(s); the audit is refused",
                log.path().display(),
                report.malformed
            ),
        ));
    }

    let mut turns: Vec<TurnRecord> = report
        .records
        .into_iter()
        .filter(|record| record.session == session)
        .collect();
    for turn in &turns {
        turn.validate()?;
    }
    turns.sort_by_key(|record| record.turn_id);

    let mut gaps = Vec::new();
    for pair in turns.windows(2) {
        let after = pair[0].turn_id;
        let before = pair[1].turn_id;
        let missing = before.get().saturating_sub(after.get()).saturating_sub(1);
        if missing > 0 {
            gaps.push(TurnGap {
                after,
                before,
                missing,
            });
        }
    }

    let totals = totals_of(&turns);
    Ok(SessionAudit {
        session: session.to_owned(),
        turns,
        gaps,
        totals,
    })
}

fn totals_of(turns: &[TurnRecord]) -> AuditTotals {
    let mut totals = AuditTotals::default();
    for turn in turns {
        totals.turns = totals.turns.saturating_add(1);
        totals.input_tokens = totals.input_tokens.saturating_add(turn.input_tokens);
        totals.output_tokens = totals.output_tokens.saturating_add(turn.output_tokens);
        totals.cache_read_tokens = totals
            .cache_read_tokens
            .saturating_add(turn.cache_read_tokens);
        totals.cache_write_tokens = totals
            .cache_write_tokens
            .saturating_add(turn.cache_write_tokens);
        totals.estimated_cost_micros = totals
            .estimated_cost_micros
            .saturating_add(turn.estimated_cost_micros);
        totals.actual_cost_micros = totals
            .actual_cost_micros
            .saturating_add(turn.actual_cost_micros);
    }
    totals
}

/// Check one record against the model and parameters the caller expected.
///
/// Any difference is `zero.pol.conflict` (a stable code imported as
/// `ErrorCode::Conflict`) naming the turn and the field, never the prompt. A
/// blank expected model is `zero.fnd.invalid_input`.
pub fn verify_turn(
    record: &TurnRecord,
    expected_model: &str,
    expected_params: ModelParameters,
) -> Result<()> {
    record.validate()?;
    if expected_model.trim().is_empty() {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            "expected model must not be blank",
        ));
    }
    if record.model != expected_model {
        return Err(ZeroError::new(
            ErrorCode::Conflict,
            format!(
                "turn {} recorded model {:?} but {:?} was expected",
                record.turn_id, record.model, expected_model
            ),
        ));
    }
    if record.parameters != expected_params {
        return Err(ZeroError::new(
            ErrorCode::Conflict,
            format!(
                "turn {} recorded parameters [{}] but [{}] was expected",
                record.turn_id, record.parameters, expected_params
            ),
        ));
    }
    Ok(())
}

/// A deterministic one-line summary of a record for an audit or a log.
///
/// The fixed field order is model, version, provider, parameters, class, role,
/// source, reason, tokens, cost, and escalation. There is no prompt text to
/// include; the record has no such field.
pub fn audit_line(record: &TurnRecord) -> String {
    let class = record.class.map_or("none", WorkClass::as_str);
    let role = record.role.as_deref().unwrap_or("none");
    let source = record.assignment_source.as_deref().unwrap_or("none");
    let escalation = match &record.escalation {
        None => "none".to_owned(),
        Some(escalation) => format!(
            "from={} kind={} attempts={}",
            escalation.from_model,
            escalation.evidence_kind.as_str(),
            escalation.attempts
        ),
    };
    format!(
        "turn {} session {} at_ms {} model {} version {} provider {} params {} class {} role {} source {} reason {:?} tokens input={} output={} cache_read={} cache_write={} cost_micros estimated={} actual={} escalation {}",
        record.turn_id,
        record.session,
        record.at_ms,
        record.model,
        record.model_version,
        record.provider,
        record.parameters,
        class,
        role,
        source,
        record.router_reason,
        record.input_tokens,
        record.output_tokens,
        record.cache_read_tokens,
        record.cache_write_tokens,
        record.estimated_cost_micros,
        record.actual_cost_micros,
        escalation
    )
}

/// A usage event projected into the fields a decision audit compares.
///
/// The scheduler owns the usage ledger and `zero-model` does not depend on it,
/// so the caller projects each event here. The pair `(session, turn_id)` is the
/// join key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEvent {
    pub session: String,
    pub turn_id: TurnId,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_micros: u64,
}

/// What disagreed between a record and its usage event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MismatchKind {
    /// No usage event carried this turn id.
    MissingEvent,
    /// The event billed a different model.
    Model { recorded: String, ledger: String },
    /// A token counter disagreed.
    Tokens {
        field: String,
        recorded: u64,
        ledger: u64,
    },
    /// The actual cost disagreed.
    Cost { recorded: u64, ledger: u64 },
}

/// One disagreement between a turn record and its usage event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mismatch {
    pub session: String,
    pub turn_id: TurnId,
    pub kind: MismatchKind,
}

/// Compare records against usage events that carry the same turn id.
///
/// Every record must have a matching `(session, turn id)` event with the same
/// model, all four token counters, and the same actual cost. A missing event is
/// a [`MismatchKind::MissingEvent`] entry, not an error: a turn may be recorded
/// before the ledger syncs. Duplicate records or duplicate events for one key
/// make the comparison ambiguous and are `zero.fnd.already_exists`. Events that
/// match no record are ignored, because the caller may pass a whole-device
/// ledger. Output order is deterministic: `(session, turn id)` ascending.
pub fn compare_with_ledger(
    records: &[TurnRecord],
    usage_events: &[LedgerEvent],
) -> Result<Vec<Mismatch>> {
    let mut by_turn: BTreeMap<(String, TurnId), &TurnRecord> = BTreeMap::new();
    for record in records {
        record.validate()?;
        let key = (record.session.clone(), record.turn_id);
        if by_turn.insert(key, record).is_some() {
            return Err(ZeroError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "session {:?} has more than one record for turn {}; compare the reconstructed audit instead",
                    record.session, record.turn_id
                ),
            ));
        }
    }

    let mut events: BTreeMap<(String, TurnId), &LedgerEvent> = BTreeMap::new();
    for event in usage_events {
        let key = (event.session.clone(), event.turn_id);
        if events.insert(key, event).is_some() {
            return Err(ZeroError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "usage ledger has more than one event for session {:?} turn {}",
                    event.session, event.turn_id
                ),
            ));
        }
    }

    let mut mismatches = Vec::new();
    for ((session, turn_id), record) in by_turn {
        let Some(event) = events.get(&(session.clone(), turn_id)) else {
            mismatches.push(Mismatch {
                session,
                turn_id,
                kind: MismatchKind::MissingEvent,
            });
            continue;
        };

        if record.model != event.model {
            mismatches.push(Mismatch {
                session: session.clone(),
                turn_id,
                kind: MismatchKind::Model {
                    recorded: record.model.clone(),
                    ledger: event.model.clone(),
                },
            });
        }
        for (field, recorded, ledger) in [
            ("input_tokens", record.input_tokens, event.input_tokens),
            ("output_tokens", record.output_tokens, event.output_tokens),
            (
                "cache_read_tokens",
                record.cache_read_tokens,
                event.cache_read_tokens,
            ),
            (
                "cache_write_tokens",
                record.cache_write_tokens,
                event.cache_write_tokens,
            ),
        ] {
            if recorded != ledger {
                mismatches.push(Mismatch {
                    session: session.clone(),
                    turn_id,
                    kind: MismatchKind::Tokens {
                        field: field.to_owned(),
                        recorded,
                        ledger,
                    },
                });
            }
        }
        if record.actual_cost_micros != event.cost_micros {
            mismatches.push(Mismatch {
                session: session.clone(),
                turn_id,
                kind: MismatchKind::Cost {
                    recorded: record.actual_cost_micros,
                    ledger: event.cost_micros,
                },
            });
        }
    }
    Ok(mismatches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{self, ModelGrades};
    use crate::router::{route, Overrides, Pool, PoolModel};

    fn parameters() -> ModelParameters {
        ModelParameters::new(0.2, 0.9, 4096, ReasoningEffort::Medium).expect("valid parameters")
    }

    fn init(session: &str, turn: u64) -> TurnRecordInit {
        TurnRecordInit {
            turn_id: TurnId::new(turn),
            session: session.to_owned(),
            at_ms: 1_700_000_000_000 + turn as i64,
            model: "model-a".to_owned(),
            model_version: "2026-11-01".to_owned(),
            provider: "test".to_owned(),
            parameters: parameters(),
            router_reason: "cheapest eligible model clears the edit floor".to_owned(),
            estimated_cost_micros: 120,
            actual_cost_micros: 150,
        }
    }

    fn record(session: &str, turn: u64) -> TurnRecord {
        TurnRecord::new(init(session, turn)).expect("valid record")
    }

    fn usage() -> Usage {
        Usage {
            input_tokens: 700,
            output_tokens: 300,
            cache_read_tokens: 40,
            cache_write_tokens: 10,
            cost_micros: 150,
        }
    }

    fn model(name: &str, tier: u8, rate: u64) -> PoolModel {
        PoolModel {
            model: name.to_owned(),
            provider: "test".to_owned(),
            grades: ModelGrades {
                model: name.to_owned(),
                grades: classify::floor_for(WorkClass::Edit).minimums,
            },
            input_cost_micros_per_mtok: rate,
            output_cost_micros_per_mtok: rate,
            available: true,
            deprecated: false,
            tier,
        }
    }

    fn route_fixture() -> RouteDecision {
        let pool =
            Pool::new(vec![model("cheap", 0, 5), model("strong", 1, 90)]).expect("valid pool");
        let classification = classify::classify(&classify::TaskSignals {
            files_changed: 1,
            ..classify::TaskSignals::default()
        });
        route(&pool, &classification, &Overrides::default(), None, 1_000).expect("a route exists")
    }

    fn raw_log(path: &Path, lines: &[&str]) {
        std::fs::write(path, lines.join("\n") + "\n").expect("raw log");
    }

    fn raw_line(record: &TurnRecord) -> String {
        serde_json::to_string(record).expect("record serialises")
    }

    #[test]
    fn append_and_reload_round_trips_and_creates_missing_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = DecisionLog::new(dir.path().join("nested").join("decisions.jsonl"));
        assert!(log
            .read_all()
            .expect("missing file is empty")
            .records
            .is_empty());

        let first = record("s1", 1);
        let second = record("s1", 2)
            .with_class(WorkClass::Edit)
            .with_role("coder")
            .with_assignment_source("default");
        log.append(&first).expect("first append");
        log.append(&second).expect("second append");

        let report = log.read_all().expect("reload");
        assert_eq!(report.records, vec![first, second]);
        assert_eq!(report.malformed, 0);
        assert_eq!(report.duplicates, 0);
        assert!(!report.torn_tail);
        assert!(log.path().metadata().expect("file exists").len() > 0);
    }

    #[test]
    fn reconstruct_returns_every_turn_once_in_order_with_totals() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = DecisionLog::new(dir.path().join("decisions.jsonl"));
        // Appended out of order on purpose.
        log.append(&record("s1", 3)).unwrap();
        log.append(&record("s1", 1)).unwrap();
        log.append(&record("s1", 2)).unwrap();
        log.append(&record("other", 1)).unwrap();

        let audit = reconstruct("s1", &log).expect("clean audit");
        let ids: Vec<u64> = audit.turns.iter().map(|turn| turn.turn_id.get()).collect();
        assert_eq!(ids, vec![1, 2, 3]);
        assert!(audit.gaps.is_empty());
        assert_eq!(audit.session, "s1");
        assert_eq!(audit.totals.turns, 3);
        assert_eq!(audit.totals.input_tokens, 0);
        assert_eq!(audit.totals.estimated_cost_micros, 360);
        assert_eq!(audit.totals.actual_cost_micros, 450);
        for turn in &audit.turns {
            assert_eq!(turn.model, "model-a");
            assert_eq!(turn.model_version, "2026-11-01");
            assert_eq!(turn.parameters, parameters());
            assert!(!turn.router_reason.is_empty());
        }
    }

    #[test]
    fn duplicate_turn_id_is_refused_and_a_different_session_is_allowed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = DecisionLog::new(dir.path().join("decisions.jsonl"));
        log.append(&record("s1", 1)).expect("first append");

        let error = log
            .append(&record("s1", 1))
            .expect_err("duplicate id is refused");
        assert_eq!(error.code(), ErrorCode::AlreadyExists);
        assert!(
            error.message().contains("not idempotent"),
            "{}",
            error.message()
        );

        let mut changed = record("s1", 1);
        changed.model = "model-b".to_owned();
        let error = log
            .append(&changed)
            .expect_err("same id with other content is refused too");
        assert_eq!(error.code(), ErrorCode::AlreadyExists);

        assert_eq!(log.read_all().expect("reload").records.len(), 1);
        log.append(&record("s2", 1))
            .expect("turn ids are per session");
        assert_eq!(log.read_all().expect("reload").records.len(), 2);
    }

    #[test]
    fn malformed_lines_are_skipped_and_counted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("decisions.jsonl");
        let valid = raw_line(&record("s1", 1));
        raw_log(
            &path,
            &[
                &valid,
                "not json at all",
                r#"{"session":"s1","turn_id":2}"#,
                &valid,
            ],
        );

        let report = DecisionLog::new(&path).read_all().expect("lenient read");
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.malformed, 2);
        assert_eq!(report.duplicates, 1);
        assert!(!report.torn_tail);

        // The audit is strict: it refuses a log with bad lines.
        let error = reconstruct("s1", &DecisionLog::new(&path)).expect_err("audit refuses");
        assert_eq!(error.code(), ErrorCode::Corrupt);
        assert!(error.message().contains("malformed"), "{}", error.message());

        // Appending to a damaged log is refused rather than extending it.
        let log = DecisionLog::new(&path);
        let error = log.append(&record("s1", 9)).expect_err("damaged log");
        assert_eq!(error.code(), ErrorCode::Corrupt);
        assert!(error.message().contains("damaged"), "{}", error.message());
    }

    #[test]
    fn a_non_jsonl_file_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let array = dir.path().join("array.json");
        std::fs::write(&array, "[\n{\"turn_id\":1}\n]\n").unwrap();
        assert_eq!(
            DecisionLog::new(&array)
                .read_all()
                .expect_err("array")
                .code(),
            ErrorCode::Corrupt
        );

        let text = dir.path().join("notes.txt");
        std::fs::write(&text, "decision one\ndecision two\n").unwrap();
        let error = DecisionLog::new(&text).read_all().expect_err("text");
        assert_eq!(error.code(), ErrorCode::Corrupt);
        assert!(
            error.message().contains("not a JSONL decision log"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn torn_tail_is_flagged_and_reconstruction_refuses_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("decisions.jsonl");
        let log = DecisionLog::new(&path);
        log.append(&record("s1", 1)).unwrap();
        log.append(&record("s1", 2)).unwrap();

        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(br#"{"turn_id":3,"session":"s1""#).unwrap();
        file.sync_all().unwrap();

        let report = log.read_all().expect("lenient read");
        assert_eq!(report.records.len(), 2);
        assert!(report.torn_tail);

        let error = reconstruct("s1", &log).expect_err("a torn tail fails the audit");
        assert_eq!(error.code(), ErrorCode::Corrupt);
        assert!(error.message().contains("torn tail"), "{}", error.message());

        let error = log
            .append(&record("s1", 3))
            .expect_err("a torn tail blocks appends");
        assert_eq!(error.code(), ErrorCode::Corrupt);
        assert!(error.message().contains("damaged"), "{}", error.message());
    }

    #[test]
    fn missing_fields_fail_with_a_typed_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("decisions.jsonl");
        raw_log(&path, &[r#"{"session":"s1","turn_id":1,"model":"m"}"#]);
        let log = DecisionLog::new(&path);
        assert_eq!(log.read_all().expect("lenient read").malformed, 1);
        let error = reconstruct("s1", &log).expect_err("a missing field fails");
        assert_eq!(error.code(), ErrorCode::Corrupt);

        // A parsed record with a blank required value fails validation and is
        // therefore a malformed line, not a usable turn.
        let mut blank = record("s1", 2);
        blank.model = "   ".to_owned();
        let error = blank.validate().expect_err("blank model");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("model"), "{}", error.message());

        let blank_session = TurnRecordInit {
            session: " ".to_owned(),
            ..init("s1", 3)
        };
        let error = TurnRecord::new(blank_session).expect_err("blank session");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("session"), "{}", error.message());

        let blank_version = TurnRecordInit {
            model_version: String::new(),
            ..init("s1", 3)
        };
        assert_eq!(
            TurnRecord::new(blank_version)
                .expect_err("blank version")
                .code(),
            ErrorCode::InvalidInput
        );

        let blank_reason = TurnRecordInit {
            router_reason: " ".to_owned(),
            ..init("s1", 3)
        };
        assert_eq!(
            TurnRecord::new(blank_reason)
                .expect_err("blank reason")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn parameters_reject_unknown_and_out_of_range_values() {
        assert_eq!(
            ModelParameters::new(0.0, 0.0, 1, ReasoningEffort::None)
                .expect("lower bounds")
                .temperature
                .to_bits(),
            0.0f32.to_bits()
        );
        assert!(ModelParameters::new(
            2.0,
            1.0,
            ModelParameters::MAX_OUTPUT_TOKENS,
            ReasoningEffort::High
        )
        .is_ok());

        for temperature in [f32::NAN, f32::INFINITY, -0.01, 2.01] {
            let error = ModelParameters::new(temperature, 0.9, 4096, ReasoningEffort::None)
                .expect_err("bad temperature");
            assert_eq!(error.code(), ErrorCode::InvalidInput);
            assert!(
                error.message().contains("temperature"),
                "{}",
                error.message()
            );
        }
        for top_p in [f32::NAN, -0.01, 1.01] {
            let error = ModelParameters::new(0.2, top_p, 4096, ReasoningEffort::None)
                .expect_err("bad top_p");
            assert!(error.message().contains("top_p"), "{}", error.message());
        }
        for tokens in [0, ModelParameters::MAX_OUTPUT_TOKENS + 1] {
            let error = ModelParameters::new(0.2, 0.9, tokens, ReasoningEffort::None)
                .expect_err("bad output budget");
            assert!(
                error.message().contains("max_output_tokens"),
                "{}",
                error.message()
            );
        }

        // Unknown enum labels and unknown fields are rejected on the wire.
        let unknown_effort = r#"{"temperature":0.2,"top_p":0.9,"max_output_tokens":4096,"reasoning_effort":"extreme"}"#;
        assert!(serde_json::from_str::<ModelParameters>(unknown_effort).is_err());
        let unknown_field = r#"{"temperature":0.2,"top_p":0.9,"max_output_tokens":4096,"reasoning_effort":"low","seed":7}"#;
        assert!(serde_json::from_str::<ModelParameters>(unknown_field).is_err());
        let wrong_type = r#"{"temperature":"hot","top_p":0.9,"max_output_tokens":4096,"reasoning_effort":"low"}"#;
        assert!(serde_json::from_str::<ModelParameters>(wrong_type).is_err());

        // Unrepresentable negatives and non-integers are rejected by serde.
        let negative =
            r#"{"temperature":0.2,"top_p":0.9,"max_output_tokens":-1,"reasoning_effort":"low"}"#;
        assert!(serde_json::from_str::<ModelParameters>(negative).is_err());
        let fractional = r#"{"temperature":0.2,"top_p":0.9,"max_output_tokens":4096.5,"reasoning_effort":"low"}"#;
        assert!(serde_json::from_str::<ModelParameters>(fractional).is_err());
    }

    #[test]
    fn escalation_and_decision_fields_are_copied_without_prompt_content() {
        let decision = route_fixture();
        let evidence = FailureEvidence::for_kind(FailureKind::Timeout, "previous-model", 2, 40);
        let context = DecisionContext {
            turn_id: TurnId::new(7),
            session: "s1".to_owned(),
            at_ms: 1_700_000_000_007,
            model_version: "2026-11-01".to_owned(),
            class: Some(WorkClass::Edit),
            role: Some("coder".to_owned()),
            assignment_source: Some("default".to_owned()),
        };
        let record =
            TurnRecord::from_decision(context, &decision, parameters(), &usage(), Some(&evidence))
                .expect("record from decision");

        assert_eq!(record.model, decision.chosen.model);
        assert_eq!(record.provider, decision.chosen.provider);
        assert_eq!(record.router_reason, decision.reason);
        assert_eq!(record.class, Some(WorkClass::Edit));
        assert_eq!(record.role.as_deref(), Some("coder"));
        assert_eq!(record.assignment_source.as_deref(), Some("default"));
        assert_eq!(record.input_tokens, 700);
        assert_eq!(record.output_tokens, 300);
        assert_eq!(record.cache_read_tokens, 40);
        assert_eq!(record.cache_write_tokens, 10);
        assert_eq!(record.actual_cost_micros, 150);
        assert_eq!(
            record.estimated_cost_micros,
            decision.chosen.estimated_cost_micros(1_000)
        );

        let escalation = record.escalation.as_ref().expect("escalation copied");
        assert_eq!(escalation.from_model, "previous-model");
        assert_eq!(escalation.evidence_kind, FailureKind::Timeout);
        assert_eq!(escalation.attempts, 2);

        let value = serde_json::to_value(&record).expect("serialises");
        let escalation_value = value.get("escalation").expect("escalation key");
        let keys: Vec<&str> = escalation_value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&"from_model"));
        assert!(keys.contains(&"evidence_kind"));
        assert!(keys.contains(&"attempts"));
        assert!(escalation_value.get("message_summary").is_none());

        // An escalation with no attempts is refused.
        let mut invalid = record.clone();
        invalid.escalation = Some(EscalationRecord {
            from_model: "x".to_owned(),
            evidence_kind: FailureKind::Failure,
            attempts: 0,
        });
        assert_eq!(
            invalid.validate().expect_err("zero attempts").code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn audit_summary_and_serde_expose_no_prompt_text() {
        let mut record = record("s1", 4).with_class(WorkClass::Edit);
        record.escalation = Some(EscalationRecord::from_evidence(&FailureEvidence::for_kind(
            FailureKind::Refusal,
            "old-model",
            1,
            5,
        )));

        let value = serde_json::to_value(&record).expect("serialises");
        let object = value.as_object().expect("object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "actual_cost_micros",
                "assignment_source",
                "at_ms",
                "cache_read_tokens",
                "cache_write_tokens",
                "class",
                "escalation",
                "estimated_cost_micros",
                "input_tokens",
                "model",
                "model_version",
                "output_tokens",
                "parameters",
                "provider",
                "role",
                "router_reason",
                "session",
                "turn_id",
            ]
        );
        for forbidden in [
            "prompt",
            "response",
            "content",
            "messages",
            "transcript",
            "text",
        ] {
            assert!(
                object.get(forbidden).is_none(),
                "record exposed {forbidden}"
            );
        }
        let debug = format!("{record:?}");
        assert!(!debug.contains("prompt"));
        assert!(!debug.contains("TOP-SECRET"));

        let summary = audit_line(&record);
        assert!(summary.contains("turn 4"));
        assert!(summary.contains("model model-a"));
        assert!(summary.contains("version 2026-11-01"));
        assert!(summary.contains("temperature=0.200"));
        assert!(summary.contains("reason \"cheapest eligible model clears the edit floor\""));
        assert!(summary.contains("actual=150"));
        assert!(summary.contains("escalation from=old-model kind=refusal attempts=1"));
        assert!(!summary.contains("prompt"));

        // A planted prompt-like field is not accepted as a record.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("decisions.jsonl");
        let mut planted = value.clone();
        planted.as_object_mut().expect("object").insert(
            "prompt".to_owned(),
            serde_json::json!("TOP-SECRET-PLACEHOLDER"),
        );
        raw_log(&path, &[&raw_line(&record), &planted.to_string()]);
        let report = DecisionLog::new(&path).read_all().expect("lenient read");
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.malformed, 1);
        let serialized = serde_json::to_string(&report.records).expect("serialises");
        assert!(!serialized.contains("TOP-SECRET"));
        assert!(!format!("{report:?}").contains("TOP-SECRET"));
    }

    #[test]
    fn sequence_gaps_are_reported_and_not_silently_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = DecisionLog::new(dir.path().join("decisions.jsonl"));
        for turn in [1, 2, 5, 6] {
            log.append(&record("s1", turn)).unwrap();
        }
        let audit = reconstruct("s1", &log).expect("clean audit");
        assert_eq!(audit.gaps.len(), 1);
        assert_eq!(
            audit.gaps[0],
            TurnGap {
                after: TurnId::new(2),
                before: TurnId::new(5),
                missing: 2
            }
        );

        // A session that starts mid-sequence does not report a prefix gap.
        log.append(&record("resumed", 9)).unwrap();
        assert!(reconstruct("resumed", &log)
            .expect("clean audit")
            .gaps
            .is_empty());
    }

    #[test]
    fn empty_session_reconstructs_to_no_turns() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = DecisionLog::new(dir.path().join("decisions.jsonl"));
        let audit = reconstruct("anything", &log).expect("a missing log is an empty audit");
        assert!(audit.turns.is_empty());
        assert!(audit.gaps.is_empty());
        assert_eq!(audit.totals, AuditTotals::default());

        log.append(&record("s1", 1)).unwrap();
        let other = reconstruct("s2", &log).expect("other session is empty");
        assert_eq!(other.session, "s2");
        assert!(other.turns.is_empty());
        assert_eq!(other.totals.turns, 0);
        assert_eq!(other.totals.actual_cost_micros, 0);
    }

    #[test]
    fn ledger_comparison_detects_mismatches_and_missing_events() {
        let first = record("s1", 1);
        let mut second = record("s2", 1);
        second.input_tokens = 7;
        second.actual_cost_micros = 9;
        let third = record("s3", 1);

        let matching = LedgerEvent {
            session: "s1".to_owned(),
            turn_id: TurnId::new(1),
            model: first.model.clone(),
            input_tokens: first.input_tokens,
            output_tokens: first.output_tokens,
            cache_read_tokens: first.cache_read_tokens,
            cache_write_tokens: first.cache_write_tokens,
            cost_micros: first.actual_cost_micros,
        };
        let disagreeing = LedgerEvent {
            session: "s2".to_owned(),
            turn_id: TurnId::new(1),
            model: "other-model".to_owned(),
            input_tokens: 999,
            output_tokens: second.output_tokens,
            cache_read_tokens: second.cache_read_tokens,
            cache_write_tokens: second.cache_write_tokens,
            cost_micros: 1,
        };
        let events = vec![matching, disagreeing];

        let mismatches =
            compare_with_ledger(&[first, second, third.clone()], &events).expect("comparison runs");
        assert!(!mismatches.iter().any(
            |mismatch| mismatch.session == "s1" && mismatch.kind == MismatchKind::MissingEvent
        ));
        assert!(mismatches.iter().any(|mismatch| {
            mismatch.session == "s2"
                && mismatch.kind
                    == MismatchKind::Model {
                        recorded: "model-a".to_owned(),
                        ledger: "other-model".to_owned(),
                    }
        }));
        assert!(mismatches.iter().any(|mismatch| {
            mismatch.session == "s2"
                && mismatch.kind
                    == MismatchKind::Tokens {
                        field: "input_tokens".to_owned(),
                        recorded: 7,
                        ledger: 999,
                    }
        }));
        assert!(mismatches.iter().any(|mismatch| {
            mismatch.session == "s2"
                && mismatch.kind
                    == MismatchKind::Cost {
                        recorded: 9,
                        ledger: 1,
                    }
        }));
        assert!(mismatches.iter().any(|mismatch| {
            mismatch.session == "s3"
                && mismatch.turn_id == TurnId::new(1)
                && mismatch.kind == MismatchKind::MissingEvent
        }));

        // Duplicate events for one turn make the comparison ambiguous.
        let duplicate = events[0].clone();
        let error = compare_with_ledger(&[third], &[duplicate.clone(), duplicate])
            .expect_err("duplicate event");
        assert_eq!(error.code(), ErrorCode::AlreadyExists);
    }

    #[test]
    fn verify_turn_checks_model_and_parameters() {
        let turn = record("s1", 1);
        verify_turn(&turn, "model-a", parameters()).expect("matching record");
        assert_eq!(
            verify_turn(&turn, "model-b", parameters())
                .expect_err("model differs")
                .code(),
            ErrorCode::Conflict
        );
        let other = ModelParameters::new(0.1, 0.9, 4096, ReasoningEffort::Low).expect("valid");
        let error = verify_turn(&turn, "model-a", other).expect_err("parameters differ");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert!(
            error.message().contains("parameters"),
            "{}",
            error.message()
        );
        assert_eq!(
            verify_turn(&turn, "", parameters())
                .expect_err("blank model")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn the_log_is_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("decisions.jsonl");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_LOG_BYTES).unwrap();
        drop(file);

        let error = DecisionLog::new(&path)
            .append(&record("s1", 1))
            .expect_err("the bound is enforced");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert!(error.message().contains("rotate"), "{}", error.message());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), MAX_LOG_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn the_log_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("decisions.jsonl");
        let log = DecisionLog::new(&path);
        log.append(&record("s1", 1)).expect("append");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        // An existing file is restricted before the next append.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        log.append(&record("s1", 2)).expect("second append");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn audit_totals_saturate_instead_of_overflowing() {
        let mut first = record("s1", 1);
        first.input_tokens = u64::MAX;
        let mut second = record("s1", 2);
        second.input_tokens = 10;
        let totals = totals_of(&[first, second]);
        assert_eq!(totals.input_tokens, u64::MAX);
        assert_eq!(totals.turns, 2);
    }
}
