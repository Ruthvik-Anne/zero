//! Monitor restart policy (MON-12; T-MON-04).
//!
//! A monitor that was running when a session was paused, teleported, or the
//! daemon restarted is **not** restarted automatically. The journal records what
//! was running; [`plan`] turns that record plus explicit, fresh, per-monitor
//! confirmations into a [`RestartPlan`]; [`apply`] starts only the confirmed
//! decisions and records the new start back into the journal.
//!
//! # Default is skip
//!
//! Every cause ([`ResumeCause::SessionResume`], [`ResumeCause::Teleport`],
//! [`ResumeCause::DaemonRestart`]) uses the same rule: a monitor restarts only
//! when a matching [`RestartRequest`] is explicit (`user_confirmed`), carries a
//! timestamp newer than the record's stop/resume boundary, and is no older than
//! the caller's `max_confirmation_age_ms` bound. Teleport is not special-cased:
//! it never restarts without confirmation.
//!
//! Confirmations are per monitor. A stale confirmation, a confirmation for a
//! different monitor, a confirmation for a different cause, a confirmation with
//! no timestamp, and a confirmation that predates the boundary are all skipped
//! with a reason recorded in [`RestartPlan::skipped`].
//!
//! # Failed monitors
//!
//! A record whose status is [`MonitorStatus::Failed`] is never a restart
//! candidate, even with a confirmation. Retrying a failed child is an explicit
//! `start`, not a resume. A start that fails during [`apply`] is reported in
//! [`RestartReport::failed`] and is not retried.
//!
//! # Type separation (MON-11)
//!
//! A background task, an MCP task, and an MCP event are distinct sources. They
//! never appear in a restart plan: [`MonitorRecord`] carries a [`MonitorKind`],
//! [`MonitorJournal`] rejects a non-monitor record on load/save with
//! `ConfigInvalid`, and [`plan`] drops such records before making any decision.
//!
//! # Security
//!
//! [`apply`] takes already-built [`MonitorSpec`] values, not raw commands, and
//! never widens a policy. The caller expands an admitted definition with
//! `MonitorDefinition::to_spec` under its [`crate::monitor_defs::MonitorPolicy`],
//! exactly as for a first start; a restart is a resume of an already-admitted
//! monitor, not a new admission.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::monitor::{MonitorEngine, MonitorHandle, MonitorSpec, MonitorStatus};
use crate::monitor_defs::MonitorRefusal;

/// Schema version understood by [`MonitorJournal::load`].
pub const MONITOR_JOURNAL_SCHEMA_VERSION: u32 = 1;
/// Default bound on the number of records kept by one journal. The oldest
/// records are dropped first.
pub const DEFAULT_JOURNAL_MAX_RECORDS: usize = 128;

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------

/// What a journal record describes (MON-11).
///
/// Only [`MonitorKind::Monitor`] belongs in a monitor journal. The other
/// variants exist so a caller that mixes sources by accident is refused with a
/// typed error instead of being silently treated as a monitor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorKind {
    #[default]
    Monitor,
    BackgroundTask,
    McpTask,
    McpEvent,
}

impl MonitorKind {
    /// True for the only kind a monitor journal may contain.
    pub fn is_monitor(self) -> bool {
        self == Self::Monitor
    }

    /// Stable snake-case name used in journal documents and error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monitor => "monitor",
            Self::BackgroundTask => "background_task",
            Self::McpTask => "mcp_task",
            Self::McpEvent => "mcp_event",
        }
    }
}

/// One monitor's last known state.
///
/// `was_running` means the monitor was live when the record was written, so it
/// is a restart candidate at all. `stopped_by_user` is a permanent veto: a
/// monitor the user stopped is never restarted, by any cause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorRecord {
    /// Source kind. Only [`MonitorKind::Monitor`] is valid in this journal.
    #[serde(default)]
    pub kind: MonitorKind,
    pub name: String,
    pub status: MonitorStatus,
    pub was_running: bool,
    pub stopped_by_user: bool,
    pub started_at_ms: i64,
    #[serde(default)]
    pub stopped_at_ms: Option<i64>,
    pub session_id: String,
}

impl MonitorRecord {
    /// The stop/resume boundary: an explicit stop when one was recorded,
    /// otherwise the start. A confirmation must be strictly newer than this.
    pub fn boundary_ms(&self) -> i64 {
        self.stopped_at_ms.unwrap_or(self.started_at_ms)
    }
}

/// The on-disk monitor journal.
///
/// Records are bounded by [`DEFAULT_JOURNAL_MAX_RECORDS`]; the oldest records
/// are dropped first. [`MonitorJournal::save`] writes a sibling temporary file,
/// syncs it, and renames it over the journal so a crash never leaves a partial
/// document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorJournal {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub records: Vec<MonitorRecord>,
}

fn default_schema_version() -> u32 {
    MONITOR_JOURNAL_SCHEMA_VERSION
}

impl Default for MonitorJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorJournal {
    pub fn new() -> Self {
        Self { schema_version: MONITOR_JOURNAL_SCHEMA_VERSION, records: Vec::new() }
    }

    pub fn records(&self) -> &[MonitorRecord] {
        &self.records
    }

    /// The record for `name`, ignoring ASCII case.
    pub fn record_for(&self, name: &str) -> Option<&MonitorRecord> {
        self.records.iter().find(|record| record.name.eq_ignore_ascii_case(name))
    }

    /// Read a journal from `path`.
    ///
    /// A missing file is an empty journal, not an error. Malformed JSON is
    /// `Serialization`; an unsupported `schema_version` is `SchemaVersion`; a
    /// record with a non-monitor kind, an empty name, or a duplicate name is
    /// `ConfigInvalid`. A valid journal over the count bound is trimmed to its
    /// newest records.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(error) => return Err(error.into()),
        };
        let mut journal: Self = serde_json::from_str(&text).map_err(|error| {
            ZeroError::new(
                ErrorCode::Serialization,
                format!("monitor journal `{}` is not valid JSON: {error}", path.display()),
            )
        })?;
        if journal.schema_version != MONITOR_JOURNAL_SCHEMA_VERSION {
            return Err(ZeroError::new(
                ErrorCode::SchemaVersion,
                format!(
                    "monitor journal schema version {} is not supported; expected {}",
                    journal.schema_version, MONITOR_JOURNAL_SCHEMA_VERSION
                ),
            ));
        }
        journal.validate()?;
        journal.enforce_bound();
        Ok(journal)
    }

    /// Replace the journal atomically.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let mut snapshot = self.clone();
        snapshot.validate()?;
        snapshot.enforce_bound();
        let bytes = serde_json::to_vec_pretty(&snapshot)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let temp = path.with_extension("json.tmp");
        {
            let mut file = std::fs::File::create(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        if let Err(error) = std::fs::rename(&temp, path) {
            let _ = std::fs::remove_file(&temp);
            return Err(error.into());
        }
        Ok(())
    }

    /// Check that every record is a monitor with a unique, non-empty name.
    pub fn validate(&self) -> Result<()> {
        let mut names = BTreeSet::new();
        for record in &self.records {
            if !record.kind.is_monitor() {
                return Err(ZeroError::new(
                    ErrorCode::ConfigInvalid,
                    format!(
                        "monitor journal record `{}` has kind `{}`; only monitors belong here (MON-11)",
                        record.name,
                        record.kind.as_str()
                    ),
                ));
            }
            if record.name.trim().is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::ConfigInvalid,
                    "monitor journal contains a record with an empty name",
                ));
            }
            if !names.insert(record.name.to_ascii_lowercase()) {
                return Err(ZeroError::new(
                    ErrorCode::ConfigInvalid,
                    format!(
                        "monitor journal contains `{}` more than once (names ignore case)",
                        record.name
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Record a start: the monitor is running and is a restart candidate.
    pub fn record_start(&mut self, name: &str, session_id: &str, started_at_ms: i64) {
        let record = self.entry(name, started_at_ms);
        record.status = MonitorStatus::Running;
        record.was_running = true;
        record.stopped_by_user = false;
        record.started_at_ms = started_at_ms;
        record.stopped_at_ms = None;
        record.session_id = session_id.to_string();
        self.enforce_bound();
    }

    /// Record a user stop. This is the permanent veto: the monitor is not a
    /// restart candidate, by any cause.
    pub fn record_stop(&mut self, name: &str, stopped_at_ms: i64) {
        let record = self.entry(name, stopped_at_ms);
        record.status = MonitorStatus::Stopped;
        record.was_running = false;
        record.stopped_by_user = true;
        record.stopped_at_ms = Some(stopped_at_ms);
        self.enforce_bound();
    }

    /// Record a session boundary (MON-08): the monitor was running but the
    /// session closed it. The next resume may *offer* a restart, but only a
    /// fresh confirmation from the user turns that offer into a start.
    pub fn record_session_stop(&mut self, name: &str, stopped_at_ms: i64) {
        let record = self.entry(name, stopped_at_ms);
        record.status = MonitorStatus::Stopped;
        record.was_running = true;
        record.stopped_by_user = false;
        record.stopped_at_ms = Some(stopped_at_ms);
        self.enforce_bound();
    }

    /// Record a natural exit or a failure. Neither is a restart candidate.
    pub fn record_exit(&mut self, name: &str, status: MonitorStatus, stopped_at_ms: i64) {
        let record = self.entry(name, stopped_at_ms);
        record.status = status;
        record.was_running = false;
        record.stopped_by_user = false;
        record.stopped_at_ms = Some(stopped_at_ms);
        self.enforce_bound();
    }

    /// Drop the oldest records until the count bound is met.
    pub fn enforce_bound(&mut self) {
        if self.records.len() > DEFAULT_JOURNAL_MAX_RECORDS {
            let excess = self.records.len() - DEFAULT_JOURNAL_MAX_RECORDS;
            self.records.drain(0..excess);
        }
    }

    fn entry(&mut self, name: &str, at_ms: i64) -> &mut MonitorRecord {
        if let Some(index) =
            self.records.iter().position(|record| record.name.eq_ignore_ascii_case(name))
        {
            return &mut self.records[index];
        }
        self.records.push(MonitorRecord {
            kind: MonitorKind::Monitor,
            name: name.to_string(),
            status: MonitorStatus::Stopped,
            was_running: false,
            stopped_by_user: false,
            started_at_ms: at_ms,
            stopped_at_ms: None,
            session_id: String::new(),
        });
        let index = self.records.len() - 1;
        &mut self.records[index]
    }
}

// ---------------------------------------------------------------------------
// Restart policy
// ---------------------------------------------------------------------------

/// Why a monitor is being considered for a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeCause {
    /// A session resumed (`zero resume`).
    SessionResume,
    /// A session moved to another device or daemon (MON-12).
    Teleport,
    /// The daemon itself restarted.
    DaemonRestart,
}

impl ResumeCause {
    /// True when this cause may restart a monitor without an explicit
    /// confirmation. Always false: no cause implicitly restarts (MON-12).
    pub fn restarts_implicitly(self) -> bool {
        false
    }
}

/// One explicit, per-monitor confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartRequest {
    pub monitor: String,
    pub cause: ResumeCause,
    pub user_confirmed: bool,
    pub confirmation_at_ms: Option<i64>,
}

impl RestartRequest {
    /// A confirmed request for `monitor` at `confirmation_at_ms`.
    pub fn confirmed(monitor: impl Into<String>, cause: ResumeCause, confirmation_at_ms: i64) -> Self {
        Self {
            monitor: monitor.into(),
            cause,
            user_confirmed: true,
            confirmation_at_ms: Some(confirmation_at_ms),
        }
    }
}

/// What to do with one monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartDecision {
    Restart,
    Skip { reason: String },
}

/// The plan for one resume/teleport/daemon-restart event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestartPlan {
    /// One decision per monitor record, in journal order.
    pub decisions: Vec<(String, RestartDecision)>,
    /// Names that will be started, in order.
    pub to_restart: Vec<String>,
    /// Names that will not be started, with a reason.
    pub skipped: Vec<(String, String)>,
}

impl RestartPlan {
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }

    /// The decision recorded for `name`, ignoring ASCII case.
    pub fn decision(&self, name: &str) -> Option<&RestartDecision> {
        self.decisions
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, decision)| decision)
    }

    fn skip(&mut self, name: &str, reason: &str) {
        self.decisions
            .push((name.to_string(), RestartDecision::Skip { reason: reason.to_string() }));
        self.skipped.push((name.to_string(), reason.to_string()));
    }
}

/// Decide what to restart.
///
/// Only a record that was running, is not user-stopped, is not `Failed`, and has
/// a matching fresh explicit confirmation becomes [`RestartDecision::Restart`].
/// Everything else is a [`RestartDecision::Skip`] with a reason. Records with a
/// non-monitor kind are dropped before any decision is made (MON-11).
pub fn plan(
    records: &[MonitorRecord],
    cause: ResumeCause,
    confirmations: &[RestartRequest],
    now_ms: i64,
    max_confirmation_age_ms: i64,
) -> RestartPlan {
    let max_age = max_confirmation_age_ms.max(0);
    let mut plan = RestartPlan::default();
    let mut seen = BTreeSet::new();
    for record in records {
        if !record.kind.is_monitor() {
            // Not a monitor: never in the plan, not even as a skip (MON-11).
            continue;
        }
        if !seen.insert(record.name.to_ascii_lowercase()) {
            plan.skip(&record.name, "duplicate journal record");
            continue;
        }
        if !record.was_running {
            plan.skip(&record.name, "monitor was not running when the journal was written");
            continue;
        }
        if record.stopped_by_user {
            plan.skip(&record.name, "monitor was stopped by the user");
            continue;
        }
        match record.status {
            MonitorStatus::Running | MonitorStatus::Starting | MonitorStatus::Stopped => {}
            MonitorStatus::Failed => {
                plan.skip(&record.name, "monitor failed; a failed monitor needs an explicit start");
                continue;
            }
        }

        let boundary = record.boundary_ms();
        let mut reasons = Vec::new();
        let mut confirmed = false;
        for confirmation in
            confirmations.iter().filter(|request| request.monitor.eq_ignore_ascii_case(&record.name))
        {
            match confirmation_failure(confirmation, cause, boundary, now_ms, max_age) {
                Some(reason) => reasons.push(reason),
                None => {
                    confirmed = true;
                    break;
                }
            }
        }
        if confirmed {
            plan.decisions.push((record.name.clone(), RestartDecision::Restart));
            plan.to_restart.push(record.name.clone());
        } else {
            let reason = reasons.pop().unwrap_or("no confirmation");
            plan.skip(&record.name, reason);
        }
    }
    plan
}

/// Why a confirmation does not authorise a restart, or `None` when it does.
fn confirmation_failure(
    confirmation: &RestartRequest,
    cause: ResumeCause,
    boundary_ms: i64,
    now_ms: i64,
    max_age_ms: i64,
) -> Option<&'static str> {
    if !confirmation.user_confirmed {
        return Some("confirmation was not explicit");
    }
    if confirmation.cause != cause {
        return Some("confirmation was given for a different cause");
    }
    let Some(at_ms) = confirmation.confirmation_at_ms else {
        return Some("confirmation has no timestamp");
    };
    if at_ms > now_ms {
        return Some("confirmation is newer than now");
    }
    if now_ms.saturating_sub(at_ms) > max_age_ms {
        return Some("confirmation is stale");
    }
    if at_ms <= boundary_ms {
        return Some("confirmation predates the stop/resume boundary");
    }
    None
}

/// What [`apply`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestartReport {
    pub restarted: Vec<MonitorHandle>,
    /// Decisions that were not started, with their reasons; a copy of
    /// [`RestartPlan::skipped`].
    pub skipped: Vec<(String, String)>,
    /// Confirmed starts that failed. They are reported once and never retried.
    pub failed: Vec<MonitorRefusal>,
}

impl RestartReport {
    pub fn is_empty(&self) -> bool {
        self.restarted.is_empty() && self.skipped.is_empty() && self.failed.is_empty()
    }
}

/// Start the confirmed decisions in `plan`.
///
/// `definitions` are the already-admitted specs for the monitors that may be
/// restarted; expand a definition with `MonitorDefinition::to_spec` under your
/// policy so a restart never widens what was allowed. A name the engine still
/// retains after an exit is forgotten only here, as part of an explicit,
/// confirmed restart; a live monitor is reported as `AlreadyExists` instead of
/// being started twice. Each successful start is written back to `journal` with
/// the record's `session_id`, so the next resume sees the monitor as running.
pub fn apply(
    plan: &RestartPlan,
    engine: &mut MonitorEngine,
    definitions: &[MonitorSpec],
    journal: &mut MonitorJournal,
    now_ms: i64,
) -> Result<RestartReport> {
    let mut report = RestartReport {
        restarted: Vec::new(),
        skipped: plan.skipped.clone(),
        failed: Vec::new(),
    };
    let mut attempted = BTreeSet::new();
    for (name, decision) in &plan.decisions {
        if !matches!(decision, RestartDecision::Restart) {
            continue;
        }
        if !attempted.insert(name.to_ascii_lowercase()) {
            continue;
        }
        let Some(spec) = definitions.iter().find(|spec| spec.id.eq_ignore_ascii_case(name)) else {
            report.failed.push(MonitorRefusal {
                name: name.clone(),
                code: ErrorCode::NotFound,
                message: format!("no monitor spec named `{name}` for a confirmed restart"),
            });
            continue;
        };
        if let Some(status) = engine.status(&spec.id) {
            match status {
                MonitorStatus::Running | MonitorStatus::Starting => {
                    report.failed.push(MonitorRefusal {
                        name: spec.id.clone(),
                        code: ErrorCode::AlreadyExists,
                        message: format!(
                            "monitor `{}` is already {status:?}; a confirmed restart does not spawn it twice",
                            spec.id
                        ),
                    });
                    continue;
                }
                MonitorStatus::Stopped | MonitorStatus::Failed => {
                    if let Err(error) = engine.forget(&spec.id) {
                        report.failed.push(MonitorRefusal::from_error(&spec.id, &error));
                        continue;
                    }
                }
            }
        }
        match engine.start(spec.clone(), now_ms) {
            Ok(handle) => {
                let session_id = journal
                    .record_for(&spec.id)
                    .map(|record| record.session_id.clone())
                    .unwrap_or_default();
                journal.record_start(&spec.id, &session_id, now_ms);
                report.restarted.push(handle);
            }
            Err(error) => report.failed.push(MonitorRefusal::from_error(&spec.id, &error)),
        }
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::monitor::BurstWindow;

    const HELPER_LINE: &str = "RESTART-T-MON-04 ok";

    // ----- child side -----------------------------------------------------

    /// Child side of the [`apply`] tests. The parent spawns this test binary
    /// with `--exact` pointing at this test, so a normal `cargo test` run
    /// (which does not pass `--exact`) is a no-op.
    #[test]
    fn monitor_restart_helper_process() {
        if !std::env::args().any(|arg| arg == "--exact") {
            return;
        }
        use std::io::Write;
        let mut stdout = std::io::stdout();
        let _ = writeln!(stdout);
        let _ = writeln!(stdout, "{HELPER_LINE}");
        let _ = stdout.flush();
        std::thread::sleep(Duration::from_millis(200));
    }

    // ----- helpers --------------------------------------------------------

    fn record(name: &str) -> MonitorRecord {
        MonitorRecord {
            kind: MonitorKind::Monitor,
            name: name.to_string(),
            status: MonitorStatus::Running,
            was_running: true,
            stopped_by_user: false,
            started_at_ms: 100,
            stopped_at_ms: None,
            session_id: "session-1".to_string(),
        }
    }

    fn confirmed(monitor: &str, cause: ResumeCause, at_ms: i64) -> RestartRequest {
        RestartRequest::confirmed(monitor, cause, at_ms)
    }

    fn spec_for_helper(name: &str) -> MonitorSpec {
        let exe = std::env::current_exe().expect("current test executable");
        let args = [
            "--exact",
            "monitor_restart::tests::monitor_restart_helper_process",
            "--nocapture",
            "--test-threads=1",
        ];
        MonitorSpec::new(name, name, exe.to_string_lossy().into_owned()).args(args)
    }

    fn engine() -> MonitorEngine {
        MonitorEngine::new().with_window(BurstWindow::new(64, 1 << 20, 20))
    }

    // ----- journal --------------------------------------------------------

    #[test]
    fn journal_round_trips_atomically() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("monitors.json");
        let mut journal = MonitorJournal::new();
        journal.record_start("alpha", "session-1", 10);
        journal.record_start("beta", "session-2", 20);
        journal.record_stop("beta", 30);

        journal.save(&path).expect("save");
        assert!(path.exists());
        assert!(!dir.path().join("monitors.json.tmp").exists(), "the temporary file is renamed, not left behind");

        let loaded = MonitorJournal::load(&path).expect("load");
        assert_eq!(loaded.schema_version, MONITOR_JOURNAL_SCHEMA_VERSION);
        assert_eq!(loaded.records().len(), 2);
        assert_eq!(loaded, journal);
        let beta = loaded.record_for("BETA").expect("case-insensitive lookup");
        assert_eq!(beta.status, MonitorStatus::Stopped);
        assert!(beta.stopped_by_user);
        assert_eq!(beta.stopped_at_ms, Some(30));
        assert_eq!(beta.boundary_ms(), 30);

        let alpha = loaded.record_for("alpha").expect("alpha");
        assert!(alpha.was_running);
        assert!(!alpha.stopped_by_user);
        assert_eq!(alpha.boundary_ms(), 10);
    }

    #[test]
    fn journal_missing_file_loads_as_empty() {
        let dir = tempfile::tempdir().expect("temp dir");
        let journal = MonitorJournal::load(dir.path().join("missing.json")).expect("missing is empty");
        assert!(journal.records().is_empty());
        assert_eq!(journal.schema_version, MONITOR_JOURNAL_SCHEMA_VERSION);
    }

    #[test]
    fn journal_trims_to_its_bound() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("journal.json");
        let mut journal = MonitorJournal::new();
        for index in 0..(DEFAULT_JOURNAL_MAX_RECORDS + 2) {
            journal.record_start(&format!("m{index}"), "session-1", index as i64);
        }
        assert_eq!(journal.records().len(), DEFAULT_JOURNAL_MAX_RECORDS);
        assert!(journal.record_for("m0").is_none(), "the oldest record is dropped");
        assert!(journal.record_for("m1").is_none(), "the oldest record is dropped");
        let newest = format!("m{}", DEFAULT_JOURNAL_MAX_RECORDS + 1);
        assert!(journal.record_for(&newest).is_some());

        journal.save(&path).expect("save");
        let loaded = MonitorJournal::load(&path).expect("load");
        assert_eq!(loaded.records().len(), DEFAULT_JOURNAL_MAX_RECORDS);
        assert!(loaded.record_for(&newest).is_some());
    }

    #[test]
    fn journal_rejects_corrupt_unsupported_and_non_monitor_records() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("journal.json");

        std::fs::write(&path, "{ not json").expect("write");
        let error = MonitorJournal::load(&path).expect_err("corrupt json");
        assert_eq!(error.code(), ErrorCode::Serialization);

        std::fs::write(&path, r#"{"schema_version":2,"records":[]}"#).expect("write");
        let error = MonitorJournal::load(&path).expect_err("future schema");
        assert_eq!(error.code(), ErrorCode::SchemaVersion);

        let text = serde_json::json!({
            "schema_version": MONITOR_JOURNAL_SCHEMA_VERSION,
            "records": [{
                "kind": "mcp_task",
                "name": "not-a-monitor",
                "status": "running",
                "was_running": true,
                "stopped_by_user": false,
                "started_at_ms": 1,
                "session_id": "s",
            }],
        })
        .to_string();
        std::fs::write(&path, text).expect("write");
        let error = MonitorJournal::load(&path).expect_err("mcp task in a monitor journal");
        assert_eq!(error.code(), ErrorCode::ConfigInvalid);
        assert!(error.message().contains("mcp_task"), "{}", error.message());

        let mut journal = MonitorJournal::new();
        let mut mcp = record("mcp");
        mcp.kind = MonitorKind::McpTask;
        journal.records.push(mcp);
        let error = journal.save(dir.path().join("other.json")).expect_err("save refuses");
        assert_eq!(error.code(), ErrorCode::ConfigInvalid);
    }

    // ----- plan -----------------------------------------------------------

    #[test]
    fn running_monitor_without_a_confirmation_is_skipped() {
        let records = vec![record("watch")];
        let plan = plan(&records, ResumeCause::SessionResume, &[], 1_000, 60_000);
        assert!(plan.to_restart.is_empty(), "{plan:?}");
        assert_eq!(
            plan.skipped,
            vec![("watch".to_string(), "no confirmation".to_string())],
            "the default is skip"
        );
        assert_eq!(
            plan.decision("watch"),
            Some(&RestartDecision::Skip { reason: "no confirmation".to_string() })
        );
    }

    #[test]
    fn a_fresh_confirmation_restarts_exactly_that_monitor() {
        let records = vec![record("alpha"), record("beta")];
        let confirmations = vec![confirmed("alpha", ResumeCause::SessionResume, 900)];
        let plan = plan(&records, ResumeCause::SessionResume, &confirmations, 1_000, 60_000);
        assert_eq!(plan.to_restart, vec!["alpha".to_string()]);
        assert_eq!(
            plan.decision("beta"),
            Some(&RestartDecision::Skip { reason: "no confirmation".to_string() })
        );
        assert_eq!(plan.decisions.len(), 2);
    }

    #[test]
    fn stale_wrong_monitor_and_out_of_order_confirmations_are_skipped() {
        let mut stale = record("stale");
        stale.started_at_ms = 0;
        let mut early = record("early");
        early.started_at_ms = 900;
        let records = vec![stale, early, record("future"), record("fresh")];
        let confirmations = vec![
            // Older than the age bound.
            confirmed("stale", ResumeCause::Teleport, 100),
            // Newer than now.
            confirmed("future", ResumeCause::Teleport, 5_000),
            // Fresh, but older than the record's start boundary.
            confirmed("early", ResumeCause::Teleport, 850),
            // Fresh and after the boundary.
            confirmed("fresh", ResumeCause::Teleport, 950),
            // Not a monitor in this journal.
            confirmed("ghost", ResumeCause::Teleport, 990),
        ];
        let plan = plan(&records, ResumeCause::Teleport, &confirmations, 1_000, 500);
        assert_eq!(plan.to_restart, vec!["fresh".to_string()]);
        assert_eq!(
            plan.decision("stale"),
            Some(&RestartDecision::Skip { reason: "confirmation is stale".to_string() })
        );
        assert_eq!(
            plan.decision("future"),
            Some(&RestartDecision::Skip {
                reason: "confirmation is newer than now".to_string()
            })
        );
        assert_eq!(
            plan.decision("early"),
            Some(&RestartDecision::Skip {
                reason: "confirmation predates the stop/resume boundary".to_string()
            })
        );
        assert_eq!(
            plan.decision("ghost"),
            None,
            "a confirmation without a monitor record is not a monitor"
        );
    }

    #[test]
    fn a_confirmation_for_another_cause_is_skipped() {
        let records = vec![record("watch")];
        let confirmations = vec![confirmed("watch", ResumeCause::SessionResume, 900)];
        let plan = plan(&records, ResumeCause::Teleport, &confirmations, 1_000, 60_000);
        assert!(plan.to_restart.is_empty());
        assert_eq!(
            plan.decision("watch"),
            Some(&RestartDecision::Skip {
                reason: "confirmation was given for a different cause".to_string()
            })
        );
    }

    #[test]
    fn a_user_stop_is_never_restarted() {
        let mut stopped = record("stopped");
        stopped.status = MonitorStatus::Stopped;
        stopped.stopped_by_user = true;
        stopped.stopped_at_ms = Some(100);
        let records = vec![stopped];
        let confirmations = vec![confirmed("stopped", ResumeCause::SessionResume, 900)];
        let plan = plan(&records, ResumeCause::SessionResume, &confirmations, 1_000, 60_000);
        assert!(plan.to_restart.is_empty(), "a user stop outranks a confirmation");
        assert_eq!(
            plan.decision("stopped"),
            Some(&RestartDecision::Skip {
                reason: "monitor was stopped by the user".to_string()
            })
        );
    }

    #[test]
    fn a_failed_monitor_is_not_restarted_even_with_a_confirmation() {
        let mut failed = record("failed");
        failed.status = MonitorStatus::Failed;
        let records = vec![failed];
        let confirmations = vec![confirmed("failed", ResumeCause::DaemonRestart, 900)];
        let plan = plan(&records, ResumeCause::DaemonRestart, &confirmations, 1_000, 60_000);
        assert!(plan.to_restart.is_empty());
        assert_eq!(
            plan.decision("failed"),
            Some(&RestartDecision::Skip {
                reason: "monitor failed; a failed monitor needs an explicit start".to_string()
            })
        );
    }

    #[test]
    fn a_monitor_that_was_not_running_is_not_a_candidate() {
        let mut stopped = record("exited");
        stopped.was_running = false;
        stopped.status = MonitorStatus::Stopped;
        stopped.stopped_at_ms = Some(100);
        let records = vec![stopped];
        let confirmations = vec![confirmed("exited", ResumeCause::SessionResume, 900)];
        let plan = plan(&records, ResumeCause::SessionResume, &confirmations, 1_000, 60_000);
        assert!(plan.to_restart.is_empty());
        assert_eq!(
            plan.decision("exited"),
            Some(&RestartDecision::Skip {
                reason: "monitor was not running when the journal was written".to_string()
            })
        );
    }

    #[test]
    fn teleport_follows_the_same_confirmation_rule() {
        let records = vec![record("watch")];
        let unconfirmed = plan(&records, ResumeCause::Teleport, &[], 1_000, 60_000);
        assert!(unconfirmed.to_restart.is_empty(), "teleport never restarts implicitly");
        assert_eq!(
            unconfirmed.decision("watch"),
            Some(&RestartDecision::Skip { reason: "no confirmation".to_string() })
        );

        let confirmations = vec![confirmed("watch", ResumeCause::Teleport, 900)];
        let confirmed_plan = plan(&records, ResumeCause::Teleport, &confirmations, 1_000, 60_000);
        assert_eq!(confirmed_plan.to_restart, vec!["watch".to_string()]);
        assert!(!ResumeCause::Teleport.restarts_implicitly());
        assert!(!ResumeCause::SessionResume.restarts_implicitly());
        assert!(!ResumeCause::DaemonRestart.restarts_implicitly());
    }

    #[test]
    fn non_monitor_kinds_never_appear_in_a_plan() {
        let mut mcp_task = record("mcp-task");
        mcp_task.kind = MonitorKind::McpTask;
        let mut mcp_event = record("mcp-event");
        mcp_event.kind = MonitorKind::McpEvent;
        let records = vec![mcp_task, mcp_event, record("real")];
        let confirmations = vec![
            confirmed("mcp-task", ResumeCause::Teleport, 900),
            confirmed("mcp-event", ResumeCause::Teleport, 900),
            confirmed("real", ResumeCause::Teleport, 900),
        ];
        let plan = plan(&records, ResumeCause::Teleport, &confirmations, 1_000, 60_000);
        assert_eq!(plan.to_restart, vec!["real".to_string()]);
        assert!(plan.decisions.iter().all(|(name, _)| name == "real"), "{plan:?}");
        assert!(plan.skipped.is_empty(), "non-monitors are dropped, not reported as skipped");
    }

    // ----- apply (the Done criterion) ------------------------------------

    #[test]
    fn apply_starts_only_confirmed_monitors_and_journals() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("journal.json");
        let mut journal = MonitorJournal::new();
        journal.record_start("alpha", "session-1", 50);
        journal.record_session_stop("alpha", 100);
        journal.record_start("beta", "session-2", 50);
        journal.record_session_stop("beta", 100);
        journal.save(&path).expect("save");

        let mut loaded = MonitorJournal::load(&path).expect("load");
        let confirmations = vec![confirmed("alpha", ResumeCause::Teleport, 900)];
        let plan = plan(loaded.records(), ResumeCause::Teleport, &confirmations, 1_000, 60_000);
        assert_eq!(plan.to_restart, vec!["alpha".to_string()]);

        let definitions = vec![spec_for_helper("alpha"), spec_for_helper("beta")];
        let mut engine = engine();
        let report = apply(&plan, &mut engine, &definitions, &mut loaded, 1_000).expect("apply");
        assert_eq!(report.restarted.len(), 1, "{report:?}");
        assert_eq!(report.restarted[0].id, "alpha");
        assert_eq!(report.skipped, vec![("beta".to_string(), "no confirmation".to_string())]);
        assert!(report.failed.is_empty(), "{report:?}");
        assert_eq!(engine.ids(), vec!["alpha"]);

        let alpha = loaded.record_for("alpha").expect("alpha record");
        assert_eq!(alpha.status, MonitorStatus::Running);
        assert!(alpha.was_running);
        assert!(!alpha.stopped_by_user);
        assert_eq!(alpha.started_at_ms, 1_000);
        assert_eq!(alpha.stopped_at_ms, None);
        assert_eq!(alpha.session_id, "session-1", "the session is carried across the restart");
        assert_eq!(loaded.record_for("beta").expect("beta").status, MonitorStatus::Stopped);

        loaded.save(&path).expect("save after restart");
        let reloaded = MonitorJournal::load(&path).expect("reload");
        assert_eq!(reloaded.record_for("alpha").expect("alpha").status, MonitorStatus::Running);

        engine.stop("alpha", 1_100).expect("stop");
    }

    #[test]
    fn two_monitors_with_one_confirmation_restart_only_one() {
        let mut journal = MonitorJournal::new();
        journal.record_session_stop("first", 100);
        journal.record_session_stop("second", 100);
        let confirmations = vec![confirmed("second", ResumeCause::SessionResume, 900)];
        let plan = plan(journal.records(), ResumeCause::SessionResume, &confirmations, 1_000, 60_000);
        assert_eq!(plan.to_restart, vec!["second".to_string()]);
        assert_eq!(
            plan.decision("first"),
            Some(&RestartDecision::Skip { reason: "no confirmation".to_string() })
        );

        let definitions = vec![spec_for_helper("first"), spec_for_helper("second")];
        let mut engine = engine();
        let report = apply(&plan, &mut engine, &definitions, &mut journal, 1_000).expect("apply");
        assert_eq!(report.restarted.len(), 1);
        assert_eq!(engine.ids(), vec!["second"], "a monitor does not silently restart");
        engine.stop("second", 1_100).expect("stop");
    }

    #[test]
    fn a_failed_start_is_reported_and_not_retried() {
        let mut journal = MonitorJournal::new();
        journal.record_session_stop("ghost", 0);
        let confirmations = vec![confirmed("ghost", ResumeCause::DaemonRestart, 900)];
        let plan = plan(journal.records(), ResumeCause::DaemonRestart, &confirmations, 1_000, 60_000);
        assert_eq!(plan.to_restart, vec!["ghost".to_string()]);

        let definitions =
            vec![MonitorSpec::new("ghost", "ghost", "zero-missing-binary-t-mon-04")];
        let mut engine = engine();
        let report = apply(&plan, &mut engine, &definitions, &mut journal, 1_000).expect("apply");
        assert!(report.restarted.is_empty());
        assert_eq!(report.failed.len(), 1, "{report:?}");
        assert_eq!(report.failed[0].code, ErrorCode::Unavailable);
        assert_eq!(engine.ids().len(), 0);
        assert_eq!(journal.record_for("ghost").expect("ghost").status, MonitorStatus::Stopped);
        assert_eq!(
            journal.record_for("ghost").expect("ghost").started_at_ms,
            0,
            "a failed start is not journaled as running"
        );
    }

    #[test]
    fn apply_does_not_start_a_live_monitor_twice() {
        let mut journal = MonitorJournal::new();
        journal.record_session_stop("alpha", 100);
        let confirmations = vec![confirmed("alpha", ResumeCause::SessionResume, 900)];
        let plan = plan(journal.records(), ResumeCause::SessionResume, &confirmations, 1_000, 60_000);

        let definitions = vec![spec_for_helper("alpha")];
        let mut engine = engine();
        engine.start(spec_for_helper("alpha"), 500).expect("first start");
        let report = apply(&plan, &mut engine, &definitions, &mut journal, 1_000).expect("apply");
        assert!(report.restarted.is_empty());
        assert_eq!(report.failed.len(), 1, "{report:?}");
        assert_eq!(report.failed[0].code, ErrorCode::AlreadyExists);
        assert_eq!(engine.ids(), vec!["alpha"], "still exactly one instance");
        engine.stop("alpha", 1_100).expect("stop");
    }
}
