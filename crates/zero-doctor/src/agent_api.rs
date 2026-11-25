//! Agent-facing doctor API (DOC-06, DOC-08).
//!
//! This module turns the doctor core, its playbooks, and the repair engine into
//! three host tools an agent can call, plus a gate the host runs before the
//! agent is allowed to finish a turn:
//!
//! - [`diagnose`] wraps [`crate::run_core_with`]: no daemon socket, no network,
//!   and no mutation.
//! - [`plan`] maps *failing* checks to the small set of repairs that are known
//!   to be safe. A check with no safe repair is refused by name instead of
//!   guessed at, and a deletion is never planned without
//!   [`RepairPolicy::allow_delete`].
//! - [`apply`] delegates to [`crate::repair::apply`], so a plan marked
//!   `dry_run` is refused before anything is written and a real apply keeps the
//!   snapshot/rollback guarantees.
//! - [`finish_turn`] makes hiding a failing check impossible: every check the
//!   report marks `fail` must appear in the agent's [`TurnReport`], either as
//!   unresolved (with the mapped playbook code and a redaction-safe summary) or
//!   as resolved backed by an applied action. Otherwise the host gets
//!   `zero.pol.ask`/`zero.pol.denied` naming the hidden check.
//!
//! The gate is deliberately structural rather than advisory: it checks the
//! report's 13-check shape, the mapping from check to [`ErrorCode`], and the
//! canonical action strings produced by [`TurnReport::record_applied`]. It reads
//! nothing from the environment, so it works with the daemon, kernel, and mesh
//! dead.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use zero_types::{ErrorCode, Result as ZeroResult, ZeroError};

use crate::repair::{
    self, RepairAction, RepairActionKind, RepairError, RepairPlan, RepairPolicy, RepairPreview,
    RepairReport, MAX_PLAN_ACTIONS,
};
use crate::{
    run_core_with, CheckResult, CheckStatus, DoctorContext, DoctorReport, LockEntry, CHECK_NAMES,
};

/// Stable plan id used by [`plan`]. Deterministic so a repeated plan is easy to
/// recognise in a report.
pub const PLAN_ID: &str = "agent-repair";

/// Longest unresolved-failure summary the gate accepts.
pub const MAX_SUMMARY_CHARS: usize = 512;

/// Which statuses the turn gate treats as failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GateOptions {
    /// Also require `warn` checks to be reported. Off by default: only `fail`
    /// blocks a turn unless the host asks for the stricter gate.
    pub include_warn: bool,
}

/// The check-to-playbook mapping the gate enforces.
///
/// Every name in [`CHECK_NAMES`] has exactly one entry, so an agent cannot pick
/// a friendlier code than the diagnosis supports. The choices follow the
/// DOC-04 scenario table in `docs/doctor.md`.
pub fn check_code(check: &str) -> Option<ErrorCode> {
    Some(match check {
        "versions" => ErrorCode::Unavailable,
        "config" => ErrorCode::ConfigInvalid,
        "keys" => ErrorCode::NotFound,
        "workers" => ErrorCode::Unavailable,
        "kernel" => ErrorCode::Unavailable,
        "auth" => ErrorCode::ProviderAuth,
        "network" => ErrorCode::ProviderUnavailable,
        "mesh" => ErrorCode::NoQuorum,
        "ports" => ErrorCode::Io,
        "disk" => ErrorCode::ResourceExhausted,
        "locks" => ErrorCode::Locked,
        "journals" => ErrorCode::SessionCorrupt,
        "mcp" => ErrorCode::Unsupported,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// diagnose
// ---------------------------------------------------------------------------

/// The `diagnose` tool: run the whole core against an injected context.
///
/// Pure with respect to services. A caller assembles [`DoctorContext`] once and
/// gets the same 13 checks on every call.
pub fn diagnose(ctx: &DoctorContext) -> DoctorReport {
    run_core_with(ctx)
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

/// One failing check the planner would not touch, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedCheck {
    /// The check name, always one of [`CHECK_NAMES`].
    pub check: String,
    /// Why no action was planned. Safe to show: paths, counts, and policy
    /// wording only, never file contents.
    pub reason: String,
}

/// The `plan` tool's result: an applyable [`RepairPlan`] plus the failing
/// checks it deliberately did not plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanOutcome {
    /// The plan. Empty when no failing check has a safe repair.
    pub plan: RepairPlan,
    /// Check names the plan covers, in report order.
    pub covered: Vec<String>,
    /// Check names with no safe action, in report order. The agent must report
    /// these as unresolved.
    pub refused: Vec<RefusedCheck>,
}

impl PlanOutcome {
    /// True when nothing safe could be planned.
    pub fn is_empty(&self) -> bool {
        self.plan.actions.is_empty()
    }

    /// The refused reason for one check, if it was refused.
    pub fn refusal(&self, check: &str) -> Option<&RefusedCheck> {
        self.refused.iter().find(|refusal| refusal.check == check)
    }
}

/// The `plan` tool: map failing checks to safe, reversible actions.
///
/// Only checks with a known repair are planned:
///
/// | Check | Planned action | Precondition |
/// |---|---|---|
/// | `config` | `RepairConfig` | a readable `<config>.bak` exists and is valid TOML |
/// | `locks` | one `RemoveStaleLock` per stale lock | `policy.allow_delete` |
/// | `journals` | `CreateDirectory` for each missing parent directory | every unreadable journal is explained by a missing parent |
///
/// Every other failing check is returned in [`PlanOutcome::refused`]. Warnings
/// are not planned: they are not failures for the turn gate either. Policy
/// limits (empty roots, `max_actions`, the hard cap) are applied after mapping;
/// if they reject the collected actions, the covered checks move to `refused`
/// with that reason instead of producing a plan that could not be applied.
pub fn plan(ctx: &DoctorContext, policy: &RepairPolicy) -> PlanOutcome {
    let report = run_core_with(ctx);
    let mut actions = Vec::new();
    let mut covered = Vec::new();
    let mut refused = Vec::new();

    for check in &report.checks {
        if check.status != CheckStatus::Fail {
            continue;
        }
        match repairs_for(ctx, &check.name, policy) {
            Ok(mut repairs) if !repairs.is_empty() => {
                actions.append(&mut repairs);
                covered.push(check.name.clone());
            }
            Ok(_) => refused.push(RefusedCheck {
                check: check.name.clone(),
                reason: "no repair action is available for this check".to_string(),
            }),
            Err(reason) => refused.push(RefusedCheck {
                check: check.name.clone(),
                reason,
            }),
        }
    }

    let limit = policy.max_actions.min(MAX_PLAN_ACTIONS);
    if !actions.is_empty() {
        let limit_reason = if policy.allowed_roots.is_empty() {
            Some("the repair policy has no allowed roots".to_string())
        } else if actions.len() > limit {
            Some(format!(
                "{} repair actions are needed but the policy allows {limit}",
                actions.len()
            ))
        } else {
            None
        };
        if let Some(reason) = limit_reason {
            refused.extend(covered.drain(..).map(|check| RefusedCheck {
                check,
                reason: reason.clone(),
            }));
            actions.clear();
        }
    }

    PlanOutcome {
        plan: RepairPlan::new(PLAN_ID, actions),
        covered,
        refused,
    }
}

fn repairs_for(
    ctx: &DoctorContext,
    check: &str,
    policy: &RepairPolicy,
) -> Result<Vec<RepairAction>, String> {
    match check {
        "config" => config_repairs(ctx),
        "locks" => lock_repairs(ctx, policy),
        "journals" => journal_repairs(ctx),
        other => Err(format!(
            "no safe automated repair is defined for `{other}`; report it unresolved"
        )),
    }
}

/// Restore a malformed config from its sibling `<name>.bak` after validating it.
fn config_repairs(ctx: &DoctorContext) -> Result<Vec<RepairAction>, String> {
    let backup = backup_path(&ctx.config.path);
    let contents = std::fs::read_to_string(&backup).map_err(|error| {
        format!(
            "config is malformed and no readable backup exists at {} ({error})",
            backup.display()
        )
    })?;
    if crate::validate_toml(&contents).is_err() {
        return Err(format!(
            "backup {} is not valid TOML, so it cannot replace the config",
            backup.display()
        ));
    }
    Ok(vec![RepairAction::RepairConfig {
        path: ctx.config.path.clone(),
        contents,
    }])
}

fn lock_repairs(
    ctx: &DoctorContext,
    policy: &RepairPolicy,
) -> Result<Vec<RepairAction>, String> {
    let stale = stale_locks(ctx);
    if stale.is_empty() {
        return Err(
            "the locks check failed but no stale lock files were captured; refusing to guess"
                .to_string(),
        );
    }
    if !policy.allow_delete {
        return Err(format!(
            "{} stale lock(s) need removal and the policy does not allow deletion",
            stale.len()
        ));
    }
    Ok(stale
        .into_iter()
        .map(|entry| RepairAction::RemoveStaleLock {
            path: entry.path.clone(),
        })
        .collect())
}

/// Recreate missing journal directories when that is the only reason the check
/// cannot read a journal. Anything else is refused rather than "fixed" by
/// deleting or rewriting evidence.
fn journal_repairs(ctx: &DoctorContext) -> Result<Vec<RepairAction>, String> {
    let mut missing_parents: Vec<PathBuf> = Vec::new();
    let mut blockers: Vec<PathBuf> = Vec::new();
    for journal in &ctx.journals {
        if std::fs::read_to_string(journal).is_ok() {
            continue;
        }
        match journal.parent() {
            Some(parent) if !parent.as_os_str().is_empty() && !parent.exists() => {
                if !missing_parents.iter().any(|existing| existing == parent) {
                    missing_parents.push(parent.to_path_buf());
                }
            }
            _ => blockers.push(journal.clone()),
        }
    }
    if !blockers.is_empty() {
        return Err(format!(
            "cannot read journal(s) for a reason other than a missing directory: {}",
            short_paths(&blockers)
        ));
    }
    if missing_parents.is_empty() {
        return Err(
            "the journals check failed but no missing journal directory explains it".to_string(),
        );
    }
    Ok(missing_parents
        .into_iter()
        .map(|path| RepairAction::CreateDirectory { path })
        .collect())
}

fn stale_locks(ctx: &DoctorContext) -> Vec<&LockEntry> {
    ctx.locks
        .entries
        .iter()
        .filter(|entry| {
            entry.modified.is_some_and(|modified| {
                crate::age_exceeds(ctx.locks.now, modified, ctx.locks.stale_after)
            })
        })
        .collect()
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".bak");
    path.with_file_name(name)
}

fn short_paths(paths: &[PathBuf]) -> String {
    let mut out = paths
        .iter()
        .take(3)
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if paths.len() > 3 {
        out.push_str(&format!(" (+{} more)", paths.len() - 3));
    }
    out
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

/// The `apply` tool: delegate to [`crate::repair::apply`].
///
/// A plan whose `dry_run` flag is set is refused with
/// [`RepairError::DryRunPlan`] before any validation or mutation; a real plan
/// keeps the snapshot, ordering, and rollback guarantees of the repair engine.
pub fn apply(
    plan: &RepairPlan,
    policy: &RepairPolicy,
    snapshot_dir: impl AsRef<Path>,
) -> Result<RepairReport, AgentError> {
    repair::apply(plan, policy, snapshot_dir).map_err(AgentError::Repair)
}

/// Typed error for the convenience wrapper: either the repair engine refused,
/// or the turn gate refused.
#[derive(Debug, Error)]
pub enum AgentError {
    /// The repair engine rejected the plan or failed during apply.
    #[error(transparent)]
    Repair(#[from] RepairError),
    /// The turn gate rejected the report.
    #[error(transparent)]
    Gate(#[from] ZeroError),
}

impl AgentError {
    /// The stable code a host should surface for this failure.
    pub fn code(&self) -> ErrorCode {
        match self {
            AgentError::Repair(error) => repair_code(error),
            AgentError::Gate(error) => error.code(),
        }
    }
}

fn repair_code(error: &RepairError) -> ErrorCode {
    match error {
        RepairError::DryRunPlan { .. }
        | RepairError::InvalidPlan { .. }
        | RepairError::InvalidAction { .. } => ErrorCode::InvalidInput,
        RepairError::Policy { .. } => ErrorCode::PolicyDenied,
        RepairError::TooManyActions { .. } => ErrorCode::LimitExceeded,
        RepairError::Apply { .. } | RepairError::ApplyRollbackFailed { .. } => ErrorCode::Io,
        RepairError::Rollback { .. } => ErrorCode::Corrupt,
    }
}

// ---------------------------------------------------------------------------
// Unresolved-failure report
// ---------------------------------------------------------------------------

/// One failing check the agent could not resolve this turn.
///
/// `code` is the stable classification for the check and `playbook_code` is the
/// playbook the agent rendered. The gate requires both to equal
/// [`check_code`] for the named check, so an agent cannot substitute a milder
/// code. `summary` is free text and must be redaction-safe: no secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedFailure {
    pub check: String,
    pub code: ErrorCode,
    pub playbook_code: ErrorCode,
    pub summary: String,
}

impl UnresolvedFailure {
    /// Build an entry with the mapped code and playbook code for `check`.
    ///
    /// Returns `None` for a name outside [`CHECK_NAMES`].
    pub fn for_check(check: &str, summary: impl Into<String>) -> Option<Self> {
        let code = check_code(check)?;
        Some(Self {
            check: check.to_string(),
            code,
            playbook_code: code,
            summary: summary.into(),
        })
    }
}

/// The agent's end-of-turn report, checked by [`finish_turn`].
///
/// Build it with [`TurnReport::mark_resolved`] and
/// [`TurnReport::record_applied`] so `actions_taken` holds the canonical
/// `check:aN:kind` strings the gate can verify against a [`RepairReport`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TurnReport {
    /// Checks fixed this turn. Each must also have an applied action.
    pub resolved: Vec<String>,
    /// Checks still failing, with the mapped playbook code.
    pub unresolved: Vec<UnresolvedFailure>,
    /// Canonical applied-action strings: `"{check}:{aN}:{kind}"`.
    pub actions_taken: Vec<String>,
}

impl TurnReport {
    /// A report with nothing recorded.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a check resolved. Rejected for an unknown check name; a matching
    /// unresolved entry is removed so a check cannot be both.
    pub fn mark_resolved(&mut self, check: &str) -> ZeroResult<()> {
        if check_code(check).is_none() {
            return Err(gate_invalid(format!("unknown doctor check `{check}`")));
        }
        self.unresolved.retain(|entry| entry.check != check);
        if !self.resolved.iter().any(|name| name == check) {
            self.resolved.push(check.to_string());
        }
        Ok(())
    }

    /// Record every action [`crate::repair::apply`] actually applied for
    /// `check` as a canonical `check:aN:kind` entry.
    pub fn record_applied(&mut self, check: &str, report: &RepairReport) -> ZeroResult<()> {
        if check_code(check).is_none() {
            return Err(gate_invalid(format!("unknown doctor check `{check}`")));
        }
        if report.applied.is_empty() {
            return Err(gate_invalid(format!(
                "repair report `{}` has no applied actions to record for `{check}`",
                report.plan_id
            )));
        }
        for action in &report.applied {
            self.actions_taken.push(format!(
                "{check}:{}:{}",
                action.id,
                kind_name(action.kind)
            ));
        }
        Ok(())
    }
}

/// What [`finish_turn`] returns when the turn is allowed to finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnSummary {
    /// Checks the gate treated as failing (`fail`, plus `warn` when configured).
    pub failing: usize,
    /// Checks reported resolved with an applied action.
    pub resolved: usize,
    /// Checks reported unresolved with the mapped code.
    pub unresolved: usize,
    /// Canonical applied-action entries recorded by the agent.
    pub actions: usize,
}

/// The gate: refuse to finish a turn that hides a failing check.
///
/// A report is accepted only when it has exactly the 13 core checks (so an
/// agent cannot fabricate a pass with an empty report), every failing check is
/// either unresolved with its mapped code or resolved with an applied action,
/// and no entry is malformed. A hidden failure is refused with
/// `zero.pol.ask` naming the check; a fabricated or contradictory entry with
/// `zero.pol.denied`; malformed input with `zero.fnd.invalid_input`.
pub fn finish_turn(report: &DoctorReport, turn: &TurnReport) -> ZeroResult<TurnSummary> {
    finish_turn_with(report, turn, GateOptions::default())
}

/// [`finish_turn`] with an explicit gate configuration.
pub fn finish_turn_with(
    report: &DoctorReport,
    turn: &TurnReport,
    options: GateOptions,
) -> ZeroResult<TurnSummary> {
    validate_report(report)?;

    let failing = failing_checks(report, options);
    let failing_names: BTreeSet<&str> = failing.iter().map(|check| check.name.as_str()).collect();

    // Every name the agent reported must be a real check.
    for name in turn
        .resolved
        .iter()
        .chain(turn.unresolved.iter().map(|failure| &failure.check))
    {
        if check_code(name).is_none() {
            return Err(gate_invalid(format!("unknown doctor check `{name}`")));
        }
    }

    let mut resolved = BTreeSet::new();
    for name in &turn.resolved {
        if !resolved.insert(name.as_str()) {
            return Err(gate_invalid(format!(
                "check `{name}` is listed as resolved more than once"
            )));
        }
        if !failing_names.contains(name.as_str()) {
            return Err(gate_denied(format!(
                "check `{name}` is marked resolved but is not failing in this report"
            )));
        }
    }

    let mut unresolved = BTreeSet::new();
    for failure in &turn.unresolved {
        if !unresolved.insert(failure.check.as_str()) {
            return Err(gate_invalid(format!(
                "check `{}` is reported unresolved more than once",
                failure.check
            )));
        }
        if resolved.contains(failure.check.as_str()) {
            return Err(gate_denied(format!(
                "check `{}` is reported both resolved and unresolved",
                failure.check
            )));
        }
        if !failing_names.contains(failure.check.as_str()) {
            return Err(gate_denied(format!(
                "check `{}` is reported unresolved but is not failing in this report",
                failure.check
            )));
        }
        let expected = check_code(&failure.check).expect("validated above");
        if failure.code != expected {
            return Err(gate_denied(format!(
                "check `{}` must report code {}; got {}",
                failure.check,
                expected.as_str(),
                failure.code.as_str()
            )));
        }
        if failure.playbook_code != expected {
            return Err(gate_denied(format!(
                "playbook code {} does not match check `{}` (expected {})",
                failure.playbook_code.as_str(),
                failure.check,
                expected.as_str()
            )));
        }
        validate_summary(&failure.check, &failure.summary)?;
    }

    // Every action entry must be one this module produced.
    for entry in &turn.actions_taken {
        let Some((check, _kind)) = parse_applied(entry) else {
            return Err(gate_invalid(format!(
                "actions_taken entry `{entry}` is not a canonical `check:aN:kind` record"
            )));
        };
        if check_code(check).is_none() {
            return Err(gate_invalid(format!(
                "actions_taken entry `{entry}` names unknown check `{check}`"
            )));
        }
    }

    // A resolution needs evidence: an applied action for the same check, and
    // one of the kinds `plan` is allowed to use for it.
    for name in &turn.resolved {
        let allowed = allowed_repairs(name);
        let backed = turn.actions_taken.iter().any(|entry| {
            parse_applied(entry).is_some_and(|(check, kind)| {
                check == name.as_str() && allowed.contains(&kind)
            })
        });
        if !backed {
            return Err(gate_denied(format!(
                "check `{name}` is marked resolved without an applied action from plan in \
                 actions_taken"
            )));
        }
    }

    let hidden: Vec<&str> = failing_names
        .difference(&resolved)
        .filter(|name| !unresolved.contains(**name))
        .copied()
        .collect();
    if !hidden.is_empty() {
        return Err(gate_ask(format!(
            "doctor turn cannot finish: failing check(s) not reported: {}; \
             report each in TurnReport::unresolved or record the applied repair",
            hidden.join(", ")
        )));
    }

    Ok(TurnSummary {
        failing: failing.len(),
        resolved: turn.resolved.len(),
        unresolved: turn.unresolved.len(),
        actions: turn.actions_taken.len(),
    })
}

fn validate_report(report: &DoctorReport) -> ZeroResult<()> {
    if report.checks.len() != CHECK_NAMES.len() {
        return Err(gate_invalid(format!(
            "doctor report has {} checks; expected {}; finish_turn only accepts a report \
             produced by run_core_with",
            report.checks.len(),
            CHECK_NAMES.len()
        )));
    }
    let mut seen = BTreeSet::new();
    for check in &report.checks {
        if !CHECK_NAMES.contains(&check.name.as_str()) {
            return Err(gate_invalid(format!(
                "doctor report contains unknown check `{}`",
                check.name
            )));
        }
        if !seen.insert(check.name.as_str()) {
            return Err(gate_invalid(format!(
                "doctor report repeats check `{}`",
                check.name
            )));
        }
    }
    Ok(())
}

fn failing_checks(report: &DoctorReport, options: GateOptions) -> Vec<&CheckResult> {
    report
        .checks
        .iter()
        .filter(|check| match check.status {
            CheckStatus::Fail => true,
            CheckStatus::Warn => options.include_warn,
            CheckStatus::Ok => false,
        })
        .collect()
}

fn validate_summary(check: &str, summary: &str) -> ZeroResult<()> {
    if summary.trim().is_empty() {
        return Err(gate_invalid(format!(
            "unresolved failure for `{check}` has an empty summary"
        )));
    }
    if summary.chars().count() > MAX_SUMMARY_CHARS {
        return Err(gate_invalid(format!(
            "unresolved failure for `{check}` has a summary longer than {MAX_SUMMARY_CHARS} characters"
        )));
    }
    if summary.chars().any(|ch| ch.is_control() && ch != ' ') {
        return Err(gate_invalid(format!(
            "unresolved failure for `{check}` summary must be a single printable line"
        )));
    }
    if contains_secret_marker(summary) {
        return Err(gate_invalid(format!(
            "unresolved failure for `{check}` summary looks like it carries a secret value"
        )));
    }
    Ok(())
}

/// Strong, low-false-positive markers of embedded credential material. Mirrors
/// the repair engine's guard so a summary cannot smuggle what a file may not.
fn contains_secret_marker(text: &str) -> bool {
    const MARKERS: [&str; 7] = [
        "-----BEGIN ",
        "PRIVATE KEY",
        "sk-",
        "ghp_",
        "xoxb-",
        "AKIA",
        "Bearer ",
    ];
    MARKERS.iter().any(|marker| text.contains(marker))
}

fn parse_applied(entry: &str) -> Option<(&str, RepairActionKind)> {
    let mut parts = entry.split(':');
    let check = parts.next()?;
    let id = parts.next()?;
    let kind = parts.next()?;
    if parts.next().is_some() || check.is_empty() {
        return None;
    }
    let digits = id.strip_prefix('a')?;
    if digits.is_empty()
        || digits.starts_with('0')
        || !digits.chars().all(|ch| ch.is_ascii_digit())
    {
        return None;
    }
    Some((check, parse_kind(kind)?))
}

/// The action kinds [`plan`] may use for a check. A `resolved` entry needs an
/// applied action of one of these kinds, so a lock cannot be "resolved" by a
/// config rewrite or vice versa.
fn allowed_repairs(check: &str) -> &'static [RepairActionKind] {
    const CONFIG: &[RepairActionKind] = &[RepairActionKind::RepairConfig];
    const LOCKS: &[RepairActionKind] = &[RepairActionKind::RemoveStaleLock];
    const JOURNALS: &[RepairActionKind] = &[RepairActionKind::CreateDirectory];
    match check {
        "config" => CONFIG,
        "locks" => LOCKS,
        "journals" => JOURNALS,
        _ => &[],
    }
}

fn kind_name(kind: RepairActionKind) -> &'static str {
    match kind {
        RepairActionKind::CreateDirectory => "create_directory",
        RepairActionKind::WriteFile => "write_file",
        RepairActionKind::MoveToTrash => "move_to_trash",
        RepairActionKind::RemoveStaleLock => "remove_stale_lock",
        RepairActionKind::RotateFile => "rotate_file",
        RepairActionKind::RepairConfig => "repair_config",
    }
}

fn parse_kind(kind: &str) -> Option<RepairActionKind> {
    Some(match kind {
        "create_directory" => RepairActionKind::CreateDirectory,
        "write_file" => RepairActionKind::WriteFile,
        "move_to_trash" => RepairActionKind::MoveToTrash,
        "remove_stale_lock" => RepairActionKind::RemoveStaleLock,
        "rotate_file" => RepairActionKind::RotateFile,
        "repair_config" => RepairActionKind::RepairConfig,
        _ => return None,
    })
}

fn gate_invalid(message: String) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn gate_denied(message: String) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn gate_ask(message: String) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyAskRequired, message)
}

// ---------------------------------------------------------------------------
// AgentDoctor
// ---------------------------------------------------------------------------

/// Convenience wrapper: one context, one repair policy, one snapshot directory,
/// and the three tools plus the turn gate.
///
/// Every method returns a typed [`AgentError`] so a host can branch on the
/// stable code without parsing messages. `diagnose` and `plan` are infallible
/// today and still return `Ok`; the signature leaves room for a future
/// caller-supplied probe without changing the host contract.
#[derive(Debug, Clone)]
pub struct AgentDoctor {
    pub context: DoctorContext,
    pub policy: RepairPolicy,
    pub snapshot_dir: PathBuf,
    pub gate: GateOptions,
}

impl AgentDoctor {
    /// Build the wrapper. `snapshot_dir` is where [`apply`] keeps snapshots and
    /// the reversible trash.
    pub fn new(
        context: DoctorContext,
        policy: RepairPolicy,
        snapshot_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            context,
            policy,
            snapshot_dir: snapshot_dir.into(),
            gate: GateOptions::default(),
        }
    }

    /// Use the stricter gate that also reports `warn` checks.
    pub fn with_warnings(mut self, include_warn: bool) -> Self {
        self.gate.include_warn = include_warn;
        self
    }

    /// Run [`diagnose`] against the stored context.
    pub fn diagnose(&self) -> Result<DoctorReport, AgentError> {
        Ok(diagnose(&self.context))
    }

    /// Run [`plan`] with the stored policy.
    pub fn plan(&self) -> Result<PlanOutcome, AgentError> {
        Ok(plan(&self.context, &self.policy))
    }

    /// Preview a plan under the stored policy without mutating anything.
    pub fn preview(&self, plan: &RepairPlan) -> Result<RepairPreview, AgentError> {
        repair::dry_run(plan, &self.policy).map_err(AgentError::Repair)
    }

    /// Apply a plan under the stored policy into the stored snapshot directory.
    pub fn apply(&self, plan: &RepairPlan) -> Result<RepairReport, AgentError> {
        apply(plan, &self.policy, &self.snapshot_dir)
    }

    /// Run the gate with the stored options.
    pub fn finish_turn(
        &self,
        report: &DoctorReport,
        turn: &TurnReport,
    ) -> Result<TurnSummary, AgentError> {
        finish_turn_with(report, turn, self.gate).map_err(AgentError::Gate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn policy(root: &Path, allow_delete: bool) -> RepairPolicy {
        RepairPolicy {
            allowed_roots: vec![root.to_path_buf()],
            max_actions: 32,
            allow_delete,
        }
    }

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    /// Files and directories under `root`, keyed by relative path. `None`
    /// marks a directory.
    fn tree(root: &Path) -> std::collections::BTreeMap<PathBuf, Option<Vec<u8>>> {
        fn walk(
            root: &Path,
            dir: &Path,
            out: &mut std::collections::BTreeMap<PathBuf, Option<Vec<u8>>>,
        ) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                let metadata = std::fs::symlink_metadata(&path).unwrap();
                if metadata.is_dir() {
                    out.insert(relative, None);
                    walk(root, &path, out);
                } else {
                    out.insert(relative, Some(std::fs::read(&path).unwrap()));
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        walk(root, root, &mut out);
        out
    }

    // -- diagnose ---------------------------------------------------------

    #[test]
    fn diagnose_returns_the_thirteen_checks_in_order() {
        let dir = dir();
        let ctx = DoctorContext::from_root(dir.path());
        let report = diagnose(&ctx);
        assert_eq!(report.checks.len(), CHECK_NAMES.len());
        let names: Vec<&str> = report
            .checks
            .iter()
            .map(|check| check.name.as_str())
            .collect();
        assert_eq!(names, CHECK_NAMES);
        assert!(report.independent);
        assert_eq!(report.daemon, crate::DaemonStatus::NotContacted);
    }

    // -- plan -------------------------------------------------------------

    /// A context with a malformed config plus a valid backup, six stale locks,
    /// and a journal under a missing directory. `keys` also fails (no key), and
    /// has no safe repair.
    fn plan_fixture(root: &Path) -> DoctorContext {
        let zero = root.join(".zero");
        write(&zero.join("config.toml"), "[core\nbroken = \"yes\"\n");
        write(
            &zero.join("config.toml.bak"),
            "[core]\nmodel = \"local\"\n",
        );
        for index in 0..6 {
            write(&zero.join("locks").join(format!("w{index}.lock")), "lock");
        }
        let mut ctx = DoctorContext::from_root(root);
        ctx.locks.entries = (0..6)
            .map(|index| LockEntry {
                path: zero.join("locks").join(format!("w{index}.lock")),
                modified: Some(UNIX_EPOCH),
            })
            .collect();
        ctx.locks.stale_after = Duration::from_secs(60 * 60);
        ctx.locks.now = UNIX_EPOCH + Duration::from_secs(2 * 60 * 60);
        ctx.journals = vec![zero.join("session-logs").join("missing.jsonl")];
        ctx
    }

    #[test]
    fn plan_maps_config_locks_and_missing_directories() {
        let dir = dir();
        let root = dir.path();
        let ctx = plan_fixture(root);
        let outcome = plan(&ctx, &policy(root, true));

        let covered: Vec<&str> = outcome.covered.iter().map(String::as_str).collect();
        assert!(covered.contains(&"config"), "{covered:?}");
        assert!(covered.contains(&"locks"), "{covered:?}");
        assert!(covered.contains(&"journals"), "{covered:?}");

        let kinds: Vec<RepairActionKind> =
            outcome.plan.actions.iter().map(RepairAction::kind).collect();
        assert!(kinds.contains(&RepairActionKind::RepairConfig));
        assert!(kinds.contains(&RepairActionKind::CreateDirectory));
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == RepairActionKind::RemoveStaleLock)
                .count(),
            6
        );
        assert!(!outcome.plan.dry_run, "a plan from plan() is applyable");

        let refused: Vec<&str> = outcome.refused.iter().map(|item| item.check.as_str()).collect();
        assert_eq!(refused, vec!["keys"], "only the key check is unrepairable");
        let keys = outcome.refusal("keys").expect("keys refusal");
        assert!(keys.reason.contains("no safe automated repair"), "{}", keys.reason);
    }

    #[test]
    fn plan_never_deletes_without_policy_allowance() {
        let dir = dir();
        let root = dir.path();
        let ctx = plan_fixture(root);
        let outcome = plan(&ctx, &policy(root, false));

        assert!(!outcome
            .plan
            .actions
            .iter()
            .any(|action| matches!(action, RepairAction::RemoveStaleLock { .. })));
        let locks = outcome.refusal("locks").expect("locks refusal");
        assert!(locks.reason.contains("deletion"), "{}", locks.reason);
        // Checks with non-deleting repairs are still planned.
        assert!(outcome.covered.iter().any(|check| check == "config"));
        assert!(outcome.covered.iter().any(|check| check == "journals"));
    }

    #[test]
    fn plan_refuses_checks_without_a_safe_action() {
        let dir = dir();
        let root = dir.path();
        let zero = root.join(".zero");
        std::fs::create_dir_all(&zero).unwrap();
        write(&zero.join("config.toml"), "[core\nbroken = \"yes\"\n");

        let outcome = plan(&DoctorContext::from_root(root), &policy(root, true));
        assert!(outcome.is_empty());
        assert!(outcome.covered.is_empty());

        let config = outcome.refusal("config").expect("config refusal");
        assert!(config.reason.contains("backup"), "{}", config.reason);
        assert!(outcome.refusal("keys").is_some(), "missing key is refused");
    }

    #[test]
    fn plan_respects_the_policy_action_limit() {
        let dir = dir();
        let root = dir.path();
        let ctx = plan_fixture(root);
        let mut bounded = policy(root, true);
        bounded.max_actions = 2;

        let outcome = plan(&ctx, &bounded);
        assert!(outcome.is_empty());
        assert!(outcome.covered.is_empty());
        let config = outcome.refusal("config").expect("config refusal");
        assert!(config.reason.contains("policy allows 2"), "{}", config.reason);
    }

    #[test]
    fn plan_is_empty_when_no_check_fails() {
        let dir = dir();
        let root = dir.path();
        let zero = root.join(".zero");
        write(&zero.join("config.toml"), "[core]\nmodel = \"local\"\n");
        write(&zero.join("key"), "key-material");
        write(
            &zero.join("workers.json"),
            r#"{"workers":[{"status":"running"}]}"#,
        );
        write(&zero.join("mesh").join("registry.json"), r#"{"devices":[{"id":"a"}]}"#);
        write(
            &zero.join("mcp.json"),
            r#"{"servers":{"fs":{"command":"node","args":["server.js"]}}}"#,
        );

        let report = diagnose(&DoctorContext::from_root(root));
        assert!(
            report
                .checks
                .iter()
                .all(|check| check.status != CheckStatus::Fail),
            "{}",
            report.render_human()
        );

        let outcome = plan(&DoctorContext::from_root(root), &policy(root, true));
        assert!(outcome.is_empty());
        assert!(outcome.covered.is_empty());
        assert!(outcome.refused.is_empty());
    }

    // -- apply / dry run / rollback ---------------------------------------

    #[test]
    fn dry_run_apply_never_mutates_and_a_real_apply_rolls_back() {
        let dir = dir();
        let root = dir.path();
        let lock = root.join("stale.lock");
        let created = root.join("newdir");
        write(&lock, "stale");
        let policy = policy(root, true);
        let snapshots = root.join("snapshots");
        let plan = RepairPlan::new(
            "agent-dry-run",
            vec![
                RepairAction::CreateDirectory {
                    path: created.clone(),
                },
                RepairAction::RemoveStaleLock { path: lock.clone() },
            ],
        );

        let before = tree(root);
        let mut dry = plan.clone();
        dry.dry_run = true;
        let error = apply(&dry, &policy, &snapshots).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(matches!(
            error,
            AgentError::Repair(RepairError::DryRunPlan { .. })
        ));
        assert_eq!(tree(root), before, "a dry-run plan must not mutate");

        let preview = repair::dry_run(&plan, &policy).unwrap();
        assert!(preview.dry_run);
        assert_eq!(preview.changes.len(), 2);
        assert_eq!(tree(root), before, "preview must not mutate");

        let report = apply(&plan, &policy, &snapshots).unwrap();
        assert!(created.is_dir());
        assert!(!lock.exists());
        assert_eq!(report.applied.len(), 2);

        repair::rollback(&report).unwrap();
        assert!(!created.exists(), "rollback removes the created directory");
        assert_eq!(std::fs::read(&lock).unwrap(), b"stale");
    }

    // -- finish_turn ------------------------------------------------------

    fn report_with(statuses: &[(&str, CheckStatus)]) -> DoctorReport {
        let checks = CHECK_NAMES
            .iter()
            .map(|name| CheckResult {
                name: (*name).to_string(),
                status: statuses
                    .iter()
                    .find(|(candidate, _)| *candidate == *name)
                    .map(|(_, status)| *status)
                    .unwrap_or(CheckStatus::Ok),
                detail: String::new(),
            })
            .collect();
        DoctorReport {
            version: crate::VERSION.to_string(),
            independent: true,
            daemon: crate::DaemonStatus::NotContacted,
            checks,
        }
    }

    #[test]
    fn finish_turn_refuses_a_hidden_failure() {
        let report = report_with(&[("locks", CheckStatus::Fail)]);
        let error = finish_turn(&report, &TurnReport::default()).unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);
        assert!(error.message().contains("locks"), "{}", error.message());
    }

    #[test]
    fn finish_turn_accepts_a_reported_unresolved_failure() {
        let report = report_with(&[("locks", CheckStatus::Fail)]);
        let turn = TurnReport {
            unresolved: vec![
                UnresolvedFailure::for_check("locks", "6 stale locks remain; user will clear them")
                    .unwrap(),
            ],
            ..Default::default()
        };
        let summary = finish_turn(&report, &turn).unwrap();
        assert_eq!(summary.failing, 1);
        assert_eq!(summary.unresolved, 1);
        assert_eq!(summary.resolved, 0);
    }

    #[test]
    fn finish_turn_requires_the_mapped_playbook_code() {
        let report = report_with(&[("locks", CheckStatus::Fail)]);
        let turn = TurnReport {
            unresolved: vec![UnresolvedFailure {
                check: "locks".to_string(),
                code: ErrorCode::Locked,
                playbook_code: ErrorCode::Internal,
                summary: "stale locks".to_string(),
            }],
            ..Default::default()
        };
        let error = finish_turn(&report, &turn).unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("playbook"), "{}", error.message());

        let wrong_code = TurnReport {
            unresolved: vec![UnresolvedFailure {
                check: "locks".to_string(),
                code: ErrorCode::Unavailable,
                playbook_code: ErrorCode::Unavailable,
                summary: "stale locks".to_string(),
            }],
            ..Default::default()
        };
        assert_eq!(
            finish_turn(&report, &wrong_code).unwrap_err().code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn finish_turn_rejects_unknown_checks_and_empty_summaries() {
        let report = report_with(&[("locks", CheckStatus::Fail)]);

        let unknown = TurnReport {
            unresolved: vec![UnresolvedFailure {
                check: "not-a-check".to_string(),
                code: ErrorCode::Locked,
                playbook_code: ErrorCode::Locked,
                summary: "x".to_string(),
            }],
            ..Default::default()
        };
        let error = finish_turn(&report, &unknown).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("not-a-check"), "{}", error.message());

        let empty = TurnReport {
            unresolved: vec![
                UnresolvedFailure::for_check("locks", "  \t ").unwrap(),
            ],
            ..Default::default()
        };
        let error = finish_turn(&report, &empty).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("summary"), "{}", error.message());

        let secret = TurnReport {
            unresolved: vec![
                UnresolvedFailure::for_check("locks", "token sk-live-1234").unwrap(),
            ],
            ..Default::default()
        };
        assert_eq!(
            finish_turn(&report, &secret).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn finish_turn_rejects_a_resolved_check_without_an_applied_action() {
        let report = report_with(&[("locks", CheckStatus::Fail)]);
        let turn = TurnReport {
            resolved: vec!["locks".to_string()],
            ..Default::default()
        };
        let error = finish_turn(&report, &turn).unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("applied"), "{}", error.message());

        // The right kind for `locks` is accepted.
        let recorded = TurnReport {
            resolved: vec!["locks".to_string()],
            actions_taken: vec!["locks:a1:remove_stale_lock".to_string()],
            ..Default::default()
        };
        assert!(finish_turn(&report, &recorded).is_ok());

        // A different repair kind cannot stand in for the lock repair.
        let wrong_kind = TurnReport {
            resolved: vec!["locks".to_string()],
            actions_taken: vec!["locks:a1:write_file".to_string()],
            ..Default::default()
        };
        assert_eq!(
            finish_turn(&report, &wrong_kind).unwrap_err().code(),
            ErrorCode::PolicyDenied
        );

        let malformed = TurnReport {
            resolved: vec!["locks".to_string()],
            actions_taken: vec!["removed the stale lock".to_string()],
            ..Default::default()
        };
        assert_eq!(
            finish_turn(&report, &malformed).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn finish_turn_accepts_a_resolution_backed_by_a_real_apply() {
        let dir = dir();
        let root = dir.path();
        let lock = root.join("stale.lock");
        write(&lock, "stale");
        let policy = policy(root, true);
        let snapshots = root.join("snapshots");
        let plan = RepairPlan::new(
            "gate",
            vec![RepairAction::RemoveStaleLock { path: lock.clone() }],
        );
        let applied = apply(&plan, &policy, &snapshots).unwrap();

        let report = report_with(&[("locks", CheckStatus::Fail)]);
        let mut turn = TurnReport::default();
        turn.mark_resolved("locks").unwrap();
        assert!(finish_turn(&report, &turn).is_err(), "no action yet");
        turn.record_applied("locks", &applied).unwrap();

        let summary = finish_turn(&report, &turn).unwrap();
        assert_eq!(summary.resolved, 1);
        assert_eq!(summary.actions, 1);
        assert!(!lock.exists());
    }

    #[test]
    fn finish_turn_rejects_a_report_with_the_wrong_check_count() {
        let empty = DoctorReport {
            version: crate::VERSION.to_string(),
            independent: true,
            daemon: crate::DaemonStatus::NotContacted,
            checks: Vec::new(),
        };
        let error = finish_turn(&empty, &TurnReport::default()).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("13"), "{}", error.message());

        let mut short = report_with(&[]);
        short.checks.pop();
        let error = finish_turn(&short, &TurnReport::default()).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("12"), "{}", error.message());

        let mut duplicated = report_with(&[]);
        duplicated.checks[1] = duplicated.checks[0].clone();
        assert_eq!(
            finish_turn(&duplicated, &TurnReport::default())
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn finish_turn_accepts_a_clean_report() {
        let report = report_with(&[]);
        let summary = finish_turn(&report, &TurnReport::default()).unwrap();
        assert_eq!(summary.failing, 0);
        assert_eq!(summary.resolved, 0);
        assert_eq!(summary.unresolved, 0);
        assert_eq!(summary.actions, 0);
    }

    #[test]
    fn the_strict_gate_also_requires_warnings_to_be_reported() {
        let report = report_with(&[("auth", CheckStatus::Warn)]);
        assert!(finish_turn(&report, &TurnReport::default()).is_ok());

        let error = finish_turn_with(
            &report,
            &TurnReport::default(),
            GateOptions {
                include_warn: true,
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);
        assert!(error.message().contains("auth"), "{}", error.message());
    }

    #[test]
    fn turn_report_rejects_unknown_checks_in_its_helpers() {
        let dir = dir();
        let root = dir.path();
        let mut turn = TurnReport::default();
        assert_eq!(
            turn.mark_resolved("nope").unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        let empty = apply(
            &RepairPlan::new("empty", Vec::new()),
            &policy(root, true),
            root.join("snapshots"),
        )
        .unwrap();
        assert_eq!(
            turn.record_applied("locks", &empty).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    // -- AgentDoctor ------------------------------------------------------

    #[test]
    fn agent_doctor_wires_the_tools_and_returns_typed_errors() {
        let dir = dir();
        let root = dir.path();
        let doctor = AgentDoctor::new(
            DoctorContext::from_root(root),
            policy(root, false),
            root.join("snapshots"),
        )
        .with_warnings(true);

        let report = doctor.diagnose().unwrap();
        assert_eq!(report.checks.len(), CHECK_NAMES.len());

        let outcome = doctor.plan().unwrap();
        assert!(outcome.refusal("keys").is_some());

        let preview = doctor
            .preview(&RepairPlan::new("preview", Vec::new()))
            .unwrap();
        assert!(preview.dry_run);
        assert!(preview.changes.is_empty());

        let error = doctor.finish_turn(&report, &TurnReport::default()).unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);

        let mut dry = RepairPlan::new("dry", vec![]);
        dry.dry_run = true;
        let error = doctor.apply(&dry).unwrap_err();
        assert!(matches!(
            error,
            AgentError::Repair(RepairError::DryRunPlan { .. })
        ));
    }
}
