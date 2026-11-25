//! Goals, heartbeats, schedules, and autonomy limits (AUT-01..AUT-09).
//!
//! Goals persist as session `state` entries, so compaction and resume keep the
//! objective and its accounting. Schedules coalesce missed ticks into one claimed
//! tick. Limits stop a runaway run with a typed reason, and cancellation cascades
//! to children.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use zero_store::session::{Entry, Record, SessionLog};
use zero_types::error::{ErrorCode, Result, ZeroError};
use zero_types::id::Timestamp;

pub const GOAL_KEY: &str = "autonomy.goal";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalState {
    Active,
    Paused,
    Cleared,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Goal {
    pub id: String,
    pub objective: String,
    pub state: GoalState,
    pub tokens_used: u64,
    pub steps_used: u64,
    pub time_ms: u64,
    pub created_ms: i64,
    pub updated_ms: i64,
}

impl Goal {
    pub fn new(id: impl Into<String>, objective: impl Into<String>, now_ms: i64) -> Self {
        Self {
            id: id.into(),
            objective: objective.into(),
            state: GoalState::Active,
            tokens_used: 0,
            steps_used: 0,
            time_ms: 0,
            created_ms: now_ms,
            updated_ms: now_ms,
        }
    }

    pub fn pause(&mut self, now_ms: i64) {
        if self.state == GoalState::Active {
            self.state = GoalState::Paused;
            self.updated_ms = now_ms;
        }
    }

    pub fn resume(&mut self, now_ms: i64) {
        if self.state == GoalState::Paused {
            self.state = GoalState::Active;
            self.updated_ms = now_ms;
        }
    }

    pub fn clear(&mut self, now_ms: i64) {
        self.state = GoalState::Cleared;
        self.updated_ms = now_ms;
    }

    pub fn account(&mut self, tokens: u64, steps: u64, time_ms: u64, now_ms: i64) {
        self.tokens_used += tokens;
        self.steps_used += steps;
        self.time_ms += time_ms;
        self.updated_ms = now_ms;
    }
}

/// Persist a goal as a session state entry (retained by compaction).
pub fn save_goal(log: &mut SessionLog, goal: &Goal, now_ms: i64) -> Result<Record> {
    log.append(
        now_ms,
        Entry::State { key: GOAL_KEY.into(), value: serde_json::to_value(goal)? },
    )
}

pub fn start_goal(log: &mut SessionLog, id: &str, objective: &str, now_ms: i64) -> Result<Goal> {
    let goal = Goal::new(id, objective, now_ms);
    save_goal(log, &goal, now_ms)?;
    Ok(goal)
}

/// Latest goal from a transcript (use the compaction-filtered visible records).
pub fn load_goal(records: &[Record]) -> Option<Goal> {
    records.iter().rev().find_map(|record| match &record.entry {
        Entry::State { key, value } if key == GOAL_KEY => serde_json::from_value(value.clone()).ok(),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// Heartbeats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatKind {
    User,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub kind: HeartbeatKind,
    pub interval_ms: i64,
    pub next_at_ms: i64,
    pub paused: bool,
}

#[derive(Debug, Default, Clone)]
pub struct HeartbeatBook {
    beats: BTreeMap<HeartbeatKind, Heartbeat>,
}

impl HeartbeatBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, kind: HeartbeatKind, interval_ms: i64, now_ms: i64) {
        self.beats.insert(
            kind,
            Heartbeat { kind, interval_ms: interval_ms.max(1), next_at_ms: now_ms + interval_ms.max(1), paused: false },
        );
    }

    pub fn pause(&mut self, kind: HeartbeatKind) -> bool {
        self.beats.get_mut(&kind).map(|beat| {
            beat.paused = true;
            true
        }).unwrap_or(false)
    }

    pub fn resume(&mut self, kind: HeartbeatKind, now_ms: i64) -> bool {
        self.beats.get_mut(&kind).map(|beat| {
            beat.paused = false;
            beat.next_at_ms = now_ms + beat.interval_ms;
            true
        }).unwrap_or(false)
    }

    /// Heartbeats due now; advances each next time (coalesced to one).
    pub fn tick(&mut self, now_ms: i64) -> Vec<HeartbeatKind> {
        let mut due = Vec::new();
        for beat in self.beats.values_mut() {
            if !beat.paused && now_ms >= beat.next_at_ms {
                due.push(beat.kind);
                beat.next_at_ms = now_ms + beat.interval_ms;
            }
        }
        due
    }

    pub fn get(&self, kind: HeartbeatKind) -> Option<&Heartbeat> {
        self.beats.get(&kind)
    }
}

// ---------------------------------------------------------------------------
// Schedules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CronSpec {
    pub minutes: String,
    pub hours: String,
    pub days: String,
    pub months: String,
    pub weekdays: String,
}

impl CronSpec {
    pub fn parse(expression: &str) -> Result<Self> {
        let fields: Vec<&str> = expression.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "cron needs five fields: min hour day month weekday"));
        }
        Ok(Self {
            minutes: fields[0].into(),
            hours: fields[1].into(),
            days: fields[2].into(),
            months: fields[3].into(),
            weekdays: fields[4].into(),
        })
    }

    fn matches(&self, minute: u32, hour: u32, day: u32, month: u32, weekday: u32) -> bool {
        field_matches(&self.minutes, minute, 59)
            && field_matches(&self.hours, hour, 23)
            && field_matches(&self.days, day, 31)
            && field_matches(&self.months, month, 12)
            && field_matches(&self.weekdays, weekday, 7)
    }
}

fn field_matches(field: &str, value: u32, max: u32) -> bool {
    for part in field.split(',') {
        if part == "*" {
            return true;
        }
        if let Some(step) = part.strip_prefix("*/") {
            if let Ok(step) = step.parse::<u32>() {
                return step > 0 && value.is_multiple_of(step);
            }
            return false;
        }
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (start.parse::<u32>(), end.parse::<u32>()) {
                if value >= start && value <= end {
                    return true;
                }
            }
            continue;
        }
        if part.parse::<u32>().ok() == Some(value) {
            return true;
        }
        let _ = max;
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleSpec {
    Once { at_ms: i64 },
    Cron { cron: CronSpec },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickClaim {
    pub id: String,
    pub owner: String,
    pub generation: u64,
    pub due_ms: i64,
}

#[derive(Debug, Clone)]
pub struct Schedule {
    pub id: String,
    pub spec: ScheduleSpec,
    pub next_due_ms: i64,
    pub claim: Option<TickClaim>,
    pub generation: u64,
    pub last_run_ms: Option<i64>,
    pub done: bool,
}

#[derive(Debug, Default, Clone)]
pub struct ScheduleBook {
    schedules: BTreeMap<String, Schedule>,
    next_id: u64,
}

impl ScheduleBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_once(&mut self, at_ms: i64) -> String {
        self.next_id += 1;
        let id = format!("sch-{}", self.next_id);
        self.schedules.insert(
            id.clone(),
            Schedule { id: id.clone(), spec: ScheduleSpec::Once { at_ms }, next_due_ms: at_ms, claim: None, generation: 0, last_run_ms: None, done: false },
        );
        id
    }

    pub fn add_cron(&mut self, expression: &str, now_ms: i64) -> Result<String> {
        let cron = CronSpec::parse(expression)?;
        let next = next_cron(&cron, now_ms).ok_or_else(|| ZeroError::new(ErrorCode::InvalidInput, "cron never matches"))?;
        self.next_id += 1;
        let id = format!("sch-{}", self.next_id);
        self.schedules.insert(
            id.clone(),
            Schedule { id: id.clone(), spec: ScheduleSpec::Cron { cron }, next_due_ms: next, claim: None, generation: 0, last_run_ms: None, done: false },
        );
        Ok(id)
    }

    pub fn due(&self, now_ms: i64) -> Vec<(String, i64)> {
        self.schedules
            .values()
            .filter(|s| !s.done && s.claim.is_none() && now_ms >= s.next_due_ms)
            .map(|s| (s.id.clone(), s.next_due_ms))
            .collect()
    }

    /// Claim one tick. Missed ticks coalesce: the claim is for the stored due
    /// time, not for every interval that elapsed.
    pub fn claim(&mut self, id: &str, owner: &str, now_ms: i64) -> Result<TickClaim> {
        let schedule = self
            .schedules
            .get_mut(id)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("schedule `{id}`")))?;
        if schedule.done {
            return Err(ZeroError::new(ErrorCode::Conflict, "schedule is finished"));
        }
        if let Some(claim) = &schedule.claim {
            return Err(ZeroError::new(
                ErrorCode::Locked,
                format!("schedule `{id}` is already claimed by `{}`", claim.owner),
            ));
        }
        if now_ms < schedule.next_due_ms {
            return Err(ZeroError::new(ErrorCode::Conflict, "schedule is not due yet"));
        }
        schedule.generation += 1;
        let claim = TickClaim { id: id.into(), owner: owner.into(), generation: schedule.generation, due_ms: schedule.next_due_ms };
        schedule.claim = Some(claim.clone());
        Ok(claim)
    }

    /// Complete a claimed tick and schedule the next one (missed intervals are
    /// skipped, not replayed).
    pub fn complete(&mut self, claim: &TickClaim, now_ms: i64) -> Result<()> {
        let schedule = self
            .schedules
            .get_mut(&claim.id)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("schedule `{}`", claim.id)))?;
        let current = schedule.claim.as_ref().ok_or_else(|| ZeroError::new(ErrorCode::Conflict, "no claim"))?;
        if current.owner != claim.owner || current.generation != claim.generation {
            return Err(ZeroError::new(ErrorCode::Stale, "schedule claim is stale"));
        }
        schedule.last_run_ms = Some(now_ms);
        schedule.claim = None;
        match &schedule.spec {
            ScheduleSpec::Once { .. } => schedule.done = true,
            ScheduleSpec::Cron { cron } => {
                schedule.next_due_ms = next_cron(cron, now_ms.max(schedule.next_due_ms))
                    .ok_or_else(|| ZeroError::new(ErrorCode::InvalidInput, "cron has no next tick"))?;
            }
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Schedule> {
        self.schedules.get(id)
    }
}

/// Next matching minute strictly after `after_ms` (UTC).
pub fn next_cron(cron: &CronSpec, after_ms: i64) -> Option<i64> {
    let base = after_ms / 60_000 + 1;
    for offset in 0..(366 * 24 * 60) {
        let ms = (base + offset) * 60_000;
        let (year, month, day, hour, min, weekday) = civil(Timestamp::from_millis(ms));
        let _ = year;
        if cron.matches(min, hour, day, month, weekday) {
            return Some(ms);
        }
    }
    None
}

fn civil(ts: Timestamp) -> (i64, u32, u32, u32, u32, u32) {
    let secs = ts.millis().div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let weekday = (days + 4).rem_euclid(7) as u32; // 1970-01-01 is Thursday
    (y, m, d, (rem / 3600) as u32, ((rem % 3600) / 60) as u32, weekday)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------------------------------------------------------------------
// Limits and cancellation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_tokens: u64,
    pub max_steps: u64,
    pub max_time_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_tokens: 1_000_000, max_steps: 10_000, max_time_ms: 60 * 60 * 1000 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    Tokens,
    Steps,
    Time,
}

impl LimitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LimitKind::Tokens => "tokens",
            LimitKind::Steps => "steps",
            LimitKind::Time => "time",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CancelScope {
    token: Arc<AtomicBool>,
    children: Arc<Mutex<Vec<CancelScope>>>,
}

impl Default for CancelScope {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelScope {
    pub fn new() -> Self {
        Self { token: Arc::new(AtomicBool::new(false)), children: Arc::new(Mutex::new(Vec::new())) }
    }

    pub fn child(&self) -> CancelScope {
        let child = CancelScope::new();
        if let Ok(mut children) = self.children.lock() {
            children.push(child.clone());
        }
        child
    }

    pub fn cancel(&self) {
        self.token.store(true, Ordering::SeqCst);
        if let Ok(children) = self.children.lock() {
            for child in children.iter() {
                child.cancel();
            }
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.token.load(Ordering::SeqCst)
    }
}

pub struct AutonomyRun {
    pub goal: Goal,
    pub limits: Limits,
    pub cancel: CancelScope,
    pub started_ms: i64,
}

impl AutonomyRun {
    pub fn new(goal: Goal, limits: Limits, now_ms: i64) -> Self {
        Self { goal, limits, cancel: CancelScope::new(), started_ms: now_ms }
    }

    /// Account one step and its tokens/time; a limit stops the run with a reason.
    pub fn account(&mut self, tokens: u64, time_ms: u64, now_ms: i64) -> Result<()> {
        self.goal.account(tokens, 1, time_ms, now_ms);
        if self.goal.tokens_used > self.limits.max_tokens {
            return Err(ZeroError::new(ErrorCode::LimitExceeded, format!("token limit {} reached", self.limits.max_tokens)));
        }
        if self.goal.steps_used > self.limits.max_steps {
            return Err(ZeroError::new(ErrorCode::LimitExceeded, format!("step limit {} reached", self.limits.max_steps)));
        }
        if now_ms - self.started_ms > self.limits.max_time_ms as i64 {
            return Err(ZeroError::new(ErrorCode::LimitExceeded, format!("time limit {}ms reached", self.limits.max_time_ms)));
        }
        if self.cancel.is_cancelled() {
            return Err(ZeroError::new(ErrorCode::Cancelled, "the run was cancelled"));
        }
        Ok(())
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_store::session::{ENTRY_SCHEMA_VERSION, SessionMeta, Role};

    fn log(dir: &std::path::Path) -> SessionLog {
        SessionLog::create(
            dir.join("s.jsonl"),
            SessionMeta { schema: ENTRY_SCHEMA_VERSION, generation: 1, created_ts: 0, name: "aut".into(), project: None, parent: None },
        )
        .unwrap()
    }

    #[test]
    fn a_goal_survives_compaction_and_resume() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = log(dir.path());
        let mut goal = start_goal(&mut log, "g1", "ship M4", 0).unwrap();
        goal.account(120, 3, 500, 1);
        save_goal(&mut log, &goal, 2).unwrap();
        for i in 0..20 {
            log.append(3 + i, Entry::Message { role: Role::User, text: format!("m{i}"), tool_calls: vec![], tool_call_id: None }).unwrap();
        }
        log.append(50, Entry::Compaction { summary: "s".into(), keep_from_seq: 10, removed_entries: 10 }).unwrap();
        let records = log.records().unwrap();
        let visible = zero_store::session::visible_slice(&records);
        let loaded = load_goal(&visible).expect("goal survives");
        assert_eq!(loaded.objective, "ship M4");
        assert_eq!(loaded.tokens_used, 120);
        assert_eq!(loaded.steps_used, 3);
        assert_eq!(loaded.state, GoalState::Active);

        let mut loaded = loaded;
        loaded.pause(60);
        loaded.resume(61);
        loaded.clear(62);
        save_goal(&mut log, &loaded, 63).unwrap();
        let reopened = SessionLog::open(dir.path().join("s.jsonl")).unwrap();
        let visible = zero_store::session::visible_slice(&reopened.records().unwrap());
        assert_eq!(load_goal(&visible).unwrap().state, GoalState::Cleared);
    }

    #[test]
    fn heartbeats_pause_and_resume() {
        let mut book = HeartbeatBook::new();
        book.register(HeartbeatKind::User, 100, 0);
        book.register(HeartbeatKind::Agent, 100, 0);
        assert_eq!(book.tick(100).len(), 2);
        assert!(book.tick(101).is_empty());
        assert!(book.pause(HeartbeatKind::User));
        assert!(book.tick(250).iter().all(|k| *k != HeartbeatKind::User));
        assert!(book.resume(HeartbeatKind::User, 300));
        assert!(book.tick(400).contains(&HeartbeatKind::User));
    }

    #[test]
    fn missed_cron_ticks_coalesce_and_claims_are_exclusive() {
        let mut book = ScheduleBook::new();
        // Every minute.
        let id = book.add_cron("* * * * *", 0).unwrap();
        assert_eq!(book.due(5 * 60_000).len(), 1, "five missed minutes coalesce");
        let claim = book.claim(&id, "worker", 5 * 60_000).unwrap();
        assert!(book.claim(&id, "other", 5 * 60_000).is_err());
        book.complete(&claim, 5 * 60_000 + 1000).unwrap();
        assert!(book.get(&id).unwrap().last_run_ms.is_some());
        // The next tick is after completion, not a replay of the missed ones.
        assert_eq!(book.due(5 * 60_000 + 30_000).len(), 0);
        assert_eq!(book.due(6 * 60_000).len(), 1);
    }

    #[test]
    fn one_off_schedules_finish_after_one_tick() {
        let mut book = ScheduleBook::new();
        let id = book.add_once(1000);
        assert!(book.due(999).is_empty());
        let claim = book.claim(&id, "w", 1000).unwrap();
        book.complete(&claim, 1001).unwrap();
        assert!(book.get(&id).unwrap().done);
        assert!(book.due(2000).is_empty());
    }

    #[test]
    fn a_runaway_run_stops_at_the_limit_and_reports() {
        let mut run = AutonomyRun::new(Goal::new("g", "run", 0), Limits { max_tokens: 10, max_steps: 1000, max_time_ms: 10_000 }, 0);
        let mut steps = 0;
        loop {
            match run.account(1, 1, steps as i64) {
                Ok(()) => steps += 1,
                Err(e) => {
                    assert_eq!(e.code(), ErrorCode::LimitExceeded);
                    assert!(e.message().contains("token limit"));
                    break;
                }
            }
            assert!(steps < 100);
        }
        assert_eq!(steps, 10);
    }

    #[test]
    fn cancel_cascades_to_children() {
        let parent = CancelScope::new();
        let child = parent.child();
        let grandchild = child.child();
        parent.cancel();
        assert!(parent.is_cancelled());
        assert!(child.is_cancelled());
        assert!(grandchild.is_cancelled());
    }
}
