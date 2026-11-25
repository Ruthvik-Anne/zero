//! Mode transitions and persistence (POL-13, POL-14).

use crate::mode::Mode;
use serde::{Deserialize, Serialize};
use zero_store::session::{Entry, Record, SessionLog};
use zero_types::error::{ErrorCode, Result, ZeroError};

pub const MODE_STATE_KEY: &str = "policy.mode";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeState {
    pub mode: Mode,
    pub headless_ended: bool,
    pub version: u64,
    /// Calls already running when a transition happens; they finish and report.
    pub running_calls: u32,
}

impl ModeState {
    pub fn new(mode: Mode) -> Self {
        Self { mode, headless_ended: false, version: 1, running_calls: 0 }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TransitionContext {
    /// The user (or an approved plan) allows promotion out of plan.
    pub plan_approved: bool,
}

/// Transition table: plan promotes on approval; any mode to manual is immediate;
/// a headless run must be ended before an interactive mode can take over.
pub fn transition(state: &ModeState, to: Mode, ctx: TransitionContext) -> Result<ModeState> {
    if state.mode == to {
        return Ok(*state);
    }
    let mut next = *state;
    next.version += 1;
    if to == Mode::Manual {
        next.mode = Mode::Manual;
        next.headless_ended = true;
        return Ok(next);
    }
    match state.mode {
        Mode::Plan if matches!(to, Mode::SemiAuto | Mode::Auto) => {
            if !ctx.plan_approved {
                return Err(ZeroError::new(
                    ErrorCode::InvalidTransition,
                    "plan to semi-auto or auto requires an approved plan",
                ));
            }
            next.mode = to;
            Ok(next)
        }
        Mode::Headless if to.is_interactive() => {
            if !state.headless_ended {
                return Err(ZeroError::new(
                    ErrorCode::InvalidTransition,
                    "the headless run must end before an interactive mode takes over",
                ));
            }
            next.mode = to;
            Ok(next)
        }
        _ => Err(ZeroError::new(
            ErrorCode::InvalidTransition,
            format!("{} to {} is not an allowed transition", state.mode.as_str(), to.as_str()),
        )),
    }
}

/// End a headless run. Required before switching to an interactive mode other
/// than manual.
pub fn end_headless(state: &ModeState) -> Result<ModeState> {
    if state.mode != Mode::Headless {
        return Err(ZeroError::new(ErrorCode::InvalidTransition, "no headless run is active"));
    }
    let mut next = *state;
    next.headless_ended = true;
    next.version += 1;
    Ok(next)
}

/// Persist the mode for this session. Written as a `state` entry so compaction
/// keeps it.
pub fn persist(state: &ModeState, log: &mut SessionLog, ts: i64) -> Result<Record> {
    log.append(
        ts,
        Entry::State {
            key: MODE_STATE_KEY.into(),
            value: serde_json::to_value(state)?,
        },
    )
}

/// Load the latest persisted mode from a transcript (the last state entry wins).
pub fn load(records: &[Record]) -> Option<ModeState> {
    records
        .iter()
        .rev()
        .find_map(|r| match &r.entry {
            Entry::State { key, value } if key == MODE_STATE_KEY => serde_json::from_value(value.clone()).ok(),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_store::session::{SessionMeta, ENTRY_SCHEMA_VERSION};

    #[test]
    fn transition_matrix_with_in_flight_work() {
        let mut state = ModeState::new(Mode::Plan);
        state.running_calls = 2;

        // Plan cannot promote without approval.
        let err = transition(&state, Mode::Auto, TransitionContext::default()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidTransition);
        // With approval, running calls are preserved and continue.
        let promoted = transition(&state, Mode::Auto, TransitionContext { plan_approved: true }).unwrap();
        assert_eq!(promoted.mode, Mode::Auto);
        assert_eq!(promoted.running_calls, 2);
        assert!(promoted.version > state.version);

        // Any mode to manual is immediate.
        let manual = transition(&promoted, Mode::Manual, TransitionContext::default()).unwrap();
        assert_eq!(manual.mode, Mode::Manual);

        // Auto to plan is not allowed.
        assert!(transition(&manual_state(), Mode::Plan, TransitionContext::default()).is_err());
    }

    fn manual_state() -> ModeState {
        ModeState::new(Mode::Manual)
    }

    #[test]
    fn headless_must_end_before_an_interactive_mode() {
        let state = ModeState::new(Mode::Headless);
        let err = transition(&state, Mode::Auto, TransitionContext::default()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidTransition);

        let ended = end_headless(&state).unwrap();
        assert!(ended.headless_ended);
        let interactive = transition(&ended, Mode::Auto, TransitionContext::default()).unwrap();
        assert_eq!(interactive.mode, Mode::Auto);

        // Manual is immediate even from an active headless run.
        let manual = transition(&state, Mode::Manual, TransitionContext::default()).unwrap();
        assert_eq!(manual.mode, Mode::Manual);
        assert!(manual.headless_ended);
    }

    #[test]
    fn mode_persists_across_reopen_and_compaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        let mut log = SessionLog::create(
            &path,
            SessionMeta {
                schema: ENTRY_SCHEMA_VERSION,
                generation: 1,
                created_ts: 0,
                name: "modes".into(),
                project: None,
                parent: None,
            },
        )
        .unwrap();
        let state = ModeState { mode: Mode::SemiAuto, headless_ended: false, version: 4, running_calls: 1 };
        persist(&state, &mut log, 10).unwrap();
        for i in 0..20 {
            log.append(20 + i, Entry::Message {
                role: zero_store::session::Role::User,
                text: format!("m{i}"),
                tool_calls: vec![],
                tool_call_id: None,
            })
            .unwrap();
        }
        // A compaction record after the state entry.
        log.append(100, Entry::Compaction { summary: "s".into(), keep_from_seq: 15, removed_entries: 15 }).unwrap();
        drop(log);

        let log = SessionLog::open(&path).unwrap();
        let records = log.records().unwrap();
        let visible = zero_store::session::visible_slice(&records);
        let loaded = load(&visible).expect("mode survives compaction and reopen");
        assert_eq!(loaded, state);
    }

    #[test]
    fn invalid_transitions_report_typed_errors() {
        let state = ModeState::new(Mode::SemiAuto);
        assert_eq!(
            transition(&state, Mode::Plan, TransitionContext::default()).unwrap_err().code(),
            ErrorCode::InvalidTransition
        );
        assert!(end_headless(&state).is_err());
    }
}
