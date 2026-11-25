//! Window pause and resume (AR-03, AR-04, AR-06, AR-07, AR-08; T-AR-03).
//!
//! A usage, rate-limit, or budget window pauses a run at a safe boundary. The
//! pause records the session, the reset time, the generation, and the last
//! effect sequence. [`poll`] is pure: the caller supplies `now_ms`, the
//! remaining budget, and whether the current mode allows a resume.
//!
//! # Rules
//!
//! - A pause is accepted only at a safe boundary (`AR-06`) and only for a reset
//!   strictly in the future.
//! - Before the reset [`poll`] returns [`ResumeWindowOutcome::Waiting`] with the
//!   visibility fields of `AR-07`. A user may cancel or switch at any time.
//! - At or after the reset the run resumes only when the budget is positive and
//!   the mode allows it. A past reset is not a licence to resume: zero budget or
//!   a disallowing mode refuses (`AR-06`).
//! - Cancel is terminal and outranks resume and switch. A switch reports the
//!   target; it does not clear the window or the ledger, so it cannot evade a
//!   limit by rotating accounts (`AR-08`).
//! - A resume continues at `last_effect_seq + 1` and uses a snapshot when the
//!   journal compacted past the cursor or changed generation (`AR-03`). Executed
//!   effects are never re-executed (`AR-04`).

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Why a run is paused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowReason {
    /// A subscription usage window is exhausted.
    UsageLimit,
    /// The provider returned a rate limit.
    RateLimit,
    /// The run's cost budget is exhausted.
    Budget,
}

impl WindowReason {
    /// Stable snake-case name for logs and the journal.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UsageLimit => "usage_limit",
            Self::RateLimit => "rate_limit",
            Self::Budget => "budget",
        }
    }

    /// Short human label used by every surface.
    pub fn label(self) -> &'static str {
        match self {
            Self::UsageLimit => "usage limit",
            Self::RateLimit => "rate limit",
            Self::Budget => "budget",
        }
    }
}

/// A run paused on a window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PausedRun {
    /// Session that owns the run.
    pub session: String,
    /// Why the run paused.
    pub reason: WindowReason,
    /// When the pause happened.
    pub paused_at_ms: i64,
    /// When the window resets.
    pub reset_at_ms: i64,
    /// The last effect sequence that was executed before the pause.
    pub last_effect_seq: u64,
    /// The session generation at the pause.
    pub generation: u64,
    /// A user requested cancellation. Terminal: the run never resumes.
    pub cancel: bool,
    /// A user requested a switch to another target (model, provider, session).
    pub switch_requested: Option<String>,
}

impl PausedRun {
    /// The sequence a resume starts from: one past the last executed effect.
    pub fn from_seq(&self) -> u64 {
        self.last_effect_seq.saturating_add(1)
    }

    /// A user cancel. This is user-only; no agent tool can set it.
    pub fn request_cancel(&mut self) {
        self.cancel = true;
    }

    /// A user switch to `target`. This is user-only; no agent tool can set it.
    ///
    /// The window and the ledger are unchanged, so a switch cannot be used to
    /// evade a limit by rotating accounts (`AR-08`).
    pub fn request_switch(&mut self, target: impl Into<String>) {
        self.switch_requested = Some(target.into());
    }

    /// The shared visibility view for every surface (`AR-07`).
    ///
    /// Before the reset this describes the wait; `remaining_ms` is clamped at
    /// zero once the reset has passed.
    pub fn waiting_view(&self, now_ms: i64) -> WaitingView {
        WaitingView {
            reason: self.reason,
            reset_at_ms: self.reset_at_ms,
            remaining_ms: self.reset_at_ms.saturating_sub(now_ms).max(0),
            cancel_action: CANCEL_ACTION,
            switch_action: SWITCH_ACTION,
        }
    }
}

/// Pause a run on a window (`AR-06`).
///
/// The pause is refused unless the caller is at a safe boundary (no effect is
/// executing) and the reset is strictly in the future. The returned run records
/// the generation and the last executed effect so a resume can continue at
/// `last_effect_seq + 1` without replaying it (`AR-04`).
pub fn pause(
    session: impl Into<String>,
    at_safe_boundary: bool,
    reason: WindowReason,
    reset_at_ms: i64,
    last_effect_seq: u64,
    generation: u64,
    now_ms: i64,
) -> Result<PausedRun> {
    if !at_safe_boundary {
        return Err(ZeroError::new(
            ErrorCode::ResumeRefused,
            "cannot pause mid-effect; wait for the running call to reach a safe boundary",
        ));
    }
    if reset_at_ms <= now_ms {
        return Err(ZeroError::new(
            ErrorCode::ResumeRefused,
            format!(
                "pause refused: reset time {reset_at_ms} is not in the future (now {now_ms})"
            ),
        ));
    }
    Ok(PausedRun {
        session: session.into(),
        reason,
        paused_at_ms: now_ms,
        reset_at_ms,
        last_effect_seq,
        generation,
        cancel: false,
        switch_requested: None,
    })
}

/// What [`poll`] decided for a paused run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeWindowOutcome {
    /// Still before the reset. Every visibility field is available (`AR-07`).
    Waiting {
        reason: WindowReason,
        reset_at_ms: i64,
        can_cancel: bool,
        can_switch: bool,
    },
    /// The window reset and the run may continue after `from_seq`.
    Resume {
        from_seq: u64,
        generation: u64,
        reason: WindowReason,
    },
    /// The user cancelled. The run never resumes.
    Cancelled,
    /// The user asked to switch to `target`.
    Switched { target: String },
    /// The window reset but the run may not continue.
    Refused { reason: String },
}

/// Evaluate a paused run at `now_ms`.
///
/// Precedence, highest first:
///
/// 1. `cancel` returns [`ResumeWindowOutcome::Cancelled`]; it outranks a switch.
/// 2. A pending switch returns [`ResumeWindowOutcome::Switched`].
/// 3. Before the reset, [`ResumeWindowOutcome::Waiting`]. Zero budget or a
///    disallowing mode does not turn a wait into a refusal: the window or the
///    mode may change before the reset.
/// 4. At or after the reset, zero budget refuses. A reset in the past is not a
///    licence to resume.
/// 5. At or after the reset, a mode that does not allow a resume refuses.
/// 6. Otherwise resume at `last_effect_seq + 1` with the recorded generation.
pub fn poll(
    run: &PausedRun,
    now_ms: i64,
    budget_remaining_micros: u64,
    mode_allows: bool,
) -> ResumeWindowOutcome {
    if run.cancel {
        return ResumeWindowOutcome::Cancelled;
    }
    if let Some(target) = &run.switch_requested {
        return ResumeWindowOutcome::Switched { target: target.clone() };
    }
    if now_ms < run.reset_at_ms {
        return ResumeWindowOutcome::Waiting {
            reason: run.reason,
            reset_at_ms: run.reset_at_ms,
            can_cancel: true,
            can_switch: true,
        };
    }
    if budget_remaining_micros == 0 {
        return ResumeWindowOutcome::Refused {
            reason: format!(
                "over budget: no budget remains after the {} window reset",
                run.reason.label()
            ),
        };
    }
    if !mode_allows {
        return ResumeWindowOutcome::Refused {
            reason: "the current mode does not allow resume; cancel, switch, or change mode"
                .to_string(),
        };
    }
    ResumeWindowOutcome::Resume {
        from_seq: run.from_seq(),
        generation: run.generation,
        reason: run.reason,
    }
}

/// A user-only action shown while a run waits (`AR-07`).
///
/// Neither action has an agent tool: the agent may observe the waiting state but
/// cannot cancel or switch on the user's behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowAction {
    /// Stable action id rendered by every surface.
    pub id: &'static str,
    /// Button or menu label.
    pub label: &'static str,
}

impl WindowAction {
    /// Always true: cancel and switch are user-only.
    pub const fn user_only(self) -> bool {
        true
    }
}

/// The cancel action offered while waiting.
pub const CANCEL_ACTION: WindowAction =
    WindowAction { id: "resume.window.cancel", label: "Cancel" };

/// The switch action offered while waiting.
pub const SWITCH_ACTION: WindowAction =
    WindowAction { id: "resume.window.switch", label: "Switch" };

/// One deterministic view that every surface renders while a run waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitingView {
    /// Why the run is paused.
    pub reason: WindowReason,
    /// When the window resets.
    pub reset_at_ms: i64,
    /// Time until the reset, clamped at zero.
    pub remaining_ms: i64,
    /// The user-only cancel action.
    pub cancel_action: WindowAction,
    /// The user-only switch action.
    pub switch_action: WindowAction,
}

impl WaitingView {
    /// Deterministic one-line text shared by the TUI, desktop, web, and Android.
    pub fn render_line(&self) -> String {
        format!(
            "paused: {}; reset at {} (in {} ms); actions: {} (user only), {} (user only)",
            self.reason.label(),
            self.reset_at_ms,
            self.remaining_ms,
            self.cancel_action.label,
            self.switch_action.label
        )
    }
}

/// A reconnect cursor: a generation plus the next sequence to deliver (`AR-03`).
///
/// `sequence` is exclusive: every event before it was already seen, so a resume
/// starts at `sequence`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeCursor {
    pub generation: u64,
    pub sequence: u64,
}

impl ResumeCursor {
    pub fn new(generation: u64, sequence: u64) -> Self {
        Self { generation, sequence }
    }
}

/// Where the journal currently is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalProgress {
    /// Current session generation.
    pub generation: u64,
    /// Next sequence the journal will assign (head + 1).
    pub sequence: u64,
    /// Oldest sequence still retained after compaction, when compacted.
    pub retained_from: Option<u64>,
}

impl JournalProgress {
    /// A journal with no compaction.
    pub fn new(generation: u64, sequence: u64) -> Self {
        Self { generation, sequence, retained_from: None }
    }

    /// A journal that compacted and now retains events from `retained_from`.
    pub fn with_retained_from(mut self, retained_from: u64) -> Self {
        self.retained_from = Some(retained_from);
        self
    }
}

/// How a resume reconstructs state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplaySource {
    /// Rebuild from the latest snapshot; no earlier event is read.
    Snapshot,
    /// Read journal events starting at `from_seq` (inclusive).
    EventsFrom { from_seq: u64 },
}

/// The plan for resuming a session at a cursor (`AR-03`, `AR-04`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayPlan {
    /// Snapshot or events.
    pub source: ReplaySource,
    /// Generation the plan resumes into.
    pub generation: u64,
    /// Next sequence the caller will append after replay (journal head + 1).
    pub next_sequence: u64,
    /// Executed effect sequences the plan would re-execute. The planner never
    /// populates this, because it only reads journal events; the field exists so
    /// a caller that attaches an effect list can assert `AR-04`.
    pub replayed_effects: Vec<u64>,
}

impl ReplayPlan {
    /// The event start, when the plan replays events.
    pub fn from_seq(&self) -> Option<u64> {
        match self.source {
            ReplaySource::Snapshot => None,
            ReplaySource::EventsFrom { from_seq } => Some(from_seq),
        }
    }

    /// True when the plan rebuilds from a snapshot.
    pub fn is_snapshot(&self) -> bool {
        matches!(self.source, ReplaySource::Snapshot)
    }

    /// Attach the effects a caller believes the plan would re-execute.
    ///
    /// The planner itself never does this; it is the hook that lets
    /// [`assert_no_effect_replay`] reject a plan that reaches back across an
    /// executed effect.
    pub fn with_replayed_effects(mut self, effects: impl IntoIterator<Item = u64>) -> Self {
        self.replayed_effects = effects.into_iter().collect();
        self
    }
}

/// Choose `Snapshot` or `EventsFrom(cursor.sequence)` (`AR-03`).
///
/// A snapshot is used when the generation changed, when the cursor is ahead of
/// the journal, or when compaction removed events at or before the cursor. At
/// the retained boundary the events are still available, so the plan replays
/// from there.
pub fn resume_from(cursor: ResumeCursor, journal: JournalProgress) -> ReplayPlan {
    let compacted_past_cursor =
        matches!(journal.retained_from, Some(retained) if cursor.sequence < retained);
    let source = if cursor.generation != journal.generation
        || cursor.sequence > journal.sequence
        || compacted_past_cursor
    {
        ReplaySource::Snapshot
    } else {
        ReplaySource::EventsFrom { from_seq: cursor.sequence }
    };
    ReplayPlan {
        source,
        generation: journal.generation,
        next_sequence: journal.sequence,
        replayed_effects: Vec::new(),
    }
}

/// Refuse a plan that would re-execute an effect at or before `last_effect_seq`.
///
/// A snapshot always passes: it reconstructs state without executing anything.
/// An event plan passes only when it starts after the last executed effect, and
/// no named effect is at or before it.
pub fn assert_no_effect_replay(plan: &ReplayPlan, last_effect_seq: u64) -> Result<()> {
    if let Some(seq) =
        plan.replayed_effects.iter().copied().find(|seq| *seq <= last_effect_seq)
    {
        return Err(ZeroError::new(
            ErrorCode::ResumeRefused,
            format!(
                "resume would re-execute effect {seq}, at or before last_effect_seq {last_effect_seq}"
            ),
        ));
    }
    if let ReplaySource::EventsFrom { from_seq } = plan.source {
        if from_seq <= last_effect_seq {
            return Err(ZeroError::new(
                ErrorCode::ResumeRefused,
                format!(
                    "resume would replay events from {from_seq}, at or before last_effect_seq {last_effect_seq}"
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;
    const RESET: i64 = NOW + 60_000;
    const GEN: u64 = 3;
    const EFFECT: u64 = 41;
    const BUDGET: u64 = 5_000;

    fn paused() -> PausedRun {
        pause("s1", true, WindowReason::UsageLimit, RESET, EFFECT, GEN, NOW).unwrap()
    }

    #[test]
    fn pause_records_the_boundary_and_cursor() {
        let run = paused();
        assert_eq!(run.session, "s1");
        assert_eq!(run.reason, WindowReason::UsageLimit);
        assert_eq!(run.paused_at_ms, NOW);
        assert_eq!(run.reset_at_ms, RESET);
        assert_eq!(run.last_effect_seq, EFFECT);
        assert_eq!(run.generation, GEN);
        assert!(!run.cancel);
        assert_eq!(run.switch_requested, None);
        assert_eq!(run.from_seq(), EFFECT + 1, "a resume starts after the last effect");
    }

    #[test]
    fn pause_is_refused_off_the_safe_boundary() {
        let err =
            pause("s1", false, WindowReason::RateLimit, RESET, EFFECT, GEN, NOW).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResumeRefused);
        assert!(err.message().contains("safe boundary"), "{}", err.message());
    }

    #[test]
    fn pause_requires_a_reset_in_the_future() {
        for reset in [NOW, NOW - 1, i64::MIN] {
            let err =
                pause("s1", true, WindowReason::Budget, reset, EFFECT, GEN, NOW).unwrap_err();
            assert_eq!(err.code(), ErrorCode::ResumeRefused);
            assert!(err.message().contains("future"), "{}", err.message());
        }
    }

    #[test]
    fn waiting_before_the_reset_exposes_visibility() {
        let run = paused();
        let view = run.waiting_view(NOW + 15_000);
        assert_eq!(view.reason, WindowReason::UsageLimit);
        assert_eq!(view.reset_at_ms, RESET);
        assert_eq!(view.remaining_ms, 45_000);
        assert_eq!(view.cancel_action.id, CANCEL_ACTION.id);
        assert_eq!(view.switch_action.id, SWITCH_ACTION.id);
        assert!(view.cancel_action.user_only(), "cancel has no agent tool");
        assert!(view.switch_action.user_only(), "switch has no agent tool");
        assert_eq!(
            view.render_line(),
            "paused: usage limit; reset at 1060000 (in 45000 ms); actions: Cancel (user only), Switch (user only)"
        );
        assert_eq!(
            run.waiting_view(NOW + 15_000).render_line(),
            view.render_line(),
            "the view is deterministic"
        );

        match poll(&run, NOW + 15_000, 0, false) {
            ResumeWindowOutcome::Waiting { reason, reset_at_ms, can_cancel, can_switch } => {
                assert_eq!(reason, WindowReason::UsageLimit);
                assert_eq!(reset_at_ms, RESET);
                assert!(can_cancel);
                assert!(can_switch);
            }
            other => panic!("expected Waiting, got {other:?}"),
        }
    }

    #[test]
    fn waiting_remaining_time_clamps_at_zero() {
        let run = paused();
        assert_eq!(run.waiting_view(RESET).remaining_ms, 0);
        assert_eq!(run.waiting_view(RESET + 10_000).remaining_ms, 0);
    }

    #[test]
    fn resume_exactly_at_and_after_the_reset() {
        let run = paused();
        for now in [RESET, RESET + 1, RESET + 86_400_000] {
            assert_eq!(
                poll(&run, now, BUDGET, true),
                ResumeWindowOutcome::Resume {
                    from_seq: EFFECT + 1,
                    generation: GEN,
                    reason: WindowReason::UsageLimit,
                },
                "resume at {now}"
            );
        }
    }

    #[test]
    fn a_past_reset_with_zero_budget_never_resumes() {
        let run = paused();
        for now in [RESET, RESET + 86_400_000] {
            match poll(&run, now, 0, true) {
                ResumeWindowOutcome::Refused { reason } => {
                    assert!(reason.contains("budget"), "{reason}");
                }
                other => panic!("zero budget at {now} must refuse, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_disallowing_mode_refuses_after_the_reset() {
        match poll(&paused(), RESET, BUDGET, false) {
            ResumeWindowOutcome::Refused { reason } => {
                assert!(reason.contains("mode"), "{reason}");
            }
            other => panic!("a disallowing mode must refuse, got {other:?}"),
        }
        assert!(
            matches!(poll(&paused(), RESET - 1, BUDGET, false), ResumeWindowOutcome::Waiting { .. }),
            "before the reset the mode is re-checked at resume, not at wait"
        );
    }

    #[test]
    fn cancel_is_terminal_and_never_resumes() {
        let mut run = paused();
        run.request_cancel();
        assert_eq!(poll(&run, RESET - 1, BUDGET, true), ResumeWindowOutcome::Cancelled);
        assert_eq!(poll(&run, RESET + 1, BUDGET, true), ResumeWindowOutcome::Cancelled);

        run.request_switch("model:other");
        assert_eq!(poll(&run, RESET + 1, BUDGET, true), ResumeWindowOutcome::Cancelled);
    }

    #[test]
    fn switch_reports_the_target_before_or_after_the_reset() {
        let mut run = paused();
        run.request_switch("model:other");
        assert_eq!(
            poll(&run, NOW, BUDGET, true),
            ResumeWindowOutcome::Switched { target: "model:other".to_string() }
        );
        assert_eq!(
            poll(&run, RESET + 1, BUDGET, true),
            ResumeWindowOutcome::Switched { target: "model:other".to_string() }
        );
    }

    #[test]
    fn a_generation_change_forces_a_snapshot() {
        let journal = JournalProgress::new(2, 20).with_retained_from(1);
        let plan = resume_from(ResumeCursor::new(1, 10), journal);
        assert!(plan.is_snapshot(), "{plan:?}");
        assert_eq!(plan.from_seq(), None);
        assert_eq!(plan.generation, 2);
        assert_eq!(plan.next_sequence, 20);
        assert!(plan.replayed_effects.is_empty());
        assert_no_effect_replay(&plan, EFFECT).unwrap();
    }

    #[test]
    fn a_compacted_journal_forces_a_snapshot() {
        let journal = JournalProgress::new(1, 20).with_retained_from(11);
        let plan = resume_from(ResumeCursor::new(1, 5), journal);
        assert_eq!(plan.source, ReplaySource::Snapshot);

        let at_boundary = resume_from(ResumeCursor::new(1, 11), journal);
        assert_eq!(at_boundary.source, ReplaySource::EventsFrom { from_seq: 11 });
        assert_eq!(at_boundary.next_sequence, 20);

        let ahead = resume_from(ResumeCursor::new(1, 21), journal);
        assert_eq!(ahead.source, ReplaySource::Snapshot, "a cursor ahead of the journal");
    }

    #[test]
    fn resume_replays_events_after_the_cursor() {
        let journal = JournalProgress::new(1, 9).with_retained_from(3);
        let plan = resume_from(ResumeCursor::new(1, 5), journal);
        assert_eq!(plan.source, ReplaySource::EventsFrom { from_seq: 5 });
        assert_eq!(plan.from_seq(), Some(5));
        assert_eq!(plan.generation, 1);
        assert_eq!(plan.next_sequence, 9);
    }

    /// The Done criterion for T-AR-03: a simulated reset resumes at
    /// `last_effect_seq + 1` and never replays an executed effect.
    #[test]
    fn a_simulated_reset_resumes_without_replaying_effects() {
        let run = pause("s1", true, WindowReason::RateLimit, RESET, EFFECT, GEN, NOW).unwrap();

        let view = run.waiting_view(NOW + 1_000);
        assert!(view.render_line().contains("rate limit"), "{}", view.render_line());

        let ResumeWindowOutcome::Resume { from_seq, generation, .. } =
            poll(&run, RESET, BUDGET, true)
        else {
            panic!("a simulated reset with budget and an allowing mode must resume");
        };
        assert_eq!(from_seq, EFFECT + 1, "resume starts after the last executed effect");
        assert_eq!(generation, GEN);

        let plan = resume_from(
            ResumeCursor::new(generation, from_seq),
            JournalProgress::new(generation, from_seq + 3),
        );
        assert_eq!(plan.source, ReplaySource::EventsFrom { from_seq: EFFECT + 1 });
        assert!(plan.replayed_effects.is_empty());
        assert_eq!(plan.next_sequence, EFFECT + 4);
        assert_no_effect_replay(&plan, EFFECT).unwrap();
        for seq in &plan.replayed_effects {
            assert!(*seq > EFFECT, "effect {seq} at or before {EFFECT} was replayed");
        }

        let stale = ReplayPlan {
            source: ReplaySource::EventsFrom { from_seq: EFFECT },
            generation: GEN,
            next_sequence: EFFECT + 1,
            replayed_effects: Vec::new(),
        };
        let err = assert_no_effect_replay(&stale, EFFECT).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResumeRefused);
        assert!(err.message().contains("replay events from"), "{}", err.message());

        let named = ReplayPlan { source: ReplaySource::Snapshot, ..stale }
            .with_replayed_effects([EFFECT]);
        let err = assert_no_effect_replay(&named, EFFECT).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResumeRefused);
        assert!(err.message().contains("re-execute effect"), "{}", err.message());
    }

    #[test]
    fn window_types_round_trip_through_json() {
        let run = paused();
        let restored: PausedRun =
            serde_json::from_str(&serde_json::to_string(&run).unwrap()).unwrap();
        assert_eq!(restored, run);

        for reason in [WindowReason::UsageLimit, WindowReason::RateLimit, WindowReason::Budget] {
            let text = serde_json::to_string(&reason).unwrap();
            assert_eq!(serde_json::from_str::<WindowReason>(&text).unwrap(), reason);
            assert_eq!(reason.as_str().replace('_', " "), reason.label());
        }

        let cursor = ResumeCursor::new(2, 7);
        let restored: ResumeCursor =
            serde_json::from_str(&serde_json::to_string(&cursor).unwrap()).unwrap();
        assert_eq!(restored, cursor);

        let plan = resume_from(cursor, JournalProgress::new(2, 9));
        let restored: ReplayPlan =
            serde_json::from_str(&serde_json::to_string(&plan).unwrap()).unwrap();
        assert_eq!(restored, plan);

        let outcome = poll(&paused(), RESET, BUDGET, true);
        let restored: ResumeWindowOutcome =
            serde_json::from_str(&serde_json::to_string(&outcome).unwrap()).unwrap();
        assert_eq!(restored, outcome);
    }
}
