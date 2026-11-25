# Auto-resume

T-AR-02 (`AR-02`, `AR-04`, `AR-05`). The policy lives in
`crates/zero-agent/src/resume.rs` and is re-exported from the crate root. It is
pure: the caller supplies `now_ms`, the result is a plan, and nothing sleeps.
Retries are described by `ResumeAttempt { attempt, next_at_ms }`; the caller
owns the timer.

T-AR-03 adds the window pause/resume state machine in
`crates/zero-agent/src/resume_window.rs`, also re-exported from the crate root.
It is pure in the same way: `poll` takes `now_ms`, the remaining budget, and
whether the mode allows a resume.

`zero-agent` already has a `ResumeCause` for monitor restarts (`MON-12`). The
auto-resume cause is re-exported at the crate root as `AgentResumeCause`; the
unambiguous paths are `zero_agent::resume::ResumeCause` and
`zero_agent::monitor_restart::ResumeCause`.

## Causes

| Cause | Meaning |
|---|---|
| `DaemonRestart` | The daemon restarted while the run was live. |
| `Crash` | The process crashed. |
| `Reboot` | The machine rebooted. |
| `Disconnect` | The daemon or provider connection was lost. |
| `Teleport` | The session moved to another device or daemon. |
| `DeviceChanged` | The same session is now observed on a different device. |
| `UsageWindow` | A subscription usage or rate-limit window closed. |

## Policy

`ResumePolicy` is copied into every decision. No field bypasses the attempt
bound, the ledger budget, or uncertain effects. A missing field in JSON falls
back to the default (`#[serde(default)]`).

| Field | Default | Rule |
|---|---|---|
| `auto` | `true` | Automatic resume for causes that need no prompt (`AR-02`). |
| `device_prompt` | `true` | Prompt on a device change instead of resuming across devices. A teleport prompts regardless. |
| `max_attempts` | `3` | Total attempts allowed, including the first. `attempts_used >= max_attempts` refuses. |
| `initial_backoff_ms` | `1_000` | Delay before the first retry (attempt 2). The first attempt is immediate. |
| `max_backoff_ms` | `60_000` | Ceiling for the exponential retry backoff. |
| `budget_allowed` | `true` | Operator veto. When false, every resume is refused regardless of the ledger; a prompt is suppressed because approval could not lead to a resume. |

The observed state is `ResumeContext`:

```text
ResumeContext {
  attempts_used: u32,
  budget_remaining_micros: u64,   // zero means over budget
  device_matches: bool,
  usage_reset_ms: Option<i64>,    // known reset of a usage/rate-limit window
  uncertain_effects: bool,        // journaled begin without a result (AR-04)
}
```

## Decision matrix

`decide(cause, policy, context, now_ms) -> ResumePlan`. A plan is exactly one of
`Auto`, `Prompt { reason }`, `Refuse { reason }`, or
`Wait { until_ms, reason }`, plus `attempt: Option<ResumeAttempt>`. Only `Auto`
carries an attempt; a prompt, refusal, or wait schedules nothing.

Rows assume the default policy unless the cell says otherwise. "Budget" means
`budget_remaining_micros > 0`; "attempts" means `attempts_used < max_attempts`.

| Cause | Budget, same device, no uncertainty | Device differs | Uncertain effects | Budget 0, no reset | Budget 0, future reset | Attempts used == max |
|---|---|---|---|---|---|---|
| `DaemonRestart` | `Auto` | `Prompt` | `Prompt` | `Refuse` over budget | `Wait` until reset | `Refuse` attempt limit |
| `Crash` | `Auto` | `Prompt` | `Prompt` | `Refuse` over budget | `Wait` until reset | `Refuse` attempt limit |
| `Reboot` | `Auto` | `Prompt` | `Prompt` | `Refuse` over budget | `Wait` until reset | `Refuse` attempt limit |
| `Disconnect` | `Auto` | `Prompt` | `Prompt` | `Refuse` over budget | `Wait` until reset | `Refuse` attempt limit |
| `DeviceChanged` | `Prompt` | `Prompt` | `Prompt` (device reason plus uncertainty) | `Refuse` over budget | `Wait` until reset | `Refuse` attempt limit |
| `Teleport` | `Prompt` | `Prompt` | `Prompt` (teleport reason plus uncertainty) | `Refuse` over budget | `Wait` until reset | `Refuse` attempt limit |
| `UsageWindow`, reset in the future | `Wait` until reset | `Wait` until reset | `Wait` until reset | n/a (the row fixes a reset) | `Wait` until reset | `Refuse` attempt limit |
| `UsageWindow`, reset reached | `Auto` | `Prompt` | `Prompt` | `Refuse` over budget | n/a | `Refuse` attempt limit |

`DeviceChanged` prompts even when `device_matches` is true: the cause itself is
the observation. It refuses when `device_prompt` is false. `auto: false` does not
silence the prompt, because a prompt is not automatic; it only removes the
automatic path. `UsageWindow` with `auto: false` refuses rather than waiting,
because it would never take the automatic step at reset.

### Precedence

The rules are applied in this order. The order is observable and tested.

1. Attempt bound. `attempts_used >= max_attempts` refuses. This outranks a
   device prompt, a usage wait, and a budget wait: a run with no attempts left
   is not resumed by any cause.
2. Policy budget veto. `budget_allowed == false` refuses. This outranks a usage
   wait and a device or teleport prompt.
3. Usage window. With `UsageWindow` and a future reset, the plan waits — even
   with zero budget. With no known reset it refuses (over budget when the budget
   is also zero). With `auto == false` it refuses. Once the reset is reached
   (`now_ms >= reset`), the cause continues through the normal checks below.
4. Ledger budget. `budget_remaining_micros == 0` refuses, unless a future reset
   is known, in which case it waits. This outranks a device or teleport prompt:
   there is no point asking to resume when approval could not lead to a resume.
5. Teleport. Always prompts, even when `device_prompt` is false. Teleport is a
   device/daemon move by definition, and `AR-02` requires a prompt when the
   device changed.
6. Device. `device_matches == false`, or `DeviceChanged`, prompts when
   `device_prompt` is true and refuses otherwise.
7. Uncertain effects. A run with a journaled `begin` and no result prompts and
   is never automatic (`AR-04`).
8. Automatic switch. `auto == false` refuses.
9. Otherwise `Auto` with the next bounded attempt.

The prompt reason is a stable sentence. When uncertain effects are also present
on a device or teleport prompt, the reason says they will not be replayed.
`ResumeDecision::reason()` and `ResumeDecision::until_ms()` expose the reason and
the wait target for the UI (`AR-07`).

## Backoff

The first attempt is immediate (`next_at_ms == now_ms`). Retry `n + 1`, after `n`
used attempts, waits:

```text
delay(n) = min(cap, initial * 2^(n - 1))    for n >= 1
cap      = max(0, max_backoff_ms)
initial  = clamp(initial_backoff_ms, 0, cap)
```

With the defaults (`initial = 1_000`, `cap = 60_000`):

| `attempts_used` | Attempt | Delay |
|---|---|---|
| 0 | 1 | 0 ms (immediate) |
| 1 | 2 | 1 s |
| 2 | 3 | 2 s |
| 3 | 4 | 4 s |
| 4 | 5 | 8 s |
| 7 | 8 | 60 s (capped) |

Negative values are clamped to zero, a zero cap makes every retry immediate, and
`now_ms + delay` saturates at `i64::MAX`. `attempt` is 1-based and equals
`attempts_used + 1`.

## Budget and usage-window waits

`budget_remaining_micros == 0` refuses with an over-budget reason. When
`usage_reset_ms` names a future reset, the plan waits instead:

```text
Wait { until_ms: reset_ms, reason: "budget exhausted; waiting for the usage window to reset" }
```

A reset in the past is not a licence to resume: it refuses as over budget. The
same wait applies to `UsageWindow` even with a positive budget, with the reason
`usage window is open; waiting for the reset`. `UsageWindow` with no reset time
refuses because there is no time to wait for. At exactly `now_ms == reset_ms` the
window counts as reset and the normal automatic checks apply.

The plan does not sleep or spawn a timer. The caller waits until `until_ms`,
then calls `decide` again with a fresh context.

## Device prompt

`AR-02` requires a prompt when the device changed. A device mismatch on any
cause other than teleport is treated as `DeviceChanged`: it prompts when
`device_prompt` is true and refuses when it is false. A prompt never resumes
anything; it is a request for approval.

## Uncertain effects (`AR-04`)

`uncertain_effects` is true when the loop journal holds a `begin` without an
`applied` result (`zero.ses.command_uncertain`). The policy never returns `Auto`
for such a run. It returns `Prompt` so the effect is surfaced, and the loop
still refuses to replay the command. This check runs after budget and device, so
a refusal already expresses the stronger hard bound; on a device or teleport
prompt the reason also mentions that the uncertain effects will not be replayed.

## Children (`AR-05`)

`children_plan(parent: &ResumePlan, children: ResumeChildren) -> ChildrenResume`
resumes goals, heartbeats, schedules, and subagents only when the root plan is
`Auto`. Each `ChildTask { id, next_at_ms }` keeps its time exactly: a heartbeat
or a schedule is not brought forward, and a goal or subagent with no timer keeps
`next_at_ms: None`.

| Parent decision | `ChildrenResume` |
|---|---|
| `Auto` | `resumed: true`; all four lists copied with their times |
| `Prompt` | `resumed: false`; all lists empty; reason says approval is pending |
| `Refuse` | `resumed: false`; all lists empty; the root reason is included |
| `Wait` | `resumed: false`; all lists empty; reason names `until_ms` |

A prompt is not approval. After the user approves, the caller re-decides with
the approved context — for a device prompt that means the device now matches and
the root cause is restored — and the resulting `Auto` plan resumes the children
with the original times.

## Window resume (`AR-03`, `AR-06`, `AR-07`, `AR-08`)

A usage, rate-limit, or budget window pauses a run instead of failing it. The
state lives in `PausedRun`:

```text
PausedRun {
  session: String,
  reason: WindowReason,          // UsageLimit | RateLimit | Budget
  paused_at_ms: i64,
  reset_at_ms: i64,
  last_effect_seq: u64,
  generation: u64,
  cancel: bool,                  // user-only
  switch_requested: Option<String>, // user-only
}
```

### Pause boundary (`AR-06`)

```text
pause(session, at_safe_boundary, reason, reset_at_ms, last_effect_seq, generation, now_ms)
  -> Result<PausedRun>
```

The pause is accepted only when `at_safe_boundary` is true: no effect may be
executing. Otherwise it returns `zero.ar.refused` with a message naming the safe
boundary. The reset must be strictly in the future (`reset_at_ms > now_ms`); an
equal or past reset is also refused, because there would be nothing to wait for.
The returned run records the generation and `last_effect_seq` so a resume
continues at `last_effect_seq + 1`.

### Poll and resume matrix

`poll(&PausedRun, now_ms, budget_remaining_micros, mode_allows)` is pure and
returns exactly one outcome. Precedence is top to bottom.

| State | Budget | Mode | Outcome |
|---|---|---|---|
| `cancel == true` | any | any | `Cancelled` (terminal; outranks switch and resume) |
| `switch_requested == Some(target)` | any | any | `Switched { target }` |
| before the reset | any | any | `Waiting { reason, reset_at_ms, can_cancel: true, can_switch: true }` |
| at/after the reset | `0` | any | `Refused` over budget |
| at/after the reset | `> 0` | disallowed | `Refused` mode disallows resume |
| at/after the reset | `> 0` | allowed | `Resume { from_seq: last_effect_seq + 1, generation, reason }` |

Before the reset, zero budget and a disallowing mode still wait: the budget or
the mode may change before the window closes. At or after the reset both are
re-checked. A past reset is never a licence to resume on its own; a stale reset
with zero budget refuses, as does a disallowing mode. The caller supplies
`now_ms` and does not sleep inside this module.

A switch only reports the target. It does not clear the window, the ledger, or
the cursor, so switching cannot evade a limit by rotating accounts (`AR-08`);
the next run is evaluated against the same window and budget.

### Visibility (`AR-07`)

Every surface consumes one `WaitingView`:

```text
WaitingView {
  reason: WindowReason,
  reset_at_ms: i64,
  remaining_ms: i64,          // clamped at zero
  cancel_action: WindowAction,
  switch_action: WindowAction,
}
```

`render_line()` is deterministic, for example:

```text
paused: usage limit; reset at 1060000 (in 45000 ms); actions: Cancel (user only), Switch (user only)
```

Both actions are user-only (`CANCEL_ACTION`, `SWITCH_ACTION`); neither has an
agent tool. `PausedRun::request_cancel` and `PausedRun::request_switch` are the
host-side setters.

### Generation, sequence, and no replay (`AR-03`, `AR-04`)

`ResumeCursor { generation, sequence }` uses an exclusive sequence: every event
before `sequence` was already seen, so a resume starts there.
`resume_from(cursor, JournalProgress)` returns a `ReplayPlan`:

| Condition | Source |
|---|---|
| generation changed | `Snapshot` |
| cursor is ahead of the journal | `Snapshot` |
| compaction removed events at or before the cursor | `Snapshot` |
| otherwise | `EventsFrom { from_seq: cursor.sequence }` |

At the retained boundary (`cursor.sequence == retained_from`) the events are
still present, so the plan replays from there. The plan exposes
`next_sequence` (the journal head, one past the last appended event) and
`replayed_effects: Vec<u64>`. The planner only reads journal events, so it never
names an effect to re-execute. `assert_no_effect_replay(&plan, last_effect_seq)`
rejects any plan whose event start or named effect is at or before
`last_effect_seq`; a snapshot always passes because it executes nothing.

## Tests

`resume::tests` is deterministic (no sleeps, a fixed `NOW`). The Done criterion
is `resume_matrix_decisions`: 56 table rows over all seven causes and the states
(attempts 0 and max, budget zero and positive, device same and different,
uncertain effects, usage reset future/past/absent, policy vetoes), asserting the
decision variant and the reason. `backoff_grows_exponentially_and_is_capped`
covers delay growth and the cap; `zero_negative_and_saturating_backoff_is_safe`
covers clamping and overflow; `daemon_restart_resumes_children_with_their_times`
and `device_change_prompts_and_does_not_resume_children_before_approval` cover
`AR-05`, and `refused_and_waiting_parents_resume_no_children` proves a refused or
waiting root never resumes a child. `policy_and_plan_round_trip_through_json`
proves a partial policy keeps its defaults and a plan survives a journal round
trip (`AR-01`).

Evidence from this change (Windows, PowerShell):

```text
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-agent resume -j 1
  lib: 16 passed, 0 failed (10 new resume tests; 6 pre-existing names also match "resume")
  integration: monitors 1 passed, summary_resume 1 passed
  total: 18 passed, 0 failed

$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-agent --all-targets -j 1 -- -D warnings
  Finished `dev` profile; no warnings
```

The filter also runs tests whose names contain "resume" from other modules
(autonomy, artifacts, the loop, export, tree, monitors, summary fixtures); they
all pass.

`resume_window::tests` adds 15 deterministic tests for `AR-03`, `AR-06`, and
`AR-07`: `pause_records_the_boundary_and_cursor`,
`pause_is_refused_off_the_safe_boundary`, `pause_requires_a_reset_in_the_future`,
`waiting_before_the_reset_exposes_visibility`,
`waiting_remaining_time_clamps_at_zero`, `resume_exactly_at_and_after_the_reset`,
`a_past_reset_with_zero_budget_never_resumes`,
`a_disallowing_mode_refuses_after_the_reset`,
`cancel_is_terminal_and_never_resumes`,
`switch_reports_the_target_before_or_after_the_reset`,
`a_generation_change_forces_a_snapshot`,
`a_compacted_journal_forces_a_snapshot`,
`resume_replays_events_after_the_cursor`, and `window_types_round_trip_through_json`.
The Done criterion is `a_simulated_reset_resumes_without_replaying_effects`: a
paused run at `last_effect_seq = 41` resumes from sequence 42 at the reset, the
reconnect plan is `EventsFrom { from_seq: 42 }`, `replayed_effects` is empty, and
both an event plan from 41 and a plan naming effect 41 are refused.

Evidence from this change (Windows, PowerShell):

```text
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-agent resume -j 1
  lib: 31 passed, 0 failed (15 new resume_window tests)
  integration: monitors 1 passed, summary_resume 1 passed
  total: 33 passed, 0 failed

$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-agent --all-targets -j 1 -- -D warnings
  Finished `dev` profile; no warnings
```

