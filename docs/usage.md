# Usage ledger

`zero_sched::usage_ledger` implements USG-01, USG-02, USG-08, and the usage
half of AUT-06. It records one event per unit of billed work, keeps each
device's ledger append-only, merges devices by union, and attributes child and
subagent usage to its parent. Nothing in this module writes telemetry or talks
to a provider.

## Event schema

One event is one JSON object per line:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable id derived from the tuple below. |
| `device` | string | Device that observed the work. |
| `session` | string | Session that owns the work. |
| `model` | string | Model id that was called. |
| `provider` | string | Provider id that served the call. |
| `tool` | string or null | Tool that caused the call, when any. |
| `input_tokens` | u64 | Prompt tokens billed. |
| `output_tokens` | u64 | Completion tokens billed. |
| `cache_read_tokens` | u64 | Tokens read from the prompt cache. |
| `cache_write_tokens` | u64 | Tokens written to the prompt cache. |
| `cost_micros` | u64 | Cost in millionths of the billing currency unit. |
| `wall_ms` | u64 | End-to-end wall time in milliseconds. |
| `retries` | u32 | Retry attempts charged to this event. |
| `parent_id` | string or null | Parent event for a child or subagent call. |
| `subagent_share_bps` | u32 | Recorded share in basis points, `0..=10 000`. |
| `at_ms` | i64 | Observation time, Unix milliseconds. |

Counts are unsigned, so negative values are unrepresentable. Empty `device`,
`session`, `model`, `provider`, or `id` is rejected with
`zero.fnd.invalid_input`; so is a share above 10 000 or an empty `parent_id`
when the field is set.

### Stable ids

`UsageEvent::new(device, session, model, provider, at_ms, parent_id, nonce)`
derives the id with BLAKE3 over the length-prefixed tuple
`(device, session, at_ms, model, parent_id, nonce)`, formatted as
`ue_<hex>`. The caller supplies the nonce; it must be unique per observation
on a device (for example a turn id). Two devices that observe the same work
with the same tuple derive the same id and deduplicate on merge. Because
`parent_id` is part of the tuple, a child must pass it to `new` rather than
assigning the field afterwards.

Builder methods (`with_tool`, `with_usage`, `with_cost`, `with_wall_ms`,
`with_retries`, `with_subagent_share`) fill in the counters without changing
the id.

## Append-only store

`UsageLedger::open(path)` opens or creates a ledger and its parent directory.
`UsageLedger::create(path)` is the same but fails with
`zero.fnd.already_exists` instead of reusing an existing file.

- `append(&event)` validates the event, serializes one object, and writes it
  followed by `\n`. The line is flushed and `fsync`ed before returning.
- On Unix the file is created mode `0600` and existing permissions are
  tightened to `0600`.
- There is no update, delete, truncate, or compaction API. Compaction is a
  later task; until then the file only grows.
- Appends from multiple handles in one process are serialized by a process-wide
  lock, so a line is never interleaved. Across processes, append mode plus a
  single write per line is the guarantee.
- `read_all()` returns the valid events. `scan()` additionally reports
  `malformed` (complete lines that were not valid events or failed validation)
  and `torn_tail` (a final line with no newline, which is skipped).
- A single malformed line does not fail the read. A file that is not JSONL at
  all - invalid UTF-8, a JSON array, or non-object text - returns
  `zero.fnd.corrupt`. The reader still refuses to treat a ledger whose every
  line is object-shaped but invalid as a different format; those lines are
  counted as malformed.

Parent existence is not checked on append: one device may record a child
before it sees the parent from another device. It is checked where the full
set is known.

## Union merge

`merge(a, b) -> MergeResult` unions two slices by `id`:

- same id and identical payload: counted in `duplicates`, one event kept;
- same id and a different payload: recorded in `conflicts` with `kept` and
  `rejected`, and the first occurrence is kept - never silently overwritten;
- parent ids that are referenced but not present are listed in
  `unresolved_parents`;
- output is sorted by `(at_ms, device, id)` so the same input set always
  produces the same order.

`merge` is infallible and assumes its inputs were validated by `append` or
`scan`. Conflicting records are evidence of a bug or tampering, so they are
surfaced rather than resolved.

`merge_files(paths, out)` reads each file, merges incrementally in the given
path order, and writes the union to `out` through a temporary file plus
rename. Repeating the same merge writes byte-identical output (the same sorted
events, the same field order). Missing input files are treated as empty; a
malformed input file is counted in the report and does not abort the merge.
On Unix the output is mode `0600`.

`validate_parents(events)` is the strict gate: it returns
`zero.fnd.not_found` when any child references a parent outside the set. Use
it when a complete set is required instead of relying on the merge report.

## Attribution

`attribute(events) -> Result<Vec<AttributedEvent>>` returns every event with:

- `own`: totals recorded on the event itself;
- `subagent`: totals of all descendants, rolled up transitively;
- `total`: `own + subagent`, so a root's total covers its whole subtree;
- `subagent_share_bps`: `subagent.cost_micros * 10 000 / own.cost_micros`,
  clamped to `0..=10 000` (`10 000` when the parent has zero cost but the
  children do not);
- `children`: direct child ids in input order.

A missing parent is `zero.fnd.not_found`. A cycle, a self-parent, or duplicate
ids are `zero.fnd.corrupt`; merge first to deduplicate. Because a child's
`total` is already inside its parent's `subagent`, sum `own` (or call
`totals`) for ledger-wide figures and use `total` for per-tree figures.

## Totals

`Totals` carries `input`, `output`, `cache_read`, `cache_write`, `cost_micros`,
`wall_ms`, `retries`, and `events`. Additions saturate rather than wrap.

- `totals(events)` sums every event, including children.
- `totals_by(events, |e| e.session.clone())` groups by any key and returns a
  `BTreeMap<K, Totals>`. The same works for `model`, `provider`, or `device`.

## Export

- `export_json(events)` returns a pretty-printed JSON array.
- `export_csv(events)` returns a header plus one row per event, in the schema
  order above; empty optional fields are empty cells, and commas, quotes, and
  newlines are RFC 4180 quoted.

Both return strings. They write no files and send nothing over the network.

## Cost budgets (USG-03)

`zero_sched::cost_budget` adds warn and stop budgets on top of the ledger. A
budget never dispatches and never calls a provider: `preflight` returns a
decision and the caller must honour it. `CostBudget` holds no durability of its
own; reconcile spend with `record` (or `record_event`) after each dispatch.

### Scopes

| Scope | Meaning |
|---|---|
| `Global` | Every unit of work. |
| `Project(name)` | Work attributed to a project. |
| `Device(name)` | Work observed on one device. |
| `Day(day)` | Work observed during one UTC day. |

A `Day` value is an epoch day (days since 1970-01-01), produced by
`day_of(now_ms)` with floor division, not a timestamp. Ledger events do not
carry a project field, so a project scope is fed by `record` or by the
`record_event(event, Some(project))` convenience call. That call records the
event against `Global`, its device, its own UTC day, and the named project.

### Limits and validation

`BudgetLimit { scope, warn_micros, stop_micros }` accepts any threshold mix
except neither: at least one of warn and stop is required, both are nonzero,
and `warn_micros <= stop_micros`. Equality is allowed. Empty project or device
names are rejected. There is exactly one limit per scope; a duplicate is
`zero.fnd.invalid_input` rather than a silent override. Build a budget with
`CostBudget::new(limits)` or add limits one at a time with `add_limit`.

### Preflight, precedence, and the boundary rule

`preflight(cost_micros, contexts, now_ms)` projects `spend(scope) +
cost_micros` (saturating) for every applicable scope:

- the project and device scopes named in `contexts`;
- `Global` whenever a global limit exists, even if the caller omits it;
- today's `Day` scope whenever a limit exists for it.

A `Day` value passed in `contexts` is normalized to the day derived from
`now_ms`, so a stale day cannot be evaluated.

Both thresholds are **inclusive**: reaching the warn line warns, and reaching
the stop line stops (`projected >= stop_micros`). The stop limit is therefore
the maximum permitted total - a projected total exactly on it is refused, one
micro below it is allowed. When warn and stop are equal, stop wins. `Allow`
means dispatch may proceed; `Warn` also permits dispatch but reports how much
headroom remains before the stop line (zero for a warn-only limit); `Stop`
must not dispatch, and its `remaining` is zero.

Precedence is deterministic and independent of context order:

1. any `Stop` wins over any `Warn`;
2. among several stops, the scope furthest over its limit wins, then the
   `BudgetScope` order (`Global`, `Project`, `Device`, `Day`) breaks a tie;
3. among warns, the scope with the least headroom to its stop line wins, then
   the scope order.

`Preflight` carries `decision`, the deciding `projected` total, and
`projected_by_scope` for every evaluated scope. `permits_dispatch()` is the
one-line contract: dispatch only when it returns true. A test drives a loop of
costs through it and asserts that the request on the stop line never runs.

### Day rollover

Spend is recorded under the event's day: `Day(day_of(event.at_ms))`. Preflight
only evaluates `Day(day_of(now_ms))`; spend recorded under any other day is
never added to today's total, so yesterday cannot stop today. A daily budget
is registered for the current epoch day (`Day(day_of(now_ms))`), and a new day
starts at zero. Tests cover a stop reached today, a clean start tomorrow, and a
stale `Day` context being normalized away.

### Dashboards and surfaces (USG-04)

`dashboard(events, budget, now_ms)` builds one `Dashboard` from the ledger and
the budgets:

- `totals` sums every ledger event (including children);
- `by_scope` has one row per configured limit, in `BudgetScope` order, with
  `spent`, `warn`, `stop`, and `state` (`Ok`, `Warn`, or `Stop`). Spend is the
  larger of the ledger figure for the scope and the spend recorded on the
  budget, so neither source under-reports the pressure; a project figure comes
  from the budget because events have no project field;
- `top_models` and `top_providers` are cost-ranked, name-ascending on ties,
  at most `TOP_N` (5) rows;
- `recent_events` counts events in the 24 hours ending at `generated_at_ms`.

`overall_state()` is the worst row state. `surfaces(&dashboard)` renders the
same dashboard three times - `Surface::Tui`, `Surface::Desktop`, and
`Surface::Android`, in that fixed order - with different line formatting but
identical numbers and a shared `state=<ok|warn|stop>` token per row. A test
asserts all three report the same stop state, the same total cost, and the
same warn row. No UI code is included; these are the data and renderings the
shells consume.

### Export (USG-06)

`cost_budget::export_csv(events)` and `cost_budget::export_json(events)`
delegate to the ledger's stable formats, including RFC 4180 quoting for model
and provider names containing commas or quotes. Both return strings: no file
is written, no telemetry is emitted, and no network call is made. The
root-level `zero_sched::export_csv` and `zero_sched::export_json` remain the
ledger exports; the budget module's copies exist so a budget-aware caller has
one import path.

## Cost audit (USG-05, SI-10)

`zero_sched::cost_audit` feeds `/cost-audit` from the same ledger.
`audit(events, &AuditOptions)` filters a closed window, aggregates spend,
emits findings, and builds bounded proposals. The module writes no files,
sends no telemetry, and never calls a provider. `--apply` is the only route
that changes anything.

### Analysis

`AuditWindow { from_ms, to_ms }` is inclusive. `AuditWindow::new` refuses an
inverted window (`from_ms > to_ms`) with `zero.fnd.invalid_input`, and `audit`
revalidates the whole `AuditOptions` before reading a single event. An empty
input is a valid zero report: zero totals, empty rows, no findings, no
proposals.

`CostAudit` carries:

| Field | Meaning |
|---|---|
| `window` | The closed interval that was analysed. |
| `totals` | Every event in the window, including children and subagents. |
| `by_model` | `ModelSpend` rows: totals, cache ratio, mean wall/cost, max retries. |
| `by_provider` | `ProviderSpend` rows with totals. |
| `by_session` | `SessionSpend` rows with totals, cache ratio, mean cost, max retries. |
| `retries` | `RetryStats`: total attempts, events with retries, max per event, rate in basis points. |
| `cache_ratio_bps` | `cache_read * 10 000 / (input + cache_read)`; zero when there are no prompt tokens. |
| `top_spenders` | The first `TOP_N` (5) rows of `by_session`. |
| `findings` | Evidence-backed insights. |
| `proposals` | Bounded, deterministic suggestions. |

All row lists are ordered by cost descending, then name ascending, so the same
event set always produces the same report regardless of input order.
`10 000` basis points is 100%.

Five findings are recognised. Thresholds live in `AuditOptions`; the defaults
are in the table.

| Finding | Trigger | Evidence |
|---|---|---|
| `HighRetryRate` | `retries/events` at or above `high_retry_rate_bps` (1 000 = 10%). | Retry count, event count, rate, events with retries, worst model, bounded event ids. |
| `LowCacheReadRatio` | Cache-read share of prompt tokens below `low_cache_ratio_bps` (2 000 = 20%). | Cache-read, input, and cache-write tokens, ratio, target. |
| `ExpensiveAndSlowModel` | A model holds at least `expensive_share_bps` (2 500 = 25%) of spend and its mean wall time is at least `slow_factor` (2) times the window mean. | Model cost, share, event count, mean wall time, window mean, bounded event ids. |
| `SessionOverStopBudget` | A session's spend exceeds `session_stop_micros`. No budget is invented: without this option the finding is absent. | Session spend, stop line, overspend, event count, bounded event ids. |
| `ProviderConcentration` | At least two providers exist and the top one holds `provider_concentration_bps` (8 000 = 80%) of spend. | Top and second provider cost, share, provider count. |

Evidence is aggregate numbers, the offending name, and at most
`MAX_EVIDENCE_IDS` (3) event ids selected deterministically by cost or retry
count. Raw event payloads (tool output, prompt text, and so on) are never
copied into a finding or proposal; a test plants a secret in `tool` and asserts
it does not appear.

### Proposals

| Field | Meaning |
|---|---|
| `id` | `ca_<hex>`, derived by BLAKE3 from the kind and the evidence lines. |
| `kind` | `SwitchModel`, `CapBudget`, `ReduceRetries`, `EnableCache`, or `SplitSession`. |
| `title`, `rationale` | Human-facing text. |
| `evidence` | One or more aggregate lines behind the proposal. |
| `estimated_savings_micros` | `Some` only when the ledger aggregates support an estimate; `None` when it does not. |
| `risk` | `low`, `medium`, or `high`. |

Bounds:

| Bound | Default | Hard cap |
|---|---|---|
| Proposals per audit | 5 (`MAX_PROPOSALS_DEFAULT`) | 32 (`MAX_PROPOSALS_HARD`) |
| Evidence lines per proposal | 4 | 32 (`MAX_EVIDENCE_LINES_HARD`) |
| Event ids per evidence line | 3 (`MAX_EVIDENCE_IDS`) | - |
| Previewed/applied changes per run | - | 8 (`MAX_APPLIED_CHANGES`) |

A proposal with no evidence is dropped. Setting `max_evidence_lines` to zero
therefore disables proposals while leaving the findings intact. Proposals are
sorted by estimated savings descending (`None` last), then kind, then id,
deduplicated, and truncated to `max_proposals`. An estimate is capped at the
observed spend, so a proposal can never claim more than the window cost.

| Kind | Risk | Estimate | Apply action |
|---|---|---|---|
| `ReduceRetries` | medium | Excess retries above `high_retry_rate_bps` times the mean observed event cost, capped at window spend. | `SetRetryCap` to `target_retry_cap`, never raised. |
| `EnableCache` | low | Window spend times `(target_ratio - current_ratio) / 10 000`, capped at window spend. A proportional estimate; real cache pricing may differ. | `SetCacheEnabled(true)`. |
| `SwitchModel` | high | Events of the chosen model times `(its mean cost - cheapest observed alternative's mean cost)`, capped at the model and window spend. | `SetModelDisallowed` for the audit's `work_class`. |
| `CapBudget` | low | `session spend - session_stop_micros` for the worst over-budget session. | `SetSessionBudget` to the stop line, never raised above an existing tighter budget. |
| `SplitSession` | high | None: the ledger cannot price a routing split. | Manual; splitting a session is not an audit configuration change. |

The model switch is only proposed when a cheaper observed alternative exists.
Without one the `ExpensiveAndSlowModel` finding remains and no estimate is
invented.

### Dry run, apply, and rollback

`AuditMode` defaults to `DryRun`, so an omitted flag never mutates anything.

```rust
let report = zero_sched::audit(&events, &options)?;
let mut state = zero_sched::AuditState::default();

// Preview only: proposals and changes, state untouched.
let dry = zero_sched::apply(&report, zero_sched::AuditMode::DryRun, &mut state);
assert!(dry.applied.is_empty());
assert_eq!(state, zero_sched::AuditState::default());

// Apply. Without the confirmation set, high-risk proposals are skipped;
// `zero_sched::apply(&report, AuditMode::Apply, &mut state)` is that form.
let ids: std::collections::BTreeSet<String> =
    report.proposals.iter().map(|proposal| proposal.id.clone()).collect();
let applied = zero_sched::apply_with_confirmations(
    &report,
    zero_sched::AuditMode::Apply,
    &mut state,
    &ids,
);

// Reverse exactly what that run changed, in reverse order.
zero_sched::rollback(&applied, &mut state)?;
```

- `DryRun` returns `proposals` and `preview`, leaves `applied` empty, and
  mutates nothing.
- `Apply` reaches the caller's `AuditState` only through the `CostChange`
  variants: `SetRetryCap`, `SetCacheEnabled`, `SetModelDisallowed`, and
  `SetSessionBudget`. Every variant records `before` and `after`.
- A `high` risk proposal is skipped with `SkipReason::HighRiskUnconfirmed`
  unless its id is in the confirmation set. Its `SplitSession` form stays
  manual even when confirmed.
- A value already present is skipped with `AlreadyApplied`; more than
  `MAX_APPLIED_CHANGES` changes in one run are skipped with `ChangeLimit`.
- `rollback` refuses a dry-run report or an empty apply, validates every
  `after` value before reverting, and returns `zero.fnd.invalid_input` when the
  state changed since the apply. A refused rollback makes no mutation.
- The audit never persists `AuditState`; the caller writes it through its
  normal settings path after inspecting `ApplyReport`.

## Test evidence

Module tests: `crates/zero-sched/src/usage_ledger.rs` (18 tests; the
permissions test is Unix-only, so 17 run on Windows and all 18 on Unix).

```
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-sched usage_ledger -j 1
running 17 tests ... test result: ok. 17 passed; 0 failed
    (28 filtered out; other zero-sched tests were not selected)
```

```
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-sched --all-targets -j 1 -- -D warnings
Finished `dev` profile ... (no warnings)
```

Coverage mirrors the acceptance criteria:

| Test | Criterion |
|---|---|
| `append_and_read_round_trip` | append/read round trip |
| `malformed_line_is_counted_not_fatal` | malformed line counted, not fatal |
| `a_file_that_is_not_jsonl_is_a_typed_error` | non-JSONL file is typed |
| `duplicate_id_and_payload_is_counted_once` | duplicate id and payload |
| `conflicting_payload_is_recorded_and_the_first_wins` | conflict recorded |
| `two_devices_union_without_conflict_and_totals_match` | two devices merge, totals sum |
| `remerging_files_is_idempotent_and_byte_identical` | idempotent re-merge |
| `unresolved_parents_are_reported_but_not_fatal_to_merge` | parent check |
| `orphan_parent_is_a_typed_error_during_attribution` | orphan parent error |
| `attribution_rolls_children_into_the_parent_share` | child/subagent roll-up |
| `attribution_rejects_cycles_and_duplicate_ids` | cycle and duplicate guard |
| `totals_and_totals_by_group` | totals and grouping |
| `export_shapes_are_stable` | JSON/CSV shapes |
| `csv_escapes_commas_and_quotes` | CSV quoting |
| `validation_rejects_empty_fields_and_bad_share` | schema validation |
| `create_refuses_to_reuse_an_existing_ledger` | create semantics |
| `concurrent_appends_from_two_handles_produce_complete_lines` | append locking |

`ledger_file_is_mode_0600_on_unix` covers file permissions and runs on Unix
only.

Cost budget module tests: `crates/zero-sched/src/cost_budget.rs` (11 tests, all
platforms).

```
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-sched cost_budget -j 1
running 11 tests ... test result: ok. 11 passed; 0 failed
    (45 filtered out)
```

```
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-sched --all-targets -j 1 -- -D warnings
Finished `dev` profile ... (no warnings)
```

| Test | Criterion |
|---|---|
| `warn_and_stop_preflight_decisions` | warn, stop, warn-only, and unbounded decisions |
| `a_stop_budget_halts_dispatch` | Done: a stop budget halts dispatch |
| `overlapping_scopes_stop_beats_warn_regardless_of_order` | stop-over-warn precedence, tie-breaks |
| `exact_boundaries_stop_and_warn_inclusively` | inclusive warn/stop boundary |
| `day_rollover_ignores_yesterday` | UTC day rollover and context normalization |
| `invalid_limits_are_rejected` | nonzero, ordering, names, duplicate scopes |
| `dashboard_state_matches_configured_budgets` | per-scope states, order, rankings |
| `all_surfaces_show_the_same_stop_state_and_numbers` | TUI/desktop/Android agree on stop |
| `empty_ledger_and_empty_budget_are_ok` | empty ledger and default budget |
| `export_reuses_ledger_formats_and_escapes_names` | stable CSV/JSON and escaping |
| `record_event_covers_global_device_project_and_day` | convenience recording and saturation |

Cost audit module tests: `crates/zero-sched/src/cost_audit.rs` (13 tests, all
platforms, no network).

```
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-sched cost_audit -j 1
running 13 tests ... test result: ok. 13 passed; 0 failed
    (56 filtered out)
```

```
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-sched --all-targets -j 1 -- -D warnings
Finished `dev` profile ... (no warnings)
```

| Test | Criterion |
|---|---|
| `empty_ledger_yields_a_zero_report` | empty input is a valid zero report; empty apply is refused |
| `window_filters_events_and_invalid_bounds_are_refused` | window filter; inverted window refused |
| `analysis_orders_rows_and_reports_ratios` | deterministic row order, retry/cache ratios, top spenders |
| `findings_name_all_five_signals_with_evidence` | every finding kind carries aggregate and event-id evidence |
| `proposals_are_bounded_evidence_backed_and_deterministic` | exact evidence-backed savings, unique ids, input-order independence |
| `proposal_cap_and_evidence_bar_are_enforced` | proposal cap, no-evidence drop, hard-cap validation |
| `dry_run_previews_without_mutating` | dry run previews and leaves state unchanged |
| `apply_is_required_and_high_risk_needs_confirmation` | only `Apply` mutates; high risk skipped without confirmation |
| `already_applied_changes_are_skipped` | idempotent second apply |
| `rollback_restores_state_and_refuses_stale_reports` | rollback restores exactly; spent/dry-run reports refused |
| `rollback_refuses_a_state_changed_after_apply` | stale state refused without partial mutation |
| `evidence_never_carries_raw_payloads_or_secrets` | planted `tool` secret absent from findings and proposals |
| `invalid_options_are_refused` | thresholds, work class, retry target, and bounds validated |


