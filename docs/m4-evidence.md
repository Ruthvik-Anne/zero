# M4 evidence (in progress)

M4 is not closed. This page records the completed task groups so far.

## File manager — T-FS-01..T-FS-08 (done)

| Task | Evidence |
|---|---|
| T-FS-01 | `manager::tests::a_handle_records_hash_size_mtime_id_encoding_and_lines`; stale write refused with `zero.fs.stale` and the external bytes preserved. |
| T-FS-02 | `manager::tests::atomic_writes_preserve_bytes_mode_and_symlinks`: UTF-8 BOM, UTF-16LE BOM, CRLF/LF, binary, executable mode, symlink write-through, read-only refusal. Temp + fsync + atomic replace (`MoveFileExW` on Windows). |
| T-FS-03 | `locks::tests`: two claimants conflict; tree covers descendants not siblings; hardlinks share a resource; an expired holder is fenced out (`zero.fs.stale`). |
| T-FS-04 | `batch::tests`: a failing op restores every file; dry-run changes nothing; success commits (removal via trash); recovery rolls back a `begin` journal. |
| T-FS-05 | `overlay::tests`: disjoint edits merge, same-line edits conflict at the precise line, one-sided changes are taken, creation collisions conflict. |
| T-FS-06 | `identity::tests`: hardlinks and symlinks share an id; NFC/case spellings agree; Windows volume+index and Unix dev+ino. |
| T-FS-07 | `manager::tests::the_watcher_reports_external_changes`; the stale-write test is the bash-edit conflict case. |
| T-FS-08 | Lock expiry + fencing (`locks`), journal replay (`batch::recover`), deletes routed to trash (`manager::delete`). |

## Edit tool — T-EDT-01..T-EDT-06 (done)

| Task | Evidence |
|---|---|
| T-EDT-01 | `edit::tests::every_text_operation_has_a_fixture`: replace, insert, delete, wrap, move, copy, write, patch; rename is a file-level op with its own test. |
| T-EDT-02 | `a_drifted_anchor_refuses_instead_of_editing`: text and line-hash anchors fail closed with `zero.edt.anchor_drift`. |
| T-EDT-03 | `receipts_are_bounded_and_never_echo_the_file`: ≤3 context lines, <1 KiB, no body echoed. |
| T-EDT-04 | `a_fifty_file_batch_undoes_byte_exactly`: 50 files restored, manifest removed so undo cannot replay. |
| T-EDT-05 | `range_edits_on_a_one_gigabyte_file_are_o_edits`: 100 edits read 0 base bytes; the line index is lazy and cached; save is exact. |
| T-EDT-06 | `deleting_files_is_refused_with_a_task_suggestion`: `zero.del.blocked` with the trash suggestion. |

## Still open in M4

T-KRN-01..05, T-AUT-01..04. No M4
task outside FS, EDT, TSK, TODO, LCK, SCH, and TOOL is marked done.

## Locks and pools — T-LCK-01..04 (done)

| Task | Evidence |
|---|---|
| T-LCK-01 | `banker::tests`: atomic grants, maxima abort, bounded safety check, aging promotes a waiting request, preemption only at a safe boundary with a fencing rejection, degraded reason. |
| T-LCK-02 | `locks::tests::canonical_order_ignores_the_caller_order`, `wound_wait_preempts_lower_priority_and_respects_critical_sections`, `ten_thousand_interleavings_never_deadlock`; optimistic versions are the stale-handle tests; overlays are the isolated workspaces. |
| T-LCK-03 | `election::tests`: deterministic owner, minority partition denies new leases (`zero.lck.no_quorum`), fenced handoff invalidates the old lease. |
| T-LCK-04 | `banker::tests::a_worker_without_maxima_is_degraded_with_a_reason` and `a_degraded_worker_uses_ordered_acquisition_with_timeouts`; `degraded_workers()` feeds status. |

## Scheduler — T-SCH-01..06 (done)

| Task | Evidence |
|---|---|
| T-SCH-01 | `mlfq::tests`: short-task-first, class round-robin, aging starves no one (served within 10 ticks under a flood), 3:1 weighted fair share, interactive priority. |
| T-SCH-02 | `admission::tests`: provider and model concurrency defer explicitly; a 429 `Retry-After` blocks the credential until reset. |
| T-SCH-03 | `budget::tests::over_budget_work_defers_with_a_reason` and reservation/reconciliation with the 80% warning. |
| T-SCH-04 | `backoff::tests`: capped retries, deterministic jitter, per-provider breakers where one outage does not stall another. |
| T-SCH-05 | `usage::tests`: pause at zero, reset time, resume without replay, repeated windows. |
| T-SCH-06 | `queue::tests` plus `tests/queue_crash.rs`: kill a claiming worker, restart, recover marks uncertain, one dispatch across the restart. |

## Tasks and todos — T-TSK-01..07, T-TODO-01..04 (done)

| Task | Evidence |
|---|---|
| T-TSK-01 | `store::tests::a_cycle_is_rejected_with_the_path`; readiness walks dependencies; plan cycles seed nothing. |
| T-TSK-02 | `one_claim_per_task_and_stale_claims_are_fenced`: one owner, monotonic generation, TTL, stale completion refused. |
| T-TSK-03 | `transitions_are_compare_and_swap_and_journaled` and `replay_reconstructs_the_state_after_reopen`; dependency edges journaled. |
| T-TSK-04 | `a_blocked_on_user_task_goes_to_the_queue_and_work_continues` with the policy user queue. |
| T-TSK-05 | `two_hundred_tasks_respect_limits_and_fair_share`: all 200 dispatched once, per-project cap; events carry actor/ts/evidence. |
| T-TSK-07 | `plan_seeding_is_exactly_once_and_cycle_checked`. |
| T-TODO-01/03 | `merged_project_and_session_views_are_ordered_and_deduplicated`. |
| T-TODO-02 | `the_agent_tool_is_versioned_and_respects_confirmation` and `the_agent_needs_confirmation_to_complete_or_drop_a_user_item`. |
| T-TODO-04 | `a_full_keyboard_capture_flow_needs_no_mouse`; `review_reports_stale_and_due_soon_items`; `linking_is_explicit_and_never_completes_the_task`. |

## Tools — T-TOOL-01..06 (done)

| Task | Evidence |
|---|---|
| T-TOOL-01 | `tools::tests::the_registry_has_metadata_schemas_and_passes_lint` and `deferred_tools_stay_off_the_wire_until_activated`; core echo/read_file load with metadata. |
| T-TOOL-02 | `bm25_ranks_the_relevant_tool_first` over a fixed six-tool corpus. |
| T-TOOL-03 | `activation_is_advisory_and_explains_itself`: language, git, keyword, and recent-use reasons; the catalogue is unchanged. |
| T-TOOL-04 | `tool_injection_leaves_the_stable_prefix_hash_unchanged`. |
| T-TOOL-05 | `denied_tools_are_hidden_and_duplicates_are_flagged`: plan hides writes and mutating shell; duplicate schema/description flagged. |
| T-TOOL-06 | `telemetry_records_all_four_outcomes_on_every_route`: surfaced/chosen/rejected/failed, identical kernel and protocol shapes; rotation report. |

## Commands

```text
cargo test -p zero-fs             44 passed
cargo clippy --workspace --all-targets -- -D warnings   clean
cargo run -p xtask -- check-docs  OK
```

Hosted matrix run [45538950771](https://github.com/Ruthvik-Anne/zero/actions/runs/45538950771)
on `ci/m0-m1-verification` (`49ef2a6e`): all eight jobs successful, including the
1 GiB range-edit test on Linux, macOS, and Windows, and the trash/atomic-write
fixtures on every platform. A CI-only gap was caught here: six new error codes
were not yet in `docs/errors.md`; the generated page is now committed and the
`error::tests::documented_codes_match_the_enum_exactly` gate passes.

Run [45541018098](https://github.com/Ruthvik-Anne/zero/actions/runs/45541018098)
on `0e4fcf46` covers the tasks/todos slice: all eight jobs successful as well.

Run [45544273274](https://github.com/Ruthvik-Anne/zero/actions/runs/45544273274)
on `d23eb167` covers the locks/pools slice: all eight jobs successful, including
the 10,000-interleaving file-lock simulation and the Banker's pool tests on
every platform.

Run [45545824128](https://github.com/Ruthvik-Anne/zero/actions/runs/45545824128)
on `7305e24c` covers the scheduler slice: all eight jobs successful, including
the kill/restart durable-queue test on every platform.

Run [45546934655](https://github.com/Ruthvik-Anne/zero/actions/runs/45546934655)
on `33df1b0d` covers the tool catalogue slice: all eight jobs successful.
