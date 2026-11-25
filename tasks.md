# Zero: tasks

Execution list derived from `features.md` Part 10 and `plan.md`. Every task
names the requirements it satisfies and the evidence that closes it.

- **Status:** `todo` (default), `doing`, `done`, `blocked`, `moved`. A task is
  `done` only with the evidence linked.
- **Done** is a command, a test name, or an artifact a reviewer can check.
- **Deps** names task IDs that must close first.
- A task with no requirement reference is invalid and fails the traceability
  check.
- When a requirement changes, its tasks change in the same commit
  (`plan.md` section 9).

---

## M0 — Foundations

- **T-FND-01 Workspace skeleton.** Create the Cargo workspace and the crates in
  `architecture.md` §5 with empty modules and dependency rules. **Refs:** FND-01,
  FND-02. **Done:** every crate builds; a dependency-direction test rejects a
  cycle or an upward edge.
- **T-FND-02 Error taxonomy.** Define typed errors with stable codes and one
  remediation line each. **Refs:** FND-02, FND-07. **Done:** every error variant has a
  code; a test fails on a duplicate or undocumented code.
- **T-FND-03 IDs and clocks.** Implement opaque IDs, monotonic sequences,
  injectable clocks, and deterministic seeds. **Refs:** FND-03, FND-08. **Done:** the
  same seed reproduces an identical event order across two runs.
- **T-FND-04 Config schema.** Define one schema with layered precedence and
  document the resolution order. **Refs:** FND-04, FND-05. **Done:** a matrix test covers
  every layer pair, including untrusted project config being inert.
- **T-FND-05 Data directories.** Resolve per-OS data, config, cache, and state
  paths from one table. **Refs:** FND-05, FND-03. **Done:** tests assert paths on all
  three platforms.
- **T-FND-06 Migration framework.** Version every store, back up before migrate,
  and refuse a downgrade. **Refs:** FND-06, FND-04. **Done:** fixtures from every prior
  schema version migrate and round-trip.
- **T-FND-07 Logging and redaction.** Structured logs with correlation IDs and a
  redaction pipeline. **Refs:** FND-07, FND-06, OBS-01, OBS-05. **Done:** a seeded fake
  secret never appears in any sink.
- **T-FND-08 Event log and SQLite.** Append-only session/event log, SQLite WAL
  store, and content-addressed blobs. **Refs:** FND-08, FND-09, SES-01, USG-02. **Done:**
  kill -9 loop leaves logs parseable and replayable.
- **T-FND-09 Durability harness.** Crash-injection tests for every durable write.
  **Refs:** FND-09. **Done:** no torn record in 1,000 injected crashes.
- **T-FND-10 Protocol skeleton.** Define frames, versioning, and the JSON
  projection. **Refs:** FND-10, FND-05, SES-07. **Done:** golden fixtures decode in the
  Rust and TypeScript readers.
- **T-FND-11 CLI shell.** Implement `resume`, `login`, `logout`, `doctor`, plus
  `install`, `update`, `uninstall`, `service`, and completion. **Refs:** FND-11, ACT-10.
  **Done:** an unknown verb prints the matching action name and exits non-zero.
- **T-FND-12 Resource limits.** Bound memory, CPU, disk, process count, and file
  size for agent-launched work. **Refs:** FND-12, FND-11. **Done:** runaway fixtures
  return typed errors.
- **T-FND-13 Offline guards.** Make every network feature report an explicit
  unavailable state when offline. **Refs:** FND-10. **Done:** with networking
  disabled, startup and file work pass smoke tests.
- **T-TST-01 CI matrix.** Six targets with build, lint, and test jobs.
  **Refs:** FND-02, TST-01. **Done:** all targets green on a clean cache.
- **T-TST-02 Virtual terminal harness.** A test terminal that records cells and
  escape sequences. **Refs:** TST-02, TST-09. **Done:** a smoke frame renders and reads
  back.
- **T-TST-03 Simulation harness.** Seeded scheduler, fake clock, and interleaving
  explorer. **Refs:** TST-03, TST-02. **Done:** an example lock trace reproduces exactly.
- **T-TST-04 Benchmark harness.** Record baselines and fail on regression.
  **Refs:** TST-04, TST-07. **Done:** startup, frame, and attach benchmarks run in CI.
- **T-PAR-01 Traceability check.** Fail the build when a requirement has no task
  or a task has no requirement. **Refs:** PAR-01, TST-11. **Done:** the check runs
  in CI and on every docs change.
- **T-PAR-02 Docs skeleton.** Create `features.md`, `architecture.md`,
  `plan.md`, and `tasks.md` cross-links and the requirement index. **Refs:**
  PAR-02, PAR-04. **Done:** every Part 10 area appears in the index.

## M0 closure

Commands were run from the repository root on 2026-11-25. `ci-local.ps1` runs
the same steps as the CI matrix and ends with `local CI: OK`. Detailed output is
recorded in `docs/m0-evidence.md`.

| Task | Status | Evidence |
|---|---|---|
| T-FND-01 | done | `cargo test -p zero-arch`: real-workspace check plus cycle and upward-edge fixtures; 24 crates, 23 edges, no violation. |
| T-FND-02 | done | `cargo test -p zero-types error::tests`: 53 codes, unique, each with a remediation; `docs/errors.md` must match exactly. |
| T-FND-03 | done | `cargo test -p zero-types id::tests::same_seed_reproduces_identical_event_order`: 1,000 events, same trace twice, different seed differs. |
| T-FND-04 | done | `config::tests::matrix_covers_every_layer_pair` (15 pairs) and `untrusted_project_config_is_inert`. |
| T-FND-05 | done | `paths::tests::each_platform_resolves_every_kind` (12 paths) and `docs_table_matches_the_code`; `docs/data-directories.md`. |
| T-FND-06 | done | `migrate::tests::fixtures_from_every_prior_version_migrate_and_round_trip` plus downgrade-refusal and missing-step cases. |
| T-FND-07 | done | `log::tests::seeded_secret_never_appears_in_any_sink` (memory and file sinks, message and field). |
| T-FND-08 | done | `cargo test -p zero-store --test kill_loop` (76 records across 4 hard kills, replay dense), SQLite WAL tests, blob dedupe/corruption tests. |
| T-FND-09 | done | `durability::tests::one_thousand_injected_crashes_leave_no_torn_record`: 1,000 crashes, prefix property, repair and continue. |
| T-FND-10 | done | `proto::tests::golden_fixtures_decode_identically` and `node protocol/ts/check.mjs` (2 fixtures, decode and re-encode byte-identical). |
| T-FND-11 | done | `cargo test -p zero-cli`: unknown verb prints `` `resume` `` and exits non-zero; version, help, doctor, completion, service tests. |
| T-FND-12 | done | `limits::tests::runaway_*_returns_a_typed_error` for memory, disk, file size, process count, CPU; `telemetry::tests` (nothing sent). |
| T-FND-13 | done | `net::tests::offline_reports_every_network_feature_as_unavailable` and the offline file-work smoke test. |
| T-TST-01 | done | Hosted run [45490519929](https://github.com/Ruthvik-Anne/zero/actions/runs/45490519929) on `ci/m0-m1-verification`: all 8 jobs green — the six targets `x86_64-unknown-linux-gnu` (1m27s), `aarch64-unknown-linux-gnu` (1m9s), `x86_64-apple-darwin` (2m39s), `aarch64-apple-darwin` (2m16s), `x86_64-pc-windows-msvc` (2m23s), `aarch64-pc-windows-msvc` (2m24s), plus `protocol readers` (20s) and `traceability and docs` (25s). Each target ran build, clippy `-D warnings`, tests, docs and architecture gates; the benchmark gate ran on `x86_64-unknown-linux-gnu`. |
| T-TST-02 | done | `cargo test -p zero-tui`: smoke frame read back, wide cells, erase, unknown sequences recorded. |
| T-TST-03 | done | `sim::tests`: identical traces per seed, 200-interleaving explorer with the lock invariant. |
| T-TST-04 | done | `cargo run -p xtask -- bench --record` then `--check`; `bench/baselines.json`; CI runs `bench --check`. Observed: startup 197.68 ms, frame 2594.18 µs, attach 419.77 ms (with a warm-up before sampling). |
| T-PAR-01 | done | `cargo run -p xtask -- check-traceability`: 478 requirements, 276 tasks, 38 areas, OK; negative fixtures cover missing refs, unknown refs, duplicates, uncovered areas; CI jobs run it. |
| T-PAR-02 | done | `docs/requirements-index.md` generated and tested against Part 10 (38 areas); `cargo test -p zero-arch --test docs` asserts the four documents cross-link. |

## M1 — Agent core and sessions

- **T-SES-01 Session log.** Write the entry kinds from SES-01 with a stable
  schema. **Refs:** SES-01. **Done:** a round-trip test covers every entry kind.
- **T-SES-02 Fork, clone, tree.** Implement branching with parent links and
  cumulative file tracking. **Refs:** SES-02. **Done:** a three-level tree forks,
  resumes, and renders correctly.
- **T-SES-03 Compaction.** Cut-point rules, hooks, and retained recent state.
  **Refs:** SES-03. **Done:** a long session compacts without losing the visible
  tail or kernel state.
- **T-SES-04 Branch summaries.** Structured summary with the six sections.
  **Refs:** SES-04. **Done:** a fixture summary passes a shape test and is used on
  resume.
- **T-SES-05 Context files.** Load `AGENTS.md` and `CLAUDE.md` with precedence
  and a size cap. **Refs:** SES-05. **Done:** conflicting files resolve by the
  documented rule.
- **T-SES-06 Leases.** Process-safe lease per canonical log path.
  **Refs:** SES-06. **Done:** two concurrent creates converge on one worker.
- **T-SES-07 Attach and cursors.** Generation and sequence cursors, coherent
  snapshots, chunked streaming. **Refs:** SES-07. **Done:** a 500 MiB session
  attaches without loading history into memory.
- **T-SES-08 Supervisor and workers.** Routing, health, adoption, and coordinated
  shutdown. **Refs:** SES-06, SES-08. **Done:** killing a worker recovers the tree
  with bounded retries.
- **T-SES-09 Command journal.** Idempotency keys, dispatch-before-apply, uncertain
  results reported. **Refs:** SES-09, ACT-07. **Done:** a replay applies one
  effect.
- **T-SES-10 Export and import.** Versioned session format. **Refs:** SES-10, SES-12.
  **Done:** export, wipe, import, and resume produce an identical transcript.
- **T-SES-11 Agent loop.** Tool dispatch, turn accounting, and cancellation.
  **Refs:** SES-11, SES-09, KRN-05. **Done:** a scripted three-turn fixture runs end to
  end with one provider stub.
- **T-SES-12 Line-mode test client.** Minimal client for testing only.
  **Refs:** SES-12, SES-07. **Done:** drives the loop in CI without a terminal.
- **T-PRV-01 Provider trait.** Streaming, tool calls, retry classification, and
  usage normalization. **Refs:** PRV-01, PRV-03, PRV-11. **Done:** a fake provider passes
  the conformance suite.
- **T-PRV-02 First hosted adapter.** One production provider with streaming and
  errors. **Refs:** PRV-02, PRV-01, PRV-07. **Done:** recorded fixtures plus a live smoke
  test behind a flag.
- **T-PRV-03 Local adapter.** Ollama or LM Studio with tool support detection.
  **Refs:** PRV-03, PRV-05. **Done:** offline session works with a local model.
- **T-PRV-04 Error mapping.** Provider errors to stable codes with remediation.
  **Refs:** PRV-04, PRV-07. **Done:** a fixture per code.
- **T-MON-01 Queue and steering.** Durable queue with `steer`, `follow_up`,
  `auto`, `interrupt`, and safe-boundary application. **Refs:** MON-01..MON-05.
  **Done:** steering during a tool call defers to the next boundary.
- **T-AR-01 Journal groundwork.** Record transitions needed to resume.
  **Refs:** AR-01, AR-04. **Done:** a crash mid-turn resumes with no duplicated
  side effect.
- **T-SES-13 Session naming and artifacts.** Auto-naming and per-session
  artifacts. **Refs:** SES-10, SES-11. **Done:** artifacts resolve from the
  transcript after resume.

## M1 closure

Run on 2026-11-25 from the repository root. Detailed output is in
`docs/m1-evidence.md`. The two live adapter tests are behind
`ZERO_LIVE_OPENAI=1` / `ZERO_LIVE_OLLAMA=1` and skip by default; the recorded
fixtures run the real adapters over loopback HTTP instead.

| Task | Status | Evidence |
|---|---|---|
| T-SES-01 | done | `session::tests::round_trip_covers_every_entry_kind`: 13 entry kinds round-trip with stable tags. |
| T-SES-02 | done | `tree::tests::three_level_tree_forks_resumes_and_renders`: A→B→C, fork prefix, cumulative files, indented render. |
| T-SES-03 | done | `compaction::tests::long_session_compacts_without_losing_the_visible_tail_or_kernel_state`: 92 removed, 8 kept, kernel state and hooks retained. |
| T-SES-04 | done | `cargo test -p zero-agent --test summary_resume`: fixture shape and the summary present in the resumed prompt. |
| T-SES-05 | done | `context::tests`: AGENTS over CLAUDE, nearest wins, 32 KiB character-safe cap; `docs/context-files.md`. |
| T-SES-06 | done | `cargo test -p zero-store --test session_lease`: two processes, one creator, loser names the owner. |
| T-SES-07 | done | `cargo test -p zero-store --test attach -- --nocapture`: 618 MiB, 5,242,880 records, 24,792-byte tail, index reused. |
| T-SES-08 | done | `cargo test -p zero-daemon`: kill/restart with one retry, four failures → Failed, adoption and coordinated shutdown. |
| T-SES-09 | done | `journal::tests`: replay applies one effect; an unfinished `begin` is reported uncertain, never replayed. |
| T-SES-10 | done | `export::tests::export_wipe_import_resume_produces_an_identical_transcript`: identical transcript and artifact. |
| T-SES-11 | done | `r#loop::tests::scripted_three_turn_fixture_runs_end_to_end`: 3 turns, 2 tool results, accounted usage. |
| T-SES-12 | done | `cargo test -p zero-cli --test line`: terminal-free turns, resume on the second run, `--script` required. |
| T-PRV-01 | done | `conformance::tests::scripted_provider_passes_the_conformance_suite`: 5 cases, and a negative case fails. |
| T-PRV-02 | done | `cargo test -p zero-model --test http_fixture hosted_*`: SSE fixture over loopback, usage and tool call, 401 mapping; live test behind a flag. |
| T-PRV-03 | done | `cargo test -p zero-model --test http_fixture local_*`: offline NDJSON session and `/api/show` tool detection; live test behind a flag. |
| T-PRV-04 | done | `errors::tests::a_fixture_for_every_error_code`: 14 HTTP fixtures and 6 transport kinds. |
| T-MON-01 | done | `queue::tests`: steering defers mid-tool and applies once at the boundary; durable reload; full-queue rejection. |
| T-AR-01 | done | `r#loop::tests::crash_mid_turn_resumes_without_duplicating_the_side_effect`: uncertain result reported, zero re-execution. |
| T-SES-13 | done | `artifacts::tests::artifacts_resolve_from_the_transcript_after_resume` and `tree::tests::auto_names_from_project_and_timestamp`. |

## M2 — Safety core

- **T-POL-01 Matrix data.** Encode mode by action class as data with defaults.
  **Refs:** POL-01, POL-02, DEL-10. **Done:** exhaustive table test.
- **T-POL-02 Evaluator.** Deny, ask, allow ordering with first terminal match and
  non-overridable hard denies. **Refs:** POL-02, POL-04. **Done:** conflict fixtures
  resolve to deny.
- **T-POL-03 Dispatch hooks.** Evaluate at every dispatch, including mid-turn and
  mid-generation. **Refs:** POL-03. **Done:** a mode change during a batch
  re-evaluates pending calls and records the new version.
- **T-POL-04 Host-request gate.** Define the host-request contract and evaluate
  every kernel effect. **Refs:** POL-04, POL-05, KRN-05. **Done:** a kernel write is
  denied in plan mode even when bypassing the edit tool.
- **T-POL-05 Approvals.** Action hash, expiry, and a durable decision record.
  **Refs:** POL-05, POL-09, POL-15. **Done:** a mutated command needs a new approval.
- **T-POL-06 Code regulator.** Protected paths, deletes, secrets, network
  allowlists, limits, cost ceilings, recursion depth, schema changes.
  **Refs:** POL-06, features.md 6.10.6, POL-02. **Done:** each rule has a fixture.
- **T-POL-07 AI regulator.** Isolated prompt with only request, policy, and
  action. **Refs:** POL-07, POL-10. **Done:** injected tool output cannot reach the
  regulator prompt.
- **T-POL-08 Fail-safe.** Degrade to manual when the regulator is unavailable.
  **Refs:** POL-08, POL-11. **Done:** outage test blocks instead of allowing.
- **T-POL-09 Headless queue.** Durable user queue for questions, approvals,
  credentials, and irreversible actions. **Refs:** POL-09, POL-12, TSK-09. **Done:** a
  headless run with one queued item completes the independent work.
- **T-POL-10 Transitions and persistence.** Allowed transitions plus per-session
  persistence across compaction, teleport, and resume. **Refs:** POL-10, POL-13, POL-14.
  **Done:** transition matrix test with in-flight work.
- **T-POL-11 No self-escalation.** Block agent writes to mode, policy, and
  protected files. **Refs:** POL-11, POL-06, TRU-05. **Done:** a typed denial plus an
  audit entry.
- **T-POL-12 Plan-mode tool policy.** Verified read-only MCP and network tools
  only, otherwise ask. **Refs:** POL-12, POL-16. **Done:** an unverified write tool asks.
- **T-DEL-01 POSIX command guard.** Parser and blocklist including wrappers.
  **Refs:** DEL-01, DEL-02. **Done:** the destructive corpus has zero false
  allows.
- **T-DEL-02 PowerShell and cmd guard.** Equivalent rules and wrapper handling.
  **Refs:** DEL-02. **Done:** the Windows corpus passes, including aliases.
- **T-DEL-03 Python guard.** Audit hook and import wrappers raising a typed
  error. **Refs:** DEL-03, DEL-04. **Done:** every listed call raises `DeletionBlocked`.
- **T-DEL-04 Shims.** PATH and PowerShell function shims. **Refs:** DEL-04, DEL-03.
  **Done:** a Makefile deletion is blocked.
- **T-DEL-05 Native trash.** Recycle Bin, `trashItemAtURL`, freedesktop trash
  with edge cases. **Refs:** DEL-05, DEL-06. **Done:** cross-device, read-only, symlink,
  open-file, and long-path fixtures.
- **T-DEL-06 Overwrite journal.** Snapshot before every managed overwrite and
  support undo. **Refs:** DEL-06, DEL-05, EDT-09. **Done:** an overwrite restores
  byte-exactly.
- **T-DEL-07 Protected paths.** Refuse the home directory, roots, `.git`,
  `.zero`, audit, journals, and the credential store. **Refs:** DEL-07.
  **Done:** each path returns a refusal with the reason.
- **T-DEL-08 Purge flow.** Human-only, dry-run, confirmed, audited. **Refs:**
  DEL-08. **Done:** the agent cannot reach purge by any route.
- **T-TRU-01 Trust store.** Explicit, per-project, revocable trust with inert
  untrusted content. **Refs:** TRU-01, TRU-02, MCP-18. **Done:** an untrusted repo's hooks,
  MCP servers, and `.halcyon-mode` do nothing.
- **T-TRU-02 Audit chain.** Hash-chained append-only log outside agent paths.
  **Refs:** TRU-02, TRU-04, OBS-02. **Done:** tampering is detected at the broken link.
- **T-TRU-03 Sandbox spike.** Evaluate Landlock/seccomp, job objects, and
  AppContainer. **Refs:** TRU-03, TRU-06. **Done:** a decision record with a working
  prototype on Windows and Linux.
- **T-TRU-04 Bypass tests.** Prove the evaluator is the only path to an effect.
  **Refs:** TRU-04, POL-03, TRU-01. **Done:** a red-team suite of attempted bypasses
  fails closed.

- **T-DEL-09 Zero-owned retention.** Limit internal GC to Zero data directories under a retention policy, logged. **Refs:** DEL-09. **Done:** a GC run deletes nothing outside the data root and trashes expired data.

## M2 closure

Run on 2026-11-25 from the repository root, plus the Linux-only tests in WSL
Ubuntu (`CARGO_TARGET_DIR=/tmp/zero-target cargo test -p zero-policy -p zero-fs`).
Hosted matrix run [45532483220](https://github.com/Ruthvik-Anne/zero/actions/runs/45532483220)
is green on all eight jobs. Detailed output is in `docs/m2-evidence.md`.

| Task | Status | Evidence |
|---|---|---|
| T-POL-01 | done | `mode::tests::matrix_is_exhaustive_and_matches_the_golden_defaults`: 5 modes × 15 classes = 75 cells; the golden rows are the regression gate. |
| T-POL-02 | done | `eval::tests::conflicting_rules_resolve_to_deny`, `self_escalation_is_a_typed_hard_deny`, `approval_lifts_an_ask_but_never_a_deny`. |
| T-POL-03 | done | `dispatch::tests::a_mode_change_re_evaluates_pending_calls_and_not_the_running_one`; the running call finishes, pending calls use the new policy version. |
| T-POL-04 | done | `dispatch::tests::kernel_writes_are_denied_in_plan_mode_without_running_the_effect`: the effect closure never runs. |
| T-POL-05 | done | `approval::tests`: exact-hash binding, a mutated command needs a new approval, expiry, first decision wins, durable across reopen. |
| T-POL-06 | done | `regulator::tests::each_code_rule_has_a_fixture`: protected path, raw delete, inline secret, credential, network allowlist, cost, recursion, schema change. |
| T-POL-07 | done | `regulator::tests::injected_tool_output_cannot_reach_the_regulator_prompt`; `RegulatorInput` has no tool-output field. |
| T-POL-08 | done | `regulator::tests::a_regulator_outage_blocks_instead_of_allowing`: absent and failing regulator both yield `Ask` plus `zero.pol.regulator_unavailable`. |
| T-POL-09 | done | `headless::tests::a_headless_run_queues_one_item_and_completes_independent_work`; durable queue, resolve once. |
| T-POL-10 | done | `transitions::tests::transition_matrix_with_in_flight_work` and `mode_persists_across_reopen_and_compaction`. |
| T-POL-11 | done | `eval` hard deny for agent mode change; `tests/policy_dispatch.rs::self_escalation_is_denied_with_an_audit_record`; protected policy path in `tests/bypass.rs`. |
| T-POL-12 | done | `eval::tests::plan_mode_requires_verified_read_only_tools`: unverified asks, verified allows, a write tool still asks. |
| T-DEL-01 | done | `delete::tests::the_destructive_corpus_has_zero_false_allows`: 17 POSIX cases including `sudo`, `env`, `sh -c`, `bash -lc`, `xargs`, `find -delete`, `git clean`. |
| T-DEL-02 | done | Same test: 10 PowerShell and 6 cmd cases, including `powershell -Command` and `cmd /c`, plus `Clear-Content` and aliases. |
| T-DEL-03 | done | `cargo test -p zero-policy --test python_guard`: 10 listed calls raise `DeletionBlocked`; a fresh-path rename still works. |
| T-DEL-04 | done | `tests/shims_windows.rs` blocks a PowerShell `Remove-Item`; `tests/shims_unix.rs` blocks a Makefile `rm -rf` through the PATH shim (green in WSL and hosted Linux). |
| T-DEL-05 | done | `zero-fs` trash tests: project file, read-only, long path, open file, symlink (target kept), cross-device on a separate tmpfs, protected refusal. |
| T-DEL-06 | done | `overwrite_journal::tests::an_overwrite_restores_byte_exactly` (4 KiB binary), snapshots survive reopen, truncation recoverable. |
| T-DEL-07 | done | `protected::tests::each_listed_path_returns_a_refusal_with_the_reason` (9 kinds) plus trash refusal for home and `.git`. |
| T-DEL-08 | done | `purge::tests::purge_is_dry_run_confirmed_and_audited`: dry-run, exact digest, literal phrase, changed plan refused, audit row; no agent route. |
| T-DEL-09 | done | `retention::tests::gc_deletes_nothing_outside_the_data_root_and_trashes_expired_data`, dry-run, symlink escape skipped. |
| T-TRU-01 | done | `trust::tests::an_untrusted_repo_contributes_nothing` and `trust_and_revocation_control_loading`: hooks, monitors, MCP, skills, instructions, and `.halcyon-mode` are inert until trusted; policy is plan-equivalent. |
| T-TRU-02 | done | `audit::tests::the_chain_verifies_and_detects_an_edited_record` and `deleting_a_middle_record_breaks_the_chain`; tampered logs refuse to open. |
| T-TRU-03 | done | `sandbox_windows` (job object, 64 MiB cap, kill-on-close) and `sandbox_linux` (Landlock denies writes, reads succeed; green in WSL); decision record `docs/decisions/0001-sandbox.md`. |
| T-TRU-04 | done | `tests/bypass.rs::bypass_suite_fails_closed` covers seven routes; `a_denied_tool_never_executes_through_the_loop`; permits are bound to one action hash. |

## M3 — TUI and actions

- **T-TUI-01 Cell grid.** Front and back buffers with styles and widths.
  **Refs:** TUI-01, TUI-03. **Done:** buffer invariants hold under random mutations.
- **T-TUI-02 Diff emitter.** Changed-run output with synchronized mode and
  fallback. **Refs:** TUI-02, TUI-03. **Done:** golden frames match byte for byte.
- **T-TUI-03 Unicode layout.** Graphemes, East Asian width, emoji, combining
  marks, tabs, bidi degradation. **Refs:** TUI-03, TUI-04. **Done:** corpus renders
  without corruption.
- **T-TUI-04 Streaming Markdown.** Tail-only parse and layout, folds, and thinking
  blocks. **Refs:** TUI-04, TUI-05. **Done:** a 10k-message stream keeps frame cost flat.
- **T-TUI-05 Virtual transcript.** Visible-only layout with a fullscreen mode.
  **Refs:** TUI-05, TUI-06. **Done:** scroll cost is independent of history.
- **T-TUI-06 Input.** Kitty protocol probe with bounded wait and declared
  fallbacks; paste, mouse, focus, resize. **Refs:** TUI-06, TUI-07. **Done:** matrix over
  Windows Terminal, ConPTY, tmux, and a legacy terminal.
- **T-TUI-07 Selection.** Identity-based selection with generation rejection.
  **Refs:** TUI-07, TUI-09. **Done:** async refresh cannot move the selection.
- **T-TUI-08 Slow terminal.** Latency detection with reduced frame rate.
  **Refs:** TUI-08, TUI-10. **Done:** 40 ms writes stay responsive.
- **T-TUI-09 Themes.** Full token model plus 256-color palette.
  **Refs:** TUI-09, TUI-12. **Done:** every token is overridable and documented.
- **T-TUI-10 Golden harness.** Snapshot infra across states and sizes.
  **Refs:** TUI-10, TST-09. **Done:** CI compares frames on every UI change.
- **T-TUI-11 Accessibility.** No-animation, high-contrast, line-oriented modes,
  and no color-only state. **Refs:** TUI-11, TUI-13. **Done:** a scripted screen-reader
  session completes.
- **T-TUI-12 Inline images.** Graphics protocol with a textual placeholder.
  **Refs:** TUI-12, TUI-11. **Done:** both paths resolve the same artifact.
- **T-TUI-13 Host-owned modals.** Approval and secret-entry chrome the agent
  cannot draw. **Refs:** TUI-13, TUI-14, SEC-03. **Done:** an agent cannot forge a modal;
  a test asserts it.
- **T-TUI-14 Status bar.** Mode, model, budget, queue, and pending approvals.
  **Refs:** TUI-14, TUI-15, ACT-15. **Done:** snapshot per state; the mode updates in one
  frame.
- **T-TUI-15 Non-blocking loops.** Prove render and input never wait on I/O.
  **Refs:** TUI-15, TUI-08. **Done:** stalled disk and provider keep input responsive.
- **T-ACT-01 Registry.** Action record schema, validation, and registration.
  **Refs:** ACT-01, ACT-02. **Done:** a schema test rejects a missing field.
- **T-ACT-02 Forms.** Slash-first and implicit dispatch through one handler.
  **Refs:** ACT-02, ACT-03. **Done:** both paths emit identical events.
- **T-ACT-03 Palette and help.** Fuzzy search, categories, and mode filtering.
  **Refs:** ACT-03, ACT-13, ACT-12. **Done:** denied actions carry the reason.
- **T-ACT-04 Keybindings.** Per-surface defaults, conflict detection, and
  remapping. **Refs:** ACT-04, ACT-12. **Done:** every action is rebindable.
- **T-ACT-05 Agent invocation.** `actions.list` and `actions.run` with policy.
  **Refs:** ACT-05. **Done:** a non-invocable action is unreachable by the agent.
- **T-ACT-06 Action idempotency.** Client and action keys with one effect.
  **Refs:** ACT-06, ACT-07. **Done:** replay test.
- **T-ACT-07 Shell prefix.** `!` routed through policy and the deletion guard.
  **Refs:** ACT-07, ACT-14. **Done:** `!rm` is blocked.
- **T-ACT-08 Daemon app.** Worker and attachment surface with `Ctrl+B` and
  `/daemon`. **Refs:** ACT-08, ACT-11, TUI-16. **Done:** worker operations exist only
  there; the draft survives the round trip.
- **T-ACT-09 No-controls lint.** Fail when an implicit action has a UI control.
  **Refs:** ACT-09, ACT-04. **Done:** lint runs in CI.
- **T-ACT-10 Deterministic execution.** Run deterministic actions without a
  model call. **Refs:** ACT-10, ACT-06. **Done:** zero provider requests in the trace.
- **T-ACT-11 Action audit.** Actor, surface, argument digest, verdict, outcome.
  **Refs:** ACT-11, ACT-08. **Done:** the audit reconstructs a session's actions.
- **T-ACT-12 Extension namespacing.** Reject shadowing and unnamespaced
  registration. **Refs:** ACT-12, ACT-09. **Done:** a plugin claiming a core ID fails.

## M3 closure

Run on 2026-11-25 from the repository root. Hosted matrix run
[45536140318](https://github.com/Ruthvik-Anne/zero/actions/runs/45536140318) is
green on all eight jobs. Detailed output is in `docs/m3-evidence.md`. The golden
comparator normalises line endings so hosted checks on LF checkouts match the
recorded frames.

| Task | Status | Evidence |
|---|---|---|
| T-TUI-01 | done | `buffer::tests::invariants_hold_under_random_mutations`: 2,000 seeded mutations with a Unicode corpus; resizing clears a truncated wide glyph. |
| T-TUI-02 | done | `screen::tests::wide_glyphs_and_styles_have_byte_exact_golden_output`; changed-run-only output with `CSI ?2026h/l`; fallback redraw without markers. |
| T-TUI-03 | done | `unicode::tests`: CJK, emoji ZWJ/skin tone/flags, combining marks, tabs, `[RTL]` degradation, control stripping; grid corpus renders without corruption. |
| T-TUI-04 | done | `markdown::tests::a_ten_thousand_message_stream_keeps_parse_and_layout_flat`: <128 bytes scanned per push, ≤41 blocks per frame, thinking folded. |
| T-TUI-05 | done | `transcript::tests::layout_visits_only_visible_messages_and_scroll_cost_is_flat`: bounded visits with 10k history; fullscreen toggle. |
| T-TUI-06 | done | `input::tests`: Windows Terminal, ConPTY, tmux, legacy, Kitty Shift+Tab; bounded Kitty probe; paste, mouse, focus, resize. |
| T-TUI-07 | done | `selection::tests::an_async_refresh_cannot_move_the_selection`; stale generation rejected. |
| T-TUI-08 | done | `slow::tests::forty_millisecond_writes_switch_to_slow_frames`; frame interval ≥ 80 ms. |
| T-TUI-09 | done | `theme::tests`: 29 tokens, every one overridable and documented in `docs/themes.md`; JSON round-trip rejects partial themes. |
| T-TUI-10 | done | `cargo test -p zero-tui --test golden`: five scenes across three sizes, text plus escape sequences. |
| T-TUI-11 | done | `a11y::tests`: scripted screen-reader session, no-animation, high contrast, text-only state. |
| T-TUI-12 | done | `image::tests`: Kitty, iTerm2, half-block, and none all resolve `image:<id>`; protocol detection. |
| T-TUI-13 | done | `modal::tests::an_agent_cannot_forge_a_modal_or_draw_into_it`; host-only approval/secret chrome; controls stripped. |
| T-TUI-14 | done | `status::tests`: idle/working, queue, approvals, WARN/STOPPED budget; mode change visible next frame. |
| T-TUI-15 | done | `nonblocking::tests`: 20 input events drained in <150 ms while two 800 ms jobs run. |
| T-TUI-16 | done | `zero-daemon-app` `the_draft_survives_the_handoff_round_trip`. |
| T-ACT-01 | done | `record::tests::a_schema_test_rejects_a_missing_field`; `deny_unknown_fields`, namespacing, lint. |
| T-ACT-02 | done | `executor::tests::slash_and_implicit_forms_emit_identical_events`. |
| T-ACT-03 | done | `palette::tests`: denied actions carry the reason; fuzzy prefix and acronym search; categories grouped. |
| T-ACT-04 | done | `keys::tests::every_action_is_rebindable`; conflicts typed; per-surface defaults. |
| T-ACT-05 | done | `executor::tests::a_non_invocable_action_is_unreachable_by_the_agent`; `actions-lint` reports 6 agent-invocable. |
| T-ACT-06 | done | `executor::tests::replaying_a_request_applies_one_effect`. |
| T-ACT-07 | done | `executor::tests::rm_through_the_shell_prefix_is_blocked_by_the_deletion_guard`; `echo` still runs. |
| T-ACT-08 | done | `zero-daemon-app` worker ops refuse outside the daemon surface; `Ctrl+B` default binding. |
| T-ACT-09 | done | `cargo run -p zero-actions --bin actions-lint` (17 registered, OK) and the CI step. |
| T-ACT-10 | done | `executor::tests::a_deterministic_action_makes_no_provider_call`; executor holds no provider. |
| T-ACT-11 | done | `executor::tests::the_audit_reconstructs_a_session_of_actions`: actor, surface, digest, verdict, outcome. |
| T-ACT-12 | done | `registry::tests::a_plugin_cannot_shadow_a_core_id`; unnamespaced ids refused. |

## M4 — Core infrastructure and kernel

- **T-FS-01 Handles and versions.** Content hash, size, mtime, and file ID on
  open; stale rejection on write. **Refs:** FS-01, FS-02. **Done:** a stale write
  returns `stale`.
- **T-FS-02 Atomic write.** Temp, fsync, rename, with metadata preserved.
  **Refs:** FS-02, FS-04. **Done:** matrix of encodings, BOMs, newlines, modes, and
  symlinks.
- **T-FS-03 Locks.** Per-file and per-subtree leases with fencing.
  **Refs:** FS-03, LCK-08. **Done:** a stale holder's write is rejected.
- **T-FS-04 Batches.** All-or-nothing with journal, dry-run, and rollback.
  **Refs:** FS-04, FS-07. **Done:** a failing op restores every file.
- **T-FS-05 Overlays.** Copy-on-write workspaces with three-way merge.
  **Refs:** FS-05, FS-08. **Done:** two parallel agents merge with a precise conflict on
  overlap.
- **T-FS-06 Identity keys.** Canonical file identity across case, Unicode,
  symlinks, junctions, hardlinks, long paths, and UNC. **Refs:** FS-06, FS-09.
  **Done:** platform fixtures.
- **T-FS-07 Watcher.** External change detection and `stale` on next write.
  **Refs:** FS-07, FS-05, FS-13, LCK-09. **Done:** a bash edit triggers a conflict, not
  corruption.
- **T-FS-08 Recovery.** Stale lock expiry, journal replay, and trash on delete.
  **Refs:** FS-08, FS-11. **Done:** crash then reopen leaves consistent state.
- **T-EDT-01 Operations.** Replace, insert, delete, wrap, move, copy, rename,
  write, and patch. **Refs:** EDT-01, EDT-02, EDT-07, EDT-10. **Done:** each op has a fixture.
- **T-EDT-02 Anchors.** Text or hash anchors with ranges and fail-closed drift.
  **Refs:** EDT-02, EDT-03. **Done:** a drifted anchor refuses instead of editing.
- **T-EDT-03 Receipts.** Compact success and bounded failure output.
  **Refs:** EDT-03, EDT-05, EDT-12. **Done:** no receipt exceeds the bound; no full file
  echo.
- **T-EDT-04 Journal and undo.** Reversible batches stored in the session
  snapshot. **Refs:** EDT-04, EDT-09. **Done:** undo after a 50-file batch.
- **T-EDT-05 Large files and performance.** Range edits and lazy line index.
  **Refs:** EDT-05, EDT-11, FS-12. **Done:** O(edits) benchmark on a 1 GB file.
- **T-EDT-06 No delete.** Refuse and route to `trash`. **Refs:** EDT-06, EDT-08.
  **Done:** typed refusal with the task suggestion.
- **T-TSK-01 DAG.** Dependencies, readiness, and cycle rejection. **Refs:**
  TSK-01, TSK-02, TSK-03. **Done:** a cycle is rejected with the path.
- **T-TSK-02 Claims and fencing.** Owner, generation, TTL, and stale write
  rejection. **Refs:** TSK-02, TSK-04, TSK-06. **Done:** concurrent claim test grants
  one.
- **T-TSK-03 Journal and replay.** CAS transitions and event journal.
  **Refs:** TSK-03, TSK-05, TSK-08. **Done:** replay reconstructs state after a crash.
- **T-TSK-04 Queue integration.** Blocked-on-user into the user queue; idle
  blocked-on-dependency. **Refs:** TSK-04, TSK-09. **Done:** headless run continues
  independent work.
- **T-TSK-05 Limits and audit.** Concurrency, priorities, fairness, and change
  records. **Refs:** TSK-05, TSK-07, TSK-11. **Done:** a 200-task fixture respects
  limits.
- **T-TODO-01 Store and scopes.** Fields, states, and merged project/session
  views. **Refs:** TODO-01, TODO-11..TODO-03. **Done:** merge view test.
- **T-TODO-02 Agent tool.** Add, list, update, complete, block, drop, versioned.
  **Refs:** TODO-02, TODO-05, TODO-10. **Done:** completing a user item needs the
  confirmation rule.
- **T-TODO-03 Capture UI.** Keyboard-first capture, bulk select, filters, review,
  stale detection. **Refs:** TODO-03, TODO-04, TODO-08. **Done:** a full capture flow with
  no mouse.
- **T-TODO-04 Linking.** Explicit task links and no implicit completion.
  **Refs:** TODO-04, TODO-06. **Done:** completing a todo leaves its task untouched.
- **T-LCK-01 Banker's pools.** Claims, safety check, atomic grants, aging, and
  preemption rules. **Refs:** LCK-01, LCK-02, LCK-11..LCK-04, LCK-12. **Done:** model check of
  safety over bounded pools.
- **T-LCK-02 File strategy.** Canonical order, wound-wait, timeouts, optimistic
  versions. **Refs:** LCK-02, LCK-05. **Done:** simulation shows no deadlock across
  10,000 interleavings.
- **T-LCK-03 Owner election.** Deterministic owner per resource with fenced
  handoff. **Refs:** LCK-03, LCK-07, LCK-10. **Done:** partition test denies new leases.
- **T-LCK-04 Degraded mode.** Report when maxima cannot be declared.
  **Refs:** LCK-04, LCK-06. **Done:** the status shows the degraded reason.
- **T-SCH-01 MLFQ.** Classes, priority, aging, round-robin, fair share.
  **Refs:** SCH-01, SCH-02, SCH-07. **Done:** simulation test for starvation.
- **T-SCH-02 Admission.** Provider, model, and credential concurrency with token
  buckets. **Refs:** SCH-02, SCH-04, SCH-13. **Done:** a 429 with `Retry-After` adjusts the
  bucket.
- **T-SCH-03 Budgets.** Prediction, reservation, reconciliation, and refusal.
  **Refs:** SCH-03, SCH-09, MDL-08. **Done:** over-budget work defers with a reason.
- **T-SCH-04 Backoff and circuit.** Jitter, breaker per provider, retry cap.
  **Refs:** SCH-04, SCH-05. **Done:** one provider outage does not stall another.
- **T-SCH-05 Usage windows.** Remaining capacity and reset time; schedule a
  resume. **Refs:** SCH-05, SCH-14, AR-06, USG-07. **Done:** simulated window resumes on reset.
- **T-TOOL-01 Registry.** Metadata, deferral, and schema generation.
  **Refs:** TOOL-01, TOOL-02, TOOL-06. **Done:** registry lint passes; core set is loaded.
- **T-TOOL-02 Search.** BM25 over names, descriptions, arguments, tags, examples.
  **Refs:** TOOL-02, TOOL-03. **Done:** relevance suite with a fixed corpus.
- **T-TOOL-03 Context activation.** File, directory, git, language, keyword, and
  recent-use rules. **Refs:** TOOL-03, TOOL-04, TOOL-05. **Done:** advisory-only test.
- **T-TOOL-04 Cache-safe injection.** Append after the stable prefix.
  **Refs:** TOOL-04, TOOL-07, TOOL-08. **Done:** prompt prefix hash is unchanged when tools
  load.
- **T-TOOL-05 Policy filtering and hygiene.** Hide denied tools; flag duplicates.
  **Refs:** TOOL-05, TOOL-09, TOOL-11. **Done:** a denied tool never appears in results.
- **T-KRN-01 Jupyter client.** Messaging, HMAC, and channel handling.
  **Refs:** KRN-01, KRN-10. **Done:** round-trip execute against a real `ipykernel`.
- **T-KRN-02 Host requests.** Typed effects, policy gate, and no ambient
  authority. **Refs:** KRN-02, KRN-05, KRN-09, TOOL-12. **Done:** a Python file write is denied in
  plan mode.
- **T-KRN-03 Restart and rehydrate.** Log-driven rebuild and lost-work report.
  **Refs:** KRN-03, KRN-06. **Done:** kill kernel mid-cell, resume, report the loss.
- **T-KRN-04 Limits and interruption.** Memory, CPU, output, duration, and
  partial-output interruption. **Refs:** KRN-04, KRN-07, KRN-11, KRN-12. **Done:** a fork
  bomb and an output flood are contained.
- **T-KRN-05 Preload and persistence.** Web tools, `tool_search`, `trash`, and
  adapters preloaded; state survives. **Refs:** KRN-05, KRN-02, KRN-03, KRN-04.
  **Done:** `%%bash` does not leak state; `%cd` persists.
- **T-AUT-01 Goals.** Objective, accounting, pause, clear. **Refs:** AUT-01.
  **Done:** a goal survives compaction and resume.
- **T-AUT-02 Heartbeats.** User and agent heartbeats with control operations.
  **Refs:** AUT-02. **Done:** pause and resume test.
- **T-AUT-03 Schedules.** One-off and cron with claimed ticks and coalescing.
  **Refs:** AUT-03. **Done:** missed ticks coalesce once.
- **T-AUT-04 Autonomy limits and cancellation.** Token, time, and step limits;
  cancel cascades. **Refs:** AUT-04, AUT-05, AUT-08, AUT-07, AUT-09. **Done:** a runaway run stops
  at the limit and reports.

- **T-TSK-07 Plan seeding.** An approved plan seeds tasks and the progress view. **Refs:** TSK-07, TSK-13, TSK-01. **Done:** approving a plan creates its tasks exactly once.
- **T-SCH-06 Durable queues.** Persist queues, resume after restart, and never duplicate an in-flight call. **Refs:** SCH-06, SCH-08, SCH-11. **Done:** kill and restart mid-queue yields one dispatch per call.
- **T-TOOL-06 Tool telemetry.** Record surfaced, chosen, rejected, and failed tools. **Refs:** TOOL-06, TOOL-10, TOOL-12. **Done:** a rotation report exists; kernel and protocol routes log identically.

## M4 closure

M4 is in progress; the file manager, edit tool, task store, and todo groups are
closed. The full list and remaining tasks stay below. Evidence:
`docs/m4-evidence.md`; hosted runs
[45538950771](https://github.com/Ruthvik-Anne/zero/actions/runs/45538950771) (FS/EDT)
and [45541018098](https://github.com/Ruthvik-Anne/zero/actions/runs/45541018098)
(tasks/todos), [45544273274](https://github.com/Ruthvik-Anne/zero/actions/runs/45544273274)
(locks/pools), [45545824128](https://github.com/Ruthvik-Anne/zero/actions/runs/45545824128)
(scheduler), and [45546934655](https://github.com/Ruthvik-Anne/zero/actions/runs/45546934655)
(tools), and [45549561333](https://github.com/Ruthvik-Anne/zero/actions/runs/45549561333)
(kernel) are green on all eight jobs.

| Task group | Status | Evidence |
|---|---|---|
| T-FS-01..T-FS-08 | done | `cargo test -p zero-fs`: handles/stale, atomic matrix, identity, watcher, leases, batch rollback/recovery, overlay merge. |
| T-EDT-01..T-EDT-06 | done | `cargo test -p zero-fs`: all ops, fail-closed anchors, bounded receipts, 50-file undo, 1 GB O(edits) range edits, no-delete refusal. |
| T-TSK-01..T-TSK-07 | done | `cargo test -p zero-tasks`: DAG/cycles, CAS journal replay, claims/fencing, limits/fairness, user queue, plan seeding. |
| T-TODO-01..T-TODO-04 | done | `cargo test -p zero-tasks`: merged scopes, versioned agent tool with confirmation, keyboard-only capture, explicit links, review. |
| T-LCK-01..T-LCK-04 | done | `cargo test -p zero-sched -p zero-fs`: Banker safety/atomic/aging/preemption, canonical + wound-wait + timeouts, 10,000 no-deadlock interleavings, election/partition/fenced handoff, degraded ordered fallback. |
| T-SCH-01..T-SCH-06 | done | `cargo test -p zero-sched`: MLFQ aging/fair share, admission with Retry-After, budgets, backoff/breakers, usage windows, and the kill/restart queue test. |
| T-TOOL-01..T-TOOL-06 | done | `cargo test -p zero-agent`: metadata/schema/deferral, BM25, advisory activation, cache-safe prefix hash, policy filtering/hygiene, telemetry rotation. |
| T-KRN-01..T-KRN-05 | done | `cargo test -p zero-kernel`: real ipykernel round-trip, HMAC, host gate, kill/rehydrate, output cap and process guard, `%cd`/preload. |
| T-AUT-01..T-AUT-04 | done | `cargo test -p zero-agent autonomy::`: goal survives compaction, heartbeats pause/resume, cron ticks coalesce with exclusive claims, limits stop a runaway run, cancellation cascades. |

## M5 — Projects, credentials, and secrets

- **T-PRJ-01 Identity.** Key generation, `projectId`, and binding registry.
  **Refs:** PRJ-01. **Done:** moving the folder keeps the identity.
- **T-PRJ-02 Creation and root detection.** Auto-create, name, `.gitignore`
  edit, and nearest-root rules. **Refs:** PRJ-02, PRJ-03. **Done:** subdirectory
  start attaches to the parent project.
- **T-PRJ-03 Move and copy detection.** Silent rebind, copy prompt, new key,
  `copiedFrom`, and non-interactive default. **Refs:** PRJ-03, PRJ-04, PRJ-05, PRJ-08.
  **Done:** copy detection leaves the original untouched and asks once.
- **T-PRJ-04 Replaced key and recovery.** Adopt or restore prompt plus recovery
  actions. **Refs:** PRJ-04, PRJ-06, PRJ-07, PRJ-12. **Done:** `/link` is user-only and
  never offered in the copy prompt.
- **T-PRJ-05 Layout and migration.** Documented `.zero/` layout and legacy
  migration. **Refs:** PRJ-05, PRJ-09, PRJ-10. **Done:** `.pi` and keyless layouts migrate
  once with a log.
- **T-PRJ-06 Mesh identity.** Replicate keys so one key is one project.
  **Refs:** PRJ-06, PRJ-11. **Done:** two devices resolve the same project at different
  paths after M8.
- **T-CRT-01 Keychain store.** Windows, macOS, and libsecret backends.
  **Refs:** CRT-01, CRT-07. **Done:** integration test per platform.
- **T-CRT-02 Encrypted fallback.** AES 256-bit GCM with a wrapped key and Argon2id
  option. **Refs:** CRT-02, CRT-03. **Done:** no plaintext file in a forced
  no-keychain run.
- **T-CRT-03 Accounts.** Named accounts, switch, rename, sign-out.
  **Refs:** CRT-03, CRT-05. **Done:** two accounts per provider with independent tokens.
- **T-CRT-04 Scrubbed children and refresh lock.** No secrets in child env; one
  refresher. **Refs:** CRT-04, CRT-10, CRT-11. **Done:** a child `env` dump has no
  credential; concurrent refresh consumes one token.
- **T-CRT-05 Import and redaction.** Explicit plaintext import and a redaction
  test suite. **Refs:** CRT-05, CRT-06, CRT-08, CRT-12. **Done:** the old file is trashed; logs
  are clean.
- **T-CRT-06 Unattended unlock.** TPM, DPAPI machine scope, `systemd-creds`, or
  per-session entry. **Refs:** CRT-06, CRT-09. **Done:** daemon starts unattended on a
  machine-bound key.
- **T-SEC-01 Vault format.** AEAD with AAD binding tag, scope, and project;
  index without values. **Refs:** SEC-01, SEC-04. **Done:** tampering with AAD fails to
  decrypt.
- **T-SEC-02 Tags and bindings.** Tag, scope precedence, bindings, expiry, and
  drift detection. **Refs:** SEC-01, SEC-02, SEC-17, SEC-18. **Done:** binding
  mismatch case.
- **T-SEC-03 Placeholder parser.** `{{secret:TAG}}` and `Secret("TAG")` handles
  with redaction-set tracking. **Refs:** SEC-03, SEC-01, SEC-08. **Done:** stringifying a
  handle outside transport fails.
- **T-SEC-04 Transport substitution.** Header, query, stdin, env slot, SDK slot;
  after policy and regulator. **Refs:** SEC-04, SEC-05, SEC-06, SEC-15. **Done:** a value
  never enters chat, receipts, files, logs, or the kernel.
- **T-SEC-05 Prompt model and UI.** One host-side request model rendered on every
  surface, with masked entry. **Refs:** SEC-05, SEC-03. **Done:** the TUI modal works; the
  agent cannot draw it.
- **T-SEC-06 Audit and modes.** Request, approval, substitution, rotation,
  revocation; action class behavior. **Refs:** SEC-06, SEC-09, SEC-15. **Done:** audit
  rows contain tags, never values.
- **T-SEC-07 `.env` rules.** Git-ignored `.env`, tracked `.env.example`, and a
  pre-commit guard. **Refs:** SEC-07, SEC-12. **Done:** committing a real value is
  blocked.
- **T-SEC-08 Scan and rotate.** File and git-history scan with rotation offer.
  **Refs:** SEC-08, SEC-10, SEC-14. **Done:** a planted key is found in history.
- **T-SEC-09 Leakage suite.** Tests across transcript, kernel, config, logs,
  teleport bundle, and crash reports. **Refs:** SEC-09, SEC-16, TST-08, TRU-08. **Done:** all
  sinks clean in CI.
- **T-SEC-10 Headless queue path.** Secret requests queue and independent work
  continues. **Refs:** SEC-10, SEC-13. **Done:** headless fixture.
- **T-SEC-11 Sign-in flows.** OpenCode Console OAuth and ChatGPT documented flow,
  with the terms gate. **Refs:** SEC-11, PRV-09, PRV-10, CRT-05. **Done:** tokens land in
  the store; an undocumented flow is disabled with the reason.

## M6 — Web, MCP, doctor, monitors, security review

- **T-WEB-01 Search engines and fusion.** Parallel adapters, RRF, dedupe.
  **Refs:** WEB-01, WEB-02. **Done:** relevance fixture with three engines.
- **T-WEB-02 Filters and provenance.** Freshness, domains, categories, substrings,
  result age. **Refs:** WEB-02, WEB-03, WEB-04. **Done:** filter matrix test.
- **T-WEB-03 Cache and resilience.** FTS5 cache with TTLs, backoff, breaker,
  bench-on-CAPTCHA. **Refs:** WEB-03, WEB-05, WEB-06. **Done:** a benched engine does not
  fail the search.
- **T-WEB-04 Fetch reader.** Reader-mode extraction and document formats.
  **Refs:** WEB-04, WEB-08, WEB-10. **Done:** fixture corpus per format.
- **T-WEB-05 Headless browser.** Local fallback with checksummed install and
  profile isolation. **Refs:** WEB-05, WEB-09. **Done:** a JS-only page renders.
- **T-WEB-06 Crawl.** Frontier, robots, sitemaps, limits, retries, resumable
  jobs. **Refs:** WEB-06, WEB-11, WEB-12. **Done:** kill and resume preserves progress.
- **T-WEB-07 Map and extract.** URL discovery and schema-driven extraction.
  **Refs:** WEB-07, WEB-13, WEB-14. **Done:** extraction validates against a schema.
- **T-WEB-08 Browser automation.** DevTools protocol actions. **Refs:** WEB-08, WEB-15.
  **Done:** scripted click, type, wait, screenshot flow.
- **T-WEB-09 SSRF and egress.** Address pinning, redirect checks, scheme refusal,
  secret checks, per-mode network policy. **Refs:** WEB-09, WEB-16, WEB-17. **Done:**
  metadata and loopback fixtures blocked.
- **T-WEB-10 Archive safety.** Zip-slip, symlink escape, and bomb limits.
  **Refs:** WEB-10, WEB-18. **Done:** fuzz corpus.
- **T-WEB-11 Budgets and untrusted labels.** Per-page cost and data labeling.
  **Refs:** WEB-11, WEB-19, WEB-21. **Done:** a crawl budget stops before the limit.
- **T-MCP-01 Core client.** Stateless calls, headers, `resultType`, caching,
  schema bounds. **Refs:** MCP-01..MCP-05. **Done:** fixtures for both revisions.
- **T-MCP-02 Transports.** stdio and Streamable HTTP, legacy shim off by default.
  **Refs:** MCP-02, MCP-06, MCP-17. **Done:** stdio launches scrubbed.
- **T-MCP-03 MRTR and elicitation.** `input_required` retry and URL-mode
  sensitivity. **Refs:** MCP-03, MCP-07, MCP-08. **Done:** form-mode credential refusal.
- **T-MCP-04 Tasks.** Poll, update, cancel, TTL, bearer-secret handling.
  **Refs:** MCP-04, MCP-09. **Done:** task lifecycle fixture.
- **T-MCP-05 Events.** Poll, push, webhook, cursors, signatures, TTL.
  **Refs:** MCP-05, MCP-10. **Done:** replay and signature tests.
- **T-MCP-06 Apps and extensions.** `ui://` sandbox, CSP, navigation block,
  unknown-extension tolerance. **Refs:** MCP-06, MCP-11, MCP-12. **Done:** a hostile app
  cannot navigate the host.
- **T-MCP-07 Auth.** OAuth 2.1, PKCE, resource indicators, issuer checks, CIMD.
  **Refs:** MCP-07, MCP-13. **Done:** token theft fixture fails.
- **T-MCP-08 Security.** Schema pinning, destructive-tool defaults, size caps,
  timeouts, SSRF, replay. **Refs:** MCP-08, MCP-14. **Done:** a changed schema warns and
  asks.
- **T-MCP-09 Resources and prompts.** `@` references, slash commands,
  completions. **Refs:** MCP-09, MCP-16. **Done:** a server resource resolves after
  restart.
- **T-MCP-10 Server mode.** Expose tools, sessions, and events behind a flag.
  **Refs:** MCP-10, MCP-15. **Done:** an editor drives a session over MCP.
- **T-MCP-11 Conformance.** Fixtures for `2025-11-25` and `2026-07-28`.
  **Refs:** MCP-11, MCP-19. **Done:** suite runs in CI.
- **T-DOC-01 Doctor binary.** Independent executable with a plugin-free core.
  **Refs:** DOC-01, DOC-09. **Done:** runs with the daemon dead.
- **T-DOC-02 Checks.** Versions, config, keys, workers, kernel, auth, network,
  mesh, ports, disk, locks, journals, MCP. **Refs:** DOC-02, DOC-03. **Done:** each check
  has a fixture.
- **T-DOC-03 Playbooks.** One per failure code. **Refs:** DOC-03, DOC-04, DOC-11.
  **Done:** fault injection per code.
- **T-DOC-04 Repair.** Dry-run, snapshot, reversible apply, rollback, policy
  bound. **Refs:** DOC-04, DOC-05, DOC-06, DOC-10. **Done:** a failed repair rolls back.
- **T-DOC-05 Forensics.** Timeline and redacted offline bundle. **Refs:** DOC-05, DOC-07, OBS-07. **Done:** bundle contains no secret.
- **T-MON-02 Monitor engine.** Line streaming, coalescing, stderr to logs.
  **Refs:** MON-02, MON-06, MON-13, MON-11, MON-14. **Done:** burst test.
- **T-MON-03 Declarative monitors.** Plugin definitions and skill-triggered
  start. **Refs:** MON-03, MON-07..MON-10. **Done:** a plugin monitor starts on skill
  invoke.
- **T-SR-01 Checklist.** Trust-boundary summary and ledger seeding.
  **Refs:** SR-01, SR-02, SR-03. **Done:** a fixture repo produces a valid ledger.
- **T-SR-02 Ledger schema.** Canonical refs, states, history, and validators.
  **Refs:** SR-02, SR-03, SR-06, SR-13. **Done:** validator rejects duplicates and bad refs.
- **T-SR-03 Hunting waves.** Per-unit agents, result schema, critic pass.
  **Refs:** SR-03, SR-04. **Done:** a planted bug is found by its unit.
- **T-SR-04 Validation.** Independent verifiers, fingerprint stability, rejection
  path. **Refs:** SR-04, SR-05, SR-07. **Done:** a false positive is rejected.
- **T-SR-05 Sandbox execution.** No network, allowlisted env, read-only target,
  scratch-only writes, resource caps, promotion rules. **Refs:** SR-05, SR-09, SR-10, TRU-07.
  **Done:** an escape attempt is blocked and reported.
- **T-SR-06 Reports.** Derived from records only, with coverage and budget gaps.
  **Refs:** SR-06, SR-14. **Done:** prose and JSON agree in a fixture.
- **T-SR-07 Fixture suite.** Vulnerable, clean, and partial-coverage repos.
  **Refs:** SR-07, SR-11, SR-12. **Done:** three golden runs.
- **T-SR-08 Zero integration.** Units as tasks, output under `.zero/audits/run-N`,
  offline. **Refs:** SR-08, SR-15, SR-16. **Done:** run appears on the task panel.

- **T-DOC-06 Doctor agent API.** `diagnose`, `plan`, and `apply` tools with a required unresolved-failure report. **Refs:** DOC-06, DOC-08. **Done:** an agent cannot finish a turn hiding an unresolved failure.
- **T-MON-04 Monitor restart policy.** Restart after teleport or resume only with confirmation. **Refs:** MON-04, MON-12, MON-11. **Done:** a monitor does not silently restart.

## M7 — Halcyon, model pool, usage, auto-resume

- **T-HAL-01 Discovery and trust.** Nearest-file rule, symlink rejection, and
  untrusted-workspace inertness. **Refs:** HAL-01, HAL-02, HAL-12. **Done:** a
  hostile repo cannot enable the mode.
- **T-HAL-02 Signature verification.** Canonical bytes, pinned key, expiry,
  project binding. **Refs:** HAL-02, HAL-03, HAL-05. **Done:** a copied repo needs its own
  signed file.
- **T-HAL-03 Key tooling.** Keygen, sign, pin, rotate, revoke, verify.
  **Refs:** HAL-03, HAL-04. **Done:** the agent cannot sign or rotate.
- **T-HAL-04 Adapters.** Runtime detection and version negotiation for `tkb`,
  `joker`, `epb`. **Refs:** HAL-04, HAL-07, HAL-13. **Done:** a missing binary shows
  install guidance.
- **T-HAL-05 Behaviour rules.** Gap recording, gates only through `joker`,
  endpoints through `epb`, check and handover before finish. **Refs:** HAL-05, HAL-08, HAL-09. **Done:** a run without `tkb check` is refused.
- **T-HAL-06 Flags.** Four flags only, resolved without project override.
  **Refs:** HAL-06, HAL-10. **Done:** project config cannot enable a flag.
- **T-HAL-07 Todo sync.** Two-way, idempotent, offline queue, visible conflicts.
  **Refs:** HAL-07, HAL-11, TODO-09, TSK-12. **Done:** a conflict surfaces as an item.
- **T-MDL-01 Pool data.** Capability grades, costs, limits, availability.
  **Refs:** MDL-01. **Done:** seeded from the classification data with a source
  recorded.
- **T-MDL-02 Classifier.** Work classes and capability floors.
  **Refs:** MDL-02, MDL-03. **Done:** a security task never downgrades.
- **T-MDL-03 Router and escalation.** Cheapest above floor, evidence-based
  escalation, deprecation reroute. **Refs:** MDL-03, MDL-02, MDL-04, MDL-14, SCH-06, MDL-10, MDL-12. **Done:** a
  failure escalates with evidence attached.
- **T-MDL-04 Roles.** Planner, coder, reviewer, tester, researcher, vision.
  **Refs:** MDL-04, MDL-07. **Done:** a subagent uses its role default.
- **T-MDL-05 Translation.** Cross-provider transcript conversion with recorded
  drops. **Refs:** MDL-05, MDL-13. **Done:** escalation mid-task keeps tool IDs valid.
- **T-MDL-06 Decision records.** Model, version, parameters, reason, cost per
  turn. **Refs:** MDL-06, MDL-11. **Done:** audit reconstructs each turn.
- **T-MDL-07 Budgets and measured routing.** Prediction, reconciliation, and
  outcome-based routing with sample minimums. **Refs:** MDL-07, MDL-08, MDL-09.
  **Done:** routing changes only with evidence.
- **T-USG-01 Ledger.** Per-device append-only events and union sync.
  **Refs:** USG-01, USG-02, USG-08, AUT-06. **Done:** two devices merge without conflict.
- **T-USG-02 Budgets and dashboards.** Warn and stop modes on every surface.
  **Refs:** USG-02, USG-03, USG-04, USG-06. **Done:** a stop budget halts dispatch.
- **T-USG-03 Cost audit.** Spend analysis and bounded proposals.
  **Refs:** USG-03, USG-05, SI-10. **Done:** `--apply` is required to change anything.
- **T-AR-02 Resume policy.** Automatic, device-change prompt, bounded retries,
  budget refusal. **Refs:** AR-02, AR-05. **Done:** matrix test.
- **T-AR-03 Usage-window resume.** Pause, display, and resume on reset.
  **Refs:** AR-03, AR-06, AR-07, AR-08. **Done:** simulated reset resumes without
  replaying effects.

- **T-PRV-05 Console provider.** OpenCode Console with `oc_sk_` keys and Go usage. **Refs:** PRV-05, PRV-06, PRV-09. **Done:** a paid key routes a turn; an invalid key fails with the documented code.
- **T-PRV-06 Catalogue refresh.** Refresh with a recorded source and keep an offline copy. **Refs:** PRV-06, PRV-08, PRV-01. **Done:** offline start uses the cached catalogue.
- **T-MDL-08 Model data freshness.** Scheduled refresh with a source and a drift report. **Refs:** MDL-08, MDL-15, MDL-01. **Done:** a stale table warns instead of routing on it silently.

## M8 — Mesh, teleport, self-improvement

- **T-MESH-01 Identity.** Device key, approval flow, join tokens, rotation.
  **Refs:** MESH-01, MESH-08. **Done:** an unapproved device cannot join.
- **T-MESH-02 Signed state.** Versioned, signed membership with owner root.
  **Refs:** MESH-02, MESH-09, MESH-11, MESH-15. **Done:** a stolen device cannot evict others.
- **T-MESH-03 LAN discovery.** Authenticated mDNS with no service.
  **Refs:** MESH-03, MESH-14, MESH-12. **Done:** an unauthenticated peer is ignored.
- **T-MESH-04 Traversal.** Discovery, hole punching, TCP fallback.
  **Refs:** MESH-04, MESH-10. **Done:** NAT matrix passes; failure explains
  rendezvous.
- **T-MESH-05 Relay.** Ciphertext-only relay through approved nodes.
  **Refs:** MESH-05. **Done:** a relay cannot read payloads.
- **T-MESH-06 Join UX.** QR and short code. **Refs:** MESH-06, MESH-07. **Done:** join in
  under a minute on two devices.
- **T-MESH-07 Transport spike.** Userspace TCP/IP versus datagram streams; record
  the decision. **Refs:** MESH-07, MESH-01. **Done:** a prototype moves a session stream
  over the overlay.
- **T-MESH-08 Revocation and partition tests.** **Refs:** MESH-08, MESH-09,
  LCK-10. **Done:** partitioned minority cannot write; revocation propagates.
- **T-MESH-09 Presence and cost.** Online/offline only, battery and metered
  awareness. **Refs:** MESH-09, MESH-13, MESH-14. **Done:** sleeping host shows offline.
- **T-TEL-01 Snapshot.** Session, kernel, artifacts, goals, schedules, ledger,
  manifest. **Refs:** TEL-01, TEL-03, TODO-07. **Done:** snapshot restores on the same device.
- **T-TEL-02 Bundle.** Content-addressed chunks, dedupe, resumable, exclusions
  reported. **Refs:** TEL-02, TEL-04, TEL-05. **Done:** an interrupted bundle resumes.
- **T-TEL-03 Transfer and verify.** E2E encryption, hash verification, retention
  until verified. **Refs:** TEL-03, TEL-06, TEL-09. **Done:** a corrupted chunk fails
  verification.
- **T-TEL-04 Restore.** Files, modes, symlinks, transcript, kernel, schedules,
  children. **Refs:** TEL-04, TEL-07, TEL-08. **Done:** restore into a conflicting
  directory stages instead of overwriting.
- **T-TEL-05 Fence and resume.** Lease handoff with generation counters.
  **Refs:** TEL-05, TEL-10, TEL-11, FS-10. **Done:** source cannot write after fencing.
- **T-TEL-06 Portability.** Path remapping, kernel rebuild, and tool preflight.
  **Refs:** TEL-06, TEL-01, TEL-12, TEL-13, TEL-14. **Done:** Windows to Linux and no-git
  directory runs pass.
- **T-TEL-07 Vault ciphertext.** Vault travels and needs one unlock.
  **Refs:** TEL-07, SEC-11, TEL-05. **Done:** target prompts once and cannot decrypt
  silently.
- **T-TEL-08 Failure matrix.** Interrupted, unreachable source, forced takeover,
  return trip. **Refs:** TEL-08, TEL-10, TEL-13, TEL-14. **Done:** all four fixtures.
- **T-SI-01 Evaluation suite.** Versioned held-out tasks the candidate cannot
  read. **Refs:** SI-01, SI-05, SI-10. **Done:** the suite runs offline.
- **T-SI-02 Loop.** Execute, verify, capture, distil, evaluate, promote, re-enter.
  **Refs:** SI-02, SI-01, SR-17..SI-04, SI-08. **Done:** one accepted and one rejected change in
  a fixture.
- **T-SI-03 Promotion and rollback.** Immutable core, human gate, diffs,
  reversibility. **Refs:** SI-03, SI-06, SI-07, SI-09. **Done:** a candidate touching the
  evaluator is refused.

- **T-TSK-06 Mesh task replication.** One writer per task across devices with fenced leases. **Refs:** TSK-06, TSK-10, LCK-07. **Done:** two devices cannot run the same task.
- **T-SCH-07 Distributed limits.** Share one credential's limit through the owning node, with a conservative offline share. **Refs:** SCH-07, SCH-12, SCH-13. **Done:** two devices do not exceed the limit together.

## M9 — Desktop, web, Android, multimodal

- **T-DSK-01 Desktop shell.** System webview around the local UI, loopback only.
  **Refs:** features.md 6.1, ACT-01. **Done:** no bundled browser engine; the
  action registry is shared.
- **T-DSK-02 Shared UI states.** Palette, modes, approvals, and secrets prompt
  reuse the same model. **Refs:** ACT-03, TUI-14, SEC-03. **Done:** identical
  behaviour to the TUI in a scripted comparison.
- **T-WEBUI-01 Web app.** Same UI served locally with a one-time token.
  **Refs:** ACT-16. **Done:** no public listener.
- **T-AND-01 Pairing.** QR or one-time code, biometric unlock, no public endpoint.
  **Refs:** AND-01, AND-02. **Done:** a stolen code cannot pair.
- **T-AND-02 Session control.** List, transcript, prompt, steer, queue, cancel,
  diffs. **Refs:** AND-02, AND-03. **Done:** full flow over the mesh.
- **T-AND-03 Approvals and secrets.** Hash-bound approvals, lock-screen hiding,
  `FLAG_SECURE` prompt. **Refs:** AND-03, AND-04, AND-08. **Done:** replay of an old
  approval fails.
- **T-AND-04 Notifications and offline.** Foreground service or UnifiedPush,
  offline queue, cursor reconnect. **Refs:** AND-04, AND-05, AND-06. **Done:** airplane
  mode then reconnect delivers queued input once.
- **T-AND-05 Share and resources.** Share sheet and relay/direct reporting.
  **Refs:** AND-05, AND-07, AND-10, AND-09, AND-11, MM-12. **Done:** a shared image reaches the
  session; no VPN eviction.
- **T-MM-01 Inputs and blocks.** Attachments, `@` references, typed blocks,
  per-modality accounting. **Refs:** MM-01, MM-02. **Done:** every input route has
  a fixture.
- **T-MM-02 Preprocessing.** Downscale, tile, OCR, frame sampling, transcription,
  originals retained. **Refs:** MM-02, MM-03, MM-04. **Done:** re-read at full
  resolution works.
- **T-MM-03 Sandboxed computer use.** VM or virtual display with network
  allowlist and no host filesystem. **Refs:** MM-03, MM-05, MM-06, MM-10. **Done:** an
  escape attempt is blocked.
- **T-MM-04 Live host computer use.** Higher-risk class with mandatory asks.
  **Refs:** MM-04, MM-05, MM-11, MM-07. **Done:** manual mode asks for every action.
- **T-MM-05 Verification and recordings.** Labeled screenshots, chapters,
  assertions, shortcut flags. **Refs:** MM-05, MM-08, MM-09. **Done:** a passing and a
  failing flow produce artifacts.
- **T-MM-06 Local CPU models.** Consent prompt with licence, disk, memory, and
  purpose. **Refs:** MM-06, MM-13, MM-14. **Done:** declining leaves the modality
  unavailable with an explanation.

## M10 — Release hardening

- **T-INST-01 Packaging.** Per-platform artifacts, SBOM, signed manifest.
  **Refs:** INST-01, INST-11, INST-02. **Done:** manifest verifies with the
  embedded key.
- **T-INST-02 Windows installer.** Non-admin path, PATH update, lock, conflict
  detection, non-interactive mode. **Refs:** INST-02, INST-04..INST-06. **Done:** clean VM
  install in CI.
- **T-INST-03 Unix installer.** POSIX and macOS paths, lock, traps, terminal
  restore, no-TTY mode. **Refs:** INST-03, INST-04, INST-05. **Done:** clean container and
  macOS VM installs.
- **T-INST-04 Update and rollback.** Atomic signed update with rollback.
  **Refs:** INST-04, INST-08, INST-10. **Done:** a corrupted update rolls back cleanly.
- **T-INST-05 Service units.** systemd, Windows service, launchd.
  **Refs:** INST-05, INST-09. **Done:** start, stop, and status on all three.
- **T-INST-06 Kernel bootstrap.** `uv`, Python, `ipykernel`, checksums, offline
  mode. **Refs:** INST-06, INST-07. **Done:** offline bootstrap from a local cache.
- **T-INST-07 Uninstall.** Trash user data after confirmation, remove services and
  PATH entries. **Refs:** INST-07, INST-12. **Done:** no orphaned state remains.
- **T-OBS-01 Metrics.** Queue depth, latency, 429s, retries, cost.
  **Refs:** OBS-01, OBS-03, SCH-10, OBS-08. **Done:** a dashboard reads local metrics.
- **T-OBS-02 Tracing.** Local end-to-end trace of a turn. **Refs:** OBS-02, OBS-04.
  **Done:** a trace spans provider, tools, and frame render.
- **T-OBS-03 Retention.** Documented retention with trash on expiry.
  **Refs:** OBS-03, OBS-06. **Done:** retention job uses `trash`.
- **T-TST-05 Network impairment.** Loss, latency, partition, NAT matrix.
  **Refs:** TST-05. **Done:** suite green.
- **T-TST-06 Fault injection.** Every doctor code. **Refs:** TST-06. **Done:** all
  codes exercised.
- **T-TST-07 Security suites.** SSRF, zip-slip, prompt injection, secret leakage.
  **Refs:** TST-07, TST-08. **Done:** suites gate the release.
- **T-TST-08 Conformance gate.** MCP and protocol fixtures. **Refs:** TST-08, TST-10.
  **Done:** both revisions pass.
- **T-PERF-01 Baselines and gates.** Startup, frame, attach, memory, session size.
  **Refs:** TST-07. **Done:** budgets recorded and enforced.
- **T-PAR-03 Parity audit.** Every Part 1, 2, and 8 item mapped with a state and a
  reason. **Refs:** PAR-03, PAR-01..PAR-04. **Done:** no "unassessed" rows.
- **T-DOCS-01 Documentation set.** Install, configure, modes, secrets, mesh,
  teleport, review, troubleshooting. **Refs:** PAR-04, DEL-11, DEL-12, KRN-08, WEB-20. **Done:** a new user can
  install and run from the docs alone.

---

## Coverage checks

- Every requirement ID in `features.md` Part 10 appears in at least one task's
  **Refs**. `T-PAR-01` enforces this in CI.
- Every task belongs to exactly one milestone and lists at least one dependency
  unless it is the first task in its area.
- A task may not be marked `done` without its **Done** evidence recorded in the
  same change.
- Deferred work keeps its task and moves milestone; it does not disappear.
