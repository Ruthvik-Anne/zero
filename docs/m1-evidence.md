# M1 evidence

Commands were run from the repository root on 2026-11-25. Per task:

| Task | Evidence | Observed |
|---|---|---|
| T-SES-01 | `cargo test -p zero-store session::tests::round_trip_covers_every_entry_kind` | 13 kinds append, reread, and equal their originals; wire tags stable. |
| T-SES-02 | `cargo test -p zero-agent tree::tests::three_level_tree_forks_resumes_and_renders` | A→B→C parent chain, fork prefix `a0..a2`, cumulative `src/lib.rs=2`, render indented tree, clone copies all. |
| T-SES-03 | `cargo test -p zero-agent compaction::tests::long_session_compacts_without_losing_the_visible_tail_or_kernel_state` | 100 messages → 92 removed, 8 kept (`m92..m99`), kernel state and both hook records survive, generation 2. |
| T-SES-04 | `cargo test -p zero-agent --test summary_resume` | Fixture passes shape; resumed prompt contains `GOAL: ship the release` and `NEXT STEPS`. |
| T-SES-05 | `cargo test -p zero-agent context::tests` | Same-dir AGENTS beats CLAUDE; nested wins; 32 KiB cap truncates on a char boundary. |
| T-SES-06 | `cargo test -p zero-store --test session_lease` | Two processes: exactly one `created`, the other `existing` with the winner's pid; one record in the log. |
| T-SES-07 | `cargo test -p zero-store --test attach -- --nocapture` | `attach: 618 MiB, 5242880 records, tail 24792 bytes, index 400 bytes, elapsed 4.65s`; second attach reuses the index. |
| T-SES-08 | `cargo test -p zero-daemon` | Killed worker restarted once with a new pid; failing worker stopped at 4 failures / 3 restarts; adopted worker healthy and stopped by the stop file. |
| T-SES-09 | `cargo test -p zero-store journal::tests` | Replay returns the recorded result with one effect; a `begin` without a result is `command_uncertain` and never re-run. |
| T-SES-10 | `cargo test -p zero-agent export::tests::export_wipe_import_resume_produces_an_identical_transcript` | Transcript equal after export, wipe, import; generation and name preserved; artifact restored. |
| T-SES-11 | `cargo test -p zero-agent r#loop::tests::scripted_three_turn_fixture_runs_end_to_end` | 3 provider turns, 2 tool results, usage 60/9, 3 turn records, 2 tool transcript entries. |
| T-SES-12 | `cargo test -p zero-cli --test line` | Line client runs two turns, prints `tool:`, `assistant:`, `usage:`, exits 0; second run resumes and appends. |
| T-PRV-01 | `cargo test -p zero-model conformance::tests::scripted_provider_passes_the_conformance_suite` | 5 cases pass; a no-tools script fails the tool case. |
| T-PRV-02 | `cargo test -p zero-model --test http_fixture hosted_*` | Real adapter over loopback HTTP: text, tool call, usage 21/7, stop=tool_calls; 401 → `zero.prv.auth`. Live test skipped without `ZERO_LIVE_OPENAI=1`. |
| T-PRV-03 | `cargo test -p zero-model --test http_fixture local_*` | Offline NDJSON session: text, tool call, usage 12/5; `/api/show` detects `tools`. Live test skipped without `ZERO_LIVE_OLLAMA=1`. |
| T-PRV-04 | `cargo test -p zero-model errors::tests::a_fixture_for_every_error_code` | 14 status/body fixtures and 6 transport kinds map to the documented codes; retry-after survives 429. |
| T-MON-01 | `cargo test -p zero-agent queue::tests` | Steer mid-tool delivers nothing and stays queued; delivered once at the boundary; full queue rejects new and keeps old; reload preserves items. |
| T-AR-01 | `cargo test -p zero-agent r#loop::tests::crash_mid_turn_resumes_without_duplicating_the_side_effect` | A durable `begin` with no result is reported uncertain, the tool runs 0 times, the effect file still has one line, the loop continues. |
| T-SES-13 | `cargo test -p zero-agent artifacts::tests::artifacts_resolve_from_the_transcript_after_resume` and `tree::tests::auto_names_from_project_and_timestamp` | Artifact resolves with size and hash after reopen; names are `<project> <YYYYMMDD-HHMMSS>`. |

## Aggregate

`cargo test --workspace`: **148 passed, 0 failed**.

| Suite | Tests |
|---|---|
| zero-store | 22 unit + 1 attach (500 MiB) + 1 concurrent lease + 1 kill loop |
| zero-model | 16 unit + 4 HTTP fixtures + 2 live (skipped without flags) |
| zero-agent | 24 unit + 1 summary resume |
| zero-daemon | 3 supervisor |
| zero-cli | 9 CLI + 2 line mode |
| zero-types | 42 |
| zero-arch | 13 unit + 3 docs |
| zero-tui | 4 |

```text
$ powershell -NoProfile -File .\ci-local.ps1
...
local CI: OK
```

The live adapter tests print a skip reason unless their environment flag is set;
they are not counted as verification of a live provider.
