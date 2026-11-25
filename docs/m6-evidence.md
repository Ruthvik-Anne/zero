# M6 evidence

M6 covers web tools, MCP, doctor, monitors, and security review. Two slices are
implemented so far; the rest of the milestone is open.

## Web search and fusion — T-WEB-01 (done)

`zero-web` now has a keyless adapter contract and reciprocal-rank fusion
(WEB-01, WEB-02). `search` runs every healthy engine in parallel with
`std::thread::scope`, collects outcomes in caller order for deterministic
output, and turns a failed or panicking engine into one `SearchError` without
failing the search. `fuse` is the pure fusion step for cached or replayed
rankings. Fusion uses `k = 60`, merges duplicates by canonical host+path or by
normalized title (title keys shorter than eight characters are ignored so
generic headings do not collapse across hosts), keeps the fields of the
best-ranked hit, sums duplicate scores, and retains every contributing
engine rank as provenance.

| Test | Covers |
|---|---|
| `three_engine_fixture_fuses_by_reciprocal_rank` | Three engines, expected RRF order and scores, merged sources. |
| `duplicate_urls_merge_into_one_result` | Scheme/query/fragment/`www` normalization. |
| `fuzzy_titles_merge_when_urls_differ` | Fuzzy title dedupe. |
| `short_generic_titles_do_not_collapse_across_hosts` | Ambiguous short titles stay separate. |
| `failed_engine_is_reported_without_failing_search` | Per-engine error isolation. |
| `unhealthy_engine_is_skipped` | Health check. |
| `empty_query_and_zero_limit_return_no_results` | No engine is consulted. |
| `canonical_url_key_normalizes_noise`, `title_normalization_ignores_punctuation_and_case`, `fuse_respects_limit_and_empty_input` | Key construction and limit handling. |

Command: `cargo test -p zero-web`.

## Doctor binary — T-DOC-01 (done)

`zero-doctor` is a separate executable with a plugin-free core. `run_core`
returns `DoctorReport { version, independent, daemon, checks }` and never
imports `zero-daemon` or opens a socket; `daemon` starts as `not_contacted`.
The binary supports `--json`, `--version`, and `--help`, and exits zero.

| Test | Covers |
|---|---|
| `runs_with_the_daemon_dead_and_says_it_was_not_contacted` | Dead daemon socket paths; exit 0; no socket created. |
| `json_report_is_independent_and_never_contacted_the_daemon` | JSON contract: `independent: true`, `daemon: "not_contacted"`, empty checks. |
| `version_flag_prints_the_version_without_a_daemon` | Version path needs no daemon. |

Commands: `cargo test -p zero-doctor`, `cargo clippy -p zero-doctor
--all-targets -- -D warnings`.

## Still open in M6

T-WEB-02..11, T-MCP-01..11, T-DOC-02..06, T-MON-01..04, and T-SR-01..08.

Hosted run [45563857571](https://github.com/Ruthvik-Anne/zero/actions/runs/45563857571)
on `fd1f322d`: all ten jobs successful.
