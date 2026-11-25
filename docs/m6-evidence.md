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

## Filters and provenance — T-WEB-02 (done)

`filter::apply` narrows a fused response without touching scores or order and
attaches a `Provenance { published, age_days, source }` to every survivor
(WEB-03, WEB-04). Filters are ANDed: freshness (Day/Week/Month/Year), include
and exclude domains (host or subdomain; exclusion wins), categories
(`docs`/`code`/`news`/`general` by a documented URL rule), and required or
forbidden substrings over title+snippet. Freshness is fail-closed: an absent or
unparseable date is dropped when a window is set. Dates accept `YYYY-MM-DD` and
RFC 3339 with an explicit offset; everything else yields `age_days: None` and
`source: unknown` rather than a guess.

| Test | Covers |
|---|---|
| `filter_matrix_keeps_exactly_the_expected_urls` | 19 table-driven cases: every filter alone and combined, fail-closed dates, exclude-over-include. |
| `filtering_preserves_scores_and_order` | Fusion fields and order are untouched. |
| `provenance_records_age_and_date_source` | Age, raw value, and source for parseable, unparseable, and absent dates. |
| `future_dates_clamp_to_age_zero`, `freshness_windows_are_documented_days` | Clock skew and window constants. |
| `timestamp_parser_accepts_only_documented_forms` | Accepted formats and 19 rejected forms. |
| `category_classification_follows_documented_rule`, `canonical_host_normalizes_www_and_ports` | Category and host rules. |

Command: `cargo test -p zero-web` (18 tests).

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

## Cache and resilience — T-WEB-03 (done)

`zero-web` now has a SQLite/FTS5 search cache and a resilience layer
(WEB-05, WEB-06). `SearchCache` stores whole `SearchResponse` payloads under a
`(query, category)` key with per-category TTLs and an optional tighter
cache-age limit, mirrors titles/snippets into an FTS5 table for later local
search, deletes expired entries, treats corrupt payloads as a miss, and
returns `zero.fnd.unsupported` when the running SQLite lacks FTS5 instead of
panicking. `ResilientSearch` adds a per-engine rate limit, capped exponential
backoff, a three-state circuit breaker, a reserve engine used only when no
primary answers, and CAPTCHA/login benching: a refusal excludes the engine for
the cooldown, is not reported as a failure, and does not fail the search.

| Test area | Evidence |
|---|---|
| Cache | 16 tests: round trip, expiry, per-category TTL, cache-age rejection, category invalidation, FTS5 search, reopen persistence. |
| Resilience | 17 tests: breaker open/half-open/close, capped backoff, rate window, reserve fallback, panic isolation. |
| Benching | A "captcha" refusal from one engine still returns the other engine's results, stays out of `failed`, and `benched` clears after the cooldown. |

Commands: `cargo test -p zero-web` (51 tests + 1 doc test), `cargo clippy
-p zero-web --all-targets -- -D warnings`.

## MCP core client — T-MCP-01 (done)

`zero-mcp` now has a stateless JSON-RPC 2.0 client over an in-memory
`Transport` seam (MCP-01..05): strict envelope validation, request-id echo,
typed JSON-RPC error mapping, revision negotiation for `2025-11-25` and
`2026-07-28`, case-insensitive routing headers, `initialize` / `tools/list` /
`tools/call`, `resultType` handling, a per-server/revision `tools/list` cache
with TTL and schema-hash invalidation, and bounded schema validation (64 KiB,
depth 32, 4096 nodes) with a deterministic schema hash. Two JSON fixtures cover
both revisions.

| Test area | Evidence |
|---|---|
| Envelopes and errors | `cargo test -p zero-mcp` unit tests: malformed envelope, id mismatch, both `result` and `error`, JSON-RPC code mapping. |
| Revisions and resultType | `2025-11-25` treats every result as complete; `2026-07-28` reads `complete` / `input_required` / unknown passthrough. |
| Caching | Second `tools/list` does not touch the transport; TTL, `ttlMs == 0`, invalidation, and schema-change refresh. |
| Schema bounds | Oversize, too-deep, and over-node schemas fail with typed errors; names cannot be empty. |
| Fixtures | `tests/core_client.rs` (14 integration tests) against `tests/fixtures/2025-11-25.json` and `2026-07-28.json`. |

Commands: `cargo test -p zero-mcp` (27 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings`.

## MCP transports — T-MCP-02 (done)

`zero-mcp` now ships the stdio and Streamable HTTP transports (MCP-02, MCP-06,
MCP-17). `StdioTransport` launches a child with a scrubbed environment (the
`KEY`/`TOKEN`/`SECRET`/`PASSWORD`/`CREDENTIAL` policy, with agent sockets
exempt), speaks newline-delimited JSON-RPC with an 8 MiB line bound and a
30 s request timeout, skips notifications and non-JSON log lines while matching
ids, keeps a bounded redacting stderr tail, and kills/reaps on timeout or drop.
`HttpTransport` POSTs to an http/https URL with `Content-Type`,
`Accept: application/json, text/event-stream`, configured routing headers, and
the server's `Mcp-Session-Id`, then accepts either a JSON body or an SSE body.
The legacy HTTP+SSE shim is not the default and `connect` refuses it with
`zero.fnd.unsupported`. The stdio test respawns the test binary as a helper
child, proving scrubbing and framing without an external runtime.

| Test area | Evidence |
|---|---|
| stdio | Helper-process initialize and tool call; a fake secret variable is absent inside the child; timeout returns `zero.fnd.timeout` and kills; drop reaps. |
| HTTP | Loopback JSON response, SSE `data:` response, session-id propagation, non-2xx status without body echo. |
| Legacy | `LegacyHttpSse` is refused when selected. |

Commands: `cargo test -p zero-mcp` (43 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings`.

## Still open in M6

T-WEB-04..11, T-MCP-03..11, T-DOC-02..06, T-MON-01..04, and T-SR-01..08.

Hosted runs [45563857571](https://github.com/Ruthvik-Anne/zero/actions/runs/45563857571)
on `fd1f322d`, [45565878012](https://github.com/Ruthvik-Anne/zero/actions/runs/45565878012)
on `702b2ec4`, and [45570302744](https://github.com/Ruthvik-Anne/zero/actions/runs/45570302744)
on `61cf6e5f`: all ten jobs successful.
