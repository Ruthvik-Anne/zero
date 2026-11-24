# M0 evidence

Every command below was run from the repository root on 2026-11-25 (Windows,
`rustc 1.98.1`, host `x86_64-pc-windows-gnu`). This file is the long form of the
M0 closure table in [`tasks.md`](../tasks.md).

## Aggregate

```text
$ powershell -NoProfile -File .\ci-local.ps1
== build (host)
== lint (clippy -D warnings)
== test (host)
== traceability and architecture
== benchmark gate
== protocol readers
== cross-check portable crates (aarch64-pc-windows-msvc)
== cross-check portable crates (x86_64-apple-darwin)
== cross-check portable crates (aarch64-apple-darwin)
== cross-check portable crates (x86_64-unknown-linux-gnu)
== cross-check portable crates (aarch64-unknown-linux-gnu)
local CI: OK
```

`cargo test --workspace`: **86 passed, 0 failed** across unit, integration, and
durability tests.

| Crate | Tests |
|---|---|
| zero-arch | 13 unit + 3 docs |
| zero-types | 42 |
| zero-store | 14 unit + 1 kill loop |
| zero-tui | 4 |
| zero-cli | 9 |

## Documents and graph

```text
$ cargo run -p xtask -- check-docs
traceability: 478 requirements, 276 tasks, 38 areas
traceability: OK
architecture: 24 crates, 23 edges
architecture: OK
```

Negative fixtures: `traceability::tests` covers an uncovered requirement, a task
without refs, an unknown ref, a duplicate task id, and full coverage passing.
`deps::tests` covers an upward edge, a same-layer edge, a three-node cycle with
the path, an unlisted dependency, and the real workspace.

## Error taxonomy

```text
$ cargo run -p xtask -- errors-doc --write
wrote ...\docs\errors.md (53 codes)
```

`error::tests::every_code_has_a_stable_unique_name_and_remediation` checks
uniqueness and a remediation line; `documented_codes_match_the_enum_exactly`
compares `docs/errors.md` to the enum in both directions.

## Determinism

`id::tests::same_seed_reproduces_identical_event_order` schedules 1,000 events
twice with seed 42 and compares the joined traces; seed 43 must differ.
`sim::tests::example_lock_trace_reproduces_exactly` repeats a two-actor lock race
for 50 seeds and asserts determinism per seed plus at least one explored deny.

## Configuration and paths

`config::tests::matrix_covers_every_layer_pair` asserts 15 ordered pairs
(6 layers), and `untrusted_project_config_is_inert` asserts the untrusted layer
loses to every other layer and produces nothing alone.

`paths::tests` asserts 12 paths (four kinds on three platforms) and compares
`docs/data-directories.md` row by row. Linux XDG overrides are covered.

## Store and durability

```text
$ cargo test -p zero-store --test kill_loop -- --nocapture
kill loop: 76 complete records, 0 runs ended with a torn tail
test result: ok. 1 passed
```

The loop starts the `append-loop` child four times, hard-kills it, then verifies
every surviving record parses, the replay sequence is dense from zero, and a new
writer can continue after repair.

`durability::tests::one_thousand_injected_crashes_leave_no_torn_record` runs
1,000 seeded crash offsets across a 64-record stream, asserts the surviving set
is a prefix, that no torn record is returned, that the torn tail is at most one
record, and that repair plus append is clean.

SQLite: `wal_mode_is_on_and_survives_reopen` asserts `journal_mode=wal`, the
schema version, event count, and KV round-trip across reopen;
`newer_schema_is_refused_not_downgraded` asserts the typed refusal.

Blobs: dedupe (`put` twice, one object), corruption detection on read, missing
id, and a chunked round-trip across the 4 MiB boundary.

Migrations: v1 and v2 fixtures migrate to v3 and equal the canonical v3 fixture;
the backup holds the original; downgrade is refused with the file untouched; a
missing step fails before any backup or write.

## Protocol

```text
$ node protocol/ts/check.mjs
typescript reader: 2 golden fixture file(s) decoded and re-encoded identically
```

Plus `proto::tests::golden_fixtures_decode_identically`, truncation and
oversize rejection, unknown version refusal, and all nine frame kinds round-trip.

## CLI

`cargo test -p zero-cli` (9 tests): unknown `resum` prints `` `resume` `` and
exits non-zero; `frobnicate` prints "unknown verb"; `--version` succeeds before
any installer step; help lists exactly the permitted verbs; `doctor --json`
passes six checks on a fresh directory; `login` reports
`zero.fnd.unavailable`; `resume --list` handles no sessions; all four completion
shells work; `service status` says "not installed".

## Limits and offline

`limits::tests` runs a simulated allocation flood, file-size flood, disk flood,
process flood, and CPU flood; each stops at the bound with
`zero.fnd.limit_exceeded` naming the resource.

`net::tests` asserts every network feature is unavailable offline with
`zero.fnd.offline`, local provider and file work stay available, and an unknown
network state is not silently treated as online.

`telemetry::tests` asserts the default build drops every event, opens no network
call, and refuses transmission.

## Benchmarks

```text
$ cargo run -p xtask -- bench --check
startup_ms=197.68 frame_us=2594.18 attach_ms=419.77
benchmarks: OK against ...\bench\baselines.json
```

Baselines are recorded with 1.5x headroom and a 4.0 tolerance. Startup measures
the built `zero --version` (one warm-up, then 9 samples, median); frame measures
a 120x40 render (500 iterations x 5 samples after a warm-up); attach measures a
50,000-record scan (median of 3). The warm-up keeps Windows' first-launch disk
and scanner cost out of the measurement.

## The one open item

`T-TST-01` asks for all six targets green on a clean cache in CI. The workflow is
committed and the local script is green, including cross-checks of the portable
crates on the five non-host targets. The host target is `x86_64-pc-windows-gnu`;
the bundled SQLite C build needs a native or cross C toolchain for the other
targets, which this machine does not have. A hosted run of
`.github/workflows/ci.yml` is therefore the outstanding evidence. It is marked
`doing`, not `done`.
