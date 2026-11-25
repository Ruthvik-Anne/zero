# Observability

This page documents the local metrics registry and dashboard (T-OBS-01), the
local turn trace (T-OBS-02), and retention for observability and session data
(T-OBS-03). Log emission, the audit log, and support bundles are separate tasks;
nothing here is a prerequisite for them.

## Metrics (`zero_store::metrics`)

`Metrics` is a thread-safe, bounded, local-only registry. It never opens a
socket and never spawns a background exporter. All values live in memory until
the caller writes a snapshot, or until the process exits.

The registry is closed: only the metric names below exist. `inc`, `add`,
`gauge_set`, and `record_latency` return `zero.fnd.invalid_input` for an unknown
name or for the wrong metric kind (for example, incrementing a gauge).

### Names and types

| Name | Type | Meaning |
| --- | --- | --- |
| `queue_depth` | gauge (`i64`) | Current queue depth. Summed across label sets in totals. |
| `latency_ms` | histogram (`u64`) | Request latency in milliseconds. |
| `rate_limited_429` | counter (`u64`) | Provider 429 responses observed on this device. |
| `retries` | counter (`u64`) | Retry attempts. |
| `cost_micros` | counter (`u64`) | Accumulated cost in millionths of a currency unit. |
| `requests` | counter (`u64`) | Requests started. |
| `errors` | counter (`u64`) | Requests that ended in error. |

Counters saturate at `u64::MAX`; they never wrap or panic. `reset()` clears
every series and leaves the registry usable.

### Latency buckets

`latency_ms` uses fixed upper bounds, in milliseconds:

```
5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, +Inf
```

An observation goes into the first bucket whose bound is `>= ms`.
Percentiles are derived from the cumulative buckets:

- `p50`, `p95`, and `p99` are the upper bound of the first bucket that reaches
  the requested rank (`ceil(p / 100 * count)`).
- When the rank lands in the `+Inf` bucket, the recorded maximum is reported so
  a slow tail is not understated.
- An empty histogram reports `0` for every percentile.

A `BucketSnapshot` also carries `count`, `sum_ms`, `min_ms`, `max_ms`, and the
ordered bucket list (`le_ms: None` is `+Inf`).

### Labels and bounds

Every metric may carry at most four labels. Series keys are canonicalised by
sorting label pairs, so `{provider="p",model="m"}` and `{model="m",provider="p"}`
are the same series.

| Bound | Value |
| --- | --- |
| Label key length | 32 bytes |
| Label value length | 64 bytes |
| Labels per series | 4 |
| Distinct label sets per metric | 64 |

Label keys must be ASCII letters, digits, `_`, `-`, or `.`. Label values must
be non-empty and must not contain control characters or the reserved
delimiters `{`, `}`, `"`, or `\`. A new label set beyond the per-metric cap
returns `zero.fnd.limit_exceeded`; existing series keep accepting writes.
Anything rejected leaves the registry unchanged.

### Snapshot

`Metrics::snapshot()` returns `MetricsSnapshot`:

- `counters: BTreeMap<String, u64>`
- `gauges: BTreeMap<String, i64>`
- `histograms: BTreeMap<String, BucketSnapshot>`
- `totals`: per-name counter sums, per-name gauge sums, the merged latency
  histogram, and the number of series.

Series keys are strings: `name` when unlabeled, otherwise
`name{key="value",...}` with sorted labels. All maps are `BTreeMap`s, so
snapshots and renders are deterministic.

Rendering:

- `render_prometheus()` emits `# HELP` / `# TYPE` for every metric, with
  zero-valued samples for metrics that have not recorded anything. Histogram
  samples use `name_bucket{le="..."}`, `name_sum`, and `name_count`; labels are
  merged into the same brace block.
- `render_json()` emits the snapshot as pretty JSON: `counters`, `gauges`,
  `histograms`, and `totals`.

Both renderers are local string builders. There is no HTTP endpoint: a local
tool reads the registry in-process or reads the persisted JSON file.

### Dashboard

`dashboard(&metrics, now_ms)` returns a `Dashboard { snapshot, generated_ms }`.
`generated_ms` is the caller's wall-clock value; every other number comes from
the snapshot.

`Dashboard::lines()` reports:

```
zero metrics generated_ms=<ms>
queue_depth: <n>
latency p50: <n> ms
latency p95: <n> ms
429s: <n>
retries: <n>
cost: <n> micros ($<units>.<micros>)
error_rate: <percent>% (<errors>/<requests> requests)
```

`Dashboard::json()` reports `generated_ms`, `queue_depth`, `latency_ms`
(`p50`, `p95`, `p99`, `count`, `sum`), `rate_limited_429`, `retries`,
`cost_micros`, `requests`, `errors`, and `error_rate_bps` (basis points, so
`5.00%` is `500`). A request count of zero reports `0.00%`, never a division
error.

`Dashboard::from_snapshot(snapshot, now_ms)` builds the same view from a loaded
snapshot, so a dashboard can be rendered after a restart.

### Persistence

`save_snapshot(&snapshot, path)` writes pretty JSON with:

```json
{ "schema_version": 1, "snapshot": { "counters": {}, "gauges": {}, "histograms": {}, "totals": {} } }
```

The write goes to a temporary file in the same directory, is synced, and is
renamed over the target. A crash therefore leaves either the previous snapshot
or the new one, never a torn file. Missing parent directories are created.

`load_snapshot(path)` parses the file and refuses any `schema_version` other
than `1` with `zero.fnd.schema_version`. `SNAPSHOT_SCHEMA_VERSION` is exported
for callers that need to display it.

### Example

```rust
use zero_store::metrics::{self, Metrics, QUEUE_DEPTH, REQUESTS};

let metrics = Metrics::new();
metrics.gauge_set(QUEUE_DEPTH, 3)?;
metrics.inc(REQUESTS)?;
metrics.record_latency(42)?;

let board = metrics::dashboard(&metrics, 1_700_000_000_000);
for line in board.lines() {
    println!("{line}");
}

metrics::save_snapshot(&metrics.snapshot(), "metrics.json")?;
```

### Local-only guarantee (OBS-08)

The module contains no network client, socket, or URL. The test
`the_module_contains_no_network_code` scans `crates/zero-store/src/metrics.rs`
for network APIs and fails if any appear. Metrics never leave the device
through this module.

### Test evidence

Commands run on branch `ci/m0-m1-verification` (Windows, PowerShell):

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-store metrics -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-store --all-targets -j 1 -- -D warnings
```

Result: `12 passed; 0 failed` for the metrics tests (25 other `zero-store`
tests filtered out), and clippy finished with no warnings.

Covered cases:

- counters and gauges accumulate; wrong metric kind is rejected;
- histogram bucket placement, bucket boundaries, and p50/p95/p99;
- concurrent increments from eight threads sum exactly;
- label-set cap is enforced while existing series stay writable;
- invalid names, control characters, over-length values, too many labels,
  duplicate keys, and reserved delimiters are rejected;
- snapshots and both renderers are deterministic regardless of call order;
- dashboard lines and JSON read the same registry values;
- save/load round-trip, atomic replacement, and schema-version refusal;
- empty registry renders zeroes and a usable dashboard;
- `reset()` clears every series;
- Prometheus and JSON shapes include labels and all 11 buckets;
- source scan finds no network code.

### Known limitations

- Percentiles are bucket upper bounds, not interpolated quantiles. Buckets are
  fixed, so a deployment with a different latency scale needs a new bucket
  constant and a schema decision.
- The registry is process-local. Two processes do not share counters unless one
  persists a snapshot and the other loads it; there is no merge operation.
- `cost_micros` is a raw integer in millionths of a currency unit. The registry
  does not convert currencies or infer a unit.
- There is no automatic flush or retention for snapshot files; the caller
  chooses when and where to write them.

## Tracing (`zero_store::trace`)

A `Trace` is a bounded tree of `Span`s for one local turn. It records where the
turn spent time: provider calls, tool executions, kernel decisions, policy
checks, scheduling, and frame rendering. Tracing is local-only; there is no
collector, no exporter, and no network code in the module.

### Span model

```rust
pub struct Span {
    pub id: SpanId,
    pub trace_id: TraceId,
    pub parent: Option<SpanId>,
    pub name: String,
    pub kind: SpanKind,
    pub start_ms: i64,
    pub end_ms: Option<i64>,
    pub attributes: BTreeMap<String, String>,
    pub events: Vec<(i64, String)>,
}
```

`SpanKind` is one of `turn`, `provider`, `tool`, `kernel`, `frame`, `policy`, or
`scheduler`. `Trace { trace_id, spans, root }` holds the spans and names the
root.

`TraceId` is 32 lowercase hex characters and `SpanId` is 16. Both are opaque
newtypes: serde reads and writes them as strings, and parsing rejects any other
shape. `TraceId::from_seed` and `SpanId::from_seed` derive deterministic ids
from a seed and an ordinal, so a scripted trace (and its rendered output) is
byte-identical across runs.

Construction is sanitizing:

- Span names are stripped of control characters, trimmed, and capped at 64
  bytes.
- Attribute keys are capped at 32 bytes and restricted to ASCII letters, digits,
  `_`, `-`, and `.`; values are capped at 128 bytes.
- One span carries at most 16 attributes and 32 events; event text is capped at
  128 bytes.
- `Span::finish` accepts an end only after the start, only once, and only after
  every recorded event.
- `Trace::add_span` refuses a duplicate id, a missing parent, a second
  parentless span, a foreign trace id, and more than 2048 spans.
- `Trace::validate` re-checks every span and rejects missing roots, duplicate
  ids, orphans, cycles, self-parents, chains deeper than 32 links, and spans not
  reachable from the root.

`Trace::span_tree` returns a `SpanNode` tree. Children are ordered by
`start_ms` and then by id, so the projection is deterministic regardless of
insertion order.

### Turn hierarchy

A turn trace is rooted at a `Turn` span. The provider, tool, and frame work all
hang under that root:

```text
turn [turn] 90ms (1000..1090) turn=1
  provider.complete [provider] 40ms (1001..1041) duration_ms=40 model=zero-local provider=local events=1
  tool.read_file [tool] 20ms (1042..1062) duration_ms=20 tool=read_file
  frame.render [frame] 15ms (1070..1085) duration_ms=15 frame=conversation
```

`turn_trace()` builds exactly this scripted turn. `assert_turn_covers(&trace)`
enforces the T-OBS-02 Done criterion on a completed turn:

- the trace validates and the root is a finished `Turn` span;
- at least one finished `Provider`, `Tool`, and `Frame` span exists and its
  parent chain reaches the root;
- no child starts before its parent or ends after its parent's end.

The test that exercises this is `scripted_turn_covers_provider_tool_and_frame`.

### Storage and export

`TraceStore::open(dir)` stores one append-only JSONL file per trace at
`<dir>/<trace_id>.jsonl`. Each record is:

```json
{ "schema_version": 1, "trace": { "trace_id": "...", "spans": [ ... ], "root": "..." } }
```

`append(&trace)` validates first, serializes one complete record, and appends it
as a single newline-terminated write, followed by flush and fsync. Appends are
serialized by a process mutex, and the file is opened in append mode. An append
that would push the file past 4 MiB (or the cap passed to
`open_with_limit`) is refused with `zero.fnd.limit_exceeded` before anything is
written; one record is capped at 1 MiB. On Unix the file is created and kept at
mode `0600`.

`load_trace(id)` returns the newest complete record. A missing file is
`zero.fnd.not_found`; an empty file, an empty line, an unparseable complete
line, or an unterminated final line is `zero.fnd.corrupt`; an unknown
`schema_version` is `zero.fnd.schema_version`. The decoded trace is revalidated.

`list_traces()` returns `TraceSummary` values sorted by trace id:

```rust
pub struct TraceSummary {
    pub trace_id: TraceId,
    pub root_name: String,
    pub span_count: usize,
    pub started_ms: i64,
    pub duration_ms: i64,
    pub complete: bool,
    pub kinds: Vec<SpanKind>,
}
```

`duration_ms` is the finished root's duration, or `0` while the root is open.
Files that are not named after a valid trace id are ignored. Retention and
trash-on-expiry are the retention job below; this module never deletes a trace.

`render_text(&trace)` produces the deterministic tree shown above, including
durations, absolute intervals, sorted attributes, and an event count.
`to_json(&trace)` produces pretty JSON for the full trace.

### Redaction

Attributes are metadata only:

- Keys containing `token`, `secret`, `key`, `password`, `passwd`, `credential`,
  `authorization`, or `cookie` are rejected.
- Keys containing `message`, `prompt`, `content`, `completion`, `transcript`, or
  `body` are rejected, so conversation text cannot ride along in an attribute.
- Control characters are stripped from names, keys, values, and event text
  before storage, so ANSI escapes and newlines never reach a text tree or a
  JSONL line.
- The scripted turn records provider/model/tool/frame names and durations only;
  it records no message bodies.

The rejection rules are a guard, not a content classifier: a caller can still
place a non-secret string in an allowed key. Callers must treat attributes as
public metadata.

### Test evidence

Commands run on branch `ci/m0-m1-verification` (Windows, PowerShell):

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-store trace -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-store --all-targets -j 1 -- -D warnings
```

Result: `12 passed; 0 failed` for the trace tests (37 other `zero-store` tests
filtered out), and clippy finished with no warnings.

Covered cases:

- add, finish, and deterministic child ordering in the span tree;
- duplicate ids, orphan parents, cycles, self-parents, and foreign trace ids are
  rejected;
- the scripted turn contains finished provider, tool, and frame spans under the
  turn root and fails when a required kind is removed;
- secret and message-body attribute keys are rejected while metadata is kept;
- control characters are stripped from names, keys, values, and event text;
- JSONL append/load round-trips and returns the newest record;
- torn, empty, unparseable, and wrong-schema records produce typed errors;
- list summaries are sorted and report count, timing, completeness, and kinds;
- text and JSON renders are deterministic;
- an append past the file cap is refused before creating a file;
- on Unix, the trace file mode is `0600`;
- a source scan finds no network code.

### Known limitations

- Timestamps are caller-supplied milliseconds. The module has no clock and does
  not reorder spans; a caller that reports inconsistent wall times gets an
  inconsistent tree.
- Every append stores a complete trace snapshot, so a frequently updated trace
  grows one record per update until the 4 MiB cap. There is no compaction in
  this task; retention is the retention job below.
- A torn final line is reported as `zero.fnd.corrupt`, not silently truncated.
  Recovery is left to an explicit repair or retention step so a trace is never
  dropped without a signal.
- In-process appends are serialized. Across processes the store relies on the
  operating system's append mode; there is no advisory file lock.
- Traces are single-process trees. There is no OpenTelemetry export, no
  cross-process context propagation, and no mesh transport.
- Attributes are strings only. Durations and counts are formatted by the caller
  and are not type-checked.

## Retention (`zero_fs::retention`)

T-OBS-03 applies documented retention to Zero's own observability and session
data and moves every expired item to the operating system trash. Nothing in this
module deletes an item permanently: expired data lands in the Recycle Bin, the
macOS Trash, or the freedesktop trash, so a retention mistake can be undone.

### Classes and default policies

Each `RetentionClass` owns one directory directly under the data root.

| Class | Directory | Max age | Byte quota | `keep_min` |
| --- | --- | --- | --- | --- |
| `Traces` | `traces/` | 30 days | 256 MiB | 20 |
| `Metrics` | `metrics/` | 90 days | 64 MiB | 1440 |
| `Logs` | `logs/` | 14 days | 128 MiB | 100 |
| `Audits` | `audits/` | 365 days | 512 MiB | 1000 |
| `Sessions` | `sessions/` | 90 days | 512 MiB | 20 |
| `Artifacts` | `artifacts/` | 30 days | 1 GiB | 10 |
| `TeleportStaging` | `teleport-staging/` | 7 days | 256 MiB | 0 |

`RetentionPolicy { max_age_days, max_bytes, keep_min }`:

- `max_age_days` is `1..=3650`. Zero or anything above 3650 is refused with
  `zero.fnd.invalid_input`.
- `max_bytes` is optional; `None` disables the quota for the class.
- `keep_min` is `0..=10,000`; anything above the cap is refused.

`RetentionPlan { classes: BTreeMap<RetentionClass, RetentionPolicy>, dry_run }`
carries one policy per class. `RetentionPlan::validate()` checks every policy,
and `sweep` validates before it touches the filesystem. `RetentionPlan::default()`
and `with_defaults(true)` produce a **dry run** across all classes; a destructive
run must be requested explicitly (`with_defaults(false)` or `dry_run: false`).

### Sweep rules

`sweep(root, &plan, &trash, now_ms)` returns a `RetentionReport`. For each class:

1. The class directory is `root/<class directory>`. A missing directory is
   skipped, which is normal on a fresh install. A class directory that is a
   symlink, is not a directory, or resolves outside `root` is reported in
   `errors` and skipped; its contents are never examined.
2. One item is one top-level entry in the class directory. A session or artifact
   directory is trashed as a whole; the sweep does not recurse into it. Items are
   ordered by modification time, oldest first, with the path as a deterministic
   tie-break.
3. **Age.** Items older than `max_age_days` are trashed, except that the newest
   `keep_min` items are never eligible.
4. **Quota.** After expiry, if the class still exceeds `max_bytes`, the oldest
   remaining items are trashed until it fits, again never dropping below
   `keep_min`. A directory counts its recursive file size; symlinks are measured
   but not followed.
5. Every removal goes through `TrashService`. Zero's data root is protected from
   agent deletion, so `trash` refuses anything under it. Retention is the
   documented DEL-09 exemption and retries only that blanket `ZeroDirectory`
   refusal through `trash_zero_owned`. Name-based protection is never retried.
6. A refusal, an unreadable directory, or a failed trash is appended to `errors`
   and the original stays in place. One bad item does not stop the sweep.

An item with a modification time in the future (clock skew) is kept, not expired.

### Report

```rust
pub struct RetentionReport {
    pub trashed: Vec<TrashedItem>,   // { class, path, reason }
    pub kept: usize,
    pub bytes_freed: u64,
    pub errors: Vec<RetentionError>, // { class, path, message }
    pub dry_run: bool,
}
```

`reason` is `Expired` or `OverQuota`. `kept` counts the items the run leaves in
place (in a dry run: what would remain). `bytes_freed` sums the sizes of items
actually moved and is `0` in a dry run, which lists its selection in `trashed`
but changes nothing. Paths in the report are resolved (canonical) paths.

### Dry run and idempotence

`RetentionPlan::default()` is a dry run. A dry run lists what would be trashed,
what would remain, and the reasons, and moves nothing. Running the same plan
twice on an unchanged tree trashes nothing on the second run: the expired items
are already gone and the retained items are the newest `keep_min`, which the
first run never touched.

### Protected paths

Retention never touches a protected path:

- the home directory, filesystem roots, and system directories may not be used as
  the retention root (`zero.del.protected`);
- a symlink is never followed or trashed;
- a `.git` or `.zero` component, a `*.journal` file, a `policy.toml`, `trust.json`
  or `.halcyon-mode` file, and a credential store are kept even inside the class
  directories, with a `protected path kept` entry in `errors`;
- the blanket "Zero data root" refusal is the one exemption, because retention is
  Zero-owned cleanup (DEL-09). It is what lets `sessions/`, `traces/`, and
  `audits/` under the data root expire at all.

### Example

```rust
use zero_fs::retention::{sweep, RetentionClass, RetentionPlan, RetentionPolicy};
use zero_fs::TrashService;

let mut plan = RetentionPlan::new(false);
plan.set(
    RetentionClass::Logs,
    RetentionPolicy::new(14, Some(128 * 1024 * 1024), 100),
);
let report = sweep(&data_root, &plan, &trash, now_ms)?;
for item in &report.trashed {
    println!("trashed {} ({})", item.path.display(), item.reason);
}
```

### Test evidence

Commands run on branch `ci/m0-m1-verification` (Windows, PowerShell):

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-fs retention -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-fs --all-targets -j 1 -- -D warnings
```

Result: `14 passed; 0 failed` for the retention tests (45 other `zero-fs` tests
filtered out), and clippy finished with no warnings.

Covered cases:

- an expired item is moved by `TrashService` and found in the OS trash afterwards
  (Windows and freedesktop Linux), not deleted;
- a fresh item is kept;
- `keep_min` keeps the newest items even when they are expired;
- the byte quota trims the oldest items first;
- a dry run reports its selection and changes nothing;
- a second run is idempotent;
- journal and policy protected paths stay in place and are reported;
- a symlinked class directory is refused (Unix);
- a forced trash failure is reported, not fatal, and the original stays (Windows);
- an empty root produces an empty report;
- report totals (`trashed`, `kept`, `bytes_freed`) match the work done;
- invalid policies are rejected before any filesystem access;
- a missing root is `zero.fnd.not_found`, and a class path that is a file is
  reported and skipped.

### Known limitations

- The quota is floor-limited: if the newest `keep_min` items alone exceed
  `max_bytes`, or protected items do, the class stays over quota and the report
  shows only that those items are in `kept`.
- Retention is one directory level per class. A class with nested subdirectories
  is retained and trashed as whole top-level entries; there is no per-file
  retention inside a directory.
- Sizes are best-effort. An unreadable subtree contributes only the bytes that
  could be read, so a quota may under-count.
- Trash availability is an OS property. If the platform trash is unavailable or
  full, every removal fails into `errors` and nothing is lost, but nothing is
  reclaimed either.
- The `Audits` class expires audit files under its directory. The blanket
  audit-log refusal is part of the Zero-owned exemption, which is why the audits
  policy is the longest default (365 days) and must stay explicit.
- Only the forced-failure and symlink cases are platform-specific: the trash
  failure test runs on Windows and the symlink test on Unix.

