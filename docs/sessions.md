# Sessions

## Log format

Append-only JSONL, one record per line, fsynced before the append returns:

```json
{"seq":42,"ts":1700000000000,"kind":"message","role":"assistant","text":"…","tool_calls":[],"tool_call_id":null}
```

- `seq` orders records. Timestamps are display only.
- `kind` is one of: `message`, `model_change`, `thinking_level`, `service_tier`,
  `compaction`, `branch_summary`, `custom`, `child_usage`, `label`, `info`,
  `state`, `status`, `git_state`.
- New kinds are additive; existing fields never move.
- A torn final line from a crash is removed on open (`repair_raw`), never
  returned as a record.

## Tree

`SessionTree` stores `tree.json` with one node per session: id, name, parent,
created time, and the files it touched. `fork` copies the prefix up to an entry;
`clone` copies everything. Cumulative files walk the parent chain. `render`
prints the tree:

```
- root (s0001)
  - branch-b (s0002)
    - branch-c (s0003)
```

## Compaction

`zero_agent::compaction` keeps the last N messages (default 8) and appends a
`compaction` record naming the cut. The retained tail never starts with a tool
result: the cut moves back to the assistant call. Kernel/state/status records
survive compaction. Hooks run before and after; each may append its own record.
The generation is bumped so attach cursors from before the compaction are stale.

## Resume

`SessionTree::resume` returns the visible tail (from the last compaction), the
latest `branch_summary`, cumulative file counts, and a `{generation, sequence}`
cursor. The agent loop turns the summary into a system message, so a resumed
session knows its goal, constraints, progress, decisions, next steps, and
critical context.

## Attach

`zero_store::session::attach` builds a sidecar index of record offsets with a
streaming scan (constant memory) and reads only the last `max_entries` records.
Measured on 618 MiB / 5,242,880 records: index build 4.65 s, tail read 24,792
bytes, index read 400 bytes, 50 records returned. A second attach reuses the
index and reads only the tail. `history_bytes` gives the offset for a client that
wants to stream older history.

## Leases

A lease is `<canonical log>.lease`, created atomically. A live lease reports its
owner, so two concurrent creates converge on one worker; the loser gets the
winner's pid. Expired leases may be stolen exactly once.

## Command journal

`CommandJournal` writes `begin` and fsyncs before the effect, then `applied` with
the result. On replay:

| Prior state | Result |
|---|---|
| `applied` | The recorded result, no second effect |
| `begin` without a result | `zero.ses.command_uncertain`; not replayed |
| `failed` | Reported; a new key is required to retry |

## Export

A bundle is versioned JSON (`zero.session.bundle`, version 1) with metadata,
every record, and artifacts as base64 plus their hashes. Import verifies every
artifact hash before writing anything. Export, wipe, import, and resume produce
an identical transcript (the test compares it record by record).
