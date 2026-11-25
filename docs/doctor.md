# Doctor

`zero-doctor` is the diagnosis surface for an installation that is already
broken: the daemon, kernel, and mesh may all be dead (DOC-09). It is its own
executable, not a subcommand that needs a live runtime, and its core loads no
plugins and never opens a daemon socket. It is also available through
`zero doctor`, `/doctor`, as a tool, and as a panel (DOC-01).

## The independent core

`zero_doctor::run_core_with(&DoctorContext)` returns a `DoctorReport`:

| Field | Meaning |
|---|---|
| `version` | the `zero-doctor` version |
| `independent` | always `true`; the core ran without plugins or a daemon |
| `daemon` | `not_contacted`; the core never probes it |
| `checks` | one `CheckResult` per check, in the fixed order below |

`run_core()` is the default-context form. Both functions are pure with respect
to services: they read injected snapshots, never a daemon socket, and never send
network traffic. `run_core_with` cannot panic on a missing or malformed input;
each check turns that into `warn`/`fail` with a short detail.

## Context model

Every check reads a `DoctorContext` captured once before the checks run. This
keeps results deterministic and lets tests inject pass, warn, and fail states
without a live installation.

| Field | Kind | Meaning |
|---|---|---|
| `versions` | `VersionsSnapshot` | `zero_version` plus one captured `rustc --version` string |
| `config` | `FileSnapshot` | config path and text (`None` when absent or unreadable) |
| `project_key_path` | `PathBuf` | project key file; contents are never printed |
| `workers_journal` | `FileSnapshot` | supervisor worker journal path and text |
| `kernel` | `KernelSnapshot` | `running`/`stopped`/`unknown` plus the socket path |
| `credential_backend` | `CredentialBackend` | OS store name, encrypted fallback, unavailable, or unknown |
| `network` | `NetworkSnapshot` | proxy, base URL, and offline flag; values are not echoed |
| `mesh_registry` | `FileSnapshot` | mesh registry path and text; identities are not echoed |
| `ports` | `PortsSnapshot` | expected and actually listening ports |
| `disk` | `Option<DiskSnapshot>` | free and total bytes, injected |
| `locks` | `LocksSnapshot` | lock paths, modification times, threshold, and a fixed `now` |
| `journals` | `Vec<PathBuf>` | JSONL journals to parse |
| `mcp_config` | `FileSnapshot` | MCP config path and text; only server names are reported |

`DoctorContext::from_root(root)` derives the local layout:
`.zero/config.toml`, `.zero/key`, `.zero/workers.json`, `.zero/journal/*.jsonl`,
`.zero/locks/*.lock`, `.zero/mesh/registry.json`, and `.zero/mcp.json`. The
default root is `ZERO_DATA_DIR` when set, otherwise the current directory.
Kernel state, credential backend, ports, and disk are not derivable without a
live service, so the default context leaves them unknown and the corresponding
checks say `skipped`/`unknown` instead of passing.

## Checks

The names and order are `zero_doctor::CHECK_NAMES`; a test asserts the report
contains exactly those 13 checks, so one cannot silently disappear.

| # | Name | Passes when | Warns when | Fails when |
|---|---|---|---|---|
| 1 | `versions` | zero version and toolchain are known | toolchain not detected | zero version is unknown |
| 2 | `config` | config text has valid TOML shape | config is absent/unreadable | malformed TOML (line number, path) |
| 3 | `keys` | key exists, is non-empty, and is not group/world-readable | — | missing, empty, not a file, or readable by group/world (Unix) |
| 4 | `workers` | journal parses with at least one worker record | journal parses but has no records | malformed JSON or unexpected shape |
| 5 | `kernel` | running with its socket, or cleanly stopped | state unknown, or stopped with a stale socket, or running without a known socket path | running but the socket file is missing |
| 6 | `auth` | OS credential store | encrypted-file fallback, or backend not probed | no backend available |
| 7 | `network` | configured URLs are valid | URL malformed, or offline mode | URL has whitespace/control characters |
| 8 | `mesh` | registry parses with at least one entry | registry empty | malformed JSON or unexpected shape |
| 9 | `ports` | every expected port is listening and nothing extra is | extra listeners | an expected port is missing |
| 10 | `disk` | at least 5 GiB free | below 5 GiB | below 1 GiB, zero total, or free > total |
| 11 | `locks` | no lock files, or none stale | 1–5 stale, or unknown mtime | more than 5 stale |
| 12 | `journals` | every line is valid JSON | no journals configured | unreadable file or an invalid JSONL line |
| 13 | `mcp` | servers have a command and string args | inline secret-looking env values | malformed JSON, or a server without a command |

### Thresholds

| Setting | Value | Effect |
|---|---|---|
| disk fail | `< 1 GiB` free | `disk` fails |
| disk warn | `< 5 GiB` free | `disk` warns |
| lock age | `> 24 hours` | lock counts as stale |
| lock fail | `> 5` stale | `locks` fails |
| list detail | first 3–8 entries | keeps details short |

### Redaction rules

Details contain paths, counts, status names, server names, port numbers, and
line numbers only. Key bytes, tokens, config values, mesh identities, and MCP
env values are never formatted into a result. File-supplied text used in a
detail (worker states, server names) is stripped of control characters and
truncated. Config and MCP parse failures report only the path and line.

## Playbooks

Every stable code in `zero_types::ErrorCode::ALL` has exactly one playbook
(DOC-04). A playbook is the diagnosis-and-repair script behind an error, so the
CLI, a panel, or an agent's `diagnose` step renders the same text instead of
inventing advice.

```rust
pub struct Playbook {
    pub code: ErrorCode,
    pub title: &'static str,
    pub symptoms: &'static [&'static str],
    pub steps: &'static [&'static str],
    pub escalation: Option<&'static str>,
    pub remediation: &'static str,
}
```

| Field | Meaning |
|---|---|
| `code` | the stable code this entry answers; a test rejects duplicates |
| `title` | a distinct human name; a test rejects reused titles |
| `symptoms` | one to three observations that point at this code |
| `steps` | two to five ordered, safe diagnostic or repair steps |
| `escalation` | the point where the user must take over; `None` when the steps suffice |
| `remediation` | `code.remediation()` verbatim, so the playbook never contradicts the stable one-line fix |

### Selecting a playbook

- `zero_doctor::playbook(code)` returns the entry for one `ErrorCode`. It is an
  exhaustive match over the enum: deterministic, allocation-free, and a compile
  error when a variant has no entry.
- `zero_doctor::all()` returns every playbook in `ErrorCode::ALL` order, so
  generated docs and tests do not churn.
- `zero_doctor::triage(&error)` returns `playbook(error.code())`.

Triage reads only the code. The error message is never matched, never formatted
into a playbook, and never echoed, so an injected or hostile message cannot
steer the advice or leak into playbook text.

### Coverage rule

One playbook per stable code, always:

- `all().len() == ErrorCode::ALL.len()`;
- every code appears exactly once, and `playbook(code).code == code`;
- `all()` follows `ErrorCode::ALL` order.

`cargo test -p zero-doctor` enforces all three. The exhaustive match makes a
missing variant a build error rather than a runtime fallback.

### Safety rule

Steps are ordered safe actions: inspect, back up, change, re-check. No step asks
for a secret to be printed, edits a protected file on the agent's behalf, or
runs an irreversible action without a backup or the user's confirmation. A test
fails if any playbook-authored text (title, symptoms, steps, escalation)
contains `rm -rf`, `del /f`, `format `, or `drop database`, case-insensitive, so
a playbook cannot recommend blind destruction. The stable `remediation` line is
owned by `zero-types` and is descriptive prose, not a command.

### DOC-04 named scenarios

The ten scenarios named in `features.md` are check findings; each surfaces as a
stable code whose playbook above covers it.

| Scenario | Closest stable code | Detected by |
|---|---|---|
| `KERNEL_BOOT` | `Unavailable` | `kernel` |
| `DAEMON_STALE` | `Unavailable` | `versions`, `kernel` |
| `AUTH_EXPIRED` | `ProviderAuth` | `auth` |
| `JOURNAL_CORRUPT` | `SessionCorrupt` | `journals` |
| `DISK_FULL` | `ResourceExhausted` | `disk` |
| `PORT_CONFLICT` | `Io` | `ports` |
| `LOCK_STALE` | `Locked` | `locks` |
| `MESH_UNREACHABLE` | `NoQuorum` | `mesh`, `network` |
| `MCP_HANDSHAKE` | `Unsupported` | `mcp` |
| `PROJECT_KEY_MISSING` | `NotFound` | `keys` |

## Repair

Repair is a plan with an inverse, not a side effect hidden inside a check
(DOC-05, DOC-06, DOC-10). `zero_doctor::repair` exposes the model and
`zero_doctor::forensics` records what happened; the repair CLI flag arrives with
its own task.

### Plan and actions

```rust
pub struct RepairPlan {
    pub id: String,
    pub actions: Vec<RepairAction>,
    pub dry_run: bool,
}

pub enum RepairAction {
    CreateDirectory { path: PathBuf },
    WriteFile { path: PathBuf, contents: String },
    MoveToTrash { path: PathBuf },
    RemoveStaleLock { path: PathBuf },
    RotateFile { path: PathBuf },
    RepairConfig { path: PathBuf, contents: String },
}
```

Actions are numbered `a1`, `a2`, ... in plan order; previews and reports use
those ids. `RepairPlan::dry_run` is a safety flag: `apply` refuses a plan marked
`dry_run` with `RepairError::DryRunPlan`.

| Action | Effect | Recorded inverse |
|---|---|---|
| `CreateDirectory` | create the directory and missing parents | remove the created directories, deepest first, only if empty |
| `WriteFile` | write a file, replacing existing bytes | restore the snapshot, or remove the file if it was new |
| `RepairConfig` | write TOML-validated config contents | same as `WriteFile` |
| `MoveToTrash` | move a regular file into `<snapshot_dir>/trash/` | move it back |
| `RemoveStaleLock` | remove a `.lock` file after snapshotting it | restore the snapshot |
| `RotateFile` | rename to `<name>.1`, preserving bytes | rename back |

Contents are bounded to `MAX_CONTENTS_BYTES` (64 KiB), must be printable text
(newline, carriage return, and tab are allowed), and may not contain strong
secret markers such as PEM private-key headers or provider token prefixes.
`RepairConfig` must also pass the structural TOML validation used by the
`config` check. Contents never appear in a preview, report, or error message;
only paths, action kinds, counts, and byte lengths do.

### Policy

```rust
pub struct RepairPolicy {
    pub allowed_roots: Vec<PathBuf>,
    pub max_actions: usize,
    pub allow_delete: bool,
}
```

The policy is checked for the whole plan before the first mutation:

- `allowed_roots` must be non-empty, and each root must canonicalise to an
  existing directory. An empty list refuses every plan.
- Every action path must be absolute and must not contain `.` or `..`
  components. Windows UNC, device, and verbatim prefixes are refused before
  resolution.
- Resolution canonicalises the nearest existing ancestor and appends the missing
  names. A symlinked ancestor must resolve inside a root; a final-component
  symlink is refused outright. An action path must be a strict descendant of a
  root, so the root itself cannot be modified.
- `allow_delete` gates `MoveToTrash` and `RemoveStaleLock`. Without it a plan
  containing either action is refused before anything changes. `RotateFile` and
  snapshotted overwrites are not deletions.
- `max_actions` bounds the plan. A hard cap of `MAX_PLAN_ACTIONS` (1024)
  applies even when the policy value is larger.

The snapshot directory is checked with the same rules: it must resolve inside an
allowed root, must not be a root itself, and must not be a symlink. A plan may
not trash or rotate a path that contains the snapshot directory, because that
would strand the evidence rollback needs.

### Dry run

```rust
let preview = zero_doctor::dry_run(&plan, &policy)?;
```

`RepairPreview` carries the plan id, the action count, one `PreviewChange` per
action, the ids already in their desired end state, and the existing files that
`apply` would snapshot. Each `PreviewEffect` is one of `Create`, `Overwrite`,
`Remove`, `Rotate { to }`, `AlreadyApplied`, or `Conflict { reason }`.

A dry run reads metadata, file lengths, and — only when a length matches — the
existing body to detect an already-applied write. It creates no directory, writes
no file, and takes no snapshot. Policy and structural violations are errors.
State-dependent problems, such as a target that is a directory, are reported as
`Conflict` in the corresponding change so the caller can still see the rest of
the plan.

### Apply, snapshots, and rollback

`zero_doctor::apply(&plan, &policy, snapshot_dir)` runs in this order:

1. Refuse a plan marked `dry_run`.
2. Validate the entire plan against the policy, including every path and every
   contents body, before mutating anything.
3. Validate the snapshot directory against the same policy.
4. Re-resolve each path immediately before its action, so a path swapped for a
   symlink after pre-flight is still refused.
5. Snapshot every affected existing file by copying its bytes into
   `snapshot_dir`, then apply the action and keep its inverse.

Snapshots are named `NNNN-aN-name.snapshot` and trashed files land at
`<snapshot_dir>/trash/NNNN-aN-name.trashed`. On Unix the snapshot directory is
created `0700` and snapshot copies `0600`; the original file mode is recorded and
restored by rollback. Snapshot copies preserve bytes exactly, and the report
contains snapshot paths only, never their contents.

`MoveToTrash` is a reversible move, not a permanent delete. If the snapshot
directory is on another volume, the move falls back to copy-and-remove and
leaves the original in place if either half fails.

If any action fails, the current action's partial effects are undone first, then
every earlier inverse is undone in reverse order. The returned
`RepairError::Apply` says how many earlier actions were rolled back. If an
inverse also fails, `RepairError::ApplyRollbackFailed` reports how many actions
were restored and the rollback error; it never claims a clean rollback.

`zero_doctor::rollback(&report)` performs the same reversal later. The inverse
log is process-local and deliberately omitted from serialization, so a report
that round-tripped through JSON is inspectable but rollback refuses it with
`RepairError::Rollback` rather than silently doing nothing. Rollback restores
overwritten bytes, removes files and directories the plan created, and moves
trashed or rotated files back. It never removes a directory that is not empty.

### Idempotency rule

A repeated apply must either be a no-op or fail without corrupting anything. An
action is reported as already applied when its desired end state already holds:

| Action | Already applied when |
|---|---|
| `CreateDirectory` | the path is an existing directory |
| `WriteFile`, `RepairConfig` | the file exists and its bytes equal `contents` |
| `MoveToTrash` | the source is absent and its trashed copy exists |
| `RemoveStaleLock` | the lock file is absent |
| `RotateFile` | the source is absent and `<name>.1` exists |

`RotateFile` refuses to clobber an existing `<name>.1` rather than overwriting
it. A repeated plan therefore never duplicates content, re-snapshots an unchanged
file, or moves a second copy to the trash.

### Repair limits

- `MoveToTrash` and `RemoveStaleLock` accept regular files only; directories are
  refused so repair never performs a recursive delete.
- Rotation is a single `<name>.1` step. Existing rotations are left alone, and a
  caller that needs a longer history must compose explicit actions.
- A cross-volume trash uses copy-and-remove; a crash between the two can leave
  both copies, but the bytes are preserved and no data is lost.
- Explicit rollback needs the in-process `RepairReport`. The inverse log is not
  serialized, so rollback across a process restart is not offered.

## Agent API

DOC-08 exposes the doctor to an agent as three host tools plus a gate the host
runs before a turn is allowed to finish (DOC-06). The module is
`zero_doctor::agent_api`; the same functions are re-exported at the crate root
except `apply`, which keeps its repair-engine name there, so the agent form is
`zero_doctor::agent_apply`.

```rust
pub fn diagnose(ctx: &DoctorContext) -> DoctorReport;
pub fn plan(ctx: &DoctorContext, policy: &RepairPolicy) -> PlanOutcome;
pub fn apply(
    plan: &RepairPlan,
    policy: &RepairPolicy,
    snapshot_dir: impl AsRef<Path>,
) -> Result<RepairReport, AgentError>;
pub fn finish_turn(report: &DoctorReport, turn: &TurnReport) -> ZeroResult<TurnSummary>;
pub fn finish_turn_with(
    report: &DoctorReport,
    turn: &TurnReport,
    options: GateOptions,
) -> ZeroResult<TurnSummary>;
```

| Tool | Delegates to | Contract |
|---|---|---|
| `diagnose` | `run_core_with` | 13 checks, `daemon: not_contacted`, no daemon socket, no network, no mutation |
| `plan` | `run_core_with` + `repair` model | only failing checks with a known safe action; everything else is refused by name |
| `apply` | `zero_doctor::repair::apply` | refuses `dry_run` plans before validation; otherwise snapshots, applies in order, and rolls back on failure |
| `finish_turn` | none | structural gate over the 13-check report and the agent's `TurnReport` |

`AgentDoctor` bundles one `DoctorContext`, one `RepairPolicy`, one snapshot
directory, and one `GateOptions`; its `diagnose`, `plan`, `preview`, `apply`,
and `finish_turn` methods return `AgentError`, whose `code()` maps a repair
failure or a gate refusal to a stable `ErrorCode`. `AgentError` never carries
file contents: repair errors already report paths and action ids only.

### Plan safety

`plan` maps only these failures; every other failing check becomes a
`RefusedCheck { check, reason }` in `PlanOutcome::refused` and must be reported
unresolved by the agent.

| Check | Planned action | Precondition |
|---|---|---|
| `config` | `RepairConfig` from `<config>.bak` | the backup is readable and passes the same structural TOML check |
| `locks` | one `RemoveStaleLock` per stale lock | `RepairPolicy::allow_delete`; otherwise the check is refused |
| `journals` | `CreateDirectory` for a missing parent directory | every unreadable journal is explained by a missing parent; any other read failure is refused |

The rules that make the plan safe:

- Warnings are never planned. `plan` reads only checks with status `fail`, which
  is the same set the default turn gate requires.
- A delete is never planned without `allow_delete`. With deletion disabled the
  `locks` check appears in `refused` with that reason, not in the plan.
- The planner never invents contents. It rewrites a config only from a backup
  that already exists and parses.
- The planner never deletes or rewrites a journal. A missing directory is the
  only journal repair; corrupt evidence is left for the user.
- Policy limits apply after mapping. An empty `allowed_roots`, `max_actions`
  smaller than the mapped actions, or the 1024-action hard cap moves every
  covered check to `refused` with the limit as the reason, so a size limit
  cannot leave a plan that `apply` must refuse. Path containment and symlink
  checks still run in `apply`, which re-resolves each path before touching it.
- The returned plan has `dry_run = false`. Marking it `true` makes `apply`
  return `RepairError::DryRunPlan` before any path is touched; `preview` (or
  `zero_doctor::dry_run`) is the read-only form.

`PlanOutcome` also exposes `covered` (checks the plan addresses, in report
order) and `refusal(check)`. `is_empty()` is true when nothing safe could be
planned.

### The unresolved-failure gate

The agent builds a `TurnReport` for the turn:

```rust
pub struct UnresolvedFailure {
    pub check: String,
    pub code: ErrorCode,
    pub playbook_code: ErrorCode,
    pub summary: String,
}

pub struct TurnReport {
    pub resolved: Vec<String>,
    pub unresolved: Vec<UnresolvedFailure>,
    pub actions_taken: Vec<String>,
}
```

`UnresolvedFailure::for_check(check, summary)` fills in the mapped code and
playbook code and returns `None` for an unknown name. `TurnReport` provides
`mark_resolved(check)` and `record_applied(check, &RepairReport)`; the latter
appends one canonical `check:aN:kind` entry per action that `apply` actually
performed (`a1`, `a2`, ... in plan order, kind names as in the repair table).

`finish_turn` then:

1. Rejects a report that does not contain exactly the 13 core checks, repeats a
   name, or names an unknown check. An agent cannot fabricate a pass by handing
   in an empty or shortened `DoctorReport`: the check-count mismatch is reported
   as `zero.fnd.invalid_input`.
2. Treats every `fail` check (and every `warn` check when
   `GateOptions { include_warn: true }`) as failing.
3. Requires each failing check to appear in `unresolved`, or in `resolved` with
   an applied action for that same check in `actions_taken` whose kind `plan`
   would use for it (`config` → `repair_config`, `locks` →
   `remove_stale_lock`, `journals` → `create_directory`). Every name in
   `resolved` and `unresolved` must be a failing check; unresolved entries also
   need a non-empty, single-line, secret-free summary of at most
   `MAX_SUMMARY_CHARS` (512) characters, and both codes must equal
   `zero_doctor::check_code(check)`.
4. Returns `zero.pol.ask` naming every hidden failing check when one is neither
   unresolved nor backed by an applied action. The agent cannot finish that
   turn.
5. Returns `Ok(TurnSummary { failing, resolved, unresolved, actions })` when the
   turn is fully reported. A clean report returns zeroes.

| Failure | Code |
|---|---|
| report is not the 13 core checks, repeats or names an unknown check | `zero.fnd.invalid_input` |
| unknown name in `resolved`/`unresolved`, a name repeated in either list, empty or oversized summary, secret-looking summary, malformed `actions_taken` entry | `zero.fnd.invalid_input` |
| `resolved` without an applied action of the planned kind, a `resolved`/`unresolved` name that is not failing, both lists naming the same check, or a code/playbook code that does not match the check | `zero.pol.denied` |
| a failing check is hidden from the report | `zero.pol.ask` |

### Check codes

`zero_doctor::check_code(check)` is the one mapping the gate enforces (it
follows the DOC-04 table above):

| Check | Code | Check | Code |
|---|---|---|---|
| `versions` | `zero.fnd.unavailable` | `network` | `zero.prv.unavailable` |
| `config` | `zero.fnd.config_invalid` | `mesh` | `zero.lck.no_quorum` |
| `keys` | `zero.fnd.not_found` | `ports` | `zero.fnd.io` |
| `workers` | `zero.fnd.unavailable` | `disk` | `zero.fnd.resource_exhausted` |
| `kernel` | `zero.fnd.unavailable` | `locks` | `zero.fs.locked` |
| `auth` | `zero.prv.auth` | `journals` | `zero.ses.corrupt` |
| | | `mcp` | `zero.fnd.unsupported` |

### Gate limits

The gate verifies that `actions_taken` contains canonical records, that each
resolved check has one for the same check, and that its action kind is one the
planner would use for that check. It does not itself hold the `RepairReport`
(the documented signature takes the report's shape, not the engine value), so a
hand-written canonical string of the right kind is indistinguishable from
`record_applied` output. It is an honesty and structure gate, not a
cryptographic proof; hosts that need the stronger link should build the
`TurnReport` through `AgentDoctor::apply` and `record_applied` only. Likewise, a
`DoctorReport` is trusted for its statuses once its 13-name shape is valid; the
gate cannot re-run the checks, so the host should pass the report returned by
`diagnose` rather than one reconstructed elsewhere.

### Agent API tests

`cargo test -p zero-doctor` runs these with `tempfile` and no network:

| Test | Proves |
|---|---|
| `diagnose_returns_the_thirteen_checks_in_order` | tool contract, order, independence, `not_contacted` |
| `plan_maps_config_locks_and_missing_directories` | config backup, stale locks, missing journal directory, refusal of `keys` |
| `plan_never_deletes_without_policy_allowance` | delete gate at plan time |
| `plan_refuses_checks_without_a_safe_action` | unplannable config without backup and missing key are listed |
| `plan_respects_the_policy_action_limit` | `max_actions` moves covered checks to `refused` |
| `plan_is_empty_when_no_check_fails` | a clean diagnosis plans nothing |
| `dry_run_apply_never_mutates_and_a_real_apply_rolls_back` | dry-run flag and preview change nothing; real apply changes the tree; rollback restores it |
| `finish_turn_refuses_a_hidden_failure` | hidden check returns `zero.pol.ask` naming it |
| `finish_turn_accepts_a_reported_unresolved_failure` | a mapped unresolved entry is accepted |
| `finish_turn_requires_the_mapped_playbook_code` | a friendlier or wrong code is denied |
| `finish_turn_rejects_unknown_checks_and_empty_summaries` | unknown names, blank summaries, and secret-looking summaries |
| `finish_turn_rejects_a_resolved_check_without_an_applied_action` | fabricated resolution is denied; malformed action strings are rejected |
| `finish_turn_accepts_a_resolution_backed_by_a_real_apply` | `record_applied` output from a real apply is accepted |
| `finish_turn_rejects_a_report_with_the_wrong_check_count` | empty, shortened, and duplicated 13-check reports |
| `finish_turn_accepts_a_clean_report` | zero-failure turn returns a zero summary |
| `the_strict_gate_also_requires_warnings_to_be_reported` | `include_warn` gate |
| `turn_report_rejects_unknown_checks_in_its_helpers` | helpers validate names and refuse empty repair reports |
| `agent_doctor_wires_the_tools_and_returns_typed_errors` | wrapper wiring and typed codes |

## Forensics

Forensics answers two questions after an incident: what happened, in order, and
what can be handed to another person without leaking a secret (DOC-07, OBS-07).
`zero_doctor::forensics` reads caller-supplied artifacts and local files only.
It contains no network code, opens no socket, and needs no daemon, so it runs
with the same independence as the diagnosis core.

```rust
pub struct TimelineEvent {
    pub at_ms: i64,
    pub source: String,
    pub kind: String,
    pub actor: Option<String>,
    pub detail: String,
}

pub struct Artifact { pub name: String, pub lines: Vec<String> }

pub struct BundleInputs {
    pub root: PathBuf,
    pub timelines: Vec<Artifact>,
    pub extra_files: Vec<PathBuf>,
    pub redactions: Vec<String>,
}

pub struct BundleLimits {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub created_at_ms: i64,
}

pub fn build_bundle(
    inputs: &BundleInputs,
    out_dir: impl AsRef<Path>,
    limits: &BundleLimits,
) -> Result<BundleReport, ForensicsError>;
```

### Timeline

`Timeline::from_artifacts(&[Artifact])` folds already-read lines. Artifacts are
processed in `name` order, and the artifact name becomes the event `source`;
nothing else is opened.

| Line shape | Accepted keys |
|---|---|
| JSONL | timestamp: `at_ms`, `ts_ms`, `timestamp_ms`, `at`, `ts`, `timestamp`; kind: `kind`, `event`, `type` (default `event`); actor: `actor`, `by`, `user`; detail: `detail`, `message`, `msg` |
| TSV | `timestamp<TAB>kind<TAB>detail`; the detail field may be absent |

Timestamps are integer milliseconds, or RFC 3339
`YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`. No calendar crate is in this crate's
dependency set, so the RFC 3339 parser accepts exactly that shape and counts
anything else as malformed.

- Ordering is `(at_ms, source, kind, detail)`, with `actor` as the final
  tie-break, so equal timestamps still sort the same way on every run.
- Exact repeats are removed after sorting; the count is reported as
  `duplicates`.
- The list is capped at `MAX_TIMELINE_EVENTS` (10,000). The newest events are
  dropped first and `truncated`/`dropped` say so; nothing is dropped silently.
- A malformed line increments `malformed` and is never fatal. Its contents are
  never stored, formatted, or echoed; only the count survives.
- Blank lines are ignored. Control characters become `?`, detail is bounded to
  512 characters, and `source`/`kind`/`actor` are bounded to 80–120 characters,
  so one long line cannot dominate a bundle.
- `Timeline::redact(&[String])` runs the bundle's redaction pass over every
  event field and re-sorts afterwards, because redaction can change a sort key.

### Bundle layout

`build_bundle` writes a directory a reader can open with any text editor:

| Path | Contents |
|---|---|
| `manifest.json` | schema version, doctor version, `created_at_ms`, `network: "none"`, `offline: true`, `hash_algorithm`, totals, redaction count, truncation flags, timeline stats, one file entry per written file, and every skipped candidate with its reason |
| `timeline.jsonl` | the folded timeline, one JSON object per line; always written, empty when there are no events |
| `files/<root-relative path>` | redacted copies of whitelisted `extra_files` |

`manifest.json` lists every other bundle file but not itself: a file cannot
carry its own hash. Each entry carries the byte count after redaction and
`fnv1a64:<16 hex>` over the written bytes. FNV-1a is used deliberately and is
documented as non-cryptographic — it is a same-bytes check, not a signature.
`BundleLimits::created_at_ms` is an input, so the same inputs and clock produce
byte-identical bundles.

`read_bundle(out_dir)` returns a `BTreeMap<path, bytes>` for inspection or
tests; it is not needed to read a bundle by hand.

### Path exclusions

Each `extra_files` entry is whitelisted individually; the bundle never walks a
directory. A candidate is skipped and reported when any of these hold:

| Rule | Matches |
|---|---|
| vault | any path segment pair `.zero/vault` or `.zero/keys` |
| credential names | a segment containing `secret`, `token`, or `credential` (case-insensitive) |
| key files | a segment named `key`, `key.prev`, or starting with `credentials` |
| env files | a segment starting with `.env` |
| encrypted or key material | a file ending in `.enc`, `.pem`, or `.key` |
| caller value | the root-relative path contains any caller redaction value of 4+ characters |
| outside root | the canonical path does not start with the canonical `root` |
| symlink | the entry itself is a symlink (including a dangling one) |
| not a file | directory, device, socket, or other special entry |
| inside the bundle | the canonical path is inside `out_dir` |
| duplicate | the same canonical file was listed twice |
| unreadable | metadata or bytes could not be read |
| binary | not UTF-8, or contains NUL, so it is dropped rather than copied |
| oversize / total limit | see below |

The substring rules are intentionally blunt: they over-exclude rather than risk
a leak, so a harmless `tokenizer-notes.txt` is also skipped. Paths are matched
case-insensitively and component-aware, so a directory named `keys` is excluded
while `monkeys.txt` is not.

### Redaction

Every text file and every timeline field passes through `redact_text` before it
is written:

1. Whole PEM blocks, from a `-----BEGIN` line through its `-----END` line, are
   replaced with `[redacted]`. An unterminated block redacts to end of file
   (fail safe), which also hides the base64 body, not just the header.
2. Strong marker tokens beginning a token are replaced whole: `sk-`, `ghp_`,
   `oc_sk_`, `AKIA`. The tail is included, and a marker in the middle of a word
   (`task-list`) is not matched, so ordinary prose survives.
3. Caller-provided values of 4 or more characters are replaced, longest first,
   so an overlapping shorter value cannot leave a tail behind. Shorter values
   are ignored: replacing them corrupts unrelated text without hiding a usable
   secret.

`redaction_count` in the manifest and `BundleReport::redactions` count every
replacement. Skipped path labels are redacted too, so a path excluded *because*
it carries a caller value does not echo that value back through the manifest.
Ordinary text is preserved: a redacted file is evidence, not an empty
placeholder.

### Size limits

| Setting | Default | Effect |
|---|---|---|
| `max_file_bytes` | 1 MiB | a larger file is skipped as `oversize` |
| `max_total_bytes` | 16 MiB | content that would exceed the total is skipped as `total_limit` |
| `MAX_TIMELINE_EVENTS` | 10,000 | older bound; newest events dropped first |

A file is never truncated mid-way: it is either copied whole or skipped with
its reason (and size when known) in `skipped`. The timeline is the one derived
artifact, and if it would exceed a cap its newest events are dropped; that is
reported through `timeline_truncated` and `timeline_events_dropped` rather than
hidden.

### Offline guarantee

The module calls only `std::fs`, `std::path`, and serde. There is no HTTP client,
no socket, no DNS, no subprocess, and no dependency that opens a connection. The
manifest and the report both say `network: "none"` and `offline: true`. A bundle
is self-contained: `manifest.json`, `timeline.jsonl`, and `files/` are read with
the daemon, kernel, and mesh dead.

### Forensics tests

`cargo test -p zero-doctor` runs the forensics suite with `tempfile` and no
network:

| Test | Proves |
|---|---|
| `timeline_orders_dedups_and_counts_malformed_lines` | ordering, TSV+JSONL, RFC 3339, dedup, malformed count |
| `timeline_accepts_json_actor_and_aliases` | alias keys, actor, detail aliases |
| `timeline_is_bounded_and_reports_truncation` | 10k bound, dropped count, truncated flag |
| `redact_text_replaces_caller_values_and_strong_markers` | caller values and four strong markers |
| `redact_text_keeps_ordinary_words_and_pem_bodies_hidden` | no over-redaction of words; PEM body hidden |
| `manifest_lists_files_sizes_and_hashes` | manifest fields, sizes, hashes, flags, totals |
| `injected_secrets_never_appear_in_any_bundle_file` | scans **every** bundle file for caller, `sk-`, `ghp_`, `AKIA`, and PEM material |
| `vault_key_credential_and_env_paths_are_excluded` | vault, keys, `key`, `.env`, credentials, `.enc`, `.pem`, `.key`, token and declared-value paths |
| `a_symlink_outside_the_root_is_excluded` (Unix) | final symlink and symlinked-ancestor escapes |
| `per_file_and_total_caps_skip_and_report` | per-file and total caps skip with reasons |
| `binary_files_are_dropped_instead_of_copied` | non-text files are dropped, not copied |
| `the_same_inputs_and_clock_produce_the_same_bundle` | byte-identical manifest and tree |
| `a_missing_root_is_an_error_and_writes_nothing` | a bad root fails before writing |

### Known forensics limits

- Redaction is pattern- and caller-based, not a guarantee for an unknown secret
  format. Any secret shaped unlike the markers above must be supplied in
  `BundleInputs::redactions` or the path must be excluded.
- Strong markers are ASCII and case-sensitive (`AKIA`, not `akia`).
- Non-UTF-8 files are dropped entirely; a binary log is not bundle evidence.
- `manifest.json` is not listed or hashed in its own file list.
- FNV-1a 64 detects accidental differences, not tampering.
- The timeline parser accepts the documented aliases only; other timestamp
  shapes count as malformed rather than being guessed at.

## CLI

```
zero-doctor            # human report
zero-doctor --json     # the DoctorReport as JSON
zero-doctor --version  # the version, then exit
```

The human output starts with the version, `independent`, `daemon`, and the check
count, then one `status  name  detail` line per check (`ok`, `warn`, or `fail`).
The binary exits zero on every path in this task: the doctor reports state, and
callers decide what a failed check means. Playbooks, repair plans, timelines,
and redacted bundles are available through the library API above; the repair CLI
flag arrives with its own task.

## Fixture strategy

The check functions take `&DoctorContext`, so every fixture is just a struct
literal plus a temporary directory:

- File-backed checks (`config`, `keys`, `workers`, `mesh`, `journals`, `mcp`)
  write real files into a `tempfile::tempdir()` and read them back, so path
  handling, presence, and parse failures are exercised end to end.
- Injected checks (`versions`, `kernel`, `auth`, `network`, `ports`, `disk`,
  `locks`) set the snapshot directly. `locks` also injects `now` and each
  modification time, so staleness is deterministic.
- Each check has at least one pass and one failure fixture, plus a warn fixture
  where the state exists. `keys` has a Unix-only permission fixture.
- Security assertions live with the fixtures: the config failure fixture asserts
  its secret value does not appear in the detail, and the MCP warning fixture
  asserts the env value is not echoed.
- `tests/independent.rs` keeps the T-DOC-01 guarantee: the binary runs with the
  daemon dead, reports `daemon: not contacted`, and serializes 13 named checks.

## Known limits

These are deliberate for T-DOC-02 and are not fabricated passes:

- TOML validation is structural only (balanced brackets, closed strings, table
  headers, `key = value` shape). The allowed dependency set has no TOML parser,
  so value semantics are left to the config loader.
- Key permission checking is Unix-only; on Windows the detail says permissions
  were not checked.
- `network` validates URL shape and offline state without DNS or connectivity
  probes.
- `disk`, `ports`, `kernel`, and `auth` report the injected snapshot; the
  default context cannot discover them while the daemon is dead, so they warn.
- Some playbooks are necessarily generic. The taxonomy is stable and a code does
  not name a subsystem, so `Internal`, `Cancelled`, `Timeout`, and similar
  entries give a safe inspection and reporting sequence rather than a specific
  repair; the message and the check details carry the specifics.
