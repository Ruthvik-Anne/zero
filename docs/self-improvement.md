# Self-improvement: the held-out suite and the loop

`zero-agent::eval_suite` is the evaluator half of the self-improvement loop
(SI-01, SI-05, SI-10; T-SI-01). It stores versioned held-out tasks, hands a
candidate only what it is allowed to see, runs the candidate offline in a fresh
workspace, and scores the result against a key the candidate never receives.

`zero-agent::self_improve` is the loop half (T-SI-02). It carries one bounded
proposal through execute → verify → capture → distil → evaluate → promote →
re-enter. Verification is injected, evaluation consumes the two `EvalReport`
values above, and promotion stops at a `Promotion` value.

`zero-agent::promotion` is the promotion half (T-SI-03, SI-03, SI-06, SI-07,
SI-09). It refuses candidates that touch the immutable core, renders a bounded
deterministic diff, requires a human approval bound to that diff hash, applies
the change with a snapshot, and can roll it back. Nothing in the loop can apply
a change itself.

`SR-17` (a bounded fix per confirmed finding, promoted only with fresh
evidence) is the reason the report is scores-only and the reason a proposal must
carry at least one evidence reference: an improvement claim is
`compare(baseline, candidate)` on the same pinned suite, nothing else.

## Suite document

```json
{
  "schema_version": 1,
  "suite_version": "si-1.0.0",
  "created_ms": 1700000000000,
  "tasks": [
    {
      "id": "write-answer",
      "prompt": "Create answer.txt containing 42.",
      "fixture": { "files": { "input.txt": "question\n" } },
      "checks": [
        { "kind": "exit_code", "code": 0 },
        { "kind": "file_contains", "path": "answer.txt", "needle": "42" },
        { "kind": "file_absent", "path": "leftover.tmp" },
        { "kind": "output_contains", "text": "done" }
      ]
    }
  ]
}
```

- `schema_version` is the wire format and is compared exactly. An unknown value
  is a typed `zero.fnd.schema_version` error.
- `suite_version` names the task set (`ALNUM . - _ +`, at most 64 bytes). It is
  copied into every report and is covered by the hash. Bumping the tasks means
  bumping this and the pinned hash.
- `created_ms` is recorded metadata; it does not drive scheduling.
- `id` is the stable scoring key. It must be unique in the suite and is
  restricted to ASCII letters, digits, `-`, `_`, and `.` so it can name a
  directory.
- `fixture.files` is a `BTreeMap`, so serialization and hashing are canonical.
- `checks` is the scoring key. It never leaves the trusted evaluator.

## Visibility split (SI-05)

`public_view(&suite)` returns a `PublicSuite` of `PublicTask { id, prompt,
fixture }`. There is no `checks` field on `PublicTask`: the key is excluded by
the type, not by a runtime filter that a refactor could drop. `run_suite`
projects the suite itself and passes each `PublicTask` to the runner, so the
runner cannot receive `EvalSuite` by accident.

Tests: `public_view_carries_no_scoring_key` serializes the public view and
asserts it contains neither `checks` nor the expected text; the recording
runner in `runner_receives_only_public_tasks` also asserts it never sees the
key.

This is a value-level boundary. It does not sandbox a runner that reads files
from the filesystem directly; a runner that wants the suite would have to be
given the trusted path, which `run_suite` never does.

## Loading and the trust root

`load_suite(path, trusted_root)`:

1. canonicalizes `trusted_root` (must exist and be a directory);
2. refuses `path` when it is a symlink;
3. canonicalizes `path` and refuses anything that is not strictly inside the
   canonical root (`zero.fnd.permission_denied`);
4. refuses a non-file, then checks the size before reading;
5. reads at most `MAX_SUITE_BYTES + 1` bytes and refuses growth past the cap;
6. parses JSON, then runs `validate_suite`.

A candidate that can write inside its own project cannot substitute the suite
it is measured on, as long as the pinned copy lives in the caller's trusted
root (the evaluator's immutable area, per SI-06). `load_suite_verified` adds
the pinned-hash check to the same call.

Bounds enforced by `validate_suite` (constants are public):

| Bound | Value |
|---|---|
| Suite file (load) | 1 MiB |
| Tasks per suite | 256 |
| Fixture files per task | 64 |
| One fixture file | 64 KiB |
| Fixture bytes per task | 256 KiB |
| Fixture bytes per suite | 4 MiB |
| Checks per task | 32 |
| Prompt | 8 KiB |
| Task id | 64 bytes |
| Fixture or check path | 512 bytes |
| Needle or expected output | 4 KiB |

A task must have at least one check and a non-empty prompt. Duplicate task ids
are refused with `zero.fnd.invalid_input`, because a duplicate would silently
give one task two scoring keys.

## Offline runner

```rust
pub trait CandidateRunner {
    fn run(&self, task: &PublicTask, workspace: &Path) -> Result<CandidateOutput>;
}
```

`run_suite(suite, runner, scratch_root)`:

1. validates the suite in memory (an in-memory suite gets the same checks as a
   loaded one);
2. creates `scratch_root` and, per task in suite order, `task-NNNN-<id>`;
3. refuses to reuse an existing workspace (`zero.fnd.already_exists`) instead
   of deleting it;
4. writes the fixture files under that directory only;
5. calls the runner;
6. scores every check and records `TaskResult { id, passed, failed_checks }`.

Fixture paths go through `safe_relative_path`, which refuses absolute paths,
drive or stream prefixes (`:`), `.`/`..` components, empty components, NUL,
and over-long paths, and treats both `/` and `\` as separators so a suite
behaves the same on Windows, macOS, and Linux. `file_contains` reads through a
canonicalized path and refuses a target that resolves outside the workspace;
`file_absent` inspects the link itself, so a dangling symlink counts as
present.

There is no network code: no socket types, no HTTP client, and no provider or
model router. `the_module_holds_no_network_or_router_api` scans this module's
source for those names (needles are assembled at run time so the test does not
match itself).

A runner error fails only that task. The report records
`runner_error: <stable error code>` and never the error message, the prompt, or
the candidate's output.

`run_suite_with_clock` takes an injected `zero_types::id::Clock` so a test can
produce an identical report twice; `run_suite` uses the system clock.

## Checks

| Kind | Passes when | Failure detail |
|---|---|---|
| `exit_code` | the runner's exit code equals `code` | expected and actual code |
| `file_contains` | `path` exists in the workspace and contains `needle` | path only |
| `file_absent` | nothing exists at `path` | path only |
| `output_contains` | `stdout` contains `text` | no text |

`stdout` only: `stderr` is deliberately not searched, so a test that expects a
diagnostic can assert on it through a file or a dedicated check rather than
depending on stream interleaving. Candidate files larger than 1 MiB are not
read past the cap and fail the check.

Failure details never include the needle or the expected text. That keeps a
failing report safe to hand to the candidate loop: it says which check failed
and, for file checks, which fixture path, not the answer.

## Hashing and versions

`EvalSuite::canonical_bytes` is the versioned domain separator
`zero.eval-suite.v1`, a newline, and the compact JSON projection (struct fields
in declaration order, fixture files ordered by `BTreeMap`; the document has no
floating-point values). `suite_hash` is BLAKE3 over those bytes as lowercase
hex.

`verify_hash(suite, expected)` accepts upper- or lower-case hex, refuses a
malformed digest with `zero.fnd.invalid_input`, and refuses a stale digest with
`zero.fnd.tamper`. The hash covers `schema_version`, `suite_version`,
`created_ms`, and every task, so editing a prompt, a fixture, or a check
invalidates the pin. The pin itself is stored by the caller (config, a signed
audit record, the promotion gate), never inside the suite document where the
same edit could update it.

## Report and comparison

```rust
pub struct EvalReport {
    pub suite_version: String,
    pub passed: usize,
    pub failed: usize,
    pub task_results: Vec<TaskResult>, // suite order
    pub started: i64,
    pub finished: i64,
}
```

Task order is suite order and failed-check order is check order, so two runs of
the same suite with the same candidate produce byte-identical JSON when the
clock is injected. The report contains no prompts and no expected text.

`compare(baseline, candidate)` returns `Delta { regressions, improvements }`
in baseline order:

- baseline pass → candidate fail: regression;
- baseline fail → candidate pass: improvement;
- a baseline task missing from the candidate: regression (no evidence of a
  pass);
- a task only the candidate has: ignored (no baseline evidence).

Both reports must come from the same `suite_version`. A version change is not
comparable evidence, which is why the version travels in the report next to the
out-of-band hash.

## The loop (T-SI-02)

`zero-agent::self_improve` runs one bounded `Proposal` through seven stages. The
declaration order of `Stage` is the execution order, and `Stage::ALL` is the
same list:

| Stage | What it does | Seam |
|---|---|---|
| Execute | applies the change in a fresh scratch workspace | `ProposalExecutor` |
| Verify | builds and tests the candidate | `Verifier` |
| Capture | hashes every written file, inside the workspace | module code |
| Distil | writes one bounded summary | module code |
| Evaluate | scores baseline and candidate on the held-out suite | `Evaluator` |
| Promote | records the automated gate decision | `promote` |
| Reenter | records the next iteration seed | module code |

The loop is synchronous. SI-08's isolation rule holds because the caller runs
it away from the task it measures; the loop itself never shares a workspace
between two attempts.

### Proposal

```rust
pub struct Proposal {
    pub id: String,            // BLAKE3 over the other fields
    pub created_ms: i64,
    pub title: String,
    pub rationale: String,
    pub change: ChangeSet { files: BTreeMap<String, String>, description: String },
    pub target: Target,        // AgentPrompt | Skill | ToolPolicy | Code
    pub evidence_refs: Vec<String>,
}
```

`Proposal::new` validates the content, then derives `id` from the versioned
domain separator `zero.si-proposal.v1` and the compact JSON of every field
except `id`. The id is content-addressed: the same proposal built twice has the
same id, and editing any field without recomputing the id is
`zero.fnd.tamper` when validation runs. At least one evidence reference is
required: a proposal with no evidence is `zero.fnd.invalid_input` before the
executor is called (SI-02). Change paths go through `safe_relative_path`, the
same check the suite fixtures use, so `..`, absolute paths, drive prefixes, and
empty components are refused at validation time.

### Seams

```rust
pub trait ProposalExecutor {
    fn scratch_root(&self) -> &Path;
    fn execute(&self, proposal: &Proposal, workspace: &Path) -> Result<ExecutionRecord>;
}

pub trait Verifier {
    fn verify(&self, workspace: &Path) -> Result<VerifyRecord>;
}

pub trait Evaluator {
    fn baseline(&self) -> Result<EvalReport>;
    fn candidate(&self, proposal: &Proposal, workspace: &Path) -> Result<EvalReport>;
}
```

The loop creates `scratch_root/attempt-NNNN-<proposal id>`, refuses an existing
directory (`zero.fnd.already_exists`) instead of deleting it, and validates
every path the executor reports: the file must exist, go through
`safe_relative_path`, and canonicalize inside the workspace. An executor that
reports `../escape.txt` fails Execute before the verifier runs. `apply_change_set`
is the supplied writer: it canonicalizes the workspace, refuses a path that
escapes it, and creates parents inside the root only.

The executor and verifier are trusted in-process seams. The path checks stop a
contract-abiding executor and a bad change set; they do not sandbox a trait
implementation that ignores its arguments. That boundary is T-TRU-03/T-SI-03.

### Acceptance rule

Evaluate calls `baseline` and `candidate`, then:

1. both reports must carry the same `suite_version`; otherwise the Evaluate
   stage fails with `LoopDecision::Failed`;
2. `compare(baseline, candidate)` produces the delta;
3. a non-empty `regressions` list rejects the candidate, even when it also
   improves another task, and the regression task ids are recorded;
4. no regressions but no improvements rejects with
   `the candidate has no measurable improvement`;
5. no regressions and at least one improvement accepts, recording the improved
   task ids and the baseline suite version.

A failed Execute, Verify, Capture, Distil, or Evaluate stage stops the loop
immediately and records `LoopDecision::Failed { stage, reason }`. No later stage
runs, so a candidate that does not build can never be evaluated or promoted.

### Promotion and the human gate

```rust
pub struct Promotion {
    pub proposal_id: String,
    pub approved: bool,
    pub gate: HumanGate { required: bool, reason: String },
}
```

`promote(&LoopState)` is pure. It returns `approved: true` only when the
decision is `Accepted` **and** both evaluation reports are present; a
hand-written `Accepted` label without reports does not promote. It never
writes a file, changes a prompt, or touches the evaluator. For an accepted
candidate `gate.required` is true: SI-03's human promotion is the only path that
applies the change, with its diff and rollback plan. For a rejected or failed
candidate `approved` and `gate.required` are both false. The implementation is
the `zero-agent::promotion` section below.

### Re-entry

The final stage records a `ReentrySeed { proposal_id, next_attempt, objective,
evidence_refs, exhausted }`. For an accepted change the objective says to keep
and extend it; for a rejection with regressions it names the regression to
repair; for a rejection without a gain it asks for a different bounded change.
`exhausted` is true when `attempts >= limits.max_attempts`. The seed carries no
authority: a caller must build a new `Proposal` from it.

### Limits

| Bound | Value |
|---|---|
| Attempts per caller budget | 8 (`MAX_ATTEMPTS`) |
| Files per change set | 16 |
| One change file | 64 KiB |
| All change files | 256 KiB |
| Title | 256 bytes |
| Rationale or change description | 4 KiB |
| Evidence references | 32, each 512 bytes |
| Distilled summary | 2 KiB |
| Verification detail or failure reason | 1 KiB |
| Executor output kept in the report | 4 KiB |

`LoopLimits::capped` clamps a caller's request to those maxima. A budget of zero
is allowed and produces `LoopDecision::Failed { stage: Execute }` without calling
the executor, so "no budget" can never mean "run anyway". One `run_loop` call
consumes exactly one attempt.

## Promotion and rollback (T-SI-03)

`zero-agent::promotion` starts where the loop stops. It accepts a
`LoopState`, never a bare `Proposal`, and is the only code that writes a
promoted change:

```text
accepted LoopState
  -> ImmutableCore::check            (SI-06)
  -> render_diff + diff_hash         (SI-03, SI-09)
  -> HumanGate::approve              (SI-07)
  -> ApprovedPromotion               (sealed)
  -> apply_promotion                 (snapshot, atomic writes)
  -> rollback                        (restore, remove)
```

### Immutable core (SI-06)

```rust
pub struct ImmutableCore { protected: Vec<String> }

impl ImmutableCore {
    pub fn check(&self, change: &ChangeSet) -> Result<()>;
    pub fn check_under(&self, change: &ChangeSet, root: &Path) -> Result<()>;
}
```

The default core protects the evaluator and its harness
(`crates/zero-agent/src/eval_suite.rs`, `self_improve.rs`), the promotion rules
(`promotion.rs`), the audit log (`crates/zero-agent/src/audit.rs`), all of
`crates/zero-policy/src/` (mode, deletion, protected paths, approvals,
regulator), and all of `crates/zero-secrets/src/` (credential handling). A
trailing `/` marks a directory subtree.

Every candidate path goes through `safe_relative_path` first, then a
`/`-separated ASCII case-folded comparison. Absolute paths, drive prefixes,
NUL, empty components, and `.`/`..` are `zero.fnd.invalid_input`; a protected
path is `zero.pol.denied`. Control characters are also refused so a path cannot
inject a line into the diff. `check_under` additionally walks the existing
components under the canonical target root and refuses a symlink with
`zero.pol.denied`.

The protected list is private and `ImmutableCore::new` validates it, so a
caller cannot widen the core through an accessor. The candidate cannot edit the
evaluator, the harness, the policy, or the promotion rules it is judged by.

### Diff (SI-03, SI-09)

`render_diff(&ChangeSet) -> String` emits, per file in `BTreeMap` order:

```text
--- a/prompts/system.md
+++ b/prompts/system.md
@@ -0,0 +1,2 @@
+line one
+line two
```

The old side is empty because a `ChangeSet` carries only new contents; every
line is an addition. There are no timestamps, no proposal title, rationale, or
change description, and no content beyond the candidate files. A file without a
trailing newline gets the standard `\ No newline at end of file` marker.

`diff_hash(&ChangeSet)` is BLAKE3 over `zero.si-diff.v1`, a newline, and the
rendered bytes, lowercase hex. `render_diff` is bounded by
`MAX_DIFF_BYTES` (1 MiB); when the cap is hit the output ends with
`--- diff truncated at the byte cap ---` and nothing after it. A valid change
set is at most 16 × 64 KiB = 1 MiB of content, and headers and line prefixes
push it over the cap, so the truncation path is reachable with a valid change
set as well as with a raw `ChangeSet`.

### Human gate (SI-07)

```rust
pub trait HumanGate {
    fn approve(&self, proposal_id: &str, diff_hash: &str) -> Approval;
}

pub enum Approval {
    Approved { by: String, at_ms: i64, diff_hash: String },
    Denied { reason: String },
}
```

`approve_promotion(&LoopState, &dyn HumanGate) -> Result<ApprovedPromotion>`
refuses unless all of these hold:

1. the proposal id still matches its content (`zero.fnd.tamper` on edit);
2. the immutable-core check passes (`zero.pol.denied`);
3. the decision is `Accepted` **and** both `EvalReport` values are present
   (`zero.pol.denied`);
4. the gate returns `Approved` for **this** proposal id and **this** diff hash.

A `Denied` decision is `zero.pol.denied`. An approval that names a different
diff hash, or an empty approver, is `zero.pol.ask`: a fresh human decision is
required, and the stale approval cannot be replayed. `ApprovedPromotion` has
private fields, a module-private seal token, and no `Deserialize`, so only
`approve_promotion` can mint it. A loop `Promotion { approved: true }`, a diff
string, or a deserialized record cannot be used as an approval, which is the
type-level "the agent cannot self-approve" guarantee.

### Apply (SI-09)

`apply_promotion(&ApprovedPromotion, target_root, backup_root, now_ms)`:

1. recomputes the diff hash and refuses a mismatch (`zero.fnd.tamper`);
2. canonicalizes the target root, re-runs `check_under`, and re-validates the
   file count, per-file size (64 KiB), and total size (256 KiB);
3. creates `backup_root/promotion-<id prefix>-<now_ms>` and refuses an existing
   directory (`zero.fnd.already_exists`) instead of deleting it;
4. per file, in canonical path order: creates parent directories one component
   at a time (refusing a symlink or a non-directory), reads an existing regular
   file through a 1 MiB cap, records its BLAKE3, and writes it to
   `NNNN.bak`;
5. writes the new content through a same-directory `create_new` temp file and
   an atomic rename.

`AppliedPromotion` records the proposal id, each file's previous and promoted
hash, the backup directory, the diff hash, the canonical target root, and the
apply time. Its fields are private and it is not `Deserialize`, so a record
cannot be fabricated to drive a later rollback.

An existing file that is a symlink or not a regular file is refused with
`zero.pol.denied`; an oversized snapshot is `zero.fnd.limit`. On any failure the
applied files are restored and created files removed in reverse order, and the
returned error keeps the original code and appends
`rolled back: N restored, M removed`.

### Rollback (SI-09)

`rollback(&AppliedPromotion, target_root)` walks the applied files in reverse
order:

- it first *preflights* every file: path validity, no symlink, the current
  target hash, and the snapshot hash. Nothing is written until every file
  passes, so a refused rollback leaves the tree exactly as it was;
- a file that existed is restored from its snapshot;
- a file the promotion created is removed;
- if the current target content no longer matches the promoted hash, rollback
  refuses with `zero.fnd.tamper` before writing anything;
- `rollback_forced` is the explicit `force`: it overwrites a changed target and
  sets `forced: true` in the `RollbackReport`.

The target root must canonicalize to the recorded root; rollback against a
different tree is `zero.pol.denied`. Protected paths are re-checked.

### Refusal rules

| Situation | Error |
|---|---|
| Candidate path is `..`, absolute, has a drive prefix, empty component, NUL, control char | `zero.fnd.invalid_input` |
| Candidate path is in the immutable core | `zero.pol.denied` |
| Candidate path passes through a symlink or replaces a symlink | `zero.pol.denied` |
| Decision is not `Accepted`, or a report is missing | `zero.pol.denied` |
| Gate denies | `zero.pol.denied` |
| Approval names a different diff, or no approver | `zero.pol.ask` |
| Approved diff hash no longer matches the change set | `zero.fnd.tamper` |
| Backup would exceed 1 MiB or a snapshot is larger | `zero.fnd.limit` |
| Backup directory already exists | `zero.fnd.already_exists` |
| Rollback target changed after promotion, without force | `zero.fnd.tamper` |
| Rollback against a different target root | `zero.pol.denied` |

### Bounds

| Bound | Value |
|---|---|
| Rendered diff | 1 MiB (`MAX_DIFF_BYTES`) |
| Snapshot bytes per promotion | 1 MiB (`MAX_BACKUP_BYTES`) |
| Snapshotted files | 16 (`MAX_BACKUP_FILES`) |
| Human denial reason kept in an error | 1 KiB (`MAX_REASON_BYTES`) |

### Test evidence

`cargo test -p zero-agent promotion` runs 13 matching tests (12 in
`promotion::tests`, plus `self_improve::tests::promotion_requires_both_evaluation_reports`),
all offline and tempdir-only:

| Test | Covers |
|---|---|
| `candidate_touching_the_evaluator_is_refused` | Done criterion: evaluator, policy, and promotion rules are `zero.pol.denied`; a prompt is allowed |
| `approved_candidate_applies_and_is_reversible` | apply two files, record hashes, rollback restores and removes |
| `gate_missing_denied_and_diff_hash_mismatch_are_refused` | denied gate, stale diff hash, unnamed approver, rejected decision, missing report |
| `self_approval_is_impossible_by_type` | the loop's `Promotion { approved: true }` is not an approval; only the sealed value applies |
| `rollback_restores_bytes_and_removes_created_files` | binary bytes restored, created file removed, snapshot recorded |
| `rollback_refuses_a_target_changed_after_promotion` | `zero.fnd.tamper` without force, no partial restore; `rollback_forced` restores |
| `apply_failure_rolls_back` | second file fails; the first is restored and the error names the rollback |
| `backup_is_bounded` | an oversized snapshot is `zero.fnd.limit` and the target is untouched |
| `diff_is_deterministic_and_bounded` | map-order independence, stable hash, no prose, 1 MiB truncation |
| `path_escapes_and_symlinks_are_refused` | `..`, both separators, absolute, drive prefix; file and directory symlinks (Unix) |
| `rollback_refuses_a_different_target_root` | a rollback pointed at another tree is refused |
| `the_module_holds_no_network_or_router_api` | offline source scan |

`cargo clippy -p zero-agent --all-targets -- -D warnings` is clean.

### Known edges

- Rollback restores files but leaves empty directories the promotion created.
- A symlink race between `check_under` and the write is not defended; the
  threat model is accidental harm, and the target root is trusted parent state.
- Windows junctions/reparse points are not distinguished from directories by
  `FileType::is_symlink`; a junction parent is caught by the canonical
  containment check only when it resolves outside the root.
- The human decision is an in-process seam. A durable approval ledger and the
  host UI that implements `HumanGate` are outside this slice.

## Test evidence

`cargo test -p zero-agent eval_suite` runs 16 tests, all offline and
tempdir-only:

| Test | Covers |
|---|---|
| `suite_loads_validates_and_round_trips` | load, equality, canonical hash, case-insensitive verify, verified load |
| `public_view_carries_no_scoring_key` | no `checks`, no expected text, ids/prompts/fixtures preserved |
| `runner_receives_only_public_tasks` | runner gets a `PublicTask`, fixture written first, workspace naming |
| `every_check_kind_passes_and_fails` | all four kinds, both outcomes, no expected text in details |
| `fixture_paths_cannot_escape_the_workspace` | `..`, both separators, absolute, drive prefix, empty, nested traversal |
| `an_existing_workspace_is_not_deleted` | fresh-workspace rule is fail-closed |
| `load_refuses_paths_outside_the_trusted_root` | outside root, traversal, directory, symlink (Unix) |
| `load_is_bounded_before_it_parses` | 1 MiB read cap |
| `unknown_schema_and_bad_versions_are_typed` | `SchemaVersion`, empty and malformed `suite_version` |
| `duplicate_task_ids_are_refused` | uniqueness |
| `suite_bounds_are_enforced` | task, file, per-file, prompt, check, suite-total caps |
| `tampered_suite_with_a_stale_hash_is_refused` | stale and malformed pins, `load_suite_verified` |
| `runner_errors_fail_the_task_without_echoing_details` | stable code only |
| `reports_are_deterministic_and_ordered` | injected clock, suite order, identical JSON |
| `compare_reports_regressions_and_improvements` | regressions, improvements, missing results, new tasks |
| `the_module_holds_no_network_or_router_api` | offline source scan |

### Loop fixture (Done criterion)

`cargo test -p zero-agent self_improve` runs 13 tests. The Done fixture is a
two-task suite (`write-answer`, `second`) whose checks are an exit code and
`answer.txt` containing `42`. The baseline runner fails `second`; the candidate
runner is varied:

| Test | Covers |
|---|---|
| `fixture_accepts_a_candidate_that_passes_both_tasks` | baseline fails `second`, candidate passes both → `Accepted { improvements: ["second"] }`, Promote in history, human gate required |
| `fixture_rejects_a_candidate_that_regresses_a_task` | baseline passes both, candidate fails `second` → `Rejected { regressions: ["second"] }`, no Promote stage, no approval |
| `stage_history_is_the_documented_order` | `Stage::ALL` order matches the recorded history positions |
| `a_failed_verification_stops_before_evaluate` | failed Verify stops with no baseline/candidate call and no re-entry |
| `promotion_requires_both_evaluation_reports` | `Accepted` without reports is not approved; both reports approve |
| `attempts_are_bounded` | zero budget fails at Execute with no executor call; `u32::MAX` caps at `MAX_ATTEMPTS` |
| `evidence_refs_are_required` | `Proposal::new` and `run_loop` both refuse an empty evidence list |
| `change_paths_cannot_escape_the_scratch_workspace` | `../escape.txt` is refused by `apply_change_set` and by proposal validation; nothing is written outside |
| `an_executor_reporting_an_outside_path_stops_the_loop` | a reported `../escape.txt` fails Execute before Verify |
| `ids_and_reports_are_deterministic` | equal content gives equal ids; fixed clock and evaluator give equal reports and JSON |
| `reenter_seeds_the_next_iteration` | seed carries attempt 2, evidence refs, and `exhausted` at the budget |
| `proposal_bounds_are_enforced` | file count, per-file bytes, and a stale id (`TamperDetected`) |
| `the_module_holds_no_network_or_router_api` | offline source scan |

`cargo clippy -p zero-agent --all-targets -- -D warnings` is clean for both
modules.

## Not in this slice

- Process isolation and wall-clock timeout: `CandidateRunner` is an in-process
  trait. A runner that spawns a child owns sandboxing and the timeout; the suite
  only guarantees a fresh directory and path-safe fixture writes.
- Fixtures are UTF-8 strings; binary fixtures are not represented.
- The loop stops at a `Promotion` value; `zero-agent::promotion` is the only
  path that applies it (T-SI-03). The executor and verifier are trusted
  in-process seams; sandboxing a hostile implementation is T-TRU-03.
- `compare` does not refuse mismatched `suite_version` values; it compares by
  task id. The loop adds the version check before it compares, and the caller
  still owns the pinned hash.
- A durable human-approval ledger, the host UI behind `HumanGate`, and removing
  empty directories after a failed apply are not in this slice.

