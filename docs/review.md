# Security review

`zero-review` implements the checklist-first half of the security review
(`features.md` §10.22): the mode gate (SR-01), the trust-boundary summary and
coverage ledger (SR-02, SR-03), canonical references, append-only status
history, review profiles (SR-13), the validators for both structured artifacts
(SR-06), the derived report set (SR-14), coverage-led hunting waves with an
independent critic pass (SR-04, SR-05), and the independent validation pass with
a verifier quorum, fingerprint stability, and the SR-07 severity rule. This
crate never modifies target source. It never runs target code on its own:
`sandbox` is the only execution seam, and it refuses to run target code unless
a real platform mechanism is present (SR-09, SR-10).

## Mode gate (SR-01)

`zero_review::gate(&ReviewRequest)` narrows the request before any work starts.
A plain question may never open a full audit, and guidance may never open a
hunting wave.

| Requested mode | `user_asked_for_audit` | `wants_report_artifacts` | Runs | Phases |
|---|---|---|---|---|
| `guidance` | any | any | `guidance` | `recon`, `output` |
| `audit` | `false` | `false` | `guidance` | `recon`, `output` |
| `audit` | `true` | `false` | `audit` | `recon`, `coverage_hunt`, `validation`, `output`, `record_verification` |
| `audit` | any | `true` | `full_report` | the audit phases plus `report` |
| `full_report` | `true` | `true` | `full_report` | the audit phases plus `report` |
| `full_report` | `true` | `false` | `audit` | a full review without derived artifacts |
| `full_report` | `false` | `false` | `guidance` | `recon`, `output` |

`ReviewPlan.guidance_only` is true exactly in guidance mode. Guidance runs
`recon` and `output` only: it produces the trust-boundary summary and a
validated ledger, with no coverage hunt and no separate validation phase.

## Trust-boundary summary (SR-02)

`seed_report(root)` returns the ledger plus a `Vec<TrustBoundary>` and a
`Vec<Surface>`. A boundary is emitted when at least one unit crosses it; its
evidence is the canonical `path:line` references of those units.

| Attack class | Boundary | Lower trust | Higher trust |
|---|---|---|---|
| `command_injection` | `process-exec` | repository content or model output | operating-system process |
| `path_traversal` | `filesystem-path` | untrusted path component | filesystem namespace |
| `ssrf_egress` | `network-egress` | local process | remote network service |
| `unsafe_deserialization` | `untrusted-input` | untrusted bytes or text | parsed application data |
| `injection` | `database-query` | untrusted input string | database engine |
| `credential_exposure` | `credential-store` | repository or configuration file | credential secret |
| `memory_safety` | `memory-model` | safe Rust code | raw memory |
| `permission_issues` | `permission-model` | unprivileged file | filesystem metadata |

## Ledger schema (SR-03)

`CoverageLedger` is the `coverage-ledger.json` artifact (`LEDGER_FILE`),
serialized with `schema_version = 1`:

```json
{
  "schema_version": 1,
  "units": [
    {
      "id": "sr-shell-command-injection-1a2b3c4d",
      "surface": "process",
      "boundary": "process-exec",
      "subsystem": "src",
      "attack_class": "command_injection",
      "refs": ["src/shell.rs:1", "src/shell.rs:4"],
      "starting_paths": ["src/shell.rs"],
      "selected_companions": ["src/lib.rs"],
      "excluded_companions": [
        { "path": "Cargo.lock", "reason": "lock file" }
      ],
      "status": "pending",
      "history": [],
      "owner": "",
      "reviewed_paths": [],
      "checks": [
        "command_injection: untrusted input never reaches an argument list",
        "command_injection: no shell-string interpolation",
        "command_injection: the executable and arguments come from an allowlist"
      ],
      "fingerprint": "9f2c1d7e4b6a8053"
    }
  ],
  "summary": {
    "units": 1,
    "pending": 1,
    "assigned": 0,
    "reviewed": 0,
    "confirmed": 0,
    "refuted": 0,
    "out_of_scope": 0,
    "deferred": 0,
    "blocked": 0,
    "surfaces": 1,
    "boundaries": 1,
    "subsystems": 1,
    "attack_classes": 1,
    "files_scanned": 6,
    "files_excluded": 4,
    "files_size_capped": 0,
    "walk_truncated": false,
    "truncation": [],
    "max_files": 512,
    "max_depth": 8,
    "max_file_bytes": 262144
  }
}
```

| Field | Meaning |
|---|---|
| `id` | `sr-<surface>-<class>-<8 hex>`; unique inside a ledger |
| `refs` | canonical path or requirement references; seeded units use root-relative `path:line`, at most 8 per unit |
| `starting_paths` | root-relative files where the marker was found |
| `selected_companions` | other scannable files in the same subsystem, at most 16 |
| `excluded_companions` | files considered and rejected, each with a reason |
| `status` | one of the statuses below |
| `history` | append-only `UnitEvent` list; missing in old artifacts, defaults to empty |
| `owner` | required once assigned; empty while pending |
| `reviewed_paths` | required for `reviewed` and `confirmed` |
| `checks` | the class's review questions; never empty |
| `fingerprint` | FNV-1a 64 of the identity fields, lowercase hex |
| `content_fingerprint` | optional FNV-1a 64 of canonical refs plus bounded file bytes, recorded on confirmation and cleared when re-review is required (SR-11) |

| Status | Counted as covered | Owner | Reviewed paths |
|---|---|---|---|
| `pending` | no | optional | not required |
| `assigned` | no | required | not required |
| `reviewed` | yes | required | required |
| `confirmed` | yes | required | required |
| `refuted` | no | required | optional |
| `out_of_scope` | **never** | optional | must be empty |
| `deferred` | no | optional | not required |
| `blocked` | no | optional | not required |

A `confirmed` unit is terminal for the hunt, but SR-11 reopens it as
`deferred` when [`check_fingerprints`] finds that the target changed. `refuted`
and `out_of_scope` never reopen; revisit those as a new unit.

## Canonical references (SR-03)

A `CanonicalRef` is either a path reference or a requirement id. `parse` rejects
everything else, and a parsed value always serializes as its canonical string.

| Form | Grammar | Examples |
|---|---|---|
| path | `path:line` or `path:line:col` | `src/net/client.rs:42`, `src/net/client.rs:42:7` |
| requirement | `^[A-Z]{2,4}-[0-9]{2,3}$` | `SEC-01`, `MCP-13`, `TRU-123` |

Path rules:

- relative, forward slashes only; absolute, drive, and UNC paths are rejected;
- no backslashes, control characters, empty segments, `.` or `..` components,
  trailing separators, or `:` inside the path;
- `line` and `col` are positive integers, and a column is only valid with a
  line.

Requirement ids are case-sensitive and upper-case only: `SEC-01` is valid;
`sec-01`, `SEC-1`, `SECURITY-01`, and `SEC-0001` are not.

`canonicalize_ref` returns the display string used for comparison (for example
`src/shell.rs:01` normalizes to `src/shell.rs:1`). It never touches the
filesystem.

`validate_refs(units, root)` rejects a duplicate reference inside one unit; the
same reference in different units is allowed. When `root` is supplied, every
path reference must resolve to an existing regular file after canonicalizing
both the root and the candidate, and the candidate must stay under the root.
Requirement references need no file.

## State transitions and history (SR-03)

`history` is append-only. Each `UnitEvent` records `at_ms`, `from`, `to`,
`actor`, and an optional `note`. `advance(unit, to, actor, note, now_ms)` appends
one event, updates the status, and adopts the actor as the owner when the target
status requires one. `CoverageLedger::advance` does the same by unit id and
refreshes the status counts.

| From | Allowed targets | Note |
|---|---|---|
| `pending` | `assigned`, `out_of_scope`, `deferred`, `blocked` | required for the last three |
| `assigned` | `pending`, `reviewed`, `out_of_scope`, `deferred`, `blocked` | required for `pending` and the last three |
| `reviewed` | `confirmed`, `refuted`, `deferred`, `blocked` | required for the last two |
| `deferred` | `assigned`, `out_of_scope`, `blocked` | required for the last two |
| `blocked` | `assigned`, `deferred`, `out_of_scope` | required for the last two |
| `confirmed` | `deferred` | required; only for SR-11 re-review after a fingerprint change |
| `refuted`, `out_of_scope` | none | terminal; revisit as a new unit |

Self-transitions are never allowed. An illegal step, a missing required note, or
an empty actor is `zero.pol.denied`; a transition time before the last event is
`zero.fnd.invalid_input`.

Validation of a non-empty history rejects:

- an `at_ms` below the previous event (non-monotonic);
- a `from` that differs from the previous event's `to`;
- an illegal matrix step or a missing required note;
- an empty actor;
- a unit status that differs from the last event's `to`.

An empty history is accepted for a seeded or adopted unit, including a unit
whose status was set by `assign`.

## Hunting waves (SR-04, SR-05)

A wave turns validated ledger units into candidates, applies the evidence bar,
and asks an independent critic for a verdict. Only an accepting critic produces
a confirmed `Finding`; the ledger records every transition.

### Candidate schema

`hunt::CandidateFinding` is the only shape an agent may return:

| Field | Rule |
|---|---|
| `id` | non-empty; unique inside one wave |
| `unit_id` | must equal the unit being hunted |
| `title` | non-empty |
| `severity` | `info`, `low`, `medium`, `high`, or `critical` |
| `lower_trust_principal` | non-empty name of the untrusted side |
| `boundary` | non-empty; must equal the unit's boundary |
| `concrete_result` | non-empty description of what the input actually does |
| `evidence_refs` | non-empty canonical refs; at least one inside the unit's starting or reviewed paths; no duplicates |
| `checks` | optional, but no blank entry |
| `notes` | optional free text; never rendered as control flow |

### Evidence bar (SR-05)

`hunt::validate_candidate(candidate, unit)` rejects, as typed
`zero.fnd.invalid_input` naming the candidate and the failed field:

- no named lower-trust principal (`lower_trust_principal`);
- a boundary that is empty or differs from the unit's boundary (both sides are
  named in the message);
- an evidence list with no ref inside the unit's starting or reviewed paths, or
  with duplicate refs;
- no concrete result;
- a severity above `info` with no concrete result, so a `critical` claim cannot
  rest on impact text that is absent;
- a `unit_id` that names another unit, an empty id or title, or a blank check.

Requirement references are valid evidence but do not satisfy the in-unit path
rule on their own. Error messages never repeat scanned file text.

### Agent and critic seams

```rust
pub trait HuntAgent {
    fn label(&self) -> &str;
    fn hunt(&self, unit: &LedgerUnit) -> zero_types::error::Result<Vec<CandidateFinding>>;
}

pub trait AgentPool {
    fn label(&self) -> &str;
    fn agent(&self, unit: &LedgerUnit) -> &dyn HuntAgent;
}

pub trait Critic {
    fn label(&self) -> &str;
    fn review(&self, candidate: &CandidateFinding, unit: &LedgerUnit) -> CriticVerdict;
}

pub enum CriticVerdict {
    Accept,
    Reject { reason: String },
    NeedsEvidence { reason: String },
}
```

A pool may return one agent per unit or one shared scripted agent. The critic is
a separate object: a wave refuses to start when the pool's label, or any
selected unit's agent label, equals the critic's label. A critic that accepts
without inspecting evidence is still accepted structurally, because every
evidence ref was validated before `review` is called. A critic must not be the
hunter that produced the candidate.

### Per-unit flow and transitions

`HuntWave { wave_id, units, agent_cap }` runs sequentially and deterministically:

1. Deduplicate `units` in request order and reject an empty or unknown id.
2. Cap the list at `WaveLimits::max_units` (default: the standard profile's
   cap). Units past the cap are not assigned, hunted, or mutated; the caller
   schedules a later wave and SR-12 reports the run as incomplete.
3. Preflight every selected unit and agent. A unit that is already `reviewed`,
   `confirmed`, `refuted`, or `out_of_scope` refuses the whole wave before any
   mutation, as does an empty agent label.
4. Assign the unit to the agent (`pending`, `deferred`, or `blocked` becomes
   `assigned` through `assign`, so history is appended; an already assigned unit
   keeps its status and takes the new owner).
5. Run the agent. An error blocks only that unit (`assigned -> blocked` with the
   bounded error message); the wave still returns a report.
6. Validate every returned candidate. A failed candidate is rejected, never a
   finding.
7. Fill `reviewed_paths` from the unit's starting paths and record
   `assigned -> reviewed`.
8. Apply the critic verdict:

| Verdict | Unit transition | Report section |
|---|---|---|
| `Accept` on at least one candidate | `reviewed -> confirmed` | `found` (confirmed `Finding`) |
| `Reject` on every candidate | `reviewed -> refuted` | `rejected` (reason kept) |
| `NeedsEvidence` and no accept | `reviewed -> deferred` | `deferred`, for `NEEDS-VALIDATION` |
| agent error | `assigned -> blocked` | `blocked` |
| no candidate at all | `reviewed -> refuted` | none; history says no candidate |

If one candidate is accepted and another is rejected, the unit is `confirmed`
and both dispositions are listed. `NeedsEvidence` defers the unit only when no
candidate is accepted; a needs-evidence candidate alongside an accepted finding
is not a finding and has no separate report slot, so it must be re-hunted as a
new unit if it still matters. Status changes are one `UnitEvent` each, appended
by `advance`; `validate` runs again before the wave returns, so the report and
the ledger cannot disagree.

### Budget

`WaveLimits { max_units, max_agents }` defaults to
`WaveLimits::for_profile(Standard)`. The effective agent cap is
`min(HuntWave::agent_cap, max_agents)`. Execution is sequential, so the agent
gap bounds distinct agents borrowed rather than in-flight work. When the agent
cap is reached, the remaining units are deferred with a reason instead of
silently skipped; `units_run` and `candidates` report what actually ran.
Reasons copied from an agent or critic are whitespace-collapsed and bounded to
240 characters before they reach a report.

### Planted-bug fixture

The fixture writes a temporary repository with:

```rust
use std::process::Command;

pub fn run(user_input: &str) {
    let _ = Command::new(user_input).spawn();
}
```

`ledger::seed` produces a `process-exec` / `command_injection` unit with
`src/agent.rs` in its starting paths. A scripted agent returns one candidate
with evidence `src/agent.rs:4`, the unit's boundary, the lower-trust principal,
and a concrete result; a scripted accepting critic confirms it. The wave report
contains `FND-1`, the unit is `confirmed` with a
`pending -> assigned -> reviewed -> confirmed` history, and `report::derive`
rebuilds the full report set from the ledger and the confirmed finding alone.

## Validation (SR-04, SR-05, SR-07, SR-11)

Hunting produces candidates; validation decides whether a candidate is a
finding. `validate::ValidationWave` re-reads the target read-only, asks
independent verifiers, and settles the ledger. A candidate that cannot be
reproduced from its own evidence is rejected, the unit is `refuted`, and no
finding is written: this is the false-positive path.

`lib.rs` re-exports this pass's `ValidationReport`; the ledger validator's
report keeps its own name as `LedgerValidationReport`.

### Verifier seam

```rust
pub trait Verifier {
    fn label(&self) -> &str;
    fn verify(&self, candidate: &CandidateFinding, unit: &LedgerUnit, target: &Path)
        -> zero_types::error::Result<VerificationVerdict>;
}

pub enum VerificationVerdict {
    Confirmed,
    Rejected { reason: String },
    NeedsEvidence { reason: String },
}
```

`EvidenceVerifier` is the deterministic implementation. It reads at most 64 KiB
per file, never runs target code, and never copies file text into a reason. For
every path reference it checks:

1. the SR-05 evidence bar (`validate_candidate`) — unit id, boundary, named
   principal, concrete result, and in-unit evidence;
2. the ref names a file in the unit's `starting_paths` or `reviewed_paths`;
3. the file exists, is a regular file, and resolves under the target root (a
   symlink escape is refused);
4. the cited line exists inside the bounded read, and a cited column, when
   present, is inside that line;
5. at least one cited line satisfies the matcher. `LineMatcher::NonEmpty`,
   `LineMatcher::Contains(marker)`, and a test-supplied
   `LineMatcher::Custom(LinePredicate)` are accepted, so a test can script
   "the cited line contains the sink" without a model.

A requirement reference is legal supporting evidence but is never read from
disk. A verifier that cannot read a file, or cannot reach the cited line inside
the bounded read, returns `NeedsEvidence`; a missing file is `Rejected`.

### Quorum and dispositions

`ValidationWave { max_verifiers, quorum }` defaults to three verifier slots and
a quorum of two (`DEFAULT_QUORUM`). `with_quorum` overrides the threshold; it
must stay between one and `max_verifiers`.

| Verifier tally | Candidate | Unit |
|---|---|---|
| confirmations ≥ quorum, no rejection, no needs-evidence | `confirmed` | `confirmed` + `Finding` |
| zero confirmations, at least one rejection, no needs-evidence | `rejected` | `refuted` |
| zero confirmations, a rejection and a needs-evidence | `needs_evidence` (disagreement) | `deferred` |
| zero confirmations, only needs-evidence | `needs_evidence` | `deferred` |
| fewer confirmations than quorum, no rejection | `needs_evidence` | `deferred` |
| confirmations and a rejection or needs-evidence | `needs_evidence` (disagreement) | `deferred` |

Preflight is mutation-free and fails with `zero.fnd.invalid_input`:

- the wave has at least one verifier slot and a quorum in range;
- every verifier label is non-empty and used at most once;
- no verifier label equals the unit's owner or any actor in the unit's history,
  so the hunter and critic cannot validate their own candidate;
- every named unit exists and is not already `confirmed`, `refuted`, or
  `out_of_scope`.

A `pending`, `deferred`, or `blocked` unit is assigned to the validation actor
first; an `assigned` unit is moved to `reviewed` (with `reviewed_paths` filled
from its starting paths). A confirmed unit is then `confirmed`; a rejected unit
is `refuted`; a needs-evidence unit is `deferred` with the reason. Every
disposition is one `UnitEvent`, and `validate` runs again before the pass
returns. A duplicated candidate id is refused as a rejected candidate rather
than a finding.

### Fingerprint stability (SR-04, SR-11)

`fingerprint_unit(unit, target)` is FNV-1a 64 over:

- the unit's canonical refs, sorted and deduplicated;
- for each path in the refs, starting paths, and reviewed paths: the path, the
  full file length, and the first 64 KiB of bytes.

A missing file hashes as a missing marker; it is a change, not an error.
`ValidationWave` records this value in `content_fingerprint` when it confirms a
unit.

`check_fingerprints(ledger, target)` re-reads every confirmed unit and returns
`FingerprintReport { stable, changed }`. When the recomputed value differs from
the carried baseline, or a confirmed unit has no baseline, the unit is moved
`confirmed -> deferred` with a reason and the baseline is cleared. The
confirmation is never silently kept; the unit becomes current work again. The
ledger is validated before and after the check.

### Severity (SR-07)

| Verdict | Claim | Recorded severity |
|---|---|---|
| `confirmed` | at or below the demonstrated impact | the claim, kept |
| `confirmed` | above the demonstrated impact | the demonstrated impact, with a reason |
| `rejected` or `needs_evidence` | any | `info`, with a reason |

`validate_severity` returns the severity; `severity_decision` returns the same
severity plus the optional reason, which is carried in
`CandidateVerification.severity_reason`. A downgrade is always recorded, never
silent. Only confirmed records may exceed `info`.

### Validation tests

The 10 `validate` tests cover the validation path:

| Test | Proves |
|---|---|
| `true_positive_is_confirmed_by_two_verifiers_and_keeps_its_severity` | two verifiers confirm the sink line; one `FND-1` finding, unit `confirmed`, severity kept, content fingerprint stored |
| `false_positive_is_rejected_and_refutes_the_unit_without_a_finding` | the cited line lacks the claimed sink; zero confirmations, candidate rejected, unit `refuted`, no finding (**Done criterion**) |
| `verifier_disagreement_defers_the_unit` | one confirm and one reject is `needs_evidence`/`deferred`, never a finding |
| `fewer_than_quorum_is_not_confirmed` | one confirmation under quorum two defers the unit |
| `a_verifier_sharing_the_hunter_label_is_refused` | a verifier labelled as the hunter refuses the pass before any mutation |
| `off_unit_or_missing_evidence_is_rejected` | an out-of-unit ref and a deleted cited file are both rejected |
| `fingerprint_is_stable_until_a_byte_changes_and_then_the_confirmation_is_deferred` | unchanged bytes keep the fingerprint; one byte edit invalidates the carried confirmation to `deferred` with a note |
| `severity_above_demonstrated_impact_is_reduced_with_a_reason` | `critical` over a `medium` impact becomes `medium` with a recorded reason; a lower claim is kept |
| `unconfirmed_severity_is_capped_at_info` | rejected and needs-evidence claims are forced to `info` with a reason |
| `duplicate_verifier_labels_are_refused` | two verifiers with one label are not independent |

## Sandbox execution (T-SR-05, SR-09, SR-10)

`zero_review::sandbox` is the only place target code may be handed to a
process. It supplies four things: an availability gate, a policy and plan, a
typed refusal path with a report, and per-agent scratch with trusted-parent
promotion. It does **not** implement the kernel calls that make the policy
true; that is the platform runner behind the `SandboxRunner` trait. The slice
therefore proves the gate, the policy, the escape checks, and the seam, not
that a real child was confined. See "OS-specific remainder" below.

### Availability: never run unconfined

`detect() -> SandboxAvailability` reports `Available { mechanism }` only when a
real mechanism is observed, and `Unavailable { reason }` otherwise.

| Platform | Probe | Mechanism name |
|---|---|---|
| Linux | `bwrap` on `PATH`, else `unshare` on `PATH` | `bubblewrap`, `unshare-namespaces` |
| macOS | `sandbox-exec` on `PATH` | `sandbox-exec` |
| Windows | create and close an unnamed job object (`CreateJobObjectW`) | `windows-job-object` |
| Other | no implementation | unavailable |

A probe that returns `Available` with a blank mechanism is downgraded to
`Unavailable`, so a misconfigured hook cannot claim confinement. `detect_with`
accepts an injected `SandboxProbe` for tests and embedders.

`Sandbox::new(policy)` returns `zero.fnd.unsupported` when detection is
unavailable. `Sandbox::with_availability` is the test/integration seam, but it
does not bypass the gate: `build_plan`, `execute`, and `execute_reported` re-check
the stored availability and refuse before resolving or calling the runner. In
the unavailable test the runner's call count stays zero.

### Policy and limits

`SandboxPolicy::new(target_root, scratch_root)` sets the secure defaults:

| Field | Default | Meaning |
|---|---|---|
| `target_root` | supplied | readable review target; canonicalized |
| `scratch_root` | supplied | the only writable tree; canonicalized |
| `env_allowlist` | `[]` | extra environment names; `PATH`, `HOME`, `LANG`, `TZ` are always baseline |
| `network` | `false` | network-shaped arguments are refused |
| `read_only_target` | `true` | carried into the plan for the runner |
| `limits` | `SandboxLimits::default()` | resource caps below |

The scratch root must not be the target root or contain it; a scratch inside
the target is allowed as an explicit carve-out. `env_allowlist` entries must be
non-empty and cannot contain `=` or NUL.

| Limit | Default | Enforced by |
|---|---|---|
| `timeout_ms` | 30,000 | the runner kills the child; `execute` records the timeout |
| `memory_mb` | 256 | the runner |
| `processes` | 8 | the runner |
| `file_bytes` | 8 MiB | `promote` before and during the copy |
| `output_bytes` | 1 MiB per stream | `execute` truncates stdout and stderr |

`output_bytes` is applied to stdout and stderr separately. Truncation prefers a
whole-line boundary and never splits a UTF-8 sequence. The caller cannot kill a
runner that ignores its budget because the trait deliberately exposes no child
handle: `execute_reported` measures wall time and marks `timed_out` when the
budget is exceeded, but a real runner must kill on expiry. A limit of zero is
`zero.fnd.invalid_input`.

### Command resolution and escape list

`Sandbox::build_plan(&SandboxCommand)` resolves the command or refuses it. A
refusal is `zero.pol.denied` and names the kind: `program`, `cwd`, `path`,
`network`, `env`, or `unavailable`. Every detected attempt is appended to
`SandboxReport.attempted` and `.blocked`; a refusal is never silent, and the
runner is not called when any denial exists. `execute_reported` returns the
result and the report together; `execute` returns only the result.

| Check | Rule |
|---|---|
| `program` | exists and is a regular file; not required to live under a root |
| `cwd` | no `..` component; must exist as a directory and canonicalize under the target or scratch |
| argument `..` | any `..` component is refused, even when it would resolve back inside |
| absolute argument | must canonicalize under the target or scratch; an absolute path elsewhere is refused |
| network argument | an argument containing `http://`, `https://`, or `git@` is refused when `network = false` |
| environment | only the baseline plus the allowlist, read from the parent; a secret-shaped allowlist name is refused |

The network check is a documented heuristic: it looks at argument text, not at
what the program actually does. The secret-name heuristic matches `key`,
`secret`, `token`, `passwd`, `password`, `credential`, `authorization`,
`bearer`, `cookie`, and `session` inside the variable **name** (never its
value). Names such as `OPENAI_API_KEY` and `GITHUB_TOKEN` are therefore refused
in an allowlist and never reach a plan. The refusal message names the variable,
never the value; URL arguments are not echoed because they can carry
credentials.

`SandboxPlan` carries the resolved `program`, `args`, canonical `cwd`, filtered
`env`, `limits`, `read_only_target`, `network`, `target_root`, and
`scratch_root`. It is handed to `SandboxRunner::run`. A runner must apply those
flags and limits with the detected mechanism, must not widen them, and must
return an error rather than run unconfined. `SandboxOutput` carries the exit
code, captured streams, the runner's `timed_out` flag, and the truncation flags.

### Scratch and promotion (SR-10)

`Scratch::create(root, agent_id)` makes or reuses `root/<agent_id>`. Agent ids
are limited to ASCII letters, digits, `.`, `_`, and `-`, and `.`/`..` are
refused, so an id cannot climb out of the root. An existing agent directory that
is a symlink or another reparse point is refused. Two agents therefore have two
distinct canonical directories, and one agent's `promote` cannot read the
other's files.

`Scratch::promote(source, dest, limits)` is trusted-parent code. It refuses, as
`zero.pol.denied` naming the kind:

| Check | Kind |
|---|---|
| `..` in the source or destination | `path` |
| source outside the agent's canonical scratch | `path` |
| source is a symlink or, on Windows, another reparse point (junction) | `symlink` |
| source is not a regular file, or changes type | `type` |
| source exceeds `max_bytes`, including growth during the copy | `size` |
| destination exists | `overwrite` |
| destination parent is missing, not a directory, or a symlink/reparse point | `parent` |
| destination parent canonicalizes outside the promotion root | `path` |

The copy uses `create_new` (no overwrite), writes to the canonical parent, and
removes a partial file if the copy fails. `PromotedFile { agent_id, source,
dest, bytes }` reports only paths and size; file contents are never part of a
report or a serialized result. The copy re-reads at most `max_bytes + 1` and
fails closed if the source grows, but promotion is not an atomic snapshot
against a concurrent writer.

### OS-specific remainder

The following are **not** implemented in this slice and remain the runner's
responsibility:

- mounting or marking the target read-only and making scratch the only writable
  tree;
- creating the network namespace, seccomp/landlock policy, or Windows job
  limits that the availability mechanism names;
- killing the child at `timeout_ms` and enforcing the memory and process caps;
- intercepting writes a program performs directly, which argv policy cannot
  see;
- argument shapes the heuristic does not model, such as a URL embedded in a
  flag (`--url=https://…`), a program that opens the network itself, or a
  relative path resolved by a child against a different directory.

The Windows probe proves that the job-object API can be created; it does not
assign a child or set a limit. On Windows, `detect()` reports
`windows-job-object` when the probe succeeds. A real Zero runner must use that
job object, or an AppContainer profile, to enforce the plan.

### Sandbox tests

The 13 `sandbox` tests cover the slice:

| Test | Proves |
|---|---|
| `an_unavailable_mechanism_refuses_execution_without_invoking_the_runner` | `Sandbox::new` is `zero.fnd.unsupported`; `build_plan` and `execute_reported` refuse, the report says `unavailable`, and the runner is never called (**Done criterion**) |
| `detection_is_honest_about_the_platform` | `detect()` returns a named mechanism or a non-empty reason, never a blank claim |
| `a_probe_must_name_a_mechanism_to_claim_availability` | a blank mechanism is downgraded to unavailable |
| `the_plan_env_is_filtered_to_the_allowlist_and_never_carries_secrets` | a parent `OPENAI_API_KEY` is absent; the allowlisted benign value is present |
| `a_secret_shaped_env_name_in_the_allowlist_is_refused_and_reported` | `OPENAI_API_KEY` in the allowlist is a typed `env` refusal with a report entry |
| `escape_attempts_are_refused_and_reported` | `../outside` cwd, an absolute path outside the roots, an argument `..`, and a network URL are each refused and reported; the runner is not called |
| `a_clean_command_inside_scratch_runs_with_a_read_only_target_plan` | a clean scratch command reaches the scripted runner; the plan carries `read_only_target = true`, `network = false`, canonical cwd, limits, and roots |
| `output_and_time_limits_are_capped_and_reported` | stdout is cut at 16 bytes, truncation is reported, an over-budget elapsed time marks `timed_out`, and the plan carries both limits |
| `a_regular_file_in_the_scratch_promotes_without_contents_in_the_report` | a regular scratch file is copied once; the serialized result has paths and size but not the body |
| `promotion_refuses_paths_oversize_files_and_overwrites` | an outside source, `..`, an outside destination, an oversize file, and an existing destination are refused; the existing file is unchanged |
| `symlink_sources_and_symlink_destination_parents_are_refused` | a symlink source and a symlink destination parent are refused where the OS permits symlink creation; a Windows directory junction is refused as a reparse point |
| `two_agents_have_isolated_scratches` | one agent cannot promote another agent's file; the owner can |
| `agent_ids_cannot_escape_the_scratch_root` | empty, `.`, `..`, separators, and backslashes are refused as agent ids |

## Seeding rules

`seed(root)` walks the tree with the default `SeedLimits`; `seed_with_limits`
takes explicit bounds. The walk is deterministic: directory entries are sorted,
units are sorted by id, and refs and companions are sorted and deduplicated
before the fingerprint is computed.

1. **Bounds.** At most `max_files` (512) regular files, `max_depth` (8)
   directories, and `max_file_bytes` (256 KiB) read per file. Hitting the file
   cap or the depth cap stops the walk and adds a note to
   `summary.truncation` with `walk_truncated = true`. Files larger than the byte
   cap are scanned up to the cap and counted in `summary.files_size_capped`.
2. **Classification.** The root-relative path selects one surface:
   `network`, `parser`, `process`, `storage`, `filesystem`, `web`,
   `credentials`, or `library`. The subsystem is the file's parent directory
   (`src/net`), or `.` at the root.
3. **Markers.** Every line is lowercased and checked against the class marker
   table below. Each matching line becomes a canonical `path:line` ref.
4. **Units.** One unit per distinct `(surface, boundary, subsystem, attack
   class)`. Several files or marker lines with the same tuple merge into one
   unit with many refs.
5. **Companions.** `selected_companions` lists other scannable files in the
   same subsystem. `excluded_companions` lists files the walk rejected, each
   with a reason. An exclusion is attached to the units of its surface; any
   orphan is attached to the first unit, so an exclusion is never silently
   dropped. If there is no unit at all, the orphan count is reported in
   `summary.truncation`.
6. **Identity.** The fingerprint hashes the surface, boundary, subsystem, attack
   class, refs, starting paths, selected companions, and excluded
   `(path, reason)` pairs with length-prefixed fields and FNV-1a 64. Status,
   owner, reviewed paths, and summary are not part of identity.

### Attack-class marker families

| Class | Example markers |
|---|---|
| `command_injection` | `Command::new`, `std::process`, `subprocess.`, `child_process`, `os/exec`, `shell_exec`, `popen(`, `system(`, `execve(`, `spawn(` |
| `path_traversal` | `os.path.join`, `path.join`, `PathBuf`, `Path::new`, `fs::read`, `fs::write`, `File::open`, `File::create`, `readFileSync`, `shutil.`, `canonicalize(`, `../` |
| `ssrf_egress` | `reqwest`, `TcpStream`, `tokio::net`, `hyper::client`, `ureq`, `axios`, `fetch(`, `urllib`, `requests.get`, `httpx`, `http://`, `https://`, `net/http` |
| `unsafe_deserialization` | `from_str`, `serde_json`, `serde_yaml`, `pickle`, `yaml.load`, `unserialize`, `JSON.parse`, `ObjectInputStream`, `bincode`, `deserialize` |
| `injection` | `SELECT `, `INSERT INTO`, `UPDATE `, `DELETE FROM`, `WHERE `, `cursor.execute`, `.query(`, `db.execute`, `prepare(`, `sql!`, `raw_sql` |
| `credential_exposure` | `password`, `passwd`, `secret`, `api_key`, `apikey`, `access_token`, `private_key`, `credential`, `authorization`, `bearer ` |
| `memory_safety` | `unsafe `, `transmute`, `from_raw_parts`, `as *mut`, `as *const`, `mem::uninitialized`, `mem::zeroed`, `set_len(`, `get_unchecked` |
| `permission_issues` | `chmod`, `set_permissions`, `permissions::from_mode`, `chown`, `0o777`, `0o666`, `0o755`, `umask`, `setuid`, `setgid`, `setWritable` |

## Validation rules (SR-02)

`validate(&ledger)` must pass before `CoverageLedger::assign`. Every rejection
is a typed `zero.fnd.invalid_input` error that names the unit and the failed
invariant; file text is never included. `assign` validates first, then moves a
pending, deferred, or blocked unit to `assigned` through `advance` (so history is
recorded), or updates the owner of an already assigned unit, and refreshes the
status counts.

- The schema version must be `1`; an unknown numeric version is rejected.
- Unit ids are non-empty and unique.
- `surface`, `boundary`, `subsystem`, and `attack_class` are non-empty.
- `refs` is non-empty and every ref is a canonical path or requirement reference;
  duplicate refs inside one unit are rejected.
- `starting_paths` is non-empty and root-relative.
- `checks` is non-empty and has no empty entry.
- The fingerprint is exactly 16 lowercase hex characters.
- `assigned`, `reviewed`, `confirmed`, and `refuted` require an owner.
- `reviewed` and `confirmed` require at least one reviewed path.
- `out_of_scope` must not list reviewed paths and is never counted as covered.
- A non-empty `history` is chronological, chained, legal, noted where required,
  and its last `to` equals the unit status.
- Every excluded companion has a path and a non-empty reason.
- A path cannot be both selected/starting and excluded.
- No duplicate `(surface, boundary, subsystem, attack_class)`.
- Duplicate selected companions are rejected.
- Summary unit and status counts, distinct surface, boundary, subsystem, and
  attack-class counts must match the units.
- The number of attached exclusions may not exceed `files_excluded`; if it is
  smaller, `truncation` must explain the difference.
- `walk_truncated` must agree with a non-empty `truncation` list, and the walk
  bounds must be non-zero.

`CoverageLedger::from_json_str` parses and validates in one step;
`to_json_pretty` is the writer. `CoverageLedger::advance` appends a history event
and refreshes the counts; call `validate` afterwards for the ledger-wide rules.

## Profiles and partial runs (SR-13)

| Profile | Phases | Max units | Max agents | Max files |
|---|---|---|---|---|
| `quick` | `recon`, `coverage_hunt`, `validation`, `output` | 8 | 3 | 64 |
| `standard` (default) | the quick phases plus `record_verification` | 32 | 8 | 256 |
| `deep` | the standard phases | 128 | 16 | 1,024 |

`quick` merges record verification into the validation phase; `standard` and
`deep` run all five audit phases, with `deep` using per-subsystem units and
critic waves inside them. The caps are conservative limits for one run, not
targets.

`scope(profile, requested_units)` plans an explicitly scoped run. Any non-empty
request is always `partial: true`, because the ledger is the coverage claim and
a subset can never claim full coverage; the reason records the requested count.
Units are deduplicated in request order and trimmed to `max_units`; when the
budget trims them, the reason reports both the requested and kept counts. An
empty request is a full run with no known units and no partial claim.

`scope_all(profile, all_units)` plans a full run over every known unit. It is
complete unless the budget trims the unit list, in which case `partial: true`
and the reason reports both counts.

## Structured output (SR-06, SR-07)

`coverage-ledger.json` and `findings.json` are the two artifacts. Both are
schema-validated before use.

`validate_coverage_ledger_json(value, root)` deserializes the ledger, runs
`validate`, then runs `validate_refs`. With a root, every path reference must
exist as a regular file under it.

`findings.json` uses schema version `1` and the following record shape:

| Field | Rule |
|---|---|
| `id` | non-empty and unique in the artifact |
| `unit_id` | non-empty; with a ledger, it must name an existing unit |
| `title` | non-empty |
| `severity` | `info`, `low`, `medium`, `high`, or `critical` |
| `status` | `needs_validation`, `confirmed`, or `rejected` |
| `evidence_refs` | non-empty canonical refs, no duplicates |
| `confirmed` | must agree with `status == confirmed` |

Only a confirmed finding may carry a severity above `info` (SR-07).

`validate_findings_json(value)` checks the schema version, ids, titles, status
and severity rules, and evidence. `validate_findings_json_with_ledger(value,
ledger)` additionally rejects a finding whose `unit_id` is not in the ledger.
Unknown schema versions, duplicate finding ids, orphan units, status/confirmed
drift, unconfirmed severity above `info`, and empty or duplicate evidence are
`zero.fnd.invalid_input`; a malformed ref fails deserialization.

## Reports (SR-06, SR-14)

`report::derive(inputs, out_dir)` derives the report set from final records only:
a validated `CoverageLedger`, a validated `Findings`, a `BudgetReport`, the
`ReviewProfile`, a `run_id`, and `created_at_ms`. It writes five files:

| File | Contents |
|---|---|
| `REPORT.md` | summary counts, scope/profile/partial flag, confirmed findings (`id`, severity, title), coverage summary, coverage gaps, budget gaps, links to the other two Markdown files |
| `FINDINGS-DETAIL.md` | one section per confirmed finding: unit id, severity, canonical evidence refs, the unit's checks, and the unit's validation history |
| `NEEDS-VALIDATION.md` | every unit without a confirmed verdict and every unconfirmed finding, each with its recorded status and reason |
| `findings.json` | the canonical finding records, copied unchanged |
| `coverage-ledger.json` | the canonical coverage ledger, copied unchanged |

`REPORT.md` never contains proposal or fix text, and none of the files may
introduce a finding, unit, or status that is not in the records. Record text is
collapsed to one line before rendering, so a title or note cannot inject a
heading or list item.

### Derivation rules

The inputs are validated before `out_dir` is created, so a refused input writes
nothing:

- the ledger passes `validate` and `validate_refs` (paths are structural; no
  review root is consulted);
- the findings pass `validate_findings`, and every `unit_id` names a ledger unit;
- unit and finding ids are non-empty and report-safe (no whitespace, control
  characters, backticks, or pipes);
- `created_at_ms` is non-negative;
- `budget.incomplete` is true exactly when `reasons` is non-empty, and every
  reason is non-blank.

`REPORT.md` renders, in order: run id, creation time, profile, partial flag, the
links, summary counts, scope and profile caps, the coverage summary
(`reviewed`, `confirmed`, `assigned`, `pending`, `refuted`, `deferred`,
`blocked`, `out_of_scope`), coverage gaps, the budget block, and confirmed
findings. Coverage gaps are the `pending`, `assigned`, `deferred`, and `blocked`
units; walk truncation notes are appended when the seed hit a bound.

A run is reported as **partial** when any of these holds:

- the budget reports `incomplete` (each reason is printed);
- the ledger has more units than the profile's `max_units`;
- the seed walk was truncated (each truncation note is printed);
- used agents or used units exceed their reserved counts.

`FINDINGS-DETAIL.md` is confirmed-only. For each confirmed finding it prints the
finding id and title, the unit id, severity, status, every canonical evidence
ref, the unit's checks, and every `UnitEvent` in the unit's history (`from ->
to`, actor, note). It never prints an unconfirmed finding and never adds a claim
that is not in the record.

`NEEDS-VALIDATION.md` lists every unit whose status is not `confirmed` — the
four open statuses (`pending`, `assigned`, `deferred`, `blocked`) plus the
settled non-confirmed statuses (`reviewed`, `refuted`, `out_of_scope`) — and
every unconfirmed finding (`needs_validation` or `rejected`). The reason is the
latest non-empty history note, otherwise a fixed description of the recorded
status. Nothing in the ledger is silently dropped: the only omission is a unit
with a confirmed verdict, which is covered by `FINDINGS-DETAIL.md`.

Ordering is deterministic. Findings are sorted by id and units by id;
statuses are listed in a fixed order; the timestamp is derived from
`created_at_ms` (UTC, `YYYY-MM-DDTHH:MM:SS.mmmZ`) rather than the wall clock;
history times use the same formatter. Two runs over the same inputs produce
byte-identical files.

The JSON copies are written first, then read back from disk, parsed, and
re-validated, and the Markdown files are compared with what is on disk. Before
the output directory is created, `derive` also runs the consistency check over
the generated text, so it never publishes prose that disagrees with the records.
A mismatch is an error, not a warning.

### Consistency check

`report::consistency_report(&bundle)` parses the generated Markdown and compares
it with the JSON copies:

| Prose | Expected |
|---|---|
| `REPORT.md` finding bullets | exactly the confirmed findings, with matching severities |
| `REPORT.md` summary counts | units, findings, confirmed/unconfirmed findings, every status count, and coverage gaps |
| `FINDINGS-DETAIL.md` finding headings | exactly the confirmed findings, with matching unit and severity |
| `NEEDS-VALIDATION.md` findings section | exactly the unconfirmed findings, with matching status and severity |
| `NEEDS-VALIDATION.md` units section | every unit without a confirmed verdict, with matching status |

It returns `ConsistencyReport { report_ids, detail_ids,
needs_validation_ids, json_ids, ok, mismatches }`; `ok` is true only when the
sets, severities, statuses, and counts agree and each id appears at most once.
`report::assert_consistent(&bundle)` returns a typed
`zero.fnd.invalid_input` error that lists each mismatch. A found mismatch is
evidence of drift between records and prose, not a recovered report.

### Reporting limits

- The module only reports the records it is given. A confirmed unit with no
  confirmed finding is counted in coverage but has no detail section, because
  inventing a finding is forbidden.
- The partial flag is inferred from the budget, the profile unit cap, walk
  truncation, and over-budget counters; a scoped-run flag is not an input and
  cannot be recovered after the fact.
- Report-safe ids are a rendering requirement, not a schema requirement: an
  artifact with whitespace or markdown punctuation in an id is refused.
- Timestamps are UTC and derived. A history time above the `i64` millisecond
  range saturates rather than wrapping.
- The consistency check is structural, not semantic: it compares ids,
  severities, statuses, and counts, not whether a record's claim is true.
- Files are written sequentially. If the filesystem fails mid-set, the error
  names the failure but files already written are left in place.

## Fixture test evidence

`cargo test -p zero-review` runs 98 unit tests (29 ledger, 30 schema, 5 report,
11 hunt, 10 validate, 13 sandbox) with 0 ignored (the doc-test harness
contributes no cases), plus the 4 integration tests in
`tests/fixture_suite.rs`. The ledger fixture
repository has a JSON parser, a shell spawn, a file writer, a network client, a
secret-looking constant, a lock file, a generated directory, a binary asset, and
a README.

| Test | Proves |
|---|---|
| `fixture_repo_produces_a_valid_ledger` | the fixture seeds a ledger that validates; every unit starts `pending` with an empty owner and reviewed paths |
| `fixture_repo_detects_the_expected_boundaries_and_attack_classes` | `process-exec`, `filesystem-path`, `network-egress`, `untrusted-input`, and `credential-store` boundaries, with the matching attack classes and attached exclusions |
| `two_seeds_of_the_same_tree_are_identical` | identical ids and fingerprints across two seeds |
| `a_tree_over_the_file_cap_truncates_and_reports` | the file cap stops the walk and records `walk_truncated` plus a `file cap` note |
| `depth_cap_truncates_and_reports` | the depth cap stops the walk and records a `max depth` note |
| `guidance_is_the_default_and_never_hunts` | a plain question yields guidance with only `recon` and `output` |
| `an_unrequested_audit_narrows_to_guidance` | an audit without an explicit request cannot start hunting |
| `an_explicit_audit_runs_the_hunting_phases` | an explicit audit runs hunting and validation, without reports |
| `report_artifacts_select_the_full_path` | report artifacts select `full_report` including `report` |
| `a_full_report_request_without_artifacts_narrows_to_an_audit` | a full report without artifacts narrows to an audit |
| `duplicate_unit_id_is_rejected` | ids are unique |
| `empty_refs_are_rejected` | every unit keeps at least one canonical ref |
| `missing_exclusion_reason_is_rejected` | exclusions carry a reason |
| `the_same_path_cannot_be_selected_and_excluded` | selection and exclusion cannot overlap |
| `out_of_scope_is_never_counted_as_covered` | `out_of_scope` cannot list reviewed paths and adds nothing to `covered` |
| `assigned_unit_without_owner_is_rejected` | assignment requires an owner |
| `reviewed_unit_without_reviewed_paths_is_rejected` | `reviewed` requires reviewed paths |
| `summary_mismatch_is_rejected` | summary counts must match the units |
| `unknown_schema_version_is_rejected` | an unknown schema version fails closed |
| `duplicate_tuple_is_rejected` | the unit tuple is unique |
| `assignment_validates_first_and_names_the_unit` | `assign` validates before mutating |
| `assignment_sets_the_owner_and_updates_the_summary` | assignment updates the status counts |
| `json_round_trip_preserves_the_ledger` | the artifact round-trips through validation |
| `an_empty_tree_yields_an_empty_valid_ledger` | an empty target produces a valid empty ledger |
| `zero_limits_are_rejected` | zero walk bounds are refused |
| `a_non_directory_root_is_rejected` | a file root is refused |
| `relative_paths_are_root_relative_and_posix` | refs and companions never leak the absolute root |
| `fingerprint_is_a_stable_function_of_the_unit_fields` | identity ignores status but changes with refs |
| `ledger_paths_are_relative_to_the_requested_root` | subsystems are derived from the requested root |

The 30 `schema` tests cover the SR-02, SR-03, SR-06, and SR-13 extensions:

| Test | Proves |
|---|---|
| `canonical_refs_parse_paths_and_requirement_ids` | both forms parse, columns are kept, and leading zeroes normalize |
| `canonical_refs_reject_bad_forms` | absolute, drive, UNC, `..`, zero-line, trailing-separator, control-character, and malformed-requirement refs are refused |
| `canonical_refs_round_trip_through_json_strings` | refs serialize as strings and deserialize back through the parser |
| `duplicate_refs_within_a_unit_are_rejected` | duplicate text and canonical-equivalent refs fail |
| `the_same_ref_may_appear_in_different_units` | the duplicate rule is per unit, not per ledger |
| `path_refs_must_exist_as_files_under_the_root` | missing files, directories, and a missing root are rejected |
| `requirement_refs_do_not_need_files_and_root_is_optional` | requirement refs skip existence; `None` skips the filesystem |
| `the_transition_matrix_allows_the_lifecycle` | pending to assigned to reviewed to confirmed, with an owner adopted from the actor |
| `the_transition_matrix_rejects_illegal_steps` | skipping assignment and an empty actor are `zero.pol.denied` |
| `out_of_scope_deferred_and_blocked_require_a_note` | each note-only status refuses a missing or blank note |
| `back_to_pending_is_only_from_assigned_and_needs_a_note` | only assigned may reopen, and only with a note |
| `confirmed_can_defer_for_re_review_and_refuted_is_terminal` | a confirmed unit reopens only as `deferred` (SR-11); refuted leaves no legal step |
| `history_must_be_chronological` | a backwards `at_ms` fails validation and `advance` |
| `history_from_must_match_the_previous_to` | a broken chain is rejected even when the step itself is legal |
| `history_status_must_match_the_last_event` | the unit status must equal the final `to` |
| `history_rejects_illegal_or_noteless_recorded_steps` | recorded illegal, noteless, and anonymous events fail |
| `empty_history_is_allowed_for_adopted_units` | an adopted unit without history still validates |
| `ledger_validation_includes_history` | `validate` rejects a status that disagrees with the history |
| `assignment_records_history_and_stays_valid` | `assign` moves through `advance` and leaves a valid ledger |
| `profiles_scale_phase_sets_and_budgets` | quick merges verification; caps increase from quick to deep |
| `scoped_runs_are_always_partial` | any non-empty request is partial and the reason records its count |
| `budget_trimming_reports_counts_and_marks_runs_partial` | scoped and full runs trim to the cap and report both counts |
| `coverage_ledger_json_validates_schema_and_refs` | unknown versions, bad refs, and missing files are rejected |
| `coverage_ledger_json_defaults_missing_history` | an older artifact without `history` deserializes as empty |
| `findings_json_validates_the_record_shape` | a confirmed record with path and requirement evidence parses |
| `findings_json_rejects_duplicates_and_unknown_versions` | duplicate ids and unknown schema versions fail |
| `findings_json_rejects_orphan_units` | a `unit_id` absent from the ledger fails |
| `findings_json_rejects_unconfirmed_severity_and_status_drift` | only confirmed records exceed `info`, and `confirmed` matches `status` |
| `findings_json_rejects_empty_or_bad_evidence` | empty, malformed, and duplicate evidence refs fail |
| `ledger_with_history_round_trips` | the artifact preserves history through serialization and validation |

The 5 `report` tests cover the SR-06, SR-12, SR-13, and SR-14 reporting path:

| Test | Proves |
|---|---|
| `derive_writes_all_five_files_and_splits_confirmed_from_the_rest` | all five files exist; `REPORT.md` and `FINDINGS-DETAIL.md` contain only `FND-1`; `NEEDS-VALIDATION.md` carries `FND-2`, `FND-3`, and every non-confirmed unit with its status; the JSON copies validate; the consistency check is clean |
| `a_dropped_finding_id_is_reported_as_a_mismatch` | removing a finding id from `REPORT.md` makes `consistency_report` fail and `assert_consistent` return a typed error naming it |
| `invalid_inputs_are_refused_before_writing` | a bad ref, a duplicate finding, an unconfirmed severity above `info`, an orphan unit, a negative `created_at_ms`, and contradictory budget reasons are refused and no output directory is created |
| `budget_incomplete_and_a_partial_profile_are_reported` | an incomplete budget and the `quick` profile print the profile, `Partial: yes`, `Incomplete: yes`, and the reason |
| `two_runs_with_the_same_inputs_are_byte_identical` | every generated file is identical across two derivations of the same inputs |

The 11 `hunt` tests cover the SR-04 and SR-05 hunting path:

| Test | Proves |
|---|---|
| `a_planted_bug_is_found_by_its_unit` | the seeded `Command::new(user_input)` unit produces a confirmed `FND-1`; the ledger is `confirmed` with a three-step history; the report set derives from records alone |
| `a_candidate_without_a_lower_trust_principal_is_rejected` | the evidence bar names the candidate and `lower_trust_principal` |
| `a_candidate_with_off_unit_evidence_is_rejected` | a ref outside the unit's starting or reviewed paths fails on `evidence_refs` |
| `a_candidate_with_a_mismatched_boundary_is_rejected_and_both_are_named` | the boundary must match, and the message lists both sides |
| `a_critical_candidate_without_a_concrete_result_is_rejected` | severity cannot exceed demonstrated impact |
| `a_critic_reject_marks_the_unit_refuted` | `Reject` records `refuted` and keeps the reason |
| `a_critic_needs_evidence_defers_the_unit` | `NeedsEvidence` records `deferred` and lists it for `NEEDS-VALIDATION` |
| `an_agent_error_blocks_the_unit_without_failing_the_wave` | an agent failure blocks only its unit and the wave still returns |
| `the_budget_stops_before_exceeding_the_unit_cap` | a two-unit cap runs two of three units; the third is never assigned |
| `the_agent_cap_defers_units_instead_of_exceeding_the_cap` | the agent cap defers the remainder instead of borrowing another agent |
| `the_critic_must_not_be_the_hunter` | a shared critic/hunter label refuses the wave before any mutation |

`cargo clippy -p zero-review --all-targets -- -D warnings` is clean.

## Fixture suite (T-SR-07)

`tests/fixture_suite.rs` creates three repositories at runtime under a temporary
directory (a few hundred bytes each, no checked-in binaries) and runs the whole
pipeline over each one: seed, reference validation, a scripted hunting wave, an
independent validation wave, and a derived report. The point is the shape of the
run, not the fixtures' size: one confirmed run, one clean run, and one partial
run.

| Repo | Files | Seeded units | Outcome |
|---|---|---|---|
| `vulnerable` | `src/process/agent.rs` (`Command::new(user_input)`), `src/files/reader.rs` (`PathBuf::from(root).join(user_path)`), `src/auth/mod.rs` (hardcoded `API_KEY`), `src/lib.rs` | `command_injection`, `path_traversal`, `credential_exposure` | 3 confirmed findings |
| `clean` | the same three shapes with an allowlist, `canonicalize()` plus a root check, and `std::env::var("ZERO_API_KEY")` | the same three markers | 0 findings, 3 refuted units |
| `partial` | the vulnerable files plus `vendor/airflow_exec.rs` and `generated/bindings.rs` | the three units; `src/files` is trimmed by the unit budget and `src/auth` is blocked by an agent error | 1 confirmed, 1 pending, 1 blocked, `partial: true` |

The walk excludes `vendor/` and `generated/` and records both exclusions on the
first unit of the ledger, so the excluded payload is evidence rather than a
silent omission.

### Pipeline

1. `ledger::seed` builds the ledger; `ledger::validate` and
   `schema::validate_refs(units, Some(root))` must pass before anything is
   assigned.
2. `HuntWave` runs one scripted agent with the unit ids in request order. The
   vulnerable and partial repos return the expected candidates; the clean repo
   returns none. The partial wave caps itself at two units.
3. The critic re-reads every cited line and rejects a candidate that does not
   show the expected sink. An evidence-backed candidate is forwarded with
   `NeedsEvidence` rather than `Accept`: a hunt-stage `Accept` confirms the unit
   and `ValidationWave` refuses confirmed units, so forwarding is what lets the
   independent verifiers record the finding. The critic still gates on evidence;
   it never forwards an unsupported candidate.
4. `ValidationWave::new(2)` asks two `EvidenceVerifier`s (labels `verifier-one`
   and `verifier-two`) that use `LineMatcher::Custom` to require the sink text on
   a cited line (`Command::new`, `PathBuf::from`, or `API_KEY`). Quorum is two.
5. `report::derive` writes the five artifacts into a temporary out directory and
   runs the consistency check.

### Golden projection

Each run has a stable projection under
`crates/zero-review/tests/fixtures/golden/{vulnerable,clean,partial}.json`.
The projection contains only fields that must not drift:

| Field | Meaning |
|---|---|
| `ledger_schema_version`, `findings_schema_version` | artifact versions |
| `units`, `findings` | totals |
| `status_counts` | one count for every `UnitStatus`, zeroes included |
| `confirmed_findings` | confirmed id, unit id, title, and severity, sorted by id |
| `rejected_candidates` | candidates the evidence bar, critic, or verifiers refused |
| `deferred_units`, `blocked_units` | final ledger counts |
| `partial` | the derived report's partial flag |
| `coverage_gap_unit_ids` | pending, assigned, deferred, and blocked unit ids |
| `needs_validation_unit_ids` | every unit without a confirmed verdict |

Timestamps, absolute paths, the run id, budget numbers, and history notes are
deliberately absent, so the golden is identical on Windows and Linux checkouts.
The comparison normalises `\r\n` to `\n`. A mismatch fails the test and names
the file to update. Goldens are never rewritten implicitly:

```powershell
$env:UPDATE_REVIEW_GOLDEN='1'; cargo test -p zero-review --test fixture_suite
```

Unset the variable (or set it to anything else) to run the comparison.

### Assertions

- **Vulnerable.** Exactly the three expected findings are confirmed, each on its
  own unit, with severity at or below the demonstrated impact (`high`, `high`,
  `medium`). Every unit records a content fingerprint and the report is not
  partial.
- **Clean.** Zero findings and zero confirmed units. All three units are refuted
  by the hunt pass, the `Confirmed findings` section says `None`, and no
  coverage gap is produced. This is the false-positive gate.
- **Partial.** The report is `partial: true` and prints the budget reason. The
  trimmed `src/files` unit is still `pending` and the failed `src/auth` unit is
  `blocked`; both appear in `NEEDS-VALIDATION.md` and in the projection's
  coverage-gap list, and the report's budget block names the trim reason. The
  excluded vendor and generated files are recorded as exclusions.

### Re-verification (SR-11)

`a_carried_confirmation_is_reverified_and_deferred_when_the_target_changes`
confirms the vulnerable repo, proves the fingerprints are stable on an untouched
target, appends a comment to `src/process/agent.rs`, and reruns
`check_fingerprints`. The unit moves `confirmed -> deferred` with the
`fingerprint-check` actor and a `re-review` note, the content baseline is
cleared, and the next report lists the unit and its invalidated finding in
`NEEDS-VALIDATION.md` instead of `REPORT.md`. The carried finding is re-recorded
as `needs_validation` and capped at `info` (SR-07).

### Evidence

| Test | Proves |
|---|---|
| `vulnerable_repo_confirms_only_the_demonstrated_findings` | 3 seeded units, 3 candidates, 3 confirmed findings with the expected ids and severity bounds |
| `clean_repo_confirms_nothing_and_raises_no_false_positive` | 0 findings, 3 refuted units, no coverage gap |
| `partial_run_is_marked_partial_and_lists_the_unreviewed_units` | `partial: true`, the budget reason printed, pending and blocked units in `NEEDS-VALIDATION.md`, vendor/generated exclusions recorded |
| `a_carried_confirmation_is_reverified_and_deferred_when_the_target_changes` | a changed target defers the carried confirmation and the next report treats it as current work |

`cargo clippy -p zero-review --all-targets -- -D warnings` is clean.

### Golden limits

The projection is a regression gate, not a full transcript. It does not compare
the prose of the three Markdown files, the history events, the budget numbers,
or the exclusion reasons; the `report` and `validate` unit tests cover those. It
also cannot detect a change that leaves every projected field identical (for
example a reworded history note). Unit ids are hash-derived from fixture
content, so changing a fixture file's bytes intentionally rewrites the ids and
requires a golden update.

## Heuristic limits

The seed is a checklist generator, not a vulnerability scanner. Markers are
substring heuristics over source and configuration extensions; they can both
miss obfuscated code and flag comments, documentation, or generated-looking
strings. Marker hits are evidence to review, never findings, and a unit is only
covered when a reviewer fills in reviewed paths and a verdict. The walk skips
symlinks, vendor/build directories, lock files, binaries, and non-source files;
each is recorded as an exclusion when a unit exists to carry it. Files larger
than the byte cap are scanned only up to the cap and counted, and refs and
companions are capped per unit. A scan over those bounds reports truncation
instead of silently widening coverage.

## Zero integration (T-SR-08, SR-08, SR-15, SR-16)

`zero-agent::audit` is the one bridge from a security review to Zero's task
system. It writes only local files and creates only local tasks; there is no
network client on this path by construction (the unit test scans the module
source for network APIs). The target tree is only read: refs are canonicalized
and must resolve to files inside the root, and every write lands under
`.zero/` (SR-08).

### Run layout

A run is a directory under the project:

```
.zero/audits/run-N/
  coverage-ledger.json
  findings.json
  REPORT.md
  FINDINGS-DETAIL.md
  NEEDS-VALIDATION.md
```

`start_audit(project_root, ledger, findings, budget, now_ms)` derives the set
with `zero_review::report::derive` into a hidden staging directory, re-reads the
copies with `validate_coverage_ledger_json(root)` and
`validate_findings_json_with_ledger`, calls `assert_consistent`, and only then
renames staging to `run-N`. A run that fails validation leaves no run
directory.

The project root must contain `.zero/`, and `.zero` must resolve inside the
canonical root. `.zero/audits` is created when missing; an existing audits path
that is a symlink or resolves outside `.zero` is refused with
`zero.pol.denied`. Run numbers come from a bounded scan of directory entries
named `run-<digits>` only; `run-evil`, `run-../x`, and plain files are ignored.
The next number is one past the highest.

### Task mapping

Each ledger unit becomes exactly one zero-tasks task. The store is
`.zero/tasks.jsonl`, shared with the panel (`open_project_task_store`). The task
title is the single text field zero-tasks exposes, so it carries every fact the
panel renders:

```
AUDIT :: run=run-1 :: unit=unit-1 :: fp=0000000000000001
      :: surface=process :: boundary=process-exec
      :: subsystem=src/shell.rs :: class=command_injection
      :: status=pending :: refs=["src/shell.rs:1"]
```

`task_metadata` parses that back into `TaskMetadata` (run, unit id, fingerprint,
surface, boundary, subsystem, attack class, refs, status). The task store has no
`pending` state, so a fresh task is `queued`, which is the pending state; the
metadata keeps the review vocabulary.

Tasks are seeded with `TaskStore::seed_plan`, using the run id as the plan id.
That groups the run in the existing store without a schema change.

### Idempotency

`seed_audit_tasks(store, run_id, units, now_ms)` is idempotent on the run id:
`seed_plan` returns the existing task ids and writes nothing on a second call.
Unit ids are unique inside a validated ledger and are the plan keys, so a unit
cannot be duplicated within its run. A new audit always claims a new run number
(`run-2`, `run-3`, …), so re-running the audit produces a fresh run directory
and a fresh task set rather than rewriting the prior run; no `(run, unit)` pair
is ever duplicated.

### Panel lookup

- `audit_tasks(store, run_id)` — the run's tasks in creation order.
- `panel_entries(store, run_id)` — rows with task id, state, and parsed metadata.
- `panel_task_for_unit(store, run_id, unit_id)` — one unit's task.

A run appears on the panel when `audit_tasks` returns its units; the Done
criterion for T-SR-08 is the test that reopens the store after
`start_audit` and finds all three unit tasks with the run id.

### Immutable bar (SR-16)

No project input can relax a run. `check_profile(caller, project)` refuses a
project request that:

- picks a profile shallower than the caller's (`quick` below `standard`),
- omits any phase the caller's profile runs,
- lowers `min_evidence_refs` below the SR-05 bar (one canonical ref).

A stronger request is accepted but never applied: the returned
`EffectiveProfile` always carries the caller's profile, phases, and evidence
bar, and lists what was ignored. `start_audit` uses `standard`; the explicit
variant is `start_audit_with_profile`. A project file at
`.zero/audit-profile.json` is read only to be checked:

```json
{ "profile": "quick", "phases": ["recon", "output"], "min_evidence_refs": 0 }
```

The example is refused with `zero.pol.denied` before any directory or task is
created. Malformed JSON is refused with `zero.fnd.config_invalid`.

### Tests

`cargo test -p zero-agent audit` runs the module tests:

| Test | Proves |
|---|---|
| `a_valid_ledger_creates_run_one_with_the_report_set_and_three_tasks` | five files, disk copies validate, 3 tasks, panel rows carry unit/fingerprint/refs, Done criterion |
| `re_running_is_idempotent_for_tasks_and_picks_run_two` | same run returns the same ids; a second audit is `run-2`; 6 tasks and no duplicate `(run, unit)` |
| `an_invalid_ledger_is_refused_before_any_directory_is_created` | ledger validation precedes writes |
| `invalid_findings_are_refused_before_any_directory_is_created` | findings validation precedes writes |
| `a_root_without_zero_is_not_a_project_root` | no root marker, no run |
| `a_symlinked_audits_directory_that_escapes_is_refused` | junction/symlink escape is `zero.pol.denied` |
| `only_numeric_run_directories_are_counted` | bounded numeric numbering ignores traversal-shaped and non-directory entries |
| `a_project_profile_cannot_lower_the_bar_or_skip_phases` | SR-16 refusal for profile, phases, and bar |
| `a_stronger_project_profile_is_ignored_and_the_caller_wins` | stronger config is ignored; caller profile is effective |
| `an_invalid_project_profile_is_refused_before_any_directory_is_created` | malformed config is refused early |
| `the_audit_path_is_offline_by_construction` | the module names no network API |

### Known limits

- A task has one text field. The title carries the complete mapping, so a
  consumer that truncates titles loses the metadata tail. There is no separate
  `description` or metadata column in `zero-tasks` today.
- If task seeding fails after the report directory was published, the run stays
  on disk without panel rows. The error is returned; the report set is left for
  inspection rather than deleted.
- The run-number scan is bounded at `MAX_RUN_SCAN` entries. A directory beyond
  that bound reports `zero.fnd.limit_exceeded` instead of scanning forever.

