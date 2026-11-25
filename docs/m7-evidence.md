# M7 evidence

M7 covers Halcyon, the model pool, usage accounting, and auto-resume. The
slices below are implemented; the rest of the milestone is open.

## Halcyon discovery and trust — T-HAL-01 (done)

`zero-halcyon` discovers `.halcyon-mode` by distance from the working directory:
the directory itself (distance 0), then immediate child directories and the
parent (distance 1), then ancestors (2..n), stopping at home. A symlinked mode
file or any symlinked directory in the walk is refused (Windows junctions via
the reparse-point attribute), non-regular files and unreadable children fail
closed with typed errors, and link-like child directories are never followed.
Nearest wins; two candidates at the same distance (child vs parent, or two
children) produce `Discovery::Conflict` and `Activation::Disabled` with a
reason. Discovery never reads content before the trust gate: an untrusted
workspace is `Inert` even with a valid file, and trust is exact-root,
non-inheriting.

| Test | Evidence |
|---|---|
| Distances | Working directory beats child+ancestor; child found; ancestor walk stops at home. |
| Conflicts | Two children conflict; child vs parent conflict (same distance); no silent pick. |
| Links | Symlinked mode file refused; symlinked child not followed; Windows junction refused. |
| Trust | Untrusted child stays inert; absent everywhere is disabled. |

Commands: `cargo test -p zero-halcyon` (24 Windows tests, 27 per platform;
3 Unix-only skip on Windows), `cargo clippy -p zero-halcyon --all-targets -- -D
warnings`.

## Halcyon todo sync — T-HAL-07 (done)

`zero-halcyon` now syncs todos with `tkb` in both directions (HAL-07, HAL-11).
The flag gate returns `Disabled` without touching the backend. Sync pulls remote
changes and merges by id/version, pushes pending ops idempotently (applied ids
are filtered, empty batches are not sent, the backend also dedupes op ids), and
queues ops when the backend is offline without advancing `last_sync_ms`. A
conflict is detected when both sides changed or a stale base version is pushed:
the local side is kept and a visible `TodoConflict` appears as a panel item,
freezing that todo so a re-pull cannot silently adopt remote. Resolution can
keep local, take remote, or merge (local title, furthest status) with a new
version. State is atomically saved with bounds (pending 256, conflicts 64,
todos 4096) and typed corrupt/schema/limit errors.

| Test area | Evidence |
|---|---|
| Done criterion | A conflict between local and remote surfaces as a conflict item. |
| Sync | 16 tests: two-way create/update/complete, idempotent repeat, offline queue flush order. |
| Safety | Stale base version conflicts, not overwrites; disabled flag makes zero backend calls. |

Commands: `cargo test -p zero-halcyon` (114 tests), `cargo clippy -p
zero-halcyon --all-targets -- -D warnings`. The trait is the seam; no `tkb`
process is spawned in this slice.

## Halcyon flags — T-HAL-06 (done)

`zero-halcyon` gates exactly four flags (HAL-10): `halcyon.mode`,
`halcyon.todo_sync`, `halcyon.joker`, and `halcyon.epb`. Parsing accepts only
boolean values for those keys, ignores unknown keys (reported), and rejects a
wrong-typed known key as `config_invalid`. Resolution has a global layer and an
optional project layer: the project may only turn a flag **off**; a project
`true` where global is `false` is ignored and recorded as rejected, never
raising the effective set. A project layer is a complete snapshot (omitted keys
are false). A flag never activates Halcyon by itself — discovery and signature
verification remain the gate.

| Test area | Evidence |
|---|---|
| Done criterion | A project `true` with global `false` stays disabled and is reported as rejected. |
| Coverage | 15 flag tests: exactly four keys, unknown ignored, wrong type rejected, global enables, project disables. |
| Gating | Flags do not bypass discovery/verification. |

Commands: `cargo test -p zero-halcyon` (98 tests), `cargo clippy -p
zero-halcyon --all-targets -- -D warnings`.

## Halcyon behaviour rules — T-HAL-05 (done)

`zero-halcyon` now records and enforces the Halcyon run contract (HAL-05,
HAL-08, HAL-09). A run records `tkb check` results, gaps (info/warn/high, with
resolve and info-only waive), a handover, gates, and endpoints. Gates are
accepted only through `joker` and endpoints only through `epb`; a `Direct`
route is refused with `zero.pol.denied` and appended to the record so an
ignored error still fails completion. `can_finish` refuses without a `tkb
check`, after a failed check with no later success, with an unresolved blocking
gap, without a handover, or with a recorded direct-route violation; `finish`
is idempotent and locks evidence recording afterwards. The Done criterion is
`a_run_without_a_tkb_check_is_refused`.

| Test area | Evidence |
|---|---|
| Done criterion | No `tkb check` -> refused with `zero.pol.denied` (not an approvable ask). |
| Checks/gaps | Failed then successful check allowed; unresolved high gap refused; info waiver only. |
| Routing | Direct gate/endpoint refused and recorded; joker/epb routes accepted. |
| Handover | Missing/malformed refused; post-finish amendment refused; finish idempotent. |

Commands: `cargo test -p zero-halcyon` (83 tests), `cargo clippy -p
zero-halcyon --all-targets -- -D warnings`. Check history is single-valued;
recording a joker route is evidence, not proof a binary ran.

## Halcyon adapters — T-HAL-04 (done)

`zero-halcyon` detects the Halcyon runtimes (HAL-04, HAL-07, HAL-13). Each of
`tkb`, `joker`, and `epb` has a binary name, package text, and minimum version
(1.0.0). Detection searches the injected/process `PATH` (with `PATHEXT` on
Windows), never executes the candidate, and probes `--version` through an
injectable seam with a 2 s timeout and 4 KiB caps. Compatibility distinguishes
compatible, too-old, unparseable, and probe-error states; a missing binary is
not an error — it returns the adapter with install guidance naming the binary,
package, `PATH`, minimum, and `--version` check. Detected paths are not
canonicalised; a `.cmd` probe on Windows produces guidance instead of a false
positive.

| Test area | Evidence |
|---|---|
| Done criterion | `a_missing_binary_shows_install_guidance`; every adapter's guidance names its binary and minimum. |
| Negotiation | 13 adapter tests: compatible, too old, unparseable, probe error, PATH order, PATHEXT (Windows). |
| Seam | Scripted probe records calls; no installer/download/shell is executed. |

Commands: `cargo test -p zero-halcyon` (68 tests), `cargo clippy -p zero-halcyon
--all-targets -- -D warnings`. Per-feature degradation below the floor is left
to T-HAL-05/07 consumers.

## Halcyon key tooling — T-HAL-03 (done)

`zero-halcyon` now owns keygen, sign, pin, rotate, revoke, and verify with a
user-only actor gate (HAL-03, HAL-04). Every mutating/signing API takes an
`Actor`; `Agent` is denied for keygen/sign/pin/unpin/rotate/revoke/un-revoke and
allowed only to verify. Private keys are sealed with Argon2id + AES-256-GCM
(random salt/nonce, key id as AEAD associated data, bounded envelope); wrong
passphrase or tampering fails as `zero.tru.tamper`. Key ids are BLAKE3 of the
public key. Rotation pins the new key, unpins the old, and records the
`{from,to}`; documents signed by the old key fail unless explicitly re-pinned.
Revocation is permanent for the id until an explicit user un-revoke, and
verification checks revocation before pin lookup. No plaintext key is written to
disk, and private scalars never appear in Debug, errors, pin files, envelopes,
or signed documents.

| Test area | Evidence |
|---|---|
| Done criterion | A test drives keygen/sign/pin/rotate/revoke as `Agent` and asserts five denials; verification is allowed. |
| Sealing | Wrong passphrase, tampered key id/ciphertext, oversized envelope -> `zero.tru.tamper`/typed errors. |
| Rotation/revocation | New key verifies after rotation; old fails unless re-pinned; revoked id denied; un-revoke restores. |
| Persistence | 11 key tests: pin file round-trip, atomic save, duplicate/invalid pins refused; private scalar never on disk. |

Commands: `cargo test -p zero-halcyon` (55 tests; 58 per platform), `cargo
clippy -p zero-halcyon --all-targets -- -D warnings`. Passkey fallback and
OS-store/hardware keys are later tasks; rotation records carry no timestamp.

## Cost audit — T-USG-03 (done)

`zero-sched` now analyzes spend and proposes bounded, evidence-backed changes
(USG-05, SI-10). `audit` produces totals, per-model/provider/session spend,
retry and cache ratios, top spenders, findings (high retries, low cache reads,
expensive-and-slow model, over-budget session, provider concentration), and at
most five proposals with aggregate evidence, computed savings capped at observed
spend, stable BLAKE3 ids, and no raw payloads. `AuditMode` defaults to
`DryRun`; only `Apply` mutates state, and only through bounded `CostChange`
values (retry cap, cache flag, model disallowed, session budget). High-risk
proposals need explicit confirmations, already-satisfied changes skip,
`SplitSession` stays manual, and `rollback` validates then reverses applied
changes.

| Test area | Evidence |
|---|---|
| Done criterion | Dry-run changes nothing; only `Apply` mutates; high-risk without confirmation skipped. |
| Proposals | 13 audit tests: evidence bar, savings caps, dedupe/order, proposal cap. |
| Rollback | Applied changes reverse in order; stale/dry-run reports refused without mutation. |
| Secrecy | Planted tool secret never appears in findings/evidence/errors. |

Commands: `cargo test -p zero-sched cost_audit` (13 tests), `cargo clippy
-p zero-sched --all-targets -- -D warnings`. Cache/retry savings are transparent
proxies; a session stop line is caller-supplied; the unsupervised loop is not
orchestrated here.

## Cost budgets and dashboards — T-USG-02 (done)

`zero-sched` now enforces warn/stop budgets across overlapping scopes (USG-02..04,
USG-06). `preflight` evaluates the projected spend against Global, Project,
Device, and the current Day, always including Global and today's Day when they
have limits; thresholds are inclusive (`>= stop` refuses, one micro below
allows), Stop wins over Warn independent of context order, and ties break
deterministically (`Global < Project < Device < Day`). Day is an epoch day with
floor division, so other days never affect today. The dashboard renders the same
numbers for TUI/desktop/Android snapshots with deterministic scope order, top
models/providers (cost-desc, name-asc, capped), and `Ok/Warn/Stop` states; CSV/
JSON exports are strings only, no telemetry.

| Test area | Evidence |
|---|---|
| Done criterion | A stop budget returns `Stop` and the caller must not dispatch. |
| Precedence | Overlapping scopes, stop-vs-warn, furthest-over-limit, exact boundary, day rollover. |
| Surfaces | All three surface snapshots agree on the stop/warn state. |
| Export | 11 tests: stable CSV/JSON with escaping; empty ledger. |

Commands: `cargo test -p zero-sched cost_budget` (11 tests), `cargo clippy
-p zero-sched --all-targets -- -D warnings`. State is in-memory (ledger remains
durable); Project budgets require explicit project records.

## Halcyon signature verification — T-HAL-02 (done)

`zero-halcyon` verifies an Ed25519 signature over a Zero-specific canonical
encoding of the mode document (domain prefix, little-endian version/times,
length-prefixed sorted flags and identifiers; signature excluded). The pin set
comes only from user configuration, with duplicate/malformed/non-32-byte keys
refused. Verification checks the exact key id (no fallback), the signature with
`verify_strict`, the project binding, and issuance/expiry with an optional skew
(default 0, capped at 1 h); a copied repo has a new project id, so even a valid
signature fails. `activation_verified` orders absent/conflict → Disabled,
untrusted → Inert (no read), trusted → bounded read/parse/verify → Enabled;
`VerifiedMode` has private fields so it cannot be forged.

| Test area | Evidence |
|---|---|
| Done criterion | `a_copied_repository_needs_its_own_signed_file`; `activation_enables_only_after_signature_binding_and_expiry_pass`. |
| Integrity | 20 verification tests: tampered bytes, wrong/unknown key, expired/future, malformed pin/signature/document. |
| Canonical | Byte-for-byte known-answer test; stable across flag order; ASCII/field bounds. |

Commands: `cargo test -p zero-halcyon` (44 tests; 47 per platform), `cargo
clippy -p zero-halcyon --all-targets -- -D warnings`. `ed25519-dalek` 2.2
(edition 2021, reuses `sha2 0.10`); signing exists only under `#[cfg(test)]`
until T-HAL-03.

## Usage ledger — T-USG-01 (done)

`zero-sched` now has an append-only per-device usage ledger (USG-01, USG-02,
USG-08). `UsageEvent` records session/device/model/provider/tool, input/output,
cache read/write, cost, wall time, retries, parent id, and subagent share, with
a stable BLAKE3 id over the immutable fields. The store appends one JSON object
per line, fsyncs, enforces 0600 on Unix, skips a malformed line with a count,
flags a torn tail, and rejects a non-JSONL/corrupt file. `merge` unions devices
by id, records identical duplicates, keeps the first payload on an id conflict,
lists unresolved parents (a sync may deliver a child first), and sorts by
`(at_ms, device, id)`; re-merging files is byte-identical. Attribution rolls
descendants into `subagent` transitively, rejects cycles/self-parents, and
computes share in basis points. Totals aggregate by session/model/provider/
device; CSV/JSON export is available without telemetry.

| Test area | Evidence |
|---|---|
| Done criterion | Two devices' events for one session merge with 0 conflicts and matching totals; re-merge is byte-identical. |
| Integrity | Malformed line counted, torn tail flagged, corrupt/non-JSONL typed; duplicate vs conflicting id. |
| Attribution | Transitive roll-up, orphan error, cycle rejection, share bounds. |
| Export | 17 ledger tests; CSV escaping and JSON shapes. |

Commands: `cargo test -p zero-sched usage_ledger` (17 tests), `cargo clippy
-p zero-sched --all-targets -- -D warnings`. Merge does not hard-fail on an
unresolved parent by design; `validate_parents()` is the strict gate.

## Transcript translation — T-MDL-05 (done)

`zero-model` now translates transcripts across provider formats (MDL-05,
MDL-13). A canonical transcript of text/tool-use/tool-result/image/thinking/
system blocks is validated (unique tool ids, every result paired to a preceding
use, bounded content). `translate` maps to/from OpenAI, Anthropic, and Gemini
wire shapes while preserving tool-use/tool-result pairing; ids are remapped
consistently where a provider requires it and recorded in
`TranslationReport::mapped_id`. Non-portable blocks are dropped with a kind and
reason, never silently, and invalid pairing is a protocol error.
`translate_for_escalation` preserves in-flight tool calls across a model switch,
and round-trips are stable. Provider wire `render` is included for adapters.

| Test area | Evidence |
|---|---|
| Done criterion | `escalation_mid_task_keeps_paired_tool_ids_valid`; a pending call survives A→B→A and its future result re-validates. |
| Mapping | 21 tests: OpenAI/Anthropic/Gemini text/system/tools/results/images/thinking; ID remap; drops. |
| Validation | Duplicate ids, orphan results, oversized input refused; no prompt text in errors. |

Commands: `cargo test -p zero-model translation` (21 tests), `cargo clippy
-p zero-model --all-targets -- -D warnings`. Gemini is name-keyed; Anthropic
thinking signatures are not modelled (noted); wire-JSON parsing stays in the
adapters.

## Measured routing — T-MDL-07 (done)

`zero-model` now routes on measured outcomes (MDL-08, MDL-09). `Outcome`
records model/class/success/retries/latency/cost/time; `OutcomeLog` dedupes
content-derived ids and computes per-(model,class) statistics over a window
(success rate, averages, samples). `choose` falls back when every candidate has
fewer than `min_samples` (insufficient evidence), switches only when the best
candidate beats the incumbent by at least `min_improvement_bps`, and attaches the
winning stats as evidence; ties break on lower cost then latency, classes never
mix, and exploration is deterministic and never overrides a proven switch. A
measured candidate may replace an unmeasured fallback (documented asymmetry), but
an unmeasured model is never reported as a measured result. `reconcile` checks
predicted vs actual cost within a tolerance and `preflight_budget` refuses
before dispatch.

| Test area | Evidence |
|---|---|
| Done criterion | Insufficient samples -> fallback with "insufficient evidence"; a clear improvement switches with stats attached. |
| Evidence | 17 measured tests: threshold, regression, window, class separation, exploration, tie-break. |
| Cost | Reconciliation boundaries; budget `limit_exceeded`; no prompt text. |

Commands: `cargo test -p zero-model measured` (17 tests), `cargo clippy
-p zero-model --all-targets -- -D warnings`. No scheduler wiring yet; prediction
is passed at the call site.

## Model data freshness — T-MDL-08 (done)

`zero-model` now gates routing on model-data age (MDL-08, MDL-15). `ModelData`
records a schema/table version, a non-empty source, fetch time, and pool models
(unique ids, valid timestamps). `FreshnessPolicy` warns after `max_age_ms` and
refuses after `hard_expiry_ms` (inclusive boundaries, default 24 h/7 d); a
backwards clock clamps to fresh. `gate` returns the data with a warning naming
source and age when stale, and `zero.fnd.unavailable` when expired. `refresh`
records the new source/fetch time and produces a deterministic drift report
(added, removed, changed fields incl. availability/deprecation/cost/grades).
`route_fresh` applies the gate before the existing router and pushes the stale
warning into `RouteDecision::warnings`, so a stale table warns instead of
routing silently (the Done criterion); expired data refuses.

| Test area | Evidence |
|---|---|
| Done criterion | `route_fresh_warns_on_a_stale_table_and_refuses_an_expired_one`. |
| Boundaries | 9 tests: exact max_age/hard expiry, +1 ms flips, invalid policy. |
| Drift | Added/removed/changed ordering; refresh records source/time. |

Commands: `cargo test -p zero-model freshness` (9 tests), `cargo clippy
-p zero-model --all-targets -- -D warnings`.

## Decision records — T-MDL-06 (done)

`zero-model` now records every turn (MDL-06, MDL-11). `TurnRecord` carries the
session/turn, model, version, provider, parameters (temperature/top_p/output/
reasoning effort), class/role, router reason, token and cache counts, estimated
and actual cost, and optional escalation evidence — with `deny_unknown_fields`
so a planted prompt field is not a record. The append-only JSONL log fsyncs,
enforces 0600 on Unix, bounds at 64 MiB, refuses duplicate `(session, turn_id)`
and appends to a damaged/torn log. `read_all` skips malformed lines with counts;
`reconstruct` is strict, returns every turn in order with totals and sequence
gaps, and refuses malformed/torn logs. `audit_line` and `compare_with_ledger`
support an audit that reconstructs each turn and detects cost/token mismatches.

| Test area | Evidence |
|---|---|
| Done criterion | `reconstruct` returns every recorded turn in order with model/version/params/reason/cost; gaps reported. |
| Integrity | 16 tests: duplicate turn, malformed/torn log, missing fields, parameter bounds, 0600 on Unix. |
| Audit | Ledger mismatch detection; escalation copied; no prompt content. |

Commands: `cargo test -p zero-model decision` (16 tests), `cargo clippy
-p zero-model --all-targets -- -D warnings`. Dedupe is per `(session, turn_id)`;
`append` is O(n) bounded by 64 MiB.

## Router and escalation — T-MDL-03 (done)

`zero-model` now routes to the cheapest eligible model above the class floor and
escalates with evidence (MDL-03/04, MDL-12, MDL-14). `Pool` validates unique
model ids, non-empty grades, and cost/grade consistency. Routing applies
availability, deprecation, floor, failure, allow/deny, and privacy-local
filters; a pin is honored only when eligible (below-floor pins are
`zero.pol.denied`), deprecated/unavailable pins reroute with a warning, and a
budget overrun is `zero.fnd.limit_exceeded` before dispatch. Deprecated models
are never selected silently. Escalation moves to the lowest eligible higher
tier, never retries the failed model, never downgrades, and returns `exhausted`
with the bounded evidence (kind/model/attempts/summary/cost, no prompt text).

| Test area | Evidence |
|---|---|
| Done criterion | A fails → B with evidence; B fails → C; no higher tier → exhausted with evidence; never re-selects A. |
| Eligibility | 12 router tests: floor, pin, allow/deny, privacy, deprecated warning, unavailable, budget. |
| Evidence | Bounded, control-stripped summaries; no prompt/transcript field. |

Commands: `cargo test -p zero-model router` (12 tests), `cargo clippy
-p zero-model --all-targets -- -D warnings`. Tier is the escalation axis;
same-tier models are alternatives only; direct `Pool` deserialization bypasses
validation (rebuild through `Pool::new`).

## Agent roles — T-MDL-04 (done)

`zero-model` now defines the six agent roles (MDL-04, MDL-07). Each role maps to
a work class (planner→plan, coder→edit, reviewer→review, tester→test,
researcher→research, vision→visual inspection) and has a seeded, configurable
default model/provider. `assign` resolves user pin → upgrade → role default →
fallback; a missing role is typed, an empty pin is ignored, and a fallback is
used when the default is unavailable or below the role floor. Pins and upgrades
are still checked against the classifier floor, including the non-downgradable
security/destructive floors. Upgrades require budget approval and a reason;
`ModelCatalogue` supplies availability and grades, and every assignment carries
a deterministic reason for the turn record.

| Test area | Evidence |
|---|---|
| Done criterion | `every_seeded_role_resolves_and_uses_its_default`: all six roles with no pin/upgrade use their default with a deterministic reason. |
| Precedence | 14 role tests: pin, upgrade, fallback, empty pin, missing role, floor refusal. |
| Floors | `enforce_floor` refuses below-floor requests for security/destructive classes. |

Commands: `cargo test -p zero-model roles` (14 tests), `cargo clippy
-p zero-model --all-targets -- -D warnings`. Defaults are representative config,
not catalogue truth; wiring into `zero-agent` subagent spawn is a follow-up.

## Work classification and floors — T-MDL-02 (done)

`zero-model` now classifies work and enforces capability floors (MDL-02,
MDL-03). Nine classes (plan, edit, review, test, research, summarize, visual
inspection, security, destructive) each carry a capability floor over coding,
reasoning, instruction following, tool use, vision, long context, and latency.
Classification uses explicit asks first, then whole-word keywords and caller
signals (secrets, network/auth, shell, irreversible, images); security and
destructive outrank everything. `meets` reports every missing capability and
treats an undeclared capability as 0 (fail closed). `choose` picks the cheapest
eligible candidate by declared grade sum with name tie-break. Security and
destructive floors have `may_downgrade=false`: any requested downgrade is refused
with `zero.pol.denied` before candidates are examined, so a security task never
silently downgrades. Other classes may lower requirements only through the
documented policy and record it.

| Test area | Evidence |
|---|---|
| Done criterion | `security_and_destructive_refuse_a_downgrade_even_when_asked` (grade 0 and near-floor grade 4). |
| Matrix | 11 tests: every class reachable with its floor, precedence, whole-word keywords, unknown=0. |
| Selection | Cheapest above floor, deterministic reasons, clamped grades. |

Commands: `cargo test -p zero-model classify` (11 tests), `cargo clippy
-p zero-model --all-targets -- -D warnings`. Classification is lexical plus
flags; a paraphrase without a keyword falls to edit/plan; grade sum is a
cheapness proxy, not price.

## Usage-window resume — T-AR-03 (done)

`zero-agent` now pauses at a safe boundary for a usage/rate-limit/budget window
and resumes when it resets (AR-03, AR-06, AR-07, AR-08). `pause` refuses an
unsafe boundary or a non-future reset and records generation plus
`last_effect_seq`. `poll` waits before the reset (surfacing reason, reset time,
remaining, cancel and switch actions); at/after it resumes only within budget
and an allowing mode, otherwise refuses; cancel outranks switch and both are
terminal. Resume planning uses a snapshot when the cursor predates the retained
journal or the generation changed, otherwise events after the cursor; it never
replays an effect at or before `last_effect_seq`, and `assert_no_effect_replay`
enforces both the plan start and an attached effect list.

| Test area | Evidence |
|---|---|
| Done criterion | Pause at seq 41, simulated reset, resume from 42 with an empty replayed-effect list; plans starting at 41 or naming 41 are refused. |
| Matrix | 15 tests: boundary refusal, waiting, exact/after reset, zero budget, disallowed mode, cancel/switch, visibility. |
| Replay | Snapshot on generation/cursor gap; events-from otherwise; no effect replay. |

Commands: `cargo test -p zero-agent resume` (33 tests), `cargo clippy -p
zero-agent --all-targets -- -D warnings`. A switch reports a target but does not
clear the window/ledger (no account-rotation evasion).

## Auto-resume policy — T-AR-02 (done)

`zero-agent` now has a pure resume policy (AR-02, AR-05). The decision matrix
covers daemon restart, crash, reboot, disconnect, teleport, device change, and a
usage window against attempts, budget, device match, uncertain effects, and
reset time. Daemon restart/crash/reboot/disconnect auto-resume when allowed;
a device change prompts (or refuses) and never silently resumes; teleport
always prompts; a usage window waits for its reset; zero budget refuses (or
waits when a reset is known); uncertain effects never auto-resume; attempts are
absolute and bounded with capped exponential backoff. `children_plan` resumes
goals/heartbeats/schedules/subagents only when the parent is Auto (a prompt is
not approval), preserving their next times.

| Test area | Evidence |
|---|---|
| Done criterion | 56 deterministic matrix cells over 7 causes and the state combinations. |
| Rules | Attempt bound absolute, budget veto, prompt precedence, teleport prompt, usage-window waiting, stale reset refusal. |
| Children | Children resume on Auto only, with preserved next times; no resume after refusal. |

Commands: `cargo test -p zero-agent resume` (18 tests), `cargo clippy -p
zero-agent --all-targets -- -D warnings`.
## M7 closure

M7 is closed: every M7 task group is implemented and verified in the tables above.

Run [45722626227](https://github.com/Ruthvik-Anne/zero/actions/runs/45722626227) on 1801d291: all 13 jobs successful.
