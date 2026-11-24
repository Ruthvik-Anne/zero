# Zero: plan

Delivery plan derived from `features.md` Part 10. This file owns order, scope,
gates, and risk. `architecture.md` owns design. `tasks.md` owns the task list.

Status: **proposal for your review.** Estimates assume one experienced
systems engineer; they are ranges, not commitments.

---

## 1. How the plan works

- Work is grouped into **milestones** `M0`–`M10`. A milestone is a coherent,
  demonstrable capability, not a date.
- **Safety before capability.** Nothing that runs model code ships before `M2`
  (policy, deletion, audit, trust).
- **The TUI comes early.** It is `M3`, immediately after safety, because the
  product is judged through it.
- **Every milestone has an exit gate.** A milestone closes only when every
  `MUST` acceptance criterion in its requirement areas passes in CI, its tasks
  are closed, the benchmark gate passes, and docs plus traceability are
  updated. Partial work stays open; it is never relabelled done.
- **Requirements are the scope unit.** A milestone lists requirement areas, and
  `tasks.md` links every task to requirement IDs.

## 2. Milestones

### M0 — Foundations (3–4 work-weeks)

**Areas:** `FND`, `OBS` (structure), `TST` (harness), `PAR` (traceability).

**Deliverables:** Cargo workspace and crate boundaries; IDs, errors, clocks,
redaction primitives; session and event log with migrations; config schema and
precedence; the client protocol skeleton; the CLI shell with only the allowed
four verbs; CI matrix for Windows, macOS, Linux on x64 and ARM64; the
requirement-to-task traceability check.

**Exit gate:** FND-01..FND-05, FND-07, FND-08, FND-11, FND-12 pass; FND-06 and
FND-09 have tests that fail on regression; every crate builds on all six
targets; the traceability check fails the build when a requirement has no task.

### M1 — Agent core and sessions (5–6 work-weeks)

**Areas:** `SES`, `PRV` (core), `AR` (journal groundwork), `MON` (queue).

**Deliverables:** agent loop with tool dispatch; provider adapters for one
hosted and one local provider with streaming, retry classification, and error
mapping; session log with fork, clone, tree, compaction, and branch summaries;
supervisor plus session workers with leases, generation cursors, and chunked
attach; idempotent command journal; a thin line-mode client for testing only
(not the product TUI); prompt queue and steering.

**Exit gate:** SES-01..SES-12 pass; PRV-01..PRV-03, PRV-07, PRV-11 pass; AR-01,
AR-03, AR-04 pass; MON-01..MON-05 pass; a 500 MiB synthetic session attaches
without loading history into memory.

### M2 — Safety core (4–5 work-weeks)

**Areas:** `POL`, `DEL`, `TRU`.

**Deliverables:** the action-class matrix as data; the single evaluator;
continuous enforcement at every dispatch; workspace trust with inert project
content; deletion guards for POSIX, PowerShell, and `cmd`; `trash` on all three
families; overwrite journal; protected paths; hash-chained audit; approval
records; the auto-mode code regulator plus the AI regulator with fail-safe
degradation; optional OS sandbox spike behind a flag.

**Exit gate:** POL-01..POL-16 pass, including mid-turn switches, subagent
inheritance, and the kernel host-request gate; DEL-01..DEL-12 pass with the
destructive corpus at zero false allows; TRU-01..TRU-05, TRU-07, TRU-08 pass;
the evaluator is the only path to an effect, proven by a bypass test.

### M3 — TUI and actions (6–8 work-weeks)

**Areas:** `TUI`, `ACT`.

**Deliverables:** our renderer with diffed frames and synchronized output;
Unicode-correct layout; incremental Markdown streaming; virtualised transcript;
Kitty keyboard protocol with declared fallbacks; identity-based selection; slow
terminal mode; themes; palette and generated help; the action registry with
slash-first and implicit actions; keybindings including `Shift+Tab` and `Ctrl+B`;
the daemon app for workers and updates; host-owned modal chrome for approvals and
the secrets prompt (wired to the vault in M5).

**Exit gate:** TUI-01..TUI-16 pass with benchmarks; ACT-01..ACT-08, ACT-10..ACT-15
pass; ACT-09 lands with extensions in M6; golden frames cover every surface
state; frame and startup budgets are recorded as baselines.

### M4 — Core infrastructure and kernel (7–9 work-weeks)

**Areas:** `FS`, `EDT`, `TSK`, `TODO`, `LCK`, `SCH`, `KRN`, `TOOL`, `AUT`.

**Deliverables:** file manager with versions, locks, batches, overlays, and
merge; edit tool with content-addressed anchors and receipts; task DAG with
claims, leases, fencing, and journal replay; todo manager; Banker's pools plus
the file strategy; MLFQ scheduler with admission, budgets, and usage windows;
tool registry, search, and context activation; IPython kernel with host requests;
goals, heartbeats, and schedules.

**Exit gate:** FS, EDT, TSK, TODO, LCK, SCH, KRN, TOOL, AUT `MUST` criteria pass;
deterministic simulation covers lock, task, and scheduler interleavings;
property tests prove fencing and atomic batches; kernel effects cannot bypass
policy; a 100k-file workspace stays within the edit and search budgets.

### M5 — Projects, credentials, and secrets (4–5 work-weeks)

**Areas:** `PRJ`, `CRT`, `SEC`.

**Deliverables:** project identity, creation, moves, copies, replaced keys, and
recovery actions; credential store on keychain with an encrypted fallback; named
accounts; scrubbed child environments; the secrets manager with tags, bindings,
encrypted vault, transport substitution, audit, rotation, scan, `.env` rules, and
the four-surface host-owned prompt (TUI in this milestone, desktop, web, and
Android surfaces when those ships).

**Exit gate:** PRJ-01..PRJ-12 pass, including copy detection with the original
untouched; CRT-01..CRT-12 pass, including a log-scrape test for leakage;
SEC-01..SEC-18 pass, including a test that no value reaches the transcript,
kernel, config, logs, or a bundle; the vault round-trips through teleport in M8.

### M6 — Web, MCP, doctor, monitors, security review (8–10 work-weeks)

**Areas:** `WEB`, `MCP`, `DOC`, `MON` (monitors), `SR`.

**Deliverables:** native search, fetch, crawl, map, extract, and browser tools
with SSRF and egress guards; MCP client with the `2026-07-28` core, MRTR,
tasks, events, apps, resources, prompts, and OAuth; MCP server mode behind a
flag; doctor binary with playbooks and forensics; monitors; `/security-review`
with the checklist, coverage ledger, six phases, schema validation, sandbox
execution, and the report set.

**Exit gate:** WEB-01..WEB-21 pass with SSRF, zip-slip, and egress suites; MCP-01
..MCP-19 pass with conformance fixtures for two revisions; DOC-01..DOC-11 pass
with fault injection per code; MON-06..MON-14 pass; SR-01..SR-17 pass, including a
run against a deliberately vulnerable fixture that finds the planted issues and
a clean run that reports none.

### M7 — Halcyon, model pool, usage, auto-resume (6–7 work-weeks)

**Areas:** `HAL`, `MDL`, `USG`, `AR`, `AUT` (refinement).

**Deliverables:** Halcyon mode with signed-file verification, key tooling,
adapters, and todo sync behind flags; the model pool with capability and cost
grades, routing, escalation, roles, and recorded decisions; the ledger and
budgets; usage-window tracking and reset resume; cost-aware routing tied to the
scheduler.

**Exit gate:** HAL-01..HAL-13 pass, including a hostile repository that cannot
enable the mode and a copied repository that needs its own file; MDL-01..MDL-15
pass with recorded routing reasons; USG-01..USG-08 pass with a reconciliation
test; AR-01..AR-08 pass under a simulated 429 with a reset time.

### M8 — Mesh, teleport, self-improvement (9–11 work-weeks)

**Areas:** `MESH`, `TEL`, `SI`.

**Deliverables:** userspace overlay with identity, owner-rooted membership,
LAN discovery, QR join, rendezvous, and relay; the transport-above-WireGuard
spike and decision; teleport with quiesce, snapshot, bundle, transfer, verify,
fence, and resume, including ciphertext vault handling; the self-improving loop
with the evaluation suite, promotion, and rollback.

**Exit gate:** MESH-01..MESH-15 pass, including partition and revocation cases;
TEL-01..TEL-14 pass with interrupted transfers, an unreachable source, a
cross-OS move, and a no-git directory; SI-01..SI-10 pass with a candidate that
cannot touch the evaluator; network-impairment suite green.

### M9 — Desktop, web app, Android, multimodal (10–12 work-weeks)

**Areas:** `AND`, `MM`, plus the desktop and web surfaces.

**Deliverables:** desktop shell over the system webview; the web app; the
Android controller with pairing, approvals, secrets prompt, and offline queue;
multimodal inputs and preprocessing; computer use with sandboxed and live-host
targets; visual verification and recordings; CPU-only local models with consent.

**Exit gate:** AND-01..AND-11 pass on physical devices; MM-01..MM-14 pass,
including an injected-instruction image suite and a CAPTCHA pause; the desktop and
web surfaces reuse the action registry without new commands; a full flow is
driven from Android with no public exposure.

### M10 — Release hardening (4–5 work-weeks)

**Areas:** `INST`, `OBS`, `TST` (full), `PAR`, performance.

**Deliverables:** signed releases with per-platform artifacts and an SBOM;
installers with channels, locks, non-interactive mode, kernel bootstrap, service
integration, and offline upgrade; metrics and tracing; the complete test matrix;
benchmark baselines for every target; parity audit; documentation.

**Exit gate:** INST-01..INST-12 pass on clean VMs for all platforms; OBS-01..OBS-08
pass; every `MUST` requirement in Part 10 has a passing AC and a recorded
evidence link; the parity matrix has no "unassessed" rows; a signed release can be
installed, updated, and uninstalled offline.

## 3. Requirement coverage

| Milestone | Areas |
|---|---|
| M0 | FND, OBS (structure), TST (harness), PAR |
| M1 | SES, PRV (core), AR (journal), MON (queue) |
| M2 | POL, DEL, TRU |
| M3 | TUI, ACT |
| M4 | FS, EDT, TSK, TODO, LCK, SCH, KRN, TOOL, AUT |
| M5 | PRJ, CRT, SEC |
| M6 | WEB, MCP, DOC, MON (monitors), SR |
| M7 | HAL, MDL, USG, AR, AUT |
| M8 | MESH, TEL, SI |
| M9 | AND, MM, desktop, web |
| M10 | INST, OBS, TST, PAR, performance |

Every area appears at least once. Areas that need continuous work (OBS, TST,
PAR) appear twice; their final gate is M10.

## 4. Why this order

- **M0 before anything:** a wrong crate boundary or log format is expensive to
  fix once five subsystems depend on it.
- **M1 before safety:** policy needs actions to police; the evaluator is written
  against the real dispatch path.
- **M2 before any UI:** a usable UI multiplies what an unsafe core can break.
- **M3 before M4:** the TUI is your first priority, and building it against a
  real session loop (M1) with real policy (M2) avoids a throwaway interface.
- **M4 before M5:** the secrets and project layers need the file manager, task
  store, and kernel host requests.
- **M6 before M7:** web and MCP add the external attack surface that the security
  review must audit, and the review's sandbox is needed for M7's adapters.
- **M8 late:** the mesh and teleport depend on stable sessions, file identity,
  and secrets, all of which are settled by M7.
- **M9 last among features:** the extra surfaces consume the same core; building
  them earlier would freeze the protocol too soon.
- **M10 last:** release engineering needs finished behaviour.

## 5. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Rust iteration speed slows delivery | medium | medium | small crates, incremental builds, cached CI, fast linker |
| TUI scope creep delays the core | medium | high | fixed gate for M3; features join later milestones |
| Banker's model does not fit real file sets | high (already mitigated) | medium | Banker's only for pools; isolated workspaces for files (LCK-05) |
| Userspace WireGuard transport is harder than expected | high | high | M8 spike with two candidates; MESH-01 does not depend on the outcome |
| Secrets substitution leaks through a new path | medium | high | single transport chokepoint; leakage suite in CI; audit per use |
| Security review is slow or expensive | medium | medium | profiles, budget gate, and a deterministic fixture baseline |
| Provider terms change again | high | medium | terms gate per release (PRV-10); API keys as the default path |
| Android VPN-free mesh is rejected by the store | medium | medium | foreground service path and a local-only controller mode |
| Windows quirk in terminal input or file identity | high | medium | first-class Windows CI and an early ConPTY input matrix |
| Scope grows through new ideas | high | high | Part 10 change control: new requirement, new area, new milestone |

## 6. Effort and assumptions

| Milestone | Weeks (one engineer) |
|---|---|
| M0 | 3–4 |
| M1 | 5–6 |
| M2 | 4–5 |
| M3 | 6–8 |
| M4 | 7–9 |
| M5 | 4–5 |
| M6 | 8–10 |
| M7 | 6–7 |
| M8 | 9–11 |
| M9 | 10–12 |
| M10 | 4–5 |
| **Total** | **66–82** |

Assumptions:

- One experienced systems engineer, full time. Two engineers on independent
  milestones (for example TUI alongside kernel work) compress elapsed time by
  roughly 30–40% without reducing total effort.
- No milestone is skipped; scope may be deferred to a later milestone only by
  moving its requirement, recorded in Part 10.
- The estimates exclude marketing, app-store review latency, and legal review of
  provider terms.

## 7. Definition of done per milestone

A milestone is done when all of the following are true, and the evidence is
linked from `tasks.md`:

1. Every `MUST` requirement in its areas has a passing acceptance criterion.
2. Every task in the milestone is closed or explicitly moved with a reason.
3. The benchmark gate passes against the recorded baseline.
4. Tests for new failure modes exist, including the negative cases.
5. Documentation and traceability are updated in the same change.
6. No known severity-1 or severity-2 defect remains.
7. For milestones that add attack surface (M2, M5, M6, M8), a security review
   of the new surface has run and its findings are resolved or recorded.

## 8. V1 scope and deferrals

V1 is M0–M8 plus the minimum of M9/M10 needed to ship: TUI, daemon app, desktop
shell, installers, and the signed release path. Explicitly later:

- Android beyond remote control (running work on the phone).
- Plugin marketplace and package distribution.
- `serve` API, SDKs, ACP, and editor integrations.
- Share links and public pairing.
- Localisation.
- Node or TypeScript compatibility shims for the archived SDK.
- Ensemble routing beyond the budgeted high-cost-of-error case.

## 9. Change control

- New behaviour enters as a numbered requirement in `features.md` Part 10, with
  an acceptance criterion and an owning area.
- If it does not fit an existing area, add an area and a milestone; do not
  smuggle it into a milestone's scope.
- A requirement may move between milestones; it may not silently drop. Dropped
  requirements are marked withdrawn with a reason.
- `plan.md`, `architecture.md`, and `tasks.md` are updated in the same change as
  the requirement.
