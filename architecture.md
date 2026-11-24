# Zero: architecture

How the system in `features.md` is built. `features.md` Part 10 is normative:
every module here maps to requirement areas there. `plan.md` sequences the work;
`tasks.md` breaks it into verifiable units.

Status: **decided where marked, proposed otherwise.** No implementation exists.
Every number in section 21 is a target, not a measurement.

---

## 1. Precedence and scope

1. `features.md` Part 10 (requirements) wins over this file.
2. This file wins over `plan.md` and `tasks.md` on design questions; those win
   on order and scheduling.
3. A design change that alters a requirement updates Part 10 first, then this
   file, then the plan.

Scope: the core, daemon, TUI, daemon app, desktop shell, web app, Android
controller, mesh, teleport, installers, and the test and build infrastructure.

## 2. Drivers

In priority order, from your direction:

1. **The best terminal UI.** It is the primary surface and ships early (M3).
2. **The fastest core.** Startup, input-to-paint, attach, memory, throughput.
3. **Safety before capability.** Nothing that runs code ships before the policy
   and deletion core (M2).
4. **Honesty.** Unknown beats a guess; no stand-in backends; no claimed
   verification without a run.

Quality attributes that shape the design:

| Attribute | Driver requirements |
|---|---|
| Interactivity | TUI-01, TUI-02, TUI-08, TUI-09 |
| Determinism in the small | FND-08, TSK-05, LCK-02, TST-02 |
| Safety and reversibility | POL-03..POL-09, DEL-01..DEL-09, FS-04..FS-07, EDT-09 |
| Privacy | FND-12, CRT-03, SEC-05, MESH-05, TEL-05, OBS-08 |
| Offline capability | FND-10, MESH-12, DOC-09 |
| Recoverability | SES-06..SES-09, TSK-08, DOC-05, AR-01..AR-05 |
| Extensibility without forks | ACT-09, MCP-12, KRN-05 |
| Cost control | SCH-04..SCH-11, MDL-08, USG-01..USG-03 |

## 3. System context

```
                 ┌──────────── surfaces (clients) ────────────┐
                 │ TUI │ desktop │ web │ Android │ SDK │ CLI  │
                 └───────────────┬────────────────────────────┘
                                 │ one client protocol (TLS over mesh, local socket)
                    ┌────────────▼────────────┐
                    │ supervisor (daemon)     │  routing, health, updates, leases
                    └───┬────────┬────────┬───┘
             ┌──────────▼─┐ ┌────▼─────┐ ┌▼──────────────┐
             │ session    │ │ kernel   │ │ daemon app    │
             │ workers    │ │ (IPython)│ │ UI (workers)  │
             └───┬────────┘ └────┬─────┘ └───────────────┘
                 │               │ host requests
        ┌────────▼───────────────▼────────────────────────┐
        │ policy · scheduler · tasks · fs · model · web   │
        │ mcp · secrets · mesh · teleport · review        │
        └────────┬───────────────────────────┬────────────┘
                 │                           │
        ┌────────▼────────┐        ┌─────────▼──────────┐
        │ SQLite + logs + │        │ mesh overlay       │
        │ blobs (local)   │        │ (userspace WG)     │
        └─────────────────┘        └────────────────────┘
```

The **doctor** is a separate minimal binary that can inspect all of the above
while they are dead (DOC-09).

## 4. Process and concurrency model

- **One supervisor per user**, owning routing, attachment state, leases, health,
  and coordinated updates.
- **One session worker per root session tree**, owning the agent loop, tool
  dispatch, and the child registry. A crash is contained to that tree.
- **One kernel process per root tree** (KRN-01), replaceable without losing the
  session log.
- **One daemon UI surface** for workers, attachments, updates, and history
  (ACT-11), sharing the client protocol with the main client.
- **Separate processes for the doctor** and for sandboxed target code (SR-09).
- **Async runtime** with structured concurrency: every task has an owner and a
  cancellation scope. Blocking work (fsync, large file IO, archive parsing) runs
  on a bounded blocking pool.
- **Backpressure is per attachment** (SES-08); no shared unbounded queues.
- **Ordering** is by monotonic sequence per stream, never wall-clock comparison
  (FND-08, LCK-08).
- **Shutdown** is generation-fenced: a new supervisor adopts live workers and
  active session IDs.

## 5. Module map

One Cargo workspace. Dependencies point downward only; no cycles. Each module
states what it **must not** do, because boundaries erode without that.

| Crate | Responsibility | Requirement areas | Must not |
|---|---|---|---|
| `zero-types` | IDs, errors, schema, clocks, redaction primitives | FND-06..FND-08, OBS | depend on any other crate |
| `zero-store` | append-only logs, SQLite, blobs, migrations, ledger, project registry | FND-03..FND-05, SES-01, USG-01, PRJ-01, PRJ-11 | contain policy decisions |
| `zero-policy` | action classes, modes, matrix, deletion guard, trust, approvals | POL, DEL, TRU | perform IO on behalf of a tool |
| `zero-actions` | action registry, determinism metadata, palette model | ACT | hold UI rendering |
| `zero-fs` | file manager, versions, locks, batches, overlays, edit ops | FS, EDT | decide permissions |
| `zero-tasks` | task DAG, claims, journal, todos, user queue | TSK, TODO | run work itself |
| `zero-sched` | MLFQ, fair share, admission, budgets, backoff | SCH | call providers directly |
| `zero-agent` | agent loop, sessions, compaction, subagents, projects, goals, heartbeats, tool registry and search | SES, MON, SI, AUT, PRJ, TOOL | bypass the policy evaluator |
| `zero-kernel` | kernel lifecycle, host requests, output capture | KRN | hold secrets or credentials |
| `zero-model` | providers, catalogue, pool, router, ledger writes | PRV, MDL | read config files directly |
| `zero-secrets` | credential store and project vault, tag resolution, `.env` | CRT, SEC | expose values to callers |
| `zero-web` | search, fetch, crawl, map, extract, browser, SSRF guard | WEB | use an unbounded parser |
| `zero-mcp` | client, tasks, events, apps, server mode | MCP | trust server output |
| `zero-review` | security review phases, ledger, schema validation | SR | modify target source |
| `zero-halcyon` | mode file verification, adapters, todo sync | HAL | vendor or link the CLIs |
| `zero-mesh` | identity, traversal, relay, signed state, teleport | MESH, TEL | expose listeners by default |
| `zero-mm` | multimodal preprocessing, computer use, recordings | MM | claim redaction is complete |
| `zero-tui` | renderer, widgets, input, themes, secrets modal | TUI | make policy decisions |
| `zero-daemon-app` | worker and attachment UI | ACT-11 | own worker control logic |
| `zero-daemon` | supervisor, protocol server, leases, adopt/update | FND-08, SES-06, ACT-07 | render anything |
| `zero-doctor` | diagnosis, playbooks, repair, forensics | DOC | depend on a healthy daemon |
| `zero-cli` | `resume`, `login`, `logout`, `doctor`, lifecycle, completion | ACT-10, INST | add product verbs |
| `android/` | Kotlin controller | AND | run an agent |
| `desktop/` | local web UI served by the core | ACT | bundle a browser engine |

## 6. Domain model

Entities and where they live:

| Entity | Key fields | Storage |
|---|---|---|
| Project | `projectId` (hash of key), name, `copiedFrom`, bindings | `.zero/project.json`, `key`, registry in user store |
| Session | id, project, mode, model binding, cursor, parent | session JSONL + index |
| Entry | kind, seq, timestamp, payload | session JSONL |
| Action invocation | action id, actor, args digest, verdict, result ref | audit + event log |
| Task | id, state, deps, claim, budget, evidence | SQLite + journal |
| Todo | id, state, priority, links | SQLite |
| Approval | id, action hash, expiry, decision, actor | SQLite (durable) |
| Secret tag | tag, scope, binding, created, rotated | vault index |
| Secret value | ciphertext, nonce, AAD | vault (`secrets.enc`) |
| Credential | provider, account, token ciphertext | OS store |
| Model record | provider, model, version, params | per-turn record |
| Ledger event | device, model, tokens, cost, latency | append-only ledger |
| Coverage unit | refs, status, owner, checks | review run ledger |
| Mesh member | device id, pubkey, approval chain | signed replicated state |

Rules: IDs are opaque and stable; every mutable entity carries a version; every
state change is an event; derived indexes are rebuildable from events.

**Project identity.** The key is an identity, not a secret (never in the OS
store). `projectId = hash(key)`. Paths are local bindings. A copy is detected as
one key at two paths with independent histories and results in a new key, a new
projectId, and `copiedFrom` provenance.

## 7. Protocols

- **Client protocol** (`zero-types::proto`): length-prefixed binary frames,
  versioned, with `hello`, `attach`, `snapshot`, `event`, `command`, `result`,
  `approval`, and `action` frames. JSON mapping generated for the SDK, ACP, MCP
  server mode, and the HTTP API.
- **Cursors:** `{generation, sequence}`; snapshots stream as opaque chunks.
- **Idempotency:** every command carries `clientId + commandId` (ACT-07).
- **Host requests** (kernel to supervisor): typed enum covering file ops, shell,
  network, credential use, secret substitution, mesh, and task operations. The
  evaluator answers with allow, ask, or deny plus a reason. There is no ambient
  authority inside the kernel (POL-05, KRN-05).
- **Secret substitution** (SEC-05) happens in the transport layer inside
  `zero-secrets`, after policy, keyed by tag and binding. The protocol carries a
  tag reference, never a value.
- **MCP** uses Streamable HTTP and stdio with the `2026-07-28` core (MCP-01).
- **Webhooks** for MCP events bind to loopback or the mesh only.

## 8. State machines

**Mode evaluation** (per dispatch):

```
action → classify → hard denies → ask rules → allow rules
       → [auto] code regulator ∩ AI regulator (both must allow)
       → verdict + reason + policy version  (recorded)
```

A running call cannot be un-run; its result is reported and the next dispatch
uses the new version (POL-03).

**Task** (TSK-02):

```
queued → ready → running → done
              ↘ blocked → ready
              ↘ waiting_input → ready
              ↘ failed | cancelled
```

Transitions are compare-and-swap on version with a fencing token; the journal is
the source of truth (TSK-05).

**Session** (SES): `created → attached → detached → resumed | forked | closed`.
A lease keyed by canonical log path prevents two writers.

**Teleport** (TEL): `plan → quiesce → snapshot → transfer → verify → fence →
resume`, with failure leaving the source authoritative from its last checkpoint.

**Mesh membership** (MESH-08..MESH-09): `invited → pending → approved → active
→ revoked`. Only an owner-signed change alters membership.

**Security review** (SR): `setup → recon → hunt* → validate → verify → report`,
with `incomplete(reason)` as the only other terminal state.

## 9. Concurrency, locks, and scheduling

- **Banker's algorithm** for bounded pools: kernel slots, provider slots,
  transfer slots, subagent slots, browser and desktop sessions. Each worker
  declares maxima before dispatch; a request is provisionally allocated and
  granted only if a safe completion sequence exists (LCK-02, LCK-03).
- **Files** use canonical-order acquisition, all-or-nothing batches, wound-wait
  preemption, timeouts, optimistic versions, and copy-on-write overlays (LCK-05,
  FS-08). No declared maxima are required, because an agent cannot know its file
  set in advance.
- **Ownership per resource** is elected deterministically; only the owner node
  runs the safety check. Ownership moves by fenced lease handoff; a minority
  partition cannot acquire new leases (LCK-07, LCK-10).
- **Scheduling** is MLFQ with aging and weighted fair share; admission control is
  per provider, model, and credential; cost is predicted before dispatch and
  reconciled after; in-flight model calls are not preemptible, and the design
  says so (SCH-02, SCH-03, SCH-09).
- **Budget reservation** happens before the provider call; failure to reserve is
  a typed deferral, never an unbounded queue (SCH-08).

## 10. Security architecture

**Boundaries.** User > agent > kernel > tools > MCP servers > web content >
mesh peers > repository content. Trust decreases downward for content and upward
for authority (TRU-01).

**One evaluator.** `zero-policy` decides every effect. There is no second path:
native tools, kernel host requests, actions, MCP calls, subagents, and extension
tools all resolve the same action class and mode (POL-02, POL-03).

**Deletion.** A parser plus shims plus a Python guard block accidental deletion;
every managed overwrite snapshots prior content first; `trash` uses the native
recycle facility; `purge` is human-only; Zero's own data is the only exemption
(DEL-01..DEL-09). The threat model is accidental harm, not a hostile local
attacker, and the docs say so (DEL-11).

**Workspace trust.** Untrusted content is inert: config, hooks, monitors, MCP
servers, skills, instruction files, and `.halcyon-mode` (TRU-02).

**Secrets.** Values live encrypted in `zero-secrets`, never in the session,
kernel, config, or logs. The agent holds tags; the transport substitutes them
into a bound destination (SEC-01..SEC-08). The UI is host-owned on every surface
(SEC-03).

**Sandbox.** Optional OS sandboxing (Landlock/seccomp, job objects or
AppContainer) hardens the kernel and shell. It is not claimed to replace the
guards (TRU-06).

**Audit.** Hash-chained, outside agent-writable paths, covering mode changes,
approvals, deletions, credential and secret use, MCP, mesh, and teleport
(TRU-04, OBS-02).

## 11. Storage and durability

- **Session logs:** append-only JSONL, memory-mapped reads, index sidecar,
  transparent compression above a size threshold.
- **SQLite:** tasks, todos, approvals, queue, review ledgers, caches, ledger
  rollups. WAL mode, one writer per database, schema versions and forward
  migrations with a backup (FND-04).
- **Blobs:** content-addressed, chunked (about 4 MiB), deduplicated; used by
  artifacts, teleport bundles, screenshots, and recordings.
- **Atomicity:** temp file plus fsync plus rename; metadata preserved (FS-04).
- **Retention:** documented per store; expired data moves to trash, not unlink
  (OBS-06).

## 12. Kernel integration

- `ipykernel` subprocess speaking Jupyter messaging with HMAC; our own client
  implementation, no Python-side Zero code beyond a thin bootstrap.
- The kernel has no credentials and no direct network or filesystem authority:
  every effect is a host request (KRN-05, KRN-09).
- Output is captured, truncated, streamed, and accounted (KRN-07).
- Restart rehydrates from the log and reports lost in-flight work (KRN-06).
- Cell limits: memory, CPU time, output bytes, wall clock; interruption returns
  partial output (KRN-11, KRN-12).

## 13. Actions, tools, and extensibility

- **Action registry** is the only command surface. Each action declares metadata
  including determinism and agent-invocability (ACT-01, ACT-02).
- **Determinism** means a handler with no model call and stable inputs; the
  registry marks it and the UI may run it without a turn (ACT-06).
- **Tools** are registry entries backed by native handlers, kernel functions, or
  MCP servers. `tool_search` ranks across all three with native tools winning
  ties and denied tools hidden (features.md 6.2).
- **Extensions** register tools, actions, and renderers in a namespace and cannot
  shadow core IDs (ACT-09).
- **MCP server mode** reuses the registry and policy; it is disabled by default
  (MCP-15).

## 14. TUI architecture

- Cell grid, front/back buffers, diffed runs, synchronized output, declared
  fallbacks (TUI-03, TUI-07).
- Incremental Markdown: parse and lay out the tail only (TUI-05).
- Virtualised transcript: layout cost is O(visible) (TUI-06).
- Input never blocks; selection is by ID with generation checks (TUI-08,
  TUI-09).
- Slow-terminal detection lowers frame rate and effects (TUI-10).
- Host-owned chrome for secrets and approvals; the agent cannot draw into it
  (TUI-14).
- Golden-frame snapshots on a virtual terminal are the primary UI test (TST-09).
- The daemon app is a second surface over the same protocol, opened with `Ctrl+B`
  and `/daemon` (ACT-11).

## 15. Model layer and scheduler

- Provider adapters normalise streaming, tools, and errors; retries are
  classified as safe or unsafe per call (PRV-03).
- The pool stores capability grades and costs; the router classifies work and
  picks the cheapest model above the floor, with a security floor that never
  downgrades (MDL-01..MDL-03).
- Every turn records model, version, parameters, router reason, and cost
  (MDL-11).
- Transcript translation handles provider differences and records dropped
  blocks (MDL-13).
- The scheduler owns admission, budgets, and usage windows; the router asks the
  scheduler for permission before dispatch (SCH-04, SCH-09, SCH-14).

## 16. Mesh and teleport

- Userspace WireGuard with no TUN device; the transport above it is an open
  design question (section 23).
- Decentralised, signed, versioned state; owner-rooted membership; authenticated
  mDNS; rendezvous node role; relay of ciphertext only (MESH-02..MESH-10).
- Teleport snapshots the session and bundles real files; verification precedes
  fencing; failure leaves the source authoritative (TEL-02..TEL-10).
- The vault travels as ciphertext and needs one unlock on the target (SEC-11).

## 17. Observability and cost

- Structured logs with correlation IDs; local metrics; redaction at the sink
  (OBS-01, OBS-05).
- Audit is separate from logs: durable, hash-chained, user-visible (OBS-02).
- The ledger is per device and append-only; union on sync; no conflict
  resolution needed (USG-02).
- `/cost-audit` reads the ledger and proposes bounded, reversible changes (SI-10).

## 18. Failure handling and recovery

| Failure | Behaviour |
|---|---|
| Worker crash | supervisor restarts with 250 ms, 1 s, 5 s backoff; three failures mark the tree failed |
| Kernel crash | rehydrate from log; report lost in-flight work (KRN-06) |
| Provider outage | circuit breaker, fallback chain, unrelated providers unaffected (SCH-05) |
| Corrupt journal | doctor detects, snapshots, repairs from the last good checkpoint (DOC-04) |
| Stale lock | lease expiry plus fencing; doctor reports repeated cases (LCK-08) |
| Teleport failure | source stays authoritative; target discards partial state (TEL-10) |
| Disk full | typed error, deferred work, no partial writes (FND-11) |
| Mode change mid-flight | pending calls re-evaluated; running call completes; next dispatch uses the new version (POL-03) |
| Regulator unavailable | affected class degrades to manual (POL-11) |

## 19. Build, release, supply chain

- Cargo workspace, `clippy`, `rustfmt`, `nextest`, `proptest`, `loom`, `miri`,
  `cargo-fuzz`, `criterion`, `cargo-deny`, and an SBOM (TST-02, TST-03, INST-11).
- CI matrix: Windows, macOS, Linux on x64 and ARM64 (FND-02).
- Releases: signed manifest with an embedded public key; atomic update with
  rollback; offline package path (INST-02, INST-08, INST-10).
- Dependencies: permissive licences only, pinned and hashed, each addition
  recorded; GPL components excluded.

## 20. Testing architecture

- **Unit and property tests** per crate, with a strict no-network default.
- **Deterministic simulation** for policy, locks, tasks, and scheduling: a fake
  clock, a seeded scheduler, and an interleaving explorer (TST-02).
- **Golden frames** on a virtual terminal for the TUI (TST-09).
- **Conformance fixtures** for MCP and the client protocol (TST-10).
- **Network impairment** harness for mesh and teleport (TST-05).
- **Fault injection** per doctor code (TST-06).
- **Security suites** for SSRF, zip-slip, prompt injection, and secret leakage
  (TST-08).
- **Benchmarks** with recorded baselines and regression gates (TST-07).

## 21. Performance targets

| Metric | Target | Gate |
|---|---|---|
| Cold start to first frame | under 100 ms | benchmark vs recorded baseline |
| Keystroke to paint | one frame | input latency benchmark |
| Typical frame compute | under 1 ms | frame benchmark |
| Attach to running session | independent of history size | attach benchmark |
| Scroll long transcript | independent of history size | transcript benchmark |
| Idle client memory | single-digit MB | memory benchmark |
| Binary size | tracked per release | regression gate |

## 22. Architecture decisions

| # | Decision | Consequence |
|---|---|---|
| A1 | Rust for the core, daemon, TUI, kernel host, mesh, doctor | speed and one binary; longer compiles |
| A2 | Our own TUI renderer | full control of latency and correctness |
| A3 | Single action registry | one behaviour across five surfaces |
| A4 | Banker's for pools, isolated workspaces for files | sound deadlock avoidance without declared file sets |
| A5 | One policy evaluator, kernel effects as host requests | no bypass path |
| A6 | Deletion guard for accidents, not attackers | honest scope, backups as backstop |
| A7 | Secrets as tags with transport substitution | values never enter context |
| A8 | Userspace overlay, no system VPN | no admin rights, no VPN eviction |
| A9 | Project identity by key, not path | copies and moves are unambiguous |
| A10 | Append-only logs plus SQLite indexes | replay, audit, and fast queries |
| A11 | Doctor as a separate binary | works when everything else is dead |
| A12 | Security review as a native module | reproducible, schema-validated audits |

## 23. Open design questions

1. **Transport above WireGuard.** Userspace WireGuard carries IP packets, so
   either a userspace TCP/IP stack or a datagram protocol with our own reliable
   streams. Decide in M8 with a spike; requirement MESH-01 does not depend on the
   answer.
2. **Android protocol sharing.** FFI to the Rust core or a Kotlin reimplementation
   against the same schema. Decide in M9.
3. **Desktop shell.** System webview per platform versus a bundled engine; the
   requirement forbids bundling a full browser, so the webview is the default.
4. **Jupyter transport.** ZeroMQ binding choice and protocol version pin.
5. **Marketplace for plugins.** Out of scope until after M10.
