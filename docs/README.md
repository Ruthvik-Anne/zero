# Zero documentation

Start with the normative documents at the repository root:

| Document | Owns |
|---|---|
| [`features.md`](../features.md) | Requirements. Part 10 is normative. |
| [`architecture.md`](../architecture.md) | Design: crates, protocols, state machines. |
| [`plan.md`](../plan.md) | Order, milestones, gates, risk. |
| [`tasks.md`](../tasks.md) | Verifiable units with requirement references. |

## Start here

| Page | Contents |
|---|---|
| [`install.md`](install.md) | Prerequisites, build from source, first run, projects, login, service, update, uninstall, offline notes, and the verify-it-works checklist. |
| [`configure.md`](configure.md) | File locations, provider/model settings, modes and approvals, tools and MCP, credentials and secrets, projects, mesh, teleport, monitors, budgets, telemetry, and where each topic is documented. |
| [`troubleshooting.md`](troubleshooting.md) | Doctor first, symptom → diagnosis → safe fix, error-code links, and the risky recovery cases. |
| [`testing.md`](testing.md) | Test layers, harnesses, the benchmark gate, and how to run everything. |
| [`errors.md`](errors.md) | Every stable error code with its one remediation line. Generated. |
| [`data-directories.md`](data-directories.md) | Per-OS data, config, cache, and state paths. Generated from the one resolution table. |

## Reference

| Page | Contents |
|---|---|
| [`requirements-index.md`](requirements-index.md) | Every Part 10 area, its requirement IDs, and task counts. Generated; a test fails when stale. |
| [`parity.md`](parity.md) | Every Part 1, 2, and 8 item with its state, reason, and references. Generated; an unassessed row fails the build. |
| [`configuration.md`](configuration.md) | The config schema and its documented precedence, including untrusted project inertness. |
| [`sessions.md`](sessions.md) | Log format, tree, compaction, resume, attach, leases, journal, export. |
| [`context-files.md`](context-files.md) | `AGENTS.md` / `CLAUDE.md` precedence and size caps. |
| [`providers.md`](providers.md) | Provider trait, adapters, retry classes, fixtures, live flags. |
| [`routing.md`](routing.md) | Work classes, floors, roles, pools, the router, translation, and freshness. |
| [`tui.md`](tui.md) | Renderer, Unicode layout, streaming, transcript, input, accessibility, golden frames. |
| [`themes.md`](themes.md) | The 29 theme tokens, defaults, overriding, accessibility. |
| [`actions.md`](actions.md) | Action record, forms, policy, idempotency, audit, namespacing, keys, lint. |
| [`tasks-and-todos.md`](tasks-and-todos.md) | Task DAG, claims, journal, limits, plan seeding; todo store, ownership, capture. |
| [`locks.md`](locks.md) | Banker's pools, aging/preemption, file strategy, owner election, degraded mode. |
| [`scheduler.md`](scheduler.md) | MLFQ/fair share, admission, budgets, backoff/breakers, usage windows, durable queue. |
| [`tools.md`](tools.md) | Tool metadata/deferral, BM25 search, activation, cache-safe injection, filtering, telemetry. |
| [`kernel.md`](kernel.md) | Jupyter messaging/HMAC, channels, host gate, restart/rehydrate, limits, preload. |
| [`autonomy.md`](autonomy.md) | Goals, heartbeats, cron schedules, limits, cancellation cascade. |
| [`auto-resume.md`](auto-resume.md) | Resume causes, policy, backoff, budget and usage-window waits, uncertain effects. |
| [`projects.md`](projects.md) | Project key/identity, root detection, moves/copies, migration, mesh bindings. |
| [`credentials.md`](credentials.md) | Encrypted credential fallback, accounts, scrubbed children, refresh lock, import. |
| [`secrets.md`](secrets.md) | Vault AAD format, scopes/bindings, placeholders, transport substitution, audit, `.env`, leakage. |
| [`web.md`](web.md) | Search adapters, parallel execution, RRF fusion, URL/title dedupe, failure policy. |
| [`webui.md`](webui.md) | Loopback binding, one-time token, origin rules, shared UI states, desktop shell. |
| [`mesh.md`](mesh.md) | Device identity, join tokens, discovery, approval, revocation, quorum, relay, traversal. |
| [`teleport.md`](teleport.md) | Snapshots, bundles, encrypted transfer, full restore, fence and resume, portability. |
| [`review.md`](review.md) | Review mode gate, trust boundaries, coverage ledger, hunting and validation. |
| [`monitors.md`](monitors.md) | Monitor engine, declarative schema, triggers, sources, restart policy, caps. |
| [`multimodal.md`](multimodal.md) | Input routes, attachments, typed blocks, preprocessing, local models, computer use. |
| [`usage.md`](usage.md) | Usage ledger, attribution, totals, cost budgets, dashboards, audit and export. |
| [`observability.md`](observability.md) | Metrics, local traces, retention classes, sweeps, protected paths. |
| [`halcyon.md`](halcyon.md) | Discovery, verification, keys, adapters, behaviour, flags, and todo sync. |
| [`doctor.md`](doctor.md) | Independent doctor binary, 13 checks, playbooks, repair plans, forensics, CLI. |
| [`mcp.md`](mcp.md) | JSON-RPC core client, revisions, transports, tasks, events, apps, server mode. |
| [`policy.md`](policy.md) | Modes, the matrix, evaluator order, permits, approvals, regulators, transitions. |
| [`deletion-safety.md`](deletion-safety.md) | Command guards, shims, the Python hook, trash, journal, purge, retention, and stated limits. |
| [`trust.md`](trust.md) | Trust boundaries, workspace trust, protected files, audit integrity. |
| [`packaging.md`](packaging.md) | Release manifest, signing, SBOM, update and rollback, kernel bootstrap, service units, uninstall. |
| [`decisions/0001-sandbox.md`](decisions/0001-sandbox.md) | Sandbox spike decision with the Windows and Linux prototypes. |
| [`protocol.md`](protocol.md) | Frame layout, versioning, JSON projection, and the two readers. |

## Quick start

```sh
cargo build --workspace
cargo test --workspace
cargo run -p xtask -- check-docs          # traceability + crate direction
cargo run -p xtask -- bench --check       # performance gate
node protocol/ts/check.mjs                # TypeScript protocol reader
cargo run -p zero-cli --bin zero -- doctor
```

## Regenerating generated pages

```sh
cargo run -p xtask -- errors-doc --write
cargo run -p xtask -- paths-doc --write
cargo run -p xtask -- docs-index --write
cargo run -p xtask -- protocol-fixtures --write
```
