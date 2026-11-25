# Zero documentation

Start with the normative documents at the repository root:

| Document | Owns |
|---|---|
| [`features.md`](../features.md) | Requirements. Part 10 is normative. |
| [`architecture.md`](../architecture.md) | Design: crates, protocols, state machines. |
| [`plan.md`](../plan.md) | Order, milestones, gates, risk. |
| [`tasks.md`](../tasks.md) | Verifiable units with requirement references. |

Supporting pages in this directory:

| Page | Contents |
|---|---|
| [`requirements-index.md`](requirements-index.md) | Every Part 10 area, its requirement IDs, and task counts. Generated; a test fails when stale. |
| [`errors.md`](errors.md) | Every stable error code with its one remediation line. Generated. |
| [`data-directories.md`](data-directories.md) | Per-OS data, config, cache, and state paths. Generated from the one resolution table. |
| [`configuration.md`](configuration.md) | The config schema and its documented precedence, including untrusted project inertness. |
| [`sessions.md`](sessions.md) | Log format, tree, compaction, resume, attach, leases, journal, export. |
| [`context-files.md`](context-files.md) | `AGENTS.md` / `CLAUDE.md` precedence and size caps. |
| [`providers.md`](providers.md) | Provider trait, adapters, retry classes, fixtures, live flags. |
| [`tui.md`](tui.md) | Renderer, Unicode layout, streaming, transcript, input, accessibility, golden frames. |
| [`themes.md`](themes.md) | The 29 theme tokens, defaults, overriding, accessibility. |
| [`actions.md`](actions.md) | Action record, forms, policy, idempotency, audit, namespacing, keys, lint. |
| [`tasks-and-todos.md`](tasks-and-todos.md) | Task DAG, claims, journal, limits, plan seeding; todo store, ownership, capture. |
| [`locks.md`](locks.md) | Banker's pools, aging/preemption, file strategy, owner election, degraded mode. |
| [`policy.md`](policy.md) | Modes, the matrix, evaluator order, permits, approvals, regulators, transitions. |
| [`deletion-safety.md`](deletion-safety.md) | Command guards, shims, the Python hook, trash, journal, purge, retention, and stated limits. |
| [`trust.md`](trust.md) | Trust boundaries, workspace trust, protected files, audit integrity. |
| [`decisions/0001-sandbox.md`](decisions/0001-sandbox.md) | Sandbox spike decision with the Windows and Linux prototypes. |
| [`protocol.md`](protocol.md) | Frame layout, versioning, JSON projection, and the two readers. |
| [`testing.md`](testing.md) | Test layers, harnesses, the benchmark gate, and how to run everything. |

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
