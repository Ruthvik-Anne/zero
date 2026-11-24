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
