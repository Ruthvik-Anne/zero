# Testing

Layers, what each proves, and the command that runs it.

| Layer | Proves | Command |
|---|---|---|
| Unit | Each module's invariants | `cargo test --workspace` |
| Property / simulation | Deterministic interleavings (TST-03) | `cargo test -p zero-types sim::` |
| Virtual terminal | Frames and escape sequences (TST-02, TST-09) | `cargo test -p zero-tui` |
| Durability | 1,000 injected crashes leave no torn record (FND-09) | `cargo test -p zero-store durability::` |
| Hard-kill loop | The log survives repeated process kills (FND-09) | `cargo test -p zero-store --test kill_loop` |
| Attach | 618 MiB attaches with a bounded tail read (SES-07) | `cargo test -p zero-store --test attach` |
| Concurrent create | Two processes converge on one worker (SES-06) | `cargo test -p zero-store --test session_lease` |
| Sessions | Fork/clone/tree, compaction, summaries, export (SES-01..04, SES-10) | `cargo test -p zero-agent` |
| Provider fixtures | Real adapters over loopback HTTP (PRV-02, PRV-03) | `cargo test -p zero-model --test http_fixture` |
| Provider live smoke | Behind `ZERO_LIVE_OPENAI` / `ZERO_LIVE_OLLAMA` | `cargo test -p zero-model --test live` |
| Policy and matrix | Modes, evaluator order, permits, approvals, transitions | `cargo test -p zero-policy` |
| Deletion guards | POSIX/PowerShell/cmd corpus, Python hook, shims | `cargo test -p zero-policy --test python_guard` and `--test shims_unix` / `--test shims_windows` |
| File safety | Trash, overwrite journal, purge, retention | `cargo test -p zero-fs` |
| Audit chain | Hash chain and tamper localisation | `cargo test -p zero-store audit::` |
| Sandbox spike | Windows job object, Linux Landlock | `cargo test -p zero-policy --test sandbox_windows` (Windows) / `--test sandbox_linux` (Linux) |
| Supervisor | Kill, bounded restart, adoption, shutdown (SES-08) | `cargo test -p zero-daemon` |
| Line client | The loop runs without a terminal (SES-12) | `cargo test -p zero-cli --test line` |
| Protocol conformance | Rust and TypeScript readers agree (FND-10) | `cargo test -p zero-types proto::` and `node protocol/ts/check.mjs` |
| Traceability | Requirements and tasks reference each other (PAR-01) | `cargo run -p xtask -- check-traceability` |
| Crate direction | No upward edge or cycle (FND-01) | `cargo run -p xtask -- check-arch` |
| Docs | Tables match code; index covers every area (PAR-02) | `cargo test -p zero-types --lib` and `cargo test -p zero-arch` |
| Benchmarks | Startup, frame, and attach stay inside the recorded budget (TST-04) | `cargo run -p xtask -- bench --check` |
| CLI | Permitted verbs only; unknown verb names the action (FND-11) | `cargo test -p zero-cli` |

## Determinism

No test reads wall-clock ordering. Clocks are `FakeClock`; ids come from a seeded
generator; the simulation harness replays the same trace for the same seed. The
`same_seed_reproduces_identical_event_order` test runs 1,000 scheduled events
twice and compares the traces.

## Benchmarks

`bench/baselines.json` records startup (ms), frame (µs), and attach (ms) with a
4× tolerance. `xtask bench --record` refreshes it deliberately; CI runs
`--check` and fails on regression. The attach measurement scans a 50,000-record
log; M1 extends it to a 500 MiB attach.

## Adding a test

A new durable write needs a durability case; a new frame needs a golden fixture;
a new requirement needs a task in `tasks.md` or the traceability check fails the
build.
