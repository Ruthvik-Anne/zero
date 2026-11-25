# M3 evidence

Run on 2026-11-25 from the repository root. Per-task mapping is the M3 closure
table in [`tasks.md`](../tasks.md).

## Aggregate

```text
$ cargo test --workspace
289 passed, 0 failed

$ cargo clippy --workspace --all-targets -- -D warnings
Finished (no warnings)

$ cargo run -p zero-actions --bin actions-lint
actions: 17 registered, 6 agent-invocable
actions lint: OK

$ cargo run -p xtask -- check-docs
traceability: 478 requirements, 276 tasks, 38 areas — OK
architecture: 24 crates, 23 edges — OK
```

New in M3: 46 `zero-tui` unit tests, 5 golden-frame tests, 16 `zero-actions`
tests, and 3 `zero-daemon-app` tests.

Hosted matrix run [45536140318](https://github.com/Ruthvik-Anne/zero/actions/runs/45536140318)
on `ci/m0-m1-verification` (`2dc071c8`): all eight jobs successful, including
golden-frame comparisons on both macOS targets and the actions lint in the docs
job.

## Golden frames

`crates/zero-tui/tests/golden/` stores the terminal read-back text and every
escape sequence for: welcome 80×24, transcript 100×20, transcript 60×12, palette
80×20, approval modal 80×16. The comparator normalises line endings so a CRLF
checkout does not produce a false failure; the cell content and SGR sequences
must match byte for byte.

## Notable proofs

- Cell invariants hold after 2,000 random mutations (wide glyphs, emoji,
  combining marks, clears, and resizes). Resizing found and fixed a real bug:
  truncating a row could orphan the left half of a wide glyph.
- Diff output is byte-exact: synchronized markers, absolute cursor moves, full
  SGR resets, wide glyphs, and 256-colour output.
- A 10,000-message Markdown stream scans <128 bytes per push and visits ≤41
  blocks per frame; the transcript visits ≤60 messages for a 40-row window and
  ≤160 after scrolling 80 lines, regardless of 10k history.
- The input matrix covers Windows Terminal (`CSI 1;2Z`), ConPTY/tmux/legacy
  (`CSI Z`), and Kitty (`CSI 9;2u`); the Kitty probe returns `Legacy` at the
  deadline with no response.
- The action executor: slash and implicit forms emit identical events; a replay
  has one effect; `!rm` is `zero.del.blocked` and never reaches the handler;
  non-invocable actions are refused to the agent; an audit scan reconstructs the
  session's action order; extension shadowing of `mode.set` is refused.
