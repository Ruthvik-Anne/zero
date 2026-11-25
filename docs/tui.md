# TUI

## Rendering

- `Buffer` is a width×height cell grid. A cell holds one grapheme, its style,
  its display width, and a continuation flag for the right half of a wide glyph.
  Invariants (no orphan continuation, no wide glyph without its half, stored
  width equals measured width) are checked after every mutation in the
  property test.
- `Screen` keeps front and back buffers and emits only changed runs, left to
  right, top to bottom, inside synchronized-output markers `CSI ?2026h/l`.
  Unsupported terminals use `redraw()` (clear + full paint) with no markers.
- Wide glyphs at the right edge degrade to a space; resizing clears any truncated
  wide glyph rather than leaving half a cell.

## Unicode

Grapheme clusters come from `unicode-segmentation`; widths from `unicode-width`,
with emoji sequences (ZWJ, variation selector 16, regional indicators) fixed at
two columns. Combining marks add no width. Tabs expand to the next tab stop.
Right-to-left runs are replaced by `[RTL]` (declared degradation) instead of
being reordered. Untrusted text has all control sequences stripped before it
reaches a cell.

## Streaming and history

`StreamingMarkdown` parses only the appended bytes plus the unfinished tail;
completed blocks are stored. Layout walks blocks from the end until the visible
rows are filled, so a 10,000-message stream has flat parse and frame cost.
`VirtualTranscript` lays out only the window plus a bounded overscan; scrolling
never touches the whole history. Fullscreen toggles presentation only.

## Input

`InputParser` handles CSI arrows/Home/End, `CSI Z` and Kitty `9;2u` Shift+Tab,
SGR mouse, bracketed paste, focus in/out, and `CSI <n>;…~` keys. Kitty is probed
with a bounded wait against an injected clock; no response declares the legacy
fallback chords. The test matrix covers Windows Terminal, ConPTY, tmux, and a
legacy terminal.

## Accessibility and chrome

- No-animation, high-contrast, and line-oriented modes. Line mode emits words,
  not colour; a scripted screen-reader session covers start, prompt, approval.
- Approvals and secret entry are host-owned: `HostChrome` is set only by host
  methods, and agent text is sanitized into transcript rows, so agent output
  cannot forge a modal.
- The status bar always states mode, model, budget (including `WARN` and
  `STOPPED`), queue depth, approvals, and busy/idle.
- Images use Kitty/iTerm2/half-block output with a textual placeholder that
  carries the same artifact id.

## Golden frames

`crates/zero-tui/tests/golden/*.txt` store the terminal read-back text and the
escape sequences for five scenes at three sizes. `cargo test -p zero-tui` compares
them on every UI change. Refresh deliberately with `UPDATE_GOLDEN=1`.
