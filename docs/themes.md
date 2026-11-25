# Themes

Every visual role is a named token. All 29 are present in the dark theme and all
are overridable per user or per project. A missing token fails
`Theme::complete()`; `theme::tests::every_token_is_documented` compares this file
to `Token::ALL`.

| Token | Purpose | Default (256-colour) |
|---|---|---|
| `background` | canvas | 234 |
| `foreground` | body text | 252 |
| `muted` | secondary text | 244 |
| `border` | frames and rules | 240 |
| `accent` | titles and highlights | 75 |
| `success` | completed work | 78 |
| `warning` | degraded or near-limit | 214 |
| `danger` | failures and denials | 203 |
| `info` | neutral notices | 81 |
| `mode_plan` | plan mode indicator | 111 |
| `mode_manual` | manual mode indicator | 180 |
| `mode_semi` | semi-auto indicator | 114 |
| `mode_auto` | auto indicator | 78 |
| `mode_headless` | headless indicator | 141 |
| `user_message` | user turns | 117 |
| `assistant_message` | assistant turns | 252 |
| `tool_message` | tool output | 246 |
| `thinking` | folded thinking blocks | 240 |
| `code` | inline and fenced code | 223 |
| `code_background` | code block surface | 236 |
| `selection` | selected row | 60 |
| `status_bar` | status background | 236 |
| `status_bar_text` | status text | 250 |
| `queue` | queued user items | 215 |
| `approval` | approval chrome | 222 |
| `secret` | secret-entry chrome | 210 |
| `diff_add` | added lines | 78 |
| `diff_remove` | removed lines | 203 |
| `diff_context` | unchanged diff context | 244 |

## Overriding

`Theme::set(token, Color)` overrides one token. `Color` is `Default`, a 256-colour
`Ansi(index)`, or `Rgb(r, g, b)`. Themes serialize to JSON; loading rejects a
theme that is missing any token, so a partial theme never silently falls back.

## Accessibility

High contrast overrides the palette with bold ANSI colours. Line-oriented mode
renders no colour at all and writes state as words. Colour is never the only
signal for mode, queue, approval, or failure.
