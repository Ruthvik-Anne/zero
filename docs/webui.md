# Local web UI

`zero-daemon-app::webui` is the local web surface (ACT-16, T-WEBUI-01): the same
action registry the TUI and the desktop app render, served from the local core
over a loopback listener behind a one-time token. It ships no public listener, no
external assets, and no telemetry.

Files: `crates/zero-daemon-app/src/webui.rs`, re-exported from
`crates/zero-daemon-app/src/lib.rs`.

## Binding policy

```rust
pub struct WebUiConfig {
    pub bind: SocketAddr,
    pub token_ttl_ms: u64,
    pub allowed_origin: Option<String>,
}
```

- `validate()` accepts only a loopback address: the IPv4 loopback range or
  `::1`. `0.0.0.0`, `::`, a LAN address (`192.168.x.x`, `10.x.x.x`), a public
  address, and an IPv4-mapped IPv6 address (`::ffff:127.0.0.1`) are refused with
  `zero.pol.denied` (remediation: switch mode or get user approval).
- A hostname never reaches `SocketAddr`, so `parse_bind("example.com:8080")`
  refuses it with the same code. `localhost:8080` is refused too: resolution is
  not part of the policy.
- Port `0` asks the OS for an ephemeral port. `LocalWebUi::local_addr()` reports
  what was actually bound; `bind_url()` is the address as a URL and never carries
  a token, so it is safe to log.
- `start()` validates the config, binds, and then validates the address the OS
  returned. A config built from a struct literal cannot widen the listener.

`WebUiConfig::loopback(0)` is the default: `127.0.0.1`, ephemeral port, five
minute token lifetime, same-origin only.

## One-time token

```rust
pub struct OneTimeToken { /* value, issued_ms, expires_ms, used */ }
```

- The value is 32 bytes from the OS entropy source, read through
  `zero_secrets::signin::random_bytes` (the same path `zero-secrets`,
  `zero-mesh`, and `zero-halcyon` use), rendered as 64 hex characters. The
  workspace fails closed on an entropy read error instead of returning a
  predictable value, so token generation has no error to report and no token is
  ever derived from time or a seed.
- `url()` returns `http://127.0.0.1:<port>/?token=<value>`. That string is the
  only place the value appears. `Debug` for both the token and `LocalWebUi`
  prints `<redacted>`; the token is not `Display` or `Serialize`, is never
  written to disk, and no code path logs it. `bind_url()` covers logging.
- `authorize(request_target, now_ms)` spends the token on the first accepted
  request. A second request, an expired token, a token minted by another
  instance, an empty `token=`, or a missing one all return `401` with the same
  body, so the response never says which case it was or echoes the presented
  value.
- Expiry is inclusive: a request at or after `expires_ms` is refused. A TTL of
  `0` produces an already-expired token.
- Comparison is length-agnostic and has no early exit: it accumulates the XOR of
  every byte plus any length difference and compares once at the end, so the
  first differing byte costs the same as the last. Length itself is public and
  fixed.
- `invalidate()` marks the token used; `state(now_ms)` reports `active`, `used`,
  or `expired`; `issue_token()` mints a fresh one for the next page load.

### One token, one request

The token is strictly single use, so the action snapshot is embedded in the page
it authorizes rather than fetched by a second request. The page is complete on
load. Reloading fails with `401`; the host calls `issue_token()` and hands out a
new URL. `/api/actions` is the same snapshot for host and tooling callers and is
subject to the same single-use rule, so it is requested with its own token.

## Endpoints

| Method | Path | Auth | Response |
|---|---|---|---|
| `GET` | `/`, `/index.html` | one-time token | fixed HTML document with the inline action snapshot, `text/html; charset=utf-8` |
| `GET` | `/api/actions` | one-time token | `Vec<ActionRecord>` JSON snapshot, `application/json; charset=utf-8` |
| other methods | any | — | `405` |
| `GET` | any other path | one-time token | `404` |
| `GET` | a path containing `..` or `\` | — | `400` |

- The document is a fixed string. CSS, the renderer, and the snapshot are inline;
  there are no external assets, no CDN, no `src=`, no iframes, and no telemetry.
  The HTML is served with `Content-Security-Policy: default-src 'none';
  script-src 'unsafe-inline'` (the inline renderer is the only script; it writes
  values with `textContent`), plus `nosniff`, `no-referrer`, and `no-store`.
- The snapshot goes into a `<script type="application/json">` element with every
  `</` escaped, so registry text cannot end the element early.
- The router knows exactly those two paths and never touches the filesystem, so
  there is no path through it to a file, and a traversal attempt is refused
  before the token is consulted.
- Every response sets `Cache-Control: no-store`, `X-Content-Type-Options:
  nosniff`, `Referrer-Policy: no-referrer`, and `Connection: close`.
- The request head is capped at `MAX_REQUEST_BYTES` (8 KiB) and refused with
  `413` before authorization, without spending the token. A response body is
  capped at `MAX_RESPONSE_BYTES` (256 KiB); a larger snapshot is refused with
  `500` rather than truncated. Accepted connections get a 5 second read and
  write timeout.

## Origin rules

- `allowed_origin = None` (default): same-origin only. A request carrying an
  `Origin` must match `http://` plus its own `Host` header; anything else is
  `403` before authorization, so a refused origin does not spend the token. A
  request without an `Origin` is a non-browser client on loopback and is
  accepted as same-origin.
- `allowed_origin = Some(origin)`: only that exact origin passes. The response
  echoes `Access-Control-Allow-Origin: <origin>`; it is never `*`.
- `validate()` refuses an `allowed_origin` that is empty, `*`, `null`, has no
  `http://`/`https://` scheme, contains a space, contains a `*`, or ends in `/`.
  `Vary: Origin` is always set.

## No public listener

The guarantee is enforced twice and tested:

1. `WebUiConfig::validate()` refuses every non-loopback bind before `bind()` is
   called.
2. `start_with_actions()` re-validates `listener.local_addr()` after binding.

A loopback socket is not reachable from another host, so the ACT-16 acceptance
case (a connection from another host finds no listener) holds by construction
and is asserted as the refusal of every non-loopback address rather than by a
test that needs a second machine.

## Server loop

- `handle_once()` accepts one connection, parses the request line and headers,
  authorizes, routes, writes one response, and returns a `WebUiOutcome`
  (`status`, `reason`, `content_type`, `body`, `allow_origin`). It waits up to 5
  seconds for a connection and fails with `zero.fnd.timeout` otherwise. Tests use
  it directly.
- `run_until(shutdown)` polls a non-blocking listener one connection at a time
  and returns when the `Arc<AtomicBool>` or `LocalWebUi::shutdown()` is set.
  A single failed connection does not stop the loop.
- Accepted sockets are forced back to blocking mode: Windows can inherit the
  listener's non-blocking mode, which would turn the request read into an
  immediate `WouldBlock`.
- A refused oversized request drains a bounded amount of input before closing,
  so the `413` is not lost to a connection reset.

## Shared UI states (T-DSK-02)

`zero-daemon-app::shared_ui` is the one host-side model the TUI, the desktop
shell, the local web UI, and the Android app render (ACT-03, TUI-14, SEC-03). It
is data plus projection: surfaces do not keep a second copy of the palette, mode,
approval, secret prompt, or status.

Files: `crates/zero-daemon-app/src/shared_ui.rs`, re-exported from
`crates/zero-daemon-app/src/lib.rs`.

### Model

```rust
pub enum UiSurface { Tui, Desktop, Web, Android }

pub struct SharedUiState {
    pub palette: PaletteState,          // open, query, entries (the catalogue)
    pub mode: ModeView,                 // label, plan_like
    pub approval: Option<ApprovalView>, // id, action, reason, hash
    pub secret: Option<SecretPromptView>,
    pub status: StatusView,             // text
}
```

- `SharedUiState::from_registry(registry, mode)` builds the palette from the one
  `zero-actions` registry and orders it by category, then title, then id.
  `attach_keys(keymap, surface)` fills each entry's `keys` from that surface's
  bindings; the keys are display data and also match the filter.
- `open_palette` opens with an empty query. `filter_palette(query)` sets the
  query only. `open_approval`, `open_secret`, `close_approval`, `close_secret`,
  and `close` are host-only transitions; `close` clears the palette and both
  prompts. `set_mode` accepts a label and derives `plan_like` once.
- `status.text` is recomputed on every transition
  (`mode: <label> · approvals: <0|1> · secrets: <0|1>`), so no surface can show a
  stale count.
- The approval `hash` is a deterministic FNV-1a 64 fingerprint of id, action, and
  reason, rendered as 16 hex characters. It binds the displayed fields together;
  it is not a signature. Replay-bound approvals are T-AND-03's job.

### Palette filtering

`PaletteState::visible()` is the only filter. It trims the query, lowercases it,
and keeps entries whose title, category, or keys contain it as a substring, in
catalogue order. It is bounded three ways: a query is at most
`MAX_PALETTE_QUERY_CHARS` (64) characters, the catalogue holds at most
`MAX_PALETTE_ENTRIES` (512) entries, and one query returns at most
`MAX_PALETTE_RESULTS` (50) rows. Every surface calls this one function, so the
rows and their order cannot drift.

Selecting an entry is deliberately not part of this model: there is no executor
handle and no `select`/`run` method, so a palette cannot run an action by itself.
Execution stays in `zero-actions`' executor behind policy and audit.

### Renderers

`SharedUiState::render(surface)` returns one `SurfaceFrame`:

| Surface | Variant | Payload |
|---|---|---|
| TUI | `SurfaceFrame::Tui(TuiFrame)` | status line, palette rows, then host chrome from `zero_tui::modal::HostChrome` with `Theme::dark()` at width `TUI_MODAL_WIDTH` (60) |
| Desktop | `SurfaceFrame::Desktop(UiJsonView)` | JSON view model |
| Web | `SurfaceFrame::Web(UiJsonView)` | same JSON view model |
| Android | `SurfaceFrame::Android(AndroidFrame)` | the same JSON view plus `mobile: true` |

- The JSON view model is `{surface, palette: {open, query, entries},
  mode, approval, secret, status}`. `palette.entries` are the filtered rows; an
  entry is `{id, title, category, keys}`. An approval is
  `{id, action, reason, hash}`.
- A secret view is `SecretPromptView`: `{prompt_id, surface, tag, reason, masked,
  field, submit, cancel}`. `field` is bullets only (`•`) and `masked` is `true`.
  The view is relabelled per surface when projected; the value-free fields are
  unchanged. No renderer ever receives a value, because
  `SecretPrompt::view` produces the view from a host-issued prompt and the model
  stores only that view.
- The TUI host chrome is one modal slot. When a secret and an approval are both
  pending it draws the secret (the only frame that takes input); otherwise it
  draws the approval. The JSON model carries both fields independently.
- `SurfaceFrame::json()` returns the serialized payload for the three JSON
  surfaces and `None` for the TUI.

### Comparison rule

```rust
compare_surfaces(&SharedUiState) -> Comparison { matches, differences }
```

`compare_surfaces` renders all four surfaces and delegates to
`compare_frames(state, &[(UiSurface, SurfaceFrame)])`. The comparison asserts:

- every surface rendered a frame whose variant matches its surface;
- each JSON view's `surface`, `mode`, `status`, and `approval` equal the shared
  state, and the palette `open` flag, query, entries, and order equal
  `PaletteState::visible()`;
- the secret view is present iff the state has one, is masked with the same
  bullet field, same id/tag/reason, and is labelled for the surface rendering it;
- the desktop, web, and Android views agree with each other on every field
  (except the surface name), and Android sets `mobile: true`;
- the TUI text carries the status line, the palette header and rows in order
  (or `no matches`), and exactly one host-owned modal frame with the same
  approval id/action/reason (`SECRET REQUIRED`, tag, and `masked` for a secret);
- a closed palette is not rendered and a cleared prompt leaves no modal frame.

`differences` lists each violation as `"<surface>: <what differs>"`.
`compare_frames` also reports a missing frame, so a test can blank or reorder one
frame and prove the comparison catches it. Scripted states are compared on every
transition (open, filter, empty result, bounds, approval open/close, secret
open/close, close-all).

### Parity limits

- `zero-tui`'s approval chrome has no hash slot, so the fingerprint appears in
  the JSON view but not in the TUI frame. The TUI draws the same id, action, and
  reason; the hash is not a required TUI field.
- The TUI clips a chrome row to the 60-column frame. Comparison therefore treats
  a value longer than 24 characters as a 24-character prefix; scripted states use
  short values.
- The TUI flattens control characters and newlines to single spaces
  (`one_line`), so registry or reason text cannot draw a second frame. The JSON
  view keeps the original text; comparison normalises the TUI side only for
  values it looks up.
- Both an approval and a secret pending at once is a model state the TUI cannot
  draw in one slot; the secret wins, and the comparison encodes that precedence
  rather than pretending both frames exist.
- `SharedUiState` models state, not execution. Palette selection, approval
  allow/deny, and secret submission are host transitions owned by the caller
  (and, for execution, by `zero-actions`); this module never runs an action.

## Desktop shell (T-DSK-01)

`zero-daemon-app::desktop_shell` is the desktop host: the operating system's
webview around the local UI, loopback only, rendering the one shared action
registry. It ships no browser engine and launches no process.

Files: `crates/zero-daemon-app/src/desktop_shell.rs`, re-exported from
`crates/zero-daemon-app/src/lib.rs`.

```rust
pub enum WebviewKind { WebView2, WkWebView, WebKitGtk }  // system engines only
pub enum EngineSource { System, Bundled }

pub struct ShellConfig {
    pub webview: WebviewKind,
    pub ui: WebUiConfig,
    pub window_title: String,
    pub engine_source: EngineSource,
}

pub struct DesktopShell { /* one validated ShellConfig */ }

pub struct ShellPlan {
    pub webview: WebviewKind,
    pub url: String,            // loopback URL, no token, safe to log
    pub token: OneTimeToken,    // single use; Debug redacts
    pub actions: Vec<ActionRecord>,
    // private: the loopback listener serving the page
}
```

### System webview rule

- `EngineSource::Bundled` is refused with `zero.pol.denied` and the message
  "no bundled browser engine". A browser engine is an OS component: WebView2 on
  Windows, WKWebView on macOS, WebKitGTK on Linux.
- `ShellConfig::validate()` requires `webview` to equal
  `webview_for_platform()` for the current OS. A mismatch (or a platform with
  no mapping) is `zero.fnd.unsupported` and carries
  `WebviewKind::install_guidance()` — for example, install the Microsoft Edge
  WebView2 Runtime, use the macOS build on macOS, or install
  `libwebkit2gtk-4.1`. There is no hidden fallback to a different engine.
- `DesktopShell::prepare` runs the same validation again, so a config rebuilt
  from a struct literal cannot skip it, and it launches nothing: the host opens
  the system webview at `ShellPlan::url_with_token()`.

### Loopback bind

`ShellConfig::ui` is a `WebUiConfig`, and `validate()` calls
`webui::validate_bind` (then `WebUiConfig::validate`) before a listener exists.
`0.0.0.0`, `::`, a LAN address, a public address, and an IPv4-mapped loopback
address are all `zero.pol.denied`; the shell cannot point a webview at a public
listener. `WebUiConfig::loopback(0)` is the default (ephemeral port, five minute
token lifetime).

### Token and launch line

- `DesktopShell::prepare` binds the loopback listener with the shared registry
  snapshot and issues a fresh `OneTimeToken`. The token is single use: the first
  authorized request spends it and a replay is `401` (inherited from `webui`).
- `ShellPlan::url` is the token-free address; `url_with_token()` is the only
  place the value appears. `ShellPlan`'s `Debug` prints the token as
  `<redacted>` and never the token URL.
- `ShellPlan::render_launch()` returns one deterministic line,
  `shell=desktop webview=<engine> url=<loopback url>`, with no token, for
  logging.

### Action registry sharing (ACT-01)

`desktop_shell::action_registry()` (also `DesktopShell::action_registry()`)
returns the entries of the one `zero-actions` registry sorted by category, then
title, then id — exactly the order
`shared_ui::SharedUiState::from_registry` puts into its palette. `prepare` hands
that same vector to the listener, so the desktop webview, the web surface, the
TUI, and Android render the same actions in the same order. The shell defines no
command of its own; a test compares the two lists entry for entry.

### Window title

The title must be non-empty, at most `MAX_WINDOW_TITLE_CHARS` (120) characters,
and free of control characters; otherwise `ShellConfig::validate` returns
`zero.fnd.invalid_input`.

### No bundled engine, structurally

A test walks `crates/zero-daemon-app` and refuses engine directories
(`node_modules`, `chromium`, `electron`), engine assets
(`webview2loader`, `libcef`, `cefsharp`), and binary extensions (`.dll`,
`.dylib`, `.so`, `.asar`, `.pak`). It also scans the production half of
`desktop_shell.rs` for those markers, for `std::process`/`Command::new`, and for
any `http://`/`https://` URL that is not loopback. Serde round-trips
`ShellConfig` including `engine_source`; validation, not deserialisation, is the
one policy gate.

## Test evidence

`cargo test -p zero-daemon-app` runs 38 tests: 10 in `desktop_shell::tests`, 9 in
`shared_ui::tests`, 15 in `webui::tests`, 4 existing `DaemonApp` tests. All are
loopback only and use no external network.

### Desktop shell tests

| Test | Covers |
|---|---|
| `a_bundled_browser_engine_is_refused` | `EngineSource::Bundled` is `zero.pol.denied` ("no bundled browser engine") from both `validate` and `prepare`; only `System` ships |
| `the_system_engine_is_accepted_on_the_matching_platform` | `ShellConfig::for_platform` validates; `prepare` reports the current engine, a token-free loopback `url`, and the shared entries |
| `a_non_loopback_ui_bind_is_refused` | `0.0.0.0`, `::`, and a LAN address are `zero.pol.denied` and never prepare |
| `a_wrong_platform_webview_is_unsupported_with_install_guidance` | a foreign engine is `zero.fnd.unsupported` with that engine's install guidance, not a fallback |
| `the_action_registry_matches_the_shared_palette_entries_and_order` | desktop entries, titles, categories, and order equal `SharedUiState`'s palette; no duplicates |
| `the_one_time_token_is_issued_and_single_use` | 64 hex characters; first request `200` and spends the token; replay `401` |
| `the_launch_line_and_debug_hide_the_token` | `render_launch` is deterministic and token-free; `Debug` prints `<redacted>` and no token URL |
| `the_window_title_is_bounded` | empty, blank, control characters, and over-cap titles are `zero.fnd.invalid_input`; the cap itself passes |
| `the_config_round_trips_through_serde_and_keeps_the_engine_source` | `ShellConfig` round-trips for both engine sources; bundled deserialises but is still refused by `validate`; stable engine names |
| `no_browser_engine_binary_or_remote_asset_is_bundled` | no engine directory, asset, or binary in the crate; no `std::process`, no non-loopback URL in the shell source |

### Shared UI state tests

| Test | Covers |
|---|---|
| `palette_open_filter_empty_and_bounds_are_identical_on_every_surface` | open/filter/case/empty agreement; query, catalogue, and result bounds |
| `palette_entries_and_order_are_identical_in_tui_text_and_json` | TUI rows and JSON entries have the same titles and order; Android mobile flag |
| `approval_and_secret_open_and_close_agree_on_every_surface` | approval fingerprint determinism, TUI text, open/close transitions, close-all |
| `the_secret_prompt_is_masked_everywhere_and_never_carries_a_value` | bullets on all surfaces, no value in any payload, host-only guard, agent text cannot open a prompt |
| `mode_label_and_plan_flag_agree_and_the_tui_status_shows_the_label` | all five mode labels, `plan_like` agreement, TUI status line |
| `compare_surfaces_detects_an_injected_mismatch` | reordered palette, unmasked secret, and blanked TUI frame are reported |
| `json_shapes_are_stable_and_android_is_the_same_view_plus_mobile` | top-level/entry/approval/secret keys; Android is the same view plus `mobile` |
| `palette_is_data_only_and_executes_nothing` | palette entries are display data; filtering does not touch the registry |
| `keys_are_shared_and_participate_in_filtering` | per-surface chords fill `keys`; `ctrl+b` filters to `daemon.toggle` |

### Web UI tests

| Test | Covers |
|---|---|
| `every_non_loopback_bind_is_refused` | `0.0.0.0`, `::`, LAN, public, and IPv4-mapped addresses get `zero.pol.denied` and never bind |
| `hostnames_are_refused_at_parse_time` | `example.com`, `localhost`, `zero.local` refused; `127.0.0.1` and `::1` accepted |
| `wildcard_origins_are_refused` | `*`, `null`, scheme-less, wildcard, and trailing-slash origins refused |
| `loopback_binds_and_the_url_uses_the_ephemeral_port` | bound address is loopback, port 0 resolves, `bind_url` and `url` shapes |
| `the_token_opens_the_page_exactly_once` | first request `200` with the page; reuse `401` with no page |
| `an_expired_or_foreign_token_is_refused` | inclusive expiry, foreign token, second use, missing/empty token |
| `an_expired_wire_token_is_a_401` | TTL 0 over the socket is `401` |
| `html_and_the_action_snapshot_are_served` | HTML carries the snapshot with no external references; `/api/actions` returns the registry JSON |
| `only_the_two_paths_exist` | unknown path `404`, traversal `400`, non-`GET` `405` without spending the token |
| `registry_text_cannot_end_the_snapshot_element` | `</script>` in a title is escaped; only the template's two closing tags remain |
| `origin_rules_refuse_foreign_pages` | same-origin mode refuses `evil.example` without spending the token; explicit origin echoes itself, never `*` |
| `oversized_requests_are_refused_without_spending_the_token` | 8 KiB+ head is `413`, then the token still opens the page |
| `shutdown_stops_the_loop` | `run_until` serves one request and returns after the flag is set |
| `the_token_never_reaches_debug_or_a_log_safe_url` | token shape, absent from `Debug`/`bind_url`/refusals, `<redacted>` present |
| `token_generation_uses_fresh_entropy_and_expiry_is_inclusive` | two tokens differ, boundary at `expires_ms`, `used` state |

`cargo clippy -p zero-daemon-app --all-targets -- -D warnings` is clean.

### Known limits

- The shell does not launch the webview or probe the installed runtime: it
  selects the engine from the build target (`webview_for_platform()` is a
  compile-time mapping) and the host opens `url_with_token()`. A machine missing
  the runtime surfaces that when the host opens the window, and the guidance in
  `WebviewKind::install_guidance()` is the remedy.
- One token authorizes one request, so a page refresh needs a new URL
  (`issue_token()`). The page itself is complete because the snapshot is inline.
- The listener speaks plain HTTP on loopback; there is no TLS, because the
  traffic never leaves the host.
- There is no long-poll or event stream yet: the page renders the snapshot its
  token authorized, and the host serves a new page for new state.
- The server is one connection at a time by design; a busy local UI would need a
  second worker reading from the same listener, which this slice does not add.
