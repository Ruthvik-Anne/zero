# M6 evidence

M6 covers web tools, MCP, doctor, monitors, and security review. Two slices are
implemented so far; the rest of the milestone is open.

## Web search and fusion — T-WEB-01 (done)

`zero-web` now has a keyless adapter contract and reciprocal-rank fusion
(WEB-01, WEB-02). `search` runs every healthy engine in parallel with
`std::thread::scope`, collects outcomes in caller order for deterministic
output, and turns a failed or panicking engine into one `SearchError` without
failing the search. `fuse` is the pure fusion step for cached or replayed
rankings. Fusion uses `k = 60`, merges duplicates by canonical host+path or by
normalized title (title keys shorter than eight characters are ignored so
generic headings do not collapse across hosts), keeps the fields of the
best-ranked hit, sums duplicate scores, and retains every contributing
engine rank as provenance.

| Test | Covers |
|---|---|
| `three_engine_fixture_fuses_by_reciprocal_rank` | Three engines, expected RRF order and scores, merged sources. |
| `duplicate_urls_merge_into_one_result` | Scheme/query/fragment/`www` normalization. |
| `fuzzy_titles_merge_when_urls_differ` | Fuzzy title dedupe. |
| `short_generic_titles_do_not_collapse_across_hosts` | Ambiguous short titles stay separate. |
| `failed_engine_is_reported_without_failing_search` | Per-engine error isolation. |
| `unhealthy_engine_is_skipped` | Health check. |
| `empty_query_and_zero_limit_return_no_results` | No engine is consulted. |
| `canonical_url_key_normalizes_noise`, `title_normalization_ignores_punctuation_and_case`, `fuse_respects_limit_and_empty_input` | Key construction and limit handling. |

Command: `cargo test -p zero-web`.

## Filters and provenance — T-WEB-02 (done)

`filter::apply` narrows a fused response without touching scores or order and
attaches a `Provenance { published, age_days, source }` to every survivor
(WEB-03, WEB-04). Filters are ANDed: freshness (Day/Week/Month/Year), include
and exclude domains (host or subdomain; exclusion wins), categories
(`docs`/`code`/`news`/`general` by a documented URL rule), and required or
forbidden substrings over title+snippet. Freshness is fail-closed: an absent or
unparseable date is dropped when a window is set. Dates accept `YYYY-MM-DD` and
RFC 3339 with an explicit offset; everything else yields `age_days: None` and
`source: unknown` rather than a guess.

| Test | Covers |
|---|---|
| `filter_matrix_keeps_exactly_the_expected_urls` | 19 table-driven cases: every filter alone and combined, fail-closed dates, exclude-over-include. |
| `filtering_preserves_scores_and_order` | Fusion fields and order are untouched. |
| `provenance_records_age_and_date_source` | Age, raw value, and source for parseable, unparseable, and absent dates. |
| `future_dates_clamp_to_age_zero`, `freshness_windows_are_documented_days` | Clock skew and window constants. |
| `timestamp_parser_accepts_only_documented_forms` | Accepted formats and 19 rejected forms. |
| `category_classification_follows_documented_rule`, `canonical_host_normalizes_www_and_ports` | Category and host rules. |

Command: `cargo test -p zero-web` (18 tests).

## Doctor binary — T-DOC-01 (done)

`zero-doctor` is a separate executable with a plugin-free core. `run_core`
returns `DoctorReport { version, independent, daemon, checks }` and never
imports `zero-daemon` or opens a socket; `daemon` starts as `not_contacted`.
The binary supports `--json`, `--version`, and `--help`, and exits zero.

| Test | Covers |
|---|---|
| `runs_with_the_daemon_dead_and_says_it_was_not_contacted` | Dead daemon socket paths; exit 0; no socket created. |
| `json_report_is_independent_and_never_contacted_the_daemon` | JSON contract: `independent: true`, `daemon: "not_contacted"`, empty checks. |
| `version_flag_prints_the_version_without_a_daemon` | Version path needs no daemon. |

Commands: `cargo test -p zero-doctor`, `cargo clippy -p zero-doctor
--all-targets -- -D warnings`.

## Cache and resilience — T-WEB-03 (done)

`zero-web` now has a SQLite/FTS5 search cache and a resilience layer
(WEB-05, WEB-06). `SearchCache` stores whole `SearchResponse` payloads under a
`(query, category)` key with per-category TTLs and an optional tighter
cache-age limit, mirrors titles/snippets into an FTS5 table for later local
search, deletes expired entries, treats corrupt payloads as a miss, and
returns `zero.fnd.unsupported` when the running SQLite lacks FTS5 instead of
panicking. `ResilientSearch` adds a per-engine rate limit, capped exponential
backoff, a three-state circuit breaker, a reserve engine used only when no
primary answers, and CAPTCHA/login benching: a refusal excludes the engine for
the cooldown, is not reported as a failure, and does not fail the search.

| Test area | Evidence |
|---|---|
| Cache | 16 tests: round trip, expiry, per-category TTL, cache-age rejection, category invalidation, FTS5 search, reopen persistence. |
| Resilience | 17 tests: breaker open/half-open/close, capped backoff, rate window, reserve fallback, panic isolation. |
| Benching | A "captcha" refusal from one engine still returns the other engine's results, stays out of `failed`, and `benched` clears after the cooldown. |

Commands: `cargo test -p zero-web` (51 tests + 1 doc test), `cargo clippy
-p zero-web --all-targets -- -D warnings`.

## MCP core client — T-MCP-01 (done)

`zero-mcp` now has a stateless JSON-RPC 2.0 client over an in-memory
`Transport` seam (MCP-01..05): strict envelope validation, request-id echo,
typed JSON-RPC error mapping, revision negotiation for `2025-11-25` and
`2026-07-28`, case-insensitive routing headers, `initialize` / `tools/list` /
`tools/call`, `resultType` handling, a per-server/revision `tools/list` cache
with TTL and schema-hash invalidation, and bounded schema validation (64 KiB,
depth 32, 4096 nodes) with a deterministic schema hash. Two JSON fixtures cover
both revisions.

| Test area | Evidence |
|---|---|
| Envelopes and errors | `cargo test -p zero-mcp` unit tests: malformed envelope, id mismatch, both `result` and `error`, JSON-RPC code mapping. |
| Revisions and resultType | `2025-11-25` treats every result as complete; `2026-07-28` reads `complete` / `input_required` / unknown passthrough. |
| Caching | Second `tools/list` does not touch the transport; TTL, `ttlMs == 0`, invalidation, and schema-change refresh. |
| Schema bounds | Oversize, too-deep, and over-node schemas fail with typed errors; names cannot be empty. |
| Fixtures | `tests/core_client.rs` (14 integration tests) against `tests/fixtures/2025-11-25.json` and `2026-07-28.json`. |

Commands: `cargo test -p zero-mcp` (27 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings`.

## MCP transports — T-MCP-02 (done)

`zero-mcp` now ships the stdio and Streamable HTTP transports (MCP-02, MCP-06,
MCP-17). `StdioTransport` launches a child with a scrubbed environment (the
`KEY`/`TOKEN`/`SECRET`/`PASSWORD`/`CREDENTIAL` policy, with agent sockets
exempt), speaks newline-delimited JSON-RPC with an 8 MiB line bound and a
30 s request timeout, skips notifications and non-JSON log lines while matching
ids, keeps a bounded redacting stderr tail, and kills/reaps on timeout or drop.
`HttpTransport` POSTs to an http/https URL with `Content-Type`,
`Accept: application/json, text/event-stream`, configured routing headers, and
the server's `Mcp-Session-Id`, then accepts either a JSON body or an SSE body.
The legacy HTTP+SSE shim is not the default and `connect` refuses it with
`zero.fnd.unsupported`. The stdio test respawns the test binary as a helper
child, proving scrubbing and framing without an external runtime.

| Test area | Evidence |
|---|---|
| stdio | Helper-process initialize and tool call; a fake secret variable is absent inside the child; timeout returns `zero.fnd.timeout` and kills; drop reaps. |
| HTTP | Loopback JSON response, SSE `data:` response, session-id propagation, non-2xx status without body echo. |
| Legacy | `LegacyHttpSse` is refused when selected. |

Commands: `cargo test -p zero-mcp` (43 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings`.

## MRTR and elicitation — T-MCP-03 (done)

`zero-mcp` now implements multi-round-trip requests and elicitation (MCP-03,
MCP-07, MCP-08). `tools_call_outcome` returns `Complete`, `InputRequired`, or
`Other`; `retry_with_inputs` re-sends the same tool call once with
`inputResponses` and the exact opaque `requestState` under a new JSON-RPC id,
and a second `input_required` is returned rather than looped. No stream is held
open between attempts, a mixed complete/input-required result is a protocol
error, and the older revision always yields `Complete`. Form-mode elicitation
refuses credential-like fields (password, passphrase, token, API key/secret,
private key, cookie, session, OTP, PIN/passcode, seed phrase, mnemonic,
recovery code, CVV, `format: password`, `writeOnly`) with `zero.pol.denied`
before any response is built. URL mode is returned as a host `HostAction`; the
client never opens, follows, or submits it, and acceptance requires matching
host approval.

| Test area | Evidence |
|---|---|
| MRTR | 8 `tests/mrtr.rs` cases: retry shape, one-retry limit, second input_required, mixed result, malformed shapes, revision behavior. |
| Credential refusal | Form password/token fields fail with `zero.pol.denied` and no wire retry. |
| URL mode | Host action names the exact URL; acceptance without approval is refused. |

Commands: `cargo test -p zero-mcp` (54 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings`.

## MCP task lifecycle — T-MCP-04 (done)

`zero-mcp` now implements the task extension (MCP-04, MCP-09): `tasks/get`,
`tasks/update` with `inputResponses`, and `tasks/cancel`, plus task parsing for
`working`, `input_required`, `completed`, `failed`, `cancelled`, and unknown
states. `resultType: "task"` from `tools/call` now yields
`ToolCallOutcome::Task`, so a tool can create a task and `poll_until_done` can
drive it to completion end-to-end. Polling uses an injected sleeper, honours a
changing `pollIntervalMs`, caps sleeps against the TTL/budget, and stops on any
non-working state. Task IDs are bearer secrets: `Debug`/`Display` are always
`[redacted]`, raw access is explicit, and ids are scrubbed from errors,
`statusMessage`, and unknown statuses. The older revision never yields a task.

| Test area | Evidence |
|---|---|
| Lifecycle | 14 `tests/tasks.rs` cases: work → input_required → update → completed, cancel, failure, TTL expiry, poll intervals. |
| End to end | `tools_call_task_result_is_polled_to_completion`; `older_revision_never_yields_a_task_outcome`. |
| Secrecy | Raw id absent from `Debug`, `Display`, and every error message, including server errors that echo it. |
| Shapes | Malformed tasks are `zero.prv.protocol`; unknown states are preserved; unsupported revisions are typed. |

Commands: `cargo test -p zero-mcp` (70 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings`, `cargo doc -p zero-mcp --no-deps` (no warnings).

## SSRF and egress — T-WEB-09 (done)

`zero-web` now has an egress guard (WEB-16, WEB-17): scheme refusal
(`http`/`https` only), userinfo rejection, full address classification
(loopback, RFC 1918, CGNAT, link-local, metadata, multicast, unspecified,
broadcast, ULA, reserved), DNS-rebinding-safe checking of every resolved
address, pinned destinations so the fetch layer cannot re-resolve, redirect
re-checks with a budget and HTTPS→HTTP downgrade refusal, and secret checks over
URL, header values, and body without echoing the value. `Offline` denies
everything; `Restricted` allows public HTTP(S) only; `Full` additionally allows
private and loopback targets but still blocks metadata, link-local, multicast,
reserved, and non-HTTP(S) schemes. IPv4-mapped, IPv4-compatible, 6to4, Teredo,
and NAT64 forms are classified through their embedded address or refused.

| Test area | Evidence |
|---|---|
| Address matrix | 19 fixtures: metadata (v4/v6/hostname), loopback, private, link-local, ULA, multicast, unspecified, broadcast, reserved. |
| Pinning and redirects | Any forbidden resolved address rejects; redirect to private/metadata/downgrade refused; budget enforced. |
| Schemes and secrets | `file`/`javascript`/`data` and userinfo refused; secrets in URL/header/body refused without echoing. |
| Modes | Offline, Restricted, and Full behavior differ exactly as documented. |

Commands: `cargo test -p zero-web` (70 tests + 1 doc test), `cargo clippy
-p zero-web --all-targets -- -D warnings`. The fetch layer (T-WEB-04) must call
`check_request` and connect only to the pinned addresses.

## Doctor checks — T-DOC-02 (done)

The doctor core now runs 13 named checks over an injectable `DoctorContext`:
versions, config, keys, workers, kernel, auth, network, mesh, ports, disk,
locks, journals, and MCP (DOC-02, DOC-03). Checks never contact the daemon or
the network: absent snapshots warn instead of inventing a pass, and key bytes,
tokens, and config values never appear in a detail. The binary keeps the same
report shape and exit code; `daemon` stays `not_contacted`.

| Check | Evidence |
|---|---|
| Shape and count | `report_lists_every_check` asserts the exact `CHECK_NAMES` list, so a check cannot silently disappear. |
| Each check | A pass and a failure fixture per check (warn where meaningful), in `crates/zero-doctor` unit tests. |
| Redaction | Details contain paths and counts, never key material or secret values. |
| Independence | `tests/independent.rs` still runs the binary with dead daemon paths and sees 13 checks. |

Commands: `cargo test -p zero-doctor` (53 tests), `cargo clippy -p zero-doctor
--all-targets -- -D warnings`.

Known limits, documented in `docs/doctor.md`: config validation is structural
(no TOML parser dependency), key permissions are checked on Unix only, disk/
ports/kernel/auth use injected snapshots, and mesh/worker/MCP checks validate
shape rather than performing live handshakes.

## Monitor engine — T-MON-02 (done)

`zero-agent` now has a monitor engine (MON-06, MON-13, MON-14). It spawns an
executable + argv (never a shell by default), merges and scrubs the child
environment (`KEY`/`TOKEN`/`SECRET`/`PASSWORD`/`CREDENTIAL`, agent sockets
exempt), streams stdout on reader threads into a bounded queue, sends stderr
only to a `LogSink` (never an event), and coalesces bursts by a monotonic
window, line count, byte count, or process exit. Bursts split rather than drop;
per-line overflow truncates with a marker; per-drain and queued-line caps drop
oldest with counters; `stop` kills/reaps and discards the final buffer (no
events after stop); natural exit flushes exactly once; muting drops events
without killing; an idle monitor emits nothing.

| Test area | Evidence |
|---|---|
| Burst (Done) | 5 unit + 10 self-spawn integration tests; 100 stdout lines + stderr produce far fewer events, all lines in order exactly once. |
| Streams | stderr only in the log sink; env secret absent inside the child; mute/unmute; stop kills; idle silence. |
| Caps | Per-line truncation marker, bounded queues with counted drops, per-drain cap, leftover retention. |

Commands: `cargo test -p zero-agent monitor` (15 tests), `cargo clippy -p
zero-agent --all-targets -- -D warnings`. Windows kills only the direct child;
no pty; stderr redaction is the sink's job.

## MCP code mode — T-MCP-12 (done)

`zero-mcp` now exposes MCP tools as a typed code API (MCP-20). From a
`ToolCatalog` it generates TypeScript interfaces/accessors and Python
`TypedDict`/function stubs for the supported JSON Schema subset, quoting or
bracketing invalid identifiers, prefixing/suffixing Python keywords and leading
digits, rejecting identifier collisions with both tool names, stripping control
characters from descriptions, and truncating whole entries at a byte cap. Two
server shapes are available: a single `code` tool whose description embeds the
declarations and an example, or `search` + `execute` for large catalogs. The
`CodeModeBridge` resolves sanitized accessors back to tools, enforces argument
size/depth, applies the existing risk matrix (read allow, write ask, destructive
ask/deny, unknown ask) with a host approval oracle, checks the replay guard,
caps responses, and records only tool names/decisions. `execute` caps program
size, bridge calls, and the final value, aborts on the first Ask/Deny even if an
executor swallows the error, and returns only the final value.

| Test area | Evidence |
|---|---|
| Generation | 20 code-mode tests: required/optional, enums, arrays, nesting, invalid identifiers, keyword/collision, control characters, truncation. |
| Done criterion | A scripted program makes two reads and one approved write, filters intermediate data, and returns only `{"total":5,"ok":true}`; the host saw exactly 3 calls. |
| Policy | Write Ask aborts without approval; destructive Deny under Restricted; approval proceeds; executor error swallowing cannot bypass the bridge refusal. |
| Caps/secrecy | Source/result/call/arg limits; replay refusal; declarations and errors contain no secrets. |

Commands: `cargo test -p zero-mcp` (224 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings` (`-j 1` under disk pressure). Unsupported schemas
(`$ref`, unions, tuples, >6 levels) fall back to `unknown`/`Any` with a comment;
Python assumes 3.11+; running model code in zero-kernel/IPython or an OS sandbox
remains a documented follow-up.

## MCP conformance — T-MCP-11 (done)

`zero-mcp` now ships a conformance fixture format and replay runner (MCP-11,
MCP-19). Two checked-in fixtures cover `2025-11-25` (initialize, tools/list,
complete call, resources/list, JSON-RPC error) and `2026-07-28` (resultType,
annotations/cache hints, structured content, input_required + retry, task
handle, prompts/list, error). The runner validates the fixture schema, rejects
unknown versions/revisions, zero exchanges, wrong request/response ids,
out-of-order methods, revision-mismatched responses, and undeclared
expectations, and returns per-exchange failures without panicking. The suite
runs under `cargo test -p zero-mcp`, so it gates CI.

| Test area | Evidence |
|---|---|
| Coverage | 8 conformance tests load every fixture and assert both revisions pass 100%. |
| Mutation | Bad expectation, wrong ids, unknown schema, zero exchanges, wrong revision, malformed JSON all fail typed. |
| CI | The suite is a normal crate test; no separate job needed. |

Commands: `cargo test -p zero-mcp` (204 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings` (run with `-j 1` under disk pressure).

## MCP server mode — T-MCP-10 (done)

`zero-mcp` can now expose tools, sessions, and events over MCP behind a flag
(MCP-10, MCP-15). `ServerConfig::default()` is disabled; `handle`/`handle_line`
refuse everything until enabled, and each capability flag gates its methods.
`McpServer` dispatches `initialize`, `tools/list`, `tools/call`, and the Zero
session tools `sessions/list`, `sessions/prompt`, `sessions/events` over the
crate's JSON-RPC envelopes against injectable `ToolHost`/`SessionHost` seams.
The server never touches credentials, and `sessions/prompt` is advertised with
`destructiveHint: true` so a client's default policy asks. Host errors map to
JSON-RPC codes with a stable `data.zeroCode`; host messages are never copied to
the wire. Requests are bounded (256 KiB, args 64 KiB/depth 32), results 1 MiB,
and live lists are capped; oversize data is rejected, not truncated.

| Test area | Evidence |
|---|---|
| Gate | Disabled server refuses all methods; enabling one capability exposes only it. |
| Done criterion | Editor flow: initialize → sessions/list → sessions/prompt → sessions/events returns the new event. |
| Safety | Destructive annotation drives `Ask`; host error payloads never reach the wire; bounds enforced. |
| Errors | `-32700/-32600/-32601/-32602/-32603` envelopes, wrong ids, malformed params. |

Commands: `cargo test -p zero-mcp` (196 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings`. The socket/stdio accept loop, resource/prompt
methods, and per-editor auth are deferred.

## MCP resources and prompts — T-MCP-09 (done)

`zero-mcp` now models resources and prompts (MCP-09, MCP-16). Resource and
prompt catalogs parse and reject duplicate names/URIs/arguments; `@name`,
`@server:name`, and `@<uri>` resolve by exact URI → exact name → unique
case-insensitive name → simple `{var}` template, and an ambiguous name lists
every candidate instead of picking one. `ResourceStore` persists catalogs as
schema-versioned JSON with atomic writes, so `@` references resolve after a
restart with the server offline; corrupt or stored-mismatch data is a typed
`zero.fnd.corrupt`, an unknown schema is `zero.fnd.schema_version`. Slash
commands parse `/name` with positional and `key=value` arguments, bind against
the prompt's arguments, and report missing/unknown/duplicate arguments; local
completions are case-insensitive, sorted, deduped, and capped at 100. A
`completion/complete` request/response model with an injectable transport is
included and documented as server-side follow-up.

| Test area | Evidence |
|---|---|
| References | 28 resource tests: all `@` forms, resolution order, ambiguity, templates, restart persistence, corrupt/version errors. |
| Slash/prompt | Parse, required/unknown/duplicate args, unknown command, binding. |
| Completions | Prefix/sort/dedupe/cap; request/response shapes. |

Commands: `cargo test -p zero-mcp` (125 lib + 63 integration tests), `cargo
clippy -p zero-mcp --all-targets -- -D warnings`. No quoting in slash arguments,
only level-1 RFC 6570 templates, and no pagination/`resources/read` yet —
documented.

## MCP security — T-MCP-08 (done)

`zero-mcp` now has the MCP security controls (MCP-08, MCP-14) as host policy
objects. `SchemaPinStore` records per-server tool schema hashes: first pin and
unchanged catalogs proceed, any added/removed/changed tool returns exactly
`ToolDecision::Ask`, and `require_approval` accepts only the exact new hash set
(empty/stale/partial/wrong-server approvals are denied). Tool risk defaults:
read-only allow, writes ask (auto may allow), destructive deny under Restricted
and ask otherwise, and unannotated tools always ask. `ResponseLimits` (1 MiB
content/structured, 1,024 items) and `TimeoutPolicy` (30 s request / 5 min
total, bounded maxima) reject without echoing payloads. A self-contained
`check_resource_url` blocks loopback/private/link-local/metadata and non-HTTP(S)
schemes, including IPv4-mapped and numeric/hex/octal forms. `ReplayGuard`
(4,096 ids, 10 min window) distinguishes fresh/replay/expired with FIFO
eviction.

| Test area | Evidence |
|---|---|
| Pinning | 24 security tests: New/Unchanged/Changed, description-only changes ignored, exact approval required, stale/wrong-server denied. |
| Done criterion | `a_changed_schema_is_changed_and_the_decision_is_exactly_ask`. |
| Risk/limits | Full risk matrix; oversize content/structured/items rejected; timeout bounds. |
| URL/replay | Metadata/loopback/private refusal; repeated id inside window rejected and expired id pruned. |

Commands: `cargo test -p zero-mcp` (160 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings`. DNS pinning, TLS pinning, cryptographic schema
signatures, cancellation, and wiring these policies into `Client`/transports are
documented as deferred.

## MCP auth — T-MCP-07 (done)

`zero-mcp` now has an OAuth 2.1 public-client flow (MCP-07, MCP-13): RFC 8414 →
OIDC discovery with a hard issuer-equality check, PKCE S256 only (RFC 7636
verifier rules, redacted verifier), authorization URLs carrying code flow,
exact redirect, state, and an RFC 8707 `resource` equal to the canonical MCP
server, code exchange and refresh with no client secret, and a token response
that must be Bearer with a matching resource. `AccessToken`/`TokenBinding`
validation rejects a wrong issuer, resource, client id, expected audience, or
expired token, and tokens never appear in `Debug`/`Display`/errors. The
`a_stolen_token_fails_on_another_server` fixture is the Done criterion: a token
minted for server A fails against server B and succeeds against A. CIMD is
primary: the client id must be an HTTPS URL with a path, metadata must be a
public client (`token_endpoint_auth_method=none`, `code`,
`authorization_code`), redirect URIs match exactly, and wildcards are refused.

| Test area | Evidence |
|---|---|
| Discovery/PKCE | 27 auth tests: discovery paths, issuer mismatch, RFC 7636 vector, S256-only, resource canonicalization. |
| Theft fixture | Wrong server/issuer/resource/client/audience/expiry all rejected; token values absent from errors. |
| CIMD | HTTPS+path client id, public-client metadata, exact redirect, wildcard refusal, bounded redirect count. |
| Exchange/refresh | Missing/blank token, non-Bearer, resource mismatch, rotated refresh token. |

Commands: `cargo test -p zero-mcp` (136 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings`. JWT/JWKS signature verification, RFC 9207 `iss`,
RFC 9728 resource metadata, DCR, and enterprise managed auth are documented as
deferred.

## MCP apps and extensions — T-MCP-06 (done)

`zero-mcp` now models untrusted MCP apps and extension negotiation (MCP-06,
MCP-11, MCP-12). `ui://` resources require an authority and reject other
schemes, userinfo, ports, queries, fragments, control characters, and raw or
percent-encoded dot/separator tricks before URL normalization. `AppFrame`
renders a sandbox of exactly `allow-scripts` (no same-origin, top-navigation,
popups, forms, downloads, or modals) with a CSP of `default-src 'none'`,
inline scripts/styles only, `connect-src 'none'`, `frame-ancestors 'none'`,
`base-uri 'none'`, `form-action 'none'`, and no `unsafe-eval`. HTML placed in
`srcdoc` escapes `& < > " '`, so a hostile `</iframe>` cannot break out. The
host navigation guard always refuses top-level, popup, download, `_top`,
`_parent`, `_blank`, javascript/data/file, and origin-mismatched intents;
extension negotiation ignores unknown optional extensions and reports a
required unknown one without failing.

| Test area | Evidence |
|---|---|
| App URI and escaping | 17 unit tests: authority rules, encoded traversal, hostile quote/tag breakout. |
| Sandbox/CSP | Exact token set; `allow-same-origin` and `unsafe-eval` absent; required directives present. |
| Navigation | Top-level/popup/form/download matrix; origin exact match; `window.open` rejected. |
| Extensions | Unknown optional ignored, required reported, malformed rejected, duplicates resolved. |

Commands: `cargo test -p zero-mcp` (109 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings`. Live browser enforcement and `ui/initialize`
are deferred to T-MCP-11.

## MCP events — T-MCP-05 (done)

`zero-mcp` now handles event delivery (MCP-05, MCP-10). Cursor polling advances
only on a batch with `next_cursor`; an expired or unknown cursor returns a typed
`ResyncRequired` and replays from the oldest event instead of silently skipping.
Each batch's `ttlMs` sets an expiry that `renew` can extend; polling a lapsed
lease returns `zero.prv.timeout` and requires `resubscribe`. Webhooks verify an
HMAC-SHA256 signature over the exact raw body in constant time (hex, optional
`sha256=` prefix), then check the timestamp replay window, then parse JSON, and
finally dedupe event ids in a 1024-entry FIFO. Missing/invalid signatures are
rejected before parsing; errors never include the signature, key, or body.
`HmacSha256Verifier` matches RFC 4231 cases 2 and 6.

| Test area | Evidence |
|---|---|
| Cursors and TTL | 17 `tests/events.rs` cases: order, advancement, resync, no-gap rule, TTL expiry/renew/resubscribe, attempt bound. |
| Signatures | RFC 4231 vectors; tampered body/key; missing headers; timestamp too old/future. |
| Replay | Duplicate id returns `Duplicate` without redelivery; FIFO eviction at the bound. |
| Secrecy | No signature, key id, key, or payload appears in an error; verifier/event `Debug` redacts payloads. |

Commands: `cargo test -p zero-mcp` (92 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings`. Durable cursors, push streaming, and the webhook
HTTP server are documented as deferred.

## Headless browser — T-WEB-05 (done)

`zero-web` now has a local headless-browser fallback (WEB-05, WEB-09).
`find_system_browser` checks the standard Chrome/Chromium/Edge paths per
platform with no PATH shell-out. `Installer` takes a versioned manifest and an
injectable `Downloader`, computes SHA-256 over the real downloaded file, refuses
a missing/mismatched checksum **before** extraction, installs via the archive
safety planner into a staging directory with an `install.json` record, and
never executes an installer or shell. Profiles are per-session
`--user-data-dir` directories under a confined root, empty on first use and
removed on close, so sessions never share cookies/cache. `HeadlessBrowser` runs
the browser headless with `--dump-dom`, a hard timeout and kill, output cap,
bounded stderr tail, and egress checks for http(s); `file:`/`data:` require an
explicit local allowance.

| Test area | Evidence |
|---|---|
| Done criterion | A real installed Chrome rendered a `file://` page whose DOM contained `rendered-by-js`; the test skips honestly when no browser exists. |
| Install | 14 headless tests: good/bad/missing checksum, zip-slip refusal, idempotent reinstall, no execution before checksum. |
| Profiles | Distinct per-session dirs, no shared files, close removes; root escape refused (Unix mode test). |
| Runtime | Launch args, timeout kill, output caps, env scrub, local-URL policy; `.cmd` launch on Windows documented. |

Commands: `cargo test -p zero-web` (235 tests + 2 doc tests), `cargo clippy
-p zero-web --all-targets -- -D warnings`. `status` is `None` under `--dump-dom`
(reserved for the CDP transport); subresource pinning remains CDP work.

## Browser automation — T-WEB-08 (done)

`zero-web` now drives a DevTools-protocol session through an injectable
`CdpTransport` (WEB-08, WEB-15): navigate with a bounded load-event wait,
click via a trusted mouse press/release at the node centre, type via
`Input.insertText`, bounded `wait_for` polling, `evaluate` with a 256 KiB
result cap and secret scan, PNG screenshot with strict base64 decode and an
8 MiB cap, and download with egress/redirect re-checks, path confinement,
`create_new` no-overwrite, and a 64 MiB cap. Session-assigned request ids are
verified; CDP errors map to `zero.prv.protocol` with a truncated message and
never echo params/data; every action has a timeout; `close` is idempotent.

| Test area | Evidence |
|---|---|
| Done flow | 22 browser tests: navigate → click → type → wait → screenshot, exact CDP method/params and decoded bytes. |
| Safety | Wrong id, CDP error, missing node, timeout, oversized screenshot/evaluate, egress refusal, download escape/overwrite. |
| Events | Load events arriving before the response are consumed without id confusion. |

Commands: `cargo test -p zero-web` (221 tests + 2 doc tests), `cargo clippy
-p zero-web --all-targets -- -D warnings`. The production WebSocket transport
and browser install/supervision are deferred (WEB-09).

## Fetch reader — T-WEB-04 (done)

`zero-web` now reads fetched content into Markdown (WEB-04, WEB-08, WEB-10).
Format detection uses extension/content-type, magic bytes, ZIP container paths,
and a NUL/invalid-UTF-8 binary check. HTML reader mode prefers the first
`<article>`/`<main>`, drops nav/header/footer/aside/script/style/noscript/
template/svg, and converts headings, paragraphs, lists, pre/code, blockquote,
hr, links, images, and simple tables to Markdown, collecting links. Markdown/
text/code pass through; CSV becomes a pipe-escaped table; JSON becomes a pretty
fenced block. DOCX, PPTX, XLSX, and EPUB are parsed through the validated ZIP
planner (document.xml, slide order, shared strings/worksheets, container→OPF→
spine) with entry/count/ratio bounds. PDF text is extracted page by page with
`lopdf` 0.47 (pure Rust, no C bindings), with encrypted PDFs returning a typed
`Unsupported`. Every path enforces input/output/tag/page caps and reports
truncation.

| Test area | Evidence |
|---|---|
| Fixture corpus | 23 reader tests: HTML with nav/script/article, Markdown, CSV, JSON, code, DOCX, XLSX, PPTX, EPUB spine order, hand-built PDFs. |
| Safety | Zip-slip and compression-bomb refusal via the archive planner; binary rejection; encrypted PDF refused. |
| Caps | Input/output/tag/page/row bounds and truncation flags. |

Commands: `cargo test -p zero-web` (199 tests + 2 doc tests), `cargo clippy
-p zero-web --all-targets -- -D warnings`. HTML is a tokenizer (no DOM repair/
CSS), PDF is text-only (no OCR), and office styling/merged cells are not
rendered — documented.

## Map and extract — T-WEB-07 (done)

`zero-web` now maps URLs and extracts structured data against a caller schema
(WEB-07, WEB-13, WEB-14). `map_urls` discovers seed-page links and sitemap
`<loc>` entries without fetching every page, resolves relatives, keeps the seed
host (optionally subdomains), dedupes with `canonical_url_key`, applies URL and
per-page limits, sorts deterministically, and reports counts per source. The
schema subset covers `type`, `properties`, `required`, `items`, `enum`, string/
number limits, `maxItems`, and `additionalProperties`, with depth/node bounds
and typed JSON-path errors. Extraction maps JSON keys or HTML `<title>`, meta
tags, links, and `data-zero-field` elements, decodes entities, ignores
script/style, and re-validates the whole object: a schema violation is an error,
never a partial result.

| Test area | Evidence |
|---|---|
| Schema | Type/required/enum/limit/array/object cases, malformed schemas, depth/node bounds, JSON paths. |
| Extraction | JSON nested/arrays/optional missing; HTML meta/title/data-field/href; entity decode; script/style ignored; input bounds. |
| URL map | Sitemap+links, relative resolution, canonical dedupe, host filter, limits, deterministic order. |
| Done criterion | `invalid_extraction_returns_the_typed_error_and_valid_one_revalidates`. |

Commands: `cargo test -p zero-web` (176 tests + 2 doc tests), `cargo clippy
-p zero-web --all-targets -- -D warnings`. The HTML reader is a bounded
tokenizer, not a DOM: no CSS selectors, DOM repair, `<base>`, or charset
decoding.

## Crawl — T-WEB-06 (done)

`zero-web` now runs persistent, resumable crawls (WEB-06, WEB-11, WEB-12). A
`CrawlJob` is stored as schema-versioned JSON and rewritten atomically after
every transition; it holds the frontier, seen set, completed/failed results,
robots-blocked list, retry attempts, and state. The engine is BFS with
canonical URL dedupe, depth/page/byte limits, and path allow/deny globs (prefix,
`*`, trailing `$`; no regex). `robots.txt` parsing supports groups, `Allow`/
`Disallow`, `*`/`$` wildcards, longest-match with allow-on-tie, and global
`Sitemap` collection; sitemap `<loc>` scanning decodes entities and expands a
sitemap index one level. Retries use exponential backoff against an injected
clock and end in `failed`; CAPTCHA/login responses become `robots_blocked`, not
failures; `cancel` stops further fetches. Progress and paging cover the three
result lists separately.

| Test area | Evidence |
|---|---|
| Frontier | BFS order/depth, canonical dedupe, page/byte limits, path matcher, relative links. |
| robots/sitemaps | Allow/disallow/longest/tie/group selection, entity decoding, index depth-1, 4xx allow / 5xx deny. |
| Retries/status | Backoff, exhaustion, failure list, robots-blocked separate, CAPTCHA 403/429, cancel. |
| Resume | 24 crawl tests including kill-and-resume: reload serializes byte-for-byte and every page is fetched exactly once. |

Commands: `cargo test -p zero-web` (133 tests + 2 doc tests), `cargo clippy
-p zero-web --all-targets -- -D warnings`. The matcher is regex-free; robots
group matching is case-insensitive substring, and nested sitemap indexes are
not expanded further.

## Archive safety — T-WEB-10 (done)

`zero-web` now inspects and extracts ZIP archives safely (WEB-10, WEB-18) using
`zip` 9.7.3 with the pure-Rust zlib backend. `inspect` walks the central
directory without extracting and refuses the whole archive on: entry-count,
total/per-entry size, compression-ratio, path-depth, absolute/drive/UNC/
backslash/NUL paths, dot-segment traversal, symlinks or any non-regular Unix
type, encrypted entries, unsupported methods, duplicate or case/alias-colliding
names, and file/directory conflicts. `extract` re-checks every path before use,
refuses to overwrite, counts actual decompressed bytes and ratio (a declared
size may lie), never follows links, writes only under the destination, and
cleans up partial output inside the destination on failure. Tests generate
their fixtures at runtime, plus a mutated-header corpus that must return typed
errors rather than panic.

| Test area | Evidence |
|---|---|
| Traversal | Zip-slip, absolute, drive/UNC, backslash, NUL, encoded dot segments. |
| Links and types | Symlink and non-regular Unix modes refused; no link is ever created. |
| Bombs | Declared and actual byte/ratio limits; entry count; depth. |
| Robustness | 20 archive tests including a mutated central-directory corpus; extraction cleanup. |

Commands: `cargo test -p zero-web` (109 tests + 2 doc tests), `cargo clippy
-p zero-web --all-targets -- -D warnings`.

## Budgets and untrusted content — T-WEB-11 (done)

`zero-web` now has crawl/search budgets and the untrusted-content envelope
(WEB-11, WEB-19, WEB-21). `CrawlBudget::reserve` checks pages, bytes, cost, and
requests before charging; a denial leaves the spend unchanged, `Some(0)` denies
every page, `None` is unlimited, exact-boundary reservations succeed, and
counter overflow is a typed `LimitExceeded` instead of a wrap. A page reserves
its estimate before the fetch, matching "account before starting".
`UntrustedContent::render_for_prompt` emits a fixed warning and a
`<untrusted-data source="…">` envelope, escaping `<`, `>`, and `&` in the body
so a payload cannot close the envelope or inject a tag, escaping the source
attribute, preserving newline/tab, and truncating at 256 KiB with an explicit
marker.

| Test area | Evidence |
|---|---|
| Budget | 19 fixtures: each dimension, zero/unlimited, failed reservation leaves spend unchanged, exact boundary, overflow. |
| Envelope | Stable label, exact tag shape, breakout payload escaped (`</untrusted-data>` becomes text), quote/control escaping, truncation marker, empty body. |

Commands: `cargo test -p zero-web` (89 tests + 2 doc tests), `cargo clippy
-p zero-web --all-targets -- -D warnings`.

## Review fixture suite — T-SR-07 (done)

`zero-review` now has three end-to-end fixture runs (SR-07, SR-11, SR-12):
vulnerable, clean, and partial repositories built at runtime, driven through
seed → hunt → critic → independent validation → report. The vulnerable repo
confirms exactly three findings (high/high/medium, none above demonstrated
impact) with fingerprints; the clean repo confirms zero and refutes the units
(no false positive); the partial repo runs 2 of 3 units, blocks one, marks the
run `partial: true`, and puts both unreviewed units in NEEDS-VALIDATION and the
coverage gaps. Golden projections keep only stable fields (ids, titles,
severities, counts, partial flag, gap unit ids), update via
`UPDATE_REVIEW_GOLDEN=1`. A carried confirmation is fingerprint-stable until a
byte edit, then moves `confirmed → deferred` and appears in NEEDS-VALIDATION
instead of REPORT.

| Test area | Evidence |
|---|---|
| Three golden runs | `tests/fixture_suite.rs` (4 tests) + three small JSON snapshots. |
| Clean run | Zero confirmed, units refuted, no coverage gap. |
| Partial run | Budget/blocked units and vendor exclusions reported, never silently covered. |
| Re-verification | Fingerprint edit defers a carried confirmation and clears its baseline. |

Commands: `cargo test -p zero-review` (85 lib + 4 fixture tests), `cargo clippy
-p zero-review --all-targets -- -D warnings`. The golden projection cannot see
changes that leave every projected field identical; unit ids are content-derived.

## Independent validation — T-SR-04 (done)

`zero-review` now has an independent validation phase (SR-04, SR-05, SR-07).
`Verifier` labels must be unique and differ from the hunter/critic/system actors;
`ValidationWave` requires a configurable quorum (default 2 of 3) with zero
rejections and zero needs-evidence before confirming, otherwise the unit is
deferred. `EvidenceVerifier` re-reads the target read-only, checks every ref is
inside the unit paths and line-bounded, and rejects a candidate whose cited
lines do not contain the expected sink marker — the false-positive path. Every
confirmed unit gets a content fingerprint (canonical refs + file length + first
64 KiB); `check_fingerprints` defers a changed unit instead of carrying its
confirmation (SR-11), and a confirmed unit with no baseline is deferred
fail-closed. Severity is kept only for confirmed findings, capped at
demonstrated impact, and reduced with a recorded reason otherwise.

| Test area | Evidence |
|---|---|
| True positive | Two verifiers confirm a cited sink; unit Confirmed, severity kept. |
| Done criterion | False positive (sink absent or file changed) is rejected/refuted with no finding. |
| Quorum | Disagreement defers, below-quorum does not confirm, same-label verifier refused. |
| Fingerprint | Stable after no change; a byte edit invalidates a carried confirmation to Deferred. |
| Severity | Above-impact reduced with reason; unconfirmed forced to info. |

Commands: `cargo test -p zero-review` (85 tests), `cargo clippy -p zero-review
--all-targets -- -D warnings`. Edits beyond the 64 KiB fingerprint window are
caught only by length; documented.

## Hunting waves — T-SR-03 (done)

`zero-review` now runs coverage-led hunting waves (SR-04, SR-05). A
`CandidateFinding` must name a lower-trust principal, a crossed boundary
matching the unit, at least one canonical evidence ref inside the unit's paths,
and a concrete result; severity is bounded by the demonstrated impact. The
`HuntAgent`/`AgentPool` and independent `Critic` seams are injectable, agent
errors mark a unit `Blocked` without failing the wave, critic `Accept` confirms
(and records the transition), `Reject` refutes with a reason, and
`NeedsEvidence` defers for NEEDS-VALIDATION. Budget/agent caps stop the wave
before exceeding.

| Test area | Evidence |
|---|---|
| Planted bug | Seeded fixture with `Command::new(user_input)`, scripted agent + critic: finding `FND-1`, unit `Confirmed`, pending→assigned→reviewed→confirmed history, report derives consistently. |
| Evidence bar | 11 hunt tests: missing principal, off-unit evidence, boundary mismatch, critical without result, critic reject/needs-evidence. |
| Limits | Unit/agent caps; hunter/critic label collision refused before mutation; agent error blocks only its unit. |

Commands: `cargo test -p zero-review` (75 tests), `cargo clippy -p zero-review
--all-targets -- -D warnings`.

## Review reports — T-SR-06 (done)

`zero-review` now derives the report set from records only (SR-06, SR-14). After
validating the ledger, findings, refs, ids, timestamps, and budget invariants,
`derive` writes `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, and
re-validated copies of `findings.json`/`coverage-ledger.json`. REPORT contains
only confirmed findings plus counts, profile/partial flag, coverage gaps, and
budget gaps; DETAIL carries confirmed findings with unit, severity, canonical
evidence, checks, and transition history; NEEDS-VALIDATION lists every
unconfirmed unit/finding with its status. Ordering is by id and timestamps come
only from the inputs. A structural consistency check parses the generated
Markdown and compares ids/severities/counts to the JSON before anything is
published, so prose and JSON cannot silently diverge.

| Test area | Evidence |
|---|---|
| Derivation | 5 report tests: five files, confirmed-only REPORT/DETAIL, all unconfirmed in NEEDS-VALIDATION. |
| Done criterion | `consistency_report`/`assert_consistent`; a mutated Markdown id is detected. |
| Safety | Invalid refs/ids/severity refused before `out_dir` is created; JSON copies re-validated. |
| Determinism | Same inputs produce byte-identical files; budget/partial flags appear. |

Commands: `cargo test -p zero-review` (64 tests), `cargo clippy -p zero-review
--all-targets -- -D warnings`. The consistency check is structural, not
semantic; scoped-run state must be supplied via budget/profile.

## Review ledger schema — T-SR-02 (done)

The review ledger now has a canonical schema (SR-02, SR-03, SR-06, SR-13).
`CanonicalRef` accepts `path:line[:col]` or `AA-01` requirement ids, rejecting
absolute/drive/UNC paths, backslashes, control characters, `.`/`..`, empty
segments, and bad line/column numbers; with a root, path refs must resolve to an
existing regular file under it, and a unit may not repeat a ref. Each unit has
an append-only history with a strict transition matrix
(`Pending → Assigned → Reviewed → Confirmed/Refuted`, note-gated
`OutOfScope`/`Deferred`/`Blocked`, no reopening a terminal unit); `advance`
rejects illegal transitions, missing notes/actors, and backwards time, and
validation rejects non-monotonic or from/to-mismatched history. Quick/Standard/
Deep profiles carry phase sets and budgets; any scoped run is labeled partial,
and a budget-trimmed full run reports both counts. `findings.json` and
`coverage-ledger.json` validators reject unknown schema versions, duplicate ids,
orphan units, empty/duplicate evidence, status/confirmed drift, and unconfirmed
severity above info.

| Test area | Evidence |
|---|---|
| Refs | Grammar and root checks; duplicates in a unit; canonical formatting. |
| History | Transition matrix, missing notes/actors, backwards time, from/to mismatch, terminal states. |
| Profiles | Phase sets, budgets, partial labeling for scoped and trimmed runs. |
| Output | Ledger/findings JSON validation incl. orphan unit and unconfirmed severity. |

Commands: `cargo test -p zero-review` (59 tests), `cargo clippy -p zero-review
--all-targets -- -D warnings`. Case-only path duplicates on Windows and
filesystem-checked finding refs are documented gaps.

## Security review ledger — T-SR-01 (done)

`zero-review` now seeds a coverage ledger (SR-01..03). The mode gate returns
guidance (recon + output) for a plain question and only plans audit phases when
the user explicitly asks for an audit/full review/report artifacts. Seeding
walks a bounded fixture tree, classifies surfaces/subsystems, detects trust
boundaries and attack classes from source markers (process spawn, path I/O,
network clients, deserialization, SQL, secrets, `unsafe`, permissions), and
emits one unit per `(surface, boundary, subsystem, attack class)` with canonical
`path:line` refs, starting paths, companions/exclusions with reasons, checks,
and a deterministic fingerprint. Exclusions are recorded, never dropped.
Validation rejects duplicate ids/tuples, empty refs/checks/fingerprints, missing
owners or reviewed paths, exclusion overlaps, `out_of_scope` counted as covered,
summary mismatches, and unknown schema versions; assignment validates first.

| Test area | Evidence |
|---|---|
| Seeding | A fixture repo with parser/shell/file/network/secret code yields the expected boundaries and classes. |
| Done criterion | The fixture ledger validates; 29 tests cover duplicates, bad refs, overlaps, out_of_scope, summaries. |
| Mode gate | Guidance never includes hunt/validation phases; audit requires an explicit request. |
| Determinism | Two seeds of the same tree produce identical ids/fingerprints; caps report truncation. |

Commands: `cargo test -p zero-review` (29 tests), `cargo clippy -p zero-review
--all-targets -- -D warnings`. Markers are heuristics: hits are review
evidence, never findings.

## Doctor agent API — T-DOC-06 (done)

The doctor exposes `diagnose`, `plan`, and `apply` to the agent (DOC-06,
DOC-08) and enforces a turn gate. `plan` maps only checks with a safe repair
(config with a backup, stale locks, missing journal directories) and refuses
everything else by name; deletion requires policy permission at plan time.
`apply` delegates to the reversible repair engine, and dry-run plans refuse
before mutation. `finish_turn` requires every failing check to appear in the
turn report with the right stable code and playbook, or to be resolved by an
actually applied action; a hidden failure returns `zero.pol.ask` naming the
check, and unknown checks, blank/oversized/secret-looking summaries, fabricated
resolutions, wrong check counts, and code mismatches are rejected.

| Test area | Evidence |
|---|---|
| Tools | `diagnose` returns 13 checks; `plan` covers only safe repairs and refuses the rest; dry-run does not mutate. |
| Gate | 18 `agent_api` tests: hidden failure refused, correct report accepted, fabricated resolution refused, unknown check/wrong code refused, wrong check count refused. |
| Apply | Delegates to repair with rollback; `actions_taken` must match the applied action. |

Commands: `cargo test -p zero-doctor` (105 lib + 3 integration tests), `cargo
clippy -p zero-doctor --all-targets -- -D warnings`. The gate is structural,
not cryptographic: the host must pass the report from `diagnose`.

## Forensics — T-DOC-05 (done)

The doctor can now build a timeline and a redacted offline bundle (DOC-05,
DOC-07, OBS-07). The timeline folds JSONL or tab-separated artifacts into a
deterministically ordered, de-duplicated event list, counts malformed lines
without echoing them, bounds at 10k events, and reports drops. `build_bundle`
writes a self-contained directory (`manifest.json`, `timeline.jsonl`,
`files/…`) with `offline: true`, `network: "none"`, per-file sizes and FNV-1a
hashes. It excludes vault/keys/credential paths, `.env*`, `*.enc`, `*.pem`,
`*.key`, caller redaction values, symlinks, outside-root paths, and binaries;
it scrubs PEM blocks, strong token prefixes, and caller values from every text
file and from skipped-path labels, and reports every skip rather than truncating
silently.

| Test area | Evidence |
|---|---|
| Timeline | JSONL/tab parsing, ordering, exact-repeat dedupe, bounds, malformed count, redaction re-sort. |
| Exclusions | Vault/key/credential/.env/enc/pem paths, symlink escape (Unix), outside root, binary. |
| Redaction | Injected caller values, `sk-`/`ghp_`/`oc_sk_`/`AKIA`, PEM block: absent from every bundle file. |
| Caps | Per-file/total skip with reasons; no silent truncation; deterministic manifest. |

Commands: `cargo test -p zero-doctor` (87 lib + 3 integration tests), `cargo
clippy -p zero-doctor --all-targets -- -D warnings`. Redaction is pattern-based,
not a guarantee for unknown secret formats; the hash is non-cryptographic.

## Repair — T-DOC-04 (done)

The doctor can now execute reversible repairs (DOC-04..06, DOC-10). A
`RepairPlan` carries stable-id actions (create dir, write/rotate/repair files,
move to trash, remove stale lock); `RepairPolicy` requires absolute paths inside
canonical allowed roots, rejects `.`/`..` and symlink escapes (nearest-existing
ancestor and final symlink), gates deletion, and caps plan size. `dry_run`
validates the whole plan and previews changes without touching the tree.
`apply` validates everything before the first mutation, snapshots existing
files, records inverses, and on any failure rolls back in reverse and reports
that rollback happened. Repeated apply is idempotent; a round-tripped report
refuses rollback because the inverse log is process-local.

| Test area | Evidence |
|---|---|
| Dry-run | Preview leaves the tree byte-identical; policy violations rejected up front. |
| Rollback | Injected failure restores original bytes; explicit rollback reverses every action. |
| Policy | Outside-root, `..`, symlink escape, delete without `allow_delete`, and too many actions refused. |
| Idempotency | Second apply reports already-applied with no changes. |

Commands: `cargo test -p zero-doctor` (75 lib + 3 integration tests), `cargo
clippy -p zero-doctor --all-targets -- -D warnings`. Two Unix-only cases
(symlink escape, mode restore) run only on Unix; syscall-level disk-full
injection is documented as not exercised.

## Playbooks — T-DOC-03 (done)

Every stable `ErrorCode` (75 today) now has a doctor playbook (DOC-03, DOC-04,
DOC-11): a distinct title, 1–3 symptoms, 2–5 ordered safe steps, the stable
remediation line, and an escalation note where the user must take over.
`playbook(code)` is an exhaustive `match`, so adding a code without a playbook
fails to compile; `all()` follows `ErrorCode::ALL` order; `triage(&ZeroError)`
selects by the stable code only. A destructive-action guard rejects
`rm -rf`/`del /f`/`format`/`drop database`-style steps, and a test asserts the
injected error message never leaks into playbook text.

| Test area | Evidence |
|---|---|
| Coverage | `every_error_code_has_exactly_one_playbook` over `ErrorCode::ALL` (75/75). |
| Fault injection | `triage_uses_the_injected_error_code` constructs one `ZeroError` per code; `remediation_matches_the_stable_code_line`. |
| Safety | Non-empty fields, trimmed text, no destructive commands, no message leakage. |

Commands: `cargo test -p zero-doctor` (55 lib + 3 integration tests), `cargo
clippy -p zero-doctor --all-targets -- -D warnings`.

## Still open in M6

T-WEB-04..05, T-WEB-08, T-MCP-10..11, T-MON-02..04, T-SR-01..08, T-MON-01..04, and T-SR-01..08.

Hosted runs [45563857571](https://github.com/Ruthvik-Anne/zero/actions/runs/45563857571)
on `fd1f322d`, [45565878012](https://github.com/Ruthvik-Anne/zero/actions/runs/45565878012)
on `702b2ec4`, [45570302744](https://github.com/Ruthvik-Anne/zero/actions/runs/45570302744)
on `61cf6e5f`, and [45575132889](https://github.com/Ruthvik-Anne/zero/actions/runs/45575132889)
on `1772ec89`, and [45587668887](https://github.com/Ruthvik-Anne/zero/actions/runs/45587668887)
on `24c27a02`: all ten jobs successful.
