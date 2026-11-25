# MCP core client

`zero-mcp` currently ships the stateless MCP core client (T-MCP-01, MCP-01 to
MCP-05), the stdio and Streamable HTTP transports (T-MCP-02, MCP-06 and
MCP-17), and MRTR with elicitation (T-MCP-03, MCP-07 and MCP-08): JSON-RPC 2.0
envelopes, revision negotiation, `resultType` classification, routing headers,
a cached `tools/list`, bounded tool schemas, a scrubbed stdio child process, a
POST/SSE HTTP exchange, an `input_required` outcome parser, one-shot
`inputResponses` retries, form-mode credential refusal, and URL-mode host
approval. The legacy HTTP+SSE shim is off by default. Tasks, events, apps, auth,
security caps, resources, server mode, and the conformance suite are later
tasks.

## Client and transport seam

`Client<T: Transport>` owns one configured server name and one transport:

```rust
pub trait Transport {
    fn exchange(&self, request: &Value) -> Result<Value>;
}
```

`exchange` takes a complete JSON-RPC request value and returns a complete
response value. `crate::transport` implements the same seam with a stdio child
process and a Streamable HTTP POST; tests also use in-memory scripts. A
transport returns the whole response envelope, so id matching and envelope
validation stay in `expect_result`.

The client keeps a sequential request id per instance (`1`, `2`, ...). It is
stateless at the protocol level: no `Mcp-Session-Id` is required, no stream is
held open, and no handshake is required. `tools/list` and `tools/call` may be
called before `initialize`; they use the requested revision until a server
negotiates another one. When a Streamable HTTP server does assign a session id,
the transport echoes it (see [Transports](#transports)).

`initialize` sends:

```json
{
  "protocolVersion": "<requested revision>",
  "capabilities": {},
  "clientInfo": {"name": "zero", "version": "<crate version>"}
}
```

Per-request capabilities in `_meta`, sampling, roots, and elicitation
capabilities are not sent yet, so `capabilities` is empty. The consequence for
MRTR is recorded in [MRTR and elicitation](#mrtr-and-elicitation): this client
parses and enforces `input_required` when a server sends it, but a strictly
conformant `2026-07-28` server may withhold elicitation until the client
declares the capability in each request's `_meta`.

## Revisions

| Revision | Status | `resultType` |
|---|---|---|
| `2026-07-28` | target; requested by default | defined |
| `2025-11-25` | compatibility; negotiated when the server selects it | not defined; treated as `complete` |

`initialize` stores the server-selected `protocolVersion` and uses it for every
later call. A revision outside the table is rejected with
`zero.fnd.unsupported`; a missing, non-string, or otherwise malformed
`protocolVersion` is `zero.prv.protocol`. The negotiated revision is exposed by
`Client::negotiated_revision` and `Client::current_revision`.

## `resultType`

`ResultType` is `Complete`, `InputRequired`, or `Other(String)`:

- On `2026-07-28`, `complete` maps to `Complete` and `input_required` maps to
  `InputRequired`.
- An unrecognised string is preserved as `Other` and passed through; the client
  does not fail a server for adding a future value.
- On `2025-11-25`, every result is `Complete`, even if a `resultType` field is
  present. Older servers are treated as `complete` (MCP-03), and an
  `input_required` payload is never produced.
- `Client::tools_call` keeps its T-MCP-01 behaviour: it surfaces the raw
  `inputRequests` value and never retries. `Client::tools_call_outcome` parses
  the requests and supports exactly one MRTR retry (see
  [MRTR and elicitation](#mrtr-and-elicitation)).
- A non-string `resultType` is a protocol error.

**Assumption:** on `2026-07-28`, a missing or `null` `resultType` is also treated
as `Complete`. The specification says every result carries the field; being
tolerant here keeps a strict-but-old server usable. This is documented rather
than guessed silently.

## MRTR and elicitation

Source: the Model Context Protocol `2026-07-28` specification, [Multi Round-Trip
Requests](https://modelcontextprotocol.io/specification/draft/basic/patterns/mrtr)
and [Elicitation](https://modelcontextprotocol.io/specification/draft/client/elicitation),
plus the linked schema for `InputRequiredResult`, `InputRequests`,
`InputResponses`, `ElicitRequestFormParams`, and `ElicitRequestURLParams`.

No stream is held open. The initial `tools/call` and the retry are independent
JSON-RPC requests with different ids; the server carries context through the
opaque `requestState`.

### Wire shape

An `input_required` result is:

```json
{
  "resultType": "input_required",
  "inputRequests": {
    "city": {
      "method": "elicitation/create",
      "params": {
        "mode": "form",
        "message": "Which city?",
        "requestedSchema": {
          "type": "object",
          "properties": {"city": {"type": "string"}},
          "required": ["city"]
        }
      }
    },
    "login": {
      "method": "elicitation/create",
      "params": {
        "mode": "url",
        "url": "https://mcp.example.com/ui/set_api_key",
        "message": "Provide an API key to continue."
      }
    }
  },
  "requestState": "opaque server state"
}
```

- `inputRequests` is a map keyed by a server-assigned, non-empty string id. The
  key becomes `InputRequest::id` and is reused as the `inputResponses` key.
- Each value is an `elicitation/create` request with a `params` object.
- `message` is required and must be a non-empty string.
- Form mode may omit `mode` (the specification defaults it to `"form"`).
  `requestedSchema` is required, must declare `type: "object"`, and must carry a
  `properties` object. Each property must be a schema object; `required`, when
  present, must be an array of strings. Unknown request fields are ignored.
- URL mode requires `mode: "url"` and `url`; it must not carry
  `requestedSchema`. The URL must be an absolute `http` or `https` URL with an
  authority, no whitespace, and no control characters. Other schemes, including
  `javascript:` and `file:`, are refused.
- `requestState` is optional and must be a string. It is echoed verbatim and
  never inspected or parsed.
- At least one of `inputRequests` or `requestState` must be present. A
  state-only result is valid and may be retried immediately.
- A result that mixes `complete` with `inputRequests`/`requestState`, or
  `input_required` with `content`/`structuredContent`/`isError`, is a protocol
  error (`zero.prv.protocol`). So is a malformed map, request, mode, message,
  schema, URL, or state.

The retry request is the same tool call with `inputResponses` and the echoed
`requestState` in `params`:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "weather",
    "arguments": {"units": "metric"},
    "inputResponses": {
      "city": {"action": "accept", "content": {"city": "Paris"}},
      "login": {"action": "accept"}
    },
    "requestState": "opaque server state"
  }
}
```

An elicitation response is `{"action": "accept" | "decline" | "cancel"}`;
`content` is present only for a form-mode `accept`. URL-mode `accept` has no
`content`.

### Retry rule

`Client::tools_call_outcome(name, arguments)` sends one `tools/call` and returns
`ToolCallOutcome`:

```rust
pub enum ToolCallOutcome {
    Complete { content: Value, structured: Option<Value> },
    InputRequired { requests: Vec<InputRequest>, state: Option<Value> },
    Other(String),
}
```

An `input_required` outcome records the pending call. `Client::retry_with_inputs`
then sends exactly **one** additional request:

1. It validates every pending request has a response and that no extra key is
   present.
2. It sends the same `name` and `arguments`, a new JSON-RPC id, the
   `inputResponses` map (omitted when empty), and the exact `requestState`.
3. It returns the retry outcome. If the server asks again, the second
   `input_required` is returned to the caller; the client does not loop and
   clears the pending call. `retry_with_inputs` without a pending call is
   `zero.fnd.invalid_input`.
4. `Client::has_pending_input` and `Client::pending_input_requests` expose the
   pending state. `Client::tools_call_outcome` refuses to start another call
   while one is pending.

There is no third request, no background continuation, and no stream kept alive
between attempts.

### Form-mode credential refusal

A form request is allowed only for non-sensitive input. If a property name,
`title`, `description`, or `format` indicates a credential, or the property is
`writeOnly: true`, the whole result is refused with `zero.pol.denied` before any
pending call is recorded, no typed response is built, and no retry is sent.

Refused markers (case-insensitive; `_`, `-`, and spaces are normalised):
`password`, `passphrase`, `passwd`, `token`, `apikey` / `api key`, `secret`,
`privatekey` / `private key`, `cookie`, `session`, `credential`. Matching is
deliberately conservative: a false refusal is safe, a false acceptance is not.
The refusal names the field but never copies field content.

### URL-mode host approval

URL mode is classified `InputSensitivity::Sensitive`. The client never opens,
follows, pre-fetches, or submits the URL, and it never invents an acceptance
response.

`ToolCallOutcome::host_actions` returns a `HostAction` for every URL-mode
request. `HostAction` has private fields and no public constructor; the only way
to obtain one is from the client, so consent is tied to the URL request the host
actually saw rather than a free-form value:

```rust
pub struct HostAction { /* private */ }

impl HostAction {
    pub fn request_id(&self) -> &str;
    pub fn url(&self) -> &str;
    pub fn message(&self) -> &str;
}
```

The host must display the full URL and obtain user consent. Only then can it call
`InputResponses::approve_url(&action)`, which records the approval and inserts the
URL-mode `{"action": "accept"}` response. `retry_with_inputs` rejects a missing
response with `zero.fnd.invalid_input` and an unapproved URL acceptance with
`zero.pol.denied`. Declining or cancelling does not require approval.

### Capability limitation

The `2026-07-28` specification asks clients to declare `elicitation` in
`_meta.io.modelcontextprotocol/clientCapabilities` on each request. This task
implements the result, request, refusal, approval, and retry shapes but does not
yet emit per-request `_meta`; that remains part of the later conformance work.
A server that only elicits after seeing the declaration can still return a
normal `complete` result.

## Headers

`Headers` is a case-insensitive map with deterministic iteration. The client
stores:

- `MCP-Protocol-Version` — the requested revision, then the negotiated one.
- `Mcp-Method` — the JSON-RPC method, added by `Client::request_headers`.
- `Mcp-Name` — the tool name, added for `tools/call` when requested.

`Client::request_headers(method, name)` returns a copy of the routing metadata.
No authorization header or token is invented here; auth is T-MCP-07. `Mcp-Name`
carries the tool name verbatim; any percent-encoding or ASCII restriction is a
transport concern and is deferred.

## Transports

T-MCP-02 ships two transports behind the `Transport` seam and a default-off
switch for the legacy one (MCP-06):

```rust
pub enum TransportMode { Stdio, StreamableHttp, LegacyHttpSse }

pub enum TransportConfig {
    Stdio(StdioConfig),
    StreamableHttp(HttpConfig),
    LegacyHttpSse { url: String },
}

pub fn connect(config: TransportConfig) -> Result<Box<dyn Transport>>;
```

`TransportMode::StreamableHttp` is the default. `connect` opens stdio or
Streamable HTTP and refuses `LegacyHttpSse` with `zero.fnd.unsupported`; the
legacy compatibility shim itself is not implemented in this task.

### stdio

`StdioTransport::spawn(StdioConfig)` launches a child with piped stdin, stdout,
and stderr. `StdioConfig` carries `program`, `args`, `env`, `cwd`, a per-request
`timeout` (default 30 s), a response-line bound (default 8 MiB), and a stderr
tail bound (default 8 KiB).

**Environment scrubbing (MCP-17).** Before launch, the inherited environment and
`StdioConfig::env` are merged, credential-bearing names are removed, and the
result is applied with `env_clear`. A name is removed when it contains `KEY`,
`TOKEN`, `SECRET`, `PASSWORD`, or `CREDENTIAL`, except `SSH_AUTH_SOCK` and
`GPG_AGENT_INFO`. Explicit `env` entries are filtered by the same rule, so a
configured `OPENAI_API_KEY` cannot bypass the policy. The policy is duplicated
from `zero-secrets::scrubbed_env` on purpose: `zero-mcp` is below
`zero-secrets` in the dependency graph and must not depend upward on it; the two
lists are kept in sync. Non-Unicode variables are dropped rather than forwarded.

**Framing.** Each request is one compact JSON line. A reader thread splits stdout
on newlines under the line bound, and the caller waits for the envelope whose
`id` matches the request. Notification lines, plain log lines, and responses for
other ids are ignored, so a chatty server does not mis-parse. A line above the
bound, an unreadable stream, or end-of-file before a response is a typed error.
On timeout the child is killed and reaped, the error is `zero.fnd.timeout`, and
later calls fail with `zero.fnd.unavailable`.

**stderr.** A bounded tail is kept for diagnostics and exposed as
`StdioTransport::stderr_tail()`. Values removed by the scrub policy (at least 4
bytes, at most 4096) are replaced with `[redacted]` if they appear in that tail.
The tail never enters a `ZeroError` message and is untrusted child output, not
instructions. A server can still print a secret it obtained by some other route;
that cannot be detected locally, so treat the tail as untrusted everywhere.

**Lifecycle.** `shutdown()` closes stdin, then kills and waits for the child;
`Drop` does the same. `is_running()`, `pid()`, and `program()` support
diagnostics. Windows caveats: `kill` targets only the direct child (a server that
spawns grandchildren can leak them; a job object is T-MCP-14/TRU-06 work), and a
console window may flash because no creation flags are set yet.

### Streamable HTTP

`HttpTransport::new(HttpConfig)` validates that the endpoint is `http` or
`https` and posts each request. `HttpConfig` carries `url`, extra `Headers`
(`MCP-Protocol-Version`, auth when it lands), a per-request `timeout` (default
30 s), and a response-body bound (default 8 MiB).

Every request sends:

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `Accept` | `application/json, text/event-stream` |
| `Mcp-Method` | the JSON-RPC `method`, derived per request |
| `Mcp-Name` | the `params.name`, for `tools/call` |
| `Mcp-Session-Id` | the server-assigned id, or a configured preset |

Configured headers are sent as given, except that a configured
`Mcp-Session-Id` is only a preset: once the server returns one, the transport
stores it and uses it instead (`session_id()` exposes it). The session is
in-memory per transport; persisting or sharing it is not implemented.

A response may be `application/json` or `text/event-stream`. For JSON, the
envelope is selected from an object or a batch array by matching `id`. For SSE,
`data:` lines are joined with newlines per the SSE rules, events without a
matching response id are skipped (notifications, comments, malformed events),
and the matching envelope is returned. All body reads are bounded.

A non-2xx response is `zero.prv.protocol` with the status line in the message
(for example `MCP HTTP transport returned HTTP 503 Service Unavailable`); the
body is never read or echoed. A timeout is `zero.fnd.timeout`, an unreachable
endpoint is `zero.fnd.offline`, and an oversized body is
`zero.fnd.limit_exceeded`. SSRF, TLS pinning, and replay protection are
T-MCP-08; this transport does not allow non-HTTP schemes but does not otherwise
restrict destinations.

### Legacy HTTP+SSE

`TransportMode::LegacyHttpSse` is off by default and not implemented. Requesting
it returns `zero.fnd.unsupported` with a reason that names the default-off
switch and points at Streamable HTTP. T-MCP-02 ships only that switch, so no
legacy stream is opened by accident; the shim is a later compatibility task.

## Caching

A successful `tools/list` is cached under:

```text
(server name, negotiated revision)
```

`Client::tools_list` returns the cached catalogue when it is present, matches
the key, and has not expired; a second identical call does not call the
transport. `Client::cached_tools` exposes the same check. `Client::invalidate_tools`
drops the entry.

`ttlMs` from the server is honoured with an injected clock (`Client::with_clock`,
`SystemClock` by default). `ttlMs == 0` disables reuse; `ttlMs` absent means the
entry stays until it is invalidated or refreshed. `cacheScope` is parsed and
passed through, but the cache is currently one client's memory; a shared or
persistent cache is not implemented.

`Client::refresh_tools` always calls the transport, replaces the cache, and
reports `schema_changed` plus the previous hash. A changed hash is the
invalidation signal for callers that will later pin schemas. `tools_list`
itself never refetches just to compare hashes; it uses the cache while fresh.

The catalogue preserves server order. Deterministic ordering across independent
servers is therefore the server's order plus the stable cache; tools are not
re-sorted. Pagination (`nextCursor`) is passed through but pages are not fetched
automatically in this task.

## Schema bounds

Every tool's `inputSchema`, and `outputSchema` when present, must be a JSON
object within Zero's limits:

| Bound | Constant | Value |
|---|---|---|
| Serialised size | `MAX_SCHEMA_BYTES` | 64 KiB |
| Container depth | `MAX_SCHEMA_DEPTH` | 32 levels |
| JSON values | `MAX_SCHEMA_NODES` | 4096 nodes |

These numbers are Zero's own conservative bounds; the MCP specification does
not fix them. Exceeding a bound returns `zero.fnd.limit_exceeded`; a non-object
schema returns `zero.fnd.invalid_input`. The error names the tool and whether
the input or output schema failed, and the whole catalogue is rejected rather
than partially accepted.

Full JSON Schema 2020-12 validation, `$ref` resolution, and composition-keyword
semantics are not implemented here (they belong to MCP-05's validation task);
only bounded structure is enforced. Schema pinning and its cryptographic hash
are MCP-14 / T-MCP-08.

`Tool::schema_hash` and `ToolCatalog::schema_hash` use deterministic FNV-1a over
canonicalised JSON (object keys sorted) and the ordered tool list. Descriptions
and titles are excluded, so only a definition change counts. The hash is a
change detector, not a signature; it does not resist a collision-seeking
adversary.

## Error mapping

A JSON-RPC error object becomes a typed `zero_types` error; the wire code and
message are kept in the error message. The stable code is chosen from the
caller's point of view:

| JSON-RPC code | Stable code |
|---|---|
| `-32700` parse, `-32600` invalid request, `-32602` invalid params | `zero.fnd.invalid_input` |
| `-32601` method not found | `zero.fnd.unsupported` |
| anything else, including `-32603` internal error | `zero.prv.protocol` |

Malformed envelopes are `zero.prv.protocol`: not an object, wrong `jsonrpc`,
missing or mismatched `id`, both `result` and `error`, neither, or a malformed
error object. A tool-level failure (`isError: true`) is not an error here; it is
returned as `ToolCallResult::is_error`.

MRTR failures use the same taxonomy:

| Condition | Stable code |
|---|---|
| Malformed `inputRequests`, request, mode, message, schema, URL, or `requestState`; mixed complete/input-required result; no requests and no state | `zero.prv.protocol` |
| Form request asks for a credential field | `zero.pol.denied` |
| Missing response, extra response key, or retry without a pending call | `zero.fnd.invalid_input` |
| URL-mode acceptance without the matching host approval | `zero.pol.denied` |

## Tests and fixtures

`crates/zero-mcp/tests/fixtures/2025-11-25.json` and
`2026-07-28.json` each contain an `initialize`, `tools/list`, and `tools/call`
result. `crates/zero-mcp/tests/core_client.rs` drives both through a scripted
in-memory transport and covers negotiation, stateless calls, caching, TTL,
invalidation, refresh hashing, `resultType` per revision, malformed envelopes,
JSON-RPC errors, routing headers, and schema bounds.

`crates/zero-mcp/tests/mrtr.rs` drives MRTR and elicitation through the same
scripted seam. It asserts the `input_required` request shape, a single retry
with the exact `inputResponses` and `requestState`, a second `input_required`
that is returned rather than looped, state-only retry, form-mode omission of
`mode`, credential refusal with no wire retry, URL-mode host approval (including
refusal of an unapproved accept), malformed request shapes, and that
`2025-11-25` never yields `input_required`.

`crates/zero-mcp/tests/transports.rs` covers the transports without an external
runtime or host:

- stdio: this test binary is respawned with `--exact stdio_helper_process` and
  `ZERO_MCP_STDIO_HELPER=1`; the helper answers JSON-RPC on stdin/stdout and the
  helper test is a no-op in a normal run. Tests assert `initialize` over stdio,
  that an inherited `OPENAI_API_KEY` and a configured secret variable are absent
  in the child while `SSH_AUTH_SOCK` survives, that notifications and log lines
  are skipped, that a timeout returns `zero.fnd.timeout` and stops the child, and
  that shutdown is idempotent.
- HTTP: a loopback `TcpListener` serves scripted JSON and SSE responses. Tests
  assert the POST headers and request body, multi-line SSE `data:` joining and
  id matching, `Mcp-Session-Id` capture and propagation, status-only errors for
  non-2xx, non-HTTP URL rejection, and the default-off legacy switch.

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-mcp
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-mcp --all-targets -- -D warnings
```

## Deferred

- The legacy HTTP+SSE compatibility shim itself; T-MCP-02 ships only the
  default-off switch.
- Per-request `_meta` and the `elicitation` capability declaration; T-MCP-03
  implements the wire shapes, refusals, approval, and retry, not the
  declaration.
- Tasks and events (T-MCP-04, T-MCP-05).
- Apps and extension negotiation (T-MCP-06).
- OAuth 2.1, PKCE, resource indicators, and CIMD (T-MCP-07).
- Schema pinning, destructive-tool defaults, output caps, timeouts, SSRF, and
  replay protection (T-MCP-08).
- Resources, prompts, and completions (T-MCP-09); server mode (T-MCP-10); the
  two-revision conformance suite in CI (T-MCP-11).
- A shared/persistent `tools/list` cache and cross-client `cacheScope`
  semantics.
