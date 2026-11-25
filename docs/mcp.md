# MCP core client

`zero-mcp` currently ships the stateless MCP core client (T-MCP-01, MCP-01 to
MCP-05) and the stdio and Streamable HTTP transports (T-MCP-02, MCP-06 and
MCP-17): JSON-RPC 2.0 envelopes, revision negotiation, `resultType`
classification, routing headers, a cached `tools/list`, bounded tool schemas, a
scrubbed stdio child process, and a POST/SSE HTTP exchange. The legacy HTTP+SSE
shim is off by default. MRTR, tasks, events, apps, auth, security caps,
resources, server mode, and the conformance suite are later tasks.

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
capabilities are not modelled yet, so `capabilities` is empty.

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
  present. Older servers are treated as `complete` (MCP-03).
- An `input_required` result is surfaced with its `inputRequests` payload but is
  not retried. The retry with `inputResponses` is MRTR (T-MCP-03).
- A non-string `resultType` is a protocol error.

**Assumption:** on `2026-07-28`, a missing or `null` `resultType` is also treated
as `Complete`. The specification says every result carries the field; being
tolerant here keeps a strict-but-old server usable. This is documented rather
than guessed silently.

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

## Tests and fixtures

`crates/zero-mcp/tests/fixtures/2025-11-25.json` and
`2026-07-28.json` each contain an `initialize`, `tools/list`, and `tools/call`
result. `crates/zero-mcp/tests/core_client.rs` drives both through a scripted
in-memory transport and covers negotiation, stateless calls, caching, TTL,
invalidation, refresh hashing, `resultType` per revision, malformed envelopes,
JSON-RPC errors, routing headers, and schema bounds.

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
- MRTR `input_required` retry and elicitation (T-MCP-03).
- Tasks and events (T-MCP-04, T-MCP-05).
- Apps and extension negotiation (T-MCP-06).
- OAuth 2.1, PKCE, resource indicators, and CIMD (T-MCP-07).
- Schema pinning, destructive-tool defaults, output caps, timeouts, SSRF, and
  replay protection (T-MCP-08).
- Resources, prompts, and completions (T-MCP-09); server mode (T-MCP-10); the
  two-revision conformance suite in CI (T-MCP-11).
- A shared/persistent `tools/list` cache and cross-client `cacheScope`
  semantics.
