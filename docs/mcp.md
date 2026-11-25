# MCP core client

`zero-mcp` currently ships the stateless MCP core client (T-MCP-01, MCP-01 to
MCP-05): JSON-RPC 2.0 envelopes, revision negotiation, `resultType`
classification, routing headers, a cached `tools/list`, and bounded tool
schemas. Production transports, MRTR, tasks, events, apps, auth, security caps,
resources, server mode, and the conformance suite are later tasks.

## Client and transport seam

`Client<T: Transport>` owns one configured server name and one transport:

```rust
pub trait Transport {
    fn exchange(&self, request: &Value) -> Result<Value>;
}
```

`exchange` takes a complete JSON-RPC request value and returns a complete
response value. Tests and future transports implement the same seam; this task
only ships an in-memory script. No production transport, socket, or process is
opened here.

The client keeps a sequential request id per instance (`1`, `2`, ...). It is
stateless at the protocol level: no `Mcp-Session-Id`, no held-open stream, and
no required handshake. `tools/list` and `tools/call` may be called before
`initialize`; they use the requested revision until a server negotiates another
one.

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

`Client::request_headers(method, name)` returns a copy for a future transport to
put on the wire. No authorization header or token is invented here; auth is
T-MCP-07. `Mcp-Name` carries the tool name verbatim; any percent-encoding or
ASCII restriction is a transport concern and is deferred.

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

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-mcp
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-mcp --all-targets -- -D warnings
```

## Deferred

- stdio and Streamable HTTP transports, and the legacy HTTP+SSE shim (T-MCP-02).
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
