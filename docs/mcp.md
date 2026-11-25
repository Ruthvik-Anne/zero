# MCP core client

`zero-mcp` currently ships the stateless MCP core client (T-MCP-01, MCP-01 to
MCP-05), the stdio and Streamable HTTP transports (T-MCP-02, MCP-06 and
MCP-17), MRTR with elicitation (T-MCP-03, MCP-07 and MCP-08), the tasks
extension (T-MCP-04, MCP-04 and MCP-09), and the event seam (T-MCP-05,
MCP-10): JSON-RPC 2.0 envelopes, revision negotiation, `resultType`
classification, routing headers, a cached `tools/list`, bounded tool schemas, a
scrubbed stdio child process, a POST/SSE HTTP exchange, an `input_required`
outcome parser, one-shot `inputResponses` retries, form-mode credential
refusal, URL-mode host approval, redacted `tasks/get`, `tasks/update`, and
`tasks/cancel` clients with TTL-aware polling, cursor-based event polling that
resyncs instead of assuming resumption, subscription TTLs, and HMAC-SHA256
webhook verification with a replay window and bounded dedupe. The apps
extension (T-MCP-06, MCP-11 and MCP-12) adds `ui://` validation, a sandboxed
iframe document with a strict CSP, a host-side navigation gate, and
unknown-extension tolerance. OAuth 2.1 authorization (T-MCP-07, MCP-07 and
MCP-13) adds authorization server discovery with strict issuer checks, PKCE
`S256`, RFC 8707 resource indicators, public-client code exchange and refresh,
access-token binding validation, and Client ID Metadata Document validation.
Security controls (T-MCP-08, MCP-08 and MCP-14) add schema pinning with host
approval, the destructive-tool risk matrix, result size caps, timeout budgets, a
resource-URL SSRF policy, and a bounded replay guard. The resources and prompts
seam (T-MCP-09, MCP-16) adds validated resource and prompt catalogues, `@`
references with restart-safe persistence, slash commands, and bounded local
completions. The legacy HTTP+SSE shim is off by default. Server mode
(T-MCP-10, MCP-10 and MCP-15) is implemented behind a default-off flag, and
declarative conformance fixtures (T-MCP-11, MCP-19) replay both supported
revisions through the real client types.

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
- `Client::tools_call_outcome` maps the extension's `task` discriminator to
  `ToolCallOutcome::Task` on `2026-07-28` (see [Tasks](#tasks));
  `Client::tools_call` still surfaces `Other("task")` because it does not parse
  task handles.
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
    Task(Task),
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

## Tasks

Source: the MCP Tasks extension `io.modelcontextprotocol/tasks` for revision
`2026-07-28`
([specification](https://tasks.extensions.modelcontextprotocol.io/specification/2026-07-28/tasks.html),
[schema](https://github.com/modelcontextprotocol/ext-tasks/blob/main/schema/2026-07-28/schema.ts)).
The `2026-07-28` extension defines this method set. On an older negotiated
revision the task methods are refused with `zero.fnd.unsupported`; the older
`2025-11-25` task surface is not implemented here.

A server creates a task by answering a supported request (currently only
`tools/call`) with a flat `CreateTaskResult`: `resultType: "task"` plus the
`Task` fields. `Client::tools_call_outcome` parses that handle into
`ToolCallOutcome::Task(Task)` on `2026-07-28`; `Task::from_create_result` is the
underlying parser. On `2025-11-25`, `resultType` is ignored, so the task variant
is never produced. The caller keeps the returned `TaskId` and drives the
lifecycle with the methods below. Declaring the extension in per-request
`_meta` is still deferred (see the end of this document).

### Methods and wire shapes

| Method | Params | Successful result |
|---|---|---|
| `tasks/get` | `{"taskId": "<raw id>"}` | `resultType: "complete"` plus a `Task` |
| `tasks/update` | `{"taskId": "<raw id>", "inputResponses": {...}}` | empty `{"resultType": "complete"}` |
| `tasks/cancel` | `{"taskId": "<raw id>"}` | empty `{"resultType": "complete"}` |

`tasks/get` returns the status-specific `DetailedTask` variant inline:

```json
{
  "resultType": "complete",
  "taskId": "...",
  "status": "completed",
  "statusMessage": "optional",
  "createdAt": "2025-11-25T10:30:00Z",
  "lastUpdatedAt": "2025-11-25T10:50:00Z",
  "ttlMs": 60000,
  "pollIntervalMs": 5000,
  "result": {"content": [{"type": "text", "text": "done"}], "isError": false}
}
```

- `status` is `working`, `input_required`, `completed`, `failed`, or
  `cancelled`; any other string is preserved as `TaskState::Unknown`.
- `completed` requires `result` (a JSON object); `failed` requires `error` (a
  JSON-RPC error object with an integer `code` and a string `message`); and
  `input_required` requires `inputRequests`.
- `inputRequests` is validated with the MRTR elicitation parser, so the
  credential refusal and URL rules above also apply to task input.
- `ttlMs` is a non-negative integer or `null` (unlimited); `pollIntervalMs` is
  an optional non-negative integer. Missing and `null` both map to `None`.
- `createdAt` and `lastUpdatedAt` are required non-empty strings, preserved
  verbatim; this crate does not parse dates.
- `statusMessage` is optional. `Task`'s debug form replaces a raw task id in
  server-supplied text with `[redacted]`.
- The `tasks/get` result must carry `resultType: "complete"`. The
  `tasks/update` and `tasks/cancel` acknowledgements must likewise be
  `complete`; any other `resultType` is `zero.prv.protocol`. A missing
  `resultType` is treated as `complete` under the client-wide tolerance
  described in [`resultType`](#resulttype).

`tasks/update` accepts only `inputResponses` (built through `InputResponses`,
which enforces the MRTR and URL-approval rules). The stable extension defines
no progress field: `statusMessage` is server-supplied and progress is read back
with `tasks/get`. `tasks_update_for(&task, &responses)` is the checked form: it
validates every response key against the task's outstanding `inputRequests`
(missing and extra keys are refused, and a URL-mode accept needs the matching
`HostAction`) before sending `tasks_update` with the task id.

### End-to-end path

`Client::tools_call_outcome(name, arguments)` sends `tools/call`. On
`2026-07-28`, a `resultType: "task"` result is parsed with the task parser and
returned as `ToolCallOutcome::Task(task)`; the other outcomes remain
`Complete`, `InputRequired`, and `Other`. The caller matches the variant and
uses `task.id` with `tasks_get` or `poll_until_done`, answers `input_required`
with `tasks_update_for`, and reads the final `result` or `error` from the
terminal task:

```rust
match client.tools_call_outcome("deploy", json!({"environment": "production"}))? {
    ToolCallOutcome::Task(task) => {
        let done = client.poll_until_done(&task.id, &SystemSleeper, PollDeadline::default())?;
        // done.state is Completed, Failed, or Cancelled.
    }
    other => { /* Complete, InputRequired, or Other */ }
}
```

`Client::tools_call` is the lower-level T-MCP-01 method: it classifies
`resultType` and never parses a task handle, so a task result appears there as
`ResultType::Other("task")`. On `2025-11-25`, `Client::tools_call_outcome`
short-circuits to `Complete` and never yields `Task`.

### State machine

```text
working ──> input_required ──(tasks/update)──> working ──> completed
   │                │                                      failed
   └────────────────┴──────────────────────────────────>  cancelled
```

`completed`, `failed`, and `cancelled` are terminal. `failed` carries a
JSON-RPC error; a tool result with `isError: true` is still `completed` with the
tool result inline. Cancellation is cooperative: `tasks/cancel` acknowledges
intent but the task may still finish, and the client may drop its local task
state immediately after the acknowledgement.

### Polling and TTL

`Client::poll_until_done(&id, &sleeper, PollDeadline)` sends `tasks/get`
repeatedly until the task is no longer `working`. It uses the latest
`pollIntervalMs` for the next sleep (falling back to
`PollDeadline::default_poll_interval_ms`), stops immediately on a terminal
state, and returns an `input_required` or unknown task to the caller rather
than looping, because polling cannot answer an elicitation. After an
`input_required` result the caller sends `tasks_update` (or the checked
`tasks_update_for`) and may poll again.

`PollDeadline` bounds the loop with `max_attempts` (at least one), an optional
`max_wait_ms`, and the fallback interval. Each sleep is capped by the remaining
TTL or wall-clock budget so a long `pollIntervalMs` cannot overshoot either
bound. A non-null `ttlMs` is treated as a budget measured from the first poll,
because there is no date parser here;
`ttlMs: 0` expires immediately unless the first response is already terminal.
Exceeding the TTL, wall-clock budget, or attempt count returns
`zero.prv.timeout` with no task id in the message. `NoopSleeper`,
`SystemSleeper`, and any `Fn(u64)` are available as sleepers. Tests pass a
recorder that also advances the injected `FakeClock`, so TTL and deadline
checks are deterministic and no test sleeps for real.

### Bearer-secret handling (MCP-09)

The extension says a task ID may be a bearer token for server state and that
there is no `tasks/list`. `TaskId` therefore never prints its value:
`Debug`/`Display` are `[redacted]`, and the raw string is available only through
`TaskId::secret()`. It still implements `Serialize`/`Deserialize` so the raw id
can be sent in `params.taskId` and persisted by the caller.

`Task`'s debug form prints the redacted id, the state, the TTL/poll interval,
and presence flags for the result/error/input requests; it does not print result
or error payloads, which are untrusted server data and may echo the id. Every
error returned by the task methods is scrubbed: if a server error message
contains the raw id, the client replaces it with `[redacted]` while preserving
the stable error code. No task id is copied into an error message or log by
this crate.

The Streamable HTTP extension also requires `Mcp-Name: <raw taskId>` on
`tasks/get`, `tasks/update`, and `tasks/cancel` for routing. The current
transport seam passes only the JSON-RPC request to `Transport::exchange`, so
that header is not emitted yet; it is deferred with transport header injection
and must never be logged when added.

### Error mapping

| Condition | Stable code |
|---|---|
| Negotiated revision older than `2026-07-28` | `zero.fnd.unsupported` |
| Empty task id | `zero.fnd.invalid_input` |
| Malformed envelope; `resultType` other than `complete`; missing, empty, or mismatched `taskId`; missing or invalid `status`/`createdAt`/`lastUpdatedAt`; negative or non-integer `ttlMs`/`pollIntervalMs`; missing status payload; malformed `inputRequests` | `zero.prv.protocol` |
| Form `inputRequests` ask for a credential field | `zero.pol.denied` (from the MRTR parser) |
| TTL, wall-clock deadline, or attempt count exhausted | `zero.prv.timeout` |

## Events

Source: the MCP Events extension `io.modelcontextprotocol/events` for revision
`2026-07-28`. The extension defines `events/list` (schemas), `events/poll`
(pull), `events/stream` (push), and `events/subscribe` (webhook). This crate
implements the transport-independent poll loop and the inbound webhook
verifier; the push transport and the webhook HTTP server are deferred (see
[Deferred push transports](#deferred-push-transports)).

### Cursors and polling

```rust
pub struct Event {
    pub id: String,
    pub kind: String,
    pub payload: serde_json::Value,
    pub delivered_at_ms: i64,
}

pub struct EventBatch {
    pub events: Vec<Event>,
    pub next_cursor: Option<EventCursor>,
    pub ttl_ms: Option<u64>,
}

pub trait EventSource {
    fn poll(&self, cursor: Option<&EventCursor>) -> Result<EventBatch>;
}
```

`EventCursor` is an opaque token issued by the source. Callers pass it back
unchanged; they never derive one from event contents and never do arithmetic
on it. `None` asks for the oldest retained events.

`EventPoller` owns the cursor. Each successful `poll_once` sends the current
cursor and, when the batch carries `next_cursor`, advances to it. A batch with
`next_cursor: None` leaves the cursor unchanged: a null means "nothing to
advance to", not permission to restart or skip. `poll_until_idle(max_attempts)`
repeats `poll_once` until an empty batch (idle), a resync signal, or the
attempt bound. The bound counts polls, not events; reaching it is not an
error, and the `EventPollSummary` reports `idle: false` with the events
collected so far. `max_attempts: 0` is `zero.fnd.invalid_input`.

The `EventPoller` clock is injected (`with_clock`). Tests pass a `FakeClock`, so
TTL checks are deterministic and nothing sleeps; webhook checks take an
explicit `now_ms` for the same reason. A poll adapter implements `EventSource`
over `events/poll`; a push adapter can buffer whatever `events/stream` delivers
and implement the same method.

### No resumption assumption (MCP-10)

A cursor is valid only while the server retains that position. When a source
no longer recognises a cursor, it returns the error built by
`resync_required(reason)`; the poller recognises it and returns
`EventPollOutcome::ResyncRequired`, discarding the local cursor. The caller
must restart from the oldest retained event.

The poller never substitutes a nearby cursor, never resumes from event
contents, and never presents a partial batch as complete. `poll_until_idle`
stops at the signal and keeps the events it already collected, setting
`resync_required` in the summary. If a caller ignores the signal and polls
again, the next request starts without a cursor, so the failure mode is
duplicate delivery (removable by event id), never a silent gap.

### Subscription TTL

A non-null `EventBatch::ttl_ms` is a fresh lease measured from the moment the
batch arrives: the poller records `expires_at_ms = now + ttl_ms`. A zero TTL
expires immediately after that batch is delivered. A batch without `ttl_ms`
does not extend the lease, so a previously recorded deadline keeps running.

`EventPoller::renew(ttl_ms)` extends the lease from now and returns the new
deadline. Renewal is refused once the lease has expired. After expiry,
`poll_once` fails with `zero.prv.timeout` before the source is called, and the
caller must call `resubscribe()`, which clears the cursor and lease; the
adapter performs the actual subscribe again. Expiry is checked against the
injected clock; as with task TTLs, there is no date parser here.

### Webhook signatures

Webhook requests carry three headers:

| Header | Value |
|---|---|
| `X-MCP-Event-Key-Id` | Key identifier the sender used |
| `X-MCP-Event-Signature` | Hex HMAC-SHA256 over the exact raw body |
| `X-MCP-Event-Timestamp` | Sender's Unix timestamp in milliseconds |

`HmacSha256Verifier` holds a key ring keyed by id and implements the
`SignatureVerifier` trait. Verification is RFC 2104 HMAC-SHA256 over the exact
`body` bytes; the signature may be lowercase or uppercase hex, with an optional
`sha256=` prefix. Comparison is constant time. The verifier's `Debug` form
prints only the key count, and `sign_hex` computes the value a sender would
use (for fixtures and future senders). Unit tests cover RFC 4231 cases 2 and 6.

`verify_webhook(headers, body, verifier, now_ms, tolerance_ms)` checks in this
order, stopping at the first failure:

1. All three headers are present and non-empty.
2. The timestamp is within `tolerance_ms` of `now_ms`, in either direction.
3. The signature verifies over the exact raw body.
4. The body parses as a JSON object with a non-empty string `id`.

Steps 1 to 3 run before any JSON parsing, so a forged body never reaches the
parser. The payload shape is:

```json
{"id": "evt-1", "kind": "resource_updated", "payload": {"status": "ok"}}
```

`id` is required; `kind` defaults to `"event"`; the whole object is preserved
as `Event::payload`. `delivered_at_ms` is the local `now_ms`, not the sender's
timestamp. A malformed payload is `zero.prv.protocol`.

No webhook error contains a header value, key id, key, signature, or body
content; messages name only the field or check that failed. `Event`'s `Debug`
form prints id, kind, and delivery time but redacts the payload body, which is
untrusted server data.

### Replay window and duplicate suppression

The replay window is enforced by the timestamp check above; the default for
`WebhookReceiver` is five minutes either side
(`DEFAULT_WEBHOOK_TOLERANCE_MS`), configurable with `with_tolerance_ms`.

`WebhookReceiver` adds a bounded first-in-first-out seen set of event ids
(1024 by default, `MAX_SEEN_EVENT_IDS`). A repeated id is reported as
`WebhookOutcome::Duplicate` and is not delivered again. Once the set is full
the oldest id is evicted, so a replay after that many distinct events is
delivered again rather than silently dropped. The set is in memory only;
persistence across restarts and within the cursor window is deferred. Binding
the receiver to loopback or the mesh is the transport's job and is also
deferred.

### Error mapping

| Condition | Stable code |
|---|---|
| Missing, empty, or invalid webhook header; stale or future timestamp; bad signature; malformed JSON or event object; empty event id | `zero.prv.protocol` |
| Source rejected the cursor | `EventPollOutcome::ResyncRequired` (built from `zero.prv.protocol`) |
| Subscription lease expired, including `ttl_ms: 0` | `zero.prv.timeout` |
| `poll_until_idle(0)` | `zero.fnd.invalid_input` |

### Deferred push transports

Polling and webhook verification are implemented. The following are not:

- The `events/stream` push transport and its reconnect loop. A push adapter
  should buffer streamed events and expose them through `EventSource::poll`.
- The `events/subscribe` HTTP server: method dispatch, loopback/mesh binding,
  and SSRF checks for subscription URLs.
- `events/list` schema discovery and the per-request capability declaration
  for `io.modelcontextprotocol/events`.
- Durable cursors, dedupe state, and event audit records across restarts.

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
`zero.fnd.limit_exceeded`. This transport does not allow non-HTTP schemes but
does not otherwise restrict destinations. The resource-URL SSRF policy and the
replay guard ship in `security.rs` (T-MCP-08) but are not wired into this
transport; destination pinning and TLS pinning remain deferred (see [Deferred
security items](#deferred-security-items)).

### Legacy HTTP+SSE

`TransportMode::LegacyHttpSse` is off by default and not implemented. Requesting
it returns `zero.fnd.unsupported` with a reason that names the default-off
switch and points at Streamable HTTP. T-MCP-02 ships only that switch, so no
legacy stream is opened by accident; the shim is a later compatibility task.

## Apps and extensions

T-MCP-06 implements the host-side half of MCP Apps (`io.modelcontextprotocol/ui`)
and the extensions framework (MCP-11 and MCP-12). Nothing in this module starts
a browser: it validates identifiers, generates the sandboxed host document, and
decides whether a navigation request is allowed. Browser-level enforcement is
listed under [Deferred](#deferred).

### `ui://` resource rules

`UiResource::parse` accepts `ui://<authority>[/<path>]`. The authority is
required; the path is optional, so both `ui://dashboard` and
`ui://dashboard/view.html` are valid. The URI is a cache key: one spelling maps
to one resource, and the stored value is the canonical form produced by the URL
parser.

| Input | Result | Reason |
|---|---|---|
| `ui://dashboard` | accepted | authority only |
| `ui://dashboard/view.html` | accepted | authority and path |
| `javascript:alert(1)`, `data:...` | refused | not the `ui` scheme |
| `http://...`, `https://...` | refused | app content is a resource, not a remote page |
| `file:///...` | refused | not the `ui` scheme |
| `ui://user@app/view` | refused | userinfo could disguise the authority |
| `ui://app:8080/view` | refused | ports make the cache key and origin ambiguous |
| `ui://app/view?x=1`, `ui://app/view#f` | refused | query and fragment are not part of an app identity |
| `ui://`, `ui:///view.html` | refused | the authority is required |
| `ui://app/../secret`, `ui://app/%2e%2e/secret` | refused | dot segments could escape a host cache directory |
| `ui://app/%2f..%2fsecret` | refused | percent-encoded separators hide a path |
| `ui://app\view` | refused | backslashes are not path separators here |
| whitespace, control characters, or more than 2048 bytes | refused | header, log, and parser hygiene |

Every refusal is `zero.prv.protocol` and never includes the rejected string.

### Sandbox

`AppFrame::render(resource, html)` returns an `AppFrame` whose `html` is the
complete host document and whose `sandbox` and `csp` fields are the exact
values the host must also use if it serves the app from an origin.

The iframe sandbox is exactly:

```text
allow-scripts
```

| Token | Granted | Why |
|---|---|---|
| `allow-scripts` | yes | an app is an interactive document |
| `allow-same-origin` | **no** | the frame keeps an opaque origin, so it cannot read host storage, cookies, or the parent DOM |
| `allow-top-navigation`, `allow-top-navigation-by-user-activation` | **no** | the app can never navigate the host |
| `allow-popups`, `allow-popups-to-escape-sandbox` | **no** | no new windows and no sandbox escape through one |
| `allow-forms` | **no** | forms are refused even if CSP were bypassed |
| `allow-downloads` | **no** | the app cannot write files through the frame |
| `allow-modals` | **no** | no `alert`, `confirm`, `prompt`, or `beforeunload` |
| `allow-storage-access-by-user-activation` | **no** | no third-party storage access |
| `allow-pointer-lock`, `allow-presentation` | **no** | not needed for an embedded app |

### Content Security Policy

The app document carries [`APP_CSP`](../crates/zero-mcp/src/apps.rs):

```text
default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline';
img-src data:; font-src 'none'; media-src 'none'; connect-src 'none';
frame-src 'none'; worker-src 'none'; object-src 'none'; manifest-src 'none';
base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

| Directive | Value | Choice |
|---|---|---|
| `default-src` | `'none'` | deny everything not named below |
| `script-src` | `'unsafe-inline'` | an app is a single resource; no external script, no `'unsafe-eval'`, so `eval` and `new Function` stay blocked |
| `style-src` | `'unsafe-inline'` | inline app styles; no external stylesheet |
| `img-src` | `data:` | bundled images only; no remote image beacon |
| `connect-src` | `'none'` | no fetch, XHR, WebSocket, or EventSource; an app talks to the host over `postMessage` |
| `frame-src` | `'none'` | no nested frames |
| `worker-src` | `'none'` | no workers or service workers |
| `object-src` | `'none'` | no plugins |
| `base-uri` | `'none'` | the app cannot rewrite relative URLs to another origin |
| `form-action` | `'none'` | a form cannot submit anywhere |
| `frame-ancestors` | `'none'` | the app document cannot be framed by a third party |

The policy is emitted in a `<meta http-equiv="Content-Security-Policy">` inside
the escaped `srcdoc` payload, and exposed as `AppFrame::csp`. Browsers ignore
`frame-ancestors` in a `<meta>` element, so a host that serves the app document
from an origin must also send the same value as a response header. Per-resource
CSP tightening from `_meta.ui.csp` is not implemented yet.

### Escaping

The app HTML is untrusted. It is escaped for an HTML attribute before it is
placed in `srcdoc`, covering `&`, `<`, `>`, `"`, and `'`. A payload such as

```html
</iframe><script>parent.location = "https://evil.example"</script>
```

cannot close the `srcdoc` attribute or the `<iframe>` element; it appears in
the host document as `&lt;/iframe&gt;...`. The rendered host document contains
exactly one real `</iframe>` (the frame's own closing tag). The
`hostile_html_is_escaped_inside_srcdoc` test asserts the breakout attempt, the
escape sequence, and the single closing tag.

### Navigation matrix

`authorize(policy, intent)` is the host-side gate. It never relies on the
sandbox alone: a compromised renderer or a host bug still meets this check.
Refusals are `zero.pol.denied` and never echo the target.

| Disposition | Result |
|---|---|
| `TopLevel` | always refused |
| `Popup` | always refused |
| `Download` | always refused |
| `Subframe` | allowed only to an exact `https` origin in `allowed_app_origins` |
| `Form` | allowed only to an exact `https` origin in `allowed_app_origins` |

Target rules:

| Target | Result |
|---|---|
| `https://apps.example.com/view` listed in the policy | accepted |
| `https://other.example/view` | refused, origin mismatch |
| `https://apps.example.com:8443/view` when the policy lists the default port | refused, the port is part of the origin |
| `http://...`, `ftp://...`, `ws://...` | refused, only `https` |
| `javascript:`, `data:`, `file:`, `blob:` | refused |
| `https://user:pass@app/...` or `https://app@evil/...` | refused, userinfo is not accepted |
| `_top`, `_parent`, `_blank` | refused |
| `_self` on `Subframe` or `Form` | accepted as a no-op in the frame |
| `/path`, `./path`, `../path` | refused unless `allow_same_origin` is set |
| `//other.example/path`, backslash targets, empty or control-character targets | refused |

`allowed_app_origins` is exact: scheme, host, and port must all match. The
host's own origin must not be listed; nothing allows a subframe or form to load
the host unless the operator explicitly adds it. `allow_same_origin` defaults
to `false` and only covers relative references that stay inside the app frame;
`//host/path` is never treated as same-origin.

`authorize_message(policy, message)` handles the `postMessage` form. It accepts
only `{"type":"navigate","frame":"self","target":...}`, defaults a missing
disposition to `subframe`, ignores unknown fields, and then runs the same
matrix. `{"type":"open_window"}`, `{"type":"window.open"}`, `frame` values
other than `self`, malformed fields, and unknown message types are refused or
rejected before any navigation decision.

### Extension negotiation

`ExtensionOffer` mirrors one entry of the capabilities `extensions` map:
`id`, optional `version`, optional `required`, and an opaque `payload`.
`negotiate(supported, offered)` never fails:

| Offer | Outcome |
|---|---|
| identifier in `supported` | `accepted`, in offered order |
| unknown identifier, `required: false` | `ignored` |
| unknown identifier, `required: true` | `unsupported_required` |
| duplicate identifier | first offer wins; later duplicates are skipped |

`Negotiation::ensure_supported()` converts a non-empty
`unsupported_required` into `zero.fnd.unsupported`, so the caller chooses
between graceful degradation and refusing the exchange. Unknown fields inside
an extension payload, and unknown top-level fields on the offer, are ignored.
A malformed entry - not an object, missing or non-string `id`, an id that is
not `{prefix}/{name}`, a non-boolean `required`, or a non-string/number
`version` - is `zero.prv.protocol`; `negotiate_values` returns it as an error.
Version compatibility is recorded but not enforced: matching is by identifier.

The two known identifiers are `io.modelcontextprotocol/ui` (`UI_EXTENSION`) and
`io.modelcontextprotocol/tasks` (`TASKS_EXTENSION_ID`). Enterprise managed
authorization settings are carried as an opaque payload on their own extension
identifier; enforcement is deferred (see [Deferred auth](#deferred-auth)).

## Resources and prompts

Source: the MCP `2025-11-25` Resources, Prompts, and Completion pages. T-MCP-09
implements the client-side catalogue, `@` references, slash commands, local
completions, and the persistence seam in
`crates/zero-mcp/src/resources.rs` (MCP-16). The server half of resources and
prompts is T-MCP-10. Nothing in this module opens a socket or a child process.

### Catalogues

`ResourceCatalog` parses one server's `resources/list` and
`resources/templates/list` results:

| Wire field | Type | Required |
|---|---|---|
| `resources[].uri` | string, no whitespace or control characters | yes |
| `resources[].name` | string, no whitespace or control characters | yes |
| `resources[].title`, `description`, `mimeType` | string or `null` | no |
| `templates[].uriTemplate` | string, no whitespace or control characters | yes |
| `templates[].name` | string, no whitespace or control characters | yes |
| `templates[].description` | string or `null` | no |

The whole result is rejected on a malformed entry, a duplicate resource URI, a
duplicate resource name, a duplicate template pattern, or a duplicate template
name. "Rejected" means `zero.prv.protocol`; no entry is silently dropped or
picked. Unknown fields and the pagination `nextCursor` are ignored - a caller
that wants later pages fetches them itself.

`PromptCatalog` parses a `prompts/list` result. Each prompt has `name`,
optional `title`/`description`, and `arguments[]` with `name`, optional
`required` (default `false`), and optional `description`. Duplicate prompt
names and duplicate argument names inside one prompt are
`zero.prv.protocol`.

### `@` references

`ResourceRef::parse` (exported as `parse_reference`) accepts three forms:

| Form | `server` | `target` |
|---|---|---|
| `@name` | `None` | `name` |
| `@server:name` | `Some(server)` | `name` |
| `@ui://app/view` | `None` | `ui://app/view` |

The URI form is recognised first: when the text after `@` contains `://`, the
whole remainder is the target and no server is parsed. A reference must start
with `@`, must not be empty, must not contain whitespace or control characters,
and must not start with `/` after the `@`. `@server:` is malformed.

`ResourceCatalog::resolve` and `ResourceStore::resolve` apply the same order:

1. exact resource URI;
2. exact resource name;
3. unique case-insensitive resource name (Unicode lowercase comparison);
4. URI template pattern, only for targets containing `://`.

A store without a server qualifier searches every catalogue with that same
global order, so an exact URI on server B beats a name match on server A. Two
matches at the strongest stage are `zero.fnd.invalid_input` with every
candidate listed as `server:name (uri)`; the resolver never picks one silently.
No match is `zero.fnd.not_found`, and an unknown `@server:` is also not found.
`LookupFailure` classifies these two outcomes.

Template matching understands simple level-1 RFC 6570 `{var}` expressions only:
each variable matches any run of characters, including an empty one. Operator
expressions (`{+path}`, `{/path}`, `{?query}`, ...) are retained in the
catalogue but never match. Variable expansion, percent-decoding, and query
handling are not implemented.

### Persistence (the Done criterion)

`ResourceStore` is a JSON file keyed by server:

```json
{
  "schema": 1,
  "servers": {
    "files": {
      "server": "files",
      "resources": [
        {"uri": "file:///notes.md", "name": "notes", "mimeType": "text/markdown"}
      ],
      "templates": []
    }
  }
}
```

`ResourceStore::open` treats a missing file as an empty store.
`ResourceStore::save` writes `<path>.tmp` and renames it over the destination,
so a crash leaves the old document or the new one, never a partial write.
`insert` revalidates the catalogue before it is stored. `open` revalidates every
stored catalogue and the `server` map key:

| Stored state | Error |
|---|---|
| malformed JSON, missing `schema`, duplicate names/URIs, catalogue/key mismatch | `zero.fnd.corrupt` |
| `schema` present but not `1` | `zero.fnd.schema_version` |

After `save`, dropping the store, and reopening it, `resolve("@notes")` returns
the same `Resource` with no server connection: the catalogue is the authority
while the server is offline. A reference that is unknown or ambiguous after the
reload fails with the same typed errors as an online lookup. Tests assert this
round trip as the task's Done criterion.

### Slash commands

`parse_slash` (or `SlashCommand::parse`) accepts `/name` followed by
whitespace-separated tokens:

| Token | Result |
|---|---|
| `arg` | positional argument |
| `key=value` | named argument; split at the first `=` |
| `key=` | named argument with an empty value |
| `=value` | `zero.fnd.invalid_input` |
| repeated `key` | `zero.fnd.invalid_input` |
| `/` with no name, or no leading `/` | `zero.fnd.invalid_input` |

There is no quoting or escaping. `"two words"` is two positional tokens
(`"two` and `words"`); a value cannot contain whitespace. This is a deliberate
grammar limitation, not a bug to work around in the parser.

`PromptCatalog::validate_command` resolves `/name` and reports an unknown
command as `zero.fnd.not_found`. `Prompt::required_arguments` lists required
names; `Prompt::missing_required` computes what a command omitted;
`Prompt::bind` fills positional tokens into declared arguments in order,
applies named tokens, and rejects an unknown name, a duplicate binding, too
many positional tokens, or a missing required argument with
`zero.fnd.invalid_input` naming the argument(s). The bound map is the input for
`prompts/get`, which is deferred.

### Completions

`complete(prefix, source, kind)` is local and transport-free. Sources are
`ResourceCatalog`, `PromptCatalog`, and `ResourceStore` (all resources across
its catalogues). Matching is case-insensitive on the prefix and returns the
original spelling; results are sorted, deduplicated, and truncated to
`MAX_COMPLETIONS` (100). An empty prefix returns the first sorted names.
Resource and prompt namespaces never leak into each other.

Server-side completion is modelled but not wired into `Client`:
`CompletionRequest` builds the `completion/complete` params
(`ref.type` is `ref/prompt` or `ref/resource`, plus `argument` and optional
`context.arguments`), `CompletionResponse` parses and bounds the result, and
`request_completion` exchanges one request through an injected
`CompletionTransport`. The local helper does not call it; tests script the
transport.

### Resources and prompts error mapping

| Condition | Stable code |
|---|---|
| malformed list result, entry, duplicate name/URI/template, malformed `completion/complete` shape | `zero.prv.protocol` |
| unknown `@` target or `/` command | `zero.fnd.not_found` |
| ambiguous `@` target, malformed reference, bad slash grammar, bad or missing prompt argument | `zero.fnd.invalid_input` |
| corrupt resource store, duplicate/mismatched stored catalogue | `zero.fnd.corrupt` |
| unsupported store schema | `zero.fnd.schema_version` |

### Deferred resources and prompts work

- `resources/read`, `resources/subscribe`, `prompts/get`, and `completion/complete`
  transport calls from `Client`. This task ships the parsed catalogues, the
  reference and command layers, and an injectable completion transport.
- Pagination: `nextCursor` is ignored, so a paginated catalogue must be paged
  by the caller.
- RFC 6570 operator expressions, variable expansion, and percent-decoding in
  template matching.
- Quoting and escaping in slash commands, and named arguments whose values
  contain whitespace.
- Persisting prompts: only resource catalogues are in `ResourceStore`; prompts
  are fetched per connection.
- A host UI that renders completions and prompt argument prompts.

## Server mode

MCP-15 is a MAY: Zero **may** expose its tools, sessions, and events over MCP,
and it is **disabled by default**. T-MCP-10 implements the protocol half in
`crates/zero-mcp/src/server.rs`: a configuration gate, two injectable host
seams, and a JSON-RPC request handler. The transport accept loop (stdio or
Streamable HTTP) is deferred to a later task; `handle` and `handle_line` are the
seam it will call.

### Configuration and the gate

```rust
pub struct ServerConfig {
    pub enabled: bool,
    pub expose_tools: bool,
    pub expose_sessions: bool,
    pub expose_events: bool,
    pub server_name: String,
    pub protocol_version: McpRevision,
}
```

| Constructor | Effect |
|---|---|
| `ServerConfig::default()` | same as `disabled()`: master switch off, every capability off |
| `ServerConfig::disabled()` | `enabled: false`, all `expose_*: false`, name `zero`, latest revision |
| `ServerConfig::serving()` | `enabled: true`, every capability still off |
| `with_tools(bool)`, `with_sessions(bool)`, `with_events(bool)` | select individual capabilities |
| `with_server_name(name)` | `initialize.serverInfo.name` |
| `with_protocol_version(revision)` | fallback revision for `initialize` |

`McpServer::new(config, host)` is infallible and does not call the host. The
gate is checked on every request: while `enabled` is false, `check_enabled`,
`handle`, and `handle_line` refuse with `zero.fnd.unsupported`. An enabled
server with one `expose_*` flag off refuses only that capability's methods with
`Unsupported` and leaves the rest serving. `expose_events` is meaningful only
with `expose_sessions`; events are always delivered for a session.

### Host seams

The server never reads provider credentials, model configuration, or the
workspace. Every effect goes through one of two traits:

```rust
pub trait SessionHost {
    fn list_sessions(&self) -> Result<Vec<SessionInfo>>;
    fn prompt(&self, session_id: &str, text: &str) -> Result<PromptReceipt>;
    fn events(&self, session_id: &str, cursor: Option<&EventCursor>) -> Result<EventBatch>;
}

pub trait ToolHost {
    fn list_tools(&self) -> Result<Vec<Tool>>;
    fn call_tool(&self, name: &str, arguments: Value) -> Result<Value>;
}

pub struct SessionInfo { pub id: String, pub name: String, pub state: String, pub updated_ms: i64 }
pub struct PromptReceipt { pub message_id: String, pub event_cursor: Option<EventCursor> }
```

`SessionInfo` serialises as `id`, `name`, `state`, `updatedMs`. A
`PromptReceipt` cursor is passed through unchanged; the server never constructs
or advances a cursor, so the no-resumption rule in [Events](#events) still
holds. `ToolHost::call_tool` returns the structured result value: the server
puts it in `structuredContent` and in one `text` content block containing its
compact JSON. A host error becomes a JSON-RPC error object, never a tool-level
`isError` payload.

`&T` and `Box<T>` implement both traits, so a host can be passed by reference
or boxed. Tests script a host and need no socket, child process, or network.

### Capabilities

`initialize` returns the configured revision, `serverInfo`, and only the
capabilities whose flags are on:

```json
{
  "protocolVersion": "2026-07-28",
  "serverInfo": {"name": "zero", "version": "<crate version>"},
  "capabilities": {
    "tools": {"listChanged": false},
    "experimental": {
      "zero.sessions": {"list": true, "prompt": true, "promptDestructive": true},
      "zero.events": {"poll": true}
    }
  },
  "resultType": "complete"
}
```

`tools` appears only with `expose_tools`; `zero.sessions` only with
`expose_sessions`; `zero.events` only with both session and event flags.
`resultType` is present only on `2026-07-28`. No `Mcp-Session-Id` or
`sessionId` is issued: the endpoint is stateless and handles one request at a
time. A requested `protocolVersion` is accepted when it is one of the two
supported revisions; anything else falls back to the configured revision rather
than failing the handshake.

### Methods

| Method | Gate | Result |
|---|---|---|
| `initialize` | `enabled` | revision, `serverInfo`, capabilities |
| `tools/list` | `expose_tools` or `expose_sessions` | host tools plus enabled session tools |
| `tools/call` | `expose_tools`, or a session tool name with `expose_sessions` | tool result (`content`, `structuredContent`, `isError`) |
| `sessions/list` | `expose_sessions` | `{"sessions": [SessionInfo, ...]}` |
| `sessions/prompt` | `expose_sessions` | `{"messageId": "...", "eventCursor": "..."}` |
| `sessions/events` | `expose_sessions` **and** `expose_events` | `{"events": [...], "nextCursor": "...", "ttlMs": N}` |

`tools/list` exists when either tools or sessions are exposed, so an
editor-only client can discover the session tools even when the host tool
catalogue is off. Each event serialises as `id`, `kind`, `payload`, and
`deliveredMs`.

### Session tools and the destructive annotation

When sessions are exposed, `tools/list` includes Zero's own tools next to the
host's:

| Tool | Annotations | Default policy |
|---|---|---|
| `sessions/list` | `readOnlyHint: true`, `idempotentHint: true` | `Allow` in every mode |
| `sessions/prompt` | `readOnlyHint: false`, `destructiveHint: true`, `idempotentHint: false` | **`Ask`** in `Manual` and `Auto`, `Deny` in `Restricted` |
| `sessions/events` | `readOnlyHint: true`, `idempotentHint: true` | `Allow` in every mode (needs `expose_events`) |

`sessions/prompt` is a write that may change the workspace, so the explicit
`destructiveHint: true` makes [`crate::security::decide`] return `Ask` under a
client's default manual policy. The same tools are reachable through
`tools/call` by name (`{"name": "sessions/prompt", "arguments": {...}}`), where
the result is wrapped in a normal tool result. A reserved session tool name
wins over a host tool with the same name, so the destructive annotation is
never shadowed; host tools must not reuse those three names.

`resources/list`, `resources/read`, and `prompts/list` are intentionally not
served: the two host seams do not back resource or prompt catalogues. A later
task that adds those host methods can advertise them without changing this
gate.

### JSON-RPC error mapping

Every failure is an envelope, never a panic. `error.message` is one of five
fixed strings (`Parse error`, `Invalid Request`, `Method not found`,
`Invalid params`, `Internal error`); `error.data.zeroCode` carries the stable
Zero code and `error.data.remediation` the code's static remediation line. A
host error's own message is never copied onto the wire, so a payload or secret
inside it cannot reach the editor.

| Condition | `error.code` | `data.zeroCode` |
|---|---|---|
| server disabled, capability not exposed, unknown method | `-32601` | `zero.fnd.unsupported` |
| unparseable NDJSON line | `-32700` | `zero.fnd.invalid_input` |
| malformed request envelope (missing/incorrect `jsonrpc`, missing id or method, non-object, notification) | `-32600` | `zero.fnd.invalid_input` |
| malformed params, missing/empty string, non-object `arguments`, oversize or too-deep arguments | `-32602` | `zero.fnd.invalid_input` |
| host `InvalidInput`/`NotFound`/`SessionNotFound` | `-32602` | the host's stable code, e.g. `zero.ses.not_found` |
| any other host error (including `PolicyDenied`) | `-32603` | the host's stable code |
| oversize returned content, tool catalogue, session catalogue, or event batch | `-32603` | `zero.fnd.limit_exceeded` |

The request id is echoed for a parseable request; an id that cannot be detected
is `null`. Notifications are not supported, so a request without an id is an
invalid request.

### Bounds

| Bound | Constant | Default |
|---|---|---|
| one request value or NDJSON line | `MAX_REQUEST_BYTES` | 256 KiB |
| `tools/call` arguments bytes | `MAX_ARGUMENT_BYTES` | 64 KiB |
| `tools/call` arguments nesting | `MAX_ARGUMENT_DEPTH` | 32 levels |
| any returned result value | `MAX_RESULT_BYTES` | 1 MiB |
| `tools/list` entries | `MAX_TOOLS` | 512 |
| `sessions/list` entries | `MAX_SESSIONS` | 1,024 |
| `sessions/events` entries | `MAX_EVENTS` | 256 |

Oversize requests are rejected before parsing (`handle_line` checks the line
length first), and returned values are measured with a bounded streaming
writer, so an oversize host value is rejected without first materialising its
full JSON. Live catalogues and event batches are rejected, never truncated. An
argument that exceeds a cap is the caller's error (`-32602`); oversize returned
live data is the server's (`-32603`).

### Deferred server work

- The stdio and Streamable HTTP accept loops. `handle` and `handle_line` are
  complete; a transport task supplies framing, connection limits, and shutdown.
- Resource and prompt methods (`resources/list`, `resources/read`,
  `prompts/list`, `prompts/get`), which need host seams that do not exist yet.
- Server-initiated notifications, subscriptions, and `events/stream` push.
- Authentication and per-editor authorization for a listening socket.
- Persisting a server-side event cursor; the receipt cursor is opaque and
  supplied by the host.

## Auth

Source: the MCP `2025-11-25` [Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
specification, RFC 8414 (authorization server metadata), RFC 7636 (PKCE),
RFC 8707 (resource indicators), and OAuth Client ID Metadata Documents
(`draft-ietf-oauth-client-id-metadata-document-00`). T-MCP-07 implements the
client half in `crates/zero-mcp/src/auth.rs` (MCP-07 and MCP-13). Nothing in
this module makes a network request unless the caller passes the shipped
`reqwest` adapters; tests script the `MetadataFetcher` and `TokenTransport`
seams.

### Authorization server discovery

```rust
pub struct AuthorizationServer {
    pub issuer: Url,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub registration_endpoint: Option<Url>,
    pub code_challenge_methods_supported: Vec<String>,
    pub client_id_metadata_document_supported: bool,
}
```

`AuthorizationServer::discover(&issuer, &fetcher)` tries the well-known
candidates in the order the specification requires, accepting the first
document that parses:

| Issuer shape | Candidate order |
|---|---|
| no path (`https://auth.example.com`) | `/.well-known/oauth-authorization-server`, then `/.well-known/openid-configuration` |
| path (`https://auth.example.com/tenant1`) | `/.well-known/oauth-authorization-server/tenant1`, `/.well-known/openid-configuration/tenant1`, then `/tenant1/.well-known/openid-configuration` |

Issuer and endpoint rules are strict:

| Condition | Result |
|---|---|
| Issuer is `https`, or `http` on an explicit `127.0.0.1` test server | accepted |
| `http://localhost`, `http://` on any other host, or a non-HTTP scheme | `zero.fnd.invalid_input` |
| Issuer has userinfo, a query, or a fragment | `zero.fnd.invalid_input` |
| Metadata `issuer` differs from the expected issuer (host, port, path, or a `auth.example.com.evil` suffix) | `zero.prv.auth` |
| Metadata document is missing `issuer`, `authorization_endpoint`, or `token_endpoint`, or the shape is wrong | `zero.prv.protocol` |
| `authorization_endpoint`, `token_endpoint`, or `registration_endpoint` is not `https`/loopback or carries userinfo or a fragment | `zero.fnd.invalid_input` |
| No candidate returns a document | `zero.prv.not_found` |
| `code_challenge_methods_supported` is absent or does not contain `S256` | `zero.fnd.unsupported` (`require_pkce_s256`) |

Issuer comparison is parsed-URL equality, never a prefix: `https://auth.example.com`
and `https://auth.example.com/` are the same URL, while a different port, path,
scheme, or host is not. A document whose issuer does not match is a hard failure;
the client does not fall through to the next well-known candidate, because a
mismatch is an identity problem, not a missing document. The shipped
`ReqwestMetadataFetcher` does not follow redirects. `registration_endpoint` is
parsed only; DCR is not performed (CIMD is the primary registration path).

### PKCE and the resource parameter

`Pkce` is S256-only. A verifier must be 43 to 128 unreserved characters
(`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`), and the challenge is the unpadded
base64url SHA-256 of the verifier (the RFC 7636 Appendix B vector is a unit
test). `Pkce::from_verifier` builds the pair from caller-supplied CSPRNG bytes;
`Pkce::validate` recomputes the challenge and refuses a hand-built mismatch.
The verifier is redacted in `Debug`. Generating the verifier is the caller's
job because `zero-mcp` deliberately does not add an entropy dependency; the
sign-in layer above this crate owns the OS random source.

`AuthorizationServer::authorization_url(server_url, redirect_uri, state, pkce, resource, client_id)`
returns the URL with exactly these query parameters:

| Parameter | Value |
|---|---|
| `response_type` | `code` |
| `client_id` | the pre-registered id or the CIMD HTTPS URL |
| `redirect_uri` | the exact registered URI |
| `state` | caller-supplied, non-empty, at most 512 bytes, no control characters |
| `code_challenge` | `S256(verifier)` |
| `code_challenge_method` | `S256` |
| `resource` | the canonical MCP server URL (RFC 8707) |

`server_url` and `resource` are both canonicalised and must identify the same
MCP server, so a request cannot authorize one server and ask for a token bound
to another. `canonical_resource` requires `https` (or `http` on `127.0.0.1`), a
host, no userinfo, and no fragment; it lets the URL parser lowercase the scheme
and host and drop a default port. A redirect URI must be `https`, or `http` on
a loopback host (`127.0.0.1`, `::1`, or `localhost`), with no userinfo or
fragment. No `scope` parameter is invented: scope selection from protected
resource metadata is deferred.

### Code exchange and refresh

Both methods are public-client flows; neither sends a `client_secret`.

| Method | Form body |
|---|---|
| `exchange_code(transport, code, verifier, redirect_uri, client_id, resource)` | `grant_type=authorization_code`, `code`, `code_verifier`, `redirect_uri`, `client_id`, `resource` |
| `refresh(transport, refresh_token, client_id, resource)` | `grant_type=refresh_token`, `refresh_token`, `client_id`, `resource` |

The token response is checked before it is returned as an `AccessToken`:

| Condition | Result |
|---|---|
| `error` field present | `zero.prv.auth`, naming only the OAuth error code (a server description is not echoed) |
| HTTP 4xx | `zero.prv.auth` with the status |
| Body is not JSON, or `access_token` is missing/blank | `zero.prv.protocol` |
| `token_type` present and not `Bearer` | `zero.prv.protocol` |
| `resource` present and not the requested canonical resource | `zero.prv.protocol` |
| `expires_in` present | `expires_at_ms = now + expires_in * 1000`, saturating |
| `scope` present | split on whitespace into `scopes`; absent means empty |
| Unknown fields | ignored |

A rotated refresh token is returned in `TokenGrant::refresh_token` so a public
client does not silently keep the old one. `AccessToken` and `TokenGrant` never
print token values; `AuthHttpResponse` prints only the status and body length.

### Token binding and the theft fixture

```rust
pub struct AccessToken {
    pub token: String,
    pub issuer: Url,
    pub resource: Url,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub audience: Option<String>,
    pub expires_at_ms: Option<i64>,
}

pub struct TokenBinding {
    pub issuer: Url,
    pub resource: Url,
    pub client_id: String,
    pub audience: Option<String>,
}
```

`validate_token(&token, &binding, now_ms)` checks in this order and returns
`zero.prv.auth` on the first failure, naming only the failed dimension:

1. The token string is non-empty.
2. The token issuer equals the binding issuer exactly (parsed-URL equality).
3. The token resource equals the binding resource exactly.
4. The token client id equals the binding client id.
5. When the binding has an audience, the token audience equals it. When the
   binding has none, the audience is not checked, because many authorization
   servers do not return one.
6. A known expiry is after `now_ms`.

The theft fixture is the task's Done criterion: a token minted for server A
(issuer, resource, and audience all for A) presented with server B's binding
fails on the resource check, while the same token with A's binding succeeds. A
token with another issuer, another client id, a wrong expected audience, an
expired timestamp, or an empty value also fails. No `Debug`, `Display`, or
error output contains the token string; `AccessToken::is_expired` exposes the
expiry check without validating the rest.

### CIMD validation

`ClientMetadata` mirrors the document fields (`client_id`, `client_name`,
`redirect_uris`, `grant_types`, `response_types`,
`token_endpoint_auth_method`, `scope`). CIMD is the primary registration
mechanism; a pre-registered opaque client id remains accepted by
`authorization_url`.

| Check | Rule |
|---|---|
| `client_id` URL | `https` with a host and a path component; no userinfo, no fragment (`zero.fnd.invalid_input`) |
| Fetched document identity | the document's `client_id` string must equal the requested URL exactly (`zero.prv.auth`) |
| `client_name` | present and non-empty |
| `redirect_uris` | one to `MAX_REDIRECT_URIS` (16) entries; each `https` or loopback `http`; no `*` wildcard |
| Requested `redirect_uri` | byte-for-byte equal to one listed entry, after passing the redirect rules |
| `response_types` | must include `code` |
| `grant_types` | must include `authorization_code` |
| `token_endpoint_auth_method` | must be `none` (public client) |
| `scope` | when present, space-separated RFC 6749 scope tokens |

Redirect matching is exact: a changed port, an added path suffix, a scheme
change, or `localhost` in place of `127.0.0.1` is refused. The document URL
itself must contain a path, so `https://client.example` is not a valid client
id while `https://client.example/oauth/client-metadata.json` is.

`fetch_client_metadata(&fetcher, &client_id)` performs the GET through the
injectable `MetadataFetcher` seam, applies the `MAX_CLIENT_METADATA_BYTES`
(64 KiB) bound, parses the document, checks the identity, and runs the
structural checks. It does not check one redirect URI; the caller then uses
`validate_client_metadata(&metadata, redirect_uri)` for the request. A missing
document is `zero.prv.not_found`, malformed JSON is `zero.prv.protocol`, and an
identity mismatch is `zero.prv.auth`.

### Error mapping

| Condition | Stable code |
|---|---|
| Caller-supplied issuer, server, redirect, state, verifier, client id, or metadata document is invalid | `zero.fnd.invalid_input` |
| Issuer mismatch, OAuth `error`, HTTP 4xx from the token endpoint, token binding failure, CIMD identity mismatch | `zero.prv.auth` |
| Malformed metadata or token response, missing `access_token`, wrong `resource`/`token_type`, malformed CIMD JSON | `zero.prv.protocol` |
| No metadata document or no CIMD document | `zero.prv.not_found` |
| Server does not advertise PKCE `S256` | `zero.fnd.unsupported` |
| Timeout, unreachable host, oversized body | `zero.fnd.timeout`, `zero.fnd.offline`, `zero.fnd.limit_exceeded` |

### Deferred auth

- JWT/`at+jwt` signature and JWKS verification. Tokens are opaque here; the
  client validates the binding metadata it received, not a cryptographic
  signature. A resource server must still verify the token it accepts.
- Authorization server metadata caching, CIMD caching, and HTTP cache-header
  handling; every discovery or document read is a fresh request today.
- Protected Resource Metadata (RFC 9728) discovery and `WWW-Authenticate`
  parsing. The caller supplies the issuer and server URL; probing the MCP
  server for `authorization_servers` is not implemented.
- Scope selection from the 401 challenge or `scopes_supported`; the
  authorization URL currently carries no `scope`.
- Dynamic Client Registration (RFC 7591) beyond parsing
  `registration_endpoint`, and Refresh-token rotation enforcement on the
  server side.
- RFC 9207 authorization response `iss` parsing in a callback handler. The
  issuer identity is enforced at metadata discovery and token binding, but the
  browser callback parser itself lives in the sign-in integration.
- PKCE verifier entropy generation (the caller supplies CSPRNG bytes) and
  enterprise managed authorization extension enforcement.

## Security

T-MCP-08 implements the MCP security controls in
`crates/zero-mcp/src/security.rs` (MCP-08 and MCP-14). Each control is a small
policy object with no network access. Tests are scripted and need no socket or
child process.

### Schema pinning and approval

`SchemaPinStore` maps `(server, tool)` to the `Tool::schema_hash` of the tool
definition. The hash covers the input and output schemas and excludes titles and
descriptions, so a wording-only change is not a schema change. It is a
deterministic FNV-1a change detector, not a cryptographic signature.

```rust
pub enum PinOutcome {
    New,
    Unchanged,
    Changed { tools: Vec<ChangedTool> },
}

pub struct ChangedTool {
    pub name: String,
    pub pinned: Option<u64>,
    pub current: Option<u64>,
}
```

| Situation | `pin_catalog` | Host decision |
|---|---|---|
| first catalogue for the server | `New`, hashes recorded | `Allow` |
| every tool hash matches, same tool set | `Unchanged` | `Allow` |
| a schema changed, a tool was added, or a tool was removed | `Changed`, old baseline kept | **`Ask`** |
| description or title changed, schema unchanged | `Unchanged` | `Allow` |

`PinOutcome::decision()` is exactly `Ask` for `Changed`; a changed schema is
never silently accepted. The baseline is only replaced after the host approves
the new hashes:

```rust
pub fn pin_catalog(&mut self, server: &str, catalog: &ToolCatalog) -> PinOutcome;
pub fn require_approval(
    &mut self,
    server: &str,
    catalog: &ToolCatalog,
    approval: &SchemaApproval,
) -> Result<()>;
```

`SchemaApproval::approve_catalog(server, catalog)` approves every hash the host
just observed; `SchemaApproval::approve_changes(server, outcome)` approves
exactly the changed set. An approval is bound to one server and carries
`tool -> hash` (`None` for a removed tool).

| Approval | Result |
|---|---|
| empty (`SchemaApproval::empty`) | `zero.pol.ask` |
| contains the exact hash of every changed tool | proceeds and updates the baseline |
| contains a stale/old hash, the wrong server, or a partial set | `zero.pol.denied` |
| first pin or unchanged catalogue | proceeds without approval |

Approval for the previous hash never authorises the new one. Errors name tool
names only; they never contain a schema, description, title, or argument value.

`SchemaPinStore::open(path)` loads a JSON file (a missing file starts empty),
and `save()` writes it back. `SchemaPinStore::default()` and `new()` are
in-memory only, which is what tests use.

### Destructive-tool defaults

`ToolRisk` is `ReadOnly`, `Write`, or `Destructive`. Classification uses MCP
`annotations` first, then name/title/description words:

| Signal | Risk |
|---|---|
| `destructiveHint: true` | `Destructive` (wins over `readOnlyHint: true`) |
| `readOnlyHint: true` | `ReadOnly` |
| marker `delete`, `remove`, `drop`, `purge`, `overwrite`, `destroy`, `erase`, `truncate`, `wipe`, `unlink`, `rm` | `Destructive` |
| marker `write`, `execute`, `exec`, `shell`, `command`, `upload`, `create`, `update`, `patch`, `insert`, `set`, `put`, `post`, `move`, `rename`, `copy`, `run`, `install`, `deploy`, `send` | `Write` |
| no usable hint and no marker | unknown; `classify` reports `Write`, `decide` asks |

Markers are matched as whole words split on non-alphanumerics, so `remote` does
not match `remove` and `truncate_log` does match `truncate`.

`decide(tool, mode)` applies this matrix:

| Risk | `Restricted` | `Manual` (default) | `Auto` |
|---|---|---|---|
| `ReadOnly` | `Allow` | `Allow` | `Allow` |
| `Write` | `Ask` | `Ask` | `Allow` |
| `Destructive` | `Deny` | `Ask` | `Ask` |
| unknown (no read-only intent, no marker) | `Ask` | `Ask` | `Ask` |

An explicit `readOnlyHint: false` is a known write, not unknown. A tool that
never states read-only intent is **not** trusted just because `Auto` allows
writes: it asks in every mode. A missing hint is deliberately different from an
explicit `false`, because a hostile server should not become trusted by staying
silent. Annotations are hints from the server, so the policy still applies on
every call even when the schema did not change.

### Result size caps

`ResponseLimits` bounds one `tools/call` result before it reaches the caller:

| Field | Default | Constant |
|---|---|---|
| serialised `content` array | 1 MiB | `DEFAULT_MAX_CONTENT_BYTES` |
| serialised `structuredContent` | 1 MiB | `DEFAULT_MAX_STRUCTURED_BYTES` |
| content blocks | 1,024 | `DEFAULT_MAX_ITEMS` |

`check_tool_result(content, structured)` and
`check_tool_call_result(&ToolCallResult)` reject an oversize value with
`zero.fnd.limit_exceeded`. The message names the dimension and cap (for example
`MCP tool result content bytes 1048577 exceeds limit 1048576`) and never echoes
the content. The content byte count is the compact JSON length of the whole
array, so splitting one value across many blocks does not evade the cap. A
zero cap is `zero.fnd.invalid_input`.

### Timeouts

`TimeoutPolicy { request_ms, total_ms }` defaults to 30 s per request and five
minutes total. Validation requires both values to be non-zero, the request bound
to be no larger than the total, and both to stay under the crate maximum:

| Bound | Constant | Value |
|---|---|---|
| per request | `MAX_REQUEST_TIMEOUT_MS` | 10 minutes |
| total operation | `MAX_TOTAL_TIMEOUT_MS` | 1 hour |

A zero or inverted budget is `zero.fnd.invalid_input`; an over-large budget is
`zero.fnd.limit_exceeded`. `check_elapsed(elapsed_ms)` returns
`zero.fnd.timeout` when the total budget is reached, and `request_timeout()` /
`total_timeout()` expose `Duration` values for a transport.

### Resource URL SSRF policy

`check_resource_url(url)` is a self-contained policy for MCP resource URLs. It
does not depend on `zero-web`; a future shared egress guard may replace it.

| Input | Result |
|---|---|
| `http` or `https` with a public host | accepted |
| any other scheme (`file:`, `data:`, `javascript:`, `ftp:`, ...) | `zero.pol.denied` |
| userinfo (`https://user:pass@host/`, `https://user@host/`) | `zero.pol.denied` |
| `localhost`, `*.localhost`, `metadata`, `metadata.google.internal`, `metadata.azure.internal`, `instance-data`, `kubernetes.default(.svc)` | `zero.pol.denied` |
| loopback (`127.0.0.0/8`, `::1`), private (`10/8`, `172.16/12`, `192.168/16`), shared (`100.64/10`), link-local (`169.254/16` including `169.254.169.254`, `fe80::/10`), unique-local (`fc00::/7` including `fd00:ec2::254`), unspecified, broadcast | `zero.pol.denied` |
| IPv4-mapped IPv6 pointing at any blocked IPv4 range | `zero.pol.denied` |
| malformed absolute URL or missing host | `zero.fnd.invalid_input` |

The URL is parsed but never fetched, and no error echoes it or its query. DNS
names are not resolved here: a public-looking name that resolves to a private
address, redirects, and rebinding are deferred to the transport/egress guard.

### Replay guard

`ReplayGuard` is a bounded, TTL-scoped set of request ids. It is standalone so
callers can use it at the JSON-RPC or webhook seam; it is not wired into
`Client` implicitly.

| Property | Default |
|---|---|
| capacity | 4,096 ids (`DEFAULT_REPLAY_CAPACITY`) |
| window | 10 minutes (`DEFAULT_REPLAY_TTL_MS`) |
| eviction | first-in-first-out once full |

`check_and_record(id, now_ms)` returns:

| Outcome | Meaning |
|---|---|
| `Fresh` | not seen inside the window; now recorded |
| `Replay` | seen inside the window; must not be processed again |
| `Expired` | seen, but older than the window; pruned and recorded afresh |

Expired unrelated ids are pruned on every check. `check_and_record_pair(id,
method, now_ms)` keys by `(method, id)` so an id reused across methods is not a
false replay. A zero window or capacity is `zero.fnd.invalid_input`. The store is
in memory only; persistence across restarts is deferred.

### Security error mapping

| Condition | Stable code |
|---|---|
| changed schema with an empty approval | `zero.pol.ask` |
| stale, partial, or wrong-server approval | `zero.pol.denied` |
| SSRF-blocked resource URL | `zero.pol.denied` |
| malformed resource URL or missing host | `zero.fnd.invalid_input` |
| oversize tool result | `zero.fnd.limit_exceeded` |
| over-large timeout budget | `zero.fnd.limit_exceeded` |
| zero or inverted timeout budget; zero replay TTL/capacity | `zero.fnd.invalid_input` |
| total timeout reached | `zero.fnd.timeout` |

### Deferred security items

- Wiring the pin store, limits, timeouts, SSRF checks, and replay guard into
  `Client` and the transports. They are callable policy objects today; the
  transport still reads its own response bound and timeout.
- DNS resolution and redirect/re-resolution checks, connection-address pinning,
  and proxy egress policy for resource URLs.
- TLS pinning and certificate checks beyond the platform verifier.
- Cryptographic schema signatures or a transparency log. The pin hash detects a
  change; it does not stop a collision-seeking adversary.
- Persisting the replay guard and the pin store across processes, and sharing
  them between clients.
- Cancellation propagation (MCP-14) with task and transport work.
- A host approval UI. `SchemaApproval` and `ToolDecision` are the seam; the UI
  that renders `Ask` and records consent belongs to the host.

## Code mode

T-MCP-12 implements MCP-20 in `crates/zero-mcp/src/code_mode.rs`. Code mode
presents the tools in a `ToolCatalog` as a typed code API, lets a model write a
program against it, and routes every tool call through a bridge so policy,
approval, replay, and size checks apply per call. Only the executor's final
value is returned.

The module does **not** launch a sandbox, child process, interpreter, or network
connection. `CodeExecutor` is the execution seam; the only implementation in
the crate is a scripted test executor. Production execution (zero-kernel,
IPython, or an OS sandbox) is a follow-up, described under
[Deferred code-mode work](#deferred-code-mode-work).

### Two server shapes

`CodeModePattern::for_tool_count` chooses a default shape, and a caller may set
one explicitly:

| Shape | Threshold | Tools |
|---|---|---|
| `SingleTool` | fewer than 20 tools | one `code` tool embedding the generated API |
| `SearchExecute` | 20 or more tools | a read-only `search` tool plus an `execute` tool |

`code_tool(api, config)` returns the `code` tool. It is not read-only and not
idempotent (`readOnlyHint: false`, `idempotentHint: false`), so the default
manual policy asks before the program runs. Its input schema is
`{"code": string}` and its output schema is `{"result": any}`.

`search_execute_tools(api, config)` returns `search` then `execute`.
`search` takes `{"query": string}`, is read-only/idempotent, and indexes tool
names and descriptions without embedding the declaration block. `execute`
carries the same declarations and annotations as `code`.

A description template may use `{{types}}` and `{{example}}`. Without a
template the fixed preamble, declarations, and one example are assembled
deterministically. Tool descriptions are untrusted data: control characters are
replaced, each description is capped at 160 bytes, `*/` is escaped in JSDoc, and
the Markdown code fence is made longer than any backtick run in the embedded
text.

### Generated TypeScript

`GeneratedTool` carries `original_name`, `ts_accessor`, `python_name`,
`input_type`, `output_type`, `required`, and `description`.

```ts
export interface ListPullRequestsInput {
  filter?: { draft?: boolean; ids?: Array<number> };
  labels: Array<string>;
  owner: string;
  page?: number;
  state?: "open" | "closed";
}

export interface ListPullRequestsOutput {
  items: Array<{ id?: string }>;
  total: number;
}

export interface CodeModeApi {
  "list-pull.requests": (
    input: ListPullRequestsInput
  ) => Promise<ListPullRequestsOutput>;
}

export declare const codemode: CodeModeApi;
```

The example generated for this tool is:

```ts
const result = await codemode["list-pull.requests"]({
  labels: [],
  owner: "value",
});
```

TypeScript property names that are not identifiers are quoted; a valid one is
left bare. `codemode` access uses bracket notation for an invalid identifier,
for example `codemode["3d-render"]`, and dot notation otherwise, for example
`codemode.delete`.

### Generated Python

Python stubs use `TypedDict`, `NotRequired`, `Optional`, `Literal`, `List`, and
`Dict[str, Any]` inside a `codemode` class namespace:

```python
from typing import Any, Dict, List, Literal, NotRequired, Optional, TypedDict

class ListPullRequestsInput(TypedDict):
    labels: List[str]
    owner: str
    page: NotRequired[int]
    state: NotRequired[Literal["open", "closed"]]

class ListPullRequestsOutput(TypedDict):
    items: List[str]
    total: int

class codemode:
    @staticmethod
    def list_pull_requests(
        input: ListPullRequestsInput,
    ) -> ListPullRequestsOutput: ...
```

`NotRequired` needs Python 3.11 or later. If a schema property name is not a
valid Python identifier, that `TypedDict` is emitted in functional syntax
instead, for example `Name = TypedDict("Name", {"x-y": str})`.

### Schema coverage and limits

The generator understands this JSON Schema subset:

| Schema | TypeScript | Python |
|---|---|---|
| `object` with `properties`/`required` | interface, `?` for optional | `TypedDict` with `NotRequired` |
| nested `object` | inline object type | `Dict[str, Any]` |
| `array` with `items` | `Array<T>` | `List[T]` |
| `enum` of string/number/boolean/null | literal union | `Literal[...]` |
| `string`, `number`, `integer`, `boolean`, `null` | `string`, `number`, `number`, `boolean`, `null` | `str`, `float`, `int`, `bool`, `None` |
| a `type` array including `null` | union including `null` | `Optional[T]` for one non-null type |
| anything else | `unknown` with a comment | `Any` with a comment |

`$ref`, `anyOf`, `oneOf`, tuple `items`, more than one non-null type in a
Python union, and objects deeper than six levels are not resolved or rendered as
concrete types. They fall back to `unknown`/`Any` with a comment rather than
being guessed. `additionalProperties: false` becomes `{}` in TypeScript;
otherwise a property-less object becomes `Record<string, unknown>` or
`Dict[str, Any]`. `integer` is `number` in TypeScript because JavaScript has one
number type.

Type names are PascalCase. If two tools produce the same type name, the second
gets a deterministic numeric suffix (`FooInput_2`), so a declaration is never
ambiguous. Python function names are sanitized and a collision is a typed
error, because two tools cannot share one function name.

### Sanitization

| Tool name | TypeScript accessor | Python name |
|---|---|---|
| `list-pull.requests` | `codemode["list-pull.requests"]` | `list_pull_requests` |
| `3d-render` | `codemode["3d-render"]` | `_3d_render` |
| `delete` | `codemode.delete` | `delete_` |

Punctuation and non-ASCII characters split words, camelCase is split into
words, and the Python result is lower snake_case. A leading digit gets a `_`
prefix. A Python or JavaScript reserved word gets a `_` suffix (`delete` becomes
`delete_`). Two tools that sanitize to one Python name are rejected with
`zero.fnd.invalid_input`, and the message names both original tools. No
declaration is ever cut mid-identifier or mid-type: truncation removes whole
tool entries only.

### Declaration budget

`CodeModeConfig::max_api_bytes` defaults to 64 KiB (`DEFAULT_MAX_API_BYTES`) and
must be at least 128 bytes so the fixed header fits. `CodeApi.entries` always
covers every catalogue tool; `CodeApi.declarations` is a bounded prefix of whole
entries and `CodeApi.truncated` reports omitted entries. Search uses `entries`,
so a tool omitted from the declaration block can still be found and called by
name.

### Bridge and policy flow

`execute(program, executor, host, limits)` performs these steps:

1. Validate the bounds and reject a source larger than 256 KiB
   (`DEFAULT_MAX_SOURCE_BYTES`).
2. Wrap the bridge in a call counter capped at 64 calls
   (`DEFAULT_MAX_CALLS`) and run the executor.
3. Return only the executor's value, rejecting it if its compact JSON exceeds
   1 MiB (`DEFAULT_MAX_RESULT_BYTES`).

The `CodeModeHost` bridge performs these steps for each call:

1. Resolve an accessor (`codemode.foo`, `codemode["foo-bar"]`, a bare Python
   name, or the original tool name) to exactly one catalogue tool.
2. Check `(program_id, call_index)` against the `ReplayGuard`; a repeat is
   `zero.pol.denied`. The automatic path uses a monotonic index per program;
   `call_at` exposes an explicit index for the host.
3. Check argument bytes (64 KiB default) and nesting depth (32 default).
4. Classify the tool with `security::classify` and apply `security::decide`
   with the configured `PolicyMode`.
5. `Allow` runs; `Ask` consults the `ApprovalOracle`; `Deny` aborts. An
   unapproved `Ask` is `zero.pol.ask`, and a `Deny` is `zero.pol.denied`.
6. Run the tool through `ToolHost`, replace any host error message with a fixed
   one (keeping the stable error code), and apply `ResponseLimits` to the
   result.
7. Record `CallRecord { tool, risk, decision, approved }`. Arguments, results,
   and program text are never recorded or logged.

`ApprovalOracle::approve(tool, risk)` sees the tool name and risk class only,
never the arguments. `DenyAllApproval` is the default, so an `Ask` fails closed
unless the host installs an oracle. Tests script approvals.

| Condition | Stable code |
|---|---|
| unknown tool or ambiguous accessor | `zero.fnd.not_found` / `zero.fnd.invalid_input` |
| repeated `(program, call index)` | `zero.pol.denied` |
| `Ask` without approval | `zero.pol.ask` |
| `Deny`, including destructive tools in `Restricted` | `zero.pol.denied` |
| source, result, call, argument, or result-size cap | `zero.fnd.limit_exceeded` |
| malformed bounds | `zero.fnd.invalid_input` |

### Final-result-only rule

Intermediate tool results stay inside the executor. The bridge returns one
value at a time to the program; `execute` returns only the executor's final
value and never accumulates bridge results. A program can read two tools, filter
the data, make an approved write, and return one object; the caller sees only the
final object. Neither the program nor any intermediate value is logged.

### Caps

| Bound | Default | Constant |
|---|---|---|
| generated declarations | 64 KiB | `DEFAULT_MAX_API_BYTES` |
| one tool description | 160 bytes | `DEFAULT_MAX_DESCRIPTION_BYTES` |
| program source | 256 KiB | `DEFAULT_MAX_SOURCE_BYTES` |
| final result | 1 MiB | `DEFAULT_MAX_RESULT_BYTES` |
| bridge calls | 64 | `DEFAULT_MAX_CALLS` |
| one call's arguments | 64 KiB | `DEFAULT_MAX_ARGUMENT_BYTES` |
| argument nesting | 32 | `DEFAULT_MAX_ARGUMENT_DEPTH` |
| search hits | 16 | `DEFAULT_MAX_SEARCH_HITS` |
| search description | 16 KiB | `MAX_SEARCH_DESCRIPTION_BYTES` |

### Test evidence

`crates/zero-mcp/src/code_mode.rs` has 20 unit tests, all scripted with no
sandbox or network. They cover:

- TypeScript output for required/optional properties, enums, arrays, nested
  objects, quoted property names, JSDoc `*/` escaping, and fence length.
- Python output for `TypedDict`, `NotRequired`, `Literal`, `List`,
  `Dict[str, Any]`, valid snake_case, functional syntax for invalid property
  names, and keyword/leading-digit sanitization.
- Sanitization of `list-pull.requests`, `3d-render`, and `delete`, plus a
  collision error naming both tools.
- Whole-entry truncation with `truncated` and a declarations length under the
  budget, and deterministic regeneration.
- `code` description content and schema, `{{types}}`/`{{example}}` templates,
  and the search/execute shape with a 25-tool catalogue.
- Unknown and too-deep schemas falling back with a comment.
- The Done criterion: a scripted executor makes two read calls and one approved
  write through the bridge, filters the intermediate data, and returns only the
  final object; the host saw three calls and the caller saw no intermediate
  value.
- Policy: read allowed, write asks without approval, destructive denied in
  `Restricted`, unknown asks, an approved write proceeds, and a policy refusal
  still aborts the program when a misbehaving executor swallows the error.
- Source, result, call-count, argument-byte, and argument-depth caps; replay
  rejection; errors and call records carrying no arguments or results; no
  secret in declarations; search hits with name/description/accessor.

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-mcp -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-mcp --all-targets -j 1 -- -D warnings
```

### Deferred code-mode work

- The executor is a seam, not a sandbox. Running model-written TypeScript or
  Python belongs in zero-kernel/IPython or an OS sandbox with the same bridge
  and caps; this task deliberately does not spawn a process or claim isolation.
- Full JSON Schema 2020-12 typing (`$ref`, `anyOf`, `oneOf`, tuples,
  discriminated unions) and reconstruction of nested Python `TypedDict` classes
  instead of `Dict[str, Any]`.
- Streaming or incremental declaration paging for very large catalogues; today
  the declarations are a bounded prefix and search indexes all entries.
- A persistent replay guard and shared call log across processes.
- Wiring code mode into a provider tool loop and the host approval UI.

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
only bounded structure is enforced. Schema pinning (T-MCP-08) is implemented in
`security.rs` on top of these hashes; see [Schema pinning and
approval](#schema-pinning-and-approval).

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

`crates/zero-mcp/tests/tasks.rs` drives the task lifecycle through the same
scripted seam. It asserts the full `working` -> `input_required` ->
`tasks/update` -> `completed` flow, a `tools/call` task result parsed into
`ToolCallOutcome::Task` and polled to completion, that `2025-11-25` never
yields the task variant, cancellation, a failed task with its JSON-RPC error,
URL-mode task input requiring host approval, malformed task shapes, TTL expiry
with a fake clock, the changing and default poll intervals with recorded
sleeps, the attempt bound, the revision gate, unknown-state preservation, and
redaction (`TaskId` `Debug`/`Display`, `Task` debug output, and server error
messages).

`crates/zero-mcp/tests/events.rs` drives a scripted `EventSource` and the
webhook path with an injected clock. It asserts cursor order and advancement,
resync on an expired cursor (including replay from the oldest event), TTL
renewal, zero-TTL expiry, the resync and attempt bounds of `poll_until_idle`,
rejection of a malformed polled event without cursor consumption, valid
lowercase/uppercase/prefixed signatures, invalid and tampered signatures,
missing and empty headers, timestamp boundary/old/future checks, verification
before JSON parsing, duplicate suppression and seen-set eviction, malformed
event payloads, and that a raw body, key id, or signature never appears in an
error. The RFC 4231 HMAC vectors and the debug redaction of keys and payloads
are unit tests in `crates/zero-mcp/src/events.rs`.

Apps and extensions have unit tests in `crates/zero-mcp/src/apps.rs` and need
no browser. They assert `ui://` acceptance and refusal (including
`javascript:`, `data:`, `http(s):`, userinfo, ports, queries, fragments, and
dot segments), hostile `srcdoc` quoting with exactly one real `</iframe>`, the
sandbox and CSP token sets (`allow-same-origin` and `unsafe-eval` absent),
refusal of top-level navigation, popups, downloads, dangerous schemes,
`_top`/`_parent`/`_blank`, and origin mismatches (including a port mismatch and
userinfo disguises), acceptance of a listed subframe and form origin, the
relative-target rule, `postMessage` same-frame enforcement and `window.open`
refusal, unknown extensions ignored, a required unknown extension reported
without a fatal negotiation but mapped to `zero.fnd.unsupported` on demand,
unknown payload fields ignored, and malformed extension entries rejected.

OAuth 2.1 has unit tests in `crates/zero-mcp/src/auth.rs` and needs no network.
A scripted `MetadataFetcher` and `TokenTransport` drive discovery, code
exchange, refresh, and CIMD. They assert the well-known candidate order (with
and without an issuer path), strict issuer equality and scheme rules, the
`S256`-only requirement, the RFC 7636 vector, authorization URL parameters
(`response_type`, `state`, `code_challenge_method`, `resource`), refusal of a
resource for another server, missing/mismatched PKCE, the public-client form
without a `client_secret`, rejection of a missing `access_token`, wrong
`resource`, wrong `token_type`, and OAuth errors without the server description.
Token binding tests cover the theft fixture (a token for server A fails on
server B and succeeds on A), wrong issuer/client/audience, expiry, an empty
token, and redaction of access and refresh tokens from `Debug`, `Display`, and
every error. CIMD tests cover the HTTPS-plus-path client id, public-client
metadata rules, the redirect-count bound, exact redirect matching (port, path,
scheme, and localhost variations), wildcard refusal, and document identity
mismatch. The theft fixture is the task's Done criterion and is asserted as
such.

Security has unit tests in `crates/zero-mcp/src/security.rs` and needs no
network. They assert a first pin is `New`, an identical catalogue is
`Unchanged`, a description-only change is `Unchanged`, and a changed schema is
`Changed` with a decision of exactly `Ask`; that a stale approval of the old
hash is denied, an empty approval asks, and an approval of the exact new hash
proceeds; and that the store round-trips through a JSON file. They cover the
risk matrix for annotated and marker-derived tools (including the unknown-tool
`Ask` default in every mode), every result-size dimension with no payload in the
error, timeout validation and total-budget expiry, the resource-URL rules for
schemes, userinfo, loopback, private, shared, link-local, unique-local,
IPv4-mapped, and metadata hosts, and replay outcomes for repeats, expiry,
pruning, eviction, and `(method, id)` keys. Leak checks assert that no error
contains a tool-result secret, a description, a URL, or a URL query token.

Resources and prompts have unit tests in `crates/zero-mcp/src/resources.rs` and
need no network. They assert all three `@` reference forms and malformed
references, exact-URI-before-name precedence, unique and ambiguous
case-insensitive names, template matching and template ambiguity, rejected
operator expressions, and catalogues rejecting duplicate names, duplicate URIs,
duplicate templates, and malformed shapes. The persistence tests write a store,
drop it, reopen it, and resolve the same resource while no server is connected;
an unknown reference and a case-insensitive ambiguity after the reload are the
same typed errors as an online lookup. The same tests assert corrupt JSON, a
missing/unsupported schema, stored duplicates, and a catalogue/key mismatch fail
with typed errors. Slash tests cover
positional and named parsing, empty values, no-quoting behaviour, unknown
commands (`zero.fnd.not_found`), missing required arguments, duplicate and
unknown named arguments, and positional overflow. Completion tests cover
case-insensitive prefix filtering, sorting, deduplication across servers, the
`MAX_COMPLETIONS` bound, namespace separation, the `completion/complete` params
round trip, response bounds, and a scripted `CompletionTransport`.

Server mode has unit tests in `crates/zero-mcp/src/server.rs` and needs no
network. Scripted `SessionHost`/`ToolHost` implementations drive every method.
They assert a default `ServerConfig` is disabled and every request is refused
with `zero.fnd.unsupported`; that enabling only tools exposes exactly the host
tools and no session methods; that enabling sessions advertises `sessions/list`
and `sessions/prompt` with `destructiveHint: true` on the prompt and that
`security::decide` returns `Ask` in the default mode; that `sessions/events`
needs both flags; the editor flow `initialize` -> `sessions/list` ->
`sessions/prompt` -> `sessions/events` where the new event is returned from the
prompt receipt's cursor (the Done criterion); unknown methods, malformed
params, malformed envelopes, and an unparseable line produce `-32601`, `-32602`,
`-32600`, and `-32700` respectively; a host error with a secret in its message
never appears in the response; oversize arguments, requests, session
catalogues, event batches, and tool content are rejected; and capabilities
track each flag (including an older revision omitting `resultType`).

Code mode has unit tests in `crates/zero-mcp/src/code_mode.rs` and needs no
sandbox or network. They cover the TypeScript and Python stubs, sanitization and
collisions, whole-entry truncation, both server shapes, the scripted two-reads
and one-approved-write Done criterion, the policy matrix, replay, every cap, and
redaction. See [Code mode](#code-mode) for the test list and the deferred
sandbox work.

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

## Conformance

T-MCP-11 and MCP-19 ship as declarative JSON fixtures plus a replay runner
(`zero_mcp::conformance`). Fixtures are checked in under
`crates/zero-mcp/tests/fixtures/conformance/`;
`crates/zero-mcp/tests/conformance.rs` loads every fixture, replays it through
the real client types, and asserts a 100% pass with both revisions covered.
This is a normal `cargo test -p zero-mcp` target, so it runs in CI.

### Fixture format

The format is versioned; `schema_version` must be `1`.

```json
{
  "schema_version": 1,
  "revision": "2026-07-28",
  "name": "conformance-2026-07-28",
  "exchanges": [
    {
      "name": "tools/call returns resultType complete",
      "request": {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": "echo", "arguments": { "text": "hello" } }
      },
      "response": {
        "jsonrpc": "2.0",
        "id": 3,
        "result": {
          "resultType": "complete",
          "content": [{ "type": "text", "text": "hello" }]
        }
      },
      "expected": {
        "result_type": "complete",
        "content": [{ "type": "text", "text": "hello" }]
      }
    }
  ]
}
```

Rules enforced before replay:

- `schema_version` must be `1`; a different value is
  `ConformanceError::UnsupportedSchemaVersion`.
- A fixture with zero exchanges is `ConformanceError::NoExchanges`.
- `revision` must be `2025-11-25` or `2026-07-28`; anything else is
  `ConformanceError::UnsupportedRevision`.
- `request.id` must equal the exchange's 1-based position, and `request.method`
  must be supported. The scripted transport checks the real client's outgoing
  id and method, so a wrong id or order is a typed fixture error rather than a
  mismatched response.
- `response` must name JSON-RPC `2.0`, echo the request id, and carry exactly
  one of `result` or `error`. A response whose `protocolVersion` (or
  `_meta.protocolVersion`) differs from the fixture revision is rejected.
- An error response must declare `expected.error_code` and may declare nothing
  else. A result response must not declare `error_code`.
- `expected` must declare at least one outcome.
- `request.params` drive `tools/call` (`name`, `arguments`, and
  `inputResponses` for an MRTR retry) and `tasks/get` (`taskId`);
  `initialize` must declare the fixture revision.

`expected` fields are all optional and only the declared ones are compared:
`negotiated_revision`, `tool_names`, `tool_catalog_hash` (16 hex digits of
`ToolCatalog::schema_hash`), `read_only_tools`, `result_type`, `content`,
`structured_content`, `task_state`, `input_request_count`, `resource_names`,
`prompt_names`, and `error_code`.

### What each revision covers

- `2025-11-25.json`: `initialize`, `tools/list` without `resultType` (parsed as
  `complete`), a complete `tools/call`, `resources/list`, and a JSON-RPC error.
- `2026-07-28.json`: `initialize` with `resultType`, `tools/list` with
  annotations and cache hints, a complete `tools/call` with
  `structuredContent`, an `input_required` result plus its one
  `inputResponses` retry, a `task` handle in `working`, `prompts/list`, and a
  JSON-RPC error.

The runner also verifies that a parsed `tools/list` catalogue is cached unless
`ttlMs` is `0`; a fixture does not need a separate cache-hit exchange.

### Adding an exchange

1. Pick the fixture for the revision and keep it small.
2. Append one object with a unique `name`, the next 1-based `id`, the request,
   the response envelope in replay order, and only the `expected` fields that
   matter. Fixtures contain data, never code or expressions.
3. Run `cargo test -p zero-mcp --test conformance`. An expectation mismatch is
   reported with the exchange name and every differing field; a structural
   problem is a typed `zero_mcp::conformance::ConformanceError`.
4. If a new JSON-RPC method is needed, add it to `SUPPORTED_METHODS` and to the
   runner dispatch. Unsupported methods are rejected, never skipped.

### CI

The suite is part of the crate's test target, so the normal gate covers it:

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
- Declaring `io.modelcontextprotocol/tasks` in per-request capabilities;
  `ToolCallOutcome::Task` parsing and the task methods are implemented.
- Task routing headers (`Mcp-Name: <taskId>`) and task notifications
  (`notifications/tasks`, `subscriptions/listen`); only polling is implemented.
- Persisting task ids across restarts is the caller's responsibility; no
  `zero-store` integration is included.
- Progress on `tasks/update`: the stable `2026-07-28` extension defines no
  progress field, so only `inputResponses` is sent.
- Events (T-MCP-05) ship the poll loop and webhook verifier; the `events/stream`
  push transport, the `events/subscribe` HTTP server, `events/list`, and the
  event capability declaration are deferred (see [Deferred push
  transports](#deferred-push-transports)).
- Durable event cursors, the persisted dedupe window, and event audit records.
- Real browser enforcement of the app sandbox and CSP (T-MCP-11): loading the
  generated document in a browser, confirming an opaque origin, blocked
  top-level navigation, blocked `window.open`, and blocked network requests.
  T-MCP-06 asserts the policy and markup, not browser behaviour.
- Per-resource `_meta.ui.csp` tightening, MCP Apps `permissions` (camera,
  microphone, clipboard), the `ui/initialize` `postMessage` bridge, and
  `sendOpenLink`. The host currently grants only `allow-scripts` and a fixed
  strict policy.
- Enforcing extension version compatibility. Negotiation matches identifiers
  and records versions; it does not compare version ranges.
- Enterprise managed authorization enforcement carried by an extension payload;
  T-MCP-07 implements the OAuth 2.1 client flow, not the managed policy.
- Signature/JWKS verification, issuer metadata and CIMD caching, Protected
  Resource Metadata discovery, scope selection, DCR registration, and RFC 9207
  callback `iss` parsing (see [Deferred auth](#deferred-auth)).
- Resources, prompts, and completions (T-MCP-09) are implemented in
  `resources.rs`; `resources/read`, `prompts/get`, pagination, RFC 6570
  operators, and quoted slash arguments are deferred (see [Deferred resources
  and prompts work](#deferred-resources-and-prompts-work)).
- Server-mode transport wiring: `McpServer` handles one JSON-RPC value or
  NDJSON line at a time, but the stdio and Streamable HTTP accept loops,
  socket authentication, and resource/prompt host seams are deferred (see
  [Deferred server work](#deferred-server-work)).
- A shared/persistent `tools/list` cache and cross-client `cacheScope`
  semantics.
