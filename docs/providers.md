# Providers

`zero-model` normalizes hosted and local providers behind one trait.

## Trait

```rust
trait Provider {
    fn id(&self) -> &str;
    fn capabilities(&self) -> Capabilities;
    fn complete(&mut self, request: &CompletionRequest, sink: &mut dyn EventSink)
        -> Result<ProviderResponse>;
    fn classify(&self, error: &ZeroError) -> RetryClass;   // default: by code
}
```

`EventSink::event` returns `Control::Cancel` to stop mid-stream. The response
carries model, text, thinking, tool calls, normalized usage, stop reason, and
latency.

## Adapters

| Adapter | Transport | Fixture | Live flag |
|---|---|---|---|
| `OpenAiProvider` | OpenAI-compatible `/chat/completions` SSE | `tests/fixtures/openai_stream.sse` | `ZERO_LIVE_OPENAI=1`, `OPENAI_API_KEY` |
| `OllamaProvider` | Ollama `/api/chat` NDJSON, `/api/show` capabilities | `tests/fixtures/ollama_stream.ndjson`, `ollama_show*.json` | `ZERO_LIVE_OLLAMA=1`, `OLLAMA_HOST` |

The fixture tests run the real adapter against a tiny loopback HTTP server, so
the transport path is exercised without a network. LM Studio works through the
Ollama adapter because it exposes the same API shape.

## Retry classification

| Code | Class |
|---|---|
| `zero.prv.rate_limited`, `overloaded`, `timeout`, `unavailable`, `zero.fnd.offline` | Safe |
| `zero.prv.stream_broken` | Unsafe (could duplicate output) |
| auth, bad request, context length, content filter, no tools, protocol | Never |

Backoff is exponential with deterministic jitter (`RetryPolicy`), so simulations
reproduce. The conformance suite asserts that every adapter agrees with the
shared table.

## Tool support

Tool support is detected, not assumed. `OllamaProvider::probe_tools` reads
`capabilities` from `/api/show`; a model without `tools` refuses a tool-bearing
request with `zero.prv.no_tools` before making the chat call.

## Conformance suite

`zero_model::conformance::run` checks five cases: streamed text order and a final
`done`, tool-call shape, usage emitted once and normalized, retry classification,
and cancellation. `ScriptedProvider` passes it; a scripted provider without tools
fails the tool case, proving the suite can reject an adapter.

## Error mapping

See `docs/errors.md`. Every HTTP and transport failure maps to a stable code with
one remediation. `errors::tests::a_fixture_for_every_error_code` exercises 14
status/body combinations plus six transport kinds.
