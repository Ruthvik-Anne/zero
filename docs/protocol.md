# Client protocol

`zero_types::proto` defines frames; `protocol/ts/reader.mjs` is the TypeScript
projection of the same schema. Both readers decode `protocol/golden/*.bin`.

## Wire format

```
┌────────────────────┬───────────────────────────────┐
│ u32 big-endian len │ UTF-8 JSON frame (len bytes)  │
└────────────────────┴───────────────────────────────┘
```

- Maximum frame: 8 MiB. A larger declared length is a typed
  `zero.fnd.limit_exceeded` error, before reading the body.
- A trailing partial frame is an error; a stream is only valid at frame
  boundaries.
- Every frame carries `v` (protocol version, currently `1`). A different version
  is refused with `zero.fnd.schema_version`.

## Frame fields

| Field | Type | Meaning |
|---|---|---|
| `v` | u16 | Protocol version. |
| `kind` | enum | `hello`, `attach`, `snapshot`, `event`, `command`, `result`, `approval`, `action`, `error`. |
| `correlation` | string | Request/response correlation id. |
| `session` | string? | Session id when the frame belongs to one. |
| `generation` | u64? | Cursor generation (SES-07). |
| `sequence` | u64? | Cursor sequence within the generation. |
| `payload` | JSON | Kind-specific body. |

## Idempotency

Every `command` frame's payload carries `clientId + commandId`; the journal
(SES-09) guarantees one effect per key. The protocol carries secret *tags*,
never values (SEC-04).

## Golden fixtures

`v1-frames.bin` covers hello, event, command, and error; `v1-stream.bin` covers
attach, snapshot, approval, and action with cursor fields. The JSON siblings are
the expected projection. Both the Rust test
(`proto::tests::golden_fixtures_decode_identically`) and
`node protocol/ts/check.mjs` must pass; the TypeScript check also re-encodes and
compares bytes.
