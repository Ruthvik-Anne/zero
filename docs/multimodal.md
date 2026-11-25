# Multimodal inputs, attachments, and accounting

`zero-mm` owns the multimodal slices. This document covers T-MM-01 (inputs,
attachments, `@` references, typed blocks, per-modality accounting) for MM-01
and MM-02, T-MM-02 (originals, preprocessing plans, and processor seams) for
MM-02, MM-03, and the untrusted-text side of MM-04, T-MM-03 (sandboxed computer
use with an escape boundary) for MM-03, MM-05, MM-06, and MM-10, T-MM-04 (live
host computer use policy) for MM-04, MM-05, MM-07, and MM-11, T-MM-06 (local CPU
model consent and the per-modality capability gate) for MM-06, MM-13, and
MM-14, and T-MM-05 (verification and recordings) for MM-05, MM-08, and MM-09.
Redaction itself is still a later task.

| Slice | Module | State |
|---|---|---|
| T-MM-01 inputs, attachments, references, blocks, accounting | `src/input.rs` | implemented |
| T-MM-02 preprocessing | `src/preprocess.rs` | implemented (seams only; no codecs) |
| T-MM-03 sandboxed computer use | `src/sandboxed.rs` | implemented (boundary only; no VM driver) |
| T-MM-04 live host computer use | `src/computer_use.rs` | implemented (policy only; no execution) |
| T-MM-05 verification and recordings | `src/recordings.rs` | implemented (no capture or codec) |
| T-MM-06 local CPU model consent and capability gate | `src/consent.rs` | implemented |

`lib.rs` re-exports the input surface: `Attachment`, `AttachmentStore`,
`AttachmentMeta`, `Modality`, `Source`, `Reference`, `ReferenceKind`,
`parse_reference`, `scan_references`, `ContentBlock`, `InputMessage`, `Role`,
`build_input`, `build_input_with_mapping`, `build_input_for_role`, `BuiltInput`,
`RefMapping`, `ModalityUsage`, `UnknownDimension`, `Dimension`, `account`,
`decode_base64`, and the `MAX_*` constants.

It re-exports the consent surface separately: `LocalModelRequest`,
`ConsentPrompt`, `ConsentDecision`, `LocalModality`, `LocalCapability`,
`CapabilityState`, `Authorization`, `DownloadPlan`, `authorize`,
`CapabilityRegistry`, and the consent `MAX_*` constants.

It re-exports the preprocessing surface separately: `OriginalStore`,
`OriginalRef`, `ImagePlan`, `ImageWork`, `Tile`, `AudioPlan`, `AudioWork`,
`AudioChunk`, `VideoPlan`, `VideoWork`, `plan_image`, `plan_audio`,
`plan_video`, `ImageProcessor`, `OcrEngine`, `Transcriber`, `FrameSampler`,
`Processors`, `SourceGeometry`, `PreprocessPlan`, `preprocess`, `Preprocessed`,
`AppliedWork`, `Derived`, `DerivedKind`, `DerivedPayload`, `DerivedMeta`,
`PreprocessAccounting`, and the preprocessing `MAX_*` constants.

It re-exports the recordings surface separately: `Recording`, `Chapter`,
`LabeledShot`, `Assertion`, `ShortcutFlag`, `FlowEvent`, `build`, `verify`,
`Verification`, `write_artifacts`, `ArtifactBundle`, `ArtifactLimits`,
`Manifest`, `ManifestChapter`, `ManifestShot`, `read_manifest`, the artifact
file-name constants, and the recordings `MAX_*` constants.

It re-exports the computer use surface separately: `Target`, `ActionKind`,
`ComputerAction`, `Risk`, `PolicyMode`, `Decision`, `AskView`, `ask_prompt`,
and `authorize` as `authorize_computer_use`. The alias keeps the consent
`authorize` export intact; both modules remain callable through their own path
(`computer_use::authorize` and `consent::authorize`).

It re-exports the sandbox surface separately: `SandboxBackend`, `SandboxSpec`,
`SandboxState`, `SandboxSession`, `SandboxRunner`, `ActionRecord`,
`ActionOutcome`, `EscapeAttempt`, `EscapeKind`, `BlockedAttempt`, `EscapeReport`,
`launch`, `execute`, `stop`, `check_escape`, `check_scratch_write`, and the
sandbox `MAX_*`/`MIN_*` constants.

## Input routes

Every route ends in the same validated `Attachment` or `ContentBlock`; no route
bypasses the checks below.

| Route | How it enters | Notes |
|---|---|---|
| Inline text | `build_input("...", &[], &store)` | Literal runs become `ContentBlock::Text`. |
| Inline image/audio/video/document | `Source::Inline { bytes_b64 }` | Standard padded base64; decoded size must equal `bytes`. |
| Pasted attachment | Pass it in the `attachments` slice | Attachments are emitted before the text walk. |
| Drag and drop | Pass it in the `attachments` slice | Same path as paste. |
| Clipboard | Pass it in the `attachments` slice | Same path as paste. |
| Android share sheet | Pass it in the `attachments` slice | The Android gateway is a later task; the Rust side is this slice. |
| Local file | `Source::Path`, or `AttachmentStore::open_path` | Absolute path inside an allowed root; the store records the real length. |
| Remote URL | `Source::Url` | `http(s)` only, no fetch in this slice. |
| `@file:path` | `build_input` expansion | Resolves through the store; a text file becomes a `Text` block, other types keep their modality. |
| `@image:path` | `build_input` expansion | The file must infer as an image. |
| `@url:https://...` | `build_input` expansion | Recorded as a URL attachment; never fetched. |
| Bare `@name` | `build_input` expansion | Selects an attachment by `Attachment::name`; duplicates are an ambiguity error. |

`build_input` emits the pre-collected `attachments` first, in slice order, then
walks the prompt left to right. Literal text and expanded references therefore
keep their relative order after the leading attachments.

## Attachment rules

```rust
Attachment {
    id, kind, source, mime, bytes, name
}
```

- `id` is non-empty, at most `MAX_ID_CHARS` (128) characters, with no control
  characters or whitespace. Store-generated ids look like `att-<16 hex>` and
  are derived from the modality, MIME type, source, and length.
- `kind` is `Text`, `Image`, `Audio`, `Video`, or `Document`.
- `mime` must be a `type/subtype` essence that matches `kind`:

| Modality | Accepted MIME family |
|---|---|
| Text | `text/*`, `application/json`, `application/xml`, `application/yaml` |
| Image | `image/*` |
| Audio | `audio/*` |
| Video | `video/*` |
| Document | PDF, RTF, Word, OOXML Word, OpenDocument text, EPUB, CSV, HTML, Markdown, `text/plain`, `application/octet-stream` |

- Byte caps are per attachment and checked before any decode or file read:

| Modality | Cap |
|---|---|
| Text | `MAX_TEXT_BYTES` = 8 MiB |
| Image | `MAX_IMAGE_BYTES` = 20 MiB |
| Audio | `MAX_AUDIO_BYTES` = 200 MiB |
| Video | `MAX_VIDEO_BYTES` = 1 GiB |
| Document | `MAX_DOCUMENT_BYTES` = 64 MiB |

- `Source::Inline` uses the standard alphabet, requires a multiple-of-four
  length and correct padding, rejects whitespace, and must decode to exactly
  `bytes`. `decode_base64` is the same strict decoder used by the tests.
- `Source::Path` must be absolute, contain no `..` component, exist, and
  canonicalise inside an allowed root. Roots are canonicalised when the store
  is created, which also matches Windows 8.3 short names; symlinks are resolved
  before the root check, so a symlink cannot escape a root.
- `Source::Url` must be `http` or `https`, have a non-empty host, and carry no
  userinfo (`user:pass@`). Nothing is fetched. `bytes == 0` on a URL means the
  size is unknown, not empty.
- `name` is optional, at most `MAX_NAME_CHARS` (256) characters, and has no
  control characters. Spaces are allowed for direct attachments, but the `@`
  grammar cannot express them. Bare `@name` references are resolved
  case-sensitively and require a unique match.

## `@` grammar

```
reference := "@" ( "file:" path | "image:" path | "url:" url | name )
name      := 1*[A-Za-z0-9._-]
```

- A reference only starts at the beginning of the text or after whitespace (or
  `(`, `[`, `{`, `<`, `"`, `'`), so `a@b.com` stays literal text.
- A token ends at whitespace, a control character, or one of `, ; ) ] } > " '`.
- Trailing `.` is dropped from a bare name, so `see @notes.` resolves `notes`.
- `@file:` and `@image:` accept an absolute path or a path relative to an
  allowed root. A relative path that exists under more than one root is an
  ambiguity error; a missing file is `NotFound`.
- `@url:` is validated at parse time; only `http` and `https` are accepted.
- An unresolvable reference is `ErrorCode::NotFound` and the message lists up
  to eight candidates (available names, or nearby files for a missing path).
  An ambiguous bare name is `ErrorCode::InvalidInput` and lists the candidate
  attachment ids.
- The grammar has no quoting. A path containing whitespace cannot be written
  as a reference; use a direct attachment route (paste, drag and drop,
  clipboard, or the share sheet) instead. A file whose name has a space can
  still be attached that way.
- `@url:` never fetches text. A URL whose extension infers `Text` is rejected
  at build time with `ErrorCode::Unsupported`; attach the bytes inline or as a
  path instead.

## Typed blocks

```rust
ContentBlock::Text      { text }
ContentBlock::Image     { attachment_id, alt }
ContentBlock::Audio     { attachment_id, duration_ms }
ContentBlock::Video     { attachment_id, duration_ms }
ContentBlock::Document  { attachment_id, page_hint }
ContentBlock::ToolResult{ tool_use_id, summary }
```

Validation rules:

- A message needs at least one block; a text block cannot be empty.
- Text is bounded by `MAX_TEXT_CHARS` (32,768 characters) and cannot contain
  NUL. A tool-result summary is bounded by `MAX_SUMMARY_CHARS` (4,096) and
  cannot be empty or contain NUL.
- Every `attachment_id` must exist in the turn's known attachments or metadata
  set, otherwise `ErrorCode::NotFound` with a candidate list.
- Ids and tool-use ids have no control characters or whitespace and are at
  most `MAX_ID_CHARS`; alt text is at most `MAX_ALT_CHARS` (1,024) with no
  control characters.
- `duration_ms` and `page_hint`, when present, must be positive.
- `Option` fields mean unknown, not zero: an image with no dimensions, an audio
  or video clip with no duration, and a document with no page count stay
  unknown until metadata supplies them.

`build_input` deduplicates by content (modality, MIME type, byte length, and
source), not by id alone. A duplicate still appears in the returned
`RefMapping` with `added = false`; the first occurrence has `added = true`.
Mapping is available from `build_input_with_mapping`, while `build_input`
returns just the `InputMessage`.

## Accounting

`account(&message, &attachment_meta)` returns `ModalityUsage`:

| Field | Source |
|---|---|
| `text_chars` | characters in text blocks and tool-result summaries |
| `image_count` | image block occurrences |
| `image_pixels` | `width * height` when both are known and positive |
| `audio_ms`, `video_ms` | block duration, else metadata duration |
| `document_pages` | metadata page count (`page_hint` is a hint, not a count) |
| `bytes_by_modality` | text bytes from the text itself; other bytes from metadata |
| `unknown` | sorted, deduplicated `(attachment_id, dimension)` pairs |

Only known values are summed. A missing width, height, duration, page count, or
byte size goes to `unknown` with `Dimension::Pixels`, `DurationMs`, `Pages`, or
`Bytes`; it is never guessed from a heuristic. `bytes_by_modality` is a
`BTreeMap`, so iteration and serialized output are deterministic.

Counts follow block occurrences: if two blocks carry the same attachment, the
model receives it twice and both are counted. `build_input` already dedupes
identical attachments, so this only happens when a caller assembles blocks by
hand.

## Fixture table

Every MM-01 input route has a fixture in `crates/zero-mm/tests/input_routes.rs`.
All fixtures are local; none uses the network.

| Route | Fixture | Assertion |
|---|---|---|
| Inline text | `inline text` | one `Text` block |
| Inline image | `inline image` | one `Image` block from base64 |
| Path file | `path file` | `.txt` path attachment becomes `Text` |
| Path image | `path image` | `.png` path attachment becomes `Image` |
| URL | `url` | `Source::Url` document block, unknown size |
| Audio | `audio` | `.wav` path attachment becomes `Audio` |
| Video | `video` | `.mp4` path attachment becomes `Video` |
| Document | `document` | `.pdf` path attachment becomes `Document` |
| `@file` | `@file` | relative file resolves and becomes `Text` |
| `@image` | `@image` | relative image resolves and becomes `Image` |
| `@url` | `@url` | URL extension infers `Image` |
| Bare `@name` | `bare @name` | store name resolves to the image |
| Duplicate refs | `duplicate refs` | one block, two mappings |

The same file also covers: reference order, pre-attached dedupe, email-looking
text, path escape, `..` rejection, URL userinfo, non-http scheme, oversize,
wrong MIME, malformed/mismatched base64, unknown and ambiguous references,
unknown attachment ids, empty input, empty text, control characters, text and
summary bounds, per-modality totals, unknown dimensions, deterministic JSON
round-trip, grammar parsing, and forced-kind mismatch.

## Preprocessing (T-MM-02)

T-MM-02 (`src/preprocess.rs`) implements MM-02 (keep originals for later
re-read), MM-03 (downscale, crop, tile, OCR, sample frames, transcribe), and
marks derived OCR and transcript text as untrusted ahead of MM-04 redaction. It
deliberately contains no image, audio, or video codec: it plans work, stores
originals, and calls injected seams. Real decoders belong to a later integration
task.

### Originals

```rust
OriginalRef { hash: String, bytes: u64, mime: String }
OriginalStore::open(root) -> Result<OriginalStore>
OriginalStore::put(kind, mime, bytes) -> Result<OriginalRef>
OriginalStore::put_with_cap(mime, bytes, cap) -> Result<OriginalRef>
OriginalStore::read_full(&original) -> Result<Vec<u8>>
```

`OriginalStore` wraps the workspace `zero_store::BlobStore` (so no new crate
dependency) and writes the exact attachment bytes once, under
`<root>/<first 2 hex>/<remaining 62 hex>` of the BLAKE3 digest. `put` is
idempotent for identical content, is capped by `Modality::byte_cap`, and records
the trimmed MIME essence. `read_full` re-reads at full resolution and verifies
both the hash and the declared length: a missing blob is
`zero.fnd.not_found`, and a blob whose bytes no longer match is
`zero.fnd.corrupt`. That re-read is the T-MM-02 Done condition.

Originals are never rewritten, downscaled, or replaced by a derived value.
Every derived item is a separate value held in `Preprocessed::derived`.

### Image plan

```rust
ImagePlan { max_edge: u32, tile_edge: u32, overlap: u32, ocr: bool }
plan_image(width, height, plan) -> Result<ImageWork>
ImageWork { downscaled: (u32, u32), tiles: Vec<Tile>, ocr_regions: Vec<Tile> }
Tile { x: u32, y: u32, w: u32, h: u32 }
```

Defaults: `max_edge = 1568`, `tile_edge = 512`, `overlap = 64`, `ocr = true`.
`max_edge` is capped at `MAX_IMAGE_EDGE` (8,192). The downscaled size preserves
the aspect ratio using integer rounding, never upscales, and never has a zero
dimension. Tiles are row-major, lie inside the downscaled image, and cover it
completely. Adjacent tiles overlap by at least `overlap`; the last tile in an
axis is shifted so it ends exactly on the edge, which can make that one overlap
larger. A plan that would need more than `MAX_TILES` (64) tiles fails with
`zero.fnd.limit_exceeded`. `ocr_regions` equals `tiles` when `ocr` is set and is
empty otherwise. The same input always produces the same plan.

### Audio plan

```rust
AudioPlan { target_rate_hz: u32, chunk_ms: u32 }
plan_audio(duration_ms, rate_hz, plan) -> Result<AudioWork>
AudioWork { resampled_rate: u32, chunks: Vec<AudioChunk> }
AudioChunk { index: u32, start_ms: u64, end_ms: u64 }
```

Defaults: `target_rate_hz = 16000`, `chunk_ms = 30000`. `resampled_rate` is
`min(source rate, target rate)`, so the plan never upsamples. Chunks are
contiguous and in order; the final chunk ends exactly at the duration. A
zero-length clip validly produces zero chunks. Source and target rates are
capped at `MAX_SAMPLE_RATE_HZ` (384,000), and a plan over `MAX_AUDIO_CHUNKS`
(4,096) chunks is rejected.

### Video plan

```rust
VideoPlan { fps_sample: u32, max_frames: u32 }
plan_video(duration_ms, fps, plan) -> Result<VideoWork>
VideoWork { frame_times: Vec<u64>, sampled: u32 }
```

Defaults: `fps_sample = 1`, `max_frames = 24`. The effective sampling rate is
`min(fps_sample, source fps)`, so the plan never asks for frames the source does
not have. Frame timestamps are milliseconds and strictly increasing. When the
requested count fits, timestamps are `i * 1000 / effective_fps`. When it does
not, the plan keeps `max_frames` timestamps spread evenly across the whole clip
(`i * duration / max_frames`) instead of dropping the tail. Source frame rate is
capped at `MAX_SOURCE_FPS` (240) and `max_frames` at `MAX_VIDEO_FRAMES` (64).
`sampled` always equals `frame_times.len()`.

### Processor seams and `preprocess`

```rust
trait ImageProcessor {
    fn downscale(&self, original: &[u8], target: (u32, u32)) -> Result<Vec<u8>>;
    fn crop(&self, image: &[u8], tile: Tile) -> Result<Vec<u8>>;
}
trait OcrEngine       { fn ocr(&self, image: &[u8]) -> Result<String>; }
trait Transcriber     { fn transcribe(&self, audio: &[u8]) -> Result<String>; }
trait FrameSampler    { fn sample(&self, video: &[u8], times_ms: &[u64]) -> Result<Vec<Vec<u8>>>; }

preprocess(&store, &attachment, &plan, &processors) -> Result<Preprocessed>
```

The same call is available as `store.preprocess(&attachment, &plan,
&processors)`.

`Processors` holds an optional reference to each seam. A missing seam means the
corresponding derived item is not produced; it never triggers an implicit codec,
download, or network call.

`PreprocessPlan` carries the three modality plans plus `SourceGeometry`, which
the caller must supply because this module does not parse container headers:

| Attachment | Required geometry | Work |
|---|---|---|
| Image | `Image { width, height }` | `plan_image`, then downscale, crop, and optionally OCR |
| Audio | `Audio { duration_ms, rate_hz }` | `plan_audio`, then transcribe the whole original |
| Video | `Video { duration_ms, fps }` | `plan_video`, then sample frames |
| Text, Document | none | original stored, `AppliedWork::Skipped` |

Image output order is one `downscaled` item, then for each tile a `tile` item
and, when OCR is enabled and an engine is present, one `ocr_text` item. Tiles
are cropped from the downscaled copy in downscaled coordinates; full detail is
always available again through `OriginalStore::read_full`. If an OCR engine is
present without an image seam, OCR runs once over the original bytes. Audio
produces one `transcript` item from the whole original; the chunk boundaries
are plan metadata, not byte slices of a compressed container. Video produces
one `frame` item per timestamp. A sampler that returns a different frame count
than the plan is `zero.fnd.invalid_input`.

`Preprocessed` is:

```rust
Preprocessed {
    original: OriginalRef,
    work: AppliedWork,          // Skipped, Image(ImageWork), Audio(AudioWork), or Video(VideoWork)
    derived: Vec<Derived>,
    accounting: PreprocessAccounting,
}
Derived { kind, bytes_or_text: DerivedPayload, meta: DerivedMeta }
```

`DerivedMeta` records `index`, optional `width`/`height`, the source `tile`, the
frame `frame_ms`, the exact payload `bytes` and `chars`, and `untrusted_text`.
`PreprocessAccounting` records `original_bytes`, `derived_items`,
`derived_bytes`, `text_chars`, `tiles`, `ocr_chars`, `transcript_chars`, and
`frames`. Every number comes from a plan that was resolved or work that ran.

### Bounds and untrusted text

| Value | Cap |
|---|---|
| image longest edge / tiles | `MAX_IMAGE_EDGE` = 8,192 / `MAX_TILES` = 64 |
| audio sample rate / chunks | `MAX_SAMPLE_RATE_HZ` = 384,000 / `MAX_AUDIO_CHUNKS` = 4,096 |
| video source fps / frames | `MAX_SOURCE_FPS` = 240 / `MAX_VIDEO_FRAMES` = 64 |
| one derived item | `MAX_DERIVED_ITEM_BYTES` = 64 MiB |
| all derived items in one run | `MAX_DERIVED_TOTAL_BYTES` = 256 MiB |
| one OCR region / one transcript | `MAX_OCR_CHARS` = 65,536 / `MAX_TRANSCRIPT_CHARS` = 524,288 |

The attachment byte cap is checked before any derived work, and the per-item
and per-run caps below bound what a seam may return. A URL attachment is
rejected with `zero.fnd.unsupported` rather than fetched, and the production
half of `src/preprocess.rs` contains no network or process API (enforced by a
structural test).

OCR text and transcripts are untrusted data: `preprocess` sets
`untrusted_text = true` for both, and `Derived::is_untrusted_text` exposes it.
Callers must delimit such text, treat it as evidence rather than instructions,
and never let it alter tool policy. Redaction of secrets and PII inside derived
text is MM-04 work and is not implemented here; until then, derived text must
not egress raw.

### Test evidence

`cargo test -p zero-mm -j 1` runs 73 tests: 46 in the library
(3 input, 10 consent, 12 preprocessing, 8 recordings, 13 computer use) and 27
input-route integration tests.
`cargo clippy -p zero-mm --all-targets -j 1 -- -D warnings` is clean.

| Behaviour | Test |
|---|---|
| original store round-trip, dedupe, missing blob, corruption detection, full re-read | `preprocess::tests::original_store_round_trips_and_re_reads_at_full_resolution` |
| image plan is deterministic, bounded, never upscales, and rejects invalid plans | `preprocess::tests::image_plan_is_deterministic_and_bounded` |
| tiles cover the image, stay in bounds, and keep the configured overlap | `preprocess::tests::image_tiles_cover_the_image_and_keep_the_overlap` |
| audio chunk count/rate, contiguous boundaries, zero-length clip, caps | `preprocess::tests::audio_chunk_count_and_rate_are_bounded` |
| video sampling bounded, ordered, clamped to source fps, caps | `preprocess::tests::video_sampling_is_bounded_and_ordered` |
| every image seam runs; OCR text is untrusted; original re-read is unchanged | `preprocess::tests::image_preprocessing_runs_every_seam_and_keeps_the_original` |
| audio/video plans are recorded and their derived metadata is correct | `preprocess::tests::audio_and_video_preprocessing_record_their_plans` |
| text and document attachments are stored with no derived work | `preprocess::tests::text_and_documents_are_stored_without_derived_work` |
| missing/wrong geometry and a frame-count mismatch are rejected; text is skipped | `preprocess::tests::geometry_and_processor_failures_are_rejected` |
| path, URL, store-size, and OCR-size caps are enforced | `preprocess::tests::path_url_and_size_caps_are_enforced` |
| plans, work, and results round-trip through serde deterministically | `preprocess::tests::plans_and_work_round_trip_through_serde` |
| no network or process API appears in the module source | `preprocess::tests::no_network_code_path_exists` |

No test uses a real image, audio, or video codec: the seams are scripted, and
the only filesystem I/O is the temp fixtures and the original store.

### Preprocessing limitations

- There are no codecs in this slice. `ImageProcessor`, `OcrEngine`,
  `Transcriber`, and `FrameSampler` are traits; a producer must supply real
  implementations and their own dependency and resource controls.
- Source geometry is caller-supplied. This module does not read PNG, JPEG, WAV,
  MP4, or any other header, so an incorrect width, duration, or fps is not
  detected here.
- Tile crop coordinates are in the downscaled image, not the original. The full
  original is always available via `read_full`, but a crop at original
  resolution needs a later seam.
- Audio is transcribed as one whole original. Compressed containers are not
  split at chunk boundaries; the chunk plan is metadata for a later decoder.
- Text and documents are stored but not chunked or extracted. Text chunking is
  still a later task.
- Derived values are in-memory only. Persisting them, their hashes, and their
  metadata belongs to the artifact/store layer.
- Redaction is not implemented, so OCR and transcript text must be treated as
  untrusted and must not be sent to a provider raw (MM-04).

## Local CPU models (T-MM-06)

T-MM-06 adds the consent gate for CPU-capable local models (MM-06, MM-13,
MM-14). The module validates a request, renders a deterministic prompt, turns
the user's decision into a capability, and records that capability per
modality. It does not download, install, or fetch anything: a grant produces a
capability token and a `DownloadPlan`, and a later task owns the
checksum-verified download.

### Request

```rust
LocalModelRequest {
    id: String,
    name: String,
    modality: LocalModality,
    licence: String,      // SPDX id or "name, https://..."
    disk_bytes: u64,
    memory_bytes: u64,
    purpose: String,
    source: String,
}
```

`LocalModality` is separate from the input `Modality` on purpose. Local CPU
models serve four modality roles, and `text-embedding` is not an attachment
kind:

| `LocalModality` | Canonical name | Examples |
|---|---|---|
| `Image` | `image` | vision model, OCR model |
| `Audio` | `audio` | speech-to-text |
| `Video` | `video` | frame captioning |
| `TextEmbedding` | `text-embedding` | local embedding model |

A modality outside this set has no local CPU path. `LocalModality::from_name`
accepts only the canonical lowercase names; serde accepts only the same strings,
so an unknown modality is rejected at the boundary instead of silently becoming
something else. `LocalModality::from_input` maps `Image`, `Audio`, and `Video`
attachments to the matching local modality and returns `None` for `Text` and
`Document`, so the router cannot invent a local path that has no model.

Validation (`LocalModelRequest::validate`, also called by `ConsentPrompt::new`
and `authorize`):

| Field | Rule |
|---|---|
| `id` | non-empty, at most `MAX_MODEL_ID_CHARS` (128), no whitespace or control characters |
| `name` | non-empty, at most `MAX_MODEL_NAME_CHARS` (128), no control characters |
| `modality` | one of the four `LocalModality` values |
| `licence` | non-empty, at most `MAX_LICENCE_CHARS` (256), no control characters; see below |
| `disk_bytes` | greater than zero and at most `MAX_LOCAL_MODEL_DISK_BYTES` (32 GiB) |
| `memory_bytes` | greater than zero and at most `MAX_LOCAL_MODEL_MEMORY_BYTES` (16 GiB) |
| `purpose` | non-empty, at most `MAX_PURPOSE_CHARS` (512), no control characters |
| `source` | non-empty, at most `MAX_SOURCE_CHARS` (512), no control characters |

An empty or oversize field is `zero.fnd.invalid_input` or
`zero.fnd.limit_exceeded`; no prompt is rendered and no authorization is
produced.

### Licence forms

- **SPDX identifier.** One token of ASCII letters, digits, `.`, `+`, or `-`:
  `MIT`, `Apache-2.0`, `BSD-3-Clause`, `CC0-1.0`. The string is checked for
  form, not looked up in the SPDX list, because that list changes independently
  of this crate.
- **Name plus URL.** A non-empty name followed by an `http` or `https` URL,
  separated by a comma, whitespace, or parentheses:
  `Llama 3.2 Community License, https://example.com/licence` or
  `Llama 3.2 Community License (https://example.com/licence)`. The URL must
  have a host and no userinfo. The prompt shows it as
  `licence: <name> (<url>)`.
- Anything else (a bare phrase with spaces, or a URL with no name) is rejected.

### Prompt

`ConsentPrompt::new(request)` validates first, then builds fixed lines.
`render()` joins them with `\n` and adds no trailing newline. Re-rendering the
same request is byte-identical. A full render:

```text
Local model consent request
model: Llama 3.2 Vision
id: llama-3.2-vision-11b
modality: image
licence: Llama 3.2 Community License (https://example.com/licence)
disk required: 6.0 GiB (6442450944 bytes)
memory required: 8.0 GiB (8589934592 bytes)
purpose: Read screenshots and describe UI elements.
source: https://example.com/models/llama-3.2-vision
consent: accepting records consent and makes this model available for the image modality only.
decline: declining leaves the image modality unavailable and no download occurs.
download: a later task performs any download and must verify a checksum first.
```

The size line carries the human-readable value and the exact byte count, so a
caller never has to re-derive the requirement. The purpose line is the request
string verbatim, not a summary.

### Consent and availability

`ConsentDecision` is either `Granted { at_ms }` or `Declined { reason }`.
`authorize(&request, &decision, now_ms)` validates both and returns an
`Authorization`:

| Decision | Result |
|---|---|
| `Granted { at_ms }` | `Authorization::Granted { capability, plan }`; the capability is `Available { model_id }` for the request's modality only. `at_ms` must not be later than `now_ms`. |
| `Declined { reason }` | `Authorization::Declined { capability }`; the capability is `Unavailable { explanation }`. |

The decline explanation names the model and its id, says that no download
occurred, and appends the optional reason. This is the T-MM-06 done condition:
after a decline the modality is still unavailable and the user can read why.

```text
local model `Llama 3.2 Vision` (llama-3.2-vision-11b) was declined; the image modality stays unavailable and no download occurred
```

A blank decline reason is rejected so the explanation cannot end in a dangling
separator. A grant applies to one model id and one modality; it does not enable
any other model or modality. Re-consenting replaces the previous state,
including revoking a previously granted model with a decline.

`Available` means consent is on record. It does not mean the weights are on
disk. The download task still has to run and verify a checksum before the model
can be loaded.

`DownloadPlan` is data only: `model_id`, `modality`, `source`, `disk_bytes`,
`memory_bytes`, and `authorized_at_ms`. There is no URL fetch, file creation, or
process launch in this module. The later download task must verify a published
checksum before the model is loaded.

### Capability registry

`CapabilityRegistry` stores one state per `LocalModality` and starts empty.
A missing entry is unavailable with `no local <modality> model has been
consented to`.

| Call | Behaviour |
|---|---|
| `capability(modality)` | the stored capability, or the default unavailable one |
| `is_available(modality)` | `true` only for `Available` |
| `require(modality)` | `Ok(model_id)`, or `zero.fnd.unavailable` with the stored explanation |
| `apply(&authorization)` | replaces only that modality's state |
| `authorize(&request, &decision, now_ms)` | the free `authorize` plus `apply` |

`require` is the gate. A declined or never-consented modality cannot be used:
the error code is `zero.fnd.unavailable` and its message carries the
explanation, so a router can show it rather than silently ignoring the input.
For MM-14, a non-vision model that receives an image asks
`require(LocalModality::Image)` and falls back to an OCR path only when that
gate fails; no path skips the gate.

The registry derives serde. A round trip is equal to the original and
re-serializes to the same JSON (the internal map is a `BTreeMap`), so a caller
can persist the consent state without this module owning a store.

### Test evidence

`cargo test -p zero-mm -j 1` runs 73 tests; 10 are the T-MM-06 consent tests,
12 are the T-MM-02 preprocessing tests, 8 are the T-MM-05 recording tests, 13
are the T-MM-04 computer use tests, 3 are input unit tests, and 27 are the
input-route integration fixtures.
`cargo clippy -p zero-mm --all-targets -j 1 -- -D warnings` is clean.

| Behaviour | Test |
|---|---|
| prompt shows name, id, modality, licence (with URL), disk, memory, exact purpose, source | `consent::tests::prompt_shows_every_required_field` |
| prompt text is byte-deterministic (full golden render) | `consent::tests::prompt_text_is_deterministic` |
| decline keeps the modality unavailable, names the model, and says no download occurred (Done) | `consent::tests::declining_leaves_the_modality_unavailable_with_an_explanation` |
| a grant enables exactly one model for one modality; other modalities stay unchanged | `consent::tests::granting_enables_only_that_model_and_modality` |
| re-consent replaces the state and a decline revokes | `consent::tests::re_consent_replaces_the_registry_state` |
| missing and oversize name, licence, disk, memory, purpose, source, id are rejected | `consent::tests::invalid_requests_are_rejected` |
| unknown modality is rejected by parse and serde | `consent::tests::unknown_modalities_are_rejected` |
| no network, download, or install API appears in the module source | `consent::tests::no_network_or_install_code_path_exists` |
| registry serde round-trip and deterministic JSON | `consent::tests::the_registry_round_trips_through_serde` |
| a consent timestamp later than `now_ms` is rejected | `consent::tests::a_consent_from_the_future_is_rejected` |

The no-download test is structural: it reads `src/consent.rs`, cuts at the test
module, and fails if the production half contains a network or install symbol
(`std::net`, `std::fs`, `reqwest`, `TcpStream`, `File::create`, `Command::new`,
and similar). A future edit that adds a hidden fetch fails the suite.

### Local model limitations

- One consented model per modality. There is no multi-model fallback chain and
  no per-request model choice yet.
- The licence is syntax-checked, not authenticated or compared against the live
  SPDX list. A bare token that looks like an SPDX id is accepted. Compound SPDX
  expressions such as `MIT OR Apache-2.0` are not parsed separately; use a
  single identifier, or put the expression in the `name, URL` form.
- No download, install, checksum verification, or disk-space probe happens
  here. `DownloadPlan` records what a later task needs; the later task must
  verify a checksum.
- Requests are CPU-only by type; there is no GPU or accelerator field.
  Hardware capability detection and model-to-machine compatibility checks are
  later work.
- Consent is an in-memory value. The registry is serde-serializable, but
  persistence and audit of the decision belong to the caller.
- The prompt is English text only; there is no localization or rich terminal
  rendering in this slice.
- `TextEmbedding` is a local modality but not an input attachment kind, so
  embeddings do not appear in `ModalityUsage`.

## Verification and recordings (T-MM-05)

T-MM-05 (`src/recordings.rs`) implements MM-05 (sandbox and live-host targets
both produce the same evidence), MM-08 (labeled screenshots, chaptered
recordings, pass/fail assertions, flagged shortcuts), and the per-project
artifact directory of MM-09. It is a recording and verification layer, not a
capture layer: a caller supplies opaque PNG bytes and dimensions, and this
module never captures, decodes, re-encodes, or uploads an image.

### Model

```rust
LabeledShot { id, label, bytes_png: Vec<u8>, at_ms, width, height }
Chapter     { title, start_ms, shots: Vec<LabeledShot>, notes: Vec<String> }
Assertion   { id, description, expected: serde_json::Value, actual, passed }
ShortcutFlag{ key, description, enabled }
Recording   { schema_version, id, flow_name, created_ms, chapters,
              assertions, shortcut_flags }
```

`LabeledShot::content_hash()` is the lowercase hex BLAKE3 digest of
`bytes_png`, using the workspace `zero_store::BlobId`. The manifest records the
digest so a later verifier can compare the stored shot with the recording.
Chapters are ordered by `start_ms`, shots within a chapter by `at_ms`, and ids
are unique across the recording. `Recording::validate` is structural: it
rejects an unknown schema version, an empty chapter list, duplicate shot or
assertion ids, duplicate shortcut keys, out-of-order chapter or shot times, and
every bound below. A chapter with no shots is structurally valid; `verify`
reports it instead.

| Value | Rule / cap |
|---|---|
| flow name | non-empty, `MAX_FLOW_NAME_CHARS` = 256, no control characters |
| recording id | token (`A-Z a-z 0-9 . _ -`), `MAX_RECORDING_ID_CHARS` = 128 |
| chapter title / note | `MAX_TITLE_CHARS` = 256 / `MAX_NOTE_CHARS` = 4,096, no control characters |
| shot label / id | `MAX_LABEL_CHARS` = 256 / `MAX_SHOT_ID_CHARS` = 128 |
| shot png | non-empty, `MAX_SHOT_BYTES` = 32 MiB; `MAX_TOTAL_SHOT_BYTES` = 512 MiB per recording |
| shot dimensions | positive, each edge at most `MAX_SHOT_EDGE` = 16,384 |
| chapters / shots | `MAX_CHAPTERS` = 128 / `MAX_SHOTS` = 1,024; `MAX_SHOTS_PER_CHAPTER` = 256 |
| notes per chapter | `MAX_NOTES_PER_CHAPTER` = 256 |
| assertions | `MAX_ASSERTIONS` = 4,096; description at most 4,096 characters |
| shortcut flags | `MAX_SHORTCUT_FLAGS` = 128; key at most 64, description at most 1,024 |
| rendered report or `FAILURES.md` | `MAX_REPORT_BYTES` = 64 MiB |

`ArtifactLimits` carries the chapter, shot, byte, assertion, flag, and report
caps. `ArtifactLimits::default()` is the table above, and
`Recording::validate_with(&limits)` and `write_artifacts` accept a stricter
set for one caller without changing the global model.

### Flow builder

```rust
FlowEvent::At(ms)
FlowEvent::Chapter(title)
FlowEvent::Shot { label, bytes, w, h }
FlowEvent::Assert { description, expected, actual }
FlowEvent::Shortcut { key, description, enabled }
FlowEvent::Note(text)
build(flow_name, &events) -> Result<Recording>
```

`build` assigns ids `shot-0001`, `assert-0001`, and so on in event order. A shot
or note before the first `Chapter` opens an implicit `Intro` chapter, so a
partial flow still produces a structurally valid recording. `created_ms` is the
greatest `At` value; the builder never reads a clock, and the same events always
produce the same recording and the same `rec-<16 hex>` id. `At` may not go
backwards.

`passed` is `expected == actual` for every assertion. A false assertion is
recorded, not raised: one failure never aborts the recording, and the remaining
shots and assertions are still added. Structural errors (empty flow name,
backwards time, an empty event list, or a bound) are `zero.fnd.invalid_input` or
`zero.fnd.limit_exceeded`.

### Verification

```rust
verify(&recording) -> Verification {
    passed, failed_assertions: Vec<String>, missing_shots: Vec<String>
}
```

Every assertion is re-evaluated from `expected == actual`, so a tampered
`passed` flag still fails. `missing_shots` lists a `chapter-NNNN` for each
chapter with no shots and a shot id for each shot with an empty label or empty
payload. `passed` requires all three: every assertion true, every chapter
non-empty, and every shot labeled and populated. A recording with no chapters
always fails. `Verification::exit_summary()` is one deterministic line such as
`FAIL (failing assertions: assert-0002, assert-0004)`.

### Artifacts and report

```rust
write_artifacts(&recording, out_dir, limits) -> Result<ArtifactBundle>
ArtifactBundle { dir, manifest: Manifest, report_md: PathBuf }
read_manifest(out_dir) -> Result<Manifest>
```

A successful publish creates a new directory:

```text
<out_dir>/
  manifest.json
  report.md
  shots/
    ch01-shot001-home-screen-0123456789ab.png
    ch02-shot001-saved-dialog-fedcba987654.png
  FAILURES.md          # failing flows only
```

- `manifest.json` is the deterministic, serde-serialized `Manifest`: the
  recording without embedded PNGs, the portable shot path, its byte length and
  BLAKE3 content hash, the assertions and shortcut flags, totals, and the
  verification snapshot. `Manifest::validate` checks the schema, unique ids,
  portable paths, hashes, and listed totals; `read_manifest`
  (`zero.fnd.not_found` when absent, `zero.fnd.schema_version` for an unknown
  version) is the later-verification entry point.
- `report.md` contains the metadata header, one section per chapter with its
  notes, a labeled-shot table (label, id, time, dimensions, bytes, hash, file),
  an assertions table with `pass`/`fail`, a shortcut-flag table, and a failure
  section with the exit summary.
- Shot files are path-safe by construction: the name is the chapter and shot
  ordinal, a lowercase ASCII slug of the label, and the first 12 hex characters
  of the content hash, under `shots/`. Labels containing `..`, separators,
  drive letters, reserved device names, or non-ASCII text cannot escape the
  directory. Names are unique even for duplicate labels.
- A failing flow still writes every shot, the manifest, and the report, and
  adds `FAILURES.md` with the failed-assertion table, missing-shot list, and
  `Exit summary` naming the failing assertion ids. The report also carries that
  summary, including when it says `PASS`.
- The bundle is assembled in a hidden sibling staging directory and renamed
  into `out_dir`, so a partial bundle is never visible under the final name. An
  existing `out_dir` is `zero.fnd.already_exists` and is not modified. Only
  local filesystem I/O is used; there is no network call, process launch, or
  screenshot capture.

### Test evidence

`cargo test -p zero-mm -j 1` runs 73 tests: 46 in the library (3 input, 10
consent, 12 preprocessing, 8 recordings, 13 computer use) and 27 input-route
integration tests.
`cargo clippy -p zero-mm --all-targets -j 1 -- -D warnings` is clean.

| Behaviour | Test |
|---|---|
| a passing flow (2 chapters, shots, assertions, note, shortcut) writes every artifact, report says PASS, manifest round-trips (Done) | `recordings::tests::passing_flow_writes_every_artifact_and_reports_pass` |
| a failing flow still writes every artifact plus `FAILURES.md` with the failing assertion ids (Done) | `recordings::tests::failing_flow_writes_every_artifact_and_names_the_failures` |
| shot/assertion ids are unique; chapters and shots are monotonic; duplicate ids and backwards times are rejected | `recordings::tests::ids_and_chapter_times_are_unique_and_monotonic` |
| an empty recording, empty label, control character, and backwards event time are rejected; an empty chapter fails verification | `recordings::tests::empty_and_unstructured_recordings_are_rejected` |
| per-shot, total-byte, per-chapter, and global shot caps fail without publishing a directory | `recordings::tests::shot_size_and_count_caps_are_enforced` |
| traversal, separators, device names, and Unicode labels produce portable unique file names | `recordings::tests::shot_file_names_are_path_safe` |
| manifest output is deterministic, round-trips, and an existing output directory is left alone | `recordings::tests::manifest_round_trips_and_is_deterministic` |
| no network or process API appears in the module source | `recordings::tests::no_network_code_path_exists` |

No test uses a real screenshot or PNG decoder: payloads are small scripted byte
strings, and all artifact I/O is under a temp directory.

### Recording limitations

- There is no capture, encoder, or decoder here. The caller supplies PNG bytes
  and width/height; a wrong dimension is not detected from the payload.
- `read_manifest` validates the manifest and its portable paths but does not
  re-hash or re-read the shot files. A later verifier that holds the
  `Recording` can compare `LabeledShot::content_hash`.
- Publish is an atomic rename, not an fsync'd commit. A crash can leave a
  hidden `.<name>.<pid>.<n>.partial` staging directory next to `out_dir`.
  There is no replace-in-place mode: the output path must be new.
- A recording is one flat set of chapters and global assertions. There are no
  nested chapters, per-shot assertion references, or video/motion formats.
- Artifact browsing on desktop and Android (the exposure half of MM-09) is a
  later surface. This module only writes a self-contained local directory.
- Reports are English Markdown with no rich rendering, localization, or
  attachment embedding.

## Sandboxed computer use (T-MM-03)

T-MM-03 (`src/sandboxed.rs`) implements the sandboxed target of MM-05 and the
safety rules of MM-10: a VM or virtual display with no host filesystem, an
exact network allowlist, and no host device access. It also answers the Done
condition for MM-03, MM-06, and MM-10: an escape attempt is blocked, recorded,
and never forwarded to the backend. The module is a boundary and a contract; a
real VM driver or virtual display is supplied through the injected
`SandboxRunner` seam.

### Backends and spec

`SandboxBackend` is `virtual-display` or `vm`. `SandboxSpec` is the complete
contract:

| Field | Rule |
|---|---|
| `backend` | a virtual display or a VM |
| `display` | optional `(width, height)`; each edge is 1..=8192 px. A virtual display requires an explicit size; a VM may be headless |
| `network_allowlist` | at most 64 entries of the form `host:port` or `[ipv6]:port` |
| `scratch_root` | the guest's only writable location: absolute, existing, a directory, and not a filesystem root |
| `host_mounts` | must be empty; a computer-use sandbox has no host filesystem |
| `device_access` | must be `false`; a computer-use sandbox has no host hardware |
| `max_runtime_ms` | 1 second to 30 minutes inclusive |

`validate()` returns `zero.pol.denied` for a host mount, host device access, or
a scratch root at a filesystem root; `zero.fnd.invalid_input` for a malformed
value; `zero.fnd.limit_exceeded` for a bound; and `zero.fnd.not_found` for a
missing scratch root. `validate_scratch_under(root)` canonicalises both paths
and requires the scratch root to live inside the caller's root, so a symbolic
link cannot point outside it. A rejected spec never reaches the runner.

### Allowlist rule

Each entry names one endpoint, `api.example.com:443`. The host comparison is
ASCII case-insensitive because DNS names are; the port must match exactly and
cannot be zero. A different host, a different port, a suffix such as
`api.example.com.evil.test`, a URL with a scheme, whitespace, and port zero are
all refused.

Wildcards are refused at validation with `zero.pol.denied`: `*:443`,
`*.example.com:443`, `api.*:443`, and `api.example.com:*` do not load. There is
no API that appends, widens, or bypasses an entry after launch.

### Session lifecycle

`launch(spec, runner)` validates the spec, asks the runner to start the backend,
and returns a session in `running` state only after the runner returns `Ok`. A
runner failure keeps its stable error code, is prefixed with the sandbox
context, and leaves the session `failed`. The session id is a deterministic
content hash of the spec, not a random value or a secret.

`execute(session, action, mode, allowlist, runner)` requires a running session
and an action whose target is `sandbox`; a live host action is refused with
`zero.pol.denied`. It then applies the T-MM-04 matrix:

| Policy result | Behaviour |
|---|---|
| `Allow` | call the runner, record the action, return the record |
| `Ask` | return `zero.pol.ask` and do not call the runner |
| `Deny` | return `zero.pol.denied` and do not call the runner |

So a screenshot and the ordinary sandbox actions run, while a destructive
action still asks: this module does not bypass the approval prompt. A runner
failure is recorded as `ActionOutcome::Failed` with the backend's code and
returned. `stop` accepts only a started, not-yet-stopped session; a backend stop
failure moves the session to `failed`.

### Escape matrix

`check_escape(session, attempt)` is the only boundary check. Every blocked
attempt is appended to `SandboxSession::attempts`, returned as
`zero.pol.denied`, and surfaced by `SandboxSession::escape_report()`. The check
takes no runner, so a blocked attempt cannot reach the backend.

| `EscapeAttempt` | Result | Reason |
|---|---|---|
| `HostPath(path)` | blocked | the sandbox has no host filesystem; any host path read or write is denied |
| `Network { host, port }` exactly allowlisted | allowed and counted | the endpoint matches one exact entry |
| `Network { host, port }` otherwise | blocked | the destination is not an exact allowlisted `host:port` |
| `DeviceAccess` | blocked | the sandbox cannot access host devices |
| `MountRequest` | blocked | the sandbox cannot mount a host path |
| `ClipboardFromHost` | blocked | the sandbox cannot read the host clipboard |

A scratch write is a separate, allowed channel: `check_scratch_write` resolves
the requested path and its parent against the canonical scratch root, so `..`
and a symbolic link cannot escape. A path inside the root is allowed and counted
even before the file exists, provided the parent exists. A path outside the root
is recorded as a blocked `host-path` attempt and returned as `zero.pol.denied`.

The two session logs are deliberately separate: `actions` holds actions that
passed policy and reached the runner, and `attempts` holds blocked escapes.
`EscapeReport { blocked, allowed }` summarises them; `allowed` counts
allowlisted network checks and accepted scratch writes. `render()` produces one
fixed line per blocked attempt plus the allowed count.

### Test evidence

`cargo test -p zero-mm -j 1` runs 90 tests: 63 in the library (3 input, 10
consent, 12 preprocessing, 8 recordings, 13 computer use, 17 sandboxed) and 27
input-route integration tests. `cargo clippy -p zero-mm --all-targets -j 1 --
-D warnings` is clean. No test starts a VM or a virtual display: the runner is
scripted, and scratch directories come from `tempfile`.

| Behaviour | Test |
|---|---|
| host filesystem access is blocked and recorded (Done) | `sandboxed::tests::host_filesystem_access_is_blocked` |
| the network allowlist permits only the exact host and port | `sandboxed::tests::network_allowlist_allows_only_the_exact_host_and_port` |
| host device access is blocked | `sandboxed::tests::device_access_is_blocked` |
| a mount request is blocked | `sandboxed::tests::mount_request_is_blocked` |
| a host clipboard read is blocked | `sandboxed::tests::clipboard_from_host_is_blocked` |
| no escape attempt is forwarded to the runner | `sandboxed::tests::escape_attempts_are_not_forwarded_to_the_runner` |
| scratch writes are allowed and outside writes are blocked | `sandboxed::tests::scratch_writes_are_allowed_and_escapes_are_blocked` |
| launch, execute, stop, and stopped-session refusal | `sandboxed::tests::sandbox_session_lifecycle` |
| a non-empty host mount list is rejected before launch | `sandboxed::tests::host_mounts_make_the_spec_invalid` |
| host device access is rejected before launch | `sandboxed::tests::device_access_makes_the_spec_invalid` |
| wildcard network entries are rejected | `sandboxed::tests::wildcard_network_entries_are_rejected` |
| runtime, display, scratch, and allowlist bounds are enforced | `sandboxed::tests::invalid_specs_are_rejected` |
| the scratch root must live under the owned root | `sandboxed::tests::scratch_root_must_live_under_the_owned_root` |
| backend launch, action, and stop failures keep their codes | `sandboxed::tests::runner_failure_is_typed` |
| actions route through policy and destructive actions ask | `sandboxed::tests::actions_route_through_policy_and_destructive_actions_ask` |
| the session id and escape report are deterministic and round-trip serde | `sandboxed::tests::session_id_and_report_are_deterministic` |
| no process, socket, or hypervisor API appears in the module source | `sandboxed::tests::no_host_code_execution_path_exists` |

### Sandbox limitations

- There is no VM, container, or virtual display driver here. `SandboxRunner`
  is the seam; this slice proves the contract and the boundary, not isolation
  on a particular host.
- The network allowlist is enforced by `check_escape`, not by an interposer.
  Any egress path must call the check; this module opens no socket and cannot
  stop a backend that ignores the rule.
- Host-filesystem denial is likewise a contract: host mounts and device access
  are rejected, host paths are blocked, and scratch writes are contained. The
  runner must implement the actual OS-level jail.
- The scratch check and a later write are separate operations, so a path can be
  swapped between them. The runner should hold an open handle or a mount rather
  than re-resolve the path.
- `max_runtime_ms` is declared and validated but not enforced here; the runner
  owns the clock and must stop the backend at the limit.
- There is no DNS pinning, redirect handling, or per-connection accounting.
  Host matching is a string comparison, not a resolution.
- Capture, element identification, deterministic waits, and retries (the
  action loop of MM-06) belong to the runner and are not part of this slice.

## Live host computer use (T-MM-04)

T-MM-04 (`src/computer_use.rs`) implements the policy half of MM-05 (a sandboxed
target is a different risk class from the live host desktop), MM-07 (pause
before a person takes over), and MM-11 (the modes apply to computer actions).
The module is policy data only: it never captures a screen, moves a pointer,
types, reads or writes a clipboard, launches or closes an application, or calls
an operating-system input API. A caller runs an action only after
`Decision::Allow`, or after a person answers an `AskView`.

### Model

```rust
Target { Sandbox, LiveHost }
ActionKind { Move, Click, DoubleClick, RightClick, Type, Key, Scroll, Drag,
             Screenshot, ClipboardRead, ClipboardWrite, LaunchApp, CloseWindow }
ComputerAction { kind, target, app: Option<String>, text_len: Option<usize>, destructive: bool }
Risk { Low, Medium, High }
PolicyMode { Plan, Manual, SemiAuto, Auto }
Decision { Allow, Ask { reason }, Deny { reason } }
AskView { action, target, app, reason }
```

`app` is the target application, or `None` for the whole desktop. `text_len` is
the number of characters a `Type` action would enter; the text itself is not
part of the value. `destructive` is the caller's declaration that the action can
delete, overwrite, close unsaved work, or otherwise lose state.

### Risk table

| Target | Action kinds | Risk |
|---|---|---|
| live host | `screenshot` | Medium (privacy: it exposes the screen) |
| live host | every other kind (input, clipboard, launch, close) | High |
| sandbox | `move`, `click`, `double-click`, `right-click`, `key`, `scroll`, `drag`, `screenshot`, `clipboard-read` | Low |
| sandbox | `type`, `clipboard-write`, `launch-app`, `close-window` | Medium |
| any | `destructive = true` | High |

A destructive declaration raises the risk to High even for a screenshot. The
risk is a property of the action alone; the mode matrix decides what may run.

### Mode matrix

`authorize(action, mode, allowlist)` applies:

| Target | `Plan` | `Manual` | `SemiAuto` / `Auto` |
|---|---|---|---|
| live host | `Deny` every action | `Ask` for every action, including screenshots | `Ask` unless the exact kind and app are allowlisted |
| sandbox | allow `Screenshot` and `ClipboardRead`; `Deny` every side effect | allow low and medium; `Ask` destructive | allow low and medium; `Ask` destructive |

On the live host two checks run before the allowlist:

- a destructive action always asks, and is never silently allowed;
- a `ClipboardRead` always asks in every mode that does not already deny it
  (`Plan` denies), so no agent path can read the live clipboard through an
  allowlist entry.

The T-MM-04 done condition is the manual row: every live host action, including
screenshots, produces `Ask`. The sandbox row follows the task matrix: the
mandatory-ask class is the live host, while the sandbox allows its low and
medium actions and asks only when the action is declared destructive. Plan mode
still denies every sandbox side effect; only the two read-only kinds pass.

### Allowlist rule

An allowlist is a `&[String]` supplied by the caller. Entries are exact,
case-sensitive, and use one of two forms:

| Form | Matches |
|---|---|
| `<kind>` | the same kind with `app = None` (the whole desktop) |
| `<kind>:<app>` | the same kind with exactly that `app` |

`<kind>` is the canonical `ActionKind` name from `ALL`:
`move`, `click`, `double-click`, `right-click`, `type`, `key`, `scroll`, `drag`,
`screenshot`, `clipboard-read`, `clipboard-write`, `launch-app`, or
`close-window`. Examples: `click:com.example.app`, `screenshot:com.example.app`,
`clipboard-write`.

- A different app, a different case, or a different kind does not match.
- An action with `app = Some(...)` is not matched by the kind-only entry, and an
  action with `app = None` is not matched by the `kind:app` entry.
- An empty or control-character app id cannot produce an entry, so it cannot be
  allowlisted.
- The allowlist only applies to live host actions in `SemiAuto` and `Auto`. It
  cannot override `Plan`, `Manual`, a destructive declaration, or a live host
  clipboard read.
- The agent has no write path to this list in this slice. The caller owns the
  configuration; there is no API that appends, widens, or bypasses an entry.

### Prompts

`ask_prompt(action)` builds an `AskView` and `AskView::render()` joins fixed
lines. There is no field for typed or clipboard content, so a prompt cannot
carry a password or a message body. A typing action reports only its length:

```text
Computer use approval
action: type
target: live-host
app: com.example.app
reason: a type action on the live-host has high risk and requires explicit approval; 42 characters would be typed and their content is withheld
answer: yes or no. Typed text and clipboard contents are never shown.
```

The view carries the kind, target, and app; the reason is built from the kind,
target, risk, the destructive flag, and `text_len`. It never reads a clock or a
random source. The same action always produces the same view and the same
bytes, and the view round-trips through serde without gaining a text field.
`authorize` ask and deny reasons use the same vocabulary, name the app, and also
include the character count for a typing action.

### Test evidence

`cargo test -p zero-mm -j 1` runs 90 tests: 63 in the library (3 input, 10
consent, 12 preprocessing, 8 recordings, 13 computer use, 17 sandboxed) and 27
input-route integration tests. `cargo clippy -p zero-mm --all-targets -j 1 --
-D warnings` is clean.

| Behaviour | Test |
|---|---|
| manual mode asks for every live host action, screenshots included (Done) | `computer_use::tests::manual_mode_asks_for_every_live_host_action` |
| plan mode denies every live host action even when allowlisted | `computer_use::tests::live_host_plan_denies_every_action_and_ignores_the_allowlist` |
| plan mode allows sandbox reads and denies sandbox side effects | `computer_use::tests::sandbox_plan_allows_reads_and_denies_side_effects` |
| an exact non-destructive allowlist entry is allowed in semi-auto and auto | `computer_use::tests::allowlisted_non_destructive_action_is_allowed_in_auto_and_semi_auto` |
| a destructive action still asks in every non-plan mode, allowlisted or not | `computer_use::tests::destructive_action_still_asks_in_auto_even_when_allowlisted` |
| sandbox low and medium actions are allowed; destructive ones ask | `computer_use::tests::sandbox_allows_low_and_medium_actions_and_asks_destructive_ones` |
| a live host clipboard read always asks and is denied in plan | `computer_use::tests::clipboard_read_on_the_live_host_always_asks` |
| live host input, clipboard, launch, and close are High; screenshot is Medium; sandbox is lower | `computer_use::tests::risk_classification_matches_the_target` |
| an unknown, empty, or control-character app is not allowlisted | `computer_use::tests::an_unknown_app_is_not_allowlisted` |
| prompts report only the text length and no typed content, deterministically | `computer_use::tests::ask_prompt_reports_lengths_and_never_typed_text` |
| decisions and prompts are deterministic and round-trip through serde | `computer_use::tests::policy_and_prompts_are_deterministic_and_serializable` |
| allowlist entries use the canonical kind and exact app | `computer_use::tests::allowlist_entry_uses_the_canonical_kind_and_exact_app` |
| no input, clipboard, process, or network API appears in the module source | `computer_use::tests::no_action_executes` |

### Computer use limitations

- There is no executor here. The module returns a verdict and a prompt; a later
  task owns the operating-system input backend, capture, deterministic waits,
  retries, and element identification (the action loop of MM-06 belongs to the
  sandbox task).
- The target is a label, not an enforced boundary. `Target::Sandbox` does not
  create a VM, container, or virtual display; T-MM-03 owns that isolation.
- `destructive` is caller-declared. This slice cannot infer that closing a
  window loses unsaved work or that a click confirms a purchase.
- `text_len` is not checked against the eventual typed text. A caller that
  reports one length and types another is outside this policy layer.
- The allowlist is an exact string list. There are no wildcards, prefixes,
  regular expressions, or per-mode lists in this slice.
- Takeover is represented by `PolicyMode::Manual` asking and by the absence of
  any automatic execution; a real pause/resume handshake with a person is the
  later MM-07 surface.

## Known limitations

- A URL is metadata only in this slice: no fetch, no redirect handling, no
  content-type check, and no byte size. T-MM-02 preprocessing also rejects a
  URL attachment instead of fetching it; T-ZERO web work owns fetching.
- Path attachments must exist when validated because canonicalisation is part
  of the root check. A path that is only planned for later is not accepted.
- MIME inference is extension-based for `@file:` and `@image:`. An unknown
  extension is rejected with advice to insert the attachment explicitly; it is
  never guessed as `application/octet-stream`.
- Image pixels and document pages still need metadata from a decoder. T-MM-02
  consumes caller-supplied `SourceGeometry` and does not populate
  `AttachmentMeta` itself.
- A text attachment larger than `MAX_TEXT_CHARS` cannot become one text block
  yet; T-MM-02 stores the original, but text chunking is still later work.
- Reference paths cannot contain whitespace, and bare names are ASCII-only.
  Both rules keep the grammar unambiguous.
