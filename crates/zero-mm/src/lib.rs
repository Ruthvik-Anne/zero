//! `zero-mm` — see `architecture.md` section 5 for the module contract.
//!
//! [`input`] is the T-MM-01 slice: validated attachments (inline, local path,
//! or `http(s)` URL), `@` references resolved through an injected
//! [`input::AttachmentStore`], typed content blocks, and per-modality
//! accounting that reports unknown dimensions instead of guessing them
//! (MM-01, MM-02). [`preprocess`] is the T-MM-02 slice: a content-addressed
//! original store with full-resolution re-read, deterministic image, audio,
//! and video plans, and injected processor seams for downscale, tile, OCR,
//! transcription, and frame sampling (MM-02, MM-03, MM-04). [`consent`] is the
//! T-MM-06 slice: a validated local CPU model request, a deterministic consent
//! prompt (licence, disk, memory, and purpose), and a per-modality capability
//! gate that never downloads or installs anything (MM-06, MM-13, MM-14).
//! [`recordings`] is the T-MM-05 slice: labeled screenshots, chapters,
//! pass/fail assertions, shortcut flags, and atomic artifact bundles with a
//! manifest and report (MM-05, MM-08, MM-09). [`computer_use`] is the T-MM-04
//! slice: sandbox and live-host targets, the mode matrix, mandatory asks for
//! live host actions, and deterministic approval prompts that never carry typed
//! text (MM-05, MM-07, MM-11). [`sandboxed`] is the T-MM-03 slice: a validated
//! VM or virtual display spec with no host mounts or devices, an exact
//! `host:port` network allowlist, an injected backend runner, and an escape
//! boundary that blocks host paths, non-allowlisted network, devices, mounts,
//! and the host clipboard (MM-03, MM-05, MM-06, MM-10). Redaction is a later
//! task.

pub mod computer_use;
pub mod consent;
pub mod input;
pub mod preprocess;
pub mod recordings;
pub mod sandboxed;

pub use computer_use::{
    ask_prompt, authorize as authorize_computer_use, ActionKind, AskView, ComputerAction, Decision,
    PolicyMode, Risk, Target,
};

pub use consent::{
    authorize, Authorization, CapabilityRegistry, CapabilityState, ConsentDecision, ConsentPrompt,
    DownloadPlan, LocalCapability, LocalModality, LocalModelRequest, MAX_DECLINE_REASON_CHARS,
    MAX_LICENCE_CHARS, MAX_LOCAL_MODEL_DISK_BYTES, MAX_LOCAL_MODEL_MEMORY_BYTES,
    MAX_MODEL_ID_CHARS, MAX_MODEL_NAME_CHARS, MAX_PURPOSE_CHARS, MAX_SOURCE_CHARS,
};
pub use input::{
    account, build_input, build_input_for_role, build_input_with_mapping, decode_base64,
    parse_reference, scan_references, Attachment, AttachmentMeta, AttachmentStore, BuiltInput,
    ContentBlock, Dimension, InputMessage, Modality, ModalityUsage, RefMapping, Reference,
    ReferenceKind, Role, Source, UnknownDimension, MAX_ALT_CHARS, MAX_AUDIO_BYTES,
    MAX_DOCUMENT_BYTES, MAX_ID_CHARS, MAX_IMAGE_BYTES, MAX_NAME_CHARS, MAX_SUMMARY_CHARS,
    MAX_TEXT_BYTES, MAX_TEXT_CHARS, MAX_VIDEO_BYTES,
};
pub use preprocess::{
    plan_audio, plan_image, plan_video, preprocess, AppliedWork, AudioChunk, AudioPlan, AudioWork,
    Derived, DerivedKind, DerivedMeta, DerivedPayload, FrameSampler, ImagePlan, ImageProcessor,
    ImageWork, OcrEngine, OriginalRef, OriginalStore, PreprocessAccounting, PreprocessPlan,
    Preprocessed, Processors, SourceGeometry, Tile, Transcriber, VideoPlan, VideoWork,
    MAX_AUDIO_CHUNKS, MAX_DERIVED_ITEM_BYTES, MAX_DERIVED_TOTAL_BYTES, MAX_IMAGE_EDGE,
    MAX_OCR_CHARS, MAX_SAMPLE_RATE_HZ, MAX_SOURCE_FPS, MAX_TILES, MAX_TRANSCRIPT_CHARS,
    MAX_VIDEO_FRAMES,
};
pub use recordings::{
    build, read_manifest, verify, write_artifacts, ArtifactBundle, ArtifactLimits, Assertion,
    Chapter, FlowEvent, LabeledShot, Manifest, ManifestChapter, ManifestShot, Recording,
    ShortcutFlag, Verification, FAILURES_FILE, MANIFEST_FILE, MAX_ASSERTIONS,
    MAX_ASSERTION_DESC_CHARS, MAX_CHAPTERS, MAX_FLOW_NAME_CHARS, MAX_LABEL_CHARS,
    MAX_NOTES_PER_CHAPTER, MAX_NOTE_CHARS, MAX_RECORDING_ID_CHARS, MAX_REPORT_BYTES,
    MAX_SHORTCUT_DESC_CHARS, MAX_SHORTCUT_FLAGS, MAX_SHORTCUT_KEY_CHARS, MAX_SHOTS,
    MAX_SHOTS_PER_CHAPTER, MAX_SHOT_BYTES, MAX_SHOT_EDGE, MAX_SHOT_ID_CHARS, MAX_TITLE_CHARS,
    MAX_TOTAL_SHOT_BYTES, RECORDING_SCHEMA_VERSION, REPORT_FILE, SHOTS_DIR,
};
pub use sandboxed::{
    check_escape, check_scratch_write, execute, launch, stop, ActionOutcome, ActionRecord,
    BlockedAttempt, EscapeAttempt, EscapeKind, EscapeReport, SandboxBackend, SandboxRunner,
    SandboxSession, SandboxSpec, SandboxState, MAX_NETWORK_ALLOWLIST_ENTRIES,
    MAX_NETWORK_ENDPOINT_CHARS, MAX_SANDBOX_DISPLAY_EDGE, MAX_SANDBOX_RUNTIME_MS,
    MIN_SANDBOX_RUNTIME_MS,
};
