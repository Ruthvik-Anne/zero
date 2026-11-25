//! `zero-halcyon` — see `architecture.md` section 5 for the module contract.
//!
//! [`discovery`] locates the nearest `.halcyon-mode` (working directory,
//! immediate children, or ancestors) and gates activation on explicit workspace
//! trust (HAL-01, HAL-02, HAL-12). Same-distance candidates disable the mode
//! with a reason.
//!
//! [`verify`] parses the document, checks an Ed25519 signature over a
//! deterministic canonical encoding against a key pinned in user configuration,
//! enforces the issuance/expiry window, and binds the document to the current
//! project id (HAL-02, HAL-03, HAL-05).
//!
//! [`keys`] provides the user-only key tooling — keygen, sign, pin, unpin,
//! rotate, revoke, un-revoke — and the actor gate that keeps every mutating or
//! signing action away from the agent (HAL-03, HAL-04). Private keys are either
//! held in memory or sealed at rest with Argon2id and AES-256-GCM.
//!
//! [`adapters`] detects the `tkb`, `joker`, and `epb` binaries on `PATH` and
//! negotiates their versions, turning a missing or outdated tool into typed
//! install or upgrade guidance with no installer, download, or vendor binding
//! (HAL-04, HAL-07, HAL-13).
//!
//! [`behaviour`] encodes the mode's workflow natively: gap recording, gates
//! only through `joker`, endpoints only through `epb`, and a completion gate
//! that refuses to finish without a `tkb check` record and a handover. A direct
//! gate or endpoint call is refused and recorded, never silently ignored
//! (HAL-05, HAL-08, HAL-09).
//!
//! [`flags`] defines exactly the four HAL-10 flags and resolves the global and
//! project layers so a project file can only disable a flag, never enable one.
//! A flag permits a capability; it never bypasses discovery or verification
//! (HAL-06, HAL-10).
//!
//! [`todo_sync`] mirrors todos to `tkb` in both directions when
//! `halcyon.todo_sync` is effective, merges by id and version, keeps an offline
//! queue, and surfaces conflicts as panel items instead of overwriting a side
//! (HAL-07, HAL-11, TODO-09, TSK-12).

pub mod adapters;
pub mod behaviour;
pub mod discovery;
pub mod flags;
pub mod keys;
pub mod todo_sync;
pub mod verify;

pub use adapters::{
    detect, detect_and_negotiate, negotiate, Adapter, AdapterKind, CommandProbe, Compatibility,
    Env, Requirement, ScriptedProbe, Version, VersionProbe, ADAPTER_DOCS_ANCHOR,
    DEFAULT_PROBE_OUTPUT_BYTES, DEFAULT_PROBE_TIMEOUT, EPB_MINIMUM_VERSION, JOKER_MINIMUM_VERSION,
    MAX_REPORTED_VERSION_BYTES, TKB_MINIMUM_VERSION,
};

pub use behaviour::{
    can_finish, finish, handover, record_check, record_gap, request_endpoint, request_gate,
    resolve_gap, waive_gap, CheckRecord, EndpointRecord, EpbAdapter, EpbRoute, FinishReport, Gap,
    GapSeverity, GateRecord, HalcyonRun, Handover, JokerAdapter, JokerRoute, Route,
    BEHAVIOUR_DOCS_ANCHOR, MAX_CHECK_SUMMARY_BYTES, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_ITEMS,
    MAX_GAP_DESCRIPTION_BYTES, MAX_HANDOVER_SUMMARY_BYTES, MAX_NAME_BYTES,
};

pub use discovery::{
    activation, discover, Activation, Discovery, ModeFile, TrustGate, TrustedRoots,
    UntrustedWorkspace, DEFAULT_MAX_MODE_FILE_BYTES, MODE_FILE_NAME, UNTRUSTED_REASON,
};

pub use flags::{
    parse_report, parse_values, resolve, Flag, FlagReport, FlagResolution, FlagSources, FlagValues,
    EPB_KEY, FLAGS_DOCS_ANCHOR, JOKER_KEY, MODE_KEY, PROJECT_CANNOT_ENABLE_REASON,
    PROJECT_DISABLED_REASON, TODO_SYNC_KEY,
};

pub use keys::{
    authorize, keygen, sign_mode, Actor, KeyAction, KeyPair, PinFile, RevokedKey, RotationRecord,
    SealedKey, SignedMode, KEY_ID_HEX_CHARS, MAX_PASSPHRASE_BYTES, MAX_SEALED_KEY_BYTES,
    PIN_FILE_SCHEMA, SEALED_KEY_VERSION,
};

pub use todo_sync::{
    conflict_items, resolve_conflict, sync, unavailable_error, ConflictChoice, ConflictItem,
    HalcyonTodo, PushOutcome, PushRejection, SyncReport, SyncState, TkbTodo, TodoConflict, TodoOp,
    TodoOpKind, TodoPayload, TodoStatus, MAX_APPLIED_OPS, MAX_CONFLICTS, MAX_PENDING_OPS,
    MAX_STATE_BYTES, MAX_TODOS, MAX_TODO_ID_BYTES, MAX_TODO_TITLE_BYTES, SYNC_STATE_SCHEMA,
    TODO_SYNC_DOCS_ANCHOR,
};

pub use verify::{
    activation_verified, canonical_bytes, verify, verify_mode_file, verify_with_skew, ModeDocument,
    PinSet, PinnedKey, VerifiedMode, Verifier, CANONICAL_DOMAIN, DEFAULT_CLOCK_SKEW_MS,
    MAX_CLOCK_SKEW_MS, MAX_MODE_DOCUMENT_BYTES, MAX_MODE_FIELD_BYTES, MAX_MODE_FLAGS, MAX_PINS,
    MAX_PIN_FILE_BYTES, MAX_SIGNATURE_B64_BYTES, MODE_DOCUMENT_VERSION, PUBLIC_KEY_BYTES,
    SIGNATURE_BYTES,
};
