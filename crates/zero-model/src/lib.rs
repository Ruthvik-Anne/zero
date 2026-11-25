//! `zero-model` — providers, streaming, error mapping, and the conformance suite.
//!
//! Contract (`architecture.md` §5): must not read config files directly.

pub mod classify;
pub mod conformance;
pub mod decision;
pub mod errors;
pub mod freshness;
pub mod measured;
pub mod ollama;
pub mod openai;
pub mod pool;
pub mod provider;
pub mod roles;
pub mod router;
pub mod scripted;
pub mod translation;

pub use classify::{
    choose, classify, floor_for, meets, Capability, CapabilityFloor, Classification, FloorResult,
    Grade, MissingCapability, ModelGrades, TaskSignals, WorkClass,
};
pub use decision::{
    audit_line, compare_with_ledger, reconstruct, verify_turn, AuditTotals, DecisionContext,
    DecisionLog, EscalationRecord, LedgerEvent, LogReport, Mismatch, MismatchKind, ModelParameters,
    ReasoningEffort, SessionAudit, TurnGap, TurnId, TurnRecord, TurnRecordInit, MAX_LOG_BYTES,
};
pub use freshness::{
    drift, freshness, freshness_with, gate, is_stale_and_unrefreshed, needs_refresh, refresh,
    route_fresh, Drift, DriftChange, Freshness, FreshnessPolicy, GateResult, ModelData,
    RefreshReport, RefreshSource, DEFAULT_HARD_EXPIRY_MS, DEFAULT_MAX_AGE_MS, MAX_TIMESTAMP_MS,
};
// `measured::choose` is namespaced (`zero_model::measured::choose`) because
// `zero_model::choose` is the classifier's selection function.
pub use measured::{
    model_stats, prediction_error, preflight_budget, reconcile, reconcile_with_tolerance,
    record_and_choose, MeasuredChoice, MeasuredPolicy, ModelStats, Outcome, OutcomeLog,
    Reconciliation, DEFAULT_MAX_OUTCOMES, DEFAULT_WINDOW_MS, MAX_OUTCOME_LOG_BYTES,
    RECONCILIATION_TOLERANCE_BPS,
};
pub use ollama::{OllamaConfig, OllamaProvider, ToolSupport};
pub use openai::{OpenAiConfig, OpenAiProvider};
pub use pool::{
    seed_default, tier_for_combined_rate, Availability, ModelCost, ModelEntry, PoolSeed,
    RateLimits, Seed, Source, DEFAULT_SEED_JSON, MAX_SEED_BYTES, SEED_SCHEMA_VERSION,
};
pub use provider::{
    Capabilities, Collector, CompletionRequest, Control, EventSink, Message, Provider, ProviderEvent,
    ProviderResponse, RetryClass, RetryPolicy, Role, StopReason, ToolCall, ToolSchema, Usage,
};
// `provider::Role` is the message role, so the agent role enum (MDL-07) is
// re-exported as `AgentRole`; use `zero_model::roles::Role` for the bare name.
pub use roles::{
    assign, enforce_floor, pick, resolve, role_candidates, ModelCatalogue, Role as AgentRole,
    RoleAssignment, RoleDefault, RoleRequest, RoleSource, RoleTable, UpgradeRequest,
};
pub use router::{
    escalate, is_local_provider, route, route_with_failures, Escalation, FailureEvidence,
    FailureKind, Overrides, Pool, PoolModel, RouteDecision,
};
pub use scripted::{ScriptTurn, ScriptedProvider};
// The canonical transcript message is re-exported as `TranscriptMessage` because
// `Message` is already the provider message type.
pub use translation::{
    translate, translate_for_escalation, translate_with_capabilities, Block, DroppedBlock,
    Message as TranscriptMessage, MessageRole, ProviderFormat, TargetCapabilities, Transcript,
    Translation, TranslationReport,
};
