//! `zero-agent` — agent loop, sessions, compaction, context files, queue,
//! artifacts, export/import, and projects/goals in later milestones.
//!
//! Contract (`architecture.md` §5): must not bypass the policy evaluator. The
//! loop is the only dispatch path; M2 inserts the evaluator here.

pub mod artifacts;
pub mod audit;
pub mod autonomy;
pub mod compaction;
pub mod context;
pub mod eval_suite;
pub mod export;
pub mod r#loop;
pub mod mobile_offline;
pub mod monitor;
pub mod monitor_defs;
pub mod monitor_restart;
pub mod project;
pub mod promotion;
pub mod queue;
pub mod resume;
pub mod resume_window;
pub mod security_suite;
pub mod self_improve;
pub mod tools;
pub mod tree;

pub use r#loop::{
    AgentLoop, CancelToken, EchoTool, LoopConfig, ReadFileTool, RunOutcome, Tool, ToolEntry,
    ToolRegistry, ToolResult, TurnRecord,
};
pub use audit::{
    audit_tasks, check_profile, open_project_task_store, panel_entries, panel_task_for_unit,
    seed_audit_tasks, start_audit, start_audit_with_profile, task_metadata, task_store_path,
    task_title_for_unit, AuditRun, EffectiveProfile, PanelEntry, ProjectAuditProfile, TaskMetadata,
    AUDITS_DIR_NAME, MIN_EVIDENCE_REFS, PROJECT_PROFILE_FILE, RUN_PREFIX, TASK_STORE_FILE,
    TASK_STATUS_PENDING, ZERO_DIR,
};
pub use autonomy::{
    load_goal, next_cron, save_goal, start_goal, AutonomyRun, CancelScope, CronSpec, Goal,
    GoalState, Heartbeat, HeartbeatBook, HeartbeatKind, LimitKind, Limits, Schedule, ScheduleBook,
    ScheduleSpec, TickClaim, GOAL_KEY,
};
pub use eval_suite::{
    compare, load_suite, load_suite_verified, public_view, run_suite, run_suite_with_clock,
    safe_relative_path, suite_hash, validate_suite, verify_hash, CandidateOutput, CandidateRunner,
    Check, Delta, EvalReport, EvalSuite, EvalTask, FailedCheck, Fixture, PublicSuite, PublicTask,
    TaskResult, EVAL_SUITE_SCHEMA_VERSION, MAX_CHECKS_PER_TASK, MAX_FILES_PER_TASK, MAX_FILE_BYTES,
    MAX_FIXTURE_BYTES, MAX_PROMPT_BYTES, MAX_SUITE_BYTES, MAX_SUITE_FIXTURE_BYTES, MAX_TASKS,
    SUITE_HASH_PREFIX,
};
pub use project::{
    answer_copy, answer_replaced, find_root, link_action, open as open_project, project_id_for, recovery_actions,
    BindingRegistry, CopyPrompt, OpenMode, OpenOutcome, Project, ProjectBinding, ProjectFile,
    ReplaceChoice,
};
pub use monitor::{
    scrubbed_env, is_secret_variable, BurstWindow, LogSink, MemoryLogSink, MonitorEngine,
    MonitorEvent, MonitorHandle, MonitorSpec, MonitorStats, MonitorStatus, DEFAULT_LINE_CAP_BYTES,
    DEFAULT_MAX_EVENTS_PER_DRAIN, DEFAULT_MAX_QUEUED_LINES, DEFAULT_MEMORY_LOG_LINES,
    DEFAULT_STDERR_QUEUE_LINES, TRUNCATION_MARKER,
};
pub use monitor_defs::{
    check as check_monitor_definition, load_manifest, start_for, start_for_report, stop_all,
    MonitorDefinition, MonitorManifest, MonitorManifestLimits, MonitorPolicy, MonitorRefusal,
    MonitorRegistry, MonitorSource, MonitorTriggerReport, MonitorWhen, MonitorWhenKey,
    DEFAULT_MANIFEST_MAX_BYTES, DEFAULT_MANIFEST_MAX_MONITORS, MONITOR_MANIFEST_SCHEMA_VERSION,
    SOURCE_KIND_ENV, SOURCE_TARGET_ENV,
};
pub use monitor_restart::{
    apply as apply_restart, plan as plan_restart, MonitorJournal, MonitorKind, MonitorRecord,
    RestartDecision, RestartPlan, RestartReport, RestartRequest, ResumeCause,
    DEFAULT_JOURNAL_MAX_RECORDS, MONITOR_JOURNAL_SCHEMA_VERSION,
};
pub use mobile_offline::{
    notify, reconnect, redact_secrets, FlushFailure, FlushReport, InputKind, MobileClient,
    Notification, NotificationAction, NotificationKind, NotificationOutbox, NotificationSink,
    NotificationTransport, OfflineInput, OfflineQueue, ReconnectOutcome, ResumeToken,
    DEFAULT_NOTIFICATION_CAP, DEFAULT_OFFLINE_MAX_BYTES, DEFAULT_OFFLINE_MAX_ENTRIES,
    MAX_DELIVERED_IDS, MAX_NOTIFICATION_BODY_CHARS, MAX_NOTIFICATION_TITLE_CHARS,
    MAX_OFFLINE_INPUT_BYTES, MAX_OFFLINE_SESSION_CHARS, OFFLINE_QUEUE_SCHEMA_VERSION,
};
// `ResumeCause` at the crate root belongs to `monitor_restart` (MON-12); the
// auto-resume cause is re-exported as `AgentResumeCause` to avoid the clash.
// Both are available unambiguously as `monitor_restart::ResumeCause` and
// `resume::ResumeCause`.
pub use resume::{
    children_plan, decide, ChildTask, ChildrenResume, ResumeAttempt, ResumeCause as AgentResumeCause,
    ResumeChildren, ResumeContext, ResumeDecision, ResumePlan, ResumePolicy,
};
pub use resume_window::{
    assert_no_effect_replay, pause, poll, resume_from, JournalProgress, PausedRun, ReplayPlan,
    ReplaySource, ResumeCursor, ResumeWindowOutcome, WaitingView, WindowAction, WindowReason,
    CANCEL_ACTION, SWITCH_ACTION,
};
pub use security_suite::{
    assert_not_instruction, assert_release_secure, external_suite_results,
    policy_is_unchanged_by_untrusted, prompt_injection_suite, render_for_sink,
    run_security_suites, secret_leakage_suite, seeded_redactor, wrap_untrusted, InjectionFixture,
    LeakSink, SecuritySuiteError, SecuritySuiteReport, SecretFixture, SuiteResult,
    UntrustedEnvelopeError, UntrustedSource, ENVELOPE_TRUNCATION_MARKER, INJECTION_FIXTURES,
    INSTRUCTION_MARKERS, MAX_ENVELOPE_BYTES, PROMPT_INJECTION_SUITE, REQUIRED_EXTERNAL_SUITES,
    SECRET_FIXTURES, SECRET_LEAKAGE_SUITE, SSRF_EGRESS_SUITE, UNTRUSTED_DATA_LABEL,
    UNTRUSTED_WARNING, ZIP_SLIP_SUITE,
};
pub use self_improve::{
    apply_change_set, promote, run_loop, run_loop_with_clock, validate_proposal, CapturedFile,
    CaptureRecord, ChangeSet, DistilRecord, Evaluator, ExecutionRecord, HumanGate, LoopDecision,
    LoopLimits, LoopReport, LoopState, Promotion, Proposal, ProposalExecutor, ReentrySeed, Stage,
    StageEvent, StageOutcome, Target, VerifyRecord, Verifier, MAX_ATTEMPTS, MAX_CHANGE_BYTES,
    MAX_CHANGE_FILES, MAX_CHANGE_FILE_BYTES, MAX_DETAIL_BYTES, MAX_EVIDENCE_REFS,
    MAX_EVIDENCE_REF_BYTES, MAX_RATIONALE_BYTES, MAX_SUMMARY_BYTES, MAX_TITLE_BYTES,
    PROPOSAL_HASH_PREFIX,
};
pub use promotion::{
    apply_promotion, approve_promotion, diff_hash, render_diff, rollback, rollback_forced, Approval,
    AppliedFile, AppliedPromotion, HumanGate as HumanApprovalGate, ImmutableCore, RollbackReport,
    DEFAULT_PROTECTED_PATHS, DIFF_HASH_PREFIX, MAX_BACKUP_BYTES, MAX_BACKUP_FILES, MAX_DIFF_BYTES,
    MAX_REASON_BYTES,
};
pub use tools::{
    activate, filter_denied, hygiene, inject_tools, search, stable_prefix_hash, wire_schemas,
    Activation, ActivationContext, PromptInjection, Route, SearchHit, ToolMeta, ToolSource,
    ToolTelemetry, Use,
};
pub use tree::{auto_name, ResumeView, SessionNode, SessionTree};

/// The core tool set loaded by the loop: echo and read-only file access.
pub fn tool_registry_with_core() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(EchoTool));
    registry.register(Box::new(ReadFileTool::default()));
    registry
}
