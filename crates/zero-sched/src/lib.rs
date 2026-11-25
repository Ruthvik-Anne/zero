//! `zero-sched` — Banker's pools, lock strategy, owner election, MLFQ,
//! admission, budgets, backoff, usage windows, and durable dispatch queues.
//!
//! Contract (`architecture.md` §5): must not call providers directly.

pub mod admission;
pub mod banker;
pub mod backoff;
pub mod budget;
pub mod cost_audit;
pub mod cost_budget;
pub mod election;
pub mod mlfq;
pub mod queue;
pub mod usage;
pub mod usage_ledger;

pub use admission::{Admission, BucketConfig, Permit, Scheduler};
pub use banker::{Banker, DeclareOutcome, Grant, PoolKind, Request};
pub use backoff::{Backoff, BreakerState, CircuitBreaker, ProviderBreakers, RetryPolicy};
pub use budget::{BudgetConfig, BudgetOutcome, Budgets, Reservation};
pub use cost_audit::{
    apply, apply_with_confirmations, audit, rollback, AppliedChange, ApplyReport, AuditMode,
    AuditOptions, AuditState, AuditWindow, CostAudit, CostChange, Finding, FindingKind,
    ManualProposal, ModelSpend, PreviewChange, Proposal, ProposalKind, ProviderSpend, RetryStats,
    Risk, SessionSpend, SkipReason, SkippedProposal, SwitchSuggestion, MAX_APPLIED_CHANGES,
    MAX_EVIDENCE_IDS, MAX_EVIDENCE_LINES_HARD, MAX_PROPOSALS_DEFAULT, MAX_PROPOSALS_HARD,
};
pub use cost_budget::{
    dashboard, day_of, surfaces, BudgetLimit, BudgetScope, BudgetState, BudgetView, CostBudget,
    Dashboard, Decision, Preflight, Surface, SurfaceUsage, DAY_MS, TOP_N,
};
pub use election::{Election, OwnerLease};
pub use mlfq::{Job, MlFq, WorkClass};
pub use queue::{Call, CallState, DurableQueue, QueueEvent};
pub use usage::{UsageWindow, WindowScheduler};
pub use usage_ledger::{
    attribute, export_csv, export_json, merge, merge_files, share_bps, totals, totals_by,
    validate_parents, AttributedEvent, MergeConflict, MergeReport, MergeResult, ReadReport, Totals,
    UsageEvent, UsageLedger, MAX_SHARE_BPS,
};
