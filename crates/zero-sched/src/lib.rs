//! `zero-sched` — Banker's pools, lock strategy, owner election, MLFQ,
//! admission, budgets, backoff, usage windows, and durable dispatch queues.
//!
//! Contract (`architecture.md` §5): must not call providers directly.

pub mod admission;
pub mod banker;
pub mod backoff;
pub mod budget;
pub mod election;
pub mod mlfq;
pub mod queue;
pub mod usage;

pub use admission::{Admission, BucketConfig, Permit, Scheduler};
pub use banker::{Banker, DeclareOutcome, Grant, PoolKind, Request};
pub use backoff::{Backoff, BreakerState, CircuitBreaker, ProviderBreakers, RetryPolicy};
pub use budget::{BudgetConfig, BudgetOutcome, Budgets, Reservation};
pub use election::{Election, OwnerLease};
pub use mlfq::{Job, MlFq, WorkClass};
pub use queue::{Call, CallState, DurableQueue, QueueEvent};
pub use usage::{UsageWindow, WindowScheduler};
