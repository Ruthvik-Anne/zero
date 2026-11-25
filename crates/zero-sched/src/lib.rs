//! `zero-sched` — Banker's pools, lock strategy, owner election, MLFQ,
//! admission, budgets, backoff, and usage windows.
//!
//! Contract (`architecture.md` §5): must not call providers directly.

pub mod banker;
pub mod election;

pub use banker::{Banker, DeclareOutcome, Grant, PoolKind, Request};
pub use election::{Election, OwnerLease};
