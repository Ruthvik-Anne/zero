//! Budget reservation and reconciliation (SCH-09, MDL-08).
//!
//! Cost is predicted and reserved before dispatch, reconciled after, and a
//! request over a session, project, or daily limit is deferred with a reason
//! rather than silently dispatched.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zero_types::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetConfig {
    pub session_limit: u64,
    pub project_limit: u64,
    pub daily_limit: u64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self { session_limit: 1_000_000, project_limit: 5_000_000, daily_limit: 10_000_000 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub key: String,
    pub project: String,
    pub amount: u64,
    pub day: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetOutcome {
    Reserved(Reservation),
    Deferred { reason: String },
}

#[derive(Debug, Clone)]
pub struct Budgets {
    config: BudgetConfig,
    session_spent: u64,
    project_spent: BTreeMap<String, u64>,
    daily_spent: BTreeMap<i64, u64>,
    reserved: u64,
}

impl Budgets {
    pub fn new(config: BudgetConfig) -> Self {
        Self { config, session_spent: 0, project_spent: BTreeMap::new(), daily_spent: BTreeMap::new(), reserved: 0 }
    }

    pub fn spent(&self) -> u64 {
        self.session_spent
    }

    pub fn reserved(&self) -> u64 {
        self.reserved
    }

    pub fn project_spent(&self, project: &str) -> u64 {
        self.project_spent.get(project).copied().unwrap_or(0)
    }

    /// Predict and reserve. Over-budget work is deferred, never queued without a
    /// bound.
    pub fn reserve(&mut self, key: &str, project: &str, predicted: u64, day: i64) -> Result<BudgetOutcome> {
        let session_total = self.session_spent + predicted;
        if session_total > self.config.session_limit {
            return Ok(BudgetOutcome::Deferred {
                reason: format!(
                    "session budget: predicted {predicted} would reach {session_total} of {}",
                    self.config.session_limit
                ),
            });
        }
        let project_total = self.project_spent(project) + predicted;
        if project_total > self.config.project_limit {
            return Ok(BudgetOutcome::Deferred {
                reason: format!("project budget: predicted {project_total} of {}", self.config.project_limit),
            });
        }
        let daily_total = self.daily_spent.get(&day).copied().unwrap_or(0) + predicted;
        if daily_total > self.config.daily_limit {
            return Ok(BudgetOutcome::Deferred {
                reason: format!("daily budget: predicted {daily_total} of {}", self.config.daily_limit),
            });
        }
        self.reserved += predicted;
        Ok(BudgetOutcome::Reserved(Reservation { key: key.into(), project: project.into(), amount: predicted, day }))
    }

    /// Reconcile a reservation with the measured cost.
    pub fn reconcile(&mut self, reservation: Reservation, actual: u64) {
        self.reserved = self.reserved.saturating_sub(reservation.amount);
        self.session_spent += actual;
        *self.project_spent.entry(reservation.project).or_insert(0) += actual;
        *self.daily_spent.entry(reservation.day).or_insert(0) += actual;
    }

    /// Warn when 80% of a limit is consumed.
    pub fn warning(&self) -> Option<String> {
        if self.session_spent * 10 >= self.config.session_limit * 8 {
            Some(format!("session budget at {}%", self.session_spent * 100 / self.config.session_limit.max(1)))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn over_budget_work_defers_with_a_reason() {
        let mut budgets = Budgets::new(BudgetConfig { session_limit: 100, project_limit: 100, daily_limit: 100 });
        let outcome = budgets.reserve("k", "p", 101, 0).unwrap();
        match outcome {
            BudgetOutcome::Deferred { reason } => assert!(reason.contains("session budget")),
            other => panic!("{other:?}"),
        }
        assert_eq!(budgets.reserved(), 0, "nothing was reserved");
    }

    #[test]
    fn reservation_then_reconciliation_records_the_actual_cost() {
        let mut budgets = Budgets::new(BudgetConfig { session_limit: 100, project_limit: 200, daily_limit: 300 });
        let reservation = match budgets.reserve("k", "p", 60, 1).unwrap() {
            BudgetOutcome::Reserved(r) => r,
            other => panic!("{other:?}"),
        };
        assert_eq!(budgets.reserved(), 60);
        budgets.reconcile(reservation, 20);
        assert_eq!(budgets.reserved(), 0);
        assert_eq!(budgets.spent(), 20);
        assert_eq!(budgets.project_spent("p"), 20);
        assert!(budgets.warning().is_none());
        let reservation = match budgets.reserve("k2", "p", 60, 1).unwrap() {
            BudgetOutcome::Reserved(r) => r,
            other => panic!("{other:?}"),
        };
        budgets.reconcile(reservation, 60);
        assert!(budgets.warning().is_some(), "80% warning");
        let deferred = budgets.reserve("k3", "p", 50, 1).unwrap();
        assert!(matches!(deferred, BudgetOutcome::Deferred { .. }));
    }
}
