//! Warn and stop cost budgets, dashboard data, and on-demand export
//! (USG-03, USG-04, USG-06).
//!
//! A budget is a scope (`Global`, `Project`, `Device`, or `Day`) plus an
//! optional warn threshold and an optional stop threshold, both in millionths
//! of the billing currency unit (`cost_micros`). [`CostBudget::preflight`] is
//! the dispatch gate: when the projected spend reaches a stop threshold the
//! caller receives [`Decision::Stop`] and must not dispatch. The module holds
//! no UI and no filesystem state; [`dashboard`] and [`surfaces`] produce the
//! numbers the TUI, desktop, and Android surfaces render, and the export
//! functions reuse the ledger's formats without writing a file or sending
//! anything over the network.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::usage_ledger::{self, Totals, UsageEvent};

/// Milliseconds in one UTC day.
pub const DAY_MS: i64 = 86_400_000;

/// How many model and provider rows a dashboard carries.
pub const TOP_N: usize = 5;

/// The UTC day containing `now_ms`, counted as days since 1970-01-01.
///
/// Floor division is used, so times before the epoch map to negative days
/// without truncating toward zero.
pub fn day_of(now_ms: i64) -> i64 {
    now_ms.div_euclid(DAY_MS)
}

/// The thing a budget applies to.
///
/// The variant order is the deterministic tie-break order used when two
/// scopes hit the same threshold: `Global`, then `Project`, then `Device`,
/// then `Day`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BudgetScope {
    /// Every unit of work.
    Global,
    /// Work attributed to a project.
    Project(String),
    /// Work observed on a device.
    Device(String),
    /// Work observed during one UTC day. The value is [`day_of`]'s epoch day,
    /// not a timestamp.
    Day(i64),
}

impl BudgetScope {
    /// Stable label used by dashboards and surfaces.
    pub fn label(&self) -> String {
        match self {
            Self::Global => "global".to_owned(),
            Self::Project(project) => format!("project:{project}"),
            Self::Device(device) => format!("device:{device}"),
            Self::Day(day) => format!("day:{day}"),
        }
    }
}

/// One warning/stop pair for one scope.
///
/// At least one threshold is required and neither may be zero. When both are
/// set, `warn_micros <= stop_micros`; equality is allowed and the stop
/// threshold wins at the boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLimit {
    pub scope: BudgetScope,
    pub warn_micros: Option<u64>,
    pub stop_micros: Option<u64>,
}

impl BudgetLimit {
    /// Warn-only limit.
    pub fn warn(scope: BudgetScope, micros: u64) -> Self {
        Self { scope, warn_micros: Some(micros), stop_micros: None }
    }

    /// Stop-only limit.
    pub fn stop(scope: BudgetScope, micros: u64) -> Self {
        Self { scope, warn_micros: None, stop_micros: Some(micros) }
    }

    /// Warn and stop limit in one pair.
    pub fn warn_stop(scope: BudgetScope, warn_micros: u64, stop_micros: u64) -> Self {
        Self { scope, warn_micros: Some(warn_micros), stop_micros: Some(stop_micros) }
    }

    /// Validate thresholds and the scope's name.
    pub fn validate(&self) -> Result<()> {
        if self.warn_micros.is_none() && self.stop_micros.is_none() {
            return Err(invalid("budget limit needs a warn or stop threshold"));
        }
        if self.warn_micros == Some(0) || self.stop_micros == Some(0) {
            return Err(invalid(format!("budget limit `{}` must be nonzero", self.scope.label())));
        }
        if let (Some(warn), Some(stop)) = (self.warn_micros, self.stop_micros) {
            if warn > stop {
                return Err(invalid(format!(
                    "budget limit `{}`: warn {warn} exceeds stop {stop}",
                    self.scope.label()
                )));
            }
        }
        match &self.scope {
            BudgetScope::Project(project) if project.trim().is_empty() => {
                Err(invalid("budget project scope must not be empty"))
            }
            BudgetScope::Device(device) if device.trim().is_empty() => {
                Err(invalid("budget device scope must not be empty"))
            }
            _ => Ok(()),
        }
    }

    /// State implied by an absolute spend. Thresholds are inclusive, and the
    /// stop threshold wins when warn and stop are equal.
    pub fn state_for(&self, spent_micros: u64) -> BudgetState {
        if self.stop_micros.is_some_and(|stop| spent_micros >= stop) {
            BudgetState::Stop
        } else if self.warn_micros.is_some_and(|warn| spent_micros >= warn) {
            BudgetState::Warn
        } else {
            BudgetState::Ok
        }
    }
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

/// Warn and stop budgets plus the spend recorded against each scope.
///
/// There is at most one [`BudgetLimit`] per scope; a duplicate scope is an
/// `invalid_input` error rather than a silent override. Spend is keyed by the
/// same scope and saturates instead of wrapping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CostBudget {
    limits: BTreeMap<BudgetScope, BudgetLimit>,
    spend: BTreeMap<BudgetScope, u64>,
}

impl CostBudget {
    /// Build a budget from limits, validating each one and rejecting a
    /// duplicate scope.
    pub fn new(limits: Vec<BudgetLimit>) -> Result<Self> {
        let mut budget = Self::default();
        for limit in limits {
            budget.add_limit(limit)?;
        }
        Ok(budget)
    }

    /// Validate and add one limit.
    pub fn add_limit(&mut self, limit: BudgetLimit) -> Result<()> {
        limit.validate()?;
        if self.limits.contains_key(&limit.scope) {
            return Err(invalid(format!(
                "duplicate budget limit for scope `{}`",
                limit.scope.label()
            )));
        }
        self.limits.insert(limit.scope.clone(), limit);
        Ok(())
    }

    /// The limit configured for a scope, if any.
    pub fn limit(&self, scope: &BudgetScope) -> Option<&BudgetLimit> {
        self.limits.get(scope)
    }

    /// Limits in deterministic scope order.
    pub fn limits(&self) -> impl Iterator<Item = &BudgetLimit> {
        self.limits.values()
    }

    /// Add spend under a scope. Additions saturate.
    pub fn record(&mut self, scope: BudgetScope, micros: u64) {
        let entry = self.spend.entry(scope).or_insert(0);
        *entry = entry.saturating_add(micros);
    }

    /// Spend recorded under a scope.
    pub fn spend(&self, scope: &BudgetScope) -> u64 {
        self.spend.get(scope).copied().unwrap_or(0)
    }

    /// Convenience recording for a ledger event: global, device, and the
    /// event's UTC day, plus the named project when the caller knows it.
    pub fn record_event(&mut self, event: &UsageEvent, project: Option<&str>) {
        self.record(BudgetScope::Global, event.cost_micros);
        self.record(BudgetScope::Device(event.device.clone()), event.cost_micros);
        self.record(BudgetScope::Day(day_of(event.at_ms)), event.cost_micros);
        if let Some(project) = project {
            self.record(BudgetScope::Project(project.to_owned()), event.cost_micros);
        }
    }

    /// Decide whether a cost may be dispatched.
    ///
    /// `contexts` names the project and device the work belongs to. `Global`
    /// and the current day's `Day` scope are always evaluated when they have a
    /// limit, even if the caller omits them, because both apply to all work.
    /// Any `Day` value in `contexts` is replaced by the day derived from
    /// `now_ms`, so a stale day cannot be evaluated and yesterday's spend
    /// cannot leak into today.
    ///
    /// Projected spend is `spend(scope) + cost_micros`, saturating. Both
    /// thresholds are inclusive: reaching the stop threshold stops and
    /// reaching the warn threshold warns. A stop anywhere wins over a warn
    /// elsewhere; among several stops the scope furthest over its limit wins,
    /// with the [`BudgetScope`] order as the tie-break. `remaining` is the
    /// headroom left under the deciding limit after this cost - zero for a
    /// stop, and zero for a warn-only limit.
    pub fn preflight(
        &self,
        cost_micros: u64,
        contexts: &[BudgetScope],
        now_ms: i64,
    ) -> Preflight {
        let today = BudgetScope::Day(day_of(now_ms));
        let mut evaluated: BTreeSet<BudgetScope> = BTreeSet::new();
        for scope in contexts {
            evaluated.insert(match scope {
                BudgetScope::Day(_) => today.clone(),
                other => other.clone(),
            });
        }
        if self.limits.contains_key(&BudgetScope::Global) {
            evaluated.insert(BudgetScope::Global);
        }
        if self.limits.contains_key(&today) {
            evaluated.insert(today);
        }

        let mut projected_by_scope = BTreeMap::new();
        let mut stop: Option<(u64, BudgetScope)> = None;
        let mut warn: Option<(u64, BudgetScope)> = None;

        for scope in evaluated {
            let Some(limit) = self.limits.get(&scope) else {
                continue;
            };
            let projected = self.spend(&scope).saturating_add(cost_micros);
            projected_by_scope.insert(scope.clone(), projected);

            if let Some(stop_micros) = limit.stop_micros {
                if projected >= stop_micros {
                    let overshoot = projected - stop_micros;
                    let better = match &stop {
                        None => true,
                        Some((best_overshoot, best_scope)) => {
                            overshoot < *best_overshoot
                                || (overshoot == *best_overshoot && scope < *best_scope)
                        }
                    };
                    if better {
                        stop = Some((overshoot, scope.clone()));
                    }
                    continue;
                }
            }

            if let Some(warn_micros) = limit.warn_micros {
                if projected >= warn_micros {
                    let headroom =
                        limit.stop_micros.map_or(0, |stop| stop.saturating_sub(projected));
                    let better = match &warn {
                        None => true,
                        Some((best_headroom, best_scope)) => {
                            headroom < *best_headroom
                                || (headroom == *best_headroom && scope < *best_scope)
                        }
                    };
                    if better {
                        warn = Some((headroom, scope.clone()));
                    }
                }
            }
        }

        if let Some((_, scope)) = stop {
            let projected = projected_by_scope.get(&scope).copied().unwrap_or(cost_micros);
            return Preflight {
                decision: Decision::Stop { scope, remaining: 0 },
                projected,
                projected_by_scope,
            };
        }

        if let Some((headroom, scope)) = warn {
            let projected = projected_by_scope.get(&scope).copied().unwrap_or(cost_micros);
            return Preflight {
                decision: Decision::Warn { remaining: headroom },
                projected,
                projected_by_scope,
            };
        }

        // No limit constrained the work. Report the largest projected total
        // across evaluated scopes, or the cost itself when nothing applies.
        let projected = projected_by_scope
            .values()
            .copied()
            .max()
            .unwrap_or(cost_micros);
        Preflight { decision: Decision::Allow, projected, projected_by_scope }
    }
}

/// Outcome of [`CostBudget::preflight`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No threshold reached; dispatch is permitted.
    Allow,
    /// Dispatch is permitted but the spend is at or above a warn threshold.
    Warn { remaining: u64 },
    /// Dispatch must not happen. The scope names the budget that stopped it.
    Stop { scope: BudgetScope, remaining: u64 },
}

/// Preflight result: the decision, the deciding projected spend, and the
/// projected spend for every evaluated scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preflight {
    pub decision: Decision,
    pub projected: u64,
    pub projected_by_scope: BTreeMap<BudgetScope, u64>,
}

impl Preflight {
    /// True when dispatch must be refused.
    pub fn is_stop(&self) -> bool {
        matches!(self.decision, Decision::Stop { .. })
    }

    /// The dispatch contract in one call: dispatch only when this is true.
    pub fn permits_dispatch(&self) -> bool {
        !self.is_stop()
    }
}

/// Severity of a budget view. Ordered so the maximum is the dashboard state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BudgetState {
    Ok,
    Warn,
    Stop,
}

impl BudgetState {
    /// Lowercase token shared by every surface.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Stop => "stop",
        }
    }
}

/// One scope's row on a dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetView {
    pub scope: BudgetScope,
    pub spent: u64,
    pub warn: Option<u64>,
    pub stop: Option<u64>,
    pub state: BudgetState,
}

/// Everything the TUI, desktop, and Android surfaces need, computed once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dashboard {
    pub generated_at_ms: i64,
    pub totals: Totals,
    /// One row per configured limit, in [`BudgetScope`] order.
    pub by_scope: Vec<BudgetView>,
    /// Cost by model, highest first, at most [`TOP_N`] rows.
    pub top_models: Vec<(String, u64)>,
    /// Cost by provider, highest first, at most [`TOP_N`] rows.
    pub top_providers: Vec<(String, u64)>,
    /// Events in the 24 hours ending at `generated_at_ms`.
    pub recent_events: usize,
}

impl Dashboard {
    /// Worst state across all scope rows.
    pub fn overall_state(&self) -> BudgetState {
        self.by_scope
            .iter()
            .map(|view| view.state)
            .max()
            .unwrap_or(BudgetState::Ok)
    }
}

/// Build a dashboard from ledger events and budgets.
///
/// Spend per scope is the larger of the ledger figure and the spend recorded
/// on the budget. A project appears only when a project limit is configured,
/// because ledger events do not carry a project field. Global totals, model
/// and provider costs, and the recent-event count always come from the
/// ledger.
pub fn dashboard(events: &[UsageEvent], budget: &CostBudget, now_ms: i64) -> Dashboard {
    let totals = usage_ledger::totals(events);
    let mut device_spend: BTreeMap<&str, u64> = BTreeMap::new();
    let mut day_spend: BTreeMap<i64, u64> = BTreeMap::new();
    let mut model_cost: BTreeMap<String, u64> = BTreeMap::new();
    let mut provider_cost: BTreeMap<String, u64> = BTreeMap::new();

    for event in events {
        let device = device_spend.entry(event.device.as_str()).or_insert(0);
        *device = device.saturating_add(event.cost_micros);
        let day = day_spend.entry(day_of(event.at_ms)).or_insert(0);
        *day = day.saturating_add(event.cost_micros);
        let model = model_cost.entry(event.model.clone()).or_insert(0);
        *model = model.saturating_add(event.cost_micros);
        let provider = provider_cost.entry(event.provider.clone()).or_insert(0);
        *provider = provider.saturating_add(event.cost_micros);
    }

    let mut by_scope = Vec::with_capacity(budget.limits.len());
    for (scope, limit) in &budget.limits {
        let ledger_spent = match scope {
            BudgetScope::Global => totals.cost_micros,
            BudgetScope::Project(_) => 0,
            BudgetScope::Device(device) => {
                device_spend.get(device.as_str()).copied().unwrap_or(0)
            }
            BudgetScope::Day(day) => day_spend.get(day).copied().unwrap_or(0),
        };
        let spent = ledger_spent.max(budget.spend(scope));
        by_scope.push(BudgetView {
            scope: scope.clone(),
            spent,
            warn: limit.warn_micros,
            stop: limit.stop_micros,
            state: limit.state_for(spent),
        });
    }

    let recent_events = events
        .iter()
        .filter(|event| event.at_ms <= now_ms && now_ms.saturating_sub(event.at_ms) <= DAY_MS)
        .count();

    Dashboard {
        generated_at_ms: now_ms,
        totals,
        by_scope,
        top_models: top_costs(model_cost),
        top_providers: top_costs(provider_cost),
        recent_events,
    }
}

fn top_costs(costs: BTreeMap<String, u64>) -> Vec<(String, u64)> {
    let mut rows: Vec<(String, u64)> = costs.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(TOP_N);
    rows
}

/// The three surfaces that must show the same usage numbers (USG-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Surface {
    Tui,
    Desktop,
    Android,
}

impl Surface {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tui => "tui",
            Self::Desktop => "desktop",
            Self::Android => "android",
        }
    }
}

/// One surface's rendering. Every surface carries the same [`BudgetState`] and
/// the same numbers, formatted natively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceUsage {
    pub surface: Surface,
    pub state: BudgetState,
    /// Rendered lines, including a `state=<ok|warn|stop>` token.
    pub lines: Vec<String>,
}

/// Render the same dashboard for the TUI, desktop, and Android surfaces, in
/// that fixed order.
pub fn surfaces(dashboard: &Dashboard) -> Vec<SurfaceUsage> {
    let state = dashboard.overall_state();
    vec![
        SurfaceUsage {
            surface: Surface::Tui,
            state,
            lines: render_tui(dashboard, state),
        },
        SurfaceUsage {
            surface: Surface::Desktop,
            state,
            lines: render_desktop(dashboard, state),
        },
        SurfaceUsage {
            surface: Surface::Android,
            state,
            lines: render_android(dashboard, state),
        },
    ]
}

fn render_tui(dashboard: &Dashboard, state: BudgetState) -> Vec<String> {
    let mut lines = vec![format!(
        "Usage · cost {} µ$ · {} events · state={}",
        dashboard.totals.cost_micros,
        dashboard.totals.events,
        state.as_str()
    )];
    for view in &dashboard.by_scope {
        lines.push(format!(
            "  {}  {}/{} µ$  state={}",
            view.scope.label(),
            view.spent,
            view.stop.unwrap_or(u64::MAX),
            view.state.as_str()
        ));
    }
    lines
}

fn render_desktop(dashboard: &Dashboard, state: BudgetState) -> Vec<String> {
    let mut lines = vec![
        "Usage dashboard".to_owned(),
        format!(
            "Total cost: {} µ$ across {} events",
            dashboard.totals.cost_micros, dashboard.totals.events
        ),
        format!("State: {} (state={})", state.as_str().to_uppercase(), state.as_str()),
    ];
    for view in &dashboard.by_scope {
        lines.push(format!(
            "  {:<22} spent {} µ$ · warn {} · stop {} · state={}",
            view.scope.label(),
            view.spent,
            optional_micros(view.warn),
            optional_micros(view.stop),
            view.state.as_str()
        ));
    }
    lines
}

fn render_android(dashboard: &Dashboard, state: BudgetState) -> Vec<String> {
    let mut lines = vec![format!(
        "cost={}u events={} state={}",
        dashboard.totals.cost_micros,
        dashboard.totals.events,
        state.as_str()
    )];
    for view in &dashboard.by_scope {
        lines.push(format!(
            "{} spent={}u warn={} stop={} state={}",
            view.scope.label(),
            view.spent,
            optional_micros(view.warn),
            optional_micros(view.stop),
            view.state.as_str()
        ));
    }
    lines
}

fn optional_micros(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_owned(), |micros| format!("{micros} µ$"))
}

/// CSV export with the ledger's stable schema and RFC 4180 quoting.
///
/// Returns a string; writes no file and sends nothing.
pub fn export_csv(events: &[UsageEvent]) -> String {
    usage_ledger::export_csv(events)
}

/// JSON export with the ledger's stable shape.
///
/// Returns a string; writes no file and sends nothing.
pub fn export_json(events: &[UsageEvent]) -> Result<String> {
    usage_ledger::export_json(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(
        device: &str,
        model: &str,
        provider: &str,
        at_ms: i64,
        cost_micros: u64,
        nonce: &str,
    ) -> UsageEvent {
        UsageEvent::new(device, "s1", model, provider, at_ms, None, nonce)
            .with_cost(cost_micros)
    }

    fn budget_of(limits: Vec<BudgetLimit>) -> CostBudget {
        CostBudget::new(limits).unwrap()
    }

    fn project(name: &str) -> BudgetScope {
        BudgetScope::Project(name.to_owned())
    }

    fn device(name: &str) -> BudgetScope {
        BudgetScope::Device(name.to_owned())
    }

    #[test]
    fn warn_and_stop_preflight_decisions() {
        let scope = project("alpha");
        let mut budget = budget_of(vec![BudgetLimit::warn_stop(scope.clone(), 800, 1_000)]);

        let allow = budget.preflight(100, std::slice::from_ref(&scope), 0);
        assert_eq!(allow.decision, Decision::Allow);
        assert!(allow.permits_dispatch());
        assert_eq!(allow.projected, 100);
        assert_eq!(allow.projected_by_scope[&scope], 100);

        budget.record(scope.clone(), 750);
        let warn = budget.preflight(60, std::slice::from_ref(&scope), 0);
        assert_eq!(warn.decision, Decision::Warn { remaining: 190 });
        assert!(warn.permits_dispatch(), "a warn must not block dispatch");
        assert_eq!(warn.projected, 810);

        let stop = budget.preflight(300, std::slice::from_ref(&scope), 0);
        assert_eq!(stop.decision, Decision::Stop { scope: scope.clone(), remaining: 0 });
        assert!(stop.is_stop());
        assert!(!stop.permits_dispatch(), "a stop must block dispatch");
        assert_eq!(stop.projected, 1_050);

        // A warn-only limit never stops, even well past its threshold.
        let mut warn_only = budget_of(vec![BudgetLimit::warn(device("dev-a"), 100)]);
        warn_only.record(device("dev-a"), 500);
        let warned = warn_only.preflight(500, &[device("dev-a")], 0);
        assert_eq!(warned.decision, Decision::Warn { remaining: 0 });
        assert!(warned.permits_dispatch());

        // No applicable limit allows the work and reports the cost.
        let unbounded = budget_of(vec![BudgetLimit::stop(project("other"), 10)]);
        let allowed = unbounded.preflight(42, &[project("alpha")], 0);
        assert_eq!(allowed.decision, Decision::Allow);
        assert_eq!(allowed.projected, 42);
    }

    #[test]
    fn a_stop_budget_halts_dispatch() {
        let scope = device("dev-a");
        let mut budget = budget_of(vec![BudgetLimit::warn_stop(scope.clone(), 50, 100)]);
        budget.record(scope.clone(), 95);

        let mut dispatched = Vec::new();
        for cost in [5_u64, 4, 5] {
            let preflight = budget.preflight(cost, std::slice::from_ref(&scope), 0);
            if preflight.permits_dispatch() {
                budget.record(scope.clone(), cost);
                dispatched.push(cost);
            }
        }

        assert_eq!(dispatched, vec![4], "only the cost that stays under the stop line runs");
        assert_eq!(budget.spend(&scope), 99);

        let blocked = budget.preflight(1, std::slice::from_ref(&scope), 0);
        assert_eq!(blocked.decision, Decision::Stop { scope, remaining: 0 });
    }

    #[test]
    fn overlapping_scopes_stop_beats_warn_regardless_of_order() {
        let global = BudgetScope::Global;
        let alpha = project("alpha");
        let alpha_device = device("dev-a");
        let mut budget = budget_of(vec![
            BudgetLimit::warn_stop(global, 1_000, 10_000),
            BudgetLimit::warn_stop(alpha.clone(), 150, 200),
            BudgetLimit::warn(alpha_device.clone(), 50),
        ]);
        budget.record(alpha.clone(), 190);
        budget.record(alpha_device.clone(), 60);

        for contexts in [
            vec![alpha.clone(), alpha_device.clone()],
            vec![alpha_device.clone(), alpha.clone()],
        ] {
            let result = budget.preflight(20, &contexts, 0);
            assert_eq!(
                result.decision,
                Decision::Stop { scope: alpha.clone(), remaining: 0 },
                "project stop wins over the device warn"
            );
        }

        // Two warns: the scope with less headroom to its stop line is chosen,
        // and the scope order breaks a tie.
        let left = project("left");
        let right = project("right");
        let mut warns = budget_of(vec![
            BudgetLimit::warn_stop(left.clone(), 10, 100),
            BudgetLimit::warn_stop(right.clone(), 10, 500),
        ]);
        warns.record(left.clone(), 40);
        warns.record(right.clone(), 20);
        let result = warns.preflight(30, &[right, left], 0);
        assert_eq!(result.decision, Decision::Warn { remaining: 30 });
    }

    #[test]
    fn exact_boundaries_stop_and_warn_inclusively() {
        let scope = project("alpha");
        let mut budget = budget_of(vec![BudgetLimit::warn_stop(scope.clone(), 50, 100)]);

        // Spend of 40 plus 10 lands exactly on the warn threshold of 50.
        budget.record(scope.clone(), 40);
        let at_warn = budget.preflight(10, std::slice::from_ref(&scope), 0);
        assert_eq!(at_warn.decision, Decision::Warn { remaining: 50 });
        assert_eq!(at_warn.projected, 50);
        assert!(at_warn.permits_dispatch(), "warn is inclusive but never blocks");

        // A cost that lands exactly on the stop limit stops.
        let mut exact = budget_of(vec![BudgetLimit::stop(scope.clone(), 100)]);
        exact.record(scope.clone(), 90);
        let at_stop = exact.preflight(10, std::slice::from_ref(&scope), 0);
        assert_eq!(at_stop.decision, Decision::Stop { scope: scope.clone(), remaining: 0 });
        assert_eq!(at_stop.projected, 100);
        assert!(!at_stop.permits_dispatch());

        // One micro below stays allowed.
        assert!(exact.preflight(9, std::slice::from_ref(&scope), 0).permits_dispatch());

        // A zero-cost preflight at an already-reached stop line still stops.
        exact.record(scope.clone(), 10);
        let zero = exact.preflight(0, std::slice::from_ref(&scope), 0);
        assert_eq!(zero.decision, Decision::Stop { scope, remaining: 0 });
    }

    #[test]
    fn day_rollover_ignores_yesterday() {
        let today = day_of(DAY_MS + 5_000);
        let yesterday = today - 1;
        assert_eq!(day_of(2 * DAY_MS + 5_000), today + 1);

        let mut budget = budget_of(vec![
            BudgetLimit::stop(BudgetScope::Day(yesterday), 100),
            BudgetLimit::stop(BudgetScope::Day(today), 100),
            BudgetLimit::stop(BudgetScope::Day(today + 1), 100),
        ]);
        budget.record(BudgetScope::Day(yesterday), 100);
        budget.record(BudgetScope::Day(today), 100);

        // Today's spend stops today even though the caller passed no context.
        let stopped = budget.preflight(1, &[], DAY_MS + 5_000);
        assert_eq!(
            stopped.decision,
            Decision::Stop { scope: BudgetScope::Day(today), remaining: 0 }
        );

        // Tomorrow starts clean: yesterday's and today's spend are irrelevant.
        let fresh = budget.preflight(50, &[], 2 * DAY_MS + 5_000);
        assert_eq!(fresh.decision, Decision::Allow);
        assert_eq!(fresh.projected, 50);
        let fresh_boundary = budget.preflight(100, &[], 2 * DAY_MS + 5_000);
        assert_eq!(
            fresh_boundary.decision,
            Decision::Stop { scope: BudgetScope::Day(today + 1), remaining: 0 }
        );

        // A stale Day context is normalized to today, never evaluated.
        let stale = budget.preflight(1, &[BudgetScope::Day(yesterday)], DAY_MS + 5_000);
        assert_eq!(
            stale.decision,
            Decision::Stop { scope: BudgetScope::Day(today), remaining: 0 }
        );

        // day_of floors correctly before the epoch.
        assert_eq!(day_of(-1), -1);
        assert_eq!(day_of(-DAY_MS), -1);
        assert_eq!(day_of(-DAY_MS - 1), -2);
    }

    #[test]
    fn invalid_limits_are_rejected() {
        let scope = project("alpha");
        assert_eq!(
            BudgetLimit { scope: scope.clone(), warn_micros: None, stop_micros: None }
                .validate()
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            BudgetLimit::warn(scope.clone(), 0).validate().unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            BudgetLimit::stop(scope.clone(), 0).validate().unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            BudgetLimit::warn_stop(scope.clone(), 500, 400).validate().unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            BudgetLimit::stop(project("  "), 10).validate().unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            BudgetLimit::stop(device(""), 10).validate().unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let mut duplicate = budget_of(vec![BudgetLimit::stop(scope.clone(), 100)]);
        assert_eq!(
            duplicate.add_limit(BudgetLimit::warn(scope.clone(), 50)).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        // Equal thresholds are legal and the stop wins at the boundary.
        let equal = budget_of(vec![BudgetLimit::warn_stop(scope.clone(), 100, 100)]);
        assert_eq!(equal.limit(&scope).unwrap().state_for(99), BudgetState::Ok);
        assert_eq!(equal.limit(&scope).unwrap().state_for(100), BudgetState::Stop);
    }

    #[test]
    fn dashboard_state_matches_configured_budgets() {
        let now = DAY_MS + 60_000;
        let today = day_of(now);
        let alpha = project("alpha");
        let dev_a = device("dev-a");
        let events = vec![
            event("dev-a", "gpt-5", "openai", now - 1_000, 400, "a1"),
            event("dev-b", "gpt-5", "openai", now - 2_000, 200, "b1"),
            event("dev-a", "local-8b", "local", now - 3_000, 100, "a2"),
        ];

        let mut budget = budget_of(vec![
            BudgetLimit::warn_stop(BudgetScope::Global, 600, 1_000),
            BudgetLimit::stop(alpha.clone(), 100),
            BudgetLimit::warn_stop(dev_a.clone(), 500, 1_000),
            BudgetLimit::stop(device("dev-b"), 200),
            BudgetLimit::warn_stop(BudgetScope::Day(today), 1_000, 2_000),
        ]);
        budget.record(alpha.clone(), 100);

        let dashboard = dashboard(&events, &budget, now);

        assert_eq!(dashboard.generated_at_ms, now);
        assert_eq!(dashboard.totals.cost_micros, 700);
        assert_eq!(dashboard.totals.events, 3);
        assert_eq!(dashboard.recent_events, 3);

        let scopes: Vec<BudgetScope> =
            dashboard.by_scope.iter().map(|view| view.scope.clone()).collect();
        assert_eq!(
            scopes,
            vec![
                BudgetScope::Global,
                alpha.clone(),
                dev_a.clone(),
                device("dev-b"),
                BudgetScope::Day(today),
            ],
            "rows follow BudgetScope order"
        );

        assert_eq!(dashboard.by_scope[0].spent, 700);
        assert_eq!(dashboard.by_scope[0].state, BudgetState::Warn);

        assert_eq!(dashboard.by_scope[1].spent, 100);
        assert_eq!(
            dashboard.by_scope[1].state,
            BudgetState::Stop,
            "recorded project spend counts even though the ledger has no project"
        );

        assert_eq!(dashboard.by_scope[2].spent, 500);
        assert_eq!(dashboard.by_scope[2].state, BudgetState::Warn);

        assert_eq!(dashboard.by_scope[3].spent, 200);
        assert_eq!(dashboard.by_scope[3].state, BudgetState::Stop);

        assert_eq!(dashboard.by_scope[4].spent, 700);
        assert_eq!(dashboard.by_scope[4].state, BudgetState::Ok);

        assert_eq!(dashboard.overall_state(), BudgetState::Stop);

        assert_eq!(
            dashboard.top_models,
            vec![("gpt-5".to_owned(), 600), ("local-8b".to_owned(), 100)]
        );
        assert_eq!(
            dashboard.top_providers,
            vec![("openai".to_owned(), 600), ("local".to_owned(), 100)]
        );

        // The budget's own state logic and the dashboard agree exactly.
        for view in &dashboard.by_scope {
            let limit = budget.limit(&view.scope).unwrap();
            assert_eq!(view.state, limit.state_for(view.spent));
        }
    }

    #[test]
    fn all_surfaces_show_the_same_stop_state_and_numbers() {
        let now = 5_000;
        let events = vec![
            event("dev-a", "gpt-5", "openai", now - 10, 700, "a1"),
            event("dev-b", "gpt-5", "openai", now - 20, 300, "b1"),
        ];
        let budget = budget_of(vec![
            BudgetLimit::warn_stop(BudgetScope::Global, 500, 900),
            BudgetLimit::warn(device("dev-a"), 600),
            BudgetLimit::stop(device("dev-b"), 300),
        ]);
        let dashboard = dashboard(&events, &budget, now);
        assert_eq!(dashboard.overall_state(), BudgetState::Stop);

        let rendered = surfaces(&dashboard);
        assert_eq!(rendered.len(), 3);
        assert_eq!(
            rendered.iter().map(|usage| usage.surface).collect::<Vec<_>>(),
            vec![Surface::Tui, Surface::Desktop, Surface::Android]
        );
        for usage in &rendered {
            assert_eq!(usage.state, BudgetState::Stop, "{} must agree", usage.surface.as_str());
            let text = usage.lines.join("\n");
            assert!(text.contains("state=stop"), "{} has no stop token: {text}", usage.surface.as_str());
            assert!(text.contains("1000"), "{} is missing the total: {text}", usage.surface.as_str());
            assert!(text.contains("state=warn"), "{} is missing the global warn row", usage.surface.as_str());
        }

        // Formatting really differs, so the surfaces are not one copy.
        assert_ne!(rendered[0].lines[0], rendered[1].lines[0]);
        assert_ne!(rendered[1].lines[0], rendered[2].lines[0]);
    }

    #[test]
    fn empty_ledger_and_empty_budget_are_ok() {
        let budget = CostBudget::default();
        let dashboard = dashboard(&[], &budget, 0);
        assert_eq!(dashboard.totals, Totals::default());
        assert!(dashboard.by_scope.is_empty());
        assert!(dashboard.top_models.is_empty());
        assert!(dashboard.top_providers.is_empty());
        assert_eq!(dashboard.recent_events, 0);
        assert_eq!(dashboard.overall_state(), BudgetState::Ok);

        let rendered = surfaces(&dashboard);
        assert_eq!(rendered.len(), 3);
        for usage in &rendered {
            assert_eq!(usage.state, BudgetState::Ok);
            assert!(usage.lines.join("\n").contains("state=ok"));
        }

        let preflight = budget.preflight(0, &[], 0);
        assert_eq!(preflight.decision, Decision::Allow);
        assert!(preflight.projected_by_scope.is_empty());
    }

    #[test]
    fn export_reuses_ledger_formats_and_escapes_names() {
        let one = event("dev-a", "gpt,5", "open\"ai", 1, 100, "n1");
        let two = event("dev-b", "local-8b", "local", 2, 50, "n2");
        let events = [one, two];

        let csv = export_csv(&events);
        assert_eq!(csv, usage_ledger::export_csv(&events), "same bytes as the ledger export");
        assert!(csv.contains("\"gpt,5\""));
        assert!(csv.contains("\"open\"\"ai\""));
        assert!(csv.ends_with('\n'));
        assert_eq!(csv.lines().count(), 3);

        let json = export_json(&events).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 2);
        assert_eq!(parsed[0]["model"], "gpt,5");
        assert_eq!(json, usage_ledger::export_json(&events).unwrap());

        // Stable across calls and independent of input order changes we do
        // not make: the same slice produces the same bytes.
        assert_eq!(export_csv(&events), csv);

        assert_eq!(export_csv(&[]), usage_ledger::export_csv(&[]));
        assert_eq!(export_csv(&[]).lines().count(), 1);
        assert_eq!(export_json(&[]).unwrap(), "[]");
    }

    #[test]
    fn record_event_covers_global_device_project_and_day() {
        let mut budget = CostBudget::default();
        let event = event("dev-a", "gpt-5", "openai", DAY_MS + 10, 250, "n1");
        budget.record_event(&event, Some("alpha"));

        assert_eq!(budget.spend(&BudgetScope::Global), 250);
        assert_eq!(budget.spend(&device("dev-a")), 250);
        assert_eq!(budget.spend(&project("alpha")), 250);
        assert_eq!(budget.spend(&BudgetScope::Day(1)), 250);
        assert_eq!(budget.spend(&device("dev-b")), 0);

        budget.record(BudgetScope::Global, u64::MAX);
        assert_eq!(budget.spend(&BudgetScope::Global), u64::MAX, "spend saturates");

        let mut bounded = budget_of(vec![BudgetLimit::stop(BudgetScope::Global, 1_000_000)]);
        bounded.record(BudgetScope::Global, u64::MAX);
        let saturated = bounded.preflight(10, &[], DAY_MS + 10);
        assert_eq!(saturated.projected, u64::MAX, "projection saturates too");
        assert!(saturated.is_stop());
    }
}
