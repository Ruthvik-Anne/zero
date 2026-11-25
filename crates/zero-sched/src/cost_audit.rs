//! Cost audit, bounded proposals, and the apply gate (USG-05, SI-10).
//!
//! [`audit`] turns a slice of [`UsageEvent`]s into a [`CostAudit`]: spend over a
//! closed window by model, provider, and session, retry and cache statistics,
//! the top spenders, evidence-backed findings, and at most a configured number
//! of bounded [`Proposal`]s. Every number is derived from the events in the
//! window; nothing is invented.
//!
//! The apply gate is deliberately strict and matches the task's Done
//! criterion: **`--apply` is required to change anything.** [`apply`] with
//! [`AuditMode::DryRun`] (the default) returns the proposals and a preview of
//! changes and mutates nothing. [`AuditMode::Apply`] mutates an [`AuditState`]
//! only through the bounded, reversible [`CostChange`] variants. A high-risk
//! proposal is skipped unless its id is in the explicit confirmation set, and
//! at most [`MAX_APPLIED_CHANGES`] changes are applied in one run. Proposals
//! that need a non-configuration action (splitting a session) are listed as
//! manual instead of being applied. [`rollback`] reverses every applied change
//! from the returned [`ApplyReport`] when the state still matches what was
//! applied.
//!
//! The module performs no filesystem writes and emits no telemetry. The caller
//! reads the ledger, calls [`audit`], and persists the [`AuditState`] it chose
//! to change.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::cost_budget::TOP_N;
use crate::usage_ledger::{Totals, UsageEvent};

/// Default number of proposals an audit returns.
pub const MAX_PROPOSALS_DEFAULT: usize = 5;

/// Hard ceiling on [`AuditOptions::max_proposals`].
pub const MAX_PROPOSALS_HARD: usize = 32;

/// Hard ceiling on [`AuditOptions::max_evidence_lines`].
pub const MAX_EVIDENCE_LINES_HARD: usize = 32;

/// How many event ids one evidence line may cite.
pub const MAX_EVIDENCE_IDS: usize = 3;

/// Upper bound on changes one [`apply`] call may make.
pub const MAX_APPLIED_CHANGES: usize = 8;

/// The closed interval an audit analyses, in Unix milliseconds.
///
/// `from_ms` and `to_ms` are inclusive. [`AuditWindow::new`] refuses an
/// inverted window so a caller cannot silently audit nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditWindow {
    pub from_ms: i64,
    pub to_ms: i64,
}

impl AuditWindow {
    /// Build a window, refusing `from_ms > to_ms`.
    pub fn new(from_ms: i64, to_ms: i64) -> Result<Self> {
        let window = Self { from_ms, to_ms };
        window.validate()?;
        Ok(window)
    }

    /// A window that contains every representable timestamp.
    pub const fn unbounded() -> Self {
        Self { from_ms: i64::MIN, to_ms: i64::MAX }
    }

    /// Refuse an inverted window.
    pub fn validate(&self) -> Result<()> {
        if self.from_ms > self.to_ms {
            return Err(invalid(format!(
                "audit window is inverted: from_ms {} is after to_ms {}",
                self.from_ms, self.to_ms
            )));
        }
        Ok(())
    }

    /// True when `at_ms` lies inside the closed window.
    pub const fn contains(&self, at_ms: i64) -> bool {
        self.from_ms <= at_ms && at_ms <= self.to_ms
    }
}

/// Thresholds and bounds for one audit.
///
/// Defaults are deliberately conservative: a 10% retry rate, a 20% cache-read
/// share, a 25% expensive-model spend share, a model at least twice the window
/// mean wall time, and 80% provider concentration. Thresholds are in basis
/// points (`10 000` is 100%). A session stop budget is never invented: set
/// [`Self::session_stop_micros`] to make the over-budget finding and proposal
/// possible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditOptions {
    /// Closed interval to analyse.
    pub window: AuditWindow,
    /// Class the audit's switch-model action applies to.
    pub work_class: String,
    /// Per-session stop budget in micros. `None` disables the over-budget
    /// finding and proposal.
    pub session_stop_micros: Option<u64>,
    /// Retry rate (retries per event, in basis points) at or above which a
    /// high-retry finding is emitted.
    pub high_retry_rate_bps: u32,
    /// Cache-read share of prompt tokens, in basis points, below which a
    /// low-cache finding is emitted.
    pub low_cache_ratio_bps: u32,
    /// A model's share of window spend, in basis points, at or above which it
    /// counts as expensive.
    pub expensive_share_bps: u32,
    /// A model is slow when its mean wall time is at least this multiple of
    /// the window mean.
    pub slow_factor: u32,
    /// Top-provider share, in basis points, at or above which a concentration
    /// finding is emitted (only when at least two providers are present).
    pub provider_concentration_bps: u32,
    /// Retry cap proposed by [`ProposalKind::ReduceRetries`].
    pub target_retry_cap: u32,
    /// Maximum proposals returned. Bounded by [`MAX_PROPOSALS_HARD`].
    pub max_proposals: usize,
    /// Maximum evidence lines per finding or proposal. Bounded by
    /// [`MAX_EVIDENCE_LINES_HARD`].
    pub max_evidence_lines: usize,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            window: AuditWindow::unbounded(),
            work_class: "default".to_owned(),
            session_stop_micros: None,
            high_retry_rate_bps: 1_000,
            low_cache_ratio_bps: 2_000,
            expensive_share_bps: 2_500,
            slow_factor: 2,
            provider_concentration_bps: 8_000,
            target_retry_cap: 2,
            max_proposals: MAX_PROPOSALS_DEFAULT,
            max_evidence_lines: 4,
        }
    }
}

impl AuditOptions {
    /// Default options over `window`.
    pub fn new(window: AuditWindow) -> Self {
        Self { window, ..Self::default() }
    }

    /// Validate every threshold and bound before analysis starts.
    pub fn validate(&self) -> Result<()> {
        self.window.validate()?;
        if self.work_class.trim().is_empty() {
            return Err(invalid("audit work_class must not be empty"));
        }
        if self.session_stop_micros == Some(0) {
            return Err(invalid("audit session_stop_micros must be nonzero when set"));
        }
        if self.high_retry_rate_bps == 0 {
            return Err(invalid("audit high_retry_rate_bps must be nonzero"));
        }
        for (name, value) in [
            ("low_cache_ratio_bps", self.low_cache_ratio_bps),
            ("expensive_share_bps", self.expensive_share_bps),
            ("provider_concentration_bps", self.provider_concentration_bps),
        ] {
            if value > 10_000 {
                return Err(invalid(format!("audit {name} must be at most 10 000, got {value}")));
            }
        }
        if self.slow_factor == 0 {
            return Err(invalid("audit slow_factor must be nonzero"));
        }
        if self.target_retry_cap == 0 {
            return Err(invalid("audit target_retry_cap must be nonzero"));
        }
        if self.max_proposals > MAX_PROPOSALS_HARD {
            return Err(invalid(format!(
                "audit max_proposals {} exceeds the hard cap {MAX_PROPOSALS_HARD}",
                self.max_proposals
            )));
        }
        if self.max_evidence_lines > MAX_EVIDENCE_LINES_HARD {
            return Err(invalid(format!(
                "audit max_evidence_lines {} exceeds the hard cap {MAX_EVIDENCE_LINES_HARD}",
                self.max_evidence_lines
            )));
        }
        Ok(())
    }
}

/// Spend and shape for one model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSpend {
    pub model: String,
    pub totals: Totals,
    /// `cache_read * 10 000 / (input + cache_read)` for this model.
    pub cache_ratio_bps: u32,
    pub mean_wall_ms: u64,
    pub mean_cost_micros: u64,
    pub max_retries: u32,
}

/// Spend for one provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSpend {
    pub provider: String,
    pub totals: Totals,
}

/// Spend and shape for one session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSpend {
    pub session: String,
    pub totals: Totals,
    /// `cache_read * 10 000 / (input + cache_read)` for this session.
    pub cache_ratio_bps: u32,
    pub mean_cost_micros: u64,
    pub max_retries: u32,
}

/// Retry shape across the window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryStats {
    /// Retry attempts charged across every event.
    pub total: u64,
    /// Events with at least one retry.
    pub events_with_retries: u64,
    /// Largest retry count on a single event.
    pub max_per_event: u32,
    /// `total * 10 000 / events` (retries per event, in basis points).
    pub rate_bps: u32,
}

/// The five spend signals an audit looks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    HighRetryRate,
    LowCacheReadRatio,
    ExpensiveAndSlowModel,
    SessionOverStopBudget,
    ProviderConcentration,
}

impl FindingKind {
    /// Stable tag used in reports and evidence.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HighRetryRate => "high_retry_rate",
            Self::LowCacheReadRatio => "low_cache_read_ratio",
            Self::ExpensiveAndSlowModel => "expensive_and_slow_model",
            Self::SessionOverStopBudget => "session_over_stop_budget",
            Self::ProviderConcentration => "provider_concentration",
        }
    }
}

/// One insight with the aggregate evidence behind it.
///
/// Evidence lines contain only aggregate numbers, names, and bounded event id
/// samples. Raw event payloads (tool output, prompt text, and so on) are never
/// copied into a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub summary: String,
    pub evidence: Vec<String>,
}

/// The model switch an audit recommends, if a cheaper alternative exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchSuggestion {
    pub from_model: String,
    pub to_model: String,
    pub from_mean_cost_micros: u64,
    pub to_mean_cost_micros: u64,
    pub estimated_savings_micros: u64,
}

/// A complete, deterministic spend analysis.
///
/// Rows are ordered by cost descending, then name ascending. [`Self::totals`]
/// sums every event in the window, including child and subagent events.
/// [`Self::top_spenders`] is the first [`TOP_N`] rows of [`Self::by_session`].
/// The suggestion fields drive [`apply`] and are `None` when the matching
/// proposal did not survive the bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostAudit {
    pub window: AuditWindow,
    /// Work class the audit's configuration actions target.
    pub work_class: String,
    pub totals: Totals,
    pub by_model: Vec<ModelSpend>,
    pub by_provider: Vec<ProviderSpend>,
    pub by_session: Vec<SessionSpend>,
    pub retries: RetryStats,
    pub cache_ratio_bps: u32,
    pub top_spenders: Vec<SessionSpend>,
    pub findings: Vec<Finding>,
    pub proposals: Vec<Proposal>,
    /// Per-session stop budget used for the over-budget signal, when set.
    pub session_stop_micros: Option<u64>,
    /// Session the [`ProposalKind::CapBudget`] action targets.
    pub over_budget_session: Option<String>,
    /// Retry cap the [`ProposalKind::ReduceRetries`] action targets.
    pub retry_cap_target: Option<u32>,
    /// Model switch the [`ProposalKind::SwitchModel`] action marks disallowed.
    pub switch: Option<SwitchSuggestion>,
}

/// Analyse `events` inside `options.window`.
///
/// An empty input produces a valid zero report: every total is zero, every row
/// list is empty, and no findings or proposals are emitted. An inverted window
/// is refused with `zero.fnd.invalid_input`, as is any out-of-range threshold.
pub fn audit(events: &[UsageEvent], options: &AuditOptions) -> Result<CostAudit> {
    options.validate()?;

    let mut totals = Totals::default();
    let mut retry_total = 0_u64;
    let mut retried_events = 0_u64;
    let mut max_retries = 0_u32;
    let mut models: BTreeMap<String, SpendAcc<'_>> = BTreeMap::new();
    let mut providers: BTreeMap<String, SpendAcc<'_>> = BTreeMap::new();
    let mut sessions: BTreeMap<String, SpendAcc<'_>> = BTreeMap::new();

    for event in events {
        if !options.window.contains(event.at_ms) {
            continue;
        }
        totals.add_event(event);
        retry_total = retry_total.saturating_add(u64::from(event.retries));
        if event.retries > 0 {
            retried_events = retried_events.saturating_add(1);
        }
        max_retries = max_retries.max(event.retries);
        models.entry(event.model.clone()).or_default().add(event);
        providers.entry(event.provider.clone()).or_default().add(event);
        sessions.entry(event.session.clone()).or_default().add(event);
    }

    let retries = RetryStats {
        total: retry_total,
        events_with_retries: retried_events,
        max_per_event: max_retries,
        rate_bps: ratio_bps(retry_total, totals.events),
    };
    let cache_ratio_bps = ratio_bps(
        totals.cache_read,
        totals.input.saturating_add(totals.cache_read),
    );

    let mut findings = Vec::new();
    if let Some(finding) = retry_finding(&totals, &retries, &models, options) {
        findings.push(finding);
    }
    if let Some(finding) = cache_finding(&totals, cache_ratio_bps, options) {
        findings.push(finding);
    }
    findings.extend(slow_model_findings(&models, &totals, options));
    findings.extend(session_budget_findings(&sessions, options));
    if let Some(finding) = provider_finding(&providers, &totals, options) {
        findings.push(finding);
    }

    let switch_candidate = switch_pick(&models, &totals, options);
    let over_budget = over_budget_pick(&sessions, options.session_stop_micros);
    let retry_excess = retry_excess(&totals, &retries, options);

    let mut proposals = Vec::new();
    if let Some(proposal) = retry_proposal(&totals, &retries, retry_excess, &models, options) {
        proposals.push(proposal);
    }
    if let Some(proposal) = cache_proposal(&totals, cache_ratio_bps, options) {
        proposals.push(proposal);
    }
    if let Some(pick) = switch_candidate.as_ref() {
        if let Some(proposal) = switch_proposal(pick, options) {
            proposals.push(proposal);
        }
    }
    if let Some((session, acc, overspend, stop)) = over_budget {
        if let Some(proposal) = cap_budget_proposal(session, acc, overspend, stop, options) {
            proposals.push(proposal);
        }
    }
    if let Some(proposal) = split_proposal(&providers, &totals, options) {
        proposals.push(proposal);
    }

    let proposals = finalize_proposals(proposals, options.max_proposals);
    let survives = |kind: ProposalKind| proposals.iter().any(|proposal| proposal.kind == kind);
    let retry_cap_target = survives(ProposalKind::ReduceRetries).then_some(options.target_retry_cap);
    let switch = switch_candidate
        .map(|pick| pick.suggestion)
        .filter(|_| survives(ProposalKind::SwitchModel));
    let over_budget_session = over_budget
        .map(|(session, ..)| session.to_owned())
        .filter(|_| survives(ProposalKind::CapBudget));

    let by_model = model_rows(models);
    let by_provider = provider_rows(providers);
    let by_session = session_rows(sessions);
    let top_spenders: Vec<SessionSpend> =
        by_session.iter().take(TOP_N).cloned().collect();

    Ok(CostAudit {
        window: options.window,
        work_class: options.work_class.clone(),
        totals,
        by_model,
        by_provider,
        by_session,
        retries,
        cache_ratio_bps,
        top_spenders,
        findings,
        proposals,
        session_stop_micros: options.session_stop_micros,
        over_budget_session,
        retry_cap_target,
        switch,
    })
}

/// One aggregated spend bucket plus the samples needed for evidence.
#[derive(Default)]
struct SpendAcc<'a> {
    totals: Totals,
    max_retries: u32,
    samples: Vec<Sample<'a>>,
}

impl<'a> SpendAcc<'a> {
    fn add(&mut self, event: &'a UsageEvent) {
        self.totals.add_event(event);
        self.max_retries = self.max_retries.max(event.retries);
        self.samples.push(Sample {
            id: &event.id,
            at_ms: event.at_ms,
            cost_micros: event.cost_micros,
            retries: event.retries,
        });
    }

    fn cache_ratio_bps(&self) -> u32 {
        ratio_bps(
            self.totals.cache_read,
            self.totals.input.saturating_add(self.totals.cache_read),
        )
    }

    fn mean_wall_ms(&self) -> u64 {
        mean(self.totals.wall_ms, self.totals.events)
    }

    fn mean_cost_micros(&self) -> u64 {
        mean(self.totals.cost_micros, self.totals.events)
    }

    /// Deterministic id sample for one evidence line.
    fn sample_ids(&self, rank: SampleRank, limit: usize) -> Vec<String> {
        let mut samples = self.samples.clone();
        match rank {
            SampleRank::Cost => samples.sort_by(|a, b| {
                b.cost_micros
                    .cmp(&a.cost_micros)
                    .then(a.at_ms.cmp(&b.at_ms))
                    .then(a.id.cmp(b.id))
            }),
            SampleRank::Retries => samples.sort_by(|a, b| {
                b.retries
                    .cmp(&a.retries)
                    .then(a.at_ms.cmp(&b.at_ms))
                    .then(a.id.cmp(b.id))
            }),
        }
        samples.truncate(limit);
        samples.into_iter().map(|sample| sample.id.to_owned()).collect()
    }
}

#[derive(Debug, Clone, Copy)]
struct Sample<'a> {
    id: &'a str,
    at_ms: i64,
    cost_micros: u64,
    retries: u32,
}

#[derive(Debug, Clone, Copy)]
enum SampleRank {
    Cost,
    Retries,
}

fn model_rows(models: BTreeMap<String, SpendAcc<'_>>) -> Vec<ModelSpend> {
    let mut rows: Vec<ModelSpend> = models
        .into_iter()
        .map(|(model, acc)| ModelSpend {
            model,
            totals: acc.totals,
            cache_ratio_bps: acc.cache_ratio_bps(),
            mean_wall_ms: acc.mean_wall_ms(),
            mean_cost_micros: acc.mean_cost_micros(),
            max_retries: acc.max_retries,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.totals.cost_micros
            .cmp(&a.totals.cost_micros)
            .then(a.model.cmp(&b.model))
    });
    rows
}

fn provider_rows(providers: BTreeMap<String, SpendAcc<'_>>) -> Vec<ProviderSpend> {
    let mut rows: Vec<ProviderSpend> = providers
        .into_iter()
        .map(|(provider, acc)| ProviderSpend { provider, totals: acc.totals })
        .collect();
    rows.sort_by(|a, b| {
        b.totals.cost_micros
            .cmp(&a.totals.cost_micros)
            .then(a.provider.cmp(&b.provider))
    });
    rows
}

fn session_rows(sessions: BTreeMap<String, SpendAcc<'_>>) -> Vec<SessionSpend> {
    let mut rows: Vec<SessionSpend> = sessions
        .into_iter()
        .map(|(session, acc)| SessionSpend {
            session,
            totals: acc.totals,
            cache_ratio_bps: acc.cache_ratio_bps(),
            mean_cost_micros: acc.mean_cost_micros(),
            max_retries: acc.max_retries,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.totals.cost_micros
            .cmp(&a.totals.cost_micros)
            .then(a.session.cmp(&b.session))
    });
    rows
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

fn retry_finding(
    totals: &Totals,
    retries: &RetryStats,
    models: &BTreeMap<String, SpendAcc<'_>>,
    options: &AuditOptions,
) -> Option<Finding> {
    if totals.events == 0 || retries.rate_bps < options.high_retry_rate_bps {
        return None;
    }
    let mut evidence = vec![
        format!(
            "retries={} over events={} (rate={}bps, threshold={}bps)",
            retries.total, totals.events, retries.rate_bps, options.high_retry_rate_bps
        ),
        format!(
            "events with retries={} max_retries_on_one_event={}",
            retries.events_with_retries, retries.max_per_event
        ),
    ];
    if let Some((model, acc)) = worst_retry_model(models) {
        evidence.push(format!(
            "worst model={model} retries={} events={}",
            acc.totals.retries, acc.totals.events
        ));
        let ids = acc.sample_ids(SampleRank::Retries, MAX_EVIDENCE_IDS);
        if !ids.is_empty() {
            evidence.push(format!("event ids: {}", ids.join(", ")));
        }
    }
    Some(Finding {
        kind: FindingKind::HighRetryRate,
        summary: format!(
            "retries are {}bp of events ({} attempts across {} events)",
            retries.rate_bps, retries.total, totals.events
        ),
        evidence: bounded(evidence, options.max_evidence_lines),
    })
}

fn cache_finding(
    totals: &Totals,
    cache_ratio_bps: u32,
    options: &AuditOptions,
) -> Option<Finding> {
    let prompt_tokens = totals.input.saturating_add(totals.cache_read);
    if prompt_tokens == 0 || cache_ratio_bps >= options.low_cache_ratio_bps {
        return None;
    }
    Some(Finding {
        kind: FindingKind::LowCacheReadRatio,
        summary: format!(
            "only {cache_ratio_bps}bp of prompt tokens were cache reads (target {}bp)",
            options.low_cache_ratio_bps
        ),
        evidence: bounded(
            vec![
                format!(
                    "cache_read={} input={} cache_ratio={}bps target={}bps",
                    totals.cache_read, totals.input, cache_ratio_bps, options.low_cache_ratio_bps
                ),
                format!(
                    "cache_write={} events={}",
                    totals.cache_write, totals.events
                ),
            ],
            options.max_evidence_lines,
        ),
    })
}

fn slow_model_findings(
    models: &BTreeMap<String, SpendAcc<'_>>,
    totals: &Totals,
    options: &AuditOptions,
) -> Vec<Finding> {
    let window_mean = mean(totals.wall_ms, totals.events);
    if window_mean == 0 || totals.cost_micros == 0 {
        return Vec::new();
    }
    let slow_line = u64::from(options.slow_factor).saturating_mul(window_mean);
    let mut findings = Vec::new();
    for (model, acc) in models {
        if acc.totals.events == 0 || acc.totals.cost_micros == 0 {
            continue;
        }
        let share = ratio_bps(acc.totals.cost_micros, totals.cost_micros);
        let model_mean = acc.mean_wall_ms();
        if share < options.expensive_share_bps || model_mean == 0 || model_mean < slow_line {
            continue;
        }
        let mut evidence = vec![
            format!(
                "model={model} cost={}µ$ share={share}bps events={}",
                acc.totals.cost_micros, acc.totals.events
            ),
            format!(
                "mean_wall_ms={model_mean} window_mean_wall_ms={window_mean} slow_factor={}",
                options.slow_factor
            ),
        ];
        let ids = acc.sample_ids(SampleRank::Cost, MAX_EVIDENCE_IDS);
        if !ids.is_empty() {
            evidence.push(format!("event ids: {}", ids.join(", ")));
        }
        findings.push(Finding {
            kind: FindingKind::ExpensiveAndSlowModel,
            summary: format!("model `{model}` is both expensive and slow"),
            evidence: bounded(evidence, options.max_evidence_lines),
        });
    }
    findings
}

fn session_budget_findings(
    sessions: &BTreeMap<String, SpendAcc<'_>>,
    options: &AuditOptions,
) -> Vec<Finding> {
    let Some(stop) = options.session_stop_micros else {
        return Vec::new();
    };
    let mut rows: Vec<(&str, &SpendAcc<'_>)> = sessions
        .iter()
        .filter(|(_, acc)| acc.totals.cost_micros > stop)
        .map(|(session, acc)| (session.as_str(), acc))
        .collect();
    rows.sort_by(|a, b| {
        let a_over = a.1.totals.cost_micros - stop;
        let b_over = b.1.totals.cost_micros - stop;
        b_over.cmp(&a_over).then(a.0.cmp(b.0))
    });
    rows.into_iter()
        .map(|(session, acc)| {
            let overspend = acc.totals.cost_micros - stop;
            let mut evidence = vec![format!(
                "session={session} spend={}µ$ stop={stop}µ$ overspend={overspend}µ$ events={}",
                acc.totals.cost_micros, acc.totals.events
            )];
            let ids = acc.sample_ids(SampleRank::Cost, MAX_EVIDENCE_IDS);
            if !ids.is_empty() {
                evidence.push(format!("event ids: {}", ids.join(", ")));
            }
            Finding {
                kind: FindingKind::SessionOverStopBudget,
                summary: format!("session `{session}` is {overspend}µ$ over its stop budget"),
                evidence: bounded(evidence, options.max_evidence_lines),
            }
        })
        .collect()
}

fn provider_finding(
    providers: &BTreeMap<String, SpendAcc<'_>>,
    totals: &Totals,
    options: &AuditOptions,
) -> Option<Finding> {
    if providers.len() < 2 || totals.cost_micros == 0 {
        return None;
    }
    let rows = provider_rank(providers);
    let (top, top_cost) = rows[0];
    let share = ratio_bps(top_cost, totals.cost_micros);
    if share < options.provider_concentration_bps {
        return None;
    }
    Some(Finding {
        kind: FindingKind::ProviderConcentration,
        summary: format!("provider `{top}` carries {share}bp of window spend"),
        evidence: bounded(
            vec![
                format!(
                    "provider={top} cost={top_cost}µ$ share={share}bps of {} providers",
                    providers.len()
                ),
                format!(
                    "second provider={} cost={}µ$ share={}bps",
                    rows[1].0,
                    rows[1].1,
                    ratio_bps(rows[1].1, totals.cost_micros)
                ),
            ],
            options.max_evidence_lines,
        ),
    })
}

// ---------------------------------------------------------------------------
// Proposals
// ---------------------------------------------------------------------------

/// The five bounded change families an audit can propose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    /// Route expensive, slow work to a cheaper model.
    SwitchModel,
    /// Install or tighten a session stop budget.
    CapBudget,
    /// Lower the scheduler retry cap.
    ReduceRetries,
    /// Enable prompt caching.
    EnableCache,
    /// Split provider-concentrated work. Manual only.
    SplitSession,
}

impl ProposalKind {
    /// Stable tag used in ids and reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SwitchModel => "switch_model",
            Self::CapBudget => "cap_budget",
            Self::ReduceRetries => "reduce_retries",
            Self::EnableCache => "enable_cache",
            Self::SplitSession => "split_session",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::SwitchModel => 0,
            Self::CapBudget => 1,
            Self::ReduceRetries => 2,
            Self::EnableCache => 3,
            Self::SplitSession => 4,
        }
    }
}

/// How risky a proposal is. A [`Risk::High`] proposal needs an explicit
/// confirmation id before [`apply`] will make it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    /// Stable lowercase tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// One bounded, evidence-backed change suggestion.
///
/// `id` is derived from the kind and the evidence lines, so the same audit
/// produces the same ids. `estimated_savings_micros` is computed only from the
/// aggregates named in `evidence` and is capped at the observed spend; it is
/// `None` when the saving cannot be estimated from the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub kind: ProposalKind,
    pub title: String,
    pub rationale: String,
    pub evidence: Vec<String>,
    pub estimated_savings_micros: Option<u64>,
    pub risk: Risk,
}

struct SwitchPick {
    suggestion: SwitchSuggestion,
    from_share_bps: u32,
    from_mean_wall_ms: u64,
    window_mean_wall_ms: u64,
    from_events: u64,
}

fn worst_retry_model<'a, 'e>(
    models: &'a BTreeMap<String, SpendAcc<'e>>,
) -> Option<(&'a str, &'a SpendAcc<'e>)> {
    models
        .iter()
        .filter(|(_, acc)| acc.totals.retries > 0)
        .max_by(|a, b| {
            a.1.totals
                .retries
                .cmp(&b.1.totals.retries)
                .then_with(|| b.0.cmp(a.0))
        })
        .map(|(model, acc)| (model.as_str(), acc))
}

fn retry_excess(totals: &Totals, retries: &RetryStats, options: &AuditOptions) -> u64 {
    if totals.events == 0 {
        return 0;
    }
    let target = (u128::from(totals.events) * u128::from(options.high_retry_rate_bps) / 10_000)
        .max(1) as u64;
    retries.total.saturating_sub(target)
}

fn retry_proposal(
    totals: &Totals,
    retries: &RetryStats,
    excess: u64,
    models: &BTreeMap<String, SpendAcc<'_>>,
    options: &AuditOptions,
) -> Option<Proposal> {
    if totals.events == 0 || excess == 0 {
        return None;
    }
    let mean_cost = mean(totals.cost_micros, totals.events);
    let savings = cap_savings(
        u128::from(excess) * u128::from(mean_cost),
        totals.cost_micros,
    );
    if savings == 0 {
        return None;
    }
    let mut evidence = vec![
        format!(
            "retries={} over events={} (rate={}bps, threshold={}bps)",
            retries.total, totals.events, retries.rate_bps, options.high_retry_rate_bps
        ),
        format!(
            "excess_retries={excess} target_retry_cap={} attempts",
            options.target_retry_cap
        ),
        format!(
            "estimate: {excess} excess retries x mean event cost {mean_cost}µ$ = {savings}µ$ \
             (capped at observed {})",
            totals.cost_micros
        ),
    ];
    if let Some((model, acc)) = worst_retry_model(models) {
        evidence.push(format!(
            "worst model={model} retries={} events={}",
            acc.totals.retries, acc.totals.events
        ));
        let ids = acc.sample_ids(SampleRank::Retries, MAX_EVIDENCE_IDS);
        if !ids.is_empty() {
            evidence.push(format!("event ids: {}", ids.join(", ")));
        }
    }
    build_proposal(
        ProposalKind::ReduceRetries,
        "Lower the retry cap",
        format!(
            "Retries are {}bp of events. Lower the scheduler retry cap to {} attempts; the \
             estimate values each excess retry at the mean observed event cost.",
            retries.rate_bps, options.target_retry_cap
        ),
        evidence,
        Some(savings),
        Risk::Medium,
        options.max_evidence_lines,
    )
}

fn cache_proposal(
    totals: &Totals,
    cache_ratio_bps: u32,
    options: &AuditOptions,
) -> Option<Proposal> {
    let prompt_tokens = totals.input.saturating_add(totals.cache_read);
    if prompt_tokens == 0
        || totals.cost_micros == 0
        || cache_ratio_bps >= options.low_cache_ratio_bps
    {
        return None;
    }
    let target = options.low_cache_ratio_bps;
    let savings = cap_savings(
        u128::from(totals.cost_micros) * u128::from(target - cache_ratio_bps) / 10_000,
        totals.cost_micros,
    );
    if savings == 0 {
        return None;
    }
    build_proposal(
        ProposalKind::EnableCache,
        "Enable prompt caching",
        format!(
            "Cache reads are {cache_ratio_bps}bp of prompt tokens against a {target}bp target. \
             Enable caching for this work; the estimate is proportional to observed spend."
        ),
        vec![
            format!(
                "cache_read={} input={} cache_ratio={}bps target={}bps",
                totals.cache_read, totals.input, cache_ratio_bps, target
            ),
            format!(
                "estimate: cost {}µ$ x ({target}-{cache_ratio_bps})bp = {savings}µ$",
                totals.cost_micros
            ),
        ],
        Some(savings),
        Risk::Low,
        options.max_evidence_lines,
    )
}

fn switch_pick(
    models: &BTreeMap<String, SpendAcc<'_>>,
    totals: &Totals,
    options: &AuditOptions,
) -> Option<SwitchPick> {
    let window_mean = mean(totals.wall_ms, totals.events);
    if window_mean == 0 || totals.cost_micros == 0 {
        return None;
    }
    let slow_line = u64::from(options.slow_factor).saturating_mul(window_mean);
    let mut candidate: Option<(&str, &SpendAcc<'_>)> = None;
    for (model, acc) in models {
        if acc.totals.events == 0 || acc.totals.cost_micros == 0 {
            continue;
        }
        let share = ratio_bps(acc.totals.cost_micros, totals.cost_micros);
        if share < options.expensive_share_bps || acc.mean_wall_ms() < slow_line {
            continue;
        }
        let better = match candidate {
            None => true,
            Some((best_model, best_acc)) => {
                acc.totals.cost_micros > best_acc.totals.cost_micros
                    || (acc.totals.cost_micros == best_acc.totals.cost_micros
                        && model.as_str() < best_model)
            }
        };
        if better {
            candidate = Some((model.as_str(), acc));
        }
    }
    let (from_model, from_acc) = candidate?;
    let from_mean = from_acc.mean_cost_micros();
    let mut alternative: Option<(&str, &SpendAcc<'_>)> = None;
    for (model, acc) in models {
        if model.as_str() == from_model || acc.totals.events == 0 {
            continue;
        }
        let mean_cost = acc.mean_cost_micros();
        if mean_cost >= from_mean {
            continue;
        }
        let better = match alternative {
            None => true,
            Some((best_model, best_acc)) => {
                mean_cost < best_acc.mean_cost_micros()
                    || (mean_cost == best_acc.mean_cost_micros()
                        && model.as_str() < best_model)
            }
        };
        if better {
            alternative = Some((model.as_str(), acc));
        }
    }
    let (to_model, to_acc) = alternative?;
    let savings = cap_savings(
        u128::from(from_mean - to_acc.mean_cost_micros()) * u128::from(from_acc.totals.events),
        from_acc.totals.cost_micros.min(totals.cost_micros),
    );
    if savings == 0 {
        return None;
    }
    Some(SwitchPick {
        suggestion: SwitchSuggestion {
            from_model: from_model.to_owned(),
            to_model: to_model.to_owned(),
            from_mean_cost_micros: from_mean,
            to_mean_cost_micros: to_acc.mean_cost_micros(),
            estimated_savings_micros: savings,
        },
        from_share_bps: ratio_bps(from_acc.totals.cost_micros, totals.cost_micros),
        from_mean_wall_ms: from_acc.mean_wall_ms(),
        window_mean_wall_ms: window_mean,
        from_events: from_acc.totals.events,
    })
}

fn switch_proposal(pick: &SwitchPick, options: &AuditOptions) -> Option<Proposal> {
    let switch = &pick.suggestion;
    build_proposal(
        ProposalKind::SwitchModel,
        "Route expensive work to a cheaper model",
        format!(
            "`{}` is expensive and slow. Mark it disallowed for work class `{}` and route to \
             `{}`; the estimate uses observed mean cost per event.",
            switch.from_model, options.work_class, switch.to_model
        ),
        vec![
            format!(
                "model={} cost_share={}bps events={} mean_wall_ms={} window_mean_wall_ms={} \
                 slow_factor={}",
                switch.from_model,
                pick.from_share_bps,
                pick.from_events,
                pick.from_mean_wall_ms,
                pick.window_mean_wall_ms,
                options.slow_factor
            ),
            format!(
                "alternative={} mean_cost={}µ$ vs from mean_cost={}µ$",
                switch.to_model, switch.to_mean_cost_micros, switch.from_mean_cost_micros
            ),
            format!(
                "estimate: {} events x ({}µ$ - {}µ$) = {}µ$",
                pick.from_events,
                switch.from_mean_cost_micros,
                switch.to_mean_cost_micros,
                switch.estimated_savings_micros
            ),
        ],
        Some(switch.estimated_savings_micros),
        Risk::High,
        options.max_evidence_lines,
    )
}

fn over_budget_pick<'a, 'e>(
    sessions: &'a BTreeMap<String, SpendAcc<'e>>,
    stop_micros: Option<u64>,
) -> Option<(&'a str, &'a SpendAcc<'e>, u64, u64)> {
    let stop = stop_micros?;
    let mut rows: Vec<(&str, &SpendAcc<'_>)> = sessions
        .iter()
        .filter(|(_, acc)| acc.totals.cost_micros > stop)
        .map(|(session, acc)| (session.as_str(), acc))
        .collect();
    rows.sort_by(|a, b| {
        let a_over = a.1.totals.cost_micros - stop;
        let b_over = b.1.totals.cost_micros - stop;
        b_over.cmp(&a_over).then(a.0.cmp(b.0))
    });
    let (session, acc) = rows.first().copied()?;
    Some((session, acc, acc.totals.cost_micros - stop, stop))
}

fn cap_budget_proposal(
    session: &str,
    acc: &SpendAcc<'_>,
    overspend: u64,
    stop: u64,
    options: &AuditOptions,
) -> Option<Proposal> {
    if overspend == 0 {
        return None;
    }
    let mut evidence = vec![
        format!(
            "session={session} spend={}µ$ stop={stop}µ$ overspend={overspend}µ$ events={}",
            acc.totals.cost_micros, acc.totals.events
        ),
        format!("estimate: overspend = spend - stop = {overspend}µ$"),
    ];
    let ids = acc.sample_ids(SampleRank::Cost, MAX_EVIDENCE_IDS);
    if !ids.is_empty() {
        evidence.push(format!("event ids: {}", ids.join(", ")));
    }
    build_proposal(
        ProposalKind::CapBudget,
        "Cap the over-budget session",
        format!(
            "Session `{session}` spent {}µ$ against a {stop}µ$ stop budget. Install or tighten \
             the stop budget so the next window starts bounded.",
            acc.totals.cost_micros
        ),
        evidence,
        Some(overspend),
        Risk::Low,
        options.max_evidence_lines,
    )
}

fn provider_rank<'a, 'e>(
    providers: &'a BTreeMap<String, SpendAcc<'e>>,
) -> Vec<(&'a str, u64)> {
    let mut rows: Vec<(&str, u64)> = providers
        .iter()
        .map(|(provider, acc)| (provider.as_str(), acc.totals.cost_micros))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    rows
}

fn split_proposal(
    providers: &BTreeMap<String, SpendAcc<'_>>,
    totals: &Totals,
    options: &AuditOptions,
) -> Option<Proposal> {
    if providers.len() < 2 || totals.cost_micros == 0 {
        return None;
    }
    let rows = provider_rank(providers);
    let (top, top_cost) = rows[0];
    let share = ratio_bps(top_cost, totals.cost_micros);
    if share < options.provider_concentration_bps {
        return None;
    }
    build_proposal(
        ProposalKind::SplitSession,
        "Split provider-concentrated work",
        format!(
            "Provider `{top}` carries {share}bp of window spend. Split this work across the \
             remaining provider so one outage or price change cannot dominate the window. This \
             needs a session operation, so the audit lists it as manual."
        ),
        vec![
            format!(
                "provider={top} cost={top_cost}µ$ share={share}bps of {} providers",
                providers.len()
            ),
            format!(
                "second provider={} cost={}µ$ share={}bps",
                rows[1].0,
                rows[1].1,
                ratio_bps(rows[1].1, totals.cost_micros)
            ),
            "estimate: none; splitting changes routing and needs a session operation".to_owned(),
        ],
        None,
        Risk::High,
        options.max_evidence_lines,
    )
}

fn build_proposal(
    kind: ProposalKind,
    title: &str,
    rationale: String,
    mut evidence: Vec<String>,
    estimated_savings_micros: Option<u64>,
    risk: Risk,
    max_evidence_lines: usize,
) -> Option<Proposal> {
    evidence.truncate(max_evidence_lines);
    if evidence.is_empty() {
        return None;
    }
    Some(Proposal {
        id: proposal_id(kind, &evidence),
        kind,
        title: title.to_owned(),
        rationale,
        evidence,
        estimated_savings_micros,
        risk,
    })
}

fn proposal_id(kind: ProposalKind, evidence: &[String]) -> String {
    let tag = kind.as_str();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(tag.len() as u64).to_le_bytes());
    hasher.update(tag.as_bytes());
    for line in evidence {
        hasher.update(&(line.len() as u64).to_le_bytes());
        hasher.update(line.as_bytes());
    }
    format!("ca_{}", hasher.finalize().to_hex())
}

fn finalize_proposals(mut proposals: Vec<Proposal>, max_proposals: usize) -> Vec<Proposal> {
    proposals.sort_by(|a, b| {
        b.estimated_savings_micros
            .unwrap_or(0)
            .cmp(&a.estimated_savings_micros.unwrap_or(0))
            .then(a.kind.rank().cmp(&b.kind.rank()))
            .then(a.id.cmp(&b.id))
    });
    let mut seen = BTreeSet::new();
    proposals.retain(|proposal| seen.insert(proposal.id.clone()));
    proposals.truncate(max_proposals);
    proposals
}

// ---------------------------------------------------------------------------
// Apply gate
// ---------------------------------------------------------------------------

/// Whether an audit run may change configuration.
///
/// [`AuditMode::DryRun`] is the default, so an omitted flag never mutates
/// anything. Only [`AuditMode::Apply`] reaches the [`AuditState`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    #[default]
    DryRun,
    Apply,
}

impl AuditMode {
    /// Stable tag used in reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DryRun => "dry_run",
            Self::Apply => "apply",
        }
    }
}

/// The reversible configuration state an audit may change.
///
/// This is caller-owned data, not a file. The module never persists it; the
/// caller writes it through its normal settings path after inspecting an
/// [`ApplyReport`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditState {
    /// Scheduler retry cap in attempts. `None` means the scheduler default.
    pub retry_cap: Option<u32>,
    /// Whether prompt caching is enabled.
    pub cache_enabled: bool,
    /// `(work_class, model)` pairs that must not be routed.
    pub disallowed_models: BTreeSet<(String, String)>,
    /// Per-session stop budgets in micros.
    pub session_budgets: BTreeMap<String, u64>,
}

impl AuditState {
    /// Whether `model` is disallowed for `work_class`.
    pub fn model_disallowed(&self, work_class: &str, model: &str) -> bool {
        self.disallowed_models
            .contains(&(work_class.to_owned(), model.to_owned()))
    }

    /// The stop budget recorded for `session`, if any.
    pub fn session_budget(&self, session: &str) -> Option<u64> {
        self.session_budgets.get(session).copied()
    }
}

/// One bounded, reversible configuration change.
///
/// Every variant carries the value before and after the change, so an
/// [`ApplyReport`] is self-describing and [`rollback`] can reverse it without
/// re-deriving anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum CostChange {
    SetRetryCap {
        before: Option<u32>,
        after: Option<u32>,
    },
    SetCacheEnabled {
        before: bool,
        after: bool,
    },
    SetModelDisallowed {
        work_class: String,
        model: String,
        before: bool,
        after: bool,
    },
    SetSessionBudget {
        session: String,
        before: Option<u64>,
        after: Option<u64>,
    },
}

impl CostChange {
    /// True when the change writes the value that is already present.
    pub fn is_noop(&self) -> bool {
        match self {
            Self::SetRetryCap { before, after } => before == after,
            Self::SetCacheEnabled { before, after } => before == after,
            Self::SetModelDisallowed { before, after, .. } => before == after,
            Self::SetSessionBudget { before, after, .. } => before == after,
        }
    }

    /// True when `state` already holds this change's `after` value.
    pub fn is_satisfied_by(&self, state: &AuditState) -> bool {
        match self {
            Self::SetRetryCap { after, .. } => state.retry_cap == *after,
            Self::SetCacheEnabled { after, .. } => state.cache_enabled == *after,
            Self::SetModelDisallowed { work_class, model, after, .. } => {
                state.model_disallowed(work_class, model) == *after
            }
            Self::SetSessionBudget { session, after, .. } => {
                state.session_budget(session) == *after
            }
        }
    }

    /// One human-readable line with before and after.
    pub fn summary(&self) -> String {
        match self {
            Self::SetRetryCap { before, after } => format!(
                "retry cap {} -> {}",
                optional_number(*before),
                optional_number(*after)
            ),
            Self::SetCacheEnabled { before, after } => {
                format!("cache enabled {before} -> {after}")
            }
            Self::SetModelDisallowed { work_class, model, before, after } => format!(
                "model `{model}` disallowed for `{work_class}`: {before} -> {after}"
            ),
            Self::SetSessionBudget { session, before, after } => format!(
                "session `{session}` stop budget {} -> {} µ$",
                optional_micros(*before),
                optional_micros(*after)
            ),
        }
    }

    fn apply_to(&self, state: &mut AuditState) {
        match self {
            Self::SetRetryCap { after, .. } => state.retry_cap = *after,
            Self::SetCacheEnabled { after, .. } => state.cache_enabled = *after,
            Self::SetModelDisallowed { work_class, model, after, .. } => {
                let key = (work_class.clone(), model.clone());
                if *after {
                    state.disallowed_models.insert(key);
                } else {
                    state.disallowed_models.remove(&key);
                }
            }
            Self::SetSessionBudget { session, after, .. } => match after {
                Some(value) => {
                    state.session_budgets.insert(session.clone(), *value);
                }
                None => {
                    state.session_budgets.remove(session);
                }
            },
        }
    }

    fn revert(&self, state: &mut AuditState) {
        match self {
            Self::SetRetryCap { before, .. } => state.retry_cap = *before,
            Self::SetCacheEnabled { before, .. } => state.cache_enabled = *before,
            Self::SetModelDisallowed { work_class, model, before, .. } => {
                let key = (work_class.clone(), model.clone());
                if *before {
                    state.disallowed_models.insert(key);
                } else {
                    state.disallowed_models.remove(&key);
                }
            }
            Self::SetSessionBudget { session, before, .. } => match before {
                Some(value) => {
                    state.session_budgets.insert(session.clone(), *value);
                }
                None => {
                    state.session_budgets.remove(session);
                }
            },
        }
    }
}

/// One change that [`apply`] would make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewChange {
    pub proposal_id: String,
    pub kind: ProposalKind,
    pub change: CostChange,
}

/// One change [`apply`] made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedChange {
    pub proposal_id: String,
    pub kind: ProposalKind,
    pub change: CostChange,
}

/// Why a proposal was not applied in this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// High risk and the proposal id was not in the confirmation set.
    HighRiskUnconfirmed,
    /// The state already held the proposed value.
    AlreadyApplied,
    /// [`MAX_APPLIED_CHANGES`] was reached.
    ChangeLimit,
}

impl SkipReason {
    /// Stable tag used in reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HighRiskUnconfirmed => "high_risk_unconfirmed",
            Self::AlreadyApplied => "already_applied",
            Self::ChangeLimit => "change_limit",
        }
    }
}

/// A proposal that was skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedProposal {
    pub proposal_id: String,
    pub kind: ProposalKind,
    pub reason: SkipReason,
}

/// A proposal that needs an action outside the audit's bounded scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualProposal {
    pub proposal_id: String,
    pub kind: ProposalKind,
    pub title: String,
    pub reason: String,
}

/// The result of [`apply`].
///
/// `proposals` and `preview` are populated for both modes. `applied` is empty
/// for a dry run. Every [`AppliedChange`] carries the before and after values
/// that [`rollback`] consumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyReport {
    pub mode: AuditMode,
    /// True exactly when `mode` is [`AuditMode::DryRun`].
    pub dry_run: bool,
    pub proposals: Vec<Proposal>,
    pub preview: Vec<PreviewChange>,
    pub applied: Vec<AppliedChange>,
    pub skipped: Vec<SkippedProposal>,
    pub manual: Vec<ManualProposal>,
}

impl ApplyReport {
    /// Number of changes actually made.
    pub fn applied_count(&self) -> usize {
        self.applied.len()
    }
}

enum ChangeOutcome {
    Change(CostChange),
    Manual(String),
}

/// Apply `report` in `mode` to `state`, with no confirmations.
///
/// This is [`apply_with_confirmations`] with an empty confirmation set, so any
/// high-risk proposal is skipped. Dry run is the default mode and changes
/// nothing.
pub fn apply(report: &CostAudit, mode: AuditMode, state: &mut AuditState) -> ApplyReport {
    apply_with_confirmations(report, mode, state, &BTreeSet::new())
}

/// Apply `report` in `mode` to `state`, honouring `confirmations`.
///
/// In [`AuditMode::DryRun`] the report contains every proposal and a preview
/// of the applicable changes, and `state` is untouched. In
/// [`AuditMode::Apply`] only [`CostChange`] actions are made, high-risk
/// proposals require their id in `confirmations`, and `MAX_APPLIED_CHANGES`
/// bounds the run. Out-of-scope proposals (splitting a session) are listed in
/// `manual`.
pub fn apply_with_confirmations(
    report: &CostAudit,
    mode: AuditMode,
    state: &mut AuditState,
    confirmations: &BTreeSet<String>,
) -> ApplyReport {
    let mut preview = Vec::new();
    let mut applied = Vec::new();
    let mut skipped = Vec::new();
    let mut manual = Vec::new();

    for proposal in &report.proposals {
        if mode == AuditMode::Apply
            && proposal.risk == Risk::High
            && !confirmations.contains(&proposal.id)
        {
            skipped.push(SkippedProposal {
                proposal_id: proposal.id.clone(),
                kind: proposal.kind,
                reason: SkipReason::HighRiskUnconfirmed,
            });
            continue;
        }

        let change = match change_for(proposal, report, state) {
            ChangeOutcome::Change(change) => change,
            ChangeOutcome::Manual(reason) => {
                manual.push(ManualProposal {
                    proposal_id: proposal.id.clone(),
                    kind: proposal.kind,
                    title: proposal.title.clone(),
                    reason,
                });
                continue;
            }
        };

        if change.is_noop() {
            skipped.push(SkippedProposal {
                proposal_id: proposal.id.clone(),
                kind: proposal.kind,
                reason: SkipReason::AlreadyApplied,
            });
            continue;
        }
        if preview.len() >= MAX_APPLIED_CHANGES {
            skipped.push(SkippedProposal {
                proposal_id: proposal.id.clone(),
                kind: proposal.kind,
                reason: SkipReason::ChangeLimit,
            });
            continue;
        }

        preview.push(PreviewChange {
            proposal_id: proposal.id.clone(),
            kind: proposal.kind,
            change: change.clone(),
        });
        if mode == AuditMode::Apply {
            change.apply_to(state);
            applied.push(AppliedChange {
                proposal_id: proposal.id.clone(),
                kind: proposal.kind,
                change,
            });
        }
    }

    ApplyReport {
        mode,
        dry_run: mode == AuditMode::DryRun,
        proposals: report.proposals.clone(),
        preview,
        applied,
        skipped,
        manual,
    }
}

fn change_for(proposal: &Proposal, report: &CostAudit, state: &AuditState) -> ChangeOutcome {
    match proposal.kind {
        ProposalKind::ReduceRetries => {
            let Some(target) = report.retry_cap_target else {
                return ChangeOutcome::Manual("the audit carries no retry cap target".to_owned());
            };
            let before = state.retry_cap;
            let after = Some(before.map_or(target, |cap| cap.min(target)));
            ChangeOutcome::Change(CostChange::SetRetryCap { before, after })
        }
        ProposalKind::EnableCache => ChangeOutcome::Change(CostChange::SetCacheEnabled {
            before: state.cache_enabled,
            after: true,
        }),
        ProposalKind::SwitchModel => {
            let Some(switch) = &report.switch else {
                return ChangeOutcome::Manual("the audit carries no switch suggestion".to_owned());
            };
            ChangeOutcome::Change(CostChange::SetModelDisallowed {
                work_class: report.work_class.clone(),
                model: switch.from_model.clone(),
                before: state.model_disallowed(&report.work_class, &switch.from_model),
                after: true,
            })
        }
        ProposalKind::CapBudget => {
            let (Some(session), Some(stop)) = (
                report.over_budget_session.as_ref(),
                report.session_stop_micros,
            ) else {
                return ChangeOutcome::Manual(
                    "the audit carries no session stop budget".to_owned(),
                );
            };
            let before = state.session_budget(session);
            let after = Some(before.map_or(stop, |budget| budget.min(stop)));
            ChangeOutcome::Change(CostChange::SetSessionBudget {
                session: session.clone(),
                before,
                after,
            })
        }
        ProposalKind::SplitSession => ChangeOutcome::Manual(
            "splitting a session is a session operation, not an audit configuration change"
                .to_owned(),
        ),
    }
}

/// Reverse every change in `report`.
///
/// The report must come from an [`AuditMode::Apply`] run, and every change's
/// `after` value must still hold in `state`; otherwise nothing is reverted and
/// `zero.fnd.invalid_input` is returned. Changes are reverted in reverse order.
pub fn rollback(report: &ApplyReport, state: &mut AuditState) -> Result<()> {
    if report.mode != AuditMode::Apply || report.dry_run {
        return Err(invalid("rollback needs the report from an apply run, not a dry run"));
    }
    if report.applied.is_empty() {
        return Err(invalid("apply report has no changes to roll back"));
    }
    for applied in &report.applied {
        if !applied.change.is_satisfied_by(state) {
            return Err(invalid(format!(
                "state changed since apply; refusing to roll back proposal `{}`",
                applied.proposal_id
            )));
        }
    }
    for applied in report.applied.iter().rev() {
        applied.change.revert(state);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

/// `part * 10 000 / whole`; zero when `whole` is zero.
fn ratio_bps(part: u64, whole: u64) -> u32 {
    if whole == 0 {
        return 0;
    }
    let scaled = u128::from(part) * 10_000 / u128::from(whole);
    scaled.min(u128::from(u32::MAX)) as u32
}

fn mean(total: u64, count: u64) -> u64 {
    total.checked_div(count).unwrap_or(0)
}

fn cap_savings(raw: u128, cap: u64) -> u64 {
    raw.min(u128::from(cap)) as u64
}

fn bounded(mut lines: Vec<String>, max_lines: usize) -> Vec<String> {
    lines.truncate(max_lines);
    lines
}

fn optional_number(value: Option<u32>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn optional_micros(value: Option<u64>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> AuditOptions {
        AuditOptions {
            window: AuditWindow::new(0, 10_000).unwrap(),
            session_stop_micros: Some(1_000),
            ..AuditOptions::default()
        }
    }

    fn slow_event() -> UsageEvent {
        UsageEvent::new("dev-a", "s1", "slow-large", "alpha", 1_000, None, "slow")
            .with_usage(100, 50, 0, 10)
            .with_cost(2_000)
            .with_wall_ms(3_000)
            .with_retries(6)
    }

    fn fast_events() -> Vec<UsageEvent> {
        (0..4)
            .map(|index| {
                UsageEvent::new(
                    "dev-b",
                    "s2",
                    "fast-small",
                    "beta",
                    2_000 + index,
                    None,
                    &format!("fast-{index}"),
                )
                .with_usage(50, 25, 10, 0)
                .with_cost(50)
                .with_wall_ms(100)
            })
            .collect()
    }

    fn fixture() -> Vec<UsageEvent> {
        let mut events = vec![slow_event()];
        events.extend(fast_events());
        events
    }

    fn proposal_of(audit: &CostAudit, kind: ProposalKind) -> &Proposal {
        audit
            .proposals
            .iter()
            .find(|proposal| proposal.kind == kind)
            .unwrap_or_else(|| panic!("missing {kind:?} proposal"))
    }

    fn all_confirmations(audit: &CostAudit) -> BTreeSet<String> {
        audit.proposals.iter().map(|proposal| proposal.id.clone()).collect()
    }

    #[test]
    fn empty_ledger_yields_a_zero_report() {
        let options = options();
        let report = audit(&[], &options).unwrap();

        assert_eq!(report.window, options.window);
        assert_eq!(report.totals, Totals::default());
        assert!(report.by_model.is_empty());
        assert!(report.by_provider.is_empty());
        assert!(report.by_session.is_empty());
        assert_eq!(report.retries, RetryStats::default());
        assert_eq!(report.cache_ratio_bps, 0);
        assert!(report.top_spenders.is_empty());
        assert!(report.findings.is_empty());
        assert!(report.proposals.is_empty());
        assert!(report.switch.is_none());
        assert!(report.retry_cap_target.is_none());
        assert!(report.over_budget_session.is_none());

        let mut state = AuditState::default();
        let dry = apply(&report, AuditMode::DryRun, &mut state);
        assert!(dry.dry_run);
        assert!(dry.applied.is_empty());
        assert!(dry.preview.is_empty());
        assert_eq!(state, AuditState::default());

        let applied = apply(&report, AuditMode::Apply, &mut state);
        assert!(!applied.dry_run);
        assert!(applied.applied.is_empty());
        assert_eq!(state, AuditState::default());
        assert_eq!(
            rollback(&applied, &mut state).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn window_filters_events_and_invalid_bounds_are_refused() {
        assert_eq!(
            AuditWindow::new(10, 9).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        let invalid = AuditOptions {
            window: AuditWindow { from_ms: 10, to_ms: 9 },
            ..AuditOptions::default()
        };
        assert_eq!(
            audit(&[], &invalid).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let narrowed = AuditOptions {
            window: AuditWindow::new(1_500, 10_000).unwrap(),
            ..options()
        };
        let report = audit(&fixture(), &narrowed).unwrap();
        assert_eq!(report.totals.events, 4, "the slow event at 1 000 ms is outside");
        assert!(report.by_model.iter().any(|row| row.model == "fast-small"));
        assert!(!report.by_model.iter().any(|row| row.model == "slow-large"));
        assert_eq!(report.by_model[0].model, "fast-small");
    }

    #[test]
    fn analysis_orders_rows_and_reports_ratios() {
        let report = audit(&fixture(), &options()).unwrap();

        assert_eq!(report.totals.events, 5);
        assert_eq!(report.totals.cost_micros, 2_200);
        assert_eq!(report.totals.retries, 6);
        assert_eq!(report.cache_ratio_bps, 1_176);
        assert_eq!(report.retries.total, 6);
        assert_eq!(report.retries.events_with_retries, 1);
        assert_eq!(report.retries.max_per_event, 6);
        assert_eq!(report.retries.rate_bps, 12_000);

        assert_eq!(report.by_model[0].model, "slow-large");
        assert_eq!(report.by_model[1].model, "fast-small");
        assert_eq!(report.by_model[0].mean_cost_micros, 2_000);
        assert_eq!(report.by_model[1].mean_cost_micros, 50);

        assert_eq!(report.by_provider[0].provider, "alpha");
        assert_eq!(report.by_provider[1].provider, "beta");

        assert_eq!(report.by_session[0].session, "s1");
        assert_eq!(report.by_session[1].session, "s2");
        assert_eq!(report.top_spenders.len(), 2);
        assert_eq!(report.top_spenders[0].session, "s1");
    }

    #[test]
    fn findings_name_all_five_signals_with_evidence() {
        let report = audit(&fixture(), &options()).unwrap();
        let kinds: BTreeSet<FindingKind> =
            report.findings.iter().map(|finding| finding.kind).collect();
        for expected in [
            FindingKind::HighRetryRate,
            FindingKind::LowCacheReadRatio,
            FindingKind::ExpensiveAndSlowModel,
            FindingKind::SessionOverStopBudget,
            FindingKind::ProviderConcentration,
        ] {
            assert!(kinds.contains(&expected), "missing {expected:?} finding");
        }
        for finding in &report.findings {
            assert!(!finding.evidence.is_empty(), "{:?} has no evidence", finding.kind);
        }

        let session = report
            .findings
            .iter()
            .find(|finding| finding.kind == FindingKind::SessionOverStopBudget)
            .unwrap();
        let text = session.evidence.join("\n");
        assert!(text.contains("session=s1"));
        assert!(text.contains("event ids:"));
        assert!(text.contains("ue_"));
        assert!(
            !session.evidence.iter().any(|line| line.contains('{')),
            "evidence must not carry a raw payload: {text}"
        );
    }

    #[test]
    fn proposals_are_bounded_evidence_backed_and_deterministic() {
        let report = audit(&fixture(), &options()).unwrap();

        assert!(report.proposals.len() <= MAX_PROPOSALS_DEFAULT);
        let ids: BTreeSet<&str> =
            report.proposals.iter().map(|proposal| proposal.id.as_str()).collect();
        assert_eq!(ids.len(), report.proposals.len(), "proposal ids are unique");

        for proposal in &report.proposals {
            assert!(!proposal.evidence.is_empty(), "{} has no evidence", proposal.title);
            if let Some(savings) = proposal.estimated_savings_micros {
                assert!(
                    savings <= report.totals.cost_micros,
                    "savings {savings} exceed observed spend"
                );
            }
        }

        // Every estimate is exact arithmetic over the fixture aggregates.
        assert_eq!(
            proposal_of(&report, ProposalKind::ReduceRetries).estimated_savings_micros,
            Some(2_200)
        );
        assert_eq!(
            proposal_of(&report, ProposalKind::SwitchModel).estimated_savings_micros,
            Some(1_950)
        );
        assert_eq!(
            proposal_of(&report, ProposalKind::CapBudget).estimated_savings_micros,
            Some(1_000)
        );
        assert_eq!(
            proposal_of(&report, ProposalKind::EnableCache).estimated_savings_micros,
            Some(181)
        );
        assert_eq!(
            proposal_of(&report, ProposalKind::SplitSession).estimated_savings_micros,
            None
        );

        let switch = report.switch.as_ref().unwrap();
        assert_eq!(switch.from_model, "slow-large");
        assert_eq!(switch.to_model, "fast-small");
        assert_eq!(switch.estimated_savings_micros, 1_950);
        assert_eq!(report.over_budget_session.as_deref(), Some("s1"));
        assert_eq!(report.retry_cap_target, Some(2));

        // The same events in another order produce an identical report.
        let mut reversed = fixture();
        reversed.reverse();
        assert_eq!(audit(&reversed, &options()).unwrap(), report);
    }

    #[test]
    fn proposal_cap_and_evidence_bar_are_enforced() {
        let mut capped = options();
        capped.max_proposals = 2;
        let report = audit(&fixture(), &capped).unwrap();
        assert_eq!(report.proposals.len(), 2);
        assert_eq!(report.proposals[0].kind, ProposalKind::ReduceRetries);
        assert_eq!(report.proposals[1].kind, ProposalKind::SwitchModel);

        let mut no_evidence = options();
        no_evidence.max_evidence_lines = 0;
        let report = audit(&fixture(), &no_evidence).unwrap();
        assert!(
            report.proposals.is_empty(),
            "a proposal without evidence must be dropped"
        );

        let too_many = AuditOptions {
            max_proposals: MAX_PROPOSALS_HARD + 1,
            ..options()
        };
        assert_eq!(
            audit(&fixture(), &too_many).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn dry_run_previews_without_mutating() {
        let report = audit(&fixture(), &options()).unwrap();
        let mut state = AuditState::default();
        let dry = apply(&report, AuditMode::DryRun, &mut state);

        assert_eq!(state, AuditState::default(), "dry run must not mutate state");
        assert!(dry.dry_run);
        assert!(dry.applied.is_empty());
        assert_eq!(dry.proposals.len(), report.proposals.len());
        assert_eq!(dry.preview.len(), 4, "retry, cache, switch, and budget preview");
        assert!(dry
            .preview
            .iter()
            .any(|change| change.kind == ProposalKind::SwitchModel));
        assert_eq!(dry.manual.len(), 1);
        assert_eq!(dry.manual[0].kind, ProposalKind::SplitSession);
        assert!(dry.skipped.is_empty());
    }

    #[test]
    fn apply_is_required_and_high_risk_needs_confirmation() {
        let report = audit(&fixture(), &options()).unwrap();

        let mut state = AuditState::default();
        let unconfirmed = apply(&report, AuditMode::Apply, &mut state);

        assert_eq!(state.retry_cap, Some(2));
        assert!(state.cache_enabled);
        assert_eq!(state.session_budget("s1"), Some(1_000));
        assert!(!state.model_disallowed("default", "slow-large"));
        assert_eq!(unconfirmed.applied.len(), 3);
        assert!(unconfirmed
            .skipped
            .iter()
            .any(|skipped| skipped.kind == ProposalKind::SwitchModel
                && skipped.reason == SkipReason::HighRiskUnconfirmed));
        assert!(unconfirmed
            .skipped
            .iter()
            .any(|skipped| skipped.kind == ProposalKind::SplitSession
                && skipped.reason == SkipReason::HighRiskUnconfirmed));
        assert!(unconfirmed.manual.is_empty());

        let confirmations = all_confirmations(&report);
        let mut confirmed_state = AuditState::default();
        let confirmed = apply_with_confirmations(
            &report,
            AuditMode::Apply,
            &mut confirmed_state,
            &confirmations,
        );
        assert_eq!(confirmed.applied.len(), 4);
        assert!(confirmed_state.model_disallowed("default", "slow-large"));
        assert_eq!(confirmed.manual.len(), 1);
        assert_eq!(confirmed.manual[0].kind, ProposalKind::SplitSession);
        assert!(confirmed.skipped.is_empty());
        assert_eq!(confirmed.preview.len(), 4);
    }

    #[test]
    fn already_applied_changes_are_skipped() {
        let report = audit(&fixture(), &options()).unwrap();
        let confirmations = all_confirmations(&report);
        let mut state = AuditState::default();
        let first =
            apply_with_confirmations(&report, AuditMode::Apply, &mut state, &confirmations);
        assert_eq!(first.applied_count(), 4);

        let second =
            apply_with_confirmations(&report, AuditMode::Apply, &mut state, &confirmations);
        assert!(second.applied.is_empty());
        assert_eq!(second.skipped.len(), 4);
        assert!(second
            .skipped
            .iter()
            .all(|skipped| skipped.reason == SkipReason::AlreadyApplied));
        assert_eq!(second.manual.len(), 1);
    }

    #[test]
    fn rollback_restores_state_and_refuses_stale_reports() {
        let report = audit(&fixture(), &options()).unwrap();
        let confirmations = all_confirmations(&report);
        let mut state = AuditState::default();
        let before = state.clone();
        let applied =
            apply_with_confirmations(&report, AuditMode::Apply, &mut state, &confirmations);
        assert_eq!(applied.applied_count(), 4);
        assert_ne!(state, before);

        rollback(&applied, &mut state).unwrap();
        assert_eq!(state, before, "rollback must restore the exact state");

        // The report is spent: the state no longer holds the after values.
        assert_eq!(
            rollback(&applied, &mut state).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let dry = apply(&report, AuditMode::DryRun, &mut state);
        assert_eq!(
            rollback(&dry, &mut state).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn rollback_refuses_a_state_changed_after_apply() {
        let report = audit(&fixture(), &options()).unwrap();
        let confirmations = all_confirmations(&report);
        let mut state = AuditState::default();
        let applied =
            apply_with_confirmations(&report, AuditMode::Apply, &mut state, &confirmations);
        state.retry_cap = Some(9);

        assert_eq!(
            rollback(&applied, &mut state).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(state.retry_cap, Some(9), "a refused rollback must not mutate");
    }

    #[test]
    fn evidence_never_carries_raw_payloads_or_secrets() {
        let secret = "sk-live-TOPSECRET";
        let mut events = fixture();
        events[0] = events[0].clone().with_tool(secret);

        let report = audit(&events, &options()).unwrap();
        let mut text = String::new();
        for finding in &report.findings {
            text.push_str(&finding.summary);
            text.push('\n');
            for line in &finding.evidence {
                text.push_str(line);
                text.push('\n');
            }
        }
        for proposal in &report.proposals {
            text.push_str(&proposal.title);
            text.push('\n');
            text.push_str(&proposal.rationale);
            text.push('\n');
            for line in &proposal.evidence {
                text.push_str(line);
                text.push('\n');
            }
        }
        assert!(!text.contains(secret), "a tool secret leaked into the audit");
        assert!(!text.contains("sk-live"), "secret-shaped material leaked");
    }

    #[test]
    fn invalid_options_are_refused() {
        let cases = [
            AuditOptions {
                session_stop_micros: Some(0),
                ..AuditOptions::default()
            },
            AuditOptions {
                work_class: "  ".to_owned(),
                ..AuditOptions::default()
            },
            AuditOptions {
                high_retry_rate_bps: 0,
                ..AuditOptions::default()
            },
            AuditOptions {
                low_cache_ratio_bps: 10_001,
                ..AuditOptions::default()
            },
            AuditOptions {
                slow_factor: 0,
                ..AuditOptions::default()
            },
            AuditOptions {
                target_retry_cap: 0,
                ..AuditOptions::default()
            },
            AuditOptions {
                max_evidence_lines: MAX_EVIDENCE_LINES_HARD + 1,
                ..AuditOptions::default()
            },
        ];
        for case in cases {
            assert_eq!(
                audit(&[], &case).unwrap_err().code(),
                ErrorCode::InvalidInput
            );
        }
    }
}
