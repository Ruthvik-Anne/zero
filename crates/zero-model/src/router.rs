//! Pool view, cheapest-above-floor routing, and evidence-based escalation
//! (MDL-02, MDL-03, MDL-04, MDL-10, MDL-12, MDL-14).
//!
//! The classifier ([`crate::classify`]) says what the work is and what floor it
//! needs. This module answers the next two questions:
//!
//! 1. **Which model?** [`route`] picks the cheapest eligible model above the
//!    class floor, after the user's overrides (pin, allowlist, denylist,
//!    privacy) and the budget are applied. Deprecated models are excluded and
//!    the reroute is reported as a warning, never performed silently.
//! 2. **What if it fails?** [`escalate`] moves one eligible tier up with the
//!    [`FailureEvidence`] attached. [`route_with_failures`] applies a whole
//!    failure history so a retry can never re-select a model that already
//!    failed.
//!
//! The contract and the test evidence live in `docs/routing.md`.
//!
//! ## Pool data
//!
//! [`PoolModel`] carries the fields routing needs to reason about: grades, the
//! input/output rate in micros per million tokens, availability, deprecation,
//! and tier. Costs are mandatory in the type, so a missing price cannot be
//! represented. A zero rate is a **declared free route** (a local model), not a
//! missing value; it is never inferred. A missing grade set is rejected by
//! [`Pool::new`] with `zero.fnd.invalid_input`, as is a [`ModelGrades`] entry
//! whose model id does not match the pool entry. Duplicate model ids are
//! rejected with `zero.fnd.already_exists`.
//!
//! ## Prompt text
//!
//! Nothing in this module receives prompt or message content. Reasons, errors,
//! and [`FailureEvidence`] name model ids, classes, capabilities, grades, costs,
//! and failure kinds only. `FailureEvidence::message_summary` is a bounded
//! diagnostic summary: [`FailureEvidence::new`] collapses whitespace, strips
//! control characters, and truncates it to
//! [`MAX_SUMMARY_CHARS`](FailureEvidence::MAX_SUMMARY_CHARS) characters, and
//! [`FailureEvidence::for_kind`] uses a fixed canonical summary per kind.

use crate::classify::{self, CapabilityFloor, Classification, ModelGrades, WorkClass};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Token denominator for the cost fields: prices are micros per million tokens.
const MICROS_PER_MTOK: u128 = 1_000_000;

/// Provider ids treated as local for [`Overrides::privacy_local_only`].
///
/// Matching is case-insensitive and trims surrounding whitespace. A provider
/// that is not listed here is remote. This is the only locality signal the
/// router reads; the pool contract has no separate `local` flag.
const LOCAL_PROVIDERS: &[&str] = &["local", "ollama", "llamacpp", "llama.cpp", "lmstudio", "vllm"];

/// True when a provider id denotes a local runtime.
pub fn is_local_provider(provider: &str) -> bool {
    let normalized = provider.trim().to_ascii_lowercase();
    LOCAL_PROVIDERS.iter().any(|local| *local == normalized)
}

/// One model in the routing pool (MDL-01 data, MDL-02 selection).
///
/// `input_cost_micros_per_mtok` and `output_cost_micros_per_mtok` are required
/// fields. A zero rate is a declared free route, not "unknown". `tier` is the
/// escalation axis: a higher tier is a stronger (normally more expensive)
/// model. Escalation only moves to a strictly higher tier, so a tier must be
/// assigned deliberately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolModel {
    pub model: String,
    pub provider: String,
    /// Capability grades for the model. Reuses the classifier's type so the
    /// floor check is the same one `classify::meets` performs.
    pub grades: ModelGrades,
    pub input_cost_micros_per_mtok: u64,
    pub output_cost_micros_per_mtok: u64,
    /// Whether the provider can currently serve the model.
    pub available: bool,
    /// Whether the model has been withdrawn. Deprecated models are never routed
    /// to; the reroute is reported as a warning (MDL-14).
    pub deprecated: bool,
    /// Escalation tier. Higher is stronger.
    pub tier: u8,
}

impl PoolModel {
    /// The combined input+output rate in micros per million tokens.
    pub fn combined_rate_micros_per_mtok(&self) -> u64 {
        self.input_cost_micros_per_mtok.saturating_add(self.output_cost_micros_per_mtok)
    }

    /// The estimated cost of one call in micros.
    ///
    /// The estimate applies the same token count to input and output:
    /// `(input_rate + output_rate) * tokens / 1_000_000`, truncated to whole
    /// micros. Saturates instead of overflowing.
    pub fn estimated_cost_micros(&self, estimate_tokens: u64) -> u64 {
        let micros = u128::from(self.combined_rate_micros_per_mtok())
            .saturating_mul(u128::from(estimate_tokens))
            / MICROS_PER_MTOK;
        u64::try_from(micros).unwrap_or(u64::MAX)
    }

    /// Deterministic pool ordering: tier, then rate, then model id.
    fn ordering_key(&self) -> (u8, u64, &str) {
        (self.tier, self.combined_rate_micros_per_mtok(), &self.model)
    }
}

/// The set of models the router may choose from.
///
/// Construction validates the pool once, so routing never has to guess about
/// duplicates or missing grades. Use [`Pool::ordered`] for a deterministic view.
/// [`Pool::new`] is the validating constructor; a struct literal or a directly
/// deserialized `Pool` bypasses those checks, so callers that load a pool from
/// storage should rebuild it through [`Pool::new`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pool {
    pub models: Vec<PoolModel>,
}

impl Pool {
    /// Validate and build a pool.
    ///
    /// Rejects, in this order, per entry:
    /// - an empty model id (`zero.fnd.invalid_input`);
    /// - an empty grade map (`zero.fnd.invalid_input`) — a missing grade set is
    ///   not routeable, so fix the entry or omit it;
    /// - a grade set for a different model id (`zero.fnd.invalid_input`);
    /// - a duplicate model id (`zero.fnd.already_exists`).
    pub fn new(models: Vec<PoolModel>) -> Result<Self> {
        let mut seen = BTreeSet::new();
        for model in &models {
            if model.model.trim().is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    "pool entry has an empty model id",
                ));
            }
            if model.grades.grades.is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "pool model {:?} has no capability grades; fix or omit the entry",
                        model.model
                    ),
                ));
            }
            if model.grades.model != model.model {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "pool model {:?} carries grades for {:?}; the ids must match",
                        model.model, model.grades.model
                    ),
                ));
            }
            if !seen.insert(model.model.clone()) {
                return Err(ZeroError::new(
                    ErrorCode::AlreadyExists,
                    format!(
                        "duplicate pool model id {:?}; model ids must be unique",
                        model.model
                    ),
                ));
            }
        }
        Ok(Self { models })
    }

    /// Look a model up by id.
    pub fn get(&self, model: &str) -> Option<&PoolModel> {
        self.models.iter().find(|entry| entry.model == model)
    }

    /// Number of models in the pool.
    pub fn len(&self) -> usize {
        self.models.len()
    }

    /// True when the pool has no models.
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }

    /// Every model in deterministic order: tier, rate, then model id.
    pub fn ordered(&self) -> Vec<&PoolModel> {
        let mut ordered: Vec<&PoolModel> = self.models.iter().collect();
        ordered.sort_by(|a, b| a.ordering_key().cmp(&b.ordering_key()));
        ordered
    }
}

/// User overrides applied before the router picks a model (MDL-12).
///
/// - `pinned` is a model id the user explicitly wants. It must be eligible; it
///   cannot undercut the class floor, the denylist, the allowlist, or the
///   privacy constraint. A pin that is merely deprecated, unavailable, or
///   previously failed is rerouted with a warning rather than dispatched.
/// - `allow` is an allowlist. Empty means no allowlist. A non-empty list means
///   only listed ids are eligible; unknown ids in the list are ignored.
/// - `deny` is a denylist and wins over everything except the floor check: a
///   denied model is never eligible, and a pin cannot override the denial.
/// - `privacy_local_only` restricts routing to providers listed in
///   [`is_local_provider`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Overrides {
    pub pinned: Option<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub privacy_local_only: bool,
}

/// A routing decision for one dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDecision {
    /// The model to use.
    pub chosen: PoolModel,
    /// Eligible models strictly above the chosen tier, in cost order. These are
    /// the targets [`escalate`] may move to.
    pub escalation_chain: Vec<String>,
    /// Deterministic explanation. Contains no prompt text.
    pub reason: String,
    /// Every other eligible model (including lower tiers), in cost order. They
    /// are alternatives, not escalation targets.
    pub alternatives: Vec<String>,
    /// Non-fatal notes, chiefly deprecation reroutes (MDL-14).
    pub warnings: Vec<String>,
}

/// Why a model call failed (MDL-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// The provider returned an error or the call broke.
    Failure,
    /// The call exceeded its deadline.
    Timeout,
    /// The model refused the request.
    Refusal,
    /// The answer was judged insufficiently confident.
    LowConfidence,
}

impl FailureKind {
    /// Stable snake-case label used in reasons and stored data.
    pub const fn as_str(self) -> &'static str {
        match self {
            FailureKind::Failure => "failure",
            FailureKind::Timeout => "timeout",
            FailureKind::Refusal => "refusal",
            FailureKind::LowConfidence => "low_confidence",
        }
    }

    /// The fixed diagnostic used when no caller summary is supplied.
    pub const fn summary(self) -> &'static str {
        match self {
            FailureKind::Failure => "provider call failed",
            FailureKind::Timeout => "provider call timed out",
            FailureKind::Refusal => "model refused the request",
            FailureKind::LowConfidence => "answer judged low confidence",
        }
    }
}

/// Evidence attached to an escalation (MDL-04).
///
/// It records only routing facts: the failure kind, the failed model, the
/// attempt count, a bounded diagnostic summary, and the cost already spent.
/// There is deliberately no field for prompt or message content, and the
/// constructors keep the summary short so a caller cannot smuggle a transcript
/// through it unnoticed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureEvidence {
    pub kind: FailureKind,
    pub model: String,
    pub attempts: u32,
    /// A bounded diagnostic. Never a prompt or transcript.
    pub message_summary: String,
    pub cost_micros: u64,
}

impl FailureEvidence {
    /// The maximum summary length, in characters.
    pub const MAX_SUMMARY_CHARS: usize = 200;

    /// Build evidence from a diagnostic summary.
    ///
    /// Whitespace is collapsed, control characters become spaces, and the
    /// result is truncated to [`Self::MAX_SUMMARY_CHARS`] characters on a char
    /// boundary. An empty summary falls back to [`FailureKind::summary`].
    pub fn new(
        kind: FailureKind,
        model: impl Into<String>,
        attempts: u32,
        summary: &str,
        cost_micros: u64,
    ) -> Self {
        let sanitized = sanitize_summary(summary);
        let message_summary = if sanitized.is_empty() {
            kind.summary().to_owned()
        } else {
            sanitized
        };
        Self {
            kind,
            model: model.into(),
            attempts,
            message_summary,
            cost_micros,
        }
    }

    /// Build evidence with the canonical summary for the failure kind.
    pub fn for_kind(
        kind: FailureKind,
        model: impl Into<String>,
        attempts: u32,
        cost_micros: u64,
    ) -> Self {
        Self {
            kind,
            model: model.into(),
            attempts,
            message_summary: kind.summary().to_owned(),
            cost_micros,
        }
    }
}

/// Collapse whitespace, drop control characters, and cap the length.
fn sanitize_summary(summary: &str) -> String {
    let mut sanitized = String::with_capacity(summary.len().min(FailureEvidence::MAX_SUMMARY_CHARS));
    let mut pending_space = false;
    for character in summary.chars() {
        if character.is_whitespace() {
            pending_space = !sanitized.is_empty();
            continue;
        }
        if character.is_control() {
            continue;
        }
        if pending_space {
            if sanitized.chars().count() >= FailureEvidence::MAX_SUMMARY_CHARS {
                break;
            }
            sanitized.push(' ');
            pending_space = false;
        }
        if sanitized.chars().count() >= FailureEvidence::MAX_SUMMARY_CHARS {
            break;
        }
        sanitized.push(character);
    }
    sanitized
}

/// The result of an escalation attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Escalation {
    /// The model to retry on, when one remains.
    pub next: Option<PoolModel>,
    /// Deterministic explanation of the move or the exhaustion.
    pub reason: String,
    /// The evidence that caused the escalation, attached unchanged.
    pub evidence: FailureEvidence,
    /// True when no eligible tier remains above the failed model.
    pub exhausted: bool,
}

/// What removed a model from consideration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Excluded {
    Unavailable,
    Deprecated,
    BelowFloor,
    Denied,
    NotAllowed,
    Privacy,
    Failed,
}

#[derive(Default)]
struct ExclusionCounts {
    unavailable: usize,
    deprecated: usize,
    below_floor: usize,
    denied: usize,
    not_allowed: usize,
    privacy: usize,
    failed: usize,
}

impl ExclusionCounts {
    fn record(&mut self, excluded: Excluded) {
        match excluded {
            Excluded::Unavailable => self.unavailable += 1,
            Excluded::Deprecated => self.deprecated += 1,
            Excluded::BelowFloor => self.below_floor += 1,
            Excluded::Denied => self.denied += 1,
            Excluded::NotAllowed => self.not_allowed += 1,
            Excluded::Privacy => self.privacy += 1,
            Excluded::Failed => self.failed += 1,
        }
    }

    fn is_empty(&self) -> bool {
        self.unavailable == 0
            && self.deprecated == 0
            && self.below_floor == 0
            && self.denied == 0
            && self.not_allowed == 0
            && self.privacy == 0
            && self.failed == 0
    }

    fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.unavailable > 0 {
            parts.push(format!("unavailable={}", self.unavailable));
        }
        if self.deprecated > 0 {
            parts.push(format!("deprecated={}", self.deprecated));
        }
        if self.below_floor > 0 {
            parts.push(format!("below_floor={}", self.below_floor));
        }
        if self.denied > 0 {
            parts.push(format!("denied={}", self.denied));
        }
        if self.not_allowed > 0 {
            parts.push(format!("not_allowed={}", self.not_allowed));
        }
        if self.privacy > 0 {
            parts.push(format!("privacy={}", self.privacy));
        }
        if self.failed > 0 {
            parts.push(format!("previously_failed={}", self.failed));
        }
        parts.join(", ")
    }
}

/// Why a model is not eligible, or `None` when it is.
fn exclusion(
    model: &PoolModel,
    floor: &CapabilityFloor,
    overrides: &Overrides,
    failed: &BTreeSet<String>,
) -> Option<Excluded> {
    if !model.available {
        return Some(Excluded::Unavailable);
    }
    if !classify::meets(&model.grades, floor).ok {
        return Some(Excluded::BelowFloor);
    }
    if failed.contains(&model.model) {
        return Some(Excluded::Failed);
    }
    if overrides.deny.iter().any(|denied| denied == &model.model) {
        return Some(Excluded::Denied);
    }
    if !overrides.allow.is_empty() && !overrides.allow.iter().any(|allowed| allowed == &model.model) {
        return Some(Excluded::NotAllowed);
    }
    if overrides.privacy_local_only && !is_local_provider(&model.provider) {
        return Some(Excluded::Privacy);
    }
    // Deprecation is checked last: a model that is deprecated *and* denied is
    // simply denied, and only an otherwise-eligible deprecated model produces
    // the reroute warning.
    if model.deprecated {
        return Some(Excluded::Deprecated);
    }
    None
}

/// Format a floor's requirements in capability order.
fn describe_floor(floor: &CapabilityFloor) -> String {
    floor
        .minimums
        .iter()
        .map(|(capability, grade)| format!("{}>={}", capability.as_str(), grade.get()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Format missing capabilities with the actual grade.
fn describe_missing(missing: &[(classify::Capability, classify::Grade, classify::Grade)]) -> String {
    missing
        .iter()
        .map(|(capability, required, actual)| {
            format!("{}>={} (has {})", capability.as_str(), required.get(), actual.get())
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The no-eligible-model error names the floor and every exclusion count, so the
/// missing constraint is visible without leaking task text.
fn no_eligible_error(
    class: WorkClass,
    floor: &CapabilityFloor,
    exclusions: &ExclusionCounts,
    failed: &BTreeSet<String>,
) -> ZeroError {
    let mut detail = Vec::new();
    if !exclusions.is_empty() {
        detail.push(format!("excluded {}", exclusions.describe()));
    }
    if !failed.is_empty() {
        detail.push(format!(
            "previously failed: {}",
            failed.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    let suffix = if detail.is_empty() {
        "the pool has no models".to_owned()
    } else {
        detail.join("; ")
    };
    ZeroError::new(
        ErrorCode::Unavailable,
        format!(
            "no eligible model clears the {} floor ({}); {suffix}",
            class.as_str(),
            describe_floor(floor)
        ),
    )
}

/// Whether a pin may be used, or why it must be rerouted.
enum PinStatus<'a> {
    Eligible(&'a PoolModel),
    Reroute(&'static str),
}

/// Validate a pin. Hard constraints (floor, deny, allow, privacy) are errors;
/// transient or lifecycle ones (failed, deprecated, unavailable) ask for a
/// reroute instead.
fn pin_status<'a>(
    pool: &'a Pool,
    pin: &str,
    class: WorkClass,
    floor: &CapabilityFloor,
    overrides: &Overrides,
    failed: &BTreeSet<String>,
) -> Result<PinStatus<'a>> {
    let model = pool.get(pin).ok_or_else(|| {
        ZeroError::new(
            ErrorCode::NotFound,
            format!("pinned model {pin:?} is not in the model pool"),
        )
    })?;
    let floor_check = classify::meets(&model.grades, floor);
    if !floor_check.ok {
        return Err(ZeroError::new(
            ErrorCode::PolicyDenied,
            format!(
                "pinned model {pin:?} is below the {} floor: {}",
                class.as_str(),
                describe_missing(&floor_check.missing)
            ),
        ));
    }
    if overrides.deny.iter().any(|denied| denied == pin) {
        return Err(ZeroError::new(
            ErrorCode::PolicyDenied,
            format!("pinned model {pin:?} is denied by the denylist"),
        ));
    }
    if !overrides.allow.is_empty() && !overrides.allow.iter().any(|allowed| allowed == pin) {
        return Err(ZeroError::new(
            ErrorCode::PolicyDenied,
            format!("pinned model {pin:?} is not in the allowlist"),
        ));
    }
    if overrides.privacy_local_only && !is_local_provider(&model.provider) {
        return Err(ZeroError::new(
            ErrorCode::PolicyDenied,
            format!(
                "pinned model {pin:?} is not a local provider; privacy_local_only is set"
            ),
        ));
    }
    if failed.contains(pin) {
        return Ok(PinStatus::Reroute("previously failed"));
    }
    if model.deprecated {
        return Ok(PinStatus::Reroute("is deprecated"));
    }
    if !model.available {
        return Ok(PinStatus::Reroute("is unavailable"));
    }
    Ok(PinStatus::Eligible(model))
}

/// Whether a cost fits an optional remaining budget.
fn fits_budget(cost_micros: u64, budget_micros: Option<u64>) -> bool {
    match budget_micros {
        None => true,
        Some(budget) => cost_micros <= budget,
    }
}

/// Shared selection used by [`route`] and [`route_with_failures`].
///
/// `estimate_tokens` is `None` when the caller has no token forecast (the
/// failure-history entry point): ordering still uses the per-million rate, which
/// is proportional to the estimated cost, so the order is identical for any
/// positive token estimate.
fn plan_route(
    pool: &Pool,
    classification: &Classification,
    overrides: &Overrides,
    budget_micros: Option<u64>,
    estimate_tokens: Option<u64>,
    failed: &BTreeSet<String>,
) -> Result<RouteDecision> {
    let class = classification.class;
    let floor = &classification.floor;
    let mut exclusions = ExclusionCounts::default();
    let mut warnings = Vec::new();
    let mut candidates: Vec<&PoolModel> = Vec::new();

    for model in pool.ordered() {
        match exclusion(model, floor, overrides, failed) {
            None => candidates.push(model),
            Some(Excluded::Deprecated) => {
                warnings.push(format!(
                    "model {} is deprecated; excluded from routing",
                    model.model
                ));
                exclusions.record(Excluded::Deprecated);
            }
            Some(other) => exclusions.record(other),
        }
    }

    // Rate order is cost order for any positive token estimate, and it stays
    // meaningful when no estimate is supplied. Ties break on the model id.
    candidates.sort_by(|a, b| {
        a.combined_rate_micros_per_mtok()
            .cmp(&b.combined_rate_micros_per_mtok())
            .then_with(|| a.model.cmp(&b.model))
    });

    let pinned = overrides
        .pinned
        .as_deref()
        .map(str::trim)
        .filter(|pin| !pin.is_empty());
    let mut pinned_choice: Option<&PoolModel> = None;
    if let Some(pin) = pinned {
        match pin_status(pool, pin, class, floor, overrides, failed)? {
            PinStatus::Eligible(model) => pinned_choice = Some(model),
            PinStatus::Reroute(cause) => {
                warnings.push(format!(
                    "pinned model {pin} {cause}; rerouted to the cheapest eligible model"
                ));
            }
        }
    }

    let chosen = match pinned_choice {
        Some(model) => model,
        None => match candidates.first() {
            Some(model) => model,
            None => return Err(no_eligible_error(class, floor, &exclusions, failed)),
        },
    };

    let estimate = estimate_tokens.unwrap_or(0);
    let chosen_cost = chosen.estimated_cost_micros(estimate);
    if let Some(budget) = budget_micros {
        if chosen_cost > budget {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "estimated cost {chosen_cost} micros for model {} exceeds the remaining budget {budget} micros; nothing was dispatched",
                    chosen.model
                ),
            ));
        }
    }

    let above: Vec<&PoolModel> = candidates
        .iter()
        .copied()
        .filter(|model| model.model != chosen.model && model.tier > chosen.tier)
        .filter(|model| fits_budget(model.estimated_cost_micros(estimate), budget_micros))
        .collect();
    let alternatives: Vec<&PoolModel> = candidates
        .iter()
        .copied()
        .filter(|model| model.model != chosen.model)
        .filter(|model| fits_budget(model.estimated_cost_micros(estimate), budget_micros))
        .collect();

    let cost_note = match estimate_tokens {
        Some(tokens) => format!(" at {chosen_cost} micros for {tokens} tokens"),
        None => String::new(),
    };
    let mut reason = if pinned_choice.is_some() {
        format!(
            "pinned model {} is eligible for work class {}{cost_note} (tier {})",
            chosen.model,
            class.as_str(),
            chosen.tier
        )
    } else if pinned.is_some() {
        format!(
            "cheapest eligible model {} clears the {} floor{cost_note} after the pinned model was rerouted (tier {})",
            chosen.model,
            class.as_str(),
            chosen.tier
        )
    } else {
        format!(
            "cheapest eligible model {} clears the {} floor{cost_note} (tier {})",
            chosen.model,
            class.as_str(),
            chosen.tier
        )
    };
    if let Some(budget) = budget_micros {
        reason.push_str(&format!("; budget {budget} micros covers the estimate"));
    }
    if !failed.is_empty() {
        reason.push_str(&format!(
            "; skipped {} previously failed model(s): {}",
            failed.len(),
            failed.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }

    Ok(RouteDecision {
        chosen: chosen.clone(),
        escalation_chain: above.into_iter().map(|model| model.model.clone()).collect(),
        reason,
        alternatives: alternatives.into_iter().map(|model| model.model.clone()).collect(),
        warnings,
    })
}

/// Route a classified task to the cheapest eligible model above its floor
/// (MDL-02, MDL-03, MDL-12, MDL-14).
///
/// Eligibility is: available, not deprecated, clears the class floor, passes the
/// overrides, and is not in the failure history (empty here). A pin is honoured
/// only when it is eligible; a pin below the floor — including the `security`
/// and `destructive` floors — is refused with `zero.pol.denied`, as are a pin
/// denied by the denylist, outside the allowlist, or not local under
/// `privacy_local_only`. A deprecated, unavailable, or previously failed pin is
/// rerouted with a warning.
///
/// The estimate applies `estimate_tokens` to both input and output. When
/// `budget_micros` is the remaining budget and the chosen estimate exceeds it,
/// the result is `zero.fnd.limit_exceeded` before any dispatch, and the
/// escalation chain and alternatives contain only models that fit.
///
/// When no model is eligible the result is `zero.fnd.unavailable` naming the
/// class floor and the exclusion counts.
pub fn route(
    pool: &Pool,
    classification: &Classification,
    overrides: &Overrides,
    budget_micros: Option<u64>,
    estimate_tokens: u64,
) -> Result<RouteDecision> {
    plan_route(
        pool,
        classification,
        overrides,
        budget_micros,
        Some(estimate_tokens),
        &BTreeSet::new(),
    )
}

/// Route with a failure history, skipping every model that already failed
/// (MDL-04).
///
/// This is the retry entry point: the first non-failed eligible model in cost
/// order is chosen, so a repeated failure walks up the eligible order and never
/// re-selects an earlier model. Deprecation and override handling are identical
/// to [`route`]; no budget is applied because the signature carries no budget,
/// so a caller that escalates under a budget re-checks it before dispatch.
pub fn route_with_failures(
    pool: &Pool,
    classification: &Classification,
    overrides: &Overrides,
    failures: &[FailureEvidence],
) -> Result<RouteDecision> {
    let failed: BTreeSet<String> = failures.iter().map(|evidence| evidence.model.clone()).collect();
    plan_route(pool, classification, overrides, None, None, &failed)
}

/// Escalate after a failure (MDL-04).
///
/// Moves to the lowest eligible tier strictly above the failed model, using the
/// [`RouteDecision::escalation_chain`] built at route time. The chain already
/// honours the floor, overrides, deprecation, availability, and budget, so an
/// escalation cannot undercut a security/destructive floor or a denylist.
///
/// Guarantees:
/// - never downgrades: the next tier is strictly greater than the failed
///   model's tier;
/// - never retries the same model: the failed id is skipped;
/// - never silently drops the evidence: it is returned in [`Escalation`]
///   whether or not a next model exists;
/// - when no eligible tier remains, `next` is `None` and `exhausted` is `true`.
///
/// The function takes the most recent evidence. For a whole history, use
/// [`route_with_failures`].
pub fn escalate(pool: &Pool, decision: &RouteDecision, evidence: FailureEvidence) -> Escalation {
    let from_tier = pool
        .get(&evidence.model)
        .map(|model| model.tier)
        .unwrap_or(decision.chosen.tier);

    let mut best: Option<&PoolModel> = None;
    for model_id in &decision.escalation_chain {
        let Some(model) = pool.get(model_id) else {
            continue;
        };
        if model.model == evidence.model || model.tier <= from_tier {
            continue;
        }
        let replace = match best {
            None => true,
            Some(current) => {
                (model.tier, model.combined_rate_micros_per_mtok(), model.model.as_str())
                    < (
                        current.tier,
                        current.combined_rate_micros_per_mtok(),
                        current.model.as_str(),
                    )
            }
        };
        if replace {
            best = Some(model);
        }
    }

    let kind = evidence.kind.as_str();
    let attempts = evidence.attempts;
    let cost_micros = evidence.cost_micros;
    let failed_model = evidence.model.clone();
    let next = best.cloned();
    let exhausted = next.is_none();
    let reason = match &next {
        Some(model) => format!(
            "escalated from model {failed_model} to {} after {kind} (attempts {attempts}, cost {cost_micros} micros); tier {from_tier}->{}",
            model.model, model.tier
        ),
        None => format!(
            "no eligible model remains above model {failed_model} after {kind} (attempts {attempts}, cost {cost_micros} micros); escalation exhausted"
        ),
    };

    Escalation { next, reason, evidence, exhausted }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{Capability, Grade, TaskSignals};
    use std::collections::BTreeMap;

    const TOKENS: u64 = 1_000_000;

    fn grades(name: &str, class: WorkClass) -> ModelGrades {
        ModelGrades { model: name.to_owned(), grades: classify::floor_for(class).minimums }
    }

    fn model(name: &str, class: WorkClass, tier: u8, input: u64, output: u64) -> PoolModel {
        PoolModel {
            model: name.to_owned(),
            provider: "test".to_owned(),
            grades: grades(name, class),
            input_cost_micros_per_mtok: input,
            output_cost_micros_per_mtok: output,
            available: true,
            deprecated: false,
            tier,
        }
    }

    fn with_provider(mut entry: PoolModel, provider: &str) -> PoolModel {
        entry.provider = provider.to_owned();
        entry
    }

    fn pool_of(models: Vec<PoolModel>) -> Pool {
        Pool::new(models).expect("valid pool")
    }

    fn edit() -> Classification {
        classify::classify(&TaskSignals { files_changed: 1, ..TaskSignals::default() })
    }

    fn security() -> Classification {
        classify::classify(&TaskSignals {
            touches_secrets: true,
            ..TaskSignals::default()
        })
    }

    #[test]
    fn the_cheapest_eligible_model_above_the_floor_is_chosen() {
        let mut below = model("below", WorkClass::Edit, 1, 1, 1);
        below.grades.grades.insert(Capability::Coding, Grade::new(1));
        let pool = pool_of(vec![
            model("expensive", WorkClass::Edit, 2, 80, 20),
            model("cheap", WorkClass::Edit, 1, 5, 5),
            below,
        ]);

        let decision = route(&pool, &edit(), &Overrides::default(), Some(10_000), TOKENS)
            .expect("cheap clears the floor");
        assert_eq!(decision.chosen.model, "cheap");
        assert_eq!(decision.chosen.estimated_cost_micros(TOKENS), 10);
        assert_eq!(decision.escalation_chain, vec!["expensive".to_owned()]);
        assert_eq!(decision.alternatives, vec!["expensive".to_owned()]);
        assert!(decision.reason.contains("cheapest eligible model cheap"), "{}", decision.reason);
        assert!(decision.reason.contains("clears the edit floor"), "{}", decision.reason);
        assert!(decision.warnings.is_empty());
    }

    #[test]
    fn pin_is_honoured_only_when_eligible_and_below_floor_pins_are_refused() {
        let pool = pool_of(vec![
            model("cheap", WorkClass::Edit, 1, 5, 5),
            model("pinned", WorkClass::Edit, 3, 90, 10),
        ]);
        let overrides = Overrides { pinned: Some("pinned".to_owned()), ..Overrides::default() };
        let decision = route(&pool, &edit(), &overrides, Some(10_000), TOKENS).expect("pin is eligible");
        assert_eq!(decision.chosen.model, "pinned");
        assert!(decision.reason.contains("pinned model pinned"), "{}", decision.reason);

        let unknown = route(
            &pool,
            &edit(),
            &Overrides { pinned: Some("missing".to_owned()), ..Overrides::default() },
            None,
            TOKENS,
        )
        .expect_err("an unknown pin is not a route");
        assert_eq!(unknown.code(), ErrorCode::NotFound);

        // A pin below the security floor is refused even when a strong model exists.
        let strong = model("strong", WorkClass::Security, 0, 50, 50);
        let mut weak = model("weak", WorkClass::Security, 0, 1, 1);
        weak.grades.grades.insert(Capability::Reasoning, Grade::new(4));
        let setting = "TOP-SECRET-PLACEHOLDER-abc123";
        let secure_pool = pool_of(vec![strong, weak]);
        let error = route(
            &secure_pool,
            &security(),
            &Overrides { pinned: Some("weak".to_owned()), ..Overrides::default() },
            None,
            TOKENS,
        )
        .expect_err("a below-floor pin must not undercut the security floor");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("security"), "{}", error.message());
        assert!(error.message().contains("reasoning>=5"), "{}", error.message());
        assert!(!error.message().contains(setting), "error leaked task text");
    }

    #[test]
    fn allow_deny_and_privacy_overrides_filter_the_pool() {
        let pool = pool_of(vec![
            with_provider(model("cheap-remote", WorkClass::Edit, 0, 5, 5), "openai"),
            with_provider(model("pricey-local", WorkClass::Edit, 1, 50, 50), "ollama"),
        ]);

        let allowed = route(
            &pool,
            &edit(),
            &Overrides { allow: vec!["pricey-local".to_owned()], ..Overrides::default() },
            None,
            TOKENS,
        )
        .expect("allowlist is eligible");
        assert_eq!(allowed.chosen.model, "pricey-local");

        let denied = route(
            &pool,
            &edit(),
            &Overrides { deny: vec!["cheap-remote".to_owned()], ..Overrides::default() },
            None,
            TOKENS,
        )
        .expect("denylist removes the cheapest");
        assert_eq!(denied.chosen.model, "pricey-local");

        let private = route(
            &pool,
            &edit(),
            &Overrides { privacy_local_only: true, ..Overrides::default() },
            None,
            TOKENS,
        )
        .expect("only the local provider is eligible");
        assert_eq!(private.chosen.model, "pricey-local");
        assert!(is_local_provider(" Ollama "));
        assert!(!is_local_provider("openai"));

        let denied_pin = route(
            &pool,
            &edit(),
            &Overrides {
                pinned: Some("cheap-remote".to_owned()),
                deny: vec!["cheap-remote".to_owned()],
                ..Overrides::default()
            },
            None,
            TOKENS,
        )
        .expect_err("a pin cannot override the denylist");
        assert_eq!(denied_pin.code(), ErrorCode::PolicyDenied);
        assert!(denied_pin.message().contains("denylist"), "{}", denied_pin.message());

        let remote_pin = route(
            &pool,
            &edit(),
            &Overrides {
                pinned: Some("cheap-remote".to_owned()),
                privacy_local_only: true,
                ..Overrides::default()
            },
            None,
            TOKENS,
        )
        .expect_err("a pin cannot override privacy");
        assert_eq!(remote_pin.code(), ErrorCode::PolicyDenied);
        assert!(remote_pin.message().contains("privacy_local_only"), "{}", remote_pin.message());
    }

    #[test]
    fn deprecated_models_are_excluded_and_the_reroute_is_reported() {
        let mut legacy = model("legacy", WorkClass::Edit, 0, 1, 1);
        legacy.deprecated = true;
        let pool = pool_of(vec![legacy, model("current", WorkClass::Edit, 1, 10, 10)]);

        let decision = route(&pool, &edit(), &Overrides::default(), None, TOKENS).expect("reroute");
        assert_eq!(decision.chosen.model, "current");
        assert!(decision.alternatives.is_empty());
        assert_eq!(decision.warnings.len(), 1);
        assert!(decision.warnings[0].contains("legacy"), "{:?}", decision.warnings);
        assert!(decision.warnings[0].contains("deprecated"), "{:?}", decision.warnings);

        let pinned = route(
            &pool,
            &edit(),
            &Overrides { pinned: Some("legacy".to_owned()), ..Overrides::default() },
            None,
            TOKENS,
        )
        .expect("a deprecated pin is rerouted");
        assert_eq!(pinned.chosen.model, "current");
        assert!(pinned.warnings.iter().any(|warning| {
            warning.contains("pinned model legacy")
                && warning.contains("deprecated")
                && warning.contains("rerouted")
        }), "{:?}", pinned.warnings);
    }

    #[test]
    fn unavailable_models_are_excluded_and_reported() {
        let mut down = model("down", WorkClass::Edit, 0, 1, 1);
        down.available = false;
        let pool = pool_of(vec![down, model("up", WorkClass::Edit, 1, 10, 10)]);
        let decision = route(&pool, &edit(), &Overrides::default(), None, TOKENS).expect("up is eligible");
        assert_eq!(decision.chosen.model, "up");

        let empty = pool_of(vec![{
            let mut only = model("only", WorkClass::Edit, 0, 1, 1);
            only.available = false;
            only
        }]);
        let error = route(&empty, &edit(), &Overrides::default(), None, TOKENS)
            .expect_err("nothing is available");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains("edit"), "{}", error.message());
        assert!(error.message().contains("unavailable=1"), "{}", error.message());
        assert!(error.message().contains("coding>=4"), "{}", error.message());
    }

    #[test]
    fn budget_refuses_before_dispatch_and_filters_the_chain() {
        let pool = pool_of(vec![
            model("cheap", WorkClass::Edit, 0, 5, 5),
            model("pricey", WorkClass::Edit, 1, 100, 50),
        ]);
        let fitted = route(&pool, &edit(), &Overrides::default(), Some(50), TOKENS)
            .expect("cheap costs 10 and fits");
        assert_eq!(fitted.chosen.model, "cheap");
        assert!(fitted.alternatives.is_empty(), "pricey costs 150 and must not be offered");

        let error = route(&pool, &edit(), &Overrides::default(), Some(9), TOKENS)
            .expect_err("the estimate exceeds the remaining budget");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert!(error.message().contains("budget"), "{}", error.message());
        assert!(error.message().contains("10"), "{}", error.message());
        assert!(error.message().contains("9"), "{}", error.message());
        assert!(error.message().contains("nothing was dispatched"), "{}", error.message());

        let exact = route(&pool, &edit(), &Overrides::default(), Some(10), TOKENS)
            .expect("an exact budget is inclusive");
        assert_eq!(exact.chosen.model, "cheap");
    }

    #[test]
    fn escalation_moves_one_tier_up_and_attaches_evidence() {
        let pool = pool_of(vec![
            model("a", WorkClass::Edit, 0, 1, 1),
            model("b", WorkClass::Edit, 1, 10, 10),
            model("c", WorkClass::Edit, 2, 100, 100),
        ]);
        let decision = route(&pool, &edit(), &Overrides::default(), None, TOKENS).expect("a is cheapest");
        assert_eq!(decision.chosen.model, "a");
        assert_eq!(decision.escalation_chain, vec!["b".to_owned(), "c".to_owned()]);

        let evidence = FailureEvidence::for_kind(FailureKind::Failure, "a", 2, 20);
        let first = escalate(&pool, &decision, evidence.clone());
        assert_eq!(first.next.as_ref().map(|model| model.model.as_str()), Some("b"));
        assert!(!first.exhausted);
        assert_eq!(first.evidence, evidence);
        assert!(first.reason.contains("from model a to b"), "{}", first.reason);
        assert!(first.reason.contains("attempts 2"), "{}", first.reason);
        assert!(first.reason.contains("cost 20 micros"), "{}", first.reason);

        let evidence = FailureEvidence::for_kind(FailureKind::Timeout, "b", 1, 25);
        let second = escalate(&pool, &decision, evidence.clone());
        assert_eq!(second.next.as_ref().map(|model| model.model.as_str()), Some("c"));
        assert_eq!(second.evidence, evidence);
        assert!(second.reason.contains("timeout"), "{}", second.reason);
    }

    #[test]
    fn escalation_never_downgrades_or_retries_and_exhausts_with_evidence() {
        let pool = pool_of(vec![
            model("a", WorkClass::Edit, 0, 1, 1),
            model("b", WorkClass::Edit, 1, 10, 10),
            model("c", WorkClass::Edit, 2, 100, 100),
        ]);
        let decision = route(&pool, &edit(), &Overrides::default(), None, TOKENS).expect("a");

        let evidence = FailureEvidence::for_kind(FailureKind::LowConfidence, "c", 3, 40);
        let exhausted = escalate(&pool, &decision, evidence.clone());
        assert!(exhausted.exhausted);
        assert!(exhausted.next.is_none());
        assert_eq!(exhausted.evidence, evidence);
        assert!(exhausted.reason.contains("exhausted"), "{}", exhausted.reason);
        assert!(exhausted.reason.contains("model c"), "{}", exhausted.reason);

        // A failure of the lowest model never returns it and never moves down.
        let low = FailureEvidence::for_kind(FailureKind::Refusal, "a", 1, 5);
        let next = escalate(&pool, &decision, low).next.expect("b is above a");
        assert_eq!(next.model, "b");
        assert!(next.tier > 0);

        // A tier with no successor is exhausted rather than downgraded.
        let top_only = pool_of(vec![
            model("only", WorkClass::Edit, 0, 1, 1),
        ]);
        let only_decision =
            route(&top_only, &edit(), &Overrides::default(), None, TOKENS).expect("only");
        let alone = escalate(
            &top_only,
            &only_decision,
            FailureEvidence::for_kind(FailureKind::Failure, "only", 1, 1),
        );
        assert!(alone.exhausted);
        assert!(alone.next.is_none());
    }

    #[test]
    fn route_with_failures_skips_failed_models_and_never_returns_them() {
        let pool = pool_of(vec![
            model("a", WorkClass::Edit, 0, 1, 1),
            model("b", WorkClass::Edit, 1, 10, 10),
            model("c", WorkClass::Edit, 2, 100, 100),
        ]);
        let a = FailureEvidence::for_kind(FailureKind::Failure, "a", 1, 5);
        let b = FailureEvidence::for_kind(FailureKind::Timeout, "b", 1, 9);
        let c = FailureEvidence::for_kind(FailureKind::Refusal, "c", 1, 90);

        let after_a = route_with_failures(&pool, &edit(), &Overrides::default(), std::slice::from_ref(&a))
            .expect("b is eligible");
        assert_eq!(after_a.chosen.model, "b");
        assert!(after_a.reason.contains("previously failed"), "{}", after_a.reason);

        let after_ab = route_with_failures(
            &pool,
            &edit(),
            &Overrides::default(),
            &[a.clone(), b.clone()],
        )
        .expect("c is eligible");
        assert_eq!(after_ab.chosen.model, "c");

        let all = [a, b, c];
        let error = route_with_failures(&pool, &edit(), &Overrides::default(), &all)
            .expect_err("every model failed");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains("previously_failed=3"), "{}", error.message());
        assert!(error.message().contains("previously failed: a, b, c"), "{}", error.message());
        assert!(!error.message().contains("model a is chosen"), "{}", error.message());
    }

    #[test]
    fn ties_and_ordering_are_deterministic() {
        let pool = pool_of(vec![
            model("zzz", WorkClass::Edit, 0, 10, 10),
            model("aaa", WorkClass::Edit, 0, 10, 10),
            model("mmm", WorkClass::Edit, 0, 5, 5),
        ]);
        let ordered: Vec<&str> = pool.ordered().iter().map(|entry| entry.model.as_str()).collect();
        assert_eq!(ordered, vec!["mmm", "aaa", "zzz"]);

        let first = route(&pool, &edit(), &Overrides::default(), None, TOKENS).expect("route");
        let second = route(&pool, &edit(), &Overrides::default(), None, TOKENS).expect("route");
        assert_eq!(first, second);
        assert_eq!(first.chosen.model, "mmm");

        let tied = pool_of(vec![
            model("zzz", WorkClass::Edit, 0, 10, 10),
            model("aaa", WorkClass::Edit, 0, 10, 10),
        ]);
        let decision = route(&tied, &edit(), &Overrides::default(), None, TOKENS).expect("route");
        assert_eq!(decision.chosen.model, "aaa");
        assert_eq!(decision.alternatives, vec!["zzz".to_owned()]);
    }

    #[test]
    fn failure_evidence_carries_no_prompt_text() {
        let canonical = FailureEvidence::for_kind(FailureKind::Timeout, "b", 3, 42);
        assert_eq!(canonical.message_summary, "provider call timed out");
        assert_eq!(canonical.message_summary, FailureKind::Timeout.summary());

        let long = format!(
            "please fix the very secret prompt\n{}",
            "x".repeat(10_000)
        );
        let evidence = FailureEvidence::new(FailureKind::Failure, "a", 1, &long, 5);
        assert!(evidence.message_summary.chars().count() <= FailureEvidence::MAX_SUMMARY_CHARS);
        assert!(!evidence.message_summary.contains('\n'));
        assert!(!evidence.message_summary.contains('\r'));

        let value = serde_json::to_value(&evidence).expect("evidence serialises");
        let object = value.as_object().expect("evidence is an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["attempts", "cost_micros", "kind", "message_summary", "model"]
        );
        for forbidden in ["prompt", "content", "messages", "transcript"] {
            assert!(object.get(forbidden).is_none(), "evidence exposed {forbidden}");
        }

        let empty = FailureEvidence::new(FailureKind::Refusal, "b", 1, "   \n\t ", 0);
        assert_eq!(empty.message_summary, "model refused the request");
    }

    #[test]
    fn pool_rejects_duplicate_ids_and_missing_grades() {
        let duplicated = model("dup", WorkClass::Edit, 0, 1, 1);
        let error = Pool::new(vec![duplicated.clone(), duplicated]).expect_err("duplicate id");
        assert_eq!(error.code(), ErrorCode::AlreadyExists);
        assert!(error.message().contains("duplicate"), "{}", error.message());

        let mut missing = model("missing", WorkClass::Edit, 0, 1, 1);
        missing.grades = ModelGrades { model: "missing".to_owned(), grades: BTreeMap::new() };
        let error = Pool::new(vec![missing]).expect_err("missing grades");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("grades"), "{}", error.message());

        let mut mismatched = model("right", WorkClass::Edit, 0, 1, 1);
        mismatched.grades.model = "other".to_owned();
        let error = Pool::new(vec![mismatched]).expect_err("mismatched ids");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("must match"), "{}", error.message());

        assert!(Pool::default().is_empty());
        assert_eq!(Pool::default().len(), 0);
    }
}
