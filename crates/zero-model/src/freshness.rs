//! Model data freshness: a versioned snapshot, a freshness policy, a route-time
//! gate, and a refresh with a drift report (T-MDL-08, MDL-15, MDL-01).
//!
//! The router ([`crate::router`]) trusts the pool it is handed. A table fetched
//! once and never refreshed keeps routing on a price, an availability flag, or a
//! deprecation that is no longer true, and it does so silently. This module puts
//! the snapshot's provenance and age in front of routing:
//!
//! 1. [`ModelData`] records the schema version, the table version, the source (a
//!    URL or a documented offline label such as `offline:seed`), the fetch time
//!    in milliseconds, and the [`PoolModel`] entries. [`ModelData::new`] rejects
//!    duplicate ids, an empty source, and an impossible timestamp.
//! 2. [`FreshnessPolicy`] sets `max_age_ms` (warn after it) and `hard_expiry_ms`
//!    (refuse after it). [`freshness`] (default policy) and [`freshness_with`]
//!    (configured policy) classify a snapshot as [`Freshness::Fresh`], `Stale`,
//!    or `Expired`.
//! 3. [`gate`] is the route-time gate: fresh passes silently, stale passes with
//!    a warning naming the source and age, expired is `zero.fnd.unavailable`
//!    naming the source and asking for a refresh.
//! 4. [`refresh`] fetches a new table from an injectable [`RefreshSource`],
//!    records the source label and fetch time, bumps the table version, and
//!    returns a [`RefreshReport`] whose [`Drift`] lists added, removed, and
//!    changed models.
//! 5. [`route_fresh`] wraps [`router::route`]: it gates the table first and
//!    returns the decision with the stale warning attached. **A caller that has
//!    a [`FreshnessPolicy`] must route through `route_fresh`**, never through
//!    `router::route` directly, so a stale table never routes silently.
//!
//! There is no network here. [`RefreshSource`] is a trait, so a scheduler wires
//! the real fetch and a test injects a fixed table. Ages are computed with
//! `now_ms.saturating_sub(fetched_ms)`, so a clock that moves backwards reads as
//! age 0 rather than as a huge age.

use crate::classify::Classification;
use crate::router::{self, Overrides, Pool, PoolModel, RouteDecision};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// The documented default freshness limit: 24 hours.
pub const DEFAULT_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1_000;

/// The documented default hard expiry: 7 days (seven times the freshness limit).
pub const DEFAULT_HARD_EXPIRY_MS: u64 = 7 * DEFAULT_MAX_AGE_MS;

/// The latest plausible fetch time: 3000-01-01T00:00:00Z in milliseconds.
///
/// [`ModelData::validate`] rejects anything later as an impossible timestamp.
pub const MAX_TIMESTAMP_MS: u64 = 32_503_680_000_000;

/// One versioned snapshot of the model table (MDL-01 data, MDL-15 provenance).
///
/// The snapshot is what the router reads. Its `source` is mandatory because a
/// table with no recorded origin cannot be refreshed, audited, or blamed for a
/// bad route. `fetched_ms` is the wall-clock fetch time in milliseconds since
/// the Unix epoch; it is what [`freshness_with`] ages against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelData {
    /// Schema version of the snapshot format. Starts at 1.
    pub schema_version: u32,
    /// Table version, bumped by every accepted [`refresh`].
    pub table_version: u64,
    /// Where the table came from: a URL, or a documented offline source label
    /// such as `offline:seed`. Must not be blank.
    pub source: String,
    /// When the table was fetched, in milliseconds since the Unix epoch.
    pub fetched_ms: u64,
    /// The models in the table, in source order.
    pub models: Vec<PoolModel>,
}

impl ModelData {
    /// Validate and build a snapshot.
    ///
    /// Rejects, in this order: a blank `source` (`zero.fnd.invalid_input`); a
    /// `schema_version` of 0 (`zero.fnd.invalid_input`); a `fetched_ms` of 0 or
    /// later than [`MAX_TIMESTAMP_MS`] (`zero.fnd.invalid_input`); an empty
    /// model id (`zero.fnd.invalid_input`); and a duplicate model id
    /// (`zero.fnd.already_exists`).
    pub fn new(
        schema_version: u32,
        table_version: u64,
        source: impl Into<String>,
        fetched_ms: u64,
        models: Vec<PoolModel>,
    ) -> Result<Self> {
        let data = Self {
            schema_version,
            table_version,
            source: source.into(),
            fetched_ms,
            models,
        };
        data.validate()?;
        Ok(data)
    }

    /// Re-check a snapshot, however it was built.
    ///
    /// A struct literal or a deserialized `ModelData` bypasses [`Self::new`],
    /// so anything loaded from storage or read from the wire is validated
    /// again before it is gated or routed on.
    pub fn validate(&self) -> Result<()> {
        if self.source.trim().is_empty() {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "model data has an empty source; record the URL or a documented offline source label",
            ));
        }
        if self.schema_version == 0 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "model data has schema version 0; snapshot schema versions start at 1",
            ));
        }
        if self.fetched_ms == 0 || self.fetched_ms > MAX_TIMESTAMP_MS {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!(
                    "model data fetch time {} ms is impossible; it must be a positive timestamp no later than {MAX_TIMESTAMP_MS} ms (year 3000)",
                    self.fetched_ms
                ),
            ));
        }
        let mut seen = BTreeSet::new();
        for model in &self.models {
            if model.model.trim().is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    "model data has an entry with an empty model id",
                ));
            }
            if !seen.insert(model.model.as_str()) {
                return Err(ZeroError::new(
                    ErrorCode::AlreadyExists,
                    format!(
                        "duplicate model id {:?} in the model data; ids must be unique",
                        model.model
                    ),
                ));
            }
        }
        Ok(())
    }

    /// The router pool for this snapshot.
    ///
    /// The snapshot is validated again and the models are rebuilt through
    /// [`Pool::new`], which also rejects a missing grade map or a grade set for
    /// a different model id. The pool owns its entries, so this clones the
    /// table; routing needs an owned [`Pool`] anyway.
    pub fn pool(&self) -> Result<Pool> {
        self.validate()?;
        Pool::new(self.models.clone())
    }
}

/// When a snapshot is too old to trust (MDL-15).
///
/// `max_age_ms` is the warn threshold: a snapshot older than it still routes,
/// but the caller is told. `hard_expiry_ms` is the refuse threshold: a snapshot
/// older than it does not route at all. The default is
/// [`DEFAULT_MAX_AGE_MS`] / [`DEFAULT_HARD_EXPIRY_MS`] (24 hours / 7 days).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessPolicy {
    pub max_age_ms: u64,
    pub hard_expiry_ms: u64,
}

impl FreshnessPolicy {
    /// Validate and build a policy.
    ///
    /// `hard_expiry_ms` must not be before `max_age_ms`: a hard expiry inside
    /// the fresh window would make the stale state unreachable and is a
    /// configuration bug, so it is `zero.fnd.invalid_input`. Equal thresholds
    /// are allowed: every stale age is expired, so there is no warn-only window.
    pub fn new(max_age_ms: u64, hard_expiry_ms: u64) -> Result<Self> {
        if hard_expiry_ms < max_age_ms {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!(
                    "hard expiry {hard_expiry_ms} ms is before the {max_age_ms} ms freshness limit; a stale window that cannot occur is a configuration bug"
                ),
            ));
        }
        Ok(Self { max_age_ms, hard_expiry_ms })
    }
}

impl Default for FreshnessPolicy {
    /// The documented default: fresh for 24 hours, warn until 7 days, refuse
    /// after that.
    fn default() -> Self {
        Self {
            max_age_ms: DEFAULT_MAX_AGE_MS,
            hard_expiry_ms: DEFAULT_HARD_EXPIRY_MS,
        }
    }
}

/// The age classification of a snapshot.
///
/// `age_ms` is monotonic and clamped at 0, and `source` is copied from the
/// snapshot so the caller can name the table it is about to trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// At or inside `max_age_ms`.
    Fresh,
    /// Past `max_age_ms` but at or inside `hard_expiry_ms`: usable with a
    /// warning.
    Stale { age_ms: u64, source: String },
    /// Past `hard_expiry_ms`: refuse to route on it.
    Expired { age_ms: u64, source: String },
}

/// Classify a snapshot under the documented default policy.
///
/// A caller with a configured [`FreshnessPolicy`] uses [`freshness_with`].
pub fn freshness(data: &ModelData, now_ms: u64) -> Freshness {
    freshness_with(data, &FreshnessPolicy::default(), now_ms)
}

/// Classify a snapshot at `now_ms` under `policy`.
///
/// Boundaries are inclusive: an age equal to `max_age_ms` is still
/// [`Freshness::Fresh`], and an age equal to `hard_expiry_ms` is still
/// [`Freshness::Stale`]. A `now_ms` before `fetched_ms` clamps to age 0.
pub fn freshness_with(data: &ModelData, policy: &FreshnessPolicy, now_ms: u64) -> Freshness {
    let age_ms = now_ms.saturating_sub(data.fetched_ms);
    if age_ms <= policy.max_age_ms {
        Freshness::Fresh
    } else if age_ms <= policy.hard_expiry_ms {
        Freshness::Stale { age_ms, source: data.source.clone() }
    } else {
        Freshness::Expired { age_ms, source: data.source.clone() }
    }
}

/// A gated snapshot and the warning the caller must surface, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// The snapshot that passed the gate.
    pub data: ModelData,
    /// `Some` only for a stale snapshot. Names the source and the age.
    pub warning: Option<String>,
}

/// Decide whether a snapshot may be routed on (T-MDL-08).
///
/// - [`Freshness::Fresh`] passes with no warning.
/// - [`Freshness::Stale`] passes with a warning naming the source and age, so a
///   stale table is never used silently.
/// - [`Freshness::Expired`] is `zero.fnd.unavailable` naming the source and
///   asking for a refresh; nothing is routed.
///
/// The snapshot is validated first, so an invalid table cannot pass by having a
/// recent timestamp.
pub fn gate(data: &ModelData, policy: &FreshnessPolicy, now_ms: u64) -> Result<GateResult> {
    data.validate()?;
    match freshness_with(data, policy, now_ms) {
        Freshness::Fresh => Ok(GateResult { data: data.clone(), warning: None }),
        Freshness::Stale { age_ms, source } => Ok(GateResult {
            data: data.clone(),
            warning: Some(format!(
                "model data source {source:?} is stale: age {age_ms} ms exceeds the {} ms freshness limit; a refresh is due and routing continues with this table in the meantime",
                policy.max_age_ms
            )),
        }),
        Freshness::Expired { age_ms, source } => Err(ZeroError::new(
            ErrorCode::Unavailable,
            format!(
                "model data source {source:?} expired: age {age_ms} ms exceeds the {} ms hard expiry; refresh the model data from {source:?} before routing",
                policy.hard_expiry_ms
            ),
        )),
    }
}

/// A source a scheduler can refresh the table from (MDL-15).
///
/// The trait is injectable on purpose: production wires an HTTP fetch, while a
/// test supplies a fixed table. Nothing in this module opens a socket, so a
/// refresh can be exercised without network access.
pub trait RefreshSource {
    /// Fetch the current table. An error aborts the refresh and changes nothing.
    fn fetch(&self) -> Result<Vec<PoolModel>>;
}

/// One model whose routing fields changed between two tables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftChange {
    /// The model id.
    pub model: String,
    /// Changed fields in this fixed order: `available`, `deprecated`, `grades`,
    /// `input_cost_micros_per_mtok`, `output_cost_micros_per_mtok`, `provider`,
    /// `tier`. Never empty (an unchanged model produces no entry).
    pub fields: Vec<String>,
}

/// What a refresh changed (MDL-15).
///
/// Ordering is deterministic: `added` and `removed` are model ids in ascending
/// order, and `changed` is in ascending model-id order with each `fields` list
/// in the documented field order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drift {
    /// Models present only in the new table.
    pub added: Vec<String>,
    /// Models present only in the old table.
    pub removed: Vec<String>,
    /// Models present in both whose fields differ.
    pub changed: Vec<DriftChange>,
    /// The old table version.
    pub table_version_from: u64,
    /// The new table version.
    pub table_version_to: u64,
}

/// The result of a refresh: the new snapshot and what changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshReport {
    /// The new snapshot: new source label, new fetch time, bumped table version.
    pub data: ModelData,
    /// The difference from the previous snapshot.
    pub drift: Drift,
}

/// The changed fields of one model, in the documented field order.
fn changed_fields(before: &PoolModel, after: &PoolModel) -> Vec<String> {
    let mut fields = Vec::new();
    if before.available != after.available {
        fields.push("available".to_owned());
    }
    if before.deprecated != after.deprecated {
        fields.push("deprecated".to_owned());
    }
    if before.grades.grades != after.grades.grades {
        fields.push("grades".to_owned());
    }
    if before.input_cost_micros_per_mtok != after.input_cost_micros_per_mtok {
        fields.push("input_cost_micros_per_mtok".to_owned());
    }
    if before.output_cost_micros_per_mtok != after.output_cost_micros_per_mtok {
        fields.push("output_cost_micros_per_mtok".to_owned());
    }
    if before.provider != after.provider {
        fields.push("provider".to_owned());
    }
    if before.tier != after.tier {
        fields.push("tier".to_owned());
    }
    fields
}

/// Compare two snapshots.
///
/// A model is added or removed by id. A model in both is changed when any of
/// its routing fields differs; the field list is fixed order, so the report is
/// byte-for-byte deterministic. Deprecation, availability, cost, and grade
/// changes are all listed.
pub fn drift(from: &ModelData, to: &ModelData) -> Drift {
    let before: BTreeMap<&str, &PoolModel> =
        from.models.iter().map(|model| (model.model.as_str(), model)).collect();
    let after: BTreeMap<&str, &PoolModel> =
        to.models.iter().map(|model| (model.model.as_str(), model)).collect();

    let mut ids: Vec<&str> = before.keys().copied().chain(after.keys().copied()).collect();
    ids.sort_unstable();
    ids.dedup();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    for id in ids {
        match (before.get(id), after.get(id)) {
            (None, Some(_)) => added.push(id.to_owned()),
            (Some(_), None) => removed.push(id.to_owned()),
            (Some(old), Some(new)) => {
                let fields = changed_fields(old, new);
                if !fields.is_empty() {
                    changed.push(DriftChange { model: id.to_owned(), fields });
                }
            }
            (None, None) => {}
        }
    }

    Drift {
        added,
        removed,
        changed,
        table_version_from: from.table_version,
        table_version_to: to.table_version,
    }
}

/// Refresh the table from `source` and report the drift (T-MDL-08).
///
/// The fetched models are validated through [`ModelData::new`]: the new
/// snapshot keeps `current.schema_version`, records `source_label` and
/// `now_ms`, and sets `table_version` to `current.table_version + 1`
/// (saturating). An empty `source_label` is `zero.fnd.invalid_input`, a fetch
/// error is returned unchanged, and in either case nothing is recorded.
pub fn refresh(
    current: &ModelData,
    source: &dyn RefreshSource,
    source_label: &str,
    now_ms: u64,
) -> Result<RefreshReport> {
    let models = source.fetch()?;
    let table_version = current.table_version.saturating_add(1);
    let data = ModelData::new(current.schema_version, table_version, source_label, now_ms, models)?;
    let drift = drift(current, &data);
    Ok(RefreshReport { data, drift })
}

/// True when the table is past `max_age_ms` but not yet past `hard_expiry_ms`.
///
/// This is the state a refresh should fix: routing still works, but only with a
/// warning. An expired table is worse than stale, so it is not "merely stale".
pub fn is_stale_and_unrefreshed(
    data: &ModelData,
    policy: &FreshnessPolicy,
    now_ms: u64,
) -> bool {
    matches!(freshness_with(data, policy, now_ms), Freshness::Stale { .. })
}

/// True when a scheduled refresh is due: the table is stale or expired.
pub fn needs_refresh(data: &ModelData, policy: &FreshnessPolicy, now_ms: u64) -> bool {
    !matches!(freshness_with(data, policy, now_ms), Freshness::Fresh)
}

/// Route on a gated snapshot (T-MDL-08).
///
/// This wraps [`router::route`] so the table is gated before any model is
/// considered:
///
/// - fresh: the decision, with no warning;
/// - stale: the decision, with a warning naming the source and age. The warning
///   is returned in the tuple **and** appended to
///   [`RouteDecision::warnings`], so a caller that already prints router
///   warnings cannot drop it;
/// - expired: `zero.fnd.unavailable` naming the source and asking for a
///   refresh. No decision is produced.
///
/// A caller with a [`FreshnessPolicy`] must use this function rather than
/// `router::route`; `route` itself has no age input and cannot warn.
pub fn route_fresh(
    data: &ModelData,
    policy: &FreshnessPolicy,
    classification: &Classification,
    overrides: &Overrides,
    budget_micros: Option<u64>,
    estimate_tokens: u64,
    now_ms: u64,
) -> Result<(RouteDecision, Option<String>)> {
    let gated = gate(data, policy, now_ms)?;
    let pool = gated.data.pool()?;
    let mut decision =
        router::route(&pool, classification, overrides, budget_micros, estimate_tokens)?;
    if let Some(warning) = &gated.warning {
        decision.warnings.push(warning.clone());
    }
    Ok((decision, gated.warning))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{self, Capability, Grade, ModelGrades, TaskSignals, WorkClass};

    const HOUR: u64 = 3_600_000;
    const BASE_NOW: u64 = 1_700_000_000_000;
    const SOURCE: &str = "https://example.test/models.json";

    fn grades(name: &str, class: WorkClass) -> ModelGrades {
        ModelGrades { model: name.to_owned(), grades: classify::floor_for(class).minimums }
    }

    fn model(name: &str) -> PoolModel {
        PoolModel {
            model: name.to_owned(),
            provider: "test".to_owned(),
            grades: grades(name, WorkClass::Edit),
            input_cost_micros_per_mtok: 5,
            output_cost_micros_per_mtok: 5,
            available: true,
            deprecated: false,
            tier: 0,
        }
    }

    fn table_at(fetched_ms: u64, models: Vec<PoolModel>) -> ModelData {
        ModelData::new(1, 7, SOURCE, fetched_ms, models).expect("valid snapshot")
    }

    fn policy() -> FreshnessPolicy {
        // Two hours fresh, six hours until refusal.
        FreshnessPolicy { max_age_ms: 2 * HOUR, hard_expiry_ms: 6 * HOUR }
    }

    fn edit() -> Classification {
        classify::classify(&TaskSignals { files_changed: 1, ..TaskSignals::default() })
    }

    /// An injected source: no network, one fixed answer.
    struct Fixed(Vec<PoolModel>);

    impl RefreshSource for Fixed {
        fn fetch(&self) -> Result<Vec<PoolModel>> {
            Ok(self.0.clone())
        }
    }

    struct Failing;

    impl RefreshSource for Failing {
        fn fetch(&self) -> Result<Vec<PoolModel>> {
            Err(ZeroError::new(ErrorCode::Unavailable, "the refresh endpoint is offline"))
        }
    }

    #[test]
    fn freshness_boundaries_are_inclusive_and_ages_clamp() {
        let data = table_at(BASE_NOW, vec![model("a")]);
        let policy = policy();

        assert_eq!(freshness_with(&data, &policy, BASE_NOW), Freshness::Fresh);
        assert_eq!(
            freshness_with(&data, &policy, BASE_NOW + 2 * HOUR),
            Freshness::Fresh,
            "an age exactly at max_age_ms is still fresh"
        );

        match freshness_with(&data, &policy, BASE_NOW + 2 * HOUR + 1) {
            Freshness::Stale { age_ms, source } => {
                assert_eq!(age_ms, 2 * HOUR + 1);
                assert_eq!(source, SOURCE);
            }
            other => panic!("expected stale, got {other:?}"),
        }

        match freshness_with(&data, &policy, BASE_NOW + 6 * HOUR) {
            Freshness::Stale { age_ms, .. } => {
                assert_eq!(age_ms, 6 * HOUR, "an age exactly at hard_expiry_ms is still stale")
            }
            other => panic!("expected stale, got {other:?}"),
        }

        match freshness_with(&data, &policy, BASE_NOW + 6 * HOUR + 1) {
            Freshness::Expired { age_ms, source } => {
                assert_eq!(age_ms, 6 * HOUR + 1);
                assert_eq!(source, SOURCE);
            }
            other => panic!("expected expired, got {other:?}"),
        }

        // A clock before the fetch clamps to age 0, and age 0 is fresh.
        assert_eq!(freshness_with(&data, &policy, BASE_NOW - 5 * HOUR), Freshness::Fresh);
        assert_eq!(freshness_with(&data, &policy, 0), Freshness::Fresh);

        // The convenience function uses the documented default policy.
        assert_eq!(
            FreshnessPolicy::default(),
            FreshnessPolicy {
                max_age_ms: DEFAULT_MAX_AGE_MS,
                hard_expiry_ms: DEFAULT_HARD_EXPIRY_MS,
            }
        );
        assert_eq!(freshness(&data, BASE_NOW + DEFAULT_MAX_AGE_MS), Freshness::Fresh);
        match freshness(&data, BASE_NOW + DEFAULT_HARD_EXPIRY_MS) {
            Freshness::Stale { age_ms, .. } => assert_eq!(age_ms, DEFAULT_HARD_EXPIRY_MS),
            other => panic!("expected stale, got {other:?}"),
        }
        match freshness(&data, BASE_NOW + DEFAULT_HARD_EXPIRY_MS + 1) {
            Freshness::Expired { .. } => {}
            other => panic!("expected expired, got {other:?}"),
        }
    }

    #[test]
    fn policy_rejects_hard_expiry_before_max_age() {
        FreshnessPolicy::new(HOUR, HOUR).expect("equal thresholds leave no warn-only window");
        let error = FreshnessPolicy::new(2 * HOUR, HOUR).expect_err("hard expiry inside the window");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("hard expiry"), "{}", error.message());
    }

    #[test]
    fn a_stale_table_warns_with_its_source_and_age() {
        let data = table_at(BASE_NOW, vec![model("a")]);

        let fresh = gate(&data, &policy(), BASE_NOW + HOUR).expect("a fresh table gates");
        assert_eq!(fresh.data, data);
        assert!(fresh.warning.is_none());

        let stale =
            gate(&data, &policy(), BASE_NOW + 3 * HOUR).expect("a stale table still gates");
        let warning = stale.warning.expect("stale must warn, never silently");
        assert!(warning.contains(SOURCE), "{warning}");
        assert!(warning.contains(&format!("age {} ms", 3 * HOUR)), "{warning}");
        assert!(warning.contains("max_age_ms") || warning.contains("freshness limit"), "{warning}");
    }

    #[test]
    fn an_expired_table_is_refused_with_a_refresh_request() {
        let data = table_at(BASE_NOW, vec![model("a")]);
        let error = gate(&data, &policy(), BASE_NOW + 7 * HOUR)
            .expect_err("an expired table must not route");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains(SOURCE), "{}", error.message());
        assert!(error.message().contains("expired"), "{}", error.message());
        assert!(error.message().contains("refresh"), "{}", error.message());
        assert!(error.message().contains(&format!("age {} ms", 7 * HOUR)), "{}", error.message());
    }

    #[test]
    fn refresh_records_the_source_and_time_and_reports_drift() {
        let current = table_at(
            BASE_NOW,
            vec![model("keep"), model("gone"), model("edit"), model("flip")],
        );

        let mut edited = model("edit");
        edited.deprecated = true;
        edited.input_cost_micros_per_mtok = 9;
        edited.grades.grades.insert(Capability::Coding, Grade::new(5));

        let mut flipped = model("flip");
        flipped.available = false;

        let now = BASE_NOW + 30 * HOUR;
        let report = refresh(
            &current,
            &Fixed(vec![model("keep"), edited, flipped, model("added")]),
            "offline:seed-fixture",
            now,
        )
        .expect("refresh succeeds");

        assert_eq!(report.data.source, "offline:seed-fixture");
        assert_eq!(report.data.fetched_ms, now);
        assert_eq!(report.data.schema_version, current.schema_version);
        assert_eq!(report.data.table_version, current.table_version + 1);
        assert_eq!(report.data.models.len(), 4);

        assert_eq!(report.drift.added, vec!["added".to_owned()]);
        assert_eq!(report.drift.removed, vec!["gone".to_owned()]);
        assert_eq!(report.drift.table_version_from, current.table_version);
        assert_eq!(report.drift.table_version_to, report.data.table_version);

        // Changed models are ordered by id; fields are in the fixed order.
        assert_eq!(report.drift.changed.len(), 2, "{:?}", report.drift.changed);
        assert_eq!(report.drift.changed[0].model, "edit");
        assert_eq!(
            report.drift.changed[0].fields,
            vec!["deprecated", "grades", "input_cost_micros_per_mtok"]
        );
        assert_eq!(report.drift.changed[1].model, "flip");
        assert_eq!(report.drift.changed[1].fields, vec!["available"]);

        let unchanged = drift(&current, &report.data);
        assert_eq!(unchanged, report.drift);

        // A fetch error changes nothing.
        let error = refresh(&current, &Failing, "offline:seed", now).expect_err("fetch failed");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains("offline"), "{}", error.message());

        // An empty source label is refused; a table with no origin is not a snapshot.
        let error = refresh(&current, &Fixed(vec![model("keep")]), "   ", now)
            .expect_err("empty source label");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("source"), "{}", error.message());
    }

    #[test]
    fn drift_order_is_deterministic() {
        let current = table_at(
            BASE_NOW,
            vec![
                model("z-removed"),
                model("m-removed"),
                model("a-changed"),
                model("z-changed"),
            ],
        );

        let mut z_changed = model("z-changed");
        z_changed.tier = 3;
        let mut a_changed = model("a-changed");
        a_changed.output_cost_micros_per_mtok = 70;
        let next = vec![model("z-added"), model("b-added"), z_changed, a_changed];

        let first = refresh(&current, &Fixed(next.clone()), SOURCE, BASE_NOW + HOUR)
            .expect("first refresh");
        let second = refresh(&current, &Fixed(next), SOURCE, BASE_NOW + HOUR)
            .expect("second refresh");
        assert_eq!(first, second, "the same inputs produce the same report");

        assert_eq!(first.drift.added, vec!["b-added", "z-added"]);
        assert_eq!(first.drift.removed, vec!["m-removed", "z-removed"]);
        let changed: Vec<&str> =
            first.drift.changed.iter().map(|change| change.model.as_str()).collect();
        assert_eq!(changed, vec!["a-changed", "z-changed"]);
        assert_eq!(first.drift.changed[0].fields, vec!["output_cost_micros_per_mtok"]);
        assert_eq!(first.drift.changed[1].fields, vec!["tier"]);
        assert_eq!(drift(&current, &first.data), first.drift);
    }

    #[test]
    fn model_data_rejects_duplicates_empty_source_and_impossible_timestamps() {
        let duplicated = model("dup");
        let error = ModelData::new(1, 1, SOURCE, BASE_NOW, vec![duplicated.clone(), duplicated])
            .expect_err("duplicate ids");
        assert_eq!(error.code(), ErrorCode::AlreadyExists);
        assert!(error.message().contains("duplicate"), "{}", error.message());

        let error =
            ModelData::new(1, 1, "   ", BASE_NOW, vec![]).expect_err("an empty source is invalid");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("source"), "{}", error.message());

        let error =
            ModelData::new(1, 1, "offline:seed", 0, vec![]).expect_err("epoch zero is impossible");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("impossible"), "{}", error.message());

        let error = ModelData::new(1, 1, "offline:seed", MAX_TIMESTAMP_MS + 1, vec![])
            .expect_err("past year 3000 is impossible");
        assert_eq!(error.code(), ErrorCode::InvalidInput);

        ModelData::new(1, 1, "offline:seed", MAX_TIMESTAMP_MS, vec![])
            .expect("the documented offline label and the upper bound are accepted");

        // A struct literal that skipped the constructor is caught by validate.
        let bypassed = ModelData {
            schema_version: 1,
            table_version: 1,
            source: String::new(),
            fetched_ms: BASE_NOW,
            models: vec![],
        };
        assert_eq!(bypassed.validate().unwrap_err().code(), ErrorCode::InvalidInput);
        assert!(bypassed.pool().is_err());

        // A bypassed duplicate id is also caught before it can be routed on.
        let dup_two = ModelData {
            schema_version: 1,
            table_version: 1,
            source: SOURCE.to_owned(),
            fetched_ms: BASE_NOW,
            models: vec![model("dup"), model("dup")],
        };
        assert_eq!(dup_two.validate().unwrap_err().code(), ErrorCode::AlreadyExists);
    }

    #[test]
    fn route_fresh_warns_on_a_stale_table_and_refuses_an_expired_one() {
        let data = table_at(BASE_NOW, vec![model("a"), model("b")]);

        let (stale_decision, warning) = route_fresh(
            &data,
            &policy(),
            &edit(),
            &Overrides::default(),
            None,
            1_000_000,
            BASE_NOW + 3 * HOUR,
        )
        .expect("a stale table still routes, with a warning");
        assert_eq!(stale_decision.chosen.model, "a");
        let warning = warning.expect("stale routing is never silent");
        assert!(warning.contains(SOURCE), "{warning}");
        assert!(
            stale_decision.warnings.iter().any(|w| w == &warning),
            "the decision carries the stale warning: {:?}",
            stale_decision.warnings
        );

        let (fresh_decision, fresh_warning) = route_fresh(
            &data,
            &policy(),
            &edit(),
            &Overrides::default(),
            None,
            1_000_000,
            BASE_NOW + HOUR,
        )
        .expect("a fresh table routes");
        assert!(fresh_warning.is_none());
        assert!(fresh_decision.warnings.is_empty());
        assert_eq!(fresh_decision.chosen.model, "a");

        let error = route_fresh(
            &data,
            &policy(),
            &edit(),
            &Overrides::default(),
            None,
            1_000_000,
            BASE_NOW + 7 * HOUR,
        )
        .expect_err("an expired table refuses to route");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains(SOURCE), "{}", error.message());
        assert!(error.message().contains("refresh"), "{}", error.message());
    }

    #[test]
    fn refresh_helpers_track_staleness() {
        let data = table_at(BASE_NOW, vec![model("a")]);
        let policy = policy();

        assert!(!needs_refresh(&data, &policy, BASE_NOW + 2 * HOUR));
        assert!(!is_stale_and_unrefreshed(&data, &policy, BASE_NOW + 2 * HOUR));

        assert!(needs_refresh(&data, &policy, BASE_NOW + 2 * HOUR + 1));
        assert!(is_stale_and_unrefreshed(&data, &policy, BASE_NOW + 2 * HOUR + 1));

        assert!(needs_refresh(&data, &policy, BASE_NOW + 6 * HOUR + 1));
        assert!(
            !is_stale_and_unrefreshed(&data, &policy, BASE_NOW + 6 * HOUR + 1),
            "an expired table is worse than stale, not merely stale"
        );
    }
}
