//! Outcome records, evidence-based (measured) routing, cost reconciliation, and
//! budget preflight (T-MDL-07; MDL-08, MDL-09).
//!
//! The router ([`crate::router`]) picks the cheapest eligible model; this module
//! lets recorded outcomes change that choice, but only with evidence:
//!
//! 1. [`Outcome`] is one recorded call: the model, the work class, success,
//!    retries, latency, cost, and the wall-clock time. [`OutcomeLog`] is a
//!    bounded in-memory store with an optional JSONL file behind it. Records are
//!    deduplicated by [`Outcome::stable_id`].
//! 2. [`ModelStats`] aggregates outcomes per `(model, class)` inside a time
//!    window: sample count, successes, retries, average latency, average cost,
//!    and the success rate in basis points.
//! 3. [`MeasuredPolicy`] sets the evidence rules: `min_samples`, `explore_bps`,
//!    `min_improvement_bps`, and `window_ms`.
//! 4. [`choose`] returns a [`MeasuredChoice`]. With too little evidence it keeps
//!    the fallback. With enough evidence it switches only when the best
//!    candidate beats the fallback by the configured margin; ties break on
//!    lower cost, then lower latency, then model id. A seeded exploration rate
//!    tries a non-best measured model when no switch is warranted.
//! 5. [`reconcile`] compares a predicted cost with the actual cost,
//!    [`prediction_error`] reports the sampling error of a success rate, and
//!    [`preflight_budget`] refuses an over-budget dispatch before it happens.
//! 6. [`record_and_choose`] appends an outcome and then chooses, so the next
//!    turn already benefits from the sample.
//!
//! ## Routing changes only with evidence
//!
//! A model is a *measured* candidate only when its window has at least
//! `min_samples` samples; a candidate with no samples is never chosen as a
//! measured result. The fallback (the router's current choice) and exploration
//! are the documented exceptions: the fallback is the status quo, and
//! exploration deliberately tries a measured non-best model. Exploration never
//! overrides a switch that already cleared the improvement threshold.
//!
//! ## No class mixing
//!
//! Statistics are per `(model, class)`. [`choose`] takes the work class from the
//! fallback's stats when present (else from the first candidate) and ignores
//! candidates of any other class, so a strong plan model cannot win an edit
//! decision. Callers normally pass one class's stats from
//! [`OutcomeLog::stats`](OutcomeLog::stats).
//!
//! ## No prompt text
//!
//! Nothing here accepts prompt, message, or response content. [`Outcome`] and
//! [`ModelStats`] use `deny_unknown_fields`, so a planted `prompt` key makes a
//! JSONL line malformed instead of being stored. Reasons and errors name model
//! ids, classes, sample counts, costs, latencies, and basis points only.

use crate::classify::WorkClass;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// The default in-memory bound for [`OutcomeLog`].
pub const DEFAULT_MAX_OUTCOMES: usize = 100_000;

/// Hard upper bound for one outcome JSONL file.
///
/// The in-memory log is bounded separately. The file keeps the durable history
/// up to this size; rotate to a new file to continue past it.
pub const MAX_OUTCOME_LOG_BYTES: u64 = 16 * 1024 * 1024;

/// The default reconciliation tolerance: 2,000 basis points (20%).
pub const RECONCILIATION_TOLERANCE_BPS: u32 = 2_000;

/// The default stats window: seven days, matching the freshness hard expiry.
pub const DEFAULT_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// Basis points in one whole unit.
const BPS: u64 = 10_000;

/// One recorded model call (MDL-09).
///
/// The record stores routing facts only. There is deliberately no prompt,
/// response, message, or transcript field, and `deny_unknown_fields` rejects a
/// JSON line that tries to add one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    /// The model that served the call.
    pub model: String,
    /// The work class the call was routed as.
    pub class: WorkClass,
    /// Whether the call produced a usable result.
    pub success: bool,
    /// Retries spent before the result.
    pub retries: u32,
    /// Observed latency in milliseconds.
    pub latency_ms: u64,
    /// Actual cost in micros.
    pub cost_micros: u64,
    /// Wall-clock time of the observation in milliseconds since the Unix epoch.
    pub at_ms: i64,
}

impl Outcome {
    /// Build and validate one outcome.
    ///
    /// A blank model id or a negative timestamp is `zero.fnd.invalid_input`.
    pub fn new(
        model: impl Into<String>,
        class: WorkClass,
        success: bool,
        retries: u32,
        latency_ms: u64,
        cost_micros: u64,
        at_ms: i64,
    ) -> Result<Self> {
        let outcome = Self {
            model: model.into(),
            class,
            success,
            retries,
            latency_ms,
            cost_micros,
            at_ms,
        };
        outcome.validate()?;
        Ok(outcome)
    }

    /// Re-check an outcome, however it was built or loaded.
    pub fn validate(&self) -> Result<()> {
        if self.model.trim().is_empty() {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "outcome has an empty model id",
            ));
        }
        if self.at_ms < 0 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!(
                    "outcome for model {:?} has a negative timestamp {} ms; use milliseconds since the Unix epoch",
                    self.model, self.at_ms
                ),
            ));
        }
        Ok(())
    }

    /// The stable deduplication id.
    ///
    /// 64-bit FNV-1a over a length-prefixed encoding of every field. The id is
    /// stable across runs and platforms, so replaying the same outcome does not
    /// create a second sample. A hash collision is treated as a duplicate; at 64
    /// bits the risk is negligible for an outcome log.
    pub fn stable_id(&self) -> String {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in self.canonical().as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{hash:016x}")
    }

    /// An unambiguous encoding of every field.
    fn canonical(&self) -> String {
        format!(
            "{}:{}|{}:{}|{}|{}|{}|{}|{}",
            self.model.len(),
            self.model,
            self.class.as_str().len(),
            self.class.as_str(),
            self.success,
            self.retries,
            self.latency_ms,
            self.cost_micros,
            self.at_ms
        )
    }
}

/// Aggregated outcomes for one `(model, class)` inside a window (MDL-09).
///
/// Averages are integer floors of the summed samples. `success_rate_bps` is
/// `successes * 10_000 / samples`, so 10,000 bps is a perfect record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelStats {
    pub model: String,
    pub class: WorkClass,
    /// Samples inside the window.
    pub samples: u64,
    /// Samples that succeeded.
    pub successes: u64,
    /// Summed retries across the samples.
    pub retries: u64,
    pub avg_latency_ms: u64,
    pub avg_cost_micros: u64,
    /// Success rate in basis points (`0..=10_000`).
    pub success_rate_bps: u32,
}

/// Convert a success count to basis points. No samples is 0 bps.
fn rate_bps(successes: u64, samples: u64) -> u32 {
    if samples == 0 {
        return 0;
    }
    let bps = (u128::from(successes) * 10_000) / u128::from(samples);
    u32::try_from(bps).unwrap_or(10_000)
}

/// Integer square root. Newton's method on `u128`.
fn isqrt(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let mut x = value;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + value / x) / 2;
    }
    x
}

/// The sampling error of a success-rate estimate, in basis points.
///
/// This is the standard error of the binomial proportion,
/// `sqrt(success_rate_bps * (10_000 - success_rate_bps) / samples)`, rounded
/// down. It says how much an observed rate could move with a different sample,
/// so a caller can compare it with [`MeasuredPolicy::min_improvement_bps`]
/// before trusting a switch. Zero samples or a perfect record is 0.
pub fn prediction_error(stats: &ModelStats) -> u32 {
    if stats.samples == 0 {
        return 0;
    }
    let rate = u128::from(stats.success_rate_bps.min(10_000));
    let variance = (rate * (10_000 - rate)) / u128::from(stats.samples);
    u32::try_from(isqrt(variance)).unwrap_or(u32::MAX)
}

/// The in-window outcomes for one model while aggregating.
#[derive(Default)]
struct Aggregate {
    samples: u64,
    successes: u64,
    retries: u64,
    latency_ms: u64,
    cost_micros: u64,
}

/// Aggregate outcomes for one class inside `[now_ms - window_ms, now_ms]`.
///
/// Samples from another class are ignored (no class mixing), a timestamp later
/// than `now_ms` is ignored, and a negative window counts only a sample exactly
/// at `now_ms`. The result is ordered by model id, so it is deterministic.
fn aggregate<'a>(
    outcomes: impl Iterator<Item = &'a Outcome>,
    class: WorkClass,
    window_ms: i64,
    now_ms: i64,
) -> Vec<ModelStats> {
    let window_ms = window_ms.max(0);
    let mut by_model: BTreeMap<&str, Aggregate> = BTreeMap::new();
    for outcome in outcomes {
        if outcome.class != class || outcome.at_ms > now_ms {
            continue;
        }
        if now_ms.saturating_sub(outcome.at_ms) > window_ms {
            continue;
        }
        let entry = by_model.entry(outcome.model.as_str()).or_default();
        entry.samples = entry.samples.saturating_add(1);
        if outcome.success {
            entry.successes = entry.successes.saturating_add(1);
        }
        entry.retries = entry.retries.saturating_add(u64::from(outcome.retries));
        entry.latency_ms = entry.latency_ms.saturating_add(outcome.latency_ms);
        entry.cost_micros = entry.cost_micros.saturating_add(outcome.cost_micros);
    }
    by_model
        .into_iter()
        .map(|(model, aggregate)| ModelStats {
            model: model.to_owned(),
            class,
            samples: aggregate.samples,
            successes: aggregate.successes,
            retries: aggregate.retries,
            avg_latency_ms: aggregate.latency_ms / aggregate.samples,
            avg_cost_micros: aggregate.cost_micros / aggregate.samples,
            success_rate_bps: rate_bps(aggregate.successes, aggregate.samples),
        })
        .collect()
}

/// Aggregate a slice of outcomes for one class.
///
/// This is the free-function form of [`OutcomeLog::stats`], useful when the
/// caller already holds the outcomes.
pub fn model_stats(
    outcomes: &[Outcome],
    class: WorkClass,
    window_ms: i64,
    now_ms: i64,
) -> Vec<ModelStats> {
    aggregate(outcomes.iter(), class, window_ms, now_ms)
}

/// A bounded outcome store with an optional JSONL file (MDL-09).
///
/// The in-memory log keeps at most `max_entries` outcomes, evicting the oldest.
/// When a path is set, every accepted outcome is also appended as one JSON line,
/// flushed and fsynced. Duplicate outcomes (the same [`Outcome::stable_id`]) are
/// ignored rather than stored twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeLog {
    outcomes: VecDeque<Outcome>,
    ids: BTreeSet<String>,
    max_entries: usize,
    path: Option<PathBuf>,
}

impl Default for OutcomeLog {
    fn default() -> Self {
        Self::new()
    }
}

impl OutcomeLog {
    /// An empty in-memory log with the [`DEFAULT_MAX_OUTCOMES`] bound.
    pub fn new() -> Self {
        Self::with_max_entries(DEFAULT_MAX_OUTCOMES)
    }

    /// An empty in-memory log with an explicit bound (at least one entry).
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            outcomes: VecDeque::new(),
            ids: BTreeSet::new(),
            max_entries: max_entries.max(1),
            path: None,
        }
    }

    /// Load an existing JSONL log, or start an empty one, and keep the path.
    ///
    /// A missing file is an empty log. The reader is lenient: a line that is not
    /// a valid outcome is skipped, so a torn tail does not block recording. A
    /// file that is not UTF-8 is `zero.fnd.corrupt`.
    pub fn with_path(path: impl Into<PathBuf>) -> Result<Self> {
        Self::with_path_and_max_entries(path, DEFAULT_MAX_OUTCOMES)
    }

    /// [`Self::with_path`] with an explicit in-memory bound.
    pub fn with_path_and_max_entries(path: impl Into<PathBuf>, max_entries: usize) -> Result<Self> {
        let mut log = Self {
            outcomes: VecDeque::new(),
            ids: BTreeSet::new(),
            max_entries: max_entries.max(1),
            path: Some(path.into()),
        };
        log.load()?;
        Ok(log)
    }

    /// The backing JSONL path, when one is configured.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The in-memory bound.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// The outcomes currently held, oldest first.
    pub fn outcomes(&self) -> impl Iterator<Item = &Outcome> {
        self.outcomes.iter()
    }

    /// Number of outcomes held in memory.
    pub fn len(&self) -> usize {
        self.outcomes.len()
    }

    /// True when the log holds no outcomes.
    pub fn is_empty(&self) -> bool {
        self.outcomes.is_empty()
    }

    /// True when this exact outcome is already recorded.
    pub fn contains(&self, outcome: &Outcome) -> bool {
        self.ids.contains(&outcome.stable_id())
    }

    /// Append one outcome, writing the JSONL line when a path is configured.
    ///
    /// Returns `Ok(true)` when the outcome was stored and `Ok(false)` when an
    /// identical outcome is already present. An invalid outcome is
    /// `zero.fnd.invalid_input`; an append that would exceed
    /// [`MAX_OUTCOME_LOG_BYTES`] is `zero.fnd.limit_exceeded` and writes
    /// nothing. The in-memory push happens only after the file write succeeds.
    pub fn append(&mut self, outcome: Outcome) -> Result<bool> {
        outcome.validate()?;
        self.insert(outcome, true)
    }

    /// `Write` the outcome when asked, then store it and evict the oldest.
    fn insert(&mut self, outcome: Outcome, write: bool) -> Result<bool> {
        let id = outcome.stable_id();
        if self.ids.contains(&id) {
            return Ok(false);
        }
        if write {
            if let Some(path) = &self.path {
                append_line(path, &outcome)?;
            }
        }
        self.ids.insert(id);
        self.outcomes.push_back(outcome);
        while self.outcomes.len() > self.max_entries {
            if let Some(evicted) = self.outcomes.pop_front() {
                self.ids.remove(&evicted.stable_id());
            }
        }
        Ok(true)
    }

    /// Aggregate the in-memory outcomes for one class.
    pub fn stats(&self, class: WorkClass, window_ms: i64, now_ms: i64) -> Vec<ModelStats> {
        aggregate(self.outcomes.iter(), class, window_ms, now_ms)
    }

    /// Read the JSONL file leniently and replay it through the in-memory bound.
    fn load(&mut self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let text = std::str::from_utf8(&bytes).map_err(|error| {
            ZeroError::new(
                ErrorCode::Corrupt,
                format!(
                    "{}: outcome log is not UTF-8 JSONL: {error}",
                    path.display()
                ),
            )
        })?;
        for line in text.lines() {
            let Ok(outcome) = serde_json::from_str::<Outcome>(line) else {
                continue;
            };
            if outcome.validate().is_err() {
                continue;
            }
            self.insert(outcome, false)?;
        }
        Ok(())
    }
}

/// Append one JSON line, fsync it, and keep the file bounded.
fn append_line(path: &Path, outcome: &Outcome) -> Result<()> {
    let mut line = serde_json::to_vec(outcome)?;
    line.push(b'\n');

    let current = match std::fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };
    let next = current.saturating_add(line.len() as u64);
    if next > MAX_OUTCOME_LOG_BYTES {
        return Err(ZeroError::new(
            ErrorCode::LimitExceeded,
            format!(
                "{} would grow to {next} bytes, past the {MAX_OUTCOME_LOG_BYTES}-byte outcome log bound; rotate the outcome log",
                path.display()
            ),
        ));
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    restrict_permissions(path)?;
    file.write_all(&line)?;
    file.flush()?;
    file.sync_data()?;
    Ok(())
}

fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// The evidence rules measured routing applies (MDL-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasuredPolicy {
    /// Minimum samples for a candidate to count as measured. At least one.
    pub min_samples: u32,
    /// Exploration rate in basis points (`0..=10_000`).
    pub explore_bps: u32,
    /// Success-rate improvement required before switching, in basis points.
    pub min_improvement_bps: u32,
    /// Stats window in milliseconds. Must be positive.
    pub window_ms: i64,
}

impl MeasuredPolicy {
    /// Validate and build a policy.
    ///
    /// Rejects, in order: `min_samples == 0` (`zero.fnd.invalid_input`) because
    /// a switch with no samples is not evidence-based; `explore_bps` or
    /// `min_improvement_bps` outside `0..=10_000` (same code); and
    /// `window_ms <= 0` (same code).
    pub fn new(
        min_samples: u32,
        explore_bps: u32,
        min_improvement_bps: u32,
        window_ms: i64,
    ) -> Result<Self> {
        if min_samples == 0 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "measured policy needs min_samples of at least 1; a switch with no samples is not evidence-based",
            ));
        }
        if explore_bps > 10_000 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!("explore_bps {explore_bps} is outside 0..=10000 basis points"),
            ));
        }
        if min_improvement_bps > 10_000 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!(
                    "min_improvement_bps {min_improvement_bps} is outside 0..=10000 basis points"
                ),
            ));
        }
        if window_ms <= 0 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!("window_ms {window_ms} must be positive"),
            ));
        }
        Ok(Self {
            min_samples,
            explore_bps,
            min_improvement_bps,
            window_ms,
        })
    }
}

impl Default for MeasuredPolicy {
    /// Five samples, 5% exploration, a 5% improvement threshold, and a
    /// seven-day window.
    fn default() -> Self {
        Self {
            min_samples: 5,
            explore_bps: 500,
            min_improvement_bps: 500,
            window_ms: DEFAULT_WINDOW_MS,
        }
    }
}

/// The result of a measured routing decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasuredChoice {
    /// The model to dispatch to.
    pub chosen: String,
    /// Deterministic explanation. Contains no prompt text.
    pub reason: String,
    /// The stats that justified the choice, when there is a measured one.
    pub evidence: Option<ModelStats>,
    /// True when the choice is an exploration pick.
    pub explored: bool,
}

/// Deterministic PRNG (SplitMix64) for the exploration rate.
struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn roll_bps(&mut self) -> u32 {
        (self.next_u64() % BPS) as u32
    }

    fn index(&mut self, len: usize) -> usize {
        (self.next_u64() % len as u64) as usize
    }
}

/// Preference order for measured candidates.
///
/// Highest success rate; then lower average cost; then lower average latency;
/// then the lexicographically smaller model id.
fn rank(stats: &ModelStats) -> (Reverse<u32>, u64, u64, &str) {
    (
        Reverse(stats.success_rate_bps),
        stats.avg_cost_micros,
        stats.avg_latency_ms,
        stats.model.as_str(),
    )
}

/// The best candidate by [`rank`]. The slice must not be empty.
fn best_of<'a>(eligible: &[&'a ModelStats]) -> &'a ModelStats {
    let mut best = eligible[0];
    for candidate in &eligible[1..] {
        if rank(candidate) < rank(best) {
            best = candidate;
        }
    }
    best
}

/// A seeded exploration pick, with the roll that triggered it.
fn exploration_pick<'a>(
    eligible: &[&'a ModelStats],
    best: &ModelStats,
    policy: &MeasuredPolicy,
    fallback_model: &str,
    rng_seed: u64,
) -> Option<(u32, &'a ModelStats)> {
    let explore_bps = policy.explore_bps.min(10_000);
    if explore_bps == 0 {
        return None;
    }
    let mut rng = Rng::new(rng_seed);
    let roll = rng.roll_bps();
    if roll >= explore_bps {
        return None;
    }
    let mut targets: Vec<&ModelStats> = eligible
        .iter()
        .copied()
        .filter(|candidate| candidate.model != best.model && candidate.model != fallback_model)
        .collect();
    if targets.is_empty() {
        return None;
    }
    // Input order is the caller's, so sort to keep the pick independent of it.
    targets.sort_by(|a, b| a.model.cmp(&b.model));
    Some((roll, targets[rng.index(targets.len())]))
}

/// Choose a model from recorded outcomes (MDL-09; Done: routing changes only
/// with evidence).
///
/// `router_candidates` are the measured candidates, normally
/// [`OutcomeLog::stats`](OutcomeLog::stats) for one class. `fallback_model` is
/// the model the router would use without evidence. `rng_seed` makes
/// exploration deterministic.
///
/// The rules, in order:
///
/// 1. **Insufficient evidence.** When no candidate has `min_samples` samples in
///    the window, the fallback is kept and the reason starts with
///    `insufficient evidence`. A model with no samples is never a measured
///    choice.
/// 2. **Exploit.** The best measured candidate is chosen when it beats the
///    fallback's measured success rate by at least `min_improvement_bps`
///    (ties: lower cost, then lower latency, then model id). The evidence is
///    attached. When the fallback has no measured samples at all, the best
///    measured candidate is chosen: an unmeasured incumbent is not evidence.
/// 3. **Keep.** Otherwise the fallback is kept, with the gap and threshold in
///    the reason.
/// 4. **Explore.** Only when no switch is warranted, `explore_bps` of seeds pick
///    a measured model other than the best and the fallback, recording
///    `explored = true`. Exploration never overrides a proven improvement.
///
/// Candidates of another work class are ignored, so classes never mix. The
/// result is deterministic for the same inputs and seed, and the reason names
/// model ids, classes, rates, costs, latencies, and thresholds only.
pub fn choose(
    router_candidates: &[ModelStats],
    policy: &MeasuredPolicy,
    fallback_model: &str,
    rng_seed: u64,
) -> MeasuredChoice {
    let fallback_model = fallback_model.trim();
    let class = router_candidates
        .iter()
        .find(|candidate| candidate.model == fallback_model)
        .map(|candidate| candidate.class)
        .or_else(|| router_candidates.first().map(|candidate| candidate.class));

    let Some(class) = class else {
        return MeasuredChoice {
            chosen: fallback_model.to_owned(),
            reason: format!(
                "insufficient evidence: no recorded outcomes; keeping the fallback model {fallback_model:?}"
            ),
            evidence: None,
            explored: false,
        };
    };

    let min_samples = u64::from(policy.min_samples.max(1));
    let same_class: Vec<&ModelStats> = router_candidates
        .iter()
        .filter(|candidate| candidate.class == class)
        .collect();
    let eligible: Vec<&ModelStats> = same_class
        .iter()
        .copied()
        .filter(|candidate| candidate.samples >= min_samples)
        .collect();

    if eligible.is_empty() {
        let most = same_class
            .iter()
            .map(|candidate| candidate.samples)
            .max()
            .unwrap_or(0);
        return MeasuredChoice {
            chosen: fallback_model.to_owned(),
            reason: format!(
                "insufficient evidence: the best {} candidate has {most} sample(s) in the window, below the {min_samples} sample minimum; keeping the fallback model {fallback_model:?}",
                class.as_str()
            ),
            evidence: None,
            explored: false,
        };
    }

    let best = best_of(&eligible);
    let incumbent = same_class
        .iter()
        .copied()
        .find(|candidate| candidate.model == fallback_model)
        .filter(|candidate| candidate.samples >= min_samples);
    let improvement = policy.min_improvement_bps.min(10_000);

    // The fallback is already the best measured candidate: keep it, but an
    // exploration roll may still sample an alternative.
    if best.model == fallback_model {
        if let Some((roll, target)) =
            exploration_pick(&eligible, best, policy, fallback_model, rng_seed)
        {
            return exploration_choice(class, fallback_model, target, roll, policy.explore_bps);
        }
        return MeasuredChoice {
            chosen: fallback_model.to_owned(),
            reason: format!(
                "fallback model {fallback_model:?} remains the best measured {} candidate: {} bps success over {} sample(s), average cost {} micros, average latency {} ms; no switch",
                class.as_str(),
                best.success_rate_bps,
                best.samples,
                best.avg_cost_micros,
                best.avg_latency_ms
            ),
            evidence: Some(best.clone()),
            explored: false,
        };
    }

    match incumbent {
        Some(current) => {
            let gain = best
                .success_rate_bps
                .saturating_sub(current.success_rate_bps);
            if gain >= improvement {
                return MeasuredChoice {
                    chosen: best.model.clone(),
                    reason: format!(
                        "switching from fallback model {fallback_model:?} to measured model {:?}: {} bps success over {} sample(s) beats the fallback's {} bps by {gain} bps, at least the {improvement} bps minimum; average cost {} micros, average latency {} ms",
                        best.model,
                        best.success_rate_bps,
                        best.samples,
                        current.success_rate_bps,
                        best.avg_cost_micros,
                        best.avg_latency_ms
                    ),
                    evidence: Some(best.clone()),
                    explored: false,
                };
            }
            if let Some((roll, target)) =
                exploration_pick(&eligible, best, policy, fallback_model, rng_seed)
            {
                return exploration_choice(class, fallback_model, target, roll, policy.explore_bps);
            }
            MeasuredChoice {
                chosen: fallback_model.to_owned(),
                reason: format!(
                    "no switch: the best measured {} candidate {:?} improves success by {gain} bps over fallback model {fallback_model:?} ({} bps to {} bps), below the {improvement} bps minimum; keeping the fallback",
                    class.as_str(),
                    best.model,
                    current.success_rate_bps,
                    best.success_rate_bps
                ),
                evidence: None,
                explored: false,
            }
        }
        // The fallback has no samples in the window, so there is no measured
        // baseline to defend; a measured candidate is strictly more evidence.
        // This is a switch, so exploration does not override it.
        None => MeasuredChoice {
            chosen: best.model.clone(),
            reason: format!(
                "switching from unmeasured fallback model {fallback_model:?} to measured model {:?}: {} bps success over {} sample(s) in work class {}; average cost {} micros, average latency {} ms",
                best.model,
                best.success_rate_bps,
                best.samples,
                class.as_str(),
                best.avg_cost_micros,
                best.avg_latency_ms
            ),
            evidence: Some(best.clone()),
            explored: false,
        },
    }
}

/// Build the exploration choice and its reason.
fn exploration_choice(
    class: WorkClass,
    fallback_model: &str,
    target: &ModelStats,
    roll: u32,
    explore_bps: u32,
) -> MeasuredChoice {
    let explore_bps = explore_bps.min(10_000);
    MeasuredChoice {
        chosen: target.model.clone(),
        reason: format!(
            "exploration: roll {roll} of 10000 is inside the {explore_bps} bps exploration rate; trying measured non-best {} candidate {:?} ({} bps over {} sample(s), average cost {} micros) instead of fallback model {fallback_model:?}",
            class.as_str(),
            target.model,
            target.success_rate_bps,
            target.samples,
            target.avg_cost_micros
        ),
        evidence: Some(target.clone()),
        explored: true,
    }
}

/// Append an outcome, then choose with the updated evidence (MDL-09).
///
/// `now_ms` is the window anchor for the choice and is normally at or after the
/// outcome's `at_ms`. The just-recorded outcome is visible to the choice, so a
/// turn's result influences the next turn's route.
pub fn record_and_choose(
    log: &mut OutcomeLog,
    outcome: Outcome,
    policy: &MeasuredPolicy,
    fallback_model: &str,
    rng_seed: u64,
    now_ms: i64,
) -> Result<MeasuredChoice> {
    let class = outcome.class;
    log.append(outcome)?;
    let stats = log.stats(class, policy.window_ms, now_ms);
    Ok(choose(&stats, policy, fallback_model, rng_seed))
}

/// A predicted and actual cost compared (MDL-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reconciliation {
    /// `actual - predicted` in micros, saturated to the `i64` range.
    pub delta: i64,
    /// `actual / predicted` in basis points; `10_000` when both are zero and
    /// `u32::MAX` for a non-zero actual against a zero prediction.
    pub ratio_bps: u32,
    /// True when the absolute delta is within
    /// [`RECONCILIATION_TOLERANCE_BPS`] of the prediction.
    pub within_tolerance: bool,
}

/// The signed delta, saturating instead of overflowing.
fn signed_delta(predicted_micros: u64, actual_micros: u64) -> i64 {
    if actual_micros >= predicted_micros {
        i64::try_from(actual_micros - predicted_micros).unwrap_or(i64::MAX)
    } else {
        -i64::try_from(predicted_micros - actual_micros).unwrap_or(i64::MAX)
    }
}

/// The actual-to-predicted ratio in basis points.
fn ratio_bps(predicted_micros: u64, actual_micros: u64) -> u32 {
    if predicted_micros == 0 {
        return if actual_micros == 0 { 10_000 } else { u32::MAX };
    }
    let ratio = (u128::from(actual_micros) * 10_000) / u128::from(predicted_micros);
    u32::try_from(ratio).unwrap_or(u32::MAX)
}

/// True when `actual` is inside `tolerance_bps` of `predicted`.
///
/// The tolerance is relative to the prediction and inclusive. A zero prediction
/// tolerates only a zero actual: there is no ratio to be within.
fn within_tolerance(predicted_micros: u64, actual_micros: u64, tolerance_bps: u32) -> bool {
    if predicted_micros == 0 {
        return actual_micros == 0;
    }
    let difference = predicted_micros.abs_diff(actual_micros);
    u128::from(difference) * 10_000 <= u128::from(predicted_micros) * u128::from(tolerance_bps)
}

/// Compare a predicted cost with the actual cost at the default tolerance.
///
/// See [`reconcile_with_tolerance`] for the fields and formulas.
pub fn reconcile(predicted_micros: u64, actual_micros: u64) -> Reconciliation {
    reconcile_with_tolerance(
        predicted_micros,
        actual_micros,
        RECONCILIATION_TOLERANCE_BPS,
    )
}

/// Compare a predicted cost with the actual cost at an explicit tolerance.
///
/// `delta = actual - predicted`, `ratio_bps = actual / predicted`, and
/// `within_tolerance` is true when `|delta| / predicted <= tolerance_bps`. A
/// zero prediction is a special case: a zero actual is a perfect prediction,
/// any non-zero actual is out of tolerance and reports `ratio_bps = u32::MAX`.
pub fn reconcile_with_tolerance(
    predicted_micros: u64,
    actual_micros: u64,
    tolerance_bps: u32,
) -> Reconciliation {
    Reconciliation {
        delta: signed_delta(predicted_micros, actual_micros),
        ratio_bps: ratio_bps(predicted_micros, actual_micros),
        within_tolerance: within_tolerance(predicted_micros, actual_micros, tolerance_bps),
    }
}

/// Refuse a dispatch whose prediction exceeds the remaining budget (MDL-08).
///
/// The comparison is inclusive: a prediction equal to the remaining budget is
/// allowed. An over-budget prediction is `zero.fnd.limit_exceeded` before
/// anything is dispatched.
pub fn preflight_budget(remaining_micros: u64, predicted_micros: u64) -> Result<()> {
    if predicted_micros > remaining_micros {
        return Err(ZeroError::new(
            ErrorCode::LimitExceeded,
            format!(
                "predicted cost {predicted_micros} micros exceeds the remaining budget {remaining_micros} micros; nothing was dispatched"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(min_samples: u32, explore_bps: u32, min_improvement_bps: u32) -> MeasuredPolicy {
        MeasuredPolicy::new(
            min_samples,
            explore_bps,
            min_improvement_bps,
            DEFAULT_WINDOW_MS,
        )
        .expect("valid policy")
    }

    fn stats(
        model: &str,
        class: WorkClass,
        samples: u64,
        successes: u64,
        avg_cost_micros: u64,
        avg_latency_ms: u64,
    ) -> ModelStats {
        ModelStats {
            model: model.to_owned(),
            class,
            samples,
            successes,
            retries: samples.saturating_sub(successes),
            avg_latency_ms,
            avg_cost_micros,
            success_rate_bps: rate_bps(successes, samples),
        }
    }

    fn outcome(
        model: &str,
        class: WorkClass,
        success: bool,
        latency_ms: u64,
        cost_micros: u64,
        at_ms: i64,
    ) -> Outcome {
        Outcome::new(model, class, success, 0, latency_ms, cost_micros, at_ms)
            .expect("valid outcome")
    }

    #[test]
    fn insufficient_samples_keep_the_fallback() {
        let candidates = vec![
            stats("cheap", WorkClass::Edit, 2, 2, 10, 100),
            stats("strong", WorkClass::Edit, 1, 1, 50, 200),
        ];
        let choice = choose(&candidates, &policy(3, 0, 500), "cheap", 7);
        assert_eq!(choice.chosen, "cheap");
        assert!(
            choice.reason.contains("insufficient evidence"),
            "{}",
            choice.reason
        );
        assert!(choice.evidence.is_none());
        assert!(!choice.explored);

        // No recorded outcomes at all is the same refusal.
        let empty = choose(&[], &policy(3, 0, 500), "cheap", 7);
        assert_eq!(empty.chosen, "cheap");
        assert!(
            empty.reason.contains("insufficient evidence"),
            "{}",
            empty.reason
        );
        assert!(empty.evidence.is_none());
    }

    #[test]
    fn clear_improvement_switches_with_evidence() {
        let candidates = vec![
            stats("incumbent", WorkClass::Edit, 10, 6, 20, 300),
            stats("better", WorkClass::Edit, 10, 9, 30, 200),
        ];
        let choice = choose(&candidates, &policy(5, 0, 1_000), "incumbent", 1);
        assert_eq!(choice.chosen, "better");
        assert!(!choice.explored);
        let evidence = choice.evidence.expect("a switch carries evidence");
        assert_eq!(evidence.model, "better");
        assert_eq!(evidence.samples, 10);
        assert_eq!(evidence.success_rate_bps, 9_000);
        assert!(choice.reason.contains("9000 bps"), "{}", choice.reason);
        assert!(choice.reason.contains("6000 bps"), "{}", choice.reason);

        // A fallback with no samples is not evidence: the measured candidate
        // wins, and exploration does not override that switch.
        let unmeasured_fallback = choose(
            &[stats("measured", WorkClass::Edit, 5, 5, 10, 100)],
            &policy(5, 10_000, 500),
            "unmeasured",
            1,
        );
        assert_eq!(unmeasured_fallback.chosen, "measured");
        assert!(!unmeasured_fallback.explored);
        assert!(unmeasured_fallback.evidence.is_some());
    }

    #[test]
    fn improvement_below_the_minimum_does_not_switch() {
        let candidates = vec![
            stats("incumbent", WorkClass::Edit, 20, 17, 20, 300),
            stats("slightly-better", WorkClass::Edit, 20, 18, 30, 200),
        ];
        let choice = choose(&candidates, &policy(5, 0, 501), "incumbent", 1);
        assert_eq!(choice.chosen, "incumbent");
        assert!(!choice.explored);
        assert!(choice.evidence.is_none());
        assert!(choice.reason.contains("below"), "{}", choice.reason);
        assert!(choice.reason.contains("500 bps"), "{}", choice.reason);
        assert!(
            choice.reason.contains("501 bps minimum"),
            "{}",
            choice.reason
        );
    }

    #[test]
    fn a_regression_does_not_switch_and_a_drop_reverts() {
        // The incumbent is perfect and the candidate regressed: no switch.
        let regressed = vec![
            stats("incumbent", WorkClass::Edit, 10, 10, 30, 200),
            stats("regressed", WorkClass::Edit, 10, 4, 10, 100),
        ];
        let choice = choose(&regressed, &policy(5, 0, 500), "incumbent", 1);
        assert_eq!(choice.chosen, "incumbent");
        assert!(
            choice.reason.contains("remains the best measured"),
            "{}",
            choice.reason
        );

        // The incumbent's recent success dropped: revert to the measured model.
        let dropped = vec![
            stats("incumbent", WorkClass::Edit, 10, 4, 30, 200),
            stats("recovered", WorkClass::Edit, 10, 8, 10, 100),
        ];
        let choice = choose(&dropped, &policy(5, 0, 500), "incumbent", 1);
        assert_eq!(choice.chosen, "recovered");
        assert_eq!(
            choice.evidence.as_ref().map(|e| e.model.as_str()),
            Some("recovered")
        );
    }

    #[test]
    fn exploration_is_deterministic_at_a_seeded_rate() {
        let candidates = vec![
            stats("fallback", WorkClass::Edit, 10, 9, 20, 200),
            stats("alpha", WorkClass::Edit, 10, 8, 25, 250),
            stats("beta", WorkClass::Edit, 10, 7, 30, 300),
        ];
        // A threshold no candidate clears, and every roll explores.
        let exploring = policy(5, 10_000, 10_000);

        let first = choose(&candidates, &exploring, "fallback", 42);
        assert!(first.explored, "{}", first.reason);
        assert_ne!(
            first.chosen, "fallback",
            "exploration skips the best candidate"
        );
        assert!(
            first.chosen == "alpha" || first.chosen == "beta",
            "exploration picks a non-best measured candidate: {}",
            first.chosen
        );
        assert!(first.evidence.is_some());
        assert!(first.reason.contains("exploration"), "{}", first.reason);

        let second = choose(&candidates, &exploring, "fallback", 42);
        assert_eq!(first, second, "the same seed is deterministic");

        let picks: BTreeSet<String> = (0..64u64)
            .map(|seed| choose(&candidates, &exploring, "fallback", seed).chosen)
            .collect();
        assert!(
            picks.len() >= 2,
            "the seed selects among exploration targets: {picks:?}"
        );

        let never = choose(&candidates, &policy(5, 0, 10_000), "fallback", 42);
        assert!(!never.explored);
        assert_eq!(never.chosen, "fallback");
    }

    #[test]
    fn cost_then_latency_then_id_break_ties() {
        let candidates = vec![
            stats("incumbent", WorkClass::Edit, 10, 8, 25, 300),
            stats("pricey", WorkClass::Edit, 10, 9, 50, 100),
            stats("cheap-slow", WorkClass::Edit, 10, 9, 20, 300),
            stats("cheap-fast", WorkClass::Edit, 10, 9, 20, 120),
        ];
        let choice = choose(&candidates, &policy(5, 0, 500), "incumbent", 1);
        assert_eq!(choice.chosen, "cheap-fast");

        let tied = vec![
            stats("incumbent", WorkClass::Edit, 10, 8, 25, 300),
            stats("bbb", WorkClass::Edit, 10, 9, 20, 100),
            stats("aaa", WorkClass::Edit, 10, 9, 20, 100),
        ];
        let choice = choose(&tied, &policy(5, 0, 500), "incumbent", 1);
        assert_eq!(choice.chosen, "aaa", "equal stats break on the model id");
    }

    #[test]
    fn the_window_excludes_old_and_future_samples() {
        let now = 1_000_000;
        let outcomes = vec![
            outcome("reliable", WorkClass::Edit, true, 100, 10, now - 10),
            outcome("reliable", WorkClass::Edit, true, 100, 10, now - 20),
            outcome("reliable", WorkClass::Edit, true, 100, 10, now - 30_000),
            outcome("reliable", WorkClass::Edit, false, 100, 10, now - 30_001),
            outcome("reliable", WorkClass::Edit, false, 100, 10, now + 1),
        ];
        let stats = model_stats(&outcomes, WorkClass::Edit, 30_000, now);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].samples, 3, "the boundary is inclusive");
        assert_eq!(stats[0].successes, 3);
        assert_eq!(stats[0].success_rate_bps, 10_000);
        assert_eq!(stats[0].avg_cost_micros, 10);
        assert_eq!(stats[0].avg_latency_ms, 100);

        // A zero window keeps only a sample exactly at `now`.
        let exact = model_stats(&outcomes, WorkClass::Edit, 0, now);
        assert!(exact.is_empty());

        // A negative window is clamped, not allowed to unbound the query.
        let clamped = model_stats(&outcomes, WorkClass::Edit, -5, now);
        assert!(clamped.is_empty());
    }

    #[test]
    fn classes_never_mix() {
        let outcomes = vec![
            outcome("shared", WorkClass::Edit, true, 100, 10, 1_000),
            outcome("shared", WorkClass::Plan, false, 100, 10, 1_001),
        ];
        let edit = model_stats(&outcomes, WorkClass::Edit, DEFAULT_WINDOW_MS, 2_000);
        assert_eq!(edit.len(), 1);
        assert_eq!(edit[0].samples, 1);
        assert_eq!(edit[0].successes, 1);
        assert_eq!(edit[0].class, WorkClass::Edit);

        // A strong plan model cannot win an edit decision.
        let candidates = vec![
            stats("edit-a", WorkClass::Edit, 5, 3, 20, 200),
            stats("plan-strong", WorkClass::Plan, 50, 50, 1, 10),
            stats("edit-b", WorkClass::Edit, 5, 5, 30, 250),
        ];
        let choice = choose(&candidates, &policy(5, 0, 500), "edit-a", 1);
        assert_eq!(choice.chosen, "edit-b");
        let evidence = choice.evidence.expect("evidence for edit-b");
        assert_eq!(evidence.class, WorkClass::Edit);
        assert_ne!(evidence.model, "plan-strong");
    }

    #[test]
    fn reconciliation_reports_within_and_out_of_tolerance() {
        let within = reconcile(1_000, 1_100);
        assert_eq!(within.delta, 100);
        assert_eq!(within.ratio_bps, 11_000);
        assert!(within.within_tolerance);

        let over = reconcile(1_000, 1_300);
        assert_eq!(over.delta, 300);
        assert_eq!(over.ratio_bps, 13_000);
        assert!(!over.within_tolerance);

        let under = reconcile(1_000, 800);
        assert_eq!(under.delta, -200);
        assert_eq!(under.ratio_bps, 8_000);
        assert!(under.within_tolerance);

        // The default tolerance is 20% and inclusive on the boundary.
        assert!(reconcile(1_000, 1_200).within_tolerance);
        assert!(!reconcile(1_000, 1_201).within_tolerance);

        // A zero prediction is a special case, not a division by zero.
        let zero = reconcile(0, 0);
        assert_eq!(zero.delta, 0);
        assert_eq!(zero.ratio_bps, 10_000);
        assert!(zero.within_tolerance);
        let zero_over = reconcile(0, 5);
        assert_eq!(zero_over.delta, 5);
        assert_eq!(zero_over.ratio_bps, u32::MAX);
        assert!(!zero_over.within_tolerance);

        // An explicit tolerance changes the verdict.
        assert!(reconcile_with_tolerance(1_000, 1_500, 5_000).within_tolerance);
        assert!(!reconcile_with_tolerance(1_000, 1_501, 5_000).within_tolerance);
    }

    #[test]
    fn prediction_error_shrinks_with_samples() {
        assert_eq!(
            prediction_error(&stats("m", WorkClass::Edit, 0, 0, 0, 0)),
            0
        );
        assert_eq!(
            prediction_error(&stats("m", WorkClass::Edit, 10, 10, 0, 0)),
            0,
            "a perfect record has no spread"
        );
        assert_eq!(
            prediction_error(&stats("m", WorkClass::Edit, 100, 80, 0, 0)),
            400,
            "80% over 100 samples is a 4% standard error"
        );
    }

    #[test]
    fn the_budget_gate_refuses_before_dispatch() {
        preflight_budget(100, 100).expect("an exact budget is inclusive");
        preflight_budget(101, 100).expect("budget left over is fine");

        let error = preflight_budget(99, 100).expect_err("the prediction does not fit");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert!(error.message().contains("99"), "{}", error.message());
        assert!(error.message().contains("100"), "{}", error.message());
        assert!(
            error.message().contains("nothing was dispatched"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn the_policy_validates_its_bounds() {
        assert_eq!(
            MeasuredPolicy::new(0, 0, 0, 1)
                .expect_err("zero samples")
                .code(),
            ErrorCode::InvalidInput
        );
        for (explore, improvement) in [(10_001, 0), (0, 10_001)] {
            let error = MeasuredPolicy::new(1, explore, improvement, 1)
                .expect_err("basis points outside the range");
            assert_eq!(error.code(), ErrorCode::InvalidInput);
        }
        let error = MeasuredPolicy::new(1, 0, 0, 0).expect_err("a zero window");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("window_ms"), "{}", error.message());

        MeasuredPolicy::default();
        let boundary = MeasuredPolicy::new(1, 10_000, 10_000, 1).expect("upper bounds");
        assert_eq!(boundary.explore_bps, 10_000);
    }

    #[test]
    fn a_measured_choice_is_recorded_before_routing() {
        let mut log = OutcomeLog::new();
        for index in 0..5 {
            log.append(outcome(
                "incumbent",
                WorkClass::Edit,
                false,
                200,
                10,
                1_000 + index,
            ))
            .expect("seed incumbent");
        }
        for index in 0..5 {
            log.append(outcome(
                "candidate",
                WorkClass::Edit,
                true,
                100,
                20,
                1_010 + index,
            ))
            .expect("seed candidate");
        }

        let choice = record_and_choose(
            &mut log,
            outcome("candidate", WorkClass::Edit, true, 100, 20, 1_020),
            &policy(5, 0, 500),
            "incumbent",
            9,
            1_020,
        )
        .expect("record and choose");
        assert_eq!(choice.chosen, "candidate");
        let evidence = choice.evidence.expect("evidence");
        assert_eq!(evidence.samples, 6);
        assert_eq!(evidence.success_rate_bps, 10_000);
        assert_eq!(log.len(), 11);
    }

    #[test]
    fn the_outcome_log_dedupes_bounds_and_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("outcomes.jsonl");
        let mut log = OutcomeLog::with_path(&path).expect("new log");
        assert!(log.is_empty());
        assert_eq!(log.path(), Some(path.as_path()));

        let first = outcome("a", WorkClass::Edit, true, 100, 10, 1_000);
        assert!(log.append(first.clone()).expect("first append"));
        assert!(!log.append(first.clone()).expect("duplicate id"));
        assert_eq!(log.len(), 1);
        assert!(log.contains(&first));

        let second = outcome("b", WorkClass::Edit, false, 200, 20, 1_001);
        log.append(second.clone()).expect("second append");
        let reloaded = OutcomeLog::with_path(&path).expect("reload");
        assert_eq!(reloaded.len(), 2);
        assert_eq!(
            reloaded.outcomes().cloned().collect::<Vec<_>>(),
            vec![first, second]
        );

        let mut bounded = OutcomeLog::with_max_entries(2);
        let oldest = outcome("old", WorkClass::Edit, true, 1, 1, 1);
        let middle = outcome("mid", WorkClass::Edit, true, 1, 1, 2);
        let newest = outcome("new", WorkClass::Edit, true, 1, 1, 3);
        for entry in [oldest.clone(), middle.clone(), newest.clone()] {
            assert!(bounded.append(entry).expect("append"));
        }
        assert_eq!(bounded.len(), 2);
        assert_eq!(bounded.max_entries(), 2);
        assert!(!bounded.contains(&oldest), "the oldest sample is evicted");
        assert!(bounded.contains(&middle));
        assert!(bounded.contains(&newest));
        assert!(
            bounded.append(oldest).expect("evicted ids are free again"),
            "an evicted outcome can be recorded again"
        );
    }

    #[test]
    fn outcomes_and_stats_expose_no_prompt_text() {
        let record = outcome("model-a", WorkClass::Edit, true, 120, 30, 1_000);
        assert_eq!(record.stable_id(), record.stable_id());

        let value = serde_json::to_value(&record).expect("outcome serialises");
        let object = value.as_object().expect("outcome is an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "at_ms",
                "class",
                "cost_micros",
                "latency_ms",
                "model",
                "retries",
                "success"
            ]
        );
        for forbidden in ["prompt", "content", "messages", "transcript"] {
            assert!(
                object.get(forbidden).is_none(),
                "outcome exposed {forbidden}"
            );
        }

        // A planted prompt key is not a stored outcome; it is malformed input.
        let planted = r#"{"model":"m","class":"edit","success":true,"retries":0,"latency_ms":1,"cost_micros":1,"at_ms":1,"prompt":"secret"}"#;
        assert!(serde_json::from_str::<Outcome>(planted).is_err());

        let summary = stats("model-a", WorkClass::Edit, 4, 3, 10, 100);
        let value = serde_json::to_value(&summary).expect("stats serialise");
        let object = value.as_object().expect("stats are an object");
        for forbidden in ["prompt", "content", "messages", "transcript"] {
            assert!(object.get(forbidden).is_none(), "stats exposed {forbidden}");
        }

        let reason = choose(
            &[stats("model-a", WorkClass::Edit, 5, 4, 10, 100)],
            &policy(5, 0, 0),
            "model-b",
            1,
        )
        .reason;
        for forbidden in ["prompt", "content", "messages", "transcript"] {
            assert!(
                !reason.contains(forbidden),
                "reason exposed {forbidden}: {reason}"
            );
        }
    }

    #[test]
    fn reasons_are_deterministic() {
        let candidates = vec![
            stats("incumbent", WorkClass::Edit, 10, 6, 20, 300),
            stats("better", WorkClass::Edit, 10, 9, 30, 200),
        ];
        let strict = policy(5, 0, 1_000);
        let first = choose(&candidates, &strict, "incumbent", 99);
        let second = choose(&candidates, &strict, "incumbent", 99);
        assert_eq!(first, second);

        let explore_policy =
            MeasuredPolicy::new(5, 10_000, 10_000, DEFAULT_WINDOW_MS).expect("valid policy");
        let first = choose(&candidates, &explore_policy, "incumbent", 3);
        let second = choose(&candidates, &explore_policy, "incumbent", 3);
        assert_eq!(first, second);
    }

    #[test]
    fn an_outcome_rejects_a_blank_model_and_negative_time() {
        let blank =
            Outcome::new("   ", WorkClass::Edit, true, 0, 1, 1, 1).expect_err("blank model");
        assert_eq!(blank.code(), ErrorCode::InvalidInput);

        let negative =
            Outcome::new("m", WorkClass::Edit, true, 0, 1, 1, -1).expect_err("negative timestamp");
        assert_eq!(negative.code(), ErrorCode::InvalidInput);

        let mut log = OutcomeLog::new();
        assert_eq!(
            log.append(blank_outcome())
                .expect_err("invalid append")
                .code(),
            ErrorCode::InvalidInput
        );
        assert!(log.is_empty());
    }

    fn blank_outcome() -> Outcome {
        Outcome {
            model: " ".to_owned(),
            class: WorkClass::Edit,
            success: true,
            retries: 0,
            latency_ms: 0,
            cost_micros: 0,
            at_ms: 0,
        }
    }
}
