//! Deterministic network impairment for the search resilience layer (TST-05).
//!
//! TST-05 asks for loss, latency, partition, and NAT-type coverage. This module
//! owns the first three as a pure simulator and records the fourth as an
//! external gate:
//!
//! - [`NetworkModel`] describes one link: a loss rate in basis points, a base
//!   latency, a jitter band, and a hard partition flag.
//! - [`SplitMix64`] seeds every request from `(seed, attempt)`, so a request
//!   outcome is reproducible no matter which caller order produced it.
//! - [`simulate_request`] returns one [`Impairment`]; [`simulate_sequence`]
//!   returns the outcome of `n` consecutive attempts for one seed.
//! - [`run_impairment_suite`] drives the real [`crate::resilience`] policy with
//!   a [`SimulatedEngine`] and returns an [`ImpairmentReport`].
//!
//! The 5×5 NAT matrix is **not** re-implemented here. It belongs to `zero-mesh`
//! traversal, which `zero-web` must not depend on; the report records the
//! external test name ([`NAT_MATRIX_GATE`]) and
//! [`assert_suite_green`] refuses a report that does not carry it.
//!
//! Everything is clock-driven: [`crate::resilience::ResilientSearch::run`] takes
//! `now_ms`, no test sleeps, and a partition or a loss burst cannot vary between
//! runs of the same seed.
//!
//! ```
//! use zero_web::{simulate_sequence, Impairment, NetworkModel};
//!
//! let model = NetworkModel {
//!     loss_bps: 1_000,
//!     latency_ms: 20,
//!     jitter_ms: 5,
//!     partition: false,
//! };
//! let first = simulate_sequence(&model, 0x5EED, 16);
//! let second = simulate_sequence(&model, 0x5EED, 16);
//! assert_eq!(first, second);
//! for outcome in &first {
//!     match outcome {
//!         Impairment::Delivered { latency_ms } => assert!((20..=25).contains(latency_ms)),
//!         Impairment::Lost | Impairment::Partitioned => {}
//!     }
//! }
//! ```

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::resilience::{BreakerState, EnginePolicy, EngineState, ResilientSearch};
use crate::search::{SearchEngine, SearchHit};

/// Backend health outcomes are sampled on a basis-point scale.
pub const MAX_LOSS_BPS: u32 = 10_000;

/// The external NAT-matrix gate: a `zero-mesh` traversal test.
///
/// `zero-web` must not depend on `zero-mesh`, so the 5×5 matrix lives in its
/// owning crate and this report only records its name.
pub const NAT_MATRIX_GATE: &str =
    "zero_mesh::traversal::tests::the_nat_matrix_is_deterministic_and_complete";

/// Cells in the 5×5 NAT matrix (MESH-04): open, full-cone, restricted,
/// port-restricted, and symmetric in every source/destination pair.
pub const NAT_MATRIX_CELLS: usize = 25;

/// External suites an impairment report must record to be green.
pub const REQUIRED_EXTERNAL_SUITES: &[&str] = &[NAT_MATRIX_GATE];

/// Scenario name: loss-free baseline.
pub const SCENARIO_BASELINE: &str = "baseline";
/// Scenario name: 10% loss under the retry/backoff policy.
pub const SCENARIO_LOSS_10: &str = "loss-10-retry";
/// Scenario name: sustained high loss that opens the breaker.
pub const SCENARIO_HIGH_LOSS: &str = "high-loss-breaker";
/// Scenario name: delivery latency inside the timeout.
pub const SCENARIO_LATENCY_WITHIN: &str = "latency-within-timeout";
/// Scenario name: delivery latency over the timeout.
pub const SCENARIO_LATENCY_OVER: &str = "latency-over-timeout";
/// Scenario name: a full network partition.
pub const SCENARIO_PARTITION: &str = "full-partition";

/// One link's impairment configuration.
///
/// `loss_bps` is clamped to [`MAX_LOSS_BPS`]. `partition` overrides the other
/// fields: every request is [`Impairment::Partitioned`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkModel {
    /// Per-request loss probability in basis points (`1_000` is 10%).
    pub loss_bps: u32,
    /// Base delivery latency in milliseconds.
    pub latency_ms: u64,
    /// Extra latency drawn uniformly from `0..=jitter_ms`.
    pub jitter_ms: u64,
    /// When true, no request is delivered at all.
    pub partition: bool,
}

impl NetworkModel {
    /// A perfect link: no loss, no latency, no jitter, no partition.
    pub const fn ideal() -> Self {
        Self {
            loss_bps: 0,
            latency_ms: 0,
            jitter_ms: 0,
            partition: false,
        }
    }
}

impl Default for NetworkModel {
    fn default() -> Self {
        Self::ideal()
    }
}

/// One request's simulated outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Impairment {
    /// The request arrived after `latency_ms`.
    Delivered {
        /// Simulated end-to-end latency, including jitter.
        latency_ms: u64,
    },
    /// The request was dropped.
    Lost,
    /// The link was partitioned: every request is dropped.
    Partitioned,
}

/// SplitMix64, a small seeded generator with no external dependency.
///
/// The constants and the finalizer are the standard SplitMix64 ones, so the
/// same seed produces the same stream on every platform and every run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// A generator starting from `seed`.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next value in the stream.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    /// A value in `0..bound` (`0` when `bound` is zero).
    ///
    /// The modulo is slightly biased for bounds that do not divide `2^64`, which
    /// is irrelevant for a test generator and is why this is not a dice.
    pub fn next_bounded(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next_u64() % bound
        }
    }
}

/// Mix `attempt` into `seed` so each request gets its own stream.
///
/// The multiplier is odd, so for one seed distinct attempts cannot collide.
fn stream_seed(seed: u64, attempt: u64) -> u64 {
    seed ^ attempt.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Simulate the request at `attempt` on the link described by `model`.
///
/// The outcome depends only on `(model, rng_seed, attempt)`: calling it out of
/// order or twice returns the same result. A partition is checked first, then
/// the loss roll, then (for a delivery) the jitter draw.
pub fn simulate_request(model: &NetworkModel, rng_seed: u64, attempt: u64) -> Impairment {
    if model.partition {
        return Impairment::Partitioned;
    }

    let mut rng = SplitMix64::new(stream_seed(rng_seed, attempt));
    let roll = rng.next_bounded(u64::from(MAX_LOSS_BPS));
    let loss_bps = u64::from(model.loss_bps.min(MAX_LOSS_BPS));
    if roll < loss_bps {
        return Impairment::Lost;
    }

    let jitter = if model.jitter_ms == 0 {
        0
    } else {
        rng.next_bounded(model.jitter_ms.saturating_add(1))
    };
    Impairment::Delivered {
        latency_ms: model.latency_ms.saturating_add(jitter),
    }
}

/// Simulate `count` consecutive attempts for one seed.
pub fn simulate_sequence(model: &NetworkModel, rng_seed: u64, count: usize) -> Vec<Impairment> {
    (0..count as u64)
        .map(|attempt| simulate_request(model, rng_seed, attempt))
        .collect()
}

/// A [`SearchEngine`] that answers from the simulator instead of a network.
///
/// The `attempt` index is the engine's own call counter, so a retry by
/// [`ResilientSearch`] consumes the next simulated request. A delivery slower
/// than the configured timeout is returned as [`ErrorCode::Timeout`]; loss and
/// partition are [`ErrorCode::Unavailable`].
pub struct SimulatedEngine {
    name: String,
    model: NetworkModel,
    rng_seed: u64,
    timeout_ms: u64,
    hits: Vec<SearchHit>,
    attempts: AtomicUsize,
}

impl SimulatedEngine {
    /// Build an engine over `model`, seeded by `rng_seed`.
    ///
    /// The default timeout is unlimited; use [`SimulatedEngine::with_timeout_ms`]
    /// to make a slow delivery fail.
    pub fn new(
        name: impl Into<String>,
        model: NetworkModel,
        rng_seed: u64,
        hits: Vec<SearchHit>,
    ) -> Self {
        Self {
            name: name.into(),
            model,
            rng_seed,
            timeout_ms: u64::MAX,
            hits,
            attempts: AtomicUsize::new(0),
        }
    }

    /// Treat a delivery slower than `timeout_ms` as a timeout.
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Simulated requests consumed so far.
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

impl SearchEngine for SimulatedEngine {
    fn name(&self) -> &str {
        &self.name
    }

    fn search(&self, _query: &str, _limit: usize) -> Result<Vec<SearchHit>> {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) as u64;
        match simulate_request(&self.model, self.rng_seed, attempt) {
            Impairment::Delivered { latency_ms } if latency_ms > self.timeout_ms => {
                Err(ZeroError::new(
                    ErrorCode::Timeout,
                    format!(
                        "simulated delivery took {latency_ms} ms, over the {} ms timeout",
                        self.timeout_ms
                    ),
                ))
            }
            Impairment::Delivered { .. } => Ok(self.hits.clone()),
            Impairment::Lost => Err(ZeroError::new(
                ErrorCode::Unavailable,
                "simulated packet loss: connection reset by peer",
            )),
            Impairment::Partitioned => Err(ZeroError::new(
                ErrorCode::Unavailable,
                "simulated network partition",
            )),
        }
    }
}

/// One scenario's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Stable scenario name, one of the `SCENARIO_*` constants.
    pub name: String,
    /// Named assertions that held.
    pub passes: usize,
    /// Named assertions that did not hold.
    pub failures: Vec<String>,
}

impl ScenarioResult {
    /// Build a result from explicit counts.
    pub fn new(name: impl Into<String>, passes: usize, failures: Vec<String>) -> Self {
        Self {
            name: name.into(),
            passes,
            failures,
        }
    }

    /// True when at least one assertion ran and none failed.
    pub fn ok(&self) -> bool {
        self.passes > 0 && self.failures.is_empty()
    }
}

/// Aggregate impairment report over the local scenarios and the external gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpairmentReport {
    /// One result per scenario.
    pub scenarios: Vec<ScenarioResult>,
    /// Recorded external suite names, currently the NAT matrix.
    pub external: Vec<String>,
    /// True only when every scenario is green and every required external suite
    /// is recorded.
    pub ok: bool,
}

impl ImpairmentReport {
    /// Build a report and compute [`ImpairmentReport::ok`] from the contents.
    pub fn from_scenarios(scenarios: Vec<ScenarioResult>, external: Vec<String>) -> Self {
        let scenarios_ok = !scenarios.is_empty() && scenarios.iter().all(ScenarioResult::ok);
        let external_ok = REQUIRED_EXTERNAL_SUITES
            .iter()
            .all(|gate| external.iter().any(|record| record.as_str() == *gate));
        Self {
            ok: scenarios_ok && external_ok,
            scenarios,
            external,
        }
    }

    /// Look up a scenario by name.
    pub fn scenario(&self, name: &str) -> Option<&ScenarioResult> {
        self.scenarios.iter().find(|scenario| scenario.name == name)
    }

    /// Required external suites that are absent from the report.
    pub fn missing_external_suites(&self) -> Vec<String> {
        REQUIRED_EXTERNAL_SUITES
            .iter()
            .filter(|gate| !self.external.iter().any(|record| record.as_str() == **gate))
            .map(|gate| (*gate).to_string())
            .collect()
    }
}

/// Typed impairment-gate failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImpairmentSuiteError {
    /// The report had no scenarios at all.
    EmptyReport,
    /// A scenario failed at least one assertion.
    ScenarioFailed {
        /// Scenario name.
        name: String,
        /// Assertions that held.
        passes: usize,
        /// Assertions that did not hold.
        failures: Vec<String>,
    },
    /// A required external suite was not recorded.
    ExternalSuiteNotRecorded {
        /// External suite name.
        suite: String,
    },
}

impl fmt::Display for ImpairmentSuiteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImpairmentSuiteError::EmptyReport => {
                formatter.write_str("impairment report contains no scenarios")
            }
            ImpairmentSuiteError::ScenarioFailed {
                name,
                passes,
                failures,
            } => write!(
                formatter,
                "impairment scenario `{name}` failed: {passes} assertions passed; failing: {}",
                failures.join(", ")
            ),
            ImpairmentSuiteError::ExternalSuiteNotRecorded { suite } => write!(
                formatter,
                "required external impairment suite `{suite}` is not recorded"
            ),
        }
    }
}

impl std::error::Error for ImpairmentSuiteError {}

/// Refuse a release when the report is empty, a scenario failed, or the external
/// NAT matrix is not recorded.
pub fn assert_suite_green(report: &ImpairmentReport) -> Result<(), ImpairmentSuiteError> {
    if report.scenarios.is_empty() {
        return Err(ImpairmentSuiteError::EmptyReport);
    }
    for scenario in &report.scenarios {
        if !scenario.ok() {
            return Err(ImpairmentSuiteError::ScenarioFailed {
                name: scenario.name.clone(),
                passes: scenario.passes,
                failures: scenario.failures.clone(),
            });
        }
    }
    for gate in REQUIRED_EXTERNAL_SUITES {
        let recorded = report
            .external
            .iter()
            .any(|record| record.as_str() == *gate);
        if !recorded {
            return Err(ImpairmentSuiteError::ExternalSuiteNotRecorded {
                suite: (*gate).to_string(),
            });
        }
    }
    Ok(())
}

/// Run every local impairment scenario and record the external NAT gate.
pub fn run_impairment_suite() -> ImpairmentReport {
    ImpairmentReport::from_scenarios(
        vec![
            baseline_scenario(),
            ten_percent_retry_scenario(),
            high_loss_breaker_scenario(),
            latency_within_timeout_scenario(),
            latency_over_timeout_scenario(),
            full_partition_scenario(),
        ],
        vec![NAT_MATRIX_GATE.to_string()],
    )
}

// -- scenario plumbing -------------------------------------------------------

/// Collects named assertions for one scenario.
struct Recorder {
    name: &'static str,
    passes: usize,
    failures: Vec<String>,
}

impl Recorder {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            passes: 0,
            failures: Vec::new(),
        }
    }

    fn check(&mut self, held: bool, label: &str) {
        if held {
            self.passes += 1;
        } else {
            self.failures.push(label.to_string());
        }
    }

    fn finish(self) -> ScenarioResult {
        ScenarioResult::new(self.name, self.passes, self.failures)
    }
}

fn suite_hit() -> SearchHit {
    SearchHit {
        title: "Simulated result".to_string(),
        url: "https://simulated.example/1".to_string(),
        snippet: "delivered across the impairment simulator".to_string(),
        published: None,
    }
}

fn suite_policy(breaker_threshold: u32) -> EnginePolicy {
    EnginePolicy {
        max_requests_per_minute: 0,
        initial_backoff_ms: 1,
        max_backoff_ms: 1,
        breaker_threshold,
        breaker_cooldown_ms: 60_000,
    }
}

/// Earliest instant the next drive may call `engine`: one millisecond after
/// `now`, the end of the backoff, and the end of an open breaker, whichever is
/// latest.
fn next_instant(search: &ResilientSearch<'_>, engine: &str, now: i64) -> i64 {
    let floor = now.saturating_add(1);
    search.engine_state(engine).map_or(floor, |state: EngineState| {
        let breaker = match state.breaker {
            BreakerState::Open { until_ms } => until_ms,
            BreakerState::Closed | BreakerState::HalfOpen => now,
        };
        breaker.max(state.next_allowed_ms).max(floor)
    })
}

// -- scenarios ---------------------------------------------------------------

/// No loss, no partition: every request is delivered inside the latency band.
fn baseline_scenario() -> ScenarioResult {
    let mut recorder = Recorder::new(SCENARIO_BASELINE);
    let model = NetworkModel {
        loss_bps: 0,
        latency_ms: 12,
        jitter_ms: 4,
        partition: false,
    };

    let sequence = simulate_sequence(&model, 0x01, 32);
    recorder.check(
        sequence.iter().all(|outcome| {
            matches!(
                outcome,
                Impairment::Delivered { latency_ms } if (12..=16).contains(latency_ms)
            )
        }),
        "a loss-free model delivers every request inside the latency band",
    );

    let engine = SimulatedEngine::new("baseline", model, 0x01, vec![suite_hit()]);
    let mut search =
        ResilientSearch::new(vec![&engine as &dyn SearchEngine], suite_policy(3));
    let response = search.run("impairment", 5, 0);
    recorder.check(
        response.results.len() == 1,
        "the baseline search returns the simulated hit",
    );
    recorder.check(
        response.failed.is_empty(),
        "the baseline search reports no engine failure",
    );
    recorder.check(
        engine.attempts() == 1,
        "the baseline search calls the engine exactly once",
    );
    recorder.finish()
}

/// 10% loss: the retry/backoff policy reaches a delivery after a loss, and the
/// breaker never opens because the threshold is far away.
fn ten_percent_retry_scenario() -> ScenarioResult {
    const RETRY_SEED: u64 = 0x5EED_1234;
    const MAX_DRIVES: usize = 64;

    let mut recorder = Recorder::new(SCENARIO_LOSS_10);
    let model = NetworkModel {
        loss_bps: 1_000,
        latency_ms: 5,
        jitter_ms: 3,
        partition: false,
    };

    let sequence = simulate_sequence(&model, RETRY_SEED, MAX_DRIVES);
    recorder.check(
        sequence.contains(&Impairment::Lost),
        "the 10% model does drop at least one request in the drive budget",
    );
    recorder.check(
        sequence
            .iter()
            .any(|outcome| matches!(outcome, Impairment::Delivered { .. })),
        "the 10% model still delivers requests in the drive budget",
    );

    let engine = SimulatedEngine::new("lossy", model, RETRY_SEED, vec![suite_hit()]);
    let mut search =
        ResilientSearch::new(vec![&engine as &dyn SearchEngine], suite_policy(50));

    let mut now = 0i64;
    let mut saw_failure = false;
    let mut recovered_after_failure = false;
    let mut failures = 0usize;
    let mut deliveries = 0usize;
    for _ in 0..MAX_DRIVES {
        let response = search.run("impairment", 5, now);
        if !response.failed.is_empty() {
            failures += 1;
            saw_failure = true;
        } else if !response.results.is_empty() {
            deliveries += 1;
            if saw_failure {
                recovered_after_failure = true;
                break;
            }
        }
        now = next_instant(&search, "lossy", now);
    }

    recorder.check(
        failures >= 1,
        "the resilient layer reports the simulated loss as an engine failure",
    );
    recorder.check(
        recovered_after_failure,
        "a later attempt succeeds after a loss within the drive budget",
    );
    recorder.check(
        deliveries <= MAX_DRIVES && engine.attempts() <= MAX_DRIVES,
        "recovery stays inside the attempt budget",
    );
    recorder.check(
        search
            .engine_state("lossy")
            .is_some_and(|state| state.breaker == BreakerState::Closed),
        "10% loss with a high threshold leaves the breaker closed",
    );
    recorder.check(
        search
            .engine_state("lossy")
            .is_some_and(|state| state.backoff_ms == 0 && state.next_allowed_ms == 0),
        "a successful retry clears the backoff",
    );
    recorder.finish()
}

/// Sustained high loss opens the breaker and stops calling the engine.
fn high_loss_breaker_scenario() -> ScenarioResult {
    const HIGH_LOSS_SEED: u64 = 0xBAD_5EED;
    const MAX_DRIVES: usize = 64;

    let mut recorder = Recorder::new(SCENARIO_HIGH_LOSS);
    let model = NetworkModel {
        loss_bps: 9_000,
        latency_ms: 5,
        jitter_ms: 0,
        partition: false,
    };
    let engine = SimulatedEngine::new("high-loss", model, HIGH_LOSS_SEED, vec![suite_hit()]);
    let mut search =
        ResilientSearch::new(vec![&engine as &dyn SearchEngine], suite_policy(3));

    let mut now = 0i64;
    let mut failed_runs = 0usize;
    let mut opened_after = None;
    let mut breaker = BreakerState::Closed;
    for step in 0..MAX_DRIVES {
        let response = search.run("impairment", 5, now);
        if !response.failed.is_empty() {
            failed_runs += 1;
        }
        if let Some(state) = search.engine_state("high-loss") {
            breaker = state.breaker;
            if matches!(breaker, BreakerState::Open { .. }) {
                opened_after = Some(step + 1);
                break;
            }
        }
        now = next_instant(&search, "high-loss", now);
    }

    recorder.check(
        opened_after.is_some(),
        "sustained high loss opens the breaker inside the drive budget",
    );
    recorder.check(
        failed_runs >= 3,
        "the breaker opens only after repeated reported failures",
    );
    recorder.check(
        engine.attempts() >= 3,
        "each counted failure consumed one simulated request",
    );
    recorder.check(
        matches!(breaker, BreakerState::Open { .. }),
        "the final breaker state is open",
    );

    let calls_when_open = engine.attempts();
    search.run("impairment", 5, now);
    recorder.check(
        engine.attempts() == calls_when_open,
        "an open breaker makes no further simulated requests",
    );
    recorder.finish()
}

/// Delivery latency inside the timeout succeeds.
fn latency_within_timeout_scenario() -> ScenarioResult {
    let mut recorder = Recorder::new(SCENARIO_LATENCY_WITHIN);
    let model = NetworkModel {
        loss_bps: 0,
        latency_ms: 30,
        jitter_ms: 25,
        partition: false,
    };

    let sequence = simulate_sequence(&model, 0x77, 32);
    recorder.check(
        sequence.iter().all(|outcome| {
            matches!(
                outcome,
                Impairment::Delivered { latency_ms } if (30..=55).contains(latency_ms)
            )
        }),
        "jitter stays inside the configured band",
    );

    let engine = SimulatedEngine::new("fast", model, 0x77, vec![suite_hit()]).with_timeout_ms(100);
    let mut search =
        ResilientSearch::new(vec![&engine as &dyn SearchEngine], suite_policy(3));
    let response = search.run("impairment", 5, 0);
    recorder.check(
        response.results.len() == 1 && response.failed.is_empty(),
        "a delivery inside the timeout yields a result",
    );
    recorder.finish()
}

/// Delivery latency over the timeout fails every attempt, opens the breaker,
/// and still returns a `failed` entry rather than panicking.
fn latency_over_timeout_scenario() -> ScenarioResult {
    const MAX_DRIVES: usize = 16;

    let mut recorder = Recorder::new(SCENARIO_LATENCY_OVER);
    let model = NetworkModel {
        loss_bps: 0,
        latency_ms: 250,
        jitter_ms: 0,
        partition: false,
    };
    let engine =
        SimulatedEngine::new("slow", model, 0x51, vec![suite_hit()]).with_timeout_ms(80);
    let mut search =
        ResilientSearch::new(vec![&engine as &dyn SearchEngine], suite_policy(3));

    let mut now = 0i64;
    let mut empty_runs = 0usize;
    let mut breaker = BreakerState::Closed;
    let mut first_failure_names_timeout = false;
    for step in 0..MAX_DRIVES {
        let response = search.run("impairment", 5, now);
        if response.results.is_empty() {
            empty_runs += 1;
        }
        if step == 0 {
            first_failure_names_timeout = response.results.is_empty()
                && response
                    .failed
                    .first()
                    .is_some_and(|error| error.message.to_ascii_lowercase().contains("timeout"));
        }
        if let Some(state) = search.engine_state("slow") {
            breaker = state.breaker;
            if matches!(breaker, BreakerState::Open { .. }) {
                break;
            }
        }
        now = next_instant(&search, "slow", now);
    }

    recorder.check(
        first_failure_names_timeout,
        "an over-timeout delivery is reported as a timeout failure, not a panic",
    );
    recorder.check(
        empty_runs >= 3,
        "every over-timeout drive yields no results",
    );
    recorder.check(
        matches!(breaker, BreakerState::Open { .. }),
        "repeated over-timeout deliveries open the breaker",
    );
    recorder.finish()
}

/// A full partition fails every attempt, opens the breaker, and one failing
/// engine never removes another engine's results.
fn full_partition_scenario() -> ScenarioResult {
    let mut recorder = Recorder::new(SCENARIO_PARTITION);
    let model = NetworkModel {
        loss_bps: 0,
        latency_ms: 5,
        jitter_ms: 0,
        partition: true,
    };

    recorder.check(
        simulate_sequence(&model, 0xA11CE, 16)
            .iter()
            .all(|outcome| *outcome == Impairment::Partitioned),
        "a partitioned model reports every request as partitioned",
    );

    let partitioned = SimulatedEngine::new("partitioned", model, 0xA11CE, vec![suite_hit()]);
    let healthy = SimulatedEngine::new("healthy", NetworkModel::ideal(), 0x01, vec![suite_hit()]);
    let mut search = ResilientSearch::new(
        vec![
            &partitioned as &dyn SearchEngine,
            &healthy as &dyn SearchEngine,
        ],
        suite_policy(3),
    );

    let first = search.run("impairment", 5, 0);
    recorder.check(
        first.results.len() == 1,
        "a partitioned engine does not remove the healthy engine's result",
    );
    recorder.check(
        first
            .failed
            .first()
            .is_some_and(|error| error.engine == "partitioned"),
        "the partitioned engine is reported in `failed`",
    );

    let mut now = 0i64;
    let mut breaker = BreakerState::Closed;
    for _ in 0..16 {
        now = next_instant(&search, "partitioned", now);
        search.run("impairment", 5, now);
        if let Some(state) = search.engine_state("partitioned") {
            breaker = state.breaker;
            if matches!(breaker, BreakerState::Open { .. }) {
                break;
            }
        }
    }
    recorder.check(
        matches!(breaker, BreakerState::Open { .. }),
        "the breaker opens on a full partition",
    );
    recorder.check(
        partitioned.attempts() == 3,
        "the breaker stops calling the partitioned engine at the threshold",
    );

    let after = search.run("impairment", 5, now);
    recorder.check(
        after.results.len() == 1,
        "the healthy engine still serves the query while the breaker is open",
    );
    recorder.check(
        partitioned.attempts() == 3,
        "an open breaker makes no further partitioned calls",
    );
    recorder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lossy_model() -> NetworkModel {
        NetworkModel {
            loss_bps: 1_000,
            latency_ms: 5,
            jitter_ms: 3,
            partition: false,
        }
    }

    #[test]
    fn simulate_sequence_is_deterministic_for_a_seed() {
        let model = lossy_model();
        let first = simulate_sequence(&model, 0xABCD, 500);
        let second = simulate_sequence(&model, 0xABCD, 500);
        assert_eq!(first, second, "the same seed must replay the same trace");

        let other = simulate_sequence(&model, 0xABCE, 500);
        assert_ne!(first, other, "a different seed changes the trace");
    }

    #[test]
    fn simulate_request_matches_the_sequence_at_each_attempt() {
        let model = lossy_model();
        let sequence = simulate_sequence(&model, 42, 64);
        for (attempt, expected) in sequence.iter().enumerate() {
            assert_eq!(
                &simulate_request(&model, 42, attempt as u64),
                expected,
                "attempt {attempt} must be order-independent"
            );
        }
    }

    #[test]
    fn loss_free_model_always_delivers_inside_the_latency_band() {
        let model = NetworkModel {
            loss_bps: 0,
            latency_ms: 12,
            jitter_ms: 4,
            partition: false,
        };
        for outcome in simulate_sequence(&model, 7, 1_000) {
            match outcome {
                Impairment::Delivered { latency_ms } => {
                    assert!((12..=16).contains(&latency_ms), "latency {latency_ms}");
                }
                other => panic!("loss-free model returned {other:?}"),
            }
        }
    }

    #[test]
    fn total_loss_model_always_loses() {
        let model = NetworkModel {
            loss_bps: MAX_LOSS_BPS,
            latency_ms: 5,
            jitter_ms: 3,
            partition: false,
        };
        assert!(simulate_sequence(&model, 9, 256)
            .iter()
            .all(|outcome| *outcome == Impairment::Lost));
    }

    #[test]
    fn partition_overrides_every_other_metric() {
        let model = NetworkModel {
            loss_bps: 0,
            latency_ms: 0,
            jitter_ms: 0,
            partition: true,
        };
        assert!(simulate_sequence(&model, 9, 256)
            .iter()
            .all(|outcome| *outcome == Impairment::Partitioned));
    }

    #[test]
    fn ten_percent_loss_mixes_delivered_and_lost() {
        let sequence = simulate_sequence(&lossy_model(), 0x5EED_1234, 1_000);
        let lost = sequence
            .iter()
            .filter(|outcome| **outcome == Impairment::Lost)
            .count();
        assert!(
            (60..=140).contains(&lost),
            "10% loss produced {lost}/1000 losses"
        );
        for outcome in &sequence {
            if let Impairment::Delivered { latency_ms } = outcome {
                assert!((5..=8).contains(latency_ms), "latency {latency_ms}");
            }
        }
    }

    #[test]
    fn retry_policy_eventually_succeeds_under_ten_percent_loss() {
        let scenario = ten_percent_retry_scenario();
        assert!(scenario.ok(), "scenario failed: {scenario:?}");
        assert!(
            scenario.passes >= 6,
            "expected every retry assertion to run: {scenario:?}"
        );
    }

    #[test]
    fn sustained_high_loss_opens_the_breaker() {
        let scenario = high_loss_breaker_scenario();
        assert!(scenario.ok(), "scenario failed: {scenario:?}");
    }

    #[test]
    fn latency_inside_the_timeout_is_delivered() {
        let scenario = latency_within_timeout_scenario();
        assert!(scenario.ok(), "scenario failed: {scenario:?}");
    }

    #[test]
    fn latency_over_the_timeout_fails_without_failing_the_search() {
        let scenario = latency_over_timeout_scenario();
        assert!(scenario.ok(), "scenario failed: {scenario:?}");
    }

    #[test]
    fn full_partition_fails_every_attempt_and_opens_the_breaker() {
        let scenario = full_partition_scenario();
        assert!(scenario.ok(), "scenario failed: {scenario:?}");

        // The whole suite must not panic across a partition either.
        let model = NetworkModel {
            partition: true,
            ..NetworkModel::ideal()
        };
        let engine = SimulatedEngine::new("down", model, 1, vec![suite_hit()]);
        let mut search =
            ResilientSearch::new(vec![&engine as &dyn SearchEngine], suite_policy(2));
        let response = search.run("impairment", 5, 0);
        assert!(response.results.is_empty());
        assert_eq!(response.failed.len(), 1);
    }

    #[test]
    fn report_is_green_and_records_the_external_nat_matrix() {
        let report = run_impairment_suite();
        assert_eq!(report.scenarios.len(), 6);
        assert!(report.ok, "report is not green: {report:?}");
        assert_eq!(
            report.external,
            vec![NAT_MATRIX_GATE.to_string()],
            "the external NAT matrix gate must be recorded verbatim"
        );
        assert_eq!(report.scenario(SCENARIO_LOSS_10).map(ScenarioResult::ok), Some(true));
        assert_eq!(
            NAT_MATRIX_CELLS, 25,
            "the external gate covers the 5x5 NAT matrix"
        );
        assert_eq!(assert_suite_green(&report), Ok(()));
        assert!(report.missing_external_suites().is_empty());
    }

    #[test]
    fn a_forced_scenario_failure_flips_ok() {
        let report = ImpairmentReport::from_scenarios(
            vec![ScenarioResult::new(
                "forced",
                1,
                vec!["forced failure".to_string()],
            )],
            vec![NAT_MATRIX_GATE.to_string()],
        );
        assert!(!report.ok);
        assert_eq!(
            assert_suite_green(&report),
            Err(ImpairmentSuiteError::ScenarioFailed {
                name: "forced".to_string(),
                passes: 1,
                failures: vec!["forced failure".to_string()],
            })
        );
    }

    #[test]
    fn a_missing_external_gate_is_refused() {
        let report = ImpairmentReport::from_scenarios(
            vec![ScenarioResult::new("green", 2, Vec::new())],
            Vec::new(),
        );
        assert!(!report.ok);
        assert_eq!(
            report.missing_external_suites(),
            vec![NAT_MATRIX_GATE.to_string()]
        );
        assert_eq!(
            assert_suite_green(&report),
            Err(ImpairmentSuiteError::ExternalSuiteNotRecorded {
                suite: NAT_MATRIX_GATE.to_string(),
            })
        );
    }

    #[test]
    fn an_empty_report_is_refused() {
        let report = ImpairmentReport::from_scenarios(Vec::new(), vec![NAT_MATRIX_GATE.to_string()]);
        assert!(!report.ok);
        assert_eq!(
            assert_suite_green(&report),
            Err(ImpairmentSuiteError::EmptyReport)
        );
    }
}
