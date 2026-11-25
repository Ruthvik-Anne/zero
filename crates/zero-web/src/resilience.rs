//! Search resilience: rate limits, backoff, breaker, benching, reserve (WEB-05).
//!
//! [`ResilientSearch`] wraps the [`SearchEngine`] trait with the policy a live
//! keyless adapter needs:
//!
//! - a per-engine **rate limit** (requests per rolling minute),
//! - **exponential backoff** after a transport or server failure,
//! - a **circuit breaker** that stops calling an engine after repeated
//!   failures and probes it again after a cooldown,
//! - **benching** on a CAPTCHA or login wall: the engine is set aside for the
//!   cooldown and the search succeeds without it,
//! - an optional **reserve engine** used when every primary engine is
//!   unavailable.
//!
//! Time is passed in as `now_ms` for every call, so the policy is fully
//! deterministic and testable without sleeping. Engines are called
//! sequentially here because each outcome decides whether the next call is
//! allowed; [`crate::search::search`] remains the parallel path for callers
//! that do not need per-engine policy. Ordering of the fused results is
//! identical because both paths use [`fuse`].
//!
//! A CAPTCHA is a refusal, not an error: a benched engine is excluded and is
//! **not** reported in [`SearchResponse::failed`], and other engines still
//! contribute their results.

use std::panic::{catch_unwind, AssertUnwindSafe};

use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::search::{fuse, SearchEngine, SearchError, SearchHit, SearchResponse};

/// Length of one rate-limit window: one minute.
pub const RATE_WINDOW_MS: i64 = 60_000;

/// Case-insensitive refusal markers that bench an engine instead of failing it.
///
/// A CAPTCHA, a human-verification interstitial, or a login wall means the
/// adapter is fine but the provider will not answer anonymous requests right
/// now. Treating that as a failure would poison `SearchResponse::failed` and,
/// with a breaker, could open on a policy that is really just a bench.
pub const BENCH_MARKERS: &[&str] = &[
    "captcha",
    "verify you are human",
    "login required",
    "sign in to continue",
];

/// Per-engine policy for [`ResilientSearch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnginePolicy {
    /// Requests allowed per rolling minute (`0` means unlimited).
    pub max_requests_per_minute: u32,
    /// Delay after the first failure.
    pub initial_backoff_ms: u64,
    /// Upper bound for the doubling backoff.
    pub max_backoff_ms: u64,
    /// Consecutive failures that open the breaker (`0` is treated as `1`).
    pub breaker_threshold: u32,
    /// How long the breaker stays open, and how long a benched engine is
    /// excluded.
    pub breaker_cooldown_ms: u64,
}

impl Default for EnginePolicy {
    fn default() -> Self {
        Self {
            max_requests_per_minute: 30,
            initial_backoff_ms: 1_000,
            max_backoff_ms: 60_000,
            breaker_threshold: 3,
            breaker_cooldown_ms: 300_000,
        }
    }
}

/// Breaker position at a given instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Calls are allowed and failures are counted.
    Closed,
    /// Calls are rejected until `until_ms`.
    Open { until_ms: i64 },
    /// The cooldown elapsed; one probe call is allowed.
    HalfOpen,
}

/// Consecutive-failure circuit breaker.
///
/// ```
/// use zero_web::{BreakerState, CircuitBreaker};
///
/// let mut breaker = CircuitBreaker::new(2, 1_000);
/// breaker.record(false, 0);
/// breaker.record(false, 10);
/// assert_eq!(breaker.state(), BreakerState::Open { until_ms: 1_010 });
/// assert!(!breaker.allow(1_009));
/// assert!(breaker.allow(1_010));
/// assert_eq!(breaker.state(), BreakerState::HalfOpen);
/// breaker.record(true, 1_010);
/// assert_eq!(breaker.state(), BreakerState::Closed);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitBreaker {
    state: BreakerState,
    consecutive_failures: u32,
    threshold: u32,
    cooldown_ms: u64,
}

impl CircuitBreaker {
    /// A closed breaker that opens after `threshold` consecutive failures.
    pub fn new(threshold: u32, cooldown_ms: u64) -> Self {
        Self {
            state: BreakerState::Closed,
            consecutive_failures: 0,
            threshold: threshold.max(1),
            cooldown_ms,
        }
    }

    /// Current position.
    pub fn state(&self) -> BreakerState {
        self.state
    }

    /// Failures counted since the last success.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Whether a call is allowed at `now_ms`.
    ///
    /// Moves an open breaker to [`BreakerState::HalfOpen`] once its cooldown
    /// has elapsed, which is what lets exactly one probe through.
    pub fn allow(&mut self, now_ms: i64) -> bool {
        match self.state {
            BreakerState::Closed => true,
            BreakerState::Open { until_ms } => {
                if now_ms >= until_ms {
                    self.state = BreakerState::HalfOpen;
                    true
                } else {
                    false
                }
            }
            BreakerState::HalfOpen => true,
        }
    }

    /// Record the outcome of one allowed call.
    ///
    /// Success closes the breaker and clears the failure count. Failure opens
    /// it at `now_ms + cooldown_ms` once the threshold is reached, or
    /// immediately when a half-open probe fails.
    pub fn record(&mut self, success: bool, now_ms: i64) {
        if success {
            self.state = BreakerState::Closed;
            self.consecutive_failures = 0;
            return;
        }

        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let threshold_reached = self.consecutive_failures >= self.threshold;
        if threshold_reached || self.state == BreakerState::HalfOpen {
            let cooldown_ms = i64::try_from(self.cooldown_ms).unwrap_or(i64::MAX);
            self.state = BreakerState::Open {
                until_ms: now_ms.saturating_add(cooldown_ms),
            };
        }
    }
}

/// Delay for the `attempt`th consecutive failure (`0` is the first failure).
///
/// The delay starts at `initial_ms` and doubles per attempt, capped at
/// `max_ms`. A zero initial delay is raised to 1 ms so a broken engine is never
/// retried twice in the same instant.
pub fn next_backoff_ms(initial_ms: u64, max_ms: u64, attempt: u32) -> u64 {
    let initial = initial_ms.max(1);
    let cap = max_ms.max(initial);
    let mut delay = initial;
    for _ in 0..attempt {
        delay = delay.saturating_mul(2);
        if delay >= cap {
            return cap;
        }
    }
    delay.min(cap)
}

/// Whether an engine error message is a CAPTCHA/login refusal.
///
/// Matching is case-insensitive over [`BENCH_MARKERS`].
pub fn is_bench_refusal(message: &str) -> bool {
    let lowercase = message.to_ascii_lowercase();
    BENCH_MARKERS
        .iter()
        .any(|marker| lowercase.contains(marker))
}

/// Snapshot of one engine's resilience state, for tests and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineState {
    pub name: String,
    pub breaker: BreakerState,
    /// Consecutive failures counted by the breaker.
    pub consecutive_failures: u32,
    /// Requests already taken from the current rate-limit window.
    pub requests_in_window: u32,
    /// Earliest instant the backoff allows another call; `0` means none.
    pub next_allowed_ms: i64,
    /// Current backoff delay in milliseconds; `0` means none.
    pub backoff_ms: u64,
    /// End of the bench window; the engine is excluded before this instant.
    /// `0` means it has never been benched.
    pub benched_until_ms: i64,
}

/// The outcome of one engine attempt, distinguishing "not allowed to call" and
/// "benched" from a real failure.
enum Attempt {
    Skipped,
    Benched,
    Succeeded(Vec<SearchHit>),
    Failed(String),
}

struct EngineSlot<'a> {
    engine: &'a dyn SearchEngine,
    breaker: CircuitBreaker,
    window_started: bool,
    window_start_ms: i64,
    requests_in_window: u32,
    next_allowed_ms: i64,
    backoff_ms: u64,
    benched_until_ms: i64,
}

impl<'a> EngineSlot<'a> {
    fn new(engine: &'a dyn SearchEngine, policy: &EnginePolicy) -> Self {
        Self {
            engine,
            breaker: CircuitBreaker::new(policy.breaker_threshold, policy.breaker_cooldown_ms),
            window_started: false,
            window_start_ms: 0,
            requests_in_window: 0,
            next_allowed_ms: 0,
            backoff_ms: 0,
            benched_until_ms: 0,
        }
    }

    /// Take one request from the rate-limit window when the breaker, the
    /// bench, and the backoff all permit a call.
    fn try_acquire(&mut self, now_ms: i64, max_requests_per_minute: u32) -> bool {
        if now_ms < self.benched_until_ms || now_ms < self.next_allowed_ms {
            return false;
        }
        if !self.breaker.allow(now_ms) {
            return false;
        }

        if !self.window_started {
            self.window_started = true;
            self.window_start_ms = now_ms;
        } else if now_ms.saturating_sub(self.window_start_ms) >= RATE_WINDOW_MS {
            self.window_start_ms = now_ms;
            self.requests_in_window = 0;
        }
        if max_requests_per_minute > 0 && self.requests_in_window >= max_requests_per_minute {
            return false;
        }
        self.requests_in_window = self.requests_in_window.saturating_add(1);
        true
    }

    fn record_success(&mut self, now_ms: i64) {
        self.breaker.record(true, now_ms);
        self.backoff_ms = 0;
        self.next_allowed_ms = 0;
    }

    fn record_failure(&mut self, now_ms: i64, policy: &EnginePolicy) {
        self.breaker.record(false, now_ms);
        let attempt = self.breaker.consecutive_failures().saturating_sub(1);
        self.backoff_ms =
            next_backoff_ms(policy.initial_backoff_ms, policy.max_backoff_ms, attempt);
        self.next_allowed_ms =
            now_ms.saturating_add(i64::try_from(self.backoff_ms).unwrap_or(i64::MAX));
    }

    fn bench(&mut self, now_ms: i64, cooldown_ms: u64) {
        let cooldown_ms = i64::try_from(cooldown_ms).unwrap_or(i64::MAX);
        self.benched_until_ms = now_ms.saturating_add(cooldown_ms);
    }

    fn attempt(
        &mut self,
        query: &str,
        limit: usize,
        now_ms: i64,
        policy: &EnginePolicy,
    ) -> Attempt {
        if !self.try_acquire(now_ms, policy.max_requests_per_minute) {
            return Attempt::Skipped;
        }

        match call_engine(self.engine, query, limit) {
            Ok(hits) => {
                self.record_success(now_ms);
                Attempt::Succeeded(hits)
            }
            Err(error) => {
                let message = error.to_string();
                if is_bench_refusal(&message) {
                    // A refusal is a bench, not a failure: the breaker and the
                    // failure list stay untouched.
                    self.bench(now_ms, policy.breaker_cooldown_ms);
                    Attempt::Benched
                } else {
                    self.record_failure(now_ms, policy);
                    Attempt::Failed(message)
                }
            }
        }
    }

    fn snapshot(&self) -> EngineState {
        EngineState {
            name: self.engine.name().to_string(),
            breaker: self.breaker.state(),
            consecutive_failures: self.breaker.consecutive_failures(),
            requests_in_window: self.requests_in_window,
            next_allowed_ms: self.next_allowed_ms,
            backoff_ms: self.backoff_ms,
            benched_until_ms: self.benched_until_ms,
        }
    }
}

/// Orchestrates primary engines plus an optional reserve with per-engine
/// resilience policy.
///
/// Engine names must be unique across the primary list and the reserve; lookups
/// by name return the first match, primaries first.
pub struct ResilientSearch<'a> {
    engines: Vec<EngineSlot<'a>>,
    reserve: Option<EngineSlot<'a>>,
    policy: EnginePolicy,
}

impl<'a> ResilientSearch<'a> {
    /// Build an orchestrator over `engines` in caller order.
    pub fn new(engines: Vec<&'a dyn SearchEngine>, policy: EnginePolicy) -> Self {
        Self {
            engines: engines
                .into_iter()
                .map(|engine| EngineSlot::new(engine, &policy))
                .collect(),
            reserve: None,
            policy,
        }
    }

    /// Attach the reserve engine, used only when every primary is unavailable.
    pub fn with_reserve(mut self, engine: &'a dyn SearchEngine) -> Self {
        let policy = self.policy;
        self.reserve = Some(EngineSlot::new(engine, &policy));
        self
    }

    /// The policy every engine slot uses.
    pub fn policy(&self) -> EnginePolicy {
        self.policy
    }

    /// Run one query through the available engines and fuse the survivors.
    ///
    /// Skipped engines (breaker open, rate window exhausted, backoff, or
    /// benched) do not fail the search. A real failure lands in
    /// [`SearchResponse::failed`]; a CAPTCHA/login refusal benches the engine
    /// and stays out of that list.
    pub fn run(&mut self, query: &str, limit: usize, now_ms: i64) -> SearchResponse {
        if limit == 0 || query.trim().is_empty() {
            return SearchResponse {
                query: query.to_string(),
                results: Vec::new(),
                failed: Vec::new(),
            };
        }

        let policy = self.policy;
        let mut ranked: Vec<(String, Vec<SearchHit>)> = Vec::new();
        let mut failed: Vec<SearchError> = Vec::new();
        let mut primary_available = false;

        for slot in &mut self.engines {
            let name = slot.engine.name().to_string();
            match slot.attempt(query, limit, now_ms, &policy) {
                Attempt::Skipped | Attempt::Benched => {}
                Attempt::Succeeded(hits) => {
                    primary_available = true;
                    ranked.push((name, hits));
                }
                Attempt::Failed(message) => failed.push(SearchError {
                    engine: name,
                    message,
                }),
            }
        }

        if !primary_available {
            if let Some(reserve) = self.reserve.as_mut() {
                let name = reserve.engine.name().to_string();
                match reserve.attempt(query, limit, now_ms, &policy) {
                    Attempt::Skipped | Attempt::Benched => {}
                    Attempt::Succeeded(hits) => ranked.push((name, hits)),
                    Attempt::Failed(message) => failed.push(SearchError {
                        engine: name,
                        message,
                    }),
                }
            }
        }

        let mut response = fuse(query, &ranked, limit);
        response.failed = failed;
        response
    }

    /// Whether `engine` is benched at `now_ms`. Unknown names are not benched.
    pub fn benched(&self, engine: &str, now_ms: i64) -> bool {
        self.slot(engine)
            .is_some_and(|slot| now_ms < slot.benched_until_ms)
    }

    /// Snapshot of one engine's state, primaries first, then the reserve.
    pub fn engine_state(&self, name: &str) -> Option<EngineState> {
        self.slot(name).map(EngineSlot::snapshot)
    }

    fn slot(&self, name: &str) -> Option<&EngineSlot<'a>> {
        self.engines
            .iter()
            .find(|slot| slot.engine.name() == name)
            .or_else(|| self.reserve.iter().find(|slot| slot.engine.name() == name))
    }
}

/// Call one engine, turning a panic into an ordinary error so one adapter can
/// never abort the whole search.
fn call_engine(engine: &dyn SearchEngine, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
    match catch_unwind(AssertUnwindSafe(|| engine.search(query, limit))) {
        Ok(outcome) => outcome,
        Err(_) => Err(ZeroError::new(
            ErrorCode::Internal,
            "engine panicked while searching",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct FixtureEngine {
        name: &'static str,
        hits: Vec<SearchHit>,
        error: Option<&'static str>,
        calls: AtomicUsize,
    }

    impl FixtureEngine {
        fn ok(name: &'static str, hits: Vec<SearchHit>) -> Self {
            Self {
                name,
                hits,
                error: None,
                calls: AtomicUsize::new(0),
            }
        }

        fn failing(name: &'static str, message: &'static str) -> Self {
            Self {
                name,
                hits: Vec::new(),
                error: Some(message),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl SearchEngine for FixtureEngine {
        fn name(&self) -> &str {
            self.name
        }

        fn search(&self, _query: &str, _limit: usize) -> Result<Vec<SearchHit>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.error {
                Some(message) => Err(ZeroError::new(ErrorCode::Unavailable, message)),
                None => Ok(self.hits.clone()),
            }
        }
    }

    /// Fails the first `failures` calls, then returns `hits`.
    struct FlakyEngine {
        name: &'static str,
        failures: usize,
        hits: Vec<SearchHit>,
        calls: AtomicUsize,
    }

    impl FlakyEngine {
        fn new(name: &'static str, failures: usize, hits: Vec<SearchHit>) -> Self {
            Self {
                name,
                failures,
                hits,
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl SearchEngine for FlakyEngine {
        fn name(&self) -> &str {
            self.name
        }

        fn search(&self, _query: &str, _limit: usize) -> Result<Vec<SearchHit>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call <= self.failures {
                Err(ZeroError::new(
                    ErrorCode::Unavailable,
                    "connection reset by peer",
                ))
            } else {
                Ok(self.hits.clone())
            }
        }
    }

    fn hit(title: &'static str, url: &'static str) -> SearchHit {
        SearchHit {
            title: title.to_string(),
            url: url.to_string(),
            snippet: "snippet".to_string(),
            published: None,
        }
    }

    fn policy() -> EnginePolicy {
        EnginePolicy {
            max_requests_per_minute: 100,
            initial_backoff_ms: 100,
            max_backoff_ms: 1_000,
            breaker_threshold: 3,
            breaker_cooldown_ms: 10_000,
        }
    }

    #[test]
    fn breaker_opens_after_n_failures_rejects_while_open_and_closes_on_success() {
        let mut breaker = CircuitBreaker::new(3, 1_000);
        assert_eq!(breaker.state(), BreakerState::Closed);

        breaker.record(false, 0);
        breaker.record(false, 1);
        assert_eq!(breaker.state(), BreakerState::Closed);
        assert_eq!(breaker.consecutive_failures(), 2);
        assert!(breaker.allow(1));

        breaker.record(false, 2);
        assert_eq!(breaker.state(), BreakerState::Open { until_ms: 1_002 });
        assert!(!breaker.allow(500));
        assert!(!breaker.allow(1_001));

        // The cooldown elapses: one half-open probe is allowed.
        assert!(breaker.allow(1_002));
        assert_eq!(breaker.state(), BreakerState::HalfOpen);

        breaker.record(true, 1_002);
        assert_eq!(breaker.state(), BreakerState::Closed);
        assert_eq!(breaker.consecutive_failures(), 0);
        assert!(breaker.allow(1_003));
    }

    #[test]
    fn a_failed_half_open_probe_reopens_the_breaker() {
        let mut breaker = CircuitBreaker::new(1, 100);
        breaker.record(false, 0);
        assert_eq!(breaker.state(), BreakerState::Open { until_ms: 100 });
        assert!(breaker.allow(100));
        assert_eq!(breaker.state(), BreakerState::HalfOpen);

        breaker.record(false, 100);
        assert_eq!(breaker.state(), BreakerState::Open { until_ms: 200 });
        assert!(!breaker.allow(199));
        assert!(breaker.allow(200));
    }

    #[test]
    fn threshold_zero_is_one_failure() {
        let mut breaker = CircuitBreaker::new(0, 100);
        breaker.record(false, 0);
        assert_eq!(breaker.state(), BreakerState::Open { until_ms: 100 });
    }

    #[test]
    fn backoff_grows_exponentially_and_is_capped() {
        assert_eq!(next_backoff_ms(100, 1_000, 0), 100);
        assert_eq!(next_backoff_ms(100, 1_000, 1), 200);
        assert_eq!(next_backoff_ms(100, 1_000, 2), 400);
        assert_eq!(next_backoff_ms(100, 1_000, 3), 800);
        assert_eq!(next_backoff_ms(100, 1_000, 4), 1_000);
        assert_eq!(next_backoff_ms(100, 1_000, 50), 1_000);
        // A zero delay is raised so a broken engine is not spun.
        assert_eq!(next_backoff_ms(0, 0, 0), 1);
        // A maximum below the initial delay never shortens it.
        assert_eq!(next_backoff_ms(500, 100, 3), 500);
    }

    #[test]
    fn captcha_benches_the_engine_without_failing_the_search() {
        let captcha =
            FixtureEngine::failing("captcha-engine", "Please complete the CAPTCHA to continue");
        let healthy = FixtureEngine::ok(
            "healthy",
            vec![hit("Kept result", "https://good.example/1")],
        );
        let policy = EnginePolicy {
            breaker_cooldown_ms: 1_000,
            ..policy()
        };
        let mut search =
            ResilientSearch::new(vec![&captcha as &dyn SearchEngine, &healthy], policy);

        let response = search.run("rust", 5, 0);
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].title, "Kept result");
        assert!(
            response.failed.is_empty(),
            "a bench is not a failure: {:?}",
            response.failed
        );
        assert!(search.benched("captcha-engine", 0));
        assert!(!search.benched("healthy", 0));
        assert!(!search.benched("unknown-engine", 0));
        assert_eq!(
            search.engine_state("captcha-engine").unwrap().breaker,
            BreakerState::Closed,
            "benching must not feed the breaker"
        );

        // Excluded for the whole cooldown, not called again.
        let during = search.run("rust", 5, 999);
        assert_eq!(during.results.len(), 1);
        assert_eq!(captcha.calls(), 1);
        assert!(!search.benched("captcha-engine", 1_000));

        // Tried again once the cooldown elapses, and re-benched on the retry.
        search.run("rust", 5, 1_000);
        assert_eq!(captcha.calls(), 2);
        assert!(search.benched("captcha-engine", 1_500));
        assert!(!search.benched("captcha-engine", 2_000));
    }

    #[test]
    fn login_refusal_is_detected_case_insensitively() {
        for message in [
            "CAPTCHA required",
            "please Verify You Are Human first",
            "Login Required to continue",
            "SIGN IN TO CONTINUE",
            "search engine `a` failed: zero.fnd.unavailable: captcha (retry later)",
        ] {
            assert!(is_bench_refusal(message), "{message:?} should bench");
        }
        for message in [
            "connection reset by peer",
            "rate limited",
            "internal server error",
            "login failed",
        ] {
            assert!(!is_bench_refusal(message), "{message:?} should not bench");
        }
    }

    #[test]
    fn rate_limit_limits_calls_per_window() {
        let engine = FixtureEngine::ok("alpha", vec![hit("A", "https://a.example/1")]);
        let policy = EnginePolicy {
            max_requests_per_minute: 2,
            ..policy()
        };
        let mut search = ResilientSearch::new(vec![&engine as &dyn SearchEngine], policy);

        search.run("rust", 5, 0);
        search.run("rust", 5, 1);
        assert_eq!(engine.calls(), 2);

        let exhausted = search.run("rust", 5, 59_999);
        assert!(exhausted.results.is_empty());
        assert!(exhausted.failed.is_empty(), "a skip is not a failure");
        assert_eq!(engine.calls(), 2);
        assert_eq!(search.engine_state("alpha").unwrap().requests_in_window, 2);

        // The window started at 0, so it refills at 60_000.
        let refilled = search.run("rust", 5, 60_000);
        assert_eq!(refilled.results.len(), 1);
        assert_eq!(engine.calls(), 3);
        assert_eq!(search.engine_state("alpha").unwrap().requests_in_window, 1);
    }

    #[test]
    fn rate_window_starts_at_the_first_request() {
        let engine = FixtureEngine::ok("alpha", vec![hit("A", "https://a.example/1")]);
        let policy = EnginePolicy {
            max_requests_per_minute: 1,
            ..policy()
        };
        let mut search = ResilientSearch::new(vec![&engine as &dyn SearchEngine], policy);

        search.run("rust", 5, 10_000);
        assert_eq!(engine.calls(), 1);
        // The window opened at 10_000, not at the epoch: 60_000 is still inside.
        search.run("rust", 5, 60_000);
        assert_eq!(engine.calls(), 1);
        search.run("rust", 5, 70_000);
        assert_eq!(engine.calls(), 2);
    }

    #[test]
    fn zero_requests_per_minute_means_unlimited() {
        let engine = FixtureEngine::ok("alpha", vec![hit("A", "https://a.example/1")]);
        let policy = EnginePolicy {
            max_requests_per_minute: 0,
            ..policy()
        };
        let mut search = ResilientSearch::new(vec![&engine as &dyn SearchEngine], policy);
        for now_ms in 0..5 {
            search.run("rust", 5, now_ms);
        }
        assert_eq!(engine.calls(), 5);
    }

    #[test]
    fn failure_gates_the_next_attempt_until_the_backoff_elapses() {
        let flaky = FlakyEngine::new("flaky", 1, vec![hit("Recovered", "https://a.example/1")]);
        let policy = EnginePolicy {
            initial_backoff_ms: 500,
            max_backoff_ms: 2_000,
            breaker_threshold: 10,
            ..policy()
        };
        let mut search = ResilientSearch::new(vec![&flaky as &dyn SearchEngine], policy);

        let first = search.run("rust", 5, 0);
        assert!(first.results.is_empty());
        assert_eq!(first.failed.len(), 1);
        assert_eq!(flaky.calls(), 1);
        let state = search.engine_state("flaky").expect("state");
        assert_eq!(state.backoff_ms, 500);
        assert_eq!(state.next_allowed_ms, 500);

        let gated = search.run("rust", 5, 499);
        assert!(gated.results.is_empty());
        assert_eq!(flaky.calls(), 1);

        let recovered = search.run("rust", 5, 500);
        assert_eq!(recovered.results.len(), 1);
        assert!(recovered.failed.is_empty());
        assert_eq!(flaky.calls(), 2);
        let state = search.engine_state("flaky").expect("state");
        assert_eq!(state.backoff_ms, 0);
        assert_eq!(state.next_allowed_ms, 0);
    }

    #[test]
    fn backoff_doubles_across_consecutive_failures() {
        let failing = FixtureEngine::failing("broken", "connection reset by peer");
        let policy = EnginePolicy {
            initial_backoff_ms: 100,
            max_backoff_ms: 1_000,
            breaker_threshold: 10,
            ..policy()
        };
        let mut search = ResilientSearch::new(vec![&failing as &dyn SearchEngine], policy);

        let mut delays = Vec::new();
        let mut now_ms = 0;
        for _ in 0..5 {
            search.run("rust", 5, now_ms);
            let state = search.engine_state("broken").expect("state");
            delays.push(state.backoff_ms);
            now_ms = state.next_allowed_ms;
        }
        assert_eq!(delays, [100, 200, 400, 800, 1_000]);
        assert_eq!(failing.calls(), 5);
    }

    #[test]
    fn breaker_skips_an_engine_after_repeated_failures_and_recovers_after_a_probe() {
        let flaky = FlakyEngine::new("flaky", 2, vec![hit("Recovered", "https://a.example/1")]);
        let policy = EnginePolicy {
            initial_backoff_ms: 1,
            max_backoff_ms: 1,
            breaker_threshold: 2,
            breaker_cooldown_ms: 100,
            ..policy()
        };
        let mut search = ResilientSearch::new(vec![&flaky as &dyn SearchEngine], policy);

        search.run("rust", 5, 0);
        search.run("rust", 5, 1);
        assert_eq!(flaky.calls(), 2);
        assert_eq!(
            search.engine_state("flaky").unwrap().breaker,
            BreakerState::Open { until_ms: 101 }
        );

        // Open: skipped even though the backoff has elapsed.
        let open = search.run("rust", 5, 2);
        assert!(open.results.is_empty());
        assert!(open.failed.is_empty());
        assert_eq!(flaky.calls(), 2);

        // Cooldown elapsed: the probe succeeds and closes the breaker.
        let recovered = search.run("rust", 5, 101);
        assert_eq!(recovered.results.len(), 1);
        assert!(recovered.failed.is_empty());
        assert_eq!(flaky.calls(), 3);
        assert_eq!(
            search.engine_state("flaky").unwrap().breaker,
            BreakerState::Closed
        );
    }

    #[test]
    fn a_panicking_engine_is_a_failure_not_an_abort() {
        struct PanicEngine;

        impl SearchEngine for PanicEngine {
            fn name(&self) -> &str {
                "panicky"
            }

            fn search(&self, _query: &str, _limit: usize) -> Result<Vec<SearchHit>> {
                panic!("adapter bug");
            }
        }

        let healthy = FixtureEngine::ok("healthy", vec![hit("Kept", "https://a.example/1")]);
        let mut search =
            ResilientSearch::new(vec![&PanicEngine as &dyn SearchEngine, &healthy], policy());

        let response = search.run("rust", 5, 0);
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.failed.len(), 1);
        assert_eq!(response.failed[0].engine, "panicky");
        assert!(response.failed[0].message.contains("panicked"));
    }

    #[test]
    fn reserve_engine_is_used_only_when_all_primaries_are_unavailable() {
        // A healthy primary answers: the reserve is never called.
        let primary = FixtureEngine::ok("primary", vec![hit("Primary hit", "https://p.example/1")]);
        let reserve = FixtureEngine::ok("reserve", vec![hit("Reserve hit", "https://r.example/1")]);
        let mut search = ResilientSearch::new(vec![&primary as &dyn SearchEngine], policy())
            .with_reserve(&reserve);

        let response = search.run("rust", 5, 0);
        assert_eq!(response.results[0].title, "Primary hit");
        assert_eq!(reserve.calls(), 0);
        assert!(response.failed.is_empty());

        // An empty-but-successful primary is still available: no reserve.
        let empty = FixtureEngine::ok("empty", Vec::new());
        let reserve = FixtureEngine::ok("reserve", vec![hit("Reserve hit", "https://r.example/1")]);
        let mut search = ResilientSearch::new(vec![&empty as &dyn SearchEngine], policy())
            .with_reserve(&reserve);
        let response = search.run("rust", 5, 0);
        assert!(response.results.is_empty());
        assert_eq!(reserve.calls(), 0);

        // Every primary fails: the reserve answers and stays out of `failed`.
        let broken = FixtureEngine::failing("broken", "connection reset by peer");
        let reserve = FixtureEngine::ok("reserve", vec![hit("Reserve hit", "https://r.example/1")]);
        let mut search = ResilientSearch::new(vec![&broken as &dyn SearchEngine], policy())
            .with_reserve(&reserve);
        let response = search.run("rust", 5, 0);
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].title, "Reserve hit");
        assert_eq!(reserve.calls(), 1);
        assert_eq!(response.failed.len(), 1);
        assert_eq!(response.failed[0].engine, "broken");
    }

    #[test]
    fn benched_primaries_also_fall_through_to_the_reserve() {
        let captcha = FixtureEngine::failing("captcha-engine", "verify you are human");
        let reserve = FixtureEngine::ok("reserve", vec![hit("Reserve hit", "https://r.example/1")]);
        let policy = EnginePolicy {
            breaker_cooldown_ms: 1_000,
            ..policy()
        };
        let mut search = ResilientSearch::new(vec![&captcha as &dyn SearchEngine], policy)
            .with_reserve(&reserve);

        let response = search.run("rust", 5, 0);
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].title, "Reserve hit");
        assert!(response.failed.is_empty());
        assert!(search.benched("captcha-engine", 0));
    }

    #[test]
    fn empty_query_and_zero_limit_consult_no_engine() {
        let engine = FixtureEngine::ok("alpha", vec![hit("A", "https://a.example/1")]);
        let mut search = ResilientSearch::new(vec![&engine as &dyn SearchEngine], policy());

        for query in ["", "   ", "\t\n"] {
            let response = search.run(query, 5, 0);
            assert!(response.results.is_empty());
            assert!(response.failed.is_empty());
            assert_eq!(response.query, query);
        }
        let response = search.run("rust", 0, 0);
        assert!(response.results.is_empty());
        assert_eq!(engine.calls(), 0);
    }

    #[test]
    fn fused_order_matches_the_plain_search_path() {
        let alpha = FixtureEngine::ok(
            "alpha",
            vec![
                hit("Shared", "https://shared.example/x"),
                hit("Alpha only", "https://alpha.example/1"),
            ],
        );
        let beta = FixtureEngine::ok("beta", vec![hit("Beta only", "https://beta.example/1")]);
        let mut search = ResilientSearch::new(
            vec![&alpha as &dyn SearchEngine, &beta as &dyn SearchEngine],
            policy(),
        );

        let resilient = search.run("rust", 10, 0);
        let expected = crate::search::search(
            &[&alpha as &dyn SearchEngine, &beta as &dyn SearchEngine],
            "rust",
            10,
        );

        let resilient_urls: Vec<&str> = resilient
            .results
            .iter()
            .map(|result| result.url.as_str())
            .collect();
        let expected_urls: Vec<&str> = expected
            .results
            .iter()
            .map(|result| result.url.as_str())
            .collect();
        assert_eq!(resilient_urls, expected_urls);
        assert_eq!(resilient.results, expected.results);
    }
}
