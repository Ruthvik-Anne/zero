//! Backoff, per-provider circuit breakers, and retry caps (SCH-05).
//!
//! Backoff is exponential with deterministic jitter. A breaker opens only for
//! its provider, so one outage never stalls another. Retries never rotate
//! credentials to evade a limit.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zero_types::id::DeterministicRng;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_ms: u64,
    pub max_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 3, base_ms: 200, max_ms: 5_000 }
    }
}

#[derive(Debug, Clone)]
pub struct Backoff {
    policy: RetryPolicy,
    attempt: u32,
    rng: DeterministicRng,
}

impl Backoff {
    pub fn new(policy: RetryPolicy, seed: u64) -> Self {
        Self { policy, attempt: 0, rng: DeterministicRng::new(seed) }
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// The next delay, or None when the retry cap is exhausted.
    pub fn next_delay(&mut self) -> Option<u64> {
        if self.attempt >= self.policy.max_attempts {
            return None;
        }
        let exponential = self.policy.base_ms.saturating_mul(1u64 << self.attempt.min(10));
        let capped = exponential.min(self.policy.max_ms);
        let jitter = self.rng.below(100) as u64;
        self.attempt += 1;
        Some(capped / 2 + jitter % (capped / 2 + 1))
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    failures: u32,
    threshold: u32,
    cooldown_ms: i64,
    open_until_ms: i64,
    state: BreakerState,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, cooldown_ms: i64) -> Self {
        Self { failures: 0, threshold, cooldown_ms, open_until_ms: 0, state: BreakerState::Closed }
    }

    pub fn state(&self) -> BreakerState {
        self.state
    }

    pub fn allow(&mut self, now_ms: i64) -> bool {
        match self.state {
            BreakerState::Closed => true,
            BreakerState::Open if now_ms >= self.open_until_ms => {
                self.state = BreakerState::HalfOpen;
                true
            }
            BreakerState::Open => false,
            BreakerState::HalfOpen => true,
        }
    }

    pub fn record_success(&mut self) {
        self.failures = 0;
        self.state = BreakerState::Closed;
        self.open_until_ms = 0;
    }

    pub fn record_failure(&mut self, now_ms: i64) {
        self.failures += 1;
        if self.failures >= self.threshold {
            self.state = BreakerState::Open;
            self.open_until_ms = now_ms + self.cooldown_ms;
        }
    }
}

/// Per-provider breakers; an outage in one provider is isolated.
#[derive(Debug, Default, Clone)]
pub struct ProviderBreakers {
    breakers: BTreeMap<String, CircuitBreaker>,
}

impl ProviderBreakers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn breaker(&mut self, provider: &str, threshold: u32, cooldown_ms: i64) -> &mut CircuitBreaker {
        self.breakers.entry(provider.into()).or_insert_with(|| CircuitBreaker::new(threshold, cooldown_ms))
    }

    pub fn allow(&mut self, provider: &str, now_ms: i64) -> bool {
        self.breakers.get_mut(provider).map(|b| b.allow(now_ms)).unwrap_or(true)
    }

    pub fn record_success(&mut self, provider: &str) {
        if let Some(breaker) = self.breakers.get_mut(provider) {
            breaker.record_success();
        }
    }

    pub fn record_failure(&mut self, provider: &str, now_ms: i64) {
        if let Some(breaker) = self.breakers.get_mut(provider) {
            breaker.record_failure(now_ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_capped_and_the_retry_cap_stops() {
        let mut backoff = Backoff::new(RetryPolicy { max_attempts: 3, base_ms: 100, max_ms: 300 }, 7);
        let mut delays = Vec::new();
        while let Some(delay) = backoff.next_delay() {
            delays.push(delay);
        }
        assert_eq!(delays.len(), 3);
        assert!(delays.iter().all(|d| *d <= 300));
        assert!(backoff.next_delay().is_none());
        assert_eq!(backoff.attempt(), 3);
    }

    #[test]
    fn one_provider_outage_does_not_stall_another() {
        let mut breakers = ProviderBreakers::new();
        breakers.breaker("a", 2, 1000);
        breakers.breaker("b", 2, 1000);
        breakers.record_failure("a", 0);
        breakers.record_failure("a", 1);
        assert!(!breakers.allow("a", 2), "a is open");
        assert!(breakers.allow("b", 2), "b is unaffected");
        assert!(!breakers.allow("a", 500), "still open inside the cooldown");
        assert!(breakers.allow("a", 1001), "half-open after the cooldown");
        breakers.record_success("a");
        assert!(breakers.allow("a", 1002));
    }

    #[test]
    fn jitter_is_deterministic_for_a_seed() {
        let delays = |seed| {
            let mut backoff = Backoff::new(RetryPolicy::default(), seed);
            (0..3).filter_map(|_| backoff.next_delay()).collect::<Vec<_>>()
        };
        assert_eq!(delays(9), delays(9));
    }
}
