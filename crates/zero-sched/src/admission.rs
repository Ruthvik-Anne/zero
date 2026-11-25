//! Admission control and token buckets (SCH-04, SCH-08, SCH-13).
//!
//! Per-provider and per-model concurrency, per-credential token buckets, and
//! `Retry-After` handling. A full or rate-limited destination returns an
//! explicit deferral; it never grows an unbounded queue. Accounts are keyed by
//! credential and never rotated to evade a limit.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BucketConfig {
    pub capacity: f64,
    pub refill_per_sec: f64,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_ms: i64,
    config: BucketConfig,
    /// Set by a 429 with Retry-After; no tokens until this time.
    blocked_until_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Admitted(Permit),
    Deferred { reason: String, retry_at_ms: Option<i64> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permit {
    pub provider: String,
    pub model: String,
    pub credential: String,
}

#[derive(Debug, Clone)]
struct ProviderLimit {
    max_concurrent: usize,
    models: BTreeMap<String, usize>,
    in_flight: usize,
    model_in_flight: BTreeMap<String, usize>,
}

#[derive(Debug, Default, Clone)]
pub struct Scheduler {
    providers: BTreeMap<String, ProviderLimit>,
    buckets: BTreeMap<String, TokenBucket>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn limit(&mut self, provider: &str, max_concurrent: usize) {
        self.providers.entry(provider.into()).or_insert(ProviderLimit {
            max_concurrent,
            models: BTreeMap::new(),
            in_flight: 0,
            model_in_flight: BTreeMap::new(),
        }).max_concurrent = max_concurrent;
    }

    pub fn limit_model(&mut self, provider: &str, model: &str, max_concurrent: usize) {
        let entry = self.providers.entry(provider.into()).or_insert(ProviderLimit {
            max_concurrent: usize::MAX,
            models: BTreeMap::new(),
            in_flight: 0,
            model_in_flight: BTreeMap::new(),
        });
        entry.models.insert(model.into(), max_concurrent);
    }

    pub fn bucket(&mut self, credential: &str, config: BucketConfig, now_ms: i64) {
        self.buckets.insert(
            credential.into(),
            TokenBucket { tokens: config.capacity, last_ms: now_ms, config, blocked_until_ms: 0 },
        );
    }

    fn refill(&mut self, credential: &str, now_ms: i64) {
        if let Some(bucket) = self.buckets.get_mut(credential) {
            let elapsed = (now_ms - bucket.last_ms).max(0) as f64 / 1000.0;
            bucket.tokens = (bucket.tokens + elapsed * bucket.config.refill_per_sec).min(bucket.config.capacity);
            bucket.last_ms = now_ms;
        }
    }

    pub fn acquire(&mut self, provider: &str, model: &str, credential: &str, now_ms: i64) -> Result<Admission> {
        self.refill(credential, now_ms);
        if let Some(bucket) = self.buckets.get(credential) {
            if now_ms < bucket.blocked_until_ms {
                return Ok(Admission::Deferred {
                    reason: format!("credential `{credential}` is rate limited"),
                    retry_at_ms: Some(bucket.blocked_until_ms),
                });
            }
            if bucket.tokens < 1.0 {
                return Ok(Admission::Deferred {
                    reason: format!("credential `{credential}` token bucket is empty"),
                    retry_at_ms: None,
                });
            }
        }
        let Some(limit) = self.providers.get_mut(provider) else {
            return Ok(Admission::Deferred { reason: format!("provider `{provider}` is not registered"), retry_at_ms: None });
        };
        if limit.in_flight >= limit.max_concurrent {
            return Ok(Admission::Deferred {
                reason: format!("provider `{provider}` is at its concurrency limit"),
                retry_at_ms: None,
            });
        }
        if let Some(max) = limit.models.get(model).copied() {
            let current = limit.model_in_flight.get(model).copied().unwrap_or(0);
            if current >= max {
                return Ok(Admission::Deferred {
                    reason: format!("model `{model}` is at its concurrency limit"),
                    retry_at_ms: None,
                });
            }
        }
        limit.in_flight += 1;
        *limit.model_in_flight.entry(model.to_string()).or_insert(0) += 1;
        if let Some(bucket) = self.buckets.get_mut(credential) {
            bucket.tokens -= 1.0;
        }
        Ok(Admission::Admitted(Permit {
            provider: provider.into(),
            model: model.into(),
            credential: credential.into(),
        }))
    }

    pub fn release(&mut self, permit: &Permit) {
        if let Some(limit) = self.providers.get_mut(&permit.provider) {
            limit.in_flight = limit.in_flight.saturating_sub(1);
            if let Some(count) = limit.model_in_flight.get_mut(&permit.model) {
                *count = count.saturating_sub(1);
            }
        }
    }

    /// A 429 with `Retry-After` blocks the credential until the retry time.
    pub fn note_rate_limit(&mut self, credential: &str, retry_after_secs: u64, now_ms: i64) -> Result<()> {
        let bucket = self
            .buckets
            .get_mut(credential)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("credential `{credential}` is not registered")))?;
        bucket.tokens = 0.0;
        bucket.blocked_until_ms = now_ms + retry_after_secs as i64 * 1000;
        Ok(())
    }

    pub fn in_flight(&self, provider: &str) -> usize {
        self.providers.get(provider).map(|p| p.in_flight).unwrap_or(0)
    }

    pub fn blocked_until(&self, credential: &str) -> Option<i64> {
        self.buckets.get(credential).map(|b| b.blocked_until_ms).filter(|t| *t > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scheduler() -> Scheduler {
        let mut scheduler = Scheduler::new();
        scheduler.limit("openai", 2);
        scheduler.limit_model("openai", "gpt", 1);
        scheduler.bucket("cred-a", BucketConfig { capacity: 2.0, refill_per_sec: 1.0 }, 0);
        scheduler
    }

    #[test]
    fn concurrency_and_model_limits_defer_explicitly() {
        let mut s = scheduler();
        let first = s.acquire("openai", "gpt", "cred-a", 0).unwrap();
        assert!(matches!(first, Admission::Admitted(_)));
        let model_full = s.acquire("openai", "gpt", "cred-a", 0).unwrap();
        match model_full {
            Admission::Deferred { reason, retry_at_ms } => {
                assert!(reason.contains("model"));
                assert!(retry_at_ms.is_none());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_429_with_retry_after_blocks_until_the_reset() {
        let mut s = scheduler();
        s.note_rate_limit("cred-a", 5, 1000).unwrap();
        let blocked = s.acquire("openai", "gpt", "cred-a", 2000).unwrap();
        match blocked {
            Admission::Deferred { retry_at_ms, .. } => assert_eq!(retry_at_ms, Some(6000)),
            other => panic!("{other:?}"),
        }
        // After the reset the bucket refills and admission succeeds.
        assert!(matches!(s.acquire("openai", "gpt", "cred-a", 7000).unwrap(), Admission::Admitted(_)));
    }

    #[test]
    fn a_provider_and_model_limit_are_independent() {
        let mut s = Scheduler::new();
        s.limit("a", 1);
        s.limit("b", 1);
        let pa = match s.acquire("a", "m", "cred", 0).unwrap() {
            Admission::Admitted(p) => p,
            other => panic!("{other:?}"),
        };
        assert!(matches!(s.acquire("a", "m", "cred", 1).unwrap(), Admission::Deferred { .. }));
        assert!(matches!(s.acquire("b", "m", "cred", 1).unwrap(), Admission::Admitted(_)));
        s.release(&pa);
        assert!(matches!(s.acquire("a", "m", "cred", 2).unwrap(), Admission::Admitted(_)));
    }
}
