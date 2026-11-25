//! Usage windows and reset resume (SCH-14, AR-06).
//!
//! A subscription window has a capacity and reset time. Work pauses at the
//! boundary when the window is exhausted and resumes when it resets, without
//! replaying side effects.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageWindow {
    pub capacity: u64,
    pub used: u64,
    pub window_ms: i64,
    pub resets_at_ms: i64,
}

impl UsageWindow {
    pub fn new(capacity: u64, window_ms: i64, now_ms: i64) -> Self {
        Self { capacity, used: 0, window_ms, resets_at_ms: now_ms + window_ms }
    }

    fn maybe_reset(&mut self, now_ms: i64) {
        while now_ms >= self.resets_at_ms {
            self.used = 0;
            self.resets_at_ms += self.window_ms;
        }
    }

    pub fn remaining(&mut self, now_ms: i64) -> u64 {
        self.maybe_reset(now_ms);
        self.capacity.saturating_sub(self.used)
    }

    pub fn consume(&mut self, amount: u64, now_ms: i64) -> Result<u64> {
        let remaining = self.remaining(now_ms);
        if amount > remaining {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!("usage window has {remaining} remaining, requested {amount}; pause until {}", self.resets_at_ms),
            ));
        }
        self.used += amount;
        Ok(self.capacity - self.used)
    }

    pub fn should_pause(&mut self, now_ms: i64) -> bool {
        self.remaining(now_ms) == 0
    }

    pub fn next_resume_ms(&mut self, now_ms: i64) -> Option<i64> {
        if self.should_pause(now_ms) {
            Some(self.resets_at_ms)
        } else {
            None
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct WindowScheduler {
    windows: BTreeMap<String, UsageWindow>,
    resumes: BTreeMap<String, u64>,
}

impl WindowScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, credential: &str, capacity: u64, window_ms: i64, now_ms: i64) {
        self.windows.insert(credential.into(), UsageWindow::new(capacity, window_ms, now_ms));
    }

    pub fn consume(&mut self, credential: &str, amount: u64, now_ms: i64) -> Result<u64> {
        let window = self
            .windows
            .get_mut(credential)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("credential `{credential}`")))?;
        window.consume(amount, now_ms)
    }

    pub fn should_pause(&mut self, credential: &str, now_ms: i64) -> bool {
        self.windows.get_mut(credential).map(|w| w.should_pause(now_ms)).unwrap_or(false)
    }

    pub fn next_resume_ms(&mut self, credential: &str, now_ms: i64) -> Option<i64> {
        self.windows.get_mut(credential).and_then(|w| w.next_resume_ms(now_ms))
    }

    /// The scheduled resume fires once per reset; returns true when work may
    /// continue. Effects are never replayed by this call.
    pub fn resume(&mut self, credential: &str, now_ms: i64) -> bool {
        let Some(window) = self.windows.get_mut(credential) else {
            return false;
        };
        let remaining = window.remaining(now_ms);
        if remaining > 0 {
            *self.resumes.entry(credential.into()).or_insert(0) += 1;
            return true;
        }
        false
    }

    pub fn resumes(&self, credential: &str) -> u64 {
        self.resumes.get(credential).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_simulated_window_pauses_and_resumes_on_reset() {
        let mut scheduler = WindowScheduler::new();
        scheduler.register("cred", 2, 1000, 0);
        assert_eq!(scheduler.consume("cred", 2, 100).unwrap(), 0);
        assert!(scheduler.should_pause("cred", 100));
        assert_eq!(scheduler.next_resume_ms("cred", 100), Some(1000));
        assert!(scheduler.consume("cred", 1, 200).is_err());
        assert!(!scheduler.resume("cred", 500));

        // At the reset, capacity is restored and work may resume.
        assert_eq!(scheduler.consume("cred", 1, 1000).unwrap(), 1);
        assert!(scheduler.resume("cred", 1000));
        assert_eq!(scheduler.resumes("cred"), 1);
    }

    #[test]
    fn repeated_resets_advance_the_window() {
        let mut window = UsageWindow::new(1, 100, 0);
        assert_eq!(window.remaining(50), 1);
        window.consume(1, 50).unwrap();
        assert_eq!(window.next_resume_ms(60), Some(100));
        assert_eq!(window.remaining(100), 1);
        window.consume(1, 100).unwrap();
        assert_eq!(window.next_resume_ms(150), Some(200));
        assert_eq!(window.remaining(250), 1);
    }
}
