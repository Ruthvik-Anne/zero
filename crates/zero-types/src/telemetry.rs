//! Telemetry policy (FND-12).
//!
//! Zero sends nothing off the machine or mesh without an explicit opt-in. The
//! default build has no sender at all: events are counted locally and dropped.
//! A network capture of a normal session therefore shows only provider and mesh
//! traffic the user configured.

use crate::error::{ErrorCode, Result, ZeroError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryMode {
    /// No telemetry is collected or sent. The default.
    #[default]
    Off,
    /// The user explicitly opted in; a sender may exist in that build.
    OptIn,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryCounters {
    pub events_dropped: u64,
    pub events_queued: u64,
    pub network_attempts: u64,
}

/// Local-only telemetry guard. There is deliberately no sender implementation in
/// this milestone; opting in only permits a future sender.
#[derive(Debug, Clone)]
pub struct TelemetryGuard {
    mode: TelemetryMode,
    counters: TelemetryCounters,
}

impl Default for TelemetryGuard {
    fn default() -> Self {
        Self::new(TelemetryMode::Off)
    }
}

impl TelemetryGuard {
    pub fn new(mode: TelemetryMode) -> Self {
        Self { mode, counters: TelemetryCounters::default() }
    }

    pub fn mode(&self) -> TelemetryMode {
        self.mode
    }

    pub fn counters(&self) -> &TelemetryCounters {
        &self.counters
    }

    /// Record a local event. With telemetry off it is counted and dropped; no
    /// sink is invoked and no network socket is opened.
    pub fn record(&mut self, _name: &str) -> Result<()> {
        match self.mode {
            TelemetryMode::Off => self.counters.events_dropped += 1,
            TelemetryMode::OptIn => self.counters.events_queued += 1,
        }
        Ok(())
    }

    /// Attempt to transmit. Always refuses in this build, with a typed error.
    pub fn transmit(&mut self) -> Result<()> {
        if self.mode == TelemetryMode::Off {
            return Err(ZeroError::new(
                ErrorCode::Unavailable,
                "telemetry is off; nothing is sent",
            ));
        }
        self.counters.network_attempts += 1;
        Err(ZeroError::new(
            ErrorCode::Unavailable,
            "this build has no telemetry sender; nothing is sent",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_build_drops_every_event_and_never_sends() {
        let mut guard = TelemetryGuard::default();
        for _ in 0..100 {
            guard.record("turn").unwrap();
        }
        assert_eq!(guard.counters().events_dropped, 100);
        assert_eq!(guard.counters().network_attempts, 0);
        let err = guard.transmit().unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert_eq!(guard.counters().network_attempts, 0);
    }

    #[test]
    fn opt_in_permits_queueing_but_this_build_still_has_no_sender() {
        let mut guard = TelemetryGuard::new(TelemetryMode::OptIn);
        guard.record("turn").unwrap();
        assert_eq!(guard.counters().events_queued, 1);
        assert!(guard.transmit().is_err());
    }
}
