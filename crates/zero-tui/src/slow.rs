//! Slow-terminal detection (TUI-10): write latency lowers the frame rate while
//! input stays independent.

use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalSpeed {
    Normal,
    Slow,
}

#[derive(Debug, Clone)]
pub struct LatencyMonitor {
    samples: VecDeque<u64>,
    capacity: usize,
    slow_threshold_ms: u64,
}

impl Default for LatencyMonitor {
    fn default() -> Self {
        Self { samples: VecDeque::new(), capacity: 10, slow_threshold_ms: 25 }
    }
}

impl LatencyMonitor {
    pub fn new(slow_threshold_ms: u64) -> Self {
        Self { slow_threshold_ms, ..Self::default() }
    }

    pub fn observe(&mut self, write_ms: u64) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(write_ms);
    }

    pub fn median(&self) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut values: Vec<u64> = self.samples.iter().copied().collect();
        values.sort_unstable();
        values[values.len() / 2]
    }

    pub fn speed(&self) -> TerminalSpeed {
        if self.median() >= self.slow_threshold_ms {
            TerminalSpeed::Slow
        } else {
            TerminalSpeed::Normal
        }
    }

    /// Frame interval: a slow terminal gets at least twice its write latency, so
    /// frames coalesce instead of queueing.
    pub fn frame_interval_ms(&self, normal_ms: u64) -> u64 {
        match self.speed() {
            TerminalSpeed::Normal => normal_ms,
            TerminalSpeed::Slow => normal_ms.max(self.median().saturating_mul(2)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forty_millisecond_writes_switch_to_slow_frames() {
        let mut monitor = LatencyMonitor::default();
        for _ in 0..10 {
            monitor.observe(40);
        }
        assert_eq!(monitor.speed(), TerminalSpeed::Slow);
        assert!(monitor.frame_interval_ms(16) >= 80, "interval {}", monitor.frame_interval_ms(16));
    }

    #[test]
    fn fast_writes_stay_normal() {
        let mut monitor = LatencyMonitor::default();
        for _ in 0..10 {
            monitor.observe(2);
        }
        assert_eq!(monitor.speed(), TerminalSpeed::Normal);
        assert_eq!(monitor.frame_interval_ms(16), 16);
    }
}
