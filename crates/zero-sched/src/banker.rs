//! Banker's pools for bounded countable resources (LCK-01..LCK-04, LCK-11, LCK-12).
//!
//! Each worker declares a maximum claim per pool before dispatch. A request is
//! granted only when a safe completion sequence exists for every worker. Grants
//! are atomic (all pools or none), waiting requests age, and preemption is only
//! allowed at a safe boundary. The safety check is bounded by workers × pools.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    Kernel,
    Provider,
    Transfer,
    Subagent,
    Browser,
    Desktop,
}

impl PoolKind {
    pub const ALL: [PoolKind; 6] = [
        PoolKind::Kernel,
        PoolKind::Provider,
        PoolKind::Transfer,
        PoolKind::Subagent,
        PoolKind::Browser,
        PoolKind::Desktop,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            PoolKind::Kernel => "kernel",
            PoolKind::Provider => "provider",
            PoolKind::Transfer => "transfer",
            PoolKind::Subagent => "subagent",
            PoolKind::Browser => "browser",
            PoolKind::Desktop => "desktop",
        }
    }
}

pub type Request = BTreeMap<PoolKind, u32>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclareOutcome {
    pub bounded: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    Granted { fence: u64 },
    Waiting { reason: String },
}

#[derive(Debug, Clone)]
pub struct WaitEntry {
    worker: String,
    request: Request,
    since_ms: i64,
    priority: i32,
}

pub struct Banker {
    totals: Request,
    maxima: BTreeMap<String, Request>,
    allocations: BTreeMap<String, Request>,
    waiting: Vec<WaitEntry>,
    degraded: BTreeMap<String, String>,
    fences: BTreeMap<String, u64>,
    next_fence: u64,
    /// Degraded workers acquire this ordered set without declared maxima.
    ordered: BTreeMap<String, String>,
    /// Steps used by the last safety check (bounded by workers × pools).
    pub last_check_steps: usize,
}

impl Banker {
    pub fn new(totals: Request) -> Self {
        Self {
            totals,
            maxima: BTreeMap::new(),
            allocations: BTreeMap::new(),
            waiting: Vec::new(),
            degraded: BTreeMap::new(),
            fences: BTreeMap::new(),
            next_fence: 1,
            ordered: BTreeMap::new(),
            last_check_steps: 0,
        }
    }

    pub fn totals(&self) -> &Request {
        &self.totals
    }

    /// Declare bounded maxima. Omitting them is reported as degraded (LCK-06).
    pub fn declare(&mut self, worker: &str, maxima: Option<Request>) -> Result<DeclareOutcome> {
        let Some(maxima) = maxima else {
            let reason = format!("`{worker}` did not declare bounded maxima; using ordered acquisition with timeouts");
            self.degraded.insert(worker.to_string(), reason.clone());
            return Ok(DeclareOutcome { bounded: false, reason: Some(reason) });
        };
        if maxima.is_empty() {
            let reason = format!("`{worker}` declared an empty maximum; using ordered acquisition with timeouts");
            self.degraded.insert(worker.to_string(), reason.clone());
            return Ok(DeclareOutcome { bounded: false, reason: Some(reason) });
        }
        for (kind, amount) in &maxima {
            let total = self.totals.get(kind).copied().unwrap_or(0);
            if *amount > total {
                return Err(ZeroError::new(
                    ErrorCode::PoolMaxima,
                    format!("`{worker}` declares {} {} but the pool has {total}", amount, kind.as_str()),
                ));
            }
        }
        self.degraded.remove(worker);
        self.maxima.insert(worker.to_string(), maxima);
        self.allocations.entry(worker.to_string()).or_default();
        Ok(DeclareOutcome { bounded: true, reason: None })
    }

    pub fn degraded_workers(&self) -> Vec<(String, String)> {
        self.degraded.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    pub fn is_degraded(&self, worker: &str) -> bool {
        self.degraded.contains_key(worker)
    }

    fn available(&self) -> Request {
        let mut available = self.totals.clone();
        for allocation in self.allocations.values() {
            for (kind, amount) in allocation {
                *available.entry(*kind).or_insert(0) = available.get(kind).copied().unwrap_or(0).saturating_sub(*amount);
            }
        }
        available
    }

    fn need(&self, worker: &str) -> Request {
        let mut need = Request::new();
        if let Some(maxima) = self.maxima.get(worker) {
            let allocated = self.allocations.get(worker);
            for (kind, max) in maxima {
                let used = allocated.and_then(|a| a.get(kind)).copied().unwrap_or(0);
                need.insert(*kind, max.saturating_sub(used));
            }
        }
        need
    }

    fn fits(need: &Request, available: &Request) -> bool {
        need.iter().all(|(kind, amount)| *amount <= available.get(kind).copied().unwrap_or(0))
    }

    fn add(target: &mut Request, add: &Request) {
        for (kind, amount) in add {
            *target.entry(*kind).or_insert(0) += amount;
        }
    }

    fn sub(target: &mut Request, sub: &Request) {
        for (kind, amount) in sub {
            let entry = target.entry(*kind).or_insert(0);
            *entry = entry.saturating_sub(*amount);
        }
    }

    /// Simulated completion of every declared worker, including an optional
    /// pending request for `extra`. Deterministic order for a stable bound.
    fn safe_with(&mut self, extra: Option<(&str, &Request)>) -> bool {
        let mut available = self.available();
        let mut workers: Vec<String> = self.maxima.keys().cloned().collect();
        if let Some((worker, request)) = extra {
            if !Self::fits(request, &available) {
                return false;
            }
            Self::sub(&mut available, request);
            if !workers.iter().any(|w| w == worker) {
                workers.push(worker.to_string());
            }
        }
        let mut finished: BTreeSet<String> = BTreeSet::new();
        let mut steps = 0usize;
        loop {
            let mut progress = false;
            for worker in &workers {
                if finished.contains(worker) {
                    continue;
                }
                steps += 1;
                let need = if Some(worker.as_str()) == extra.map(|(w, _)| w) {
                    let mut need = self.need(worker);
                    // The request is now allocated; the worker still needs the rest.
                    Self::sub(&mut need, extra.map(|(_, r)| r).unwrap_or(&Request::new()));
                    need
                } else {
                    self.need(worker)
                };
                if Self::fits(&need, &available) {
                    let allocated = self.allocations.get(worker).cloned().unwrap_or_default();
                    Self::add(&mut available, &allocated);
                    if let Some((w, request)) = extra {
                        if w == worker {
                            Self::add(&mut available, request);
                        }
                    }
                    finished.insert(worker.clone());
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
        self.last_check_steps = steps;
        finished.len() == workers.len()
    }

    pub fn check_safety(&mut self) -> bool {
        self.safe_with(None)
    }

    /// Request a vector of claims. The grant is all-or-nothing.
    pub fn request(&mut self, worker: &str, request: Request, now_ms: i64, priority: i32) -> Result<Grant> {
        let maxima = self
            .maxima
            .get(worker)
            .ok_or_else(|| ZeroError::new(ErrorCode::PolicyDenied, format!("`{worker}` has not declared maxima")))?;
        let allocated_now = self.allocations.get(worker).cloned().unwrap_or_default();
        for (kind, amount) in &request {
            let max = maxima.get(kind).copied().unwrap_or(0);
            let held = allocated_now.get(kind).copied().unwrap_or(0);
            if held + *amount > max {
                return Err(ZeroError::new(
                    ErrorCode::PoolMaxima,
                    format!("`{worker}` requests {amount} {} above its remaining maximum {max} (held {held})", kind.as_str()),
                ));
            }
        }
        if self.safe_with(Some((worker, &request))) {
            let allocation = self.allocations.entry(worker.to_string()).or_default();
            Self::add(allocation, &request);
            let fence = self.next_fence;
            self.next_fence += 1;
            self.fences.insert(worker.to_string(), fence);
            self.waiting.retain(|w| w.worker != worker);
            Ok(Grant::Granted { fence })
        } else {
            if !self.waiting.iter().any(|w| w.worker == worker) {
                self.waiting.push(WaitEntry { worker: worker.into(), request, since_ms: now_ms, priority });
            }
            Ok(Grant::Waiting { reason: "no safe completion sequence; request is waiting".into() })
        }
    }

    /// Grant aged waiting requests that are now safe, oldest/highest priority
    /// first. Returns the granted workers with fences.
    pub fn promote_aged(&mut self, now_ms: i64, aging_ms: i64) -> Result<Vec<(String, u64)>> {
        let mut candidates = self.waiting.clone();
        candidates.sort_by(|a, b| {
            let age_a = (now_ms - a.since_ms) / aging_ms.max(1);
            let age_b = (now_ms - b.since_ms) / aging_ms.max(1);
            let score_a = a.priority + age_a as i32;
            let score_b = b.priority + age_b as i32;
            score_b.cmp(&score_a).then(a.since_ms.cmp(&b.since_ms))
        });
        let mut granted = Vec::new();
        for candidate in candidates {
            if now_ms - candidate.since_ms < aging_ms {
                continue;
            }
            if self.safe_with(Some((&candidate.worker, &candidate.request))) {
                let allocation = self.allocations.entry(candidate.worker.clone()).or_default();
                Self::add(allocation, &candidate.request);
                let fence = self.next_fence;
                self.next_fence += 1;
                self.fences.insert(candidate.worker.clone(), fence);
                self.waiting.retain(|w| w.worker != candidate.worker);
                granted.push((candidate.worker, fence));
            }
        }
        Ok(granted)
    }

    pub fn release(&mut self, worker: &str, request: &Request) -> Result<()> {
        let allocation = self
            .allocations
            .get_mut(worker)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("`{worker}` has no allocation")))?;
        Self::sub(allocation, request);
        Ok(())
    }

    pub fn allocated(&self, worker: &str) -> Request {
        self.allocations.get(worker).cloned().unwrap_or_default()
    }

    pub fn waiting(&self) -> &[WaitEntry] {
        &self.waiting
    }

    /// Preempt a worker's allocation only at a safe boundary. The victim's fence
    /// advances, so a stale token cannot write.
    pub fn preempt(&mut self, worker: &str, at_safe_boundary: bool) -> Result<Request> {
        if !at_safe_boundary {
            return Err(ZeroError::new(
                ErrorCode::UnsafePreemption,
                "preemption is only allowed at a safe boundary",
            ));
        }
        let freed = self
            .allocations
            .get_mut(worker)
            .map(std::mem::take)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("`{worker}` has no allocation")))?;
        let fence = self.next_fence;
        self.next_fence += 1;
        self.fences.insert(worker.to_string(), fence);
        Ok(freed)
    }

    pub fn fence(&self, worker: &str) -> Option<u64> {
        self.fences.get(worker).copied()
    }

    /// Ordered fallback for a worker that could not declare maxima (LCK-06):
    /// acquire a canonical-ordered set with a hard timeout, all or nothing.
    pub fn acquire_ordered(&mut self, worker: &str, resources: &[String], now_ms: i64, deadline_ms: i64) -> Result<Vec<String>> {
        if !self.is_degraded(worker) {
            return Err(ZeroError::new(ErrorCode::PolicyDenied, "ordered acquisition is the degraded path only"));
        }
        if now_ms >= deadline_ms {
            return Err(ZeroError::new(ErrorCode::Timeout, "ordered acquisition timed out"));
        }
        let mut sorted: Vec<String> = resources.to_vec();
        sorted.sort();
        sorted.dedup();
        for resource in &sorted {
            if let Some(holder) = self.ordered.get(resource) {
                if holder != worker {
                    return Err(ZeroError::new(
                        ErrorCode::Locked,
                        format!("`{resource}` is held by `{holder}`"),
                    ));
                }
            }
        }
        for resource in &sorted {
            self.ordered.insert(resource.clone(), worker.to_string());
        }
        Ok(sorted)
    }

    pub fn release_ordered(&mut self, worker: &str) {
        self.ordered.retain(|_, holder| holder != worker);
    }

    pub fn validate_fence(&self, worker: &str, fence: u64) -> Result<()> {
        if self.fences.get(worker).copied() == Some(fence) {
            Ok(())
        } else {
            Err(ZeroError::new(ErrorCode::Stale, "the pool grant was preempted"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(pairs: &[(PoolKind, u32)]) -> Request {
        pairs.iter().copied().collect()
    }

    fn bank() -> Banker {
        let mut b = Banker::new(request(&[(PoolKind::Kernel, 2), (PoolKind::Provider, 1)]));
        b.declare("a", Some(request(&[(PoolKind::Kernel, 2), (PoolKind::Provider, 1)]))).unwrap();
        b.declare("b", Some(request(&[(PoolKind::Kernel, 1), (PoolKind::Provider, 1)]))).unwrap();
        b
    }

    #[test]
    fn grants_are_atomic_and_exceeding_maxima_aborts() {
        let mut banker = bank();
        let grant = banker.request("a", request(&[(PoolKind::Kernel, 1), (PoolKind::Provider, 1)]), 0, 0).unwrap();
        assert!(matches!(grant, Grant::Granted { .. }));
        let err = banker
            .request("a", request(&[(PoolKind::Kernel, 2), (PoolKind::Provider, 1)]), 1, 0)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PoolMaxima, "a batch above the declared maximum is aborted");
        // No partial allocation from the failed batch.
        assert_eq!(banker.allocated("a").get(&PoolKind::Kernel), Some(&1));
    }

    #[test]
    fn the_safety_check_is_bounded_and_rejects_a_deadlocking_request() {
        let mut banker = Banker::new(request(&[(PoolKind::Kernel, 1), (PoolKind::Provider, 1)]));
        banker.declare("a", Some(request(&[(PoolKind::Kernel, 1), (PoolKind::Provider, 1)]))).unwrap();
        banker.declare("b", Some(request(&[(PoolKind::Kernel, 1), (PoolKind::Provider, 1)]))).unwrap();

        assert!(matches!(
            banker.request("a", request(&[(PoolKind::Kernel, 1)]), 0, 0).unwrap(),
            Grant::Granted { .. }
        ));
        assert!(banker.check_safety(), "a can finish and release");

        // Granting b the last provider would leave neither able to finish.
        let waiting = banker.request("b", request(&[(PoolKind::Provider, 1)]), 1, 0).unwrap();
        assert!(matches!(waiting, Grant::Waiting { .. }));
        assert!(banker.allocated("b").is_empty(), "an unsafe batch is not partially granted");
        assert!(
            banker.last_check_steps <= (2 + 1) * PoolKind::ALL.len() + 6,
            "safety check is bounded: {} steps",
            banker.last_check_steps
        );

        // Releasing a's kernel slot makes b's aged request safe.
        banker.release("a", &request(&[(PoolKind::Kernel, 1)])).unwrap();
        let granted = banker.promote_aged(2000, 1000).unwrap();
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].0, "b");
    }

    #[test]
    fn waiting_requests_age_into_a_grant() {
        let mut banker = bank();
        banker.request("a", request(&[(PoolKind::Provider, 1)]), 0, 10).unwrap();
        let waiting = banker.request("b", request(&[(PoolKind::Provider, 1)]), 10, 0).unwrap();
        assert!(matches!(waiting, Grant::Waiting { .. }));
        assert!(banker.promote_aged(20, 1000).unwrap().is_empty());
        banker.release("a", &request(&[(PoolKind::Provider, 1)])).unwrap();
        let granted = banker.promote_aged(2000, 1000).unwrap();
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].0, "b");
    }

    #[test]
    fn preemption_requires_a_safe_boundary_and_fences_the_victim() {
        let mut banker = bank();
        let fence = match banker.request("a", request(&[(PoolKind::Kernel, 1)]), 0, 0).unwrap() {
            Grant::Granted { fence } => fence,
            _ => panic!("expected grant"),
        };
        assert_eq!(banker.preempt("a", false).unwrap_err().code(), ErrorCode::UnsafePreemption);
        let freed = banker.preempt("a", true).unwrap();
        assert_eq!(freed.get(&PoolKind::Kernel), Some(&1));
        assert!(banker.validate_fence("a", fence).is_err(), "the stale grant is rejected");
    }

    #[test]
    fn a_degraded_worker_uses_ordered_acquisition_with_timeouts() {
        let mut banker = bank();
        banker.declare("c", None).unwrap();
        let granted = banker
            .acquire_ordered("c", &["b".into(), "a".into()], 0, 100)
            .unwrap();
        assert_eq!(granted, vec!["a".to_string(), "b".to_string()], "canonical order");
        let blocked = banker.acquire_ordered("d", &["a".into()], 1, 100).unwrap_err();
        assert_eq!(blocked.code(), ErrorCode::PolicyDenied, "d is not degraded");
        banker.declare("d", Some(request(&[(PoolKind::Kernel, 1)]))).unwrap();
        assert!(!banker.declare("d", None).unwrap().bounded);
        let conflict = banker.acquire_ordered("d", &["a".into()], 2, 100).unwrap_err();
        assert_eq!(conflict.code(), ErrorCode::Locked);
        let timeout = banker.acquire_ordered("c", &["c".into()], 200, 100).unwrap_err();
        assert_eq!(timeout.code(), ErrorCode::Timeout);
        banker.release_ordered("c");
        assert!(banker.acquire_ordered("c", &["a".into()], 201, 300).is_ok());
    }

    #[test]
    fn a_worker_without_maxima_is_degraded_with_a_reason() {
        let mut banker = bank();
        let outcome = banker.declare("c", None).unwrap();
        assert!(!outcome.bounded);
        assert!(outcome.reason.as_deref().unwrap().contains("ordered acquisition"));
        assert!(banker.is_degraded("c"));
        assert_eq!(banker.degraded_workers().len(), 1);
        assert!(banker.degraded_workers()[0].1.contains("timeouts"));
    }
}
