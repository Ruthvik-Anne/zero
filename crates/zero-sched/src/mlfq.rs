//! Multi-level feedback queue (SCH-01, SCH-02, SCH-07).
//!
//! Classes: interactive, background, batch. Selection uses effective priority
//! (base priority + age), short-task-first within a class, round-robin across
//! equal classes, and weighted fair share per project. Aging guarantees a
//! low-priority job is eventually served.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkClass {
    Interactive,
    Background,
    Batch,
}

impl WorkClass {
    pub const ALL: [WorkClass; 3] = [WorkClass::Interactive, WorkClass::Background, WorkClass::Batch];

    fn index(self) -> usize {
        match self {
            WorkClass::Interactive => 0,
            WorkClass::Background => 1,
            WorkClass::Batch => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            WorkClass::Interactive => "interactive",
            WorkClass::Background => "background",
            WorkClass::Batch => "batch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub class: WorkClass,
    pub project: String,
    pub priority: i32,
    /// Short-task-first uses this estimate within a class.
    pub estimate_ms: u64,
    pub submitted_ms: i64,
    pub sequence: u64,
}

#[derive(Debug, Clone)]
pub struct MlFq {
    waiting: Vec<Job>,
    weights: BTreeMap<String, f64>,
    served: BTreeMap<String, u64>,
    aging_ms: i64,
    sequence: u64,
    class_cursor: usize,
    /// (time, job id) for every dispatch.
    pub history: Vec<(i64, String)>,
}

impl MlFq {
    pub fn new(aging_ms: i64) -> Self {
        Self {
            waiting: Vec::new(),
            weights: BTreeMap::new(),
            served: BTreeMap::new(),
            aging_ms,
            sequence: 0,
            class_cursor: 0,
            history: Vec::new(),
        }
    }

    pub fn set_weight(&mut self, project: &str, weight: f64) {
        self.weights.insert(project.to_string(), weight.max(0.1));
    }

    pub fn submit(&mut self, id: impl Into<String>, class: WorkClass, project: impl Into<String>, priority: i32, estimate_ms: u64, now_ms: i64) -> String {
        let id = id.into();
        let project = project.into();
        self.weights.entry(project.clone()).or_insert(1.0);
        self.waiting.push(Job {
            id: id.clone(),
            class,
            project,
            priority,
            estimate_ms,
            submitted_ms: now_ms,
            sequence: self.sequence,
        });
        self.sequence += 1;
        id
    }

    pub fn waiting(&self) -> &[Job] {
        &self.waiting
    }

    pub fn served_ms(&self, project: &str) -> u64 {
        self.served.get(project).copied().unwrap_or(0)
    }

    fn effective(&self, job: &Job, now_ms: i64) -> i64 {
        job.priority as i64 + (now_ms - job.submitted_ms) / self.aging_ms.max(1)
    }

    fn share(&self, project: &str) -> f64 {
        let served = self.served.get(project).copied().unwrap_or(0) as f64;
        let weight = self.weights.get(project).copied().unwrap_or(1.0);
        served / weight
    }

    /// Pick and remove the next job. `quantum_ms` is charged to the project's
    /// fair-share counter.
    pub fn next(&mut self, now_ms: i64, quantum_ms: u64) -> Option<Job> {
        if self.waiting.is_empty() {
            return None;
        }
        let best_effective = self
            .waiting
            .iter()
            .map(|job| self.effective(job, now_ms))
            .max()
            .expect("non-empty");
        let top: Vec<&Job> = self
            .waiting
            .iter()
            .filter(|job| self.effective(job, now_ms) == best_effective)
            .collect();
        // Round-robin across equal classes starting after the last class served.
        let chosen_class = (0..WorkClass::ALL.len())
            .map(|offset| WorkClass::ALL[(self.class_cursor + offset) % WorkClass::ALL.len()])
            .find(|class| top.iter().any(|job| job.class == *class))
            .unwrap_or(WorkClass::Interactive);
        let mut candidates: Vec<&Job> = top.into_iter().filter(|job| job.class == chosen_class).collect();
        // Short-task-first, then fair share, then arrival order.
        candidates.sort_by(|a, b| {
            a.estimate_ms
                .cmp(&b.estimate_ms)
                .then_with(|| self.share(&a.project).partial_cmp(&self.share(&b.project)).unwrap_or(std::cmp::Ordering::Equal))
                .then(a.sequence.cmp(&b.sequence))
        });
        let chosen = (*candidates.first()?).clone();
        self.waiting.retain(|job| job.id != chosen.id);
        *self.served.entry(chosen.project.clone()).or_insert(0) += quantum_ms;
        self.class_cursor = (chosen_class.index() + 1) % WorkClass::ALL.len();
        self.history.push((now_ms, chosen.id.clone()));
        Some(chosen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_tasks_run_first_within_a_class() {
        let mut queue = MlFq::new(100);
        queue.submit("long", WorkClass::Batch, "p", 0, 500, 0);
        queue.submit("short", WorkClass::Batch, "p", 0, 10, 0);
        assert_eq!(queue.next(0, 10).unwrap().id, "short");
        assert_eq!(queue.next(0, 10).unwrap().id, "long");
    }

    #[test]
    fn equal_classes_round_robin() {
        let mut queue = MlFq::new(100);
        queue.submit("i", WorkClass::Interactive, "p", 0, 10, 0);
        queue.submit("b", WorkClass::Background, "p", 0, 10, 0);
        queue.submit("t", WorkClass::Batch, "p", 0, 10, 0);
        let first = queue.next(0, 5).unwrap();
        let second = queue.next(0, 5).unwrap();
        let third = queue.next(0, 5).unwrap();
        // Starting at interactive, the equal-priority classes cycle.
        assert_eq!(first.class, WorkClass::Interactive);
        assert_eq!(second.class, WorkClass::Background);
        assert_eq!(third.class, WorkClass::Batch);
    }

    #[test]
    fn aging_prevents_starvation_under_a_priority_flood() {
        let mut queue = MlFq::new(1);
        queue.submit("starved", WorkClass::Batch, "p", 0, 10, 0);
        let mut served_at = None;
        for tick in 1..=1000 {
            queue.submit(format!("high-{tick}"), WorkClass::Interactive, "other", 5, 10, tick);
            let job = queue.next(tick, 1).unwrap();
            if job.id == "starved" {
                served_at = Some(tick);
                break;
            }
        }
        assert!(served_at.is_some(), "the low-priority job starved");
        assert!(served_at.unwrap() <= 10, "served at {served_at:?}");
    }

    #[test]
    fn weighted_fair_share_tracks_the_weights() {
        let mut queue = MlFq::new(1000);
        queue.set_weight("interactive", 3.0);
        queue.set_weight("background", 1.0);
        for i in 0..80 {
            queue.submit(format!("i{i}"), WorkClass::Batch, "interactive", 0, 10, 0);
            queue.submit(format!("b{i}"), WorkClass::Batch, "background", 0, 10, 0);
        }
        for _ in 0..80 {
            queue.next(0, 1).unwrap();
        }
        let i = queue.served_ms("interactive");
        let b = queue.served_ms("background");
        assert!(i > b * 2, "3:1 weight should favour interactive: {i} vs {b}");
    }

    #[test]
    fn interactive_preempts_background_at_the_next_selection() {
        let mut queue = MlFq::new(1000);
        queue.submit("bg", WorkClass::Background, "p", 0, 10, 0);
        queue.submit("fg", WorkClass::Interactive, "p", 0, 10, 0);
        // Effective ties resolve to the round-robin class, but an interactive
        // job submitted with higher priority wins immediately.
        queue.submit("fg2", WorkClass::Interactive, "p", 5, 10, 0);
        let first = queue.next(0, 1).unwrap();
        assert_eq!(first.id, "fg2");
    }

    #[test]
    fn nothing_ready_returns_none() {
        let mut queue = MlFq::new(10);
        assert!(queue.next(0, 1).is_none());
    }
}
