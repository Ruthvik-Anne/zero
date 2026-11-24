//! Deterministic simulation harness (TST-03): a seeded scheduler, a fake clock,
//! and an interleaving explorer.
//!
//! A trace is a list of strings keyed by logical tick, so the same seed must
//! reproduce it exactly on every run and every platform.

use crate::id::FakeClock;
use crate::id::DeterministicRng;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ActorId(pub u64);

type Action = Box<dyn FnOnce(&mut Vec<String>, u64) + Send>;

struct Step {
    label: String,
    action: Action,
}

/// A seeded cooperative scheduler. Tasks advance one step at a time in an order
/// decided by the seed, so interleavings are reproducible.
pub struct Simulation {
    seed: u64,
    rng: DeterministicRng,
    clock: FakeClock,
    tick: u64,
    ready: VecDeque<Step>,
    trace: Arc<Mutex<Vec<String>>>,
    next_actor: u64,
}

impl Simulation {
    pub fn new(seed: u64, clock: FakeClock) -> Self {
        Self {
            seed,
            rng: DeterministicRng::new(seed),
            clock,
            tick: 0,
            ready: VecDeque::new(),
            trace: Arc::new(Mutex::new(Vec::new())),
            next_actor: 0,
        }
    }

    pub fn clock(&self) -> &FakeClock {
        &self.clock
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn new_actor(&mut self) -> ActorId {
        let id = ActorId(self.next_actor);
        self.next_actor += 1;
        id
    }

    pub fn schedule<F>(&mut self, label: impl Into<String>, f: F)
    where
        F: FnOnce(&mut Vec<String>, u64) + Send + 'static,
    {
        self.next_actor += 1;
        self.ready.push_back(Step { label: label.into(), action: Box::new(f) });
    }

    /// Run one step chosen by the seeded RNG. Returns false when nothing is ready.
    pub fn step(&mut self) -> bool {
        if self.ready.is_empty() {
            return false;
        }
        let idx = self.rng.below(self.ready.len() as u32) as usize;
        let step = self.ready.remove(idx).expect("index in range");
        self.tick += 1;
        let mut trace = self.trace.lock().expect("trace lock");
        trace.push(format!("t{}:{}", self.tick, step.label));
        (step.action)(&mut trace, self.tick);
        drop(trace);
        true
    }

    pub fn run_all(&mut self) {
        while self.step() {}
    }

    pub fn trace(&self) -> Vec<String> {
        self.trace.lock().expect("trace lock").clone()
    }

    pub fn tick(&self) -> u64 {
        self.tick
    }
}

/// Runs a scenario across many seeded interleavings and records each trace.
pub struct InterleavingExplorer {
    pub seeds: std::ops::Range<u64>,
}

pub struct InterleavingReport {
    pub traces: Vec<(u64, Vec<String>)>,
}

impl InterleavingExplorer {
    pub fn new(seeds: std::ops::Range<u64>) -> Self {
        Self { seeds }
    }

    /// `scenario` receives a fresh simulation and must schedule its work.
    pub fn explore<F>(&self, mut scenario: F) -> InterleavingReport
    where
        F: FnMut(&mut Simulation),
    {
        let mut traces = Vec::new();
        for seed in self.seeds.clone() {
            let clock = FakeClock::at(0);
            let mut sim = Simulation::new(seed, clock);
            scenario(&mut sim);
            sim.run_all();
            traces.push((seed, sim.trace()));
        }
        InterleavingReport { traces }
    }
}

impl InterleavingReport {
    /// True when no trace contains every forbidden pair, i.e. the invariant held
    /// in every explored interleaving.
    pub fn holds(&self, invariant: impl Fn(&[String]) -> bool) -> bool {
        self.traces.iter().all(|(_, trace)| invariant(trace))
    }

    pub fn distinct_traces(&self) -> usize {
        let mut set = std::collections::BTreeSet::new();
        for (_, trace) in &self.traces {
            set.insert(trace.join("|"));
        }
        set.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_lock_trace_reproduces_exactly() {
        // Two actors race for one lock. The trace must be identical per seed.
        let build = |seed: u64| {
            let clock = FakeClock::at(0);
            let mut sim = Simulation::new(seed, clock);
            let held = Arc::new(Mutex::new(None::<u64>));
            for actor in 0..2u64 {
                let held = Arc::clone(&held);
                sim.schedule(format!("acquire-{actor}"), move |trace, tick| {
                    let mut guard = held.lock().unwrap();
                    if guard.is_none() {
                        *guard = Some(actor);
                        trace.push(format!("{tick}:acquire:{actor}"));
                    } else {
                        trace.push(format!("{tick}:deny:{actor}"));
                    }
                });
            }
            sim.run_all();
            sim.trace()
        };
        for seed in 0..50 {
            assert_eq!(build(seed), build(seed), "seed {seed} must be deterministic");
        }
        // At least one seed must exercise the deny branch; otherwise the harness
        // is not exploring interleavings.
        assert!((0..50).any(|seed| build(seed).iter().any(|l| l.contains("deny"))));
    }

    #[test]
    fn explorer_reports_the_invariant_across_many_interleavings() {
        let explorer = InterleavingExplorer::new(0..200);
        let report = explorer.explore(|sim| {
            let held = Arc::new(Mutex::new(false));
            for actor in 0..3u64 {
                let held = Arc::clone(&held);
                sim.schedule(format!("a{actor}"), move |trace, tick| {
                    let mut guard = held.lock().unwrap();
                    if !*guard {
                        *guard = true;
                        trace.push(format!("{tick}:held"));
                    } else {
                        trace.push(format!("{tick}:wait"));
                    }
                });
            }
        });
        // Exactly one holder per run.
        assert!(report.holds(|trace| trace.iter().filter(|l| l.ends_with(":held")).count() == 1));
        assert!(report.distinct_traces() > 1, "explorer must vary the order");
    }
}


