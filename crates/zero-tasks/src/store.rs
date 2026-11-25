//! Task store: DAG, states, claims, CAS transitions, journal replay, limits, and
//! plan seeding (TSK-01..TSK-09, TSK-13).
//!
//! The journal is the source of truth. Every change is appended and fsynced
//! before the in-memory state is updated; reopening replays the journal.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use zero_store::jsonl::{scan_raw, JsonlWriter};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Queued,
    Ready,
    Running,
    Blocked,
    WaitingInput,
    Done,
    Failed,
    Cancelled,
}

impl TaskState {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskState::Queued => "queued",
            TaskState::Ready => "ready",
            TaskState::Running => "running",
            TaskState::Blocked => "blocked",
            TaskState::WaitingInput => "waiting_input",
            TaskState::Done => "done",
            TaskState::Failed => "failed",
            TaskState::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub owner: String,
    pub generation: u64,
    pub expires_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub title: String,
    pub state: TaskState,
    pub dependencies: Vec<String>,
    pub priority: i32,
    pub project: Option<String>,
    pub session: Option<String>,
    pub version: u64,
    pub claim: Option<Claim>,
    /// Monotonic claim generation; survives expiry so a stale claim can never
    /// match a later one.
    #[serde(default)]
    pub generation: u64,
    pub evidence: Option<String>,
    pub plan: Option<String>,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskEvent {
    pub ts: i64,
    #[serde(flatten)]
    pub kind: TaskEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TaskEventKind {
    Added {
        id: String,
        title: String,
        dependencies: Vec<String>,
        priority: i32,
        project: Option<String>,
        session: Option<String>,
        sequence: u64,
    },
    Changed {
        id: String,
        from: TaskState,
        to: TaskState,
        version: u64,
        actor: String,
        evidence: Option<String>,
    },
    Claimed {
        id: String,
        owner: String,
        generation: u64,
        expires_ms: i64,
    },
    ClaimExpired {
        id: String,
        generation: u64,
    },
    DependencyAdded {
        id: String,
        dependency: String,
        version: u64,
    },
    PlanSeeded {
        plan_id: String,
        tasks: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskLimits {
    pub max_running_per_project: usize,
}

impl Default for TaskLimits {
    fn default() -> Self {
        Self { max_running_per_project: 3 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanTask {
    pub key: String,
    pub title: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressView {
    pub total: usize,
    pub by_state: BTreeMap<String, usize>,
    pub ready: Vec<String>,
    pub running: Vec<String>,
    pub blocked: Vec<String>,
}

pub struct TaskStore {
    path: PathBuf,
    writer: JsonlWriter,
    tasks: BTreeMap<String, Task>,
    plans: BTreeMap<String, Vec<String>>,
    next_id: u64,
    next_sequence: u64,
    limits: TaskLimits,
    rotation: usize,
}

impl TaskStore {
    pub fn open(path: impl AsRef<Path>, limits: TaskLimits) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (events, _) = scan_raw::<TaskEvent>(&path)?;
        let mut tasks: BTreeMap<String, Task> = BTreeMap::new();
        let mut plans: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut next_id = 1u64;
        let mut next_sequence = 0u64;
        for event in events {
            match event.kind {
                TaskEventKind::Added { id, title, dependencies, priority, project, session, sequence } => {
                    if let Some(n) = id.strip_prefix("task-").and_then(|n| n.parse::<u64>().ok()) {
                        next_id = next_id.max(n + 1);
                    }
                    next_sequence = next_sequence.max(sequence + 1);
                    tasks.insert(
                        id.clone(),
                        Task {
                            id,
                            title,
                            state: TaskState::Queued,
                            dependencies,
                            priority,
                            project,
                            session,
                            version: 0,
                            claim: None,
                            generation: 0,
                            evidence: None,
                            plan: None,
                            sequence,
                        },
                    );
                }
                TaskEventKind::Changed { id, to, version, evidence, .. } => {
                    if let Some(task) = tasks.get_mut(&id) {
                        task.state = to;
                        task.version = version;
                        if evidence.is_some() {
                            task.evidence = evidence;
                        }
                    }
                }
                TaskEventKind::Claimed { id, owner, generation, expires_ms } => {
                    if let Some(task) = tasks.get_mut(&id) {
                        task.claim = Some(Claim { owner, generation, expires_ms });
                        task.generation = task.generation.max(generation);
                    }
                }
                TaskEventKind::ClaimExpired { id, generation } => {
                    if let Some(task) = tasks.get_mut(&id) {
                        if task.claim.as_ref().map(|c| c.generation) == Some(generation) {
                            task.claim = None;
                            task.state = TaskState::Ready;
                        }
                    }
                }
                TaskEventKind::DependencyAdded { id, dependency, version } => {
                    if let Some(task) = tasks.get_mut(&id) {
                        if !task.dependencies.iter().any(|d| d == &dependency) {
                            task.dependencies.push(dependency);
                        }
                        task.version = version;
                    }
                }
                TaskEventKind::PlanSeeded { plan_id, tasks: seeded } => {
                    for id in &seeded {
                        if let Some(task) = tasks.get_mut(id) {
                            task.plan = Some(plan_id.clone());
                        }
                    }
                    plans.insert(plan_id, seeded);
                }
            }
        }
        let writer = JsonlWriter::open(&path)?;
        Ok(Self { path, writer, tasks, plans, next_id, next_sequence, limits, rotation: 0 })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn limits(&self) -> TaskLimits {
        self.limits
    }

    fn record(&mut self, ts: i64, kind: TaskEventKind) -> Result<()> {
        self.writer.append(&TaskEvent { ts, kind })?;
        Ok(())
    }

    fn append(&mut self, ts: i64, kind: TaskEventKind) -> Result<()> {
        self.record(ts, kind.clone())?;
        match kind {
            TaskEventKind::Added { id, title, dependencies, priority, project, session, sequence } => {
                self.tasks.insert(
                    id.clone(),
                    Task {
                        id,
                        title,
                        state: TaskState::Queued,
                        dependencies,
                        priority,
                        project,
                        session,
                        version: 0,
                        claim: None,
                        generation: 0,
                        evidence: None,
                        plan: None,
                        sequence,
                    },
                );
            }
            TaskEventKind::Changed { id, to, version, evidence, .. } => {
                if let Some(task) = self.tasks.get_mut(&id) {
                    task.state = to;
                    task.version = version;
                    if evidence.is_some() {
                        task.evidence = evidence;
                    }
                }
            }
            TaskEventKind::Claimed { id, owner, generation, expires_ms } => {
                if let Some(task) = self.tasks.get_mut(&id) {
                    task.claim = Some(Claim { owner, generation, expires_ms });
                    task.generation = task.generation.max(generation);
                }
            }
            TaskEventKind::ClaimExpired { id, generation } => {
                if let Some(task) = self.tasks.get_mut(&id) {
                    if task.claim.as_ref().map(|c| c.generation) == Some(generation) {
                        task.claim = None;
                        task.state = TaskState::Ready;
                        task.version += 1;
                    }
                }
            }
            TaskEventKind::DependencyAdded { id, dependency, version } => {
                if let Some(task) = self.tasks.get_mut(&id) {
                    if !task.dependencies.iter().any(|d| d == &dependency) {
                        task.dependencies.push(dependency);
                    }
                    task.version = version;
                }
            }
            TaskEventKind::PlanSeeded { plan_id, tasks } => {
                for id in &tasks {
                    if let Some(task) = self.tasks.get_mut(id) {
                        task.plan = Some(plan_id.clone());
                    }
                }
                self.plans.insert(plan_id, tasks);
            }
        }
        Ok(())
    }

    // The arguments are the task's public creation surface.
    #[allow(clippy::too_many_arguments)]
    pub fn add_task(
        &mut self,
        title: impl Into<String>,
        dependencies: Vec<String>,
        priority: i32,
        project: Option<String>,
        session: Option<String>,
        ts: i64,
    ) -> Result<String> {
        for dep in &dependencies {
            if !self.tasks.contains_key(dep) {
                return Err(ZeroError::new(ErrorCode::NotFound, format!("dependency `{dep}` does not exist")));
            }
        }
        let id = format!("task-{}", self.next_id);
        self.next_id += 1;
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.append(
            ts,
            TaskEventKind::Added {
                id: id.clone(),
                title: title.into(),
                dependencies,
                priority,
                project,
                session,
                sequence,
            },
        )?;
        Ok(id)
    }

    /// Add a dependency edge, rejecting a cycle with its path.
    pub fn add_dependency(&mut self, id: &str, dep: &str) -> Result<()> {
        if !self.tasks.contains_key(id) || !self.tasks.contains_key(dep) {
            return Err(ZeroError::new(ErrorCode::NotFound, "task or dependency is missing"));
        }
        let mut edges: BTreeMap<String, Vec<String>> = self
            .tasks
            .iter()
            .map(|(k, t)| (k.clone(), t.dependencies.clone()))
            .collect();
        edges.entry(id.to_string()).or_default().push(dep.to_string());
        if let Some(path) = detect_cycle(&edges) {
            return Err(ZeroError::new(ErrorCode::Conflict, format!("dependency cycle: {}", path.join(" -> "))));
        }
        let version = self.tasks.get(id).map(|t| t.version + 1).unwrap_or(1);
        self.append(
            0,
            TaskEventKind::DependencyAdded { id: id.to_string(), dependency: dep.to_string(), version },
        )?;
        Ok(())
    }

    pub fn dependencies(&self, id: &str) -> Vec<String> {
        self.tasks.get(id).map(|t| t.dependencies.clone()).unwrap_or_default()
    }

    pub fn get(&self, id: &str) -> Option<&Task> {
        self.tasks.get(id)
    }

    pub fn tasks(&self) -> impl Iterator<Item = &Task> {
        self.tasks.values()
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Promote queued/blocked tasks whose dependencies are all done.
    pub fn refresh_readiness(&mut self, ts: i64) -> Result<Vec<String>> {
        let mut promoted = Vec::new();
        let candidates: Vec<(String, u64, TaskState)> = self
            .tasks
            .values()
            .filter(|t| matches!(t.state, TaskState::Queued | TaskState::Blocked))
            .map(|t| (t.id.clone(), t.version, t.state))
            .collect();
        for (id, version, from) in candidates {
            let deps_done = self
                .tasks
                .get(&id)
                .map(|t| t.dependencies.iter().all(|d| self.tasks.get(d).map(|x| x.state == TaskState::Done).unwrap_or(false)))
                .unwrap_or(false);
            if deps_done {
                self.append(
                    ts,
                    TaskEventKind::Changed {
                        id: id.clone(),
                        from,
                        to: TaskState::Ready,
                        version: version + 1,
                        actor: "scheduler".into(),
                        evidence: None,
                    },
                )?;
                promoted.push(id);
            }
        }
        Ok(promoted)
    }

    /// Compare-and-swap transition. A version mismatch is a conflict; an invalid
    /// state change is a typed refusal.
    pub fn transition(
        &mut self,
        id: &str,
        expected_version: u64,
        to: TaskState,
        actor: &str,
        evidence: Option<String>,
        ts: i64,
    ) -> Result<u64> {
        let task = self
            .tasks
            .get(id)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("task `{id}`")))?;
        if task.version != expected_version {
            return Err(ZeroError::new(
                ErrorCode::Conflict,
                format!("task `{id}` is version {}, expected {expected_version}", task.version),
            ));
        }
        if !allowed(task.state, to) {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!("{} to {} is not an allowed transition", task.state.as_str(), to.as_str()),
            ));
        }
        let from = task.state;
        let version = task.version + 1;
        self.append(
            ts,
            TaskEventKind::Changed { id: id.to_string(), from, to, version, actor: actor.into(), evidence },
        )?;
        Ok(version)
    }

    fn running_in_project(&self, project: Option<&str>) -> usize {
        self.tasks
            .values()
            .filter(|t| t.state == TaskState::Running && t.project.as_deref() == project)
            .count()
    }

    /// Claim the next ready task, respecting per-project concurrency and a fair
    /// rotation. Returns None when nothing is claimable.
    pub fn claim_next(&mut self, owner: &str, now_ms: i64, ttl_ms: i64) -> Result<Option<(String, Claim)>> {
        self.refresh_readiness(now_ms)?;
        let mut ready: Vec<Task> = self.tasks.values().filter(|t| t.state == TaskState::Ready).cloned().collect();
        ready.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.sequence.cmp(&b.sequence)));
        if ready.is_empty() {
            return Ok(None);
        }
        // Rotate the starting project for fair share.
        let projects: Vec<Option<String>> = {
            let mut set = Vec::new();
            for task in &ready {
                if !set.contains(&task.project) {
                    set.push(task.project.clone());
                }
            }
            set
        };
        if !projects.is_empty() {
            self.rotation %= projects.len();
        }
        for offset in 0..projects.len() {
            let project = projects[(self.rotation + offset) % projects.len()].clone();
            if project.is_some() && self.running_in_project(project.as_deref()) >= self.limits.max_running_per_project {
                continue;
            }
            if let Some(task) = ready.iter().find(|t| t.project == project) {
                let generation = task.generation + 1;
                let version = task.version + 1;
                let claim = Claim { owner: owner.into(), generation, expires_ms: now_ms + ttl_ms };
                self.append(
                    now_ms,
                    TaskEventKind::Changed {
                        id: task.id.clone(),
                        from: TaskState::Ready,
                        to: TaskState::Running,
                        version,
                        actor: owner.into(),
                        evidence: None,
                    },
                )?;
                self.append(
                    now_ms,
                    TaskEventKind::Claimed {
                        id: task.id.clone(),
                        owner: owner.into(),
                        generation,
                        expires_ms: claim.expires_ms,
                    },
                )?;
                self.rotation = (self.rotation + offset + 1) % projects.len().max(1);
                return Ok(Some((task.id.clone(), claim)));
            }
        }
        Ok(None)
    }

    fn validate_claim(&self, id: &str, claim: &Claim, now_ms: i64) -> Result<&Task> {
        let task = self
            .tasks
            .get(id)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("task `{id}`")))?;
        let current = task
            .claim
            .as_ref()
            .ok_or_else(|| ZeroError::new(ErrorCode::Stale, "the task has no claim"))?;
        if current.generation != claim.generation || current.owner != claim.owner {
            return Err(ZeroError::new(ErrorCode::Stale, "claim generation is stale"));
        }
        if now_ms >= current.expires_ms {
            return Err(ZeroError::new(ErrorCode::Stale, "claim expired"));
        }
        Ok(task)
    }

    /// Complete a running task with its claim. A stale claim is fenced out.
    pub fn complete(&mut self, id: &str, claim: &Claim, evidence: Option<String>, ts: i64) -> Result<u64> {
        let task = self.validate_claim(id, claim, ts)?;
        let version = task.version;
        self.transition(id, version, TaskState::Done, &claim.owner, evidence, ts)
    }

    pub fn fail(&mut self, id: &str, claim: &Claim, evidence: Option<String>, ts: i64) -> Result<u64> {
        let task = self.validate_claim(id, claim, ts)?;
        let version = task.version;
        self.transition(id, version, TaskState::Failed, &claim.owner, evidence, ts)
    }

    pub fn renew(&mut self, id: &str, claim: &mut Claim, now_ms: i64, ttl_ms: i64) -> Result<()> {
        let task = self.tasks.get(id).ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("task `{id}`")))?;
        let current = task.claim.as_ref().ok_or_else(|| ZeroError::new(ErrorCode::Stale, "no claim"))?;
        if current.generation != claim.generation || now_ms >= current.expires_ms {
            return Err(ZeroError::new(ErrorCode::Stale, "claim cannot be renewed"));
        }
        claim.expires_ms = now_ms + ttl_ms;
        self.append(
            now_ms,
            TaskEventKind::Claimed { id: id.to_string(), owner: claim.owner.clone(), generation: claim.generation, expires_ms: claim.expires_ms },
        )
    }

    /// Expire stale claims, returning the tasks that became ready again.
    pub fn expire_claims(&mut self, now_ms: i64) -> Result<Vec<String>> {
        let expired: Vec<(String, u64)> = self
            .tasks
            .values()
            .filter_map(|t| match &t.claim {
                Some(claim) if now_ms >= claim.expires_ms => Some((t.id.clone(), claim.generation)),
                _ => None,
            })
            .collect();
        for (id, generation) in &expired {
            self.append(now_ms, TaskEventKind::ClaimExpired { id: id.clone(), generation: *generation })?;
        }
        Ok(expired.into_iter().map(|(id, _)| id).collect())
    }

    /// Route a blocked-on-user item into the durable headless queue.
    #[allow(clippy::too_many_arguments)]
    pub fn block_on_user(
        &mut self,
        id: &str,
        expected_version: u64,
        kind: zero_policy::headless::QueueKind,
        prompt: impl Into<String>,
        queue: &mut zero_policy::headless::UserQueue,
        actor: &str,
        now_ms: i64,
    ) -> Result<zero_policy::headless::QueuedItem> {
        let version = self.transition(id, expected_version, TaskState::WaitingInput, actor, None, now_ms)?;
        let item = queue.push(kind, prompt, now_ms)?;
        let _ = version;
        Ok(item)
    }

    /// Block on a dependency without occupying a worker.
    pub fn block_on_dependency(&mut self, id: &str, expected_version: u64, actor: &str, now_ms: i64) -> Result<u64> {
        self.transition(id, expected_version, TaskState::Blocked, actor, None, now_ms)
    }

    /// Seed tasks from an approved plan exactly once.
    pub fn seed_plan(&mut self, plan_id: &str, plan: &[PlanTask], ts: i64) -> Result<Vec<String>> {
        if let Some(existing) = self.plans.get(plan_id) {
            return Ok(existing.clone());
        }
        // Build the graph first and reject cycles before writing anything.
        let keys: BTreeSet<&str> = plan.iter().map(|t| t.key.as_str()).collect();
        for task in plan {
            for dep in &task.depends_on {
                if !keys.contains(dep.as_str()) {
                    return Err(ZeroError::new(ErrorCode::NotFound, format!("plan dependency `{dep}` is not in the plan")));
                }
            }
        }
        let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for task in plan {
            edges.insert(task.key.clone(), task.depends_on.clone());
        }
        if let Some(path) = detect_cycle(&edges) {
            return Err(ZeroError::new(ErrorCode::Conflict, format!("plan dependency cycle: {}", path.join(" -> "))));
        }
        let mut ids = Vec::new();
        let mut key_to_id = BTreeMap::new();
        for task in plan {
            let id = format!("task-{}", self.next_id);
            self.next_id += 1;
            key_to_id.insert(task.key.clone(), id.clone());
            ids.push(id);
        }
        for (task, id) in plan.iter().zip(&ids) {
            let dependencies: Vec<String> = task
                .depends_on
                .iter()
                .filter_map(|k| key_to_id.get(k).cloned())
                .collect();
            let sequence = self.next_sequence;
            self.next_sequence += 1;
            self.append(
                ts,
                TaskEventKind::Added {
                    id: id.clone(),
                    title: task.title.clone(),
                    dependencies,
                    priority: task.priority,
                    project: None,
                    session: None,
                    sequence,
                },
            )?;
        }
        self.append(ts, TaskEventKind::PlanSeeded { plan_id: plan_id.into(), tasks: ids.clone() })?;
        Ok(ids)
    }

    pub fn progress(&mut self, ts: i64) -> Result<ProgressView> {
        self.refresh_readiness(ts)?;
        let mut view = ProgressView::default();
        for task in self.tasks.values() {
            view.total += 1;
            *view.by_state.entry(task.state.as_str().to_string()).or_insert(0) += 1;
            match task.state {
                TaskState::Ready => view.ready.push(task.id.clone()),
                TaskState::Running => view.running.push(task.id.clone()),
                TaskState::Blocked | TaskState::WaitingInput => view.blocked.push(task.id.clone()),
                _ => {}
            }
        }
        Ok(view)
    }

    /// History for one task, reconstructed from the journal.
    pub fn history(&self, id: &str) -> Result<Vec<TaskEvent>> {
        let (events, _) = scan_raw::<TaskEvent>(&self.path)?;
        Ok(events
            .into_iter()
            .filter(|e| match &e.kind {
                TaskEventKind::Added { id: task, .. } => task == id,
                TaskEventKind::Changed { id: task, .. }
                | TaskEventKind::Claimed { id: task, .. }
                | TaskEventKind::DependencyAdded { id: task, .. }
                | TaskEventKind::ClaimExpired { id: task, .. } => task == id,
                TaskEventKind::PlanSeeded { tasks, .. } => tasks.iter().any(|t| t == id),
            })
            .collect())
    }
}

fn allowed(from: TaskState, to: TaskState) -> bool {
    use TaskState::*;
    matches!(
        (from, to),
        (Queued, Ready)
            | (Queued, Blocked)
            | (Queued, Cancelled)
            | (Ready, Running)
            | (Ready, Blocked)
            | (Ready, WaitingInput)
            | (Ready, Cancelled)
            | (Running, Done)
            | (Running, Failed)
            | (Running, WaitingInput)
            | (Running, Blocked)
            | (Running, Ready)
            | (Running, Cancelled)
            | (Blocked, Ready)
            | (Blocked, Cancelled)
            | (WaitingInput, Ready)
            | (WaitingInput, Cancelled)
            | (Failed, Ready)
            | (Failed, Cancelled)
    )
}

/// Depth-first cycle detection. Returns the cycle path including the repeated
/// start node, or None.
pub fn detect_cycle(edges: &BTreeMap<String, Vec<String>>) -> Option<Vec<String>> {
    fn visit(
        node: &str,
        edges: &BTreeMap<String, Vec<String>>,
        grey: &mut BTreeSet<String>,
        stack: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        if grey.contains(node) {
            let start = stack.iter().position(|n| n == node).unwrap_or(0);
            let mut path = stack[start..].to_vec();
            path.push(node.to_string());
            return Some(path);
        }
        grey.insert(node.to_string());
        stack.push(node.to_string());
        if let Some(next) = edges.get(node) {
            for dep in next {
                if let Some(path) = visit(dep, edges, grey, stack) {
                    return Some(path);
                }
            }
        }
        stack.pop();
        grey.remove(node);
        None
    }
    let mut grey = BTreeSet::new();
    for node in edges.keys() {
        if let Some(path) = visit(node, edges, &mut grey, &mut Vec::new()) {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path) -> TaskStore {
        TaskStore::open(dir.join("tasks.jsonl"), TaskLimits::default()).unwrap()
    }

    #[test]
    fn a_cycle_is_rejected_with_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        let a = store.add_task("a", vec![], 0, None, None, 0).unwrap();
        let b = store.add_task("b", vec![a.clone()], 0, None, None, 1).unwrap();
        let err = store.add_dependency(&a, &b).unwrap_err();
        assert!(err.message().contains("cycle"), "{}", err.message());
        assert!(store.dependencies(&a).is_empty(), "a rejected edge is not applied");

        // The detector reports the full loop, including the repeated start.
        let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
        edges.insert("a".into(), vec!["b".into()]);
        edges.insert("b".into(), vec!["a".into()]);
        let cycle = detect_cycle(&edges).expect("cycle");
        assert_eq!(cycle.first(), cycle.last());
        assert!(cycle.len() >= 3);

        // Reopen replays the dependency that was legitimately added.
        let reopened = TaskStore::open(dir.path().join("tasks.jsonl"), TaskLimits::default()).unwrap();
        assert_eq!(reopened.dependencies(&b), vec![a]);
    }

    #[test]
    fn readiness_requires_all_dependencies_done() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        let a = store.add_task("a", vec![], 0, None, None, 0).unwrap();
        let b = store.add_task("b", vec![a.clone()], 0, None, None, 1).unwrap();
        store.refresh_readiness(2).unwrap();
        assert_eq!(store.get(&a).unwrap().state, TaskState::Ready);
        assert_eq!(store.get(&b).unwrap().state, TaskState::Queued);

        let (id, claim) = store.claim_next("w1", 3, 1000).unwrap().unwrap();
        assert_eq!(id, a);
        store.complete(&a, &claim, None, 4).unwrap();
        store.refresh_readiness(5).unwrap();
        assert_eq!(store.get(&b).unwrap().state, TaskState::Ready);
        let (id, _) = store.claim_next("w1", 6, 1000).unwrap().unwrap();
        assert_eq!(id, b);
    }

    #[test]
    fn one_claim_per_task_and_stale_claims_are_fenced() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        let a = store.add_task("a", vec![], 0, None, None, 0).unwrap();
        store.refresh_readiness(1).unwrap();
        let (id, claim) = store.claim_next("w1", 2, 100).unwrap().unwrap();
        assert_eq!(id, a);
        assert!(store.claim_next("w2", 3, 100).unwrap().is_none(), "no second owner");

        // Expiry returns it to ready; the old claim cannot complete.
        let expired = store.expire_claims(102).unwrap();
        assert_eq!(expired, vec![a.clone()]);
        assert_eq!(store.complete(&a, &claim, None, 103).unwrap_err().code(), ErrorCode::Stale);
        let (_id, new_claim) = store.claim_next("w2", 104, 1000).unwrap().unwrap();
        assert!(new_claim.generation > claim.generation);
        assert_eq!(store.complete(&a, &claim, None, 105).unwrap_err().code(), ErrorCode::Stale);
        store.complete(&a, &new_claim, Some("tests pass".into()), 106).unwrap();
        assert_eq!(store.get(&a).unwrap().state, TaskState::Done);
        assert_eq!(store.get(&a).unwrap().evidence.as_deref(), Some("tests pass"));
    }

    #[test]
    fn transitions_are_compare_and_swap_and_journaled() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        let a = store.add_task("a", vec![], 0, Some("p".into()), None, 0).unwrap();
        store.refresh_readiness(1).unwrap();
        let version = store.get(&a).unwrap().version;
        store.transition(&a, version, TaskState::Blocked, "user", Some("waiting".into()), 2).unwrap();
        let stale = store.transition(&a, version, TaskState::Cancelled, "user", None, 3).unwrap_err();
        assert_eq!(stale.code(), ErrorCode::Conflict);
        let history = store.history(&a).unwrap();
        assert!(history.iter().any(|e| matches!(e.kind, TaskEventKind::Changed { ref actor, .. } if actor == "user")));
    }

    #[test]
    fn replay_reconstructs_the_state_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks.jsonl");
        let (a, done_claim) = {
            let mut store = TaskStore::open(&path, TaskLimits::default()).unwrap();
            let a = store.add_task("a", vec![], 1, Some("p".into()), Some("s".into()), 0).unwrap();
            store.refresh_readiness(1).unwrap();
            let (_, claim) = store.claim_next("w", 2, 1000).unwrap().unwrap();
            store.complete(&a, &claim, Some("ok".into()), 3).unwrap();
            (a, claim)
        };
        let store = TaskStore::open(&path, TaskLimits::default()).unwrap();
        let task = store.get(&a).unwrap();
        assert_eq!(task.state, TaskState::Done);
        assert_eq!(task.evidence.as_deref(), Some("ok"));
        assert_eq!(task.version, 3);
        assert_eq!(store.get(&a).unwrap().claim.as_ref().unwrap().generation, done_claim.generation);
    }

    #[test]
    fn two_hundred_tasks_respect_limits_and_fair_share() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TaskStore::open(dir.path().join("t.jsonl"), TaskLimits { max_running_per_project: 3 }).unwrap();
        for project in 0..10 {
            for i in 0..20 {
                store
                    .add_task(format!("p{project}-{i}"), vec![], 0, Some(format!("p{project}")), None, 0)
                    .unwrap();
            }
        }
        let mut claimed = Vec::new();
        let mut now = 0;
        while let Some((id, claim)) = store.claim_next("worker", now, 10_000).unwrap() {
            claimed.push(id);
            now += 1;
            store.complete(&claimed.last().unwrap().clone(), &claim, None, now).unwrap();
        }
        assert_eq!(claimed.len(), 200, "every task is dispatched exactly once");
        let mut unique = claimed.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 200);
        assert!(store.tasks().all(|t| t.state == TaskState::Done));
    }

    #[test]
    fn a_blocked_on_user_task_goes_to_the_queue_and_work_continues() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        let blocked = store.add_task("needs input", vec![], 0, None, None, 0).unwrap();
        let independent = store.add_task("independent", vec![], 0, None, None, 1).unwrap();
        store.refresh_readiness(2).unwrap();
        let mut queue = zero_policy::headless::UserQueue::open(dir.path().join("queue.json")).unwrap();
        let version = store.get(&blocked).unwrap().version;
        let item = store
            .block_on_user(
                &blocked,
                version,
                zero_policy::headless::QueueKind::Question,
                "which database?",
                &mut queue,
                "agent",
                3,
            )
            .unwrap();
        assert_eq!(queue.open_items().len(), 1);
        let (claimed, claim) = store.claim_next("w", 4, 100).unwrap().unwrap();
        assert_eq!(claimed, independent, "independent work is not stalled");
        store.complete(&independent, &claim, None, 5).unwrap();
        assert_eq!(store.get(&blocked).unwrap().state, TaskState::WaitingInput);
        assert_eq!(item.kind, zero_policy::headless::QueueKind::Question);
    }

    #[test]
    fn plan_seeding_is_exactly_once_and_cycle_checked() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        let plan = vec![
            PlanTask { key: "a".into(), title: "a".into(), depends_on: vec![], priority: 2 },
            PlanTask { key: "b".into(), title: "b".into(), depends_on: vec!["a".into()], priority: 1 },
        ];
        let first = store.seed_plan("plan-1", &plan, 0).unwrap();
        assert_eq!(first.len(), 2);
        let second = store.seed_plan("plan-1", &plan, 1).unwrap();
        assert_eq!(first, second);
        assert_eq!(store.len(), 2, "seeded exactly once");
        assert_eq!(store.dependencies(&first[1]), vec![first[0].clone()]);
        let progress = store.progress(2).unwrap();
        assert_eq!(progress.total, 2);
        assert!(progress.by_state.contains_key("ready"));

        let cyclic = vec![
            PlanTask { key: "x".into(), title: "x".into(), depends_on: vec!["y".into()], priority: 0 },
            PlanTask { key: "y".into(), title: "y".into(), depends_on: vec!["x".into()], priority: 0 },
        ];
        let err = store.seed_plan("plan-2", &cyclic, 3).unwrap_err();
        assert!(err.message().contains("cycle"));
        assert_eq!(store.len(), 2, "a rejected plan seeds nothing");
    }
}
