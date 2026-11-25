//! Todo store and keyboard-first capture (TODO-01..TODO-11).
//!
//! Todos are separate from executable tasks. Completing or dropping a
//! user-created item requires the user (or an explicit auto rule); links are
//! explicit and never complete the other side.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use zero_store::jsonl::{scan_raw, JsonlWriter};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TodoState {
    Open,
    Doing,
    Blocked,
    Done,
    Dropped,
}

impl TodoState {
    pub fn as_str(self) -> &'static str {
        match self {
            TodoState::Open => "open",
            TodoState::Doing => "doing",
            TodoState::Blocked => "blocked",
            TodoState::Done => "done",
            TodoState::Dropped => "dropped",
        }
    }

    fn rank(self) -> u8 {
        match self {
            TodoState::Doing => 0,
            TodoState::Open => 1,
            TodoState::Blocked => 2,
            TodoState::Done => 3,
            TodoState::Dropped => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "scope", content = "id", rename_all = "snake_case")]
pub enum Scope {
    Project(String),
    Session(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Creator {
    User,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Todo {
    pub id: String,
    pub title: String,
    pub notes: String,
    pub state: TodoState,
    pub priority: i32,
    pub due_ms: Option<i64>,
    pub tags: Vec<String>,
    pub links: Vec<String>,
    pub evidence: Option<String>,
    pub scope: Scope,
    pub created_by: Creator,
    pub version: u64,
    pub created_ms: i64,
    pub updated_ms: i64,
}

#[derive(Debug, Clone, Default)]
pub struct TodoPatch {
    pub title: Option<String>,
    pub notes: Option<String>,
    pub priority: Option<i32>,
    pub due_ms: Option<Option<i64>>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TodoEvent {
    pub ts: i64,
    #[serde(flatten)]
    pub kind: TodoEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TodoEventKind {
    Saved { todo: Todo },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewReport {
    pub open: usize,
    pub doing: usize,
    pub blocked: usize,
    pub stale: Vec<String>,
    pub due_soon: Vec<String>,
}

pub struct TodoStore {
    path: PathBuf,
    writer: JsonlWriter,
    todos: BTreeMap<String, Todo>,
    next_id: u64,
}

impl TodoStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (events, _) = scan_raw::<TodoEvent>(&path)?;
        let mut todos = BTreeMap::new();
        let mut next_id = 1u64;
        for event in events {
            let TodoEventKind::Saved { todo } = event.kind;
            if let Some(n) = todo.id.strip_prefix("todo-").and_then(|n| n.parse::<u64>().ok()) {
                next_id = next_id.max(n + 1);
            }
            todos.insert(todo.id.clone(), todo);
        }
        let writer = JsonlWriter::open(&path)?;
        Ok(Self { path, writer, todos, next_id })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn save(&mut self, todo: Todo, ts: i64) -> Result<Todo> {
        self.writer.append(&TodoEvent { ts, kind: TodoEventKind::Saved { todo: todo.clone() } })?;
        self.todos.insert(todo.id.clone(), todo.clone());
        Ok(todo)
    }

    pub fn add(&mut self, scope: Scope, title: impl Into<String>, creator: Creator, now_ms: i64) -> Result<Todo> {
        let title = title.into();
        if title.trim().is_empty() {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "a todo needs a title"));
        }
        let todo = Todo {
            id: format!("todo-{}", self.next_id),
            title,
            notes: String::new(),
            state: TodoState::Open,
            priority: 0,
            due_ms: None,
            tags: Vec::new(),
            links: Vec::new(),
            evidence: None,
            scope,
            created_by: creator,
            version: 1,
            created_ms: now_ms,
            updated_ms: now_ms,
        };
        self.next_id += 1;
        self.save(todo, now_ms)
    }

    pub fn get(&self, id: &str) -> Option<&Todo> {
        self.todos.get(id)
    }

    pub fn len(&self) -> usize {
        self.todos.len()
    }

    pub fn is_empty(&self) -> bool {
        self.todos.is_empty()
    }

    pub fn update(&mut self, id: &str, expected_version: u64, patch: TodoPatch, now_ms: i64) -> Result<Todo> {
        let mut todo = self
            .todos
            .get(id)
            .cloned()
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("todo `{id}`")))?;
        if todo.version != expected_version {
            return Err(ZeroError::new(
                ErrorCode::Conflict,
                format!("todo `{id}` is version {}, expected {expected_version}", todo.version),
            ));
        }
        if let Some(title) = patch.title {
            if title.trim().is_empty() {
                return Err(ZeroError::new(ErrorCode::InvalidInput, "a todo needs a title"));
            }
            todo.title = title;
        }
        if let Some(notes) = patch.notes {
            todo.notes = notes;
        }
        if let Some(priority) = patch.priority {
            todo.priority = priority;
        }
        if let Some(due) = patch.due_ms {
            todo.due_ms = due;
        }
        if let Some(tags) = patch.tags {
            todo.tags = tags;
        }
        todo.version += 1;
        todo.updated_ms = now_ms;
        self.save(todo, now_ms)
    }

    /// Set a state with the ownership rule. An agent may not complete or drop a
    /// user-created item without an explicit auto rule.
    // State, actor, evidence, ownership rule, and clock are all explicit.
    #[allow(clippy::too_many_arguments)]
    pub fn set_state(
        &mut self,
        id: &str,
        expected_version: u64,
        actor: Creator,
        state: TodoState,
        evidence: Option<String>,
        auto_rule: bool,
        now_ms: i64,
    ) -> Result<Todo> {
        let mut todo = self
            .todos
            .get(id)
            .cloned()
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("todo `{id}`")))?;
        if todo.version != expected_version {
            return Err(ZeroError::new(ErrorCode::Conflict, format!("todo `{id}` version mismatch")));
        }
        if matches!(state, TodoState::Done | TodoState::Dropped)
            && todo.created_by == Creator::User
            && actor == Creator::Agent
            && !auto_rule
        {
            return Err(ZeroError::new(
                ErrorCode::TodoConfirmation,
                format!("`{id}` was created by the user; ask before marking it {}", state.as_str()),
            ));
        }
        if todo.state == state {
            return Ok(todo);
        }
        todo.state = state;
        if let Some(evidence) = evidence {
            todo.evidence = Some(evidence);
        }
        todo.version += 1;
        todo.updated_ms = now_ms;
        self.save(todo, now_ms)
    }

    pub fn complete(&mut self, id: &str, expected_version: u64, actor: Creator, auto_rule: bool, now_ms: i64) -> Result<Todo> {
        self.set_state(id, expected_version, actor, TodoState::Done, None, auto_rule, now_ms)
    }

    pub fn block(&mut self, id: &str, expected_version: u64, actor: Creator, now_ms: i64) -> Result<Todo> {
        self.set_state(id, expected_version, actor, TodoState::Blocked, None, false, now_ms)
    }

    pub fn drop(&mut self, id: &str, expected_version: u64, actor: Creator, auto_rule: bool, now_ms: i64) -> Result<Todo> {
        self.set_state(id, expected_version, actor, TodoState::Dropped, None, auto_rule, now_ms)
    }

    /// Explicit link only. Never completes the task or the todo.
    pub fn link_task(&mut self, id: &str, expected_version: u64, task_id: &str, now_ms: i64) -> Result<Todo> {
        let mut todo = self
            .todos
            .get(id)
            .cloned()
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("todo `{id}`")))?;
        if todo.version != expected_version {
            return Err(ZeroError::new(ErrorCode::Conflict, "todo version mismatch"));
        }
        if !todo.links.iter().any(|l| l == task_id) {
            todo.links.push(task_id.to_string());
        }
        todo.version += 1;
        todo.updated_ms = now_ms;
        self.save(todo, now_ms)
    }

    pub fn unlink_task(&mut self, id: &str, expected_version: u64, task_id: &str, now_ms: i64) -> Result<Todo> {
        let mut todo = self
            .todos
            .get(id)
            .cloned()
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("todo `{id}`")))?;
        if todo.version != expected_version {
            return Err(ZeroError::new(ErrorCode::Conflict, "todo version mismatch"));
        }
        todo.links.retain(|l| l != task_id);
        todo.version += 1;
        todo.updated_ms = now_ms;
        self.save(todo, now_ms)
    }

    pub fn list_scope(&self, scope: &Scope) -> Vec<Todo> {
        let mut out: Vec<Todo> = self.todos.values().filter(|t| &t.scope == scope).cloned().collect();
        out.sort_by(|a, b| a.state.rank().cmp(&b.state.rank()).then(b.priority.cmp(&a.priority)).then(a.title.cmp(&b.title)));
        out
    }

    /// Project and session scopes merged without duplicates.
    pub fn list_merged(&self, project: &str, session: &str) -> Vec<Todo> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for scope in [Scope::Project(project.to_string()), Scope::Session(session.to_string())] {
            for todo in self.list_scope(&scope) {
                if seen.insert(todo.id.clone()) {
                    out.push(todo);
                }
            }
        }
        out.sort_by(|a, b| a.state.rank().cmp(&b.state.rank()).then(b.priority.cmp(&a.priority)).then(a.title.cmp(&b.title)));
        out
    }

    pub fn stale(&self, now_ms: i64) -> Vec<Todo> {
        self.todos
            .values()
            .filter(|t| {
                t.due_ms.map(|due| due < now_ms).unwrap_or(false)
                    && !matches!(t.state, TodoState::Done | TodoState::Dropped)
            })
            .cloned()
            .collect()
    }

    pub fn review(&self, now_ms: i64) -> ReviewReport {
        let mut report = ReviewReport::default();
        for todo in self.todos.values() {
            match todo.state {
                TodoState::Open => report.open += 1,
                TodoState::Doing => report.doing += 1,
                TodoState::Blocked => report.blocked += 1,
                _ => continue,
            }
            if let Some(due) = todo.due_ms {
                if due < now_ms {
                    report.stale.push(todo.id.clone());
                } else if due - now_ms <= 24 * 60 * 60 * 1000 {
                    report.due_soon.push(todo.id.clone());
                }
            }
        }
        report
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TodoFilter {
    All,
    Open,
    Done,
    Stale,
}

impl TodoFilter {
    fn next(self) -> Self {
        match self {
            TodoFilter::All => TodoFilter::Open,
            TodoFilter::Open => TodoFilter::Done,
            TodoFilter::Done => TodoFilter::Stale,
            TodoFilter::Stale => TodoFilter::All,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TodoFilter::All => "all",
            TodoFilter::Open => "open",
            TodoFilter::Done => "done",
            TodoFilter::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureKey {
    Char(char),
    Backspace,
    Enter,
    Tab,
    Up,
    Down,
    Toggle,
    SelectAll,
    SearchMode,
    Escape,
    Review,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureEffect {
    Created(String),
    FilterChanged(String),
    Review(ReviewReport),
    Completed(usize),
    Cleared,
}

/// Keyboard-first capture state. There is no mouse path by construction.
pub struct TodoCapture {
    pub input: String,
    pub search: String,
    pub filter: TodoFilter,
    pub searching: bool,
    pub selected: BTreeSet<String>,
    pub cursor: usize,
}

impl Default for TodoCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl TodoCapture {
    pub fn new() -> Self {
        Self { input: String::new(), search: String::new(), filter: TodoFilter::All, searching: false, selected: BTreeSet::new(), cursor: 0 }
    }

    pub fn visible(&self, store: &TodoStore, scope: &Scope, now_ms: i64) -> Vec<Todo> {
        let stale: BTreeSet<String> = store.stale(now_ms).into_iter().map(|t| t.id).collect();
        store
            .list_scope(scope)
            .into_iter()
            .filter(|t| match self.filter {
                TodoFilter::All => true,
                TodoFilter::Open => matches!(t.state, TodoState::Open | TodoState::Doing | TodoState::Blocked),
                TodoFilter::Done => t.state == TodoState::Done,
                TodoFilter::Stale => stale.contains(&t.id),
            })
            .filter(|t| {
                let query = if self.searching { &self.search } else { "" };
                query.is_empty()
                    || t.title.to_lowercase().contains(&query.to_lowercase())
                    || t.tags.iter().any(|tag| tag.to_lowercase().contains(&query.to_lowercase()))
            })
            .collect()
    }

    pub fn handle(
        &mut self,
        key: CaptureKey,
        store: &mut TodoStore,
        scope: &Scope,
        now_ms: i64,
    ) -> Result<Vec<CaptureEffect>> {
        let visible = self.visible(store, scope, now_ms);
        self.cursor = self.cursor.min(visible.len().saturating_sub(1));
        let mut effects = Vec::new();
        match key {
            CaptureKey::Char(c) => {
                if self.searching {
                    self.search.push(c);
                } else {
                    self.input.push(c);
                }
            }
            CaptureKey::Backspace => {
                if self.searching {
                    self.search.pop();
                } else {
                    self.input.pop();
                }
            }
            CaptureKey::Enter => {
                if !self.input.trim().is_empty() {
                    let todo = store.add(scope.clone(), self.input.trim(), Creator::User, now_ms)?;
                    self.input.clear();
                    effects.push(CaptureEffect::Created(todo.id));
                }
            }
            CaptureKey::Tab => {
                self.filter = self.filter.next();
                effects.push(CaptureEffect::FilterChanged(self.filter.as_str().into()));
            }
            CaptureKey::Down => self.cursor = (self.cursor + 1).min(visible.len().saturating_sub(1)),
            CaptureKey::Up => self.cursor = self.cursor.saturating_sub(1),
            CaptureKey::Toggle => {
                if let Some(todo) = visible.get(self.cursor) {
                    if !self.selected.insert(todo.id.clone()) {
                        self.selected.remove(&todo.id);
                    }
                }
            }
            CaptureKey::SelectAll => {
                for todo in &visible {
                    self.selected.insert(todo.id.clone());
                }
            }
            CaptureKey::SearchMode => self.searching = !self.searching,
            CaptureKey::Escape => {
                self.input.clear();
                self.search.clear();
                self.selected.clear();
                self.searching = false;
                effects.push(CaptureEffect::Cleared);
            }
            CaptureKey::Review => effects.push(CaptureEffect::Review(store.review(now_ms))),
        }
        Ok(effects)
    }

    /// Bulk complete selected items as the user.
    pub fn bulk_complete(&mut self, store: &mut TodoStore, now_ms: i64) -> Result<usize> {
        let mut completed = 0;
        for id in self.selected.clone() {
            if let Some(todo) = store.get(&id).cloned() {
                if matches!(todo.state, TodoState::Done | TodoState::Dropped) {
                    continue;
                }
                store.complete(&id, todo.version, Creator::User, true, now_ms)?;
                completed += 1;
            }
        }
        self.selected.clear();
        Ok(completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path) -> TodoStore {
        TodoStore::open(dir.join("todos.jsonl")).unwrap()
    }

    #[test]
    fn merged_project_and_session_views_are_ordered_and_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        let project = Scope::Project("p".into());
        let session = Scope::Session("s".into());
        let low = store.add(project.clone(), "low", Creator::User, 0).unwrap();
        store.update(&low.id, low.version, TodoPatch { priority: Some(1), ..Default::default() }, 1).unwrap();
        store.add(session.clone(), "session task", Creator::User, 2).unwrap();
        let merged = store.list_merged("p", "s");
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].title, "low", "higher priority first");
        assert!(merged.iter().any(|t| t.scope == session));
        // A different project sees only its own project scope plus the session.
        assert_eq!(store.list_merged("other", "s").len(), 1);
    }

    #[test]
    fn the_agent_needs_confirmation_to_complete_or_drop_a_user_item() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        let scope = Scope::Session("s".into());
        let todo = store.add(scope, "user item", Creator::User, 0).unwrap();
        let err = store.complete(&todo.id, todo.version, Creator::Agent, false, 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::TodoConfirmation);
        assert_eq!(store.get(&todo.id).unwrap().state, TodoState::Open);

        // With an explicit auto rule, or as the user, it completes.
        store.complete(&todo.id, todo.version, Creator::Agent, true, 2).unwrap();
        let agent_item = store.add(Scope::Session("s".into()), "agent item", Creator::Agent, 3).unwrap();
        store.drop(&agent_item.id, agent_item.version, Creator::Agent, false, 4).unwrap();
    }

    #[test]
    fn versioned_changes_are_journaled_and_replay() {
        let dir = tempfile::tempdir().unwrap();
        let id;
        {
            let mut store = store(dir.path());
            let todo = store.add(Scope::Project("p".into()), "write docs", Creator::User, 0).unwrap();
            id = todo.id.clone();
            store
                .update(&todo.id, todo.version, TodoPatch { tags: Some(vec!["docs".into()]), ..Default::default() }, 1)
                .unwrap();
            let stale = store.update(&todo.id, todo.version, TodoPatch::default(), 2).unwrap_err();
            assert_eq!(stale.code(), ErrorCode::Conflict);
        }
        let store = TodoStore::open(dir.path().join("todos.jsonl")).unwrap();
        let todo = store.get(&id).unwrap();
        assert_eq!(todo.tags, vec!["docs"]);
        assert_eq!(todo.version, 2);
    }

    #[test]
    fn linking_is_explicit_and_never_completes_the_task() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        let todo = store.add(Scope::Session("s".into()), "needs code", Creator::User, 0).unwrap();
        let linked = store.link_task(&todo.id, todo.version, "task-7", 1).unwrap();
        assert_eq!(linked.links, vec!["task-7"]);
        assert_eq!(linked.state, TodoState::Open);
        let done = store.complete(&todo.id, linked.version, Creator::User, false, 2).unwrap();
        assert_eq!(done.links, vec!["task-7"], "completing the todo leaves the link intact");
        assert_eq!(done.state, TodoState::Done);
    }

    #[test]
    fn a_full_keyboard_capture_flow_needs_no_mouse() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        let scope = Scope::Session("s".into());
        let mut capture = TodoCapture::new();
        for c in "buy milk".chars() {
            capture.handle(CaptureKey::Char(c), &mut store, &scope, 0).unwrap();
        }
        let effects = capture.handle(CaptureKey::Enter, &mut store, &scope, 1).unwrap();
        assert!(matches!(effects.as_slice(), [CaptureEffect::Created(_)]));
        assert_eq!(store.len(), 1);

        // Add a stale item directly and filter to it.
        let stale = store.add(scope.clone(), "overdue report", Creator::User, 2).unwrap();
        let stale = store
            .update(&stale.id, stale.version, TodoPatch { due_ms: Some(Some(0)), ..Default::default() }, 3)
            .unwrap();
        capture.handle(CaptureKey::Tab, &mut store, &scope, 4).unwrap(); // open
        capture.handle(CaptureKey::Tab, &mut store, &scope, 5).unwrap(); // done
        let effects = capture.handle(CaptureKey::Tab, &mut store, &scope, 6).unwrap(); // stale
        assert!(matches!(effects.as_slice(), [CaptureEffect::FilterChanged(f)] if f == "stale"));
        let visible = capture.visible(&store, &scope, 7);
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, stale.id);

        // Search mode narrows a list, select-all and bulk complete.
        capture.filter = TodoFilter::All;
        capture.handle(CaptureKey::SearchMode, &mut store, &scope, 8).unwrap();
        for c in "milk".chars() {
            capture.handle(CaptureKey::Char(c), &mut store, &scope, 9).unwrap();
        }
        assert_eq!(capture.visible(&store, &scope, 10).len(), 1);
        capture.handle(CaptureKey::SelectAll, &mut store, &scope, 11).unwrap();
        assert_eq!(capture.bulk_complete(&mut store, 12).unwrap(), 1);
        assert_eq!(store.list_scope(&scope).iter().filter(|t| t.state == TodoState::Open).count(), 1, "the overdue item stays open");
    }

    #[test]
    fn review_reports_stale_and_due_soon_items() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        let scope = Scope::Project("p".into());
        let stale = store.add(scope.clone(), "stale", Creator::User, 0).unwrap();
        store.update(&stale.id, stale.version, TodoPatch { due_ms: Some(Some(100)), ..Default::default() }, 1).unwrap();
        let soon = store.add(scope.clone(), "soon", Creator::User, 2).unwrap();
        store
            .update(&soon.id, soon.version, TodoPatch { due_ms: Some(Some(1000 + 60_000)), ..Default::default() }, 3)
            .unwrap();
        let report = store.review(2000);
        assert_eq!(report.open, 2);
        assert_eq!(report.stale, vec![stale.id]);
        assert_eq!(report.due_soon, vec![soon.id]);
    }

    #[test]
    fn the_agent_tool_is_versioned_and_respects_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        let tool = TodoTool;
        let created = tool
            .call(
                &mut store,
                &serde_json::json!({
                    "op": "add",
                    "scope": {"scope": "session", "id": "s"},
                    "title": "agent found a follow-up"
                }),
                0,
            )
            .unwrap();
        let id = created["id"].as_str().unwrap().to_string();
        let _version = created["version"].as_u64().unwrap();
        let listed = tool
            .call(&mut store, &serde_json::json!({"op": "list", "scope": {"scope": "session", "id": "s"}}), 1)
            .unwrap();
        assert_eq!(listed["todos"].as_array().unwrap().len(), 1);

        // The tool is an agent actor: a completed agent-created item is fine,
        // but create a user item and require confirmation.
        let user = store.add(Scope::Session("s".into()), "user item", Creator::User, 2).unwrap();
        let err = tool
            .call(&mut store, &serde_json::json!({"op": "complete", "id": user.id, "version": user.version}), 3)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::TodoConfirmation);
        let done = tool
            .call(
                &mut store,
                &serde_json::json!({"op": "complete", "id": user.id, "version": user.version, "auto_rule": true}),
                4,
            )
            .unwrap();
        assert_eq!(done["state"], "done");

        let conflict = tool
            .call(&mut store, &serde_json::json!({"op": "update", "id": id, "version": 0, "title": "x"}), 5)
            .unwrap_err();
        assert_eq!(conflict.code(), ErrorCode::Conflict);
    }
}

/// The agent-facing todo tool (TODO-05). Versioned and journaled like the store,
/// and it goes through the same ownership rule.
#[allow(clippy::items_after_test_module)]
pub struct TodoTool;

impl TodoTool {
    pub fn call(&self, store: &mut TodoStore, operation: &serde_json::Value, now_ms: i64) -> Result<serde_json::Value> {
        let action = operation
            .get("op")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ZeroError::new(ErrorCode::InvalidInput, "todo tool needs an `op`"))?;
        let id = operation.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let version = operation.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        match action {
            "add" => {
                let scope: Scope = serde_json::from_value(operation.get("scope").cloned().unwrap_or(serde_json::json!({"scope":"session","id":"default"})))
                    .map_err(|e| ZeroError::new(ErrorCode::InvalidInput, format!("scope: {e}")))?;
                let title = operation.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let todo = store.add(scope, title, Creator::Agent, now_ms)?;
                Ok(serde_json::to_value(todo)?)
            }
            "list" => {
                let scope: Scope = serde_json::from_value(operation.get("scope").cloned().unwrap_or(serde_json::json!({"scope":"session","id":"default"})))
                    .map_err(|e| ZeroError::new(ErrorCode::InvalidInput, format!("scope: {e}")))?;
                Ok(serde_json::json!({ "todos": store.list_scope(&scope) }))
            }
            "update" => {
                let patch = TodoPatch {
                    title: operation.get("title").and_then(|v| v.as_str()).map(str::to_string),
                    notes: operation.get("notes").and_then(|v| v.as_str()).map(str::to_string),
                    priority: operation.get("priority").and_then(|v| v.as_i64()).map(|v| v as i32),
                    due_ms: operation.get("due_ms").map(|v| v.as_i64()),
                    tags: operation
                        .get("tags")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|t| t.as_str().map(str::to_string)).collect()),
                };
                Ok(serde_json::to_value(store.update(id, version, patch, now_ms)?)?)
            }
            "complete" | "block" | "drop" => {
                let auto_rule = operation.get("auto_rule").and_then(|v| v.as_bool()).unwrap_or(false);
                let todo = match action {
                    "complete" => store.complete(id, version, Creator::Agent, auto_rule, now_ms)?,
                    "block" => store.block(id, version, Creator::Agent, now_ms)?,
                    _ => store.drop(id, version, Creator::Agent, auto_rule, now_ms)?,
                };
                Ok(serde_json::to_value(todo)?)
            }
            other => Err(ZeroError::new(ErrorCode::InvalidInput, format!("unknown todo op `{other}`"))),
        }
    }
}