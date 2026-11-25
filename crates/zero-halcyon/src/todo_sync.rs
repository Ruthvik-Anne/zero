//! Two-way todo sync with the `tkb` task backend (HAL-07, HAL-11, TODO-09,
//! TSK-12).
//!
//! Todos are owned locally ([`HalcyonTodo`]) and mirrored to `tkb` only when
//! `halcyon.todo_sync` is effective ([`crate::flags::Flag::TodoSync`]). A sync
//! is three steps in a fixed order:
//!
//! 1. **Pull** every remote todo changed since [`SyncState::last_sync_ms`].
//! 2. **Merge** by id and version. A remote todo newer than the local copy is
//!    adopted, unless a local pending op is based on an older version and the
//!    two sides changed the title or status. That case is a [`TodoConflict`],
//!    not an overwrite, and it stays visible through [`conflict_items`].
//! 3. **Push** the pending ops in queue order. An op whose id is already in
//!    [`SyncState::applied`] is skipped, and a batch with nothing left is not
//!    sent at all, so a repeated sync after success pushes nothing. `tkb` also
//!    dedupes by `op_id`, so a retry after a partially observed success is
//!    safe.
//!
//! If `tkb` is unavailable the ops stay in [`SyncState::pending`], the report
//! is [`SyncReport::Offline`], and [`SyncState::last_sync_ms`] is **not**
//! advanced: the next sync pulls the same window again and flushes the queue in
//! order. Version checks make this safe: a backend rejects an op whose
//! `base_version` is below the remote version and returns the remote todo, and
//! that rejection becomes a conflict instead of an overwrite.
//!
//! Conflicts are resolved explicitly with [`resolve_conflict`]
//! ([`ConflictChoice::KeepLocal`], [`ConflictChoice::TakeRemote`], or
//! [`ConflictChoice::Merge`]); resolution removes the conflict, replaces the
//! local todo, and, unless the remote side won, queues a fresh op based on the
//! remote version.
//!
//! [`SyncState`] is bounded, validated, and written atomically (temporary file,
//! `sync_all`, rename). A malformed stored state is a typed
//! [`ErrorCode::Corrupt`], an unsupported schema is
//! [`ErrorCode::SchemaVersion`], and an oversized file is
//! [`ErrorCode::LimitExceeded`]. Nothing in this module starts a process; the
//! only backend surface is the [`TkbTodo`] seam.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::flags::{Flag, FlagValues};

/// Documentation anchor referenced by conflict items and errors.
pub const TODO_SYNC_DOCS_ANCHOR: &str = "docs/halcyon.md#todo-sync-t-hal-07";

/// Schema version of the [`SyncState`] document.
pub const SYNC_STATE_SCHEMA: u16 = 1;

/// Upper bound on a serialised sync-state file.
pub const MAX_STATE_BYTES: usize = 256 * 1024;

/// Upper bound on queued ops. A queue at the cap refuses a new op with
/// [`ErrorCode::LimitExceeded`] rather than dropping the oldest queued change.
pub const MAX_PENDING_OPS: usize = 256;

/// Upper bound on visible conflicts. At the cap, the oldest conflict is
/// replaced by a new one.
pub const MAX_CONFLICTS: usize = 64;

/// Upper bound on remembered applied op ids.
///
/// `tkb` dedupes by `op_id`, so trimming this memory cannot double-apply an op;
/// it only makes this side re-send a very old id it has already forgotten.
pub const MAX_APPLIED_OPS: usize = 1024;

/// Upper bound on locally known todos.
pub const MAX_TODOS: usize = 4096;

/// Upper bound on a todo id or op id.
pub const MAX_TODO_ID_BYTES: usize = 128;

/// Upper bound on a todo title.
pub const MAX_TODO_TITLE_BYTES: usize = 1024;

/// The state a todo can be in. Deliberately smaller than TODO-02: sync carries
/// only what `tkb` mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TodoStatus {
    /// Not finished.
    Open,
    /// Finished.
    Done,
    /// Waiting on something.
    Blocked,
}

impl TodoStatus {
    /// Stable lower-case name used in docs, reports, and serialised state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Done => "done",
            Self::Blocked => "blocked",
        }
    }
}

impl fmt::Display for TodoStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A todo as both sides store it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HalcyonTodo {
    /// Stable todo id, shared with `tkb`.
    pub id: String,
    /// One-line title.
    pub title: String,
    /// Current status.
    pub status: TodoStatus,
    /// Last change time, in milliseconds since the Unix epoch.
    pub updated_ms: i64,
    /// Change counter. A local create starts at 1 and every accepted op makes
    /// the next version `base_version + 1`.
    pub version: u64,
}

impl HalcyonTodo {
    /// A local todo at version 1, open.
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        now_ms: i64,
    ) -> Result<Self, ZeroError> {
        let todo = Self {
            id: id.into(),
            title: title.into(),
            status: TodoStatus::Open,
            updated_ms: now_ms,
            version: 1,
        };
        todo.validate()?;
        Ok(todo)
    }

    /// Check the id and title bounds and character rules.
    pub fn validate(&self) -> Result<(), ZeroError> {
        validate_identifier("todo id", &self.id)?;
        validate_title(&self.title)?;
        Ok(())
    }
}

/// What a [`TodoOp`] asks the backend to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TodoOpKind {
    /// Create a todo that does not exist yet. `base_version` is 0.
    Create,
    /// Change a title and/or status.
    Update,
    /// Set the status to [`TodoStatus::Done`].
    Complete,
    /// Set the status to [`TodoStatus::Blocked`].
    Block,
}

impl TodoOpKind {
    /// Stable lower-case name used in reports and serialised state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Complete => "complete",
            Self::Block => "block",
        }
    }
}

impl fmt::Display for TodoOpKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The fields an op carries. `kind` decides how they are applied.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TodoPayload {
    /// New title. Required for create and update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// New status. Optional; complete and block set it from `kind`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TodoStatus>,
}

impl TodoPayload {
    /// A title-only payload.
    pub fn title(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            status: None,
        }
    }

    /// A status-only payload.
    pub fn status(status: TodoStatus) -> Self {
        Self {
            title: None,
            status: Some(status),
        }
    }
}

/// One idempotent, version-checked change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TodoOp {
    /// Backend idempotency key. Repeating an op id is a no-op on both sides.
    pub op_id: String,
    /// The todo this op changes.
    pub todo_id: String,
    /// The change to make.
    pub kind: TodoOpKind,
    /// The values the change carries.
    pub payload: TodoPayload,
    /// The version the change was made against. The backend rejects the op when
    /// this is below the remote version.
    pub base_version: u64,
    /// When the change was made, in milliseconds since the Unix epoch.
    pub at_ms: i64,
}

impl TodoOp {
    /// Check the ids and payload bounds.
    pub fn validate(&self) -> Result<(), ZeroError> {
        validate_identifier("todo op id", &self.op_id)?;
        validate_identifier("todo id", &self.todo_id)?;
        match self.kind {
            TodoOpKind::Create | TodoOpKind::Update => {
                let title = self.payload.title.as_deref().ok_or_else(|| {
                    invalid(format!(
                        "a {} op requires a payload title (see {TODO_SYNC_DOCS_ANCHOR})",
                        self.kind
                    ))
                })?;
                validate_title(title)?;
            }
            TodoOpKind::Complete | TodoOpKind::Block => {
                if let Some(title) = self.payload.title.as_deref() {
                    validate_title(title)?;
                }
            }
        }
        if self.kind == TodoOpKind::Create && self.base_version != 0 {
            return Err(invalid(format!(
                "a create op must have base_version 0, found {} (see {TODO_SYNC_DOCS_ANCHOR})",
                self.base_version
            )));
        }
        Ok(())
    }

    /// Apply this op's content to `todo`.
    ///
    /// A [`TkbTodo`] implementation can use this to update its own records.
    /// Version bookkeeping stays with the caller: an accepted op sets the next
    /// version to `base_version + 1`.
    pub fn apply(&self, todo: &mut HalcyonTodo) -> Result<(), ZeroError> {
        match self.kind {
            TodoOpKind::Create => {
                todo.title = self
                    .payload
                    .title
                    .clone()
                    .ok_or_else(|| invalid("a create op requires a title"))?;
                todo.status = self.payload.status.unwrap_or(TodoStatus::Open);
            }
            TodoOpKind::Update => {
                todo.title = self
                    .payload
                    .title
                    .clone()
                    .ok_or_else(|| invalid("an update op requires a title"))?;
                if let Some(status) = self.payload.status {
                    todo.status = status;
                }
            }
            TodoOpKind::Complete => todo.status = TodoStatus::Done,
            TodoOpKind::Block => todo.status = TodoStatus::Blocked,
        }
        todo.updated_ms = self.at_ms;
        Ok(())
    }
}

/// A visible conflict: the local edit and the newer remote edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TodoConflict {
    /// The todo both sides changed.
    pub todo_id: String,
    /// The local side at detection time.
    pub local: HalcyonTodo,
    /// The remote side at detection time.
    pub remote: HalcyonTodo,
    /// When the conflict was detected, in milliseconds since the Unix epoch.
    pub detected_ms: i64,
}

/// How [`resolve_conflict`] settles a conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictChoice {
    /// Keep the local title and status, and queue an op based on the remote
    /// version so the backend accepts it.
    KeepLocal,
    /// Adopt the remote todo verbatim and drop the local queued change.
    TakeRemote,
    /// Keep the local title, take the furthest status (`done` > `blocked` >
    /// `open`), and queue the result as a new version.
    Merge,
}

/// One panel item a UI can render for a conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictItem {
    /// The conflicting todo.
    pub todo_id: String,
    /// The local title, which is what the user's panel showed before the
    /// conflict.
    pub title: String,
    /// The local status.
    pub status: TodoStatus,
    /// Stable reference a panel can open: the docs anchor plus the todo id.
    pub reference: String,
}

/// The result of one [`sync`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncReport {
    /// `halcyon.todo_sync` is off; the backend was not called.
    Disabled,
    /// `tkb` is unavailable. The ops stay queued; nothing is lost.
    Offline {
        /// Ops waiting in the queue after the failed attempt.
        queued: usize,
    },
    /// Pull, merge, and push all completed.
    Synced {
        /// Remote todos inserted or adopted into local state.
        pulled: usize,
        /// Ops the backend accepted.
        pushed: usize,
        /// Ops skipped because their `op_id` was already applied.
        skipped: usize,
        /// Conflicts visible after the sync.
        conflicts: usize,
        /// The window cursor recorded for the next pull.
        last_sync_ms: i64,
    },
    /// A backend or state error that is not "offline".
    Failed(ZeroError),
}

impl SyncReport {
    /// True for [`SyncReport::Disabled`].
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// True for [`SyncReport::Offline`].
    pub fn is_offline(&self) -> bool {
        matches!(self, Self::Offline { .. })
    }

    /// True for [`SyncReport::Synced`].
    pub fn is_synced(&self) -> bool {
        matches!(self, Self::Synced { .. })
    }
}

/// Durable sync state. Serialised atomically; validated on load and save.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    /// Schema version; see [`SYNC_STATE_SCHEMA`].
    pub schema_version: u16,
    /// Pull cursor. Advanced only after a fully successful sync, so an offline
    /// attempt re-reads the same window.
    #[serde(default)]
    pub last_sync_ms: i64,
    /// Ops not yet accepted by the backend, in send order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<TodoOp>,
    /// Op ids that have been accepted. A repeated sync skips them.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub applied: BTreeSet<String>,
    /// Visible conflicts, newest last.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<TodoConflict>,
    /// Locally known todos, keyed by id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub todos: BTreeMap<String, HalcyonTodo>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncState {
    /// Empty state at the current schema.
    pub fn new() -> Self {
        Self {
            schema_version: SYNC_STATE_SCHEMA,
            last_sync_ms: 0,
            pending: Vec::new(),
            applied: BTreeSet::new(),
            conflicts: Vec::new(),
            todos: BTreeMap::new(),
        }
    }

    /// The local todo with `id`, if any.
    pub fn todo(&self, id: &str) -> Option<&HalcyonTodo> {
        self.todos.get(id)
    }

    /// Create a local todo at version 1 and queue its create op.
    pub fn create_todo(&mut self, id: &str, title: &str, now_ms: i64) -> Result<TodoOp, ZeroError> {
        validate_identifier("todo id", id)?;
        validate_title(title)?;
        if self.todos.contains_key(id) {
            return Err(ZeroError::new(
                ErrorCode::AlreadyExists,
                format!("todo `{id}` already exists"),
            ));
        }
        if self.todos.len() >= MAX_TODOS {
            return Err(limit(format!(
                "the sync state already holds {MAX_TODOS} todos, the supported maximum"
            )));
        }
        let op = TodoOp {
            op_id: self.next_op_id(id, now_ms),
            todo_id: id.to_string(),
            kind: TodoOpKind::Create,
            payload: TodoPayload::title(title),
            base_version: 0,
            at_ms: now_ms,
        };
        self.queue_op(op.clone())?;
        self.todos.insert(
            id.to_string(),
            HalcyonTodo {
                id: id.to_string(),
                title: title.to_string(),
                status: TodoStatus::Open,
                updated_ms: now_ms,
                version: 1,
            },
        );
        Ok(op)
    }

    /// Change a local todo's title and queue its update op.
    pub fn update_todo(&mut self, id: &str, title: &str, now_ms: i64) -> Result<TodoOp, ZeroError> {
        validate_title(title)?;
        let mut todo = self.require_todo(id)?.clone();
        let op = TodoOp {
            op_id: self.next_op_id(id, now_ms),
            todo_id: id.to_string(),
            kind: TodoOpKind::Update,
            payload: TodoPayload::title(title),
            base_version: todo.version,
            at_ms: now_ms,
        };
        self.queue_op(op.clone())?;
        todo.title = title.to_string();
        todo.updated_ms = now_ms;
        todo.version += 1;
        self.todos.insert(id.to_string(), todo);
        Ok(op)
    }

    /// Mark a local todo done and queue its complete op.
    pub fn complete_todo(&mut self, id: &str, now_ms: i64) -> Result<TodoOp, ZeroError> {
        self.change_status(id, TodoOpKind::Complete, TodoStatus::Done, now_ms)
    }

    /// Mark a local todo blocked and queue its block op.
    pub fn block_todo(&mut self, id: &str, now_ms: i64) -> Result<TodoOp, ZeroError> {
        self.change_status(id, TodoOpKind::Block, TodoStatus::Blocked, now_ms)
    }

    /// Append an op to the queue.
    ///
    /// Queueing an op id that is already pending or already applied is a no-op,
    /// so a caller cannot queue the same change twice. A full queue is
    /// [`ErrorCode::LimitExceeded`] rather than a silent drop.
    pub fn queue_op(&mut self, op: TodoOp) -> Result<(), ZeroError> {
        op.validate()?;
        if self.applied.contains(&op.op_id)
            || self.pending.iter().any(|queued| queued.op_id == op.op_id)
        {
            return Ok(());
        }
        if self.pending.len() >= MAX_PENDING_OPS {
            return Err(limit(format!(
                "the todo sync queue already holds {MAX_PENDING_OPS} ops; sync with tkb before queueing more (see {TODO_SYNC_DOCS_ANCHOR})"
            )));
        }
        self.pending.push(op);
        Ok(())
    }

    /// Validate the stored shape and bounds.
    pub fn validate(&self) -> Result<(), ZeroError> {
        if self.schema_version != SYNC_STATE_SCHEMA {
            return Err(ZeroError::new(
                ErrorCode::SchemaVersion,
                format!(
                    "todo sync state schema {} is unsupported; this build understands schema {SYNC_STATE_SCHEMA}",
                    self.schema_version
                ),
            ));
        }
        if self.todos.len() > MAX_TODOS {
            return Err(corrupt(format!(
                "todo sync state holds {} todos, above the {MAX_TODOS} limit",
                self.todos.len()
            )));
        }
        for (id, todo) in &self.todos {
            if todo.id != *id {
                return Err(corrupt(format!(
                    "todo `{id}` is stored under a key that does not match its id `{}`",
                    todo.id
                )));
            }
            todo.validate().map_err(stored)?;
        }
        if self.pending.len() > MAX_PENDING_OPS {
            return Err(corrupt(format!(
                "todo sync queue holds {} ops, above the {MAX_PENDING_OPS} limit",
                self.pending.len()
            )));
        }
        let mut seen = BTreeSet::new();
        for op in &self.pending {
            op.validate().map_err(stored)?;
            if !seen.insert(op.op_id.clone()) {
                return Err(corrupt(format!(
                    "todo sync queue contains op `{}` more than once",
                    op.op_id
                )));
            }
            if self.applied.contains(&op.op_id) {
                return Err(corrupt(format!(
                    "op `{}` is both queued and already applied",
                    op.op_id
                )));
            }
        }
        if self.applied.len() > MAX_APPLIED_OPS {
            return Err(corrupt(format!(
                "todo sync applied set holds {} ids, above the {MAX_APPLIED_OPS} limit",
                self.applied.len()
            )));
        }
        if self.conflicts.len() > MAX_CONFLICTS {
            return Err(corrupt(format!(
                "todo sync state holds {} conflicts, above the {MAX_CONFLICTS} limit",
                self.conflicts.len()
            )));
        }
        for conflict in &self.conflicts {
            conflict.local.validate().map_err(stored)?;
            conflict.remote.validate().map_err(stored)?;
            if conflict.local.id != conflict.todo_id
                || conflict.remote.id != conflict.todo_id
                || !self.todos.contains_key(&conflict.todo_id)
            {
                return Err(corrupt(format!(
                    "conflict for todo `{}` does not match the local and remote sides",
                    conflict.todo_id
                )));
            }
        }
        Ok(())
    }

    /// Serialise the state as pretty JSON after validating it.
    pub fn to_json(&self) -> Result<Vec<u8>, ZeroError> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(limit(format!(
                "todo sync state is {} bytes, above the {MAX_STATE_BYTES} byte limit",
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    /// Parse and validate a state document.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ZeroError> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err(limit(format!(
                "todo sync state is {} bytes, above the {MAX_STATE_BYTES} byte limit",
                bytes.len()
            )));
        }
        let state: Self = serde_json::from_slice(bytes).map_err(|error| {
            corrupt(format!(
                "todo sync state does not match the schema: {error}"
            ))
        })?;
        state.validate()?;
        Ok(state)
    }

    /// Load and validate a state file with a size bound.
    pub fn load(path: &Path) -> Result<Self, ZeroError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| io_error("cannot inspect the todo sync state", path, error))?;
        if !metadata.is_file() {
            return Err(invalid(format!("{} is not a regular file", path.display())));
        }
        if metadata.len() > MAX_STATE_BYTES as u64 {
            return Err(limit(format!(
                "todo sync state is {} bytes, above the {MAX_STATE_BYTES} byte limit",
                metadata.len()
            )));
        }
        let file = fs::File::open(path)
            .map_err(|error| io_error("cannot open the todo sync state", path, error))?;
        let mut bytes = Vec::new();
        file.take(MAX_STATE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("cannot read the todo sync state", path, error))?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(limit(format!(
                "todo sync state grew past the {MAX_STATE_BYTES} byte limit while being read"
            )));
        }
        Self::from_json(&bytes)
    }

    /// Validate and write the state through a temporary file and a rename.
    pub fn save_atomic(&self, path: &Path) -> Result<(), ZeroError> {
        let bytes = self.to_json()?;
        write_atomic(path, &bytes)
    }

    fn require_todo(&self, id: &str) -> Result<&HalcyonTodo, ZeroError> {
        self.todos.get(id).ok_or_else(|| {
            ZeroError::new(
                ErrorCode::NotFound,
                format!("no local todo `{id}` exists (see {TODO_SYNC_DOCS_ANCHOR})"),
            )
        })
    }

    fn change_status(
        &mut self,
        id: &str,
        kind: TodoOpKind,
        status: TodoStatus,
        now_ms: i64,
    ) -> Result<TodoOp, ZeroError> {
        let mut todo = self.require_todo(id)?.clone();
        let op = TodoOp {
            op_id: self.next_op_id(id, now_ms),
            todo_id: id.to_string(),
            kind,
            payload: TodoPayload::status(status),
            base_version: todo.version,
            at_ms: now_ms,
        };
        self.queue_op(op.clone())?;
        todo.status = status;
        todo.updated_ms = now_ms;
        todo.version += 1;
        self.todos.insert(id.to_string(), todo);
        Ok(op)
    }

    /// A deterministic op id that no queued or applied op is using.
    fn next_op_id(&self, todo_id: &str, now_ms: i64) -> String {
        let stem = format!("local-{todo_id}-{now_ms}");
        if self.op_id_is_free(&stem) {
            return stem;
        }
        let mut suffix = 1_u32;
        loop {
            let candidate = format!("{stem}-{suffix}");
            if self.op_id_is_free(&candidate) {
                return candidate;
            }
            suffix = suffix.saturating_add(1);
        }
    }

    fn op_id_is_free(&self, op_id: &str) -> bool {
        !self.applied.contains(op_id) && !self.pending.iter().any(|op| op.op_id == op_id)
    }
}

/// One op the backend refused because its base version was stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRejection {
    /// The refused op id.
    pub op_id: String,
    /// The remote todo that made the op stale. Never overwritten by the op.
    pub remote: HalcyonTodo,
}

/// What [`TkbTodo::push`] reports for one batch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PushOutcome {
    /// Op ids the backend accepted (or already had seen).
    pub applied: Vec<String>,
    /// Ops refused by the version check, with the remote side.
    pub rejected: Vec<PushRejection>,
}

/// The seam a host binds to the real `tkb` binary.
///
/// Implementations must dedupe by `op_id` and reject an op whose `base_version`
/// is below the remote version instead of overwriting. An unreachable backend
/// returns the error from [`unavailable_error`], which [`sync`] maps to
/// [`SyncReport::Offline`] without dropping the queue.
pub trait TkbTodo {
    /// Return every remote todo changed at or after `since_ms`.
    fn pull(&self, since_ms: i64) -> Result<Vec<HalcyonTodo>, ZeroError>;

    /// Apply `ops` idempotently, in order.
    fn push(&self, ops: &[TodoOp]) -> Result<PushOutcome, ZeroError>;
}

/// The typed "backend is unavailable" error a [`TkbTodo`] returns when offline.
pub fn unavailable_error(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Unavailable, message)
}

/// Pull, merge, and push when `halcyon.todo_sync` is enabled.
///
/// The flag is checked first; when it is off nothing is read or written and
/// [`SyncReport::Disabled`] is returned. Otherwise:
///
/// 1. `backend.pull(last_sync_ms)`;
/// 2. adopt remote changes, conflicted where a pending op and the remote both
///    changed the same todo;
/// 3. `backend.push(pending)` with already-applied ids filtered out. An empty
///    batch is not sent;
/// 4. advance `last_sync_ms` only after steps 1-3 succeeded.
///
/// `ErrorCode::Unavailable` and `ErrorCode::Offline` from the backend mean the
/// queue is kept and the window is not advanced. Any other backend error leaves
/// the queue intact too, but is reported as [`SyncReport::Failed`] so it is not
/// mistaken for an ordinary offline period.
pub fn sync(
    state: &mut SyncState,
    backend: &dyn TkbTodo,
    flags: &FlagValues,
    now_ms: i64,
) -> SyncReport {
    if !flags.enabled(Flag::TodoSync) {
        return SyncReport::Disabled;
    }

    let remote = match backend.pull(state.last_sync_ms) {
        Ok(remote) => remote,
        Err(error) if is_offline(&error) => {
            return SyncReport::Offline {
                queued: state.pending.len(),
            }
        }
        Err(error) => return SyncReport::Failed(error),
    };

    let mut pulled = 0_usize;
    for remote_todo in remote {
        if let Err(error) = remote_todo.validate() {
            return SyncReport::Failed(corrupt(format!(
                "tkb returned an invalid todo `{}`: {}",
                remote_todo.id,
                error.message()
            )));
        }
        match merge_remote(state, remote_todo, now_ms) {
            Ok(true) => pulled += 1,
            Ok(false) => {}
            Err(error) => return SyncReport::Failed(error),
        }
    }

    let batch: Vec<TodoOp> = state
        .pending
        .iter()
        .filter(|op| !state.applied.contains(&op.op_id))
        .cloned()
        .collect();
    let skipped = state.pending.len().saturating_sub(batch.len());
    let mut pushed = 0_usize;

    if !batch.is_empty() {
        match backend.push(&batch) {
            Ok(outcome) => {
                let accepted: BTreeSet<String> = outcome.applied.iter().cloned().collect();
                let rejected: BTreeSet<String> = outcome
                    .rejected
                    .iter()
                    .map(|rejection| rejection.op_id.clone())
                    .collect();
                let rejected_todos: BTreeSet<String> = outcome
                    .rejected
                    .iter()
                    .map(|rejection| rejection.remote.id.clone())
                    .collect();

                pushed = accepted.len();
                state.applied.extend(accepted.iter().cloned());
                state.pending.retain(|op| {
                    !accepted.contains(&op.op_id)
                        && !rejected.contains(&op.op_id)
                        && !rejected_todos.contains(&op.todo_id)
                });
                for rejection in &outcome.rejected {
                    record_rejection(state, rejection, now_ms);
                }
            }
            Err(error) if is_offline(&error) => {
                return SyncReport::Offline {
                    queued: state.pending.len(),
                }
            }
            Err(error) => return SyncReport::Failed(error),
        }
    }

    prune_applied(state);
    state.last_sync_ms = now_ms;
    SyncReport::Synced {
        pulled,
        pushed,
        skipped,
        conflicts: state.conflicts.len(),
        last_sync_ms: now_ms,
    }
}

/// Settle one conflict and remove it from the visible list.
///
/// `KeepLocal` and `Merge` keep a local todo and queue a new op whose
/// `base_version` is the remote version, so the backend accepts it.
/// `TakeRemote` adopts the remote todo and drops the local queued change. The
/// changed state is applied all at once: a failure while queueing leaves the
/// state and the conflict untouched.
pub fn resolve_conflict(
    state: &mut SyncState,
    todo_id: &str,
    choice: ConflictChoice,
    now_ms: i64,
) -> Result<(), ZeroError> {
    let index = state
        .conflicts
        .iter()
        .position(|conflict| conflict.todo_id == todo_id)
        .ok_or_else(|| {
            ZeroError::new(
                ErrorCode::NotFound,
                format!("no todo conflict `{todo_id}` is visible (see {TODO_SYNC_DOCS_ANCHOR})"),
            )
        })?;
    let conflict = state.conflicts[index].clone();

    let resolved = match choice {
        ConflictChoice::TakeRemote => conflict.remote.clone(),
        ConflictChoice::KeepLocal => HalcyonTodo {
            id: conflict.todo_id.clone(),
            title: conflict.local.title.clone(),
            status: conflict.local.status,
            updated_ms: now_ms,
            version: conflict.remote.version + 1,
        },
        ConflictChoice::Merge => HalcyonTodo {
            id: conflict.todo_id.clone(),
            title: conflict.local.title.clone(),
            status: merge_status(conflict.local.status, conflict.remote.status),
            updated_ms: now_ms,
            version: conflict.remote.version + 1,
        },
    };

    let mut next = state.clone();
    next.conflicts.retain(|stored| stored.todo_id != todo_id);
    next.pending.retain(|op| op.todo_id != conflict.todo_id);
    next.todos
        .insert(conflict.todo_id.clone(), resolved.clone());

    if !matches!(choice, ConflictChoice::TakeRemote) {
        let op = TodoOp {
            op_id: next.next_op_id(&conflict.todo_id, now_ms),
            todo_id: conflict.todo_id.clone(),
            kind: TodoOpKind::Update,
            payload: TodoPayload {
                title: Some(resolved.title.clone()),
                status: Some(resolved.status),
            },
            base_version: conflict.remote.version,
            at_ms: now_ms,
        };
        next.queue_op(op)?;
    }
    next.validate()?;
    *state = next;
    Ok(())
}

/// Conflicts as panel items, sorted by todo id.
///
/// This is the T-HAL-07 Done criterion: a conflict is not a log line or a
/// silent last-writer-wins overwrite, it is an item the UI can show and the
/// user can resolve.
pub fn conflict_items(state: &SyncState) -> Vec<ConflictItem> {
    let mut items: Vec<ConflictItem> = state
        .conflicts
        .iter()
        .map(|conflict| ConflictItem {
            todo_id: conflict.todo_id.clone(),
            title: conflict.local.title.clone(),
            status: conflict.local.status,
            reference: format!("{TODO_SYNC_DOCS_ANCHOR} todo:{}", conflict.todo_id),
        })
        .collect();
    items.sort_by(|left, right| left.todo_id.cmp(&right.todo_id));
    items
}

/// Merge one remote todo. `Ok(true)` means local state adopted it.
fn merge_remote(
    state: &mut SyncState,
    remote: HalcyonTodo,
    now_ms: i64,
) -> Result<bool, ZeroError> {
    let Some(local) = state.todos.get(&remote.id).cloned() else {
        if state.todos.len() >= MAX_TODOS {
            return Err(limit(format!(
                "adopting remote todo `{}` would exceed the {MAX_TODOS} todo limit",
                remote.id
            )));
        }
        state
            .pending
            .retain(|op| !(op.todo_id == remote.id && op.base_version < remote.version));
        state.todos.insert(remote.id.clone(), remote);
        return Ok(true);
    };

    // A visible conflict freezes the local side until the user resolves it.
    // Re-pulling the same remote change must not silently adopt it.
    if state
        .conflicts
        .iter()
        .any(|conflict| conflict.todo_id == remote.id)
    {
        return Ok(false);
    }

    let has_stale_op = state
        .pending
        .iter()
        .any(|op| op.todo_id == remote.id && op.base_version < remote.version);
    let diverged = local.title != remote.title || local.status != remote.status;

    if has_stale_op && diverged {
        let todo_id = remote.id.clone();
        note_conflict(state, local, remote, now_ms);
        // The conflict carries the local values; the stale op must not be
        // pushed, because the backend would only reject it.
        state.pending.retain(|op| op.todo_id != todo_id);
        return Ok(false);
    }

    if remote.version >= local.version {
        state
            .pending
            .retain(|op| !(op.todo_id == remote.id && op.base_version < remote.version));
        state.todos.insert(remote.id.clone(), remote);
        Ok(true)
    } else {
        // Local is ahead: its queued ops will raise the remote version.
        Ok(false)
    }
}

/// Record a push rejection as a conflict, or adopt the remote when no local
/// todo exists to conflict with.
fn record_rejection(state: &mut SyncState, rejection: &PushRejection, now_ms: i64) {
    if let Some(local) = state.todos.get(&rejection.remote.id).cloned() {
        note_conflict(state, local, rejection.remote.clone(), now_ms);
    } else {
        state
            .todos
            .insert(rejection.remote.id.clone(), rejection.remote.clone());
    }
}

/// Insert or replace the visible conflict for a todo.
fn note_conflict(state: &mut SyncState, local: HalcyonTodo, remote: HalcyonTodo, now_ms: i64) {
    let conflict = TodoConflict {
        todo_id: local.id.clone(),
        local,
        remote,
        detected_ms: now_ms,
    };
    if let Some(existing) = state
        .conflicts
        .iter_mut()
        .find(|stored| stored.todo_id == conflict.todo_id)
    {
        *existing = conflict;
        return;
    }
    if state.conflicts.len() >= MAX_CONFLICTS {
        state.conflicts.remove(0);
    }
    state.conflicts.push(conflict);
}

fn merge_status(local: TodoStatus, remote: TodoStatus) -> TodoStatus {
    if local == TodoStatus::Done || remote == TodoStatus::Done {
        TodoStatus::Done
    } else if local == TodoStatus::Blocked || remote == TodoStatus::Blocked {
        TodoStatus::Blocked
    } else {
        TodoStatus::Open
    }
}

fn prune_applied(state: &mut SyncState) {
    while state.applied.len() > MAX_APPLIED_OPS {
        let Some(oldest) = state.applied.iter().next().cloned() else {
            break;
        };
        state.applied.remove(&oldest);
    }
}

fn is_offline(error: &ZeroError) -> bool {
    matches!(error.code(), ErrorCode::Unavailable | ErrorCode::Offline)
}

fn validate_identifier(field: &str, value: &str) -> Result<(), ZeroError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must not be empty")));
    }
    if value.len() > MAX_TODO_ID_BYTES {
        return Err(limit(format!(
            "{field} is {} bytes, above the {MAX_TODO_ID_BYTES} byte limit",
            value.len()
        )));
    }
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(invalid(format!(
            "{field} must be non-empty visible ASCII without spaces"
        )));
    }
    Ok(())
}

fn validate_title(title: &str) -> Result<(), ZeroError> {
    if title.is_empty() {
        return Err(invalid("todo title must not be empty"));
    }
    if title.len() > MAX_TODO_TITLE_BYTES {
        return Err(limit(format!(
            "todo title is {} bytes, above the {MAX_TODO_TITLE_BYTES} byte limit",
            title.len()
        )));
    }
    if title
        .chars()
        .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(invalid(
            "todo title must not contain control characters other than newline and tab",
        ));
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ZeroError> {
    let temporary = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&temporary)
            .map_err(|error| io_error("cannot create the temporary file for", path, error))?;
        file.write_all(bytes)
            .map_err(|error| io_error("cannot write the temporary file for", path, error))?;
        file.sync_all()
            .map_err(|error| io_error("cannot sync the temporary file for", path, error))?;
    }
    fs::rename(&temporary, path).map_err(|error| io_error("cannot replace", path, error))
}

fn io_error(context: &str, path: &Path, error: io::Error) -> ZeroError {
    let code = match error.kind() {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::Io,
    };
    ZeroError::new(code, format!("{context} {}: {error}", path.display()))
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn corrupt(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Corrupt, message)
}

/// A stored field that fails validation is corrupt state, not bad caller input.
fn stored(error: ZeroError) -> ZeroError {
    corrupt(format!("todo sync state is malformed: {}", error.message()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeSet as Set;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const T0: i64 = 1_700_000_000_000;

    fn enabled_flags() -> FlagValues {
        let mut flags = FlagValues::new();
        flags.set(Flag::TodoSync, true);
        flags
    }

    #[derive(Default)]
    struct ScriptedBackend {
        remote: RefCell<BTreeMap<String, HalcyonTodo>>,
        applied: RefCell<Set<String>>,
        pulls: Cell<usize>,
        pushes: Cell<usize>,
        last_since: Cell<i64>,
        sent: RefCell<Vec<TodoOp>>,
        offline: Cell<bool>,
        pull_silently: Cell<bool>,
    }

    impl ScriptedBackend {
        fn new() -> Self {
            Self::default()
        }

        fn remote_put(&self, todo: HalcyonTodo) {
            self.remote.borrow_mut().insert(todo.id.clone(), todo);
        }

        fn remote_edit(
            &self,
            id: &str,
            title: &str,
            status: TodoStatus,
            version: u64,
            updated_ms: i64,
        ) {
            let mut remote = self.remote.borrow_mut();
            let todo = remote.get_mut(id).expect("remote todo");
            todo.title = title.to_string();
            todo.status = status;
            todo.version = version;
            todo.updated_ms = updated_ms;
        }

        fn remote_todo(&self, id: &str) -> HalcyonTodo {
            self.remote.borrow().get(id).cloned().expect("remote todo")
        }

        fn sent_kinds(&self) -> Vec<TodoOpKind> {
            self.sent.borrow().iter().map(|op| op.kind).collect()
        }
    }

    impl TkbTodo for ScriptedBackend {
        fn pull(&self, since_ms: i64) -> Result<Vec<HalcyonTodo>, ZeroError> {
            self.pulls.set(self.pulls.get() + 1);
            self.last_since.set(since_ms);
            if self.offline.get() {
                return Err(unavailable_error("tkb is offline"));
            }
            if self.pull_silently.get() {
                return Ok(Vec::new());
            }
            let mut changed: Vec<HalcyonTodo> = self
                .remote
                .borrow()
                .values()
                .filter(|todo| todo.updated_ms >= since_ms)
                .cloned()
                .collect();
            changed.sort_by(|left, right| left.id.cmp(&right.id));
            Ok(changed)
        }

        fn push(&self, ops: &[TodoOp]) -> Result<PushOutcome, ZeroError> {
            self.pushes.set(self.pushes.get() + 1);
            if self.offline.get() {
                return Err(unavailable_error("tkb is offline"));
            }
            let mut outcome = PushOutcome::default();
            for op in ops {
                self.sent.borrow_mut().push(op.clone());
                if self.applied.borrow().contains(&op.op_id) {
                    outcome.applied.push(op.op_id.clone());
                    continue;
                }
                match op.kind {
                    TodoOpKind::Create => {
                        if self.remote.borrow().contains_key(&op.todo_id) {
                            let remote = self.remote_todo(&op.todo_id);
                            outcome.rejected.push(PushRejection {
                                op_id: op.op_id.clone(),
                                remote,
                            });
                            continue;
                        }
                        let todo = HalcyonTodo {
                            id: op.todo_id.clone(),
                            title: op.payload.title.clone().expect("create payload title"),
                            status: op.payload.status.unwrap_or(TodoStatus::Open),
                            updated_ms: op.at_ms,
                            version: 1,
                        };
                        self.remote_put(todo);
                    }
                    TodoOpKind::Update | TodoOpKind::Complete | TodoOpKind::Block => {
                        let Some(current) = self.remote.borrow().get(&op.todo_id).cloned() else {
                            return Err(ZeroError::new(
                                ErrorCode::NotFound,
                                format!("remote todo `{}` does not exist", op.todo_id),
                            ));
                        };
                        if op.base_version < current.version {
                            outcome.rejected.push(PushRejection {
                                op_id: op.op_id.clone(),
                                remote: current,
                            });
                            continue;
                        }
                        let mut todo = current;
                        op.apply(&mut todo)?;
                        todo.version = op.base_version + 1;
                        self.remote_put(todo);
                    }
                }
                self.applied.borrow_mut().insert(op.op_id.clone());
                outcome.applied.push(op.op_id.clone());
            }
            Ok(outcome)
        }
    }

    fn state_with_todo() -> (SyncState, ScriptedBackend) {
        let mut state = SyncState::new();
        let backend = ScriptedBackend::new();
        state
            .create_todo("t1", "write docs", T0)
            .expect("queue create");
        (state, backend)
    }

    fn synced_once() -> (SyncState, ScriptedBackend) {
        let (mut state, backend) = state_with_todo();
        let report = sync(&mut state, &backend, &enabled_flags(), T0 + 10);
        assert!(report.is_synced(), "{report:?}");
        (state, backend)
    }

    fn create_conflict(state: &mut SyncState, backend: &ScriptedBackend) {
        state
            .update_todo("t1", "local rewrite", T0 + 20)
            .expect("local update");
        backend.remote_edit("t1", "remote rewrite", TodoStatus::Open, 2, T0 + 30);
        let report = sync(state, backend, &enabled_flags(), T0 + 40);
        assert!(
            matches!(report, SyncReport::Synced { conflicts: 1, .. }),
            "{report:?}"
        );
        assert_eq!(state.conflicts.len(), 1);
    }

    fn fixture_state() -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("halcyon-todo-sync.json");
        (dir, path)
    }

    #[test]
    fn two_way_create_update_and_complete_sync() {
        let (mut state, backend) = state_with_todo();

        let report = sync(&mut state, &backend, &enabled_flags(), T0 + 10);
        assert!(report.is_synced(), "{report:?}");
        let remote = backend.remote_todo("t1");
        assert_eq!(remote.title, "write docs");
        assert_eq!(remote.status, TodoStatus::Open);
        assert_eq!(remote.version, 1);

        state
            .update_todo("t1", "write halcyon docs", T0 + 20)
            .expect("update");
        sync(&mut state, &backend, &enabled_flags(), T0 + 30);
        let remote = backend.remote_todo("t1");
        assert_eq!(remote.title, "write halcyon docs");
        assert_eq!(remote.version, 2);

        state.complete_todo("t1", T0 + 40).expect("complete");
        sync(&mut state, &backend, &enabled_flags(), T0 + 50);
        let remote = backend.remote_todo("t1");
        assert_eq!(remote.status, TodoStatus::Done);
        assert_eq!(remote.version, 3);
        assert_eq!(state.todo("t1").expect("local").version, 3);

        // Pull direction: a remote-only create is adopted with no push.
        backend.remote_put(HalcyonTodo {
            id: "t2".to_string(),
            title: "remote task".to_string(),
            status: TodoStatus::Open,
            updated_ms: T0 + 60,
            version: 1,
        });
        let pushes = backend.pushes.get();
        let report = sync(&mut state, &backend, &enabled_flags(), T0 + 70);
        assert!(
            matches!(report, SyncReport::Synced { pulled: 1, .. }),
            "{report:?}"
        );
        assert_eq!(
            state.todo("t2").map(|todo| todo.title.as_str()),
            Some("remote task")
        );
        assert_eq!(backend.pushes.get(), pushes, "nothing to push");
    }

    #[test]
    fn repeated_sync_is_idempotent_and_sends_nothing() {
        let (mut state, backend) = synced_once();
        let pushes = backend.pushes.get();
        let sent = backend.sent.borrow().len();

        let report = sync(&mut state, &backend, &enabled_flags(), T0 + 20);

        assert!(
            matches!(
                report,
                SyncReport::Synced {
                    pushed: 0,
                    skipped: 0,
                    ..
                }
            ),
            "{report:?}"
        );
        assert_eq!(backend.pushes.get(), pushes, "no second push batch");
        assert_eq!(backend.sent.borrow().len(), sent, "no duplicate op");
        assert_eq!(backend.remote_todo("t1").version, 1);
        assert!(state.pending.is_empty());
        assert_eq!(state.applied.len(), 1);
    }

    #[test]
    fn offline_queues_then_flushes_in_order_and_keeps_the_window() {
        let (mut state, backend) = state_with_todo();
        backend.offline.set(true);
        state
            .create_todo("t2", "second", T0 + 1)
            .expect("create t2");

        let report = sync(&mut state, &backend, &enabled_flags(), T0 + 10);

        assert_eq!(report, SyncReport::Offline { queued: 2 });
        assert_eq!(state.pending.len(), 2);
        assert_eq!(state.last_sync_ms, 0, "a failed sync must not advance");
        assert!(backend.sent.borrow().is_empty());

        backend.offline.set(false);
        let report = sync(&mut state, &backend, &enabled_flags(), T0 + 20);

        assert!(
            matches!(report, SyncReport::Synced { pushed: 2, .. }),
            "{report:?}"
        );
        assert!(state.pending.is_empty());
        assert_eq!(state.last_sync_ms, T0 + 20);
        assert_eq!(
            backend.sent_kinds(),
            vec![TodoOpKind::Create, TodoOpKind::Create]
        );
        assert_eq!(
            backend
                .sent
                .borrow()
                .iter()
                .map(|op| op.todo_id.as_str())
                .collect::<Vec<_>>(),
            vec!["t1", "t2"],
            "the queue flushes in order"
        );
    }

    #[test]
    fn both_sides_editing_the_same_todo_surfaces_a_conflict_item() {
        let (mut state, backend) = synced_once();
        create_conflict(&mut state, &backend);

        let items = conflict_items(&state);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].todo_id, "t1");
        assert_eq!(items[0].title, "local rewrite");
        assert_eq!(items[0].status, TodoStatus::Open);
        assert!(items[0].reference.contains(TODO_SYNC_DOCS_ANCHOR));
        assert!(items[0].reference.contains("t1"));

        let conflict = &state.conflicts[0];
        assert_eq!(conflict.remote.title, "remote rewrite");
        assert_eq!(conflict.detected_ms, T0 + 40);
        assert_eq!(
            state.todo("t1").expect("local").title,
            "local rewrite",
            "the pull must not overwrite the local side"
        );
        assert!(
            state.pending.is_empty(),
            "the stale op is held by the conflict"
        );

        // A second sync neither duplicates the conflict nor pushes the op.
        let sent = backend.sent.borrow().len();
        let report = sync(&mut state, &backend, &enabled_flags(), T0 + 50);
        assert!(
            matches!(report, SyncReport::Synced { conflicts: 1, .. }),
            "{report:?}"
        );
        assert_eq!(state.conflicts.len(), 1);
        assert_eq!(backend.sent.borrow().len(), sent);
    }

    #[test]
    fn a_stale_base_version_creates_a_conflict_not_an_overwrite() {
        let (mut state, backend) = synced_once();
        state
            .update_todo("t1", "local rewrite", T0 + 20)
            .expect("local update");
        backend.remote_edit("t1", "remote rewrite", TodoStatus::Open, 2, T0 + 20);
        backend.pull_silently.set(true);

        let report = sync(&mut state, &backend, &enabled_flags(), T0 + 30);

        assert!(
            matches!(report, SyncReport::Synced { conflicts: 1, .. }),
            "{report:?}"
        );
        let remote = backend.remote_todo("t1");
        assert_eq!(
            remote.title, "remote rewrite",
            "the stale op did not overwrite"
        );
        assert_eq!(remote.version, 2);
        assert_eq!(state.todo("t1").expect("local").title, "local rewrite");
        assert_eq!(state.conflicts.len(), 1);
        assert_eq!(state.conflicts[0].remote.title, "remote rewrite");
        assert!(state.pending.is_empty(), "a rejected op leaves the queue");
    }

    #[test]
    fn resolving_keep_local_pushes_the_local_side_at_the_remote_version() {
        let (mut state, backend) = synced_once();
        create_conflict(&mut state, &backend);

        resolve_conflict(&mut state, "t1", ConflictChoice::KeepLocal, T0 + 60).expect("resolve");

        assert!(state.conflicts.is_empty());
        assert!(conflict_items(&state).is_empty());
        let local = state.todo("t1").expect("local");
        assert_eq!(local.title, "local rewrite");
        assert_eq!(local.version, 3, "remote version 2 plus one");
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.pending[0].base_version, 2);

        sync(&mut state, &backend, &enabled_flags(), T0 + 70);
        let remote = backend.remote_todo("t1");
        assert_eq!(remote.title, "local rewrite");
        assert_eq!(remote.version, 3);
    }

    #[test]
    fn resolving_take_remote_adopts_the_remote_side_and_drops_the_change() {
        let (mut state, backend) = synced_once();
        create_conflict(&mut state, &backend);
        let sent = backend.sent.borrow().len();

        resolve_conflict(&mut state, "t1", ConflictChoice::TakeRemote, T0 + 60).expect("resolve");

        assert!(state.conflicts.is_empty());
        let local = state.todo("t1").expect("local");
        assert_eq!(local.title, "remote rewrite");
        assert_eq!(local.version, 2);
        assert!(state.pending.is_empty());

        sync(&mut state, &backend, &enabled_flags(), T0 + 70);
        assert_eq!(backend.sent.borrow().len(), sent, "nothing to push");
        assert_eq!(backend.remote_todo("t1").title, "remote rewrite");
    }

    #[test]
    fn resolving_merge_keeps_the_local_title_and_the_furthest_status() {
        let (mut state, backend) = synced_once();
        state.complete_todo("t1", T0 + 20).expect("local complete");
        backend.remote_edit("t1", "remote rewrite", TodoStatus::Open, 2, T0 + 30);
        let report = sync(&mut state, &backend, &enabled_flags(), T0 + 40);
        assert!(
            matches!(report, SyncReport::Synced { conflicts: 1, .. }),
            "{report:?}"
        );

        resolve_conflict(&mut state, "t1", ConflictChoice::Merge, T0 + 50).expect("resolve");

        let local = state.todo("t1").expect("local");
        assert_eq!(local.title, "write docs", "the local title is kept");
        assert_eq!(local.status, TodoStatus::Done, "done beats open");
        assert_eq!(local.version, 3);
        assert_eq!(state.pending[0].payload.status, Some(TodoStatus::Done));

        sync(&mut state, &backend, &enabled_flags(), T0 + 60);
        let remote = backend.remote_todo("t1");
        assert_eq!(remote.title, "write docs");
        assert_eq!(remote.status, TodoStatus::Done);
        assert_eq!(remote.version, 3);
    }

    #[test]
    fn a_disabled_flag_never_calls_the_backend() {
        let (mut state, backend) = state_with_todo();

        let report = sync(&mut state, &backend, &FlagValues::new(), T0 + 10);

        assert_eq!(report, SyncReport::Disabled);
        assert_eq!(backend.pulls.get(), 0);
        assert_eq!(backend.pushes.get(), 0);
        assert_eq!(state.pending.len(), 1, "the queue is untouched");
        assert_eq!(state.last_sync_ms, 0);
        assert!(state.conflicts.is_empty());
    }

    #[test]
    fn corrupt_and_malformed_state_is_typed_and_state_round_trips() {
        let error = SyncState::from_json(b"not json").expect_err("corrupt");
        assert_eq!(error.code(), ErrorCode::Corrupt);

        let error = SyncState::from_json(br#"{"schema_version": 99}"#).expect_err("schema");
        assert_eq!(error.code(), ErrorCode::SchemaVersion);

        let oversized = vec![b' '; MAX_STATE_BYTES + 1];
        let error = SyncState::from_json(&oversized).expect_err("oversized");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);

        let mismatched = br#"{
            "schema_version": 1,
            "todos": {"t1": {"id": "t2", "title": "x", "status": "open", "updated_ms": 1, "version": 1}}
        }"#;
        let error = SyncState::from_json(mismatched).expect_err("mismatched id");
        assert_eq!(error.code(), ErrorCode::Corrupt);

        let mut state = SyncState::new();
        state.create_todo("t1", "persisted", T0).expect("create");
        let (_dir, path) = fixture_state();
        state.save_atomic(&path).expect("save");
        let loaded = SyncState::load(&path).expect("load");
        assert_eq!(loaded, state);
        assert!(
            !path.with_extension("tmp").exists(),
            "the temporary is gone"
        );

        fs::write(&path, b"{").expect("corrupt the file");
        let error = SyncState::load(&path).expect_err("corrupt file");
        assert_eq!(error.code(), ErrorCode::Corrupt);
    }

    #[test]
    fn the_queue_and_the_conflict_list_are_bounded() {
        let mut state = SyncState::new();
        for index in 0..MAX_PENDING_OPS {
            state
                .create_todo(&format!("t{index}"), "title", T0)
                .expect("queue");
        }
        assert_eq!(state.pending.len(), MAX_PENDING_OPS);
        let error = state
            .create_todo("overflow", "title", T0)
            .expect_err("queue is full");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert_eq!(state.pending.len(), MAX_PENDING_OPS);
        assert!(state.todo("overflow").is_none());

        for index in 0..=MAX_CONFLICTS {
            let id = format!("c{index}");
            let local = HalcyonTodo::new(id.clone(), "local", T0).expect("local");
            let mut remote = local.clone();
            remote.title = "remote".to_string();
            remote.version = 2;
            note_conflict(&mut state, local, remote, T0);
        }
        assert_eq!(state.conflicts.len(), MAX_CONFLICTS);
        assert_eq!(
            state
                .conflicts
                .last()
                .map(|conflict| conflict.todo_id.as_str()),
            Some("c64"),
            "the newest conflict is kept"
        );
    }

    #[test]
    fn versions_increment_with_every_accepted_op() {
        let (mut state, backend) = synced_once();

        state.update_todo("t1", "v2", T0 + 20).expect("update");
        sync(&mut state, &backend, &enabled_flags(), T0 + 30);
        state.complete_todo("t1", T0 + 40).expect("complete");
        sync(&mut state, &backend, &enabled_flags(), T0 + 50);
        state.block_todo("t1", T0 + 60).expect("block");
        sync(&mut state, &backend, &enabled_flags(), T0 + 70);

        let local = state.todo("t1").expect("local");
        let remote = backend.remote_todo("t1");
        assert_eq!(local.version, 4);
        assert_eq!(remote.version, 4);
        assert_eq!(remote.status, TodoStatus::Blocked);
        assert_eq!(remote.updated_ms, T0 + 60);
        assert_eq!(state.last_sync_ms, T0 + 70);
    }

    #[test]
    fn an_offline_pull_does_not_advance_the_window() {
        let (mut state, backend) = state_with_todo();
        backend.offline.set(true);

        assert!(sync(&mut state, &backend, &enabled_flags(), T0 + 10).is_offline());
        assert_eq!(state.last_sync_ms, 0);

        backend.offline.set(false);
        assert!(sync(&mut state, &backend, &enabled_flags(), T0 + 20).is_synced());
        assert_eq!(state.last_sync_ms, T0 + 20);
        // The flush re-reads the window the failed attempt would have read.
        assert_eq!(backend.last_since.get(), 0);
    }

    #[test]
    fn resolving_an_unknown_conflict_is_not_found() {
        let mut state = SyncState::new();
        let error = resolve_conflict(&mut state, "missing", ConflictChoice::KeepLocal, T0)
            .expect_err("no conflict");
        assert_eq!(error.code(), ErrorCode::NotFound);
    }

    #[test]
    fn queueing_a_duplicate_op_id_is_a_no_op() {
        let mut state = SyncState::new();
        let op = state.create_todo("t1", "title", T0).expect("create");

        state.queue_op(op.clone()).expect("duplicate queue");
        assert_eq!(state.pending.len(), 1);
    }

    #[test]
    fn a_backend_failure_other_than_offline_is_reported_and_keeps_the_queue() {
        struct Broken;
        impl TkbTodo for Broken {
            fn pull(&self, _since_ms: i64) -> Result<Vec<HalcyonTodo>, ZeroError> {
                Err(ZeroError::new(ErrorCode::Internal, "tkb protocol error"))
            }
            fn push(&self, _ops: &[TodoOp]) -> Result<PushOutcome, ZeroError> {
                unreachable!("pull fails first")
            }
        }

        let (mut state, _) = state_with_todo();
        let report = sync(&mut state, &Broken, &enabled_flags(), T0 + 10);

        match report {
            SyncReport::Failed(error) => assert_eq!(error.code(), ErrorCode::Internal),
            other => panic!("unexpected report {other:?}"),
        }
        assert_eq!(state.pending.len(), 1, "no queued op was dropped");
        assert_eq!(state.last_sync_ms, 0);
    }
}
