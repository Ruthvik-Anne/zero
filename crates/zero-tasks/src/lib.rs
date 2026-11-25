//! `zero-tasks` — task DAG, claims, journal, limits, plan seeding, the todo
//! store, and keyboard-first capture.
//!
//! Contract (`architecture.md` §5): must not run work itself.

pub mod store;
pub mod todo;

pub use store::{
    detect_cycle, Claim, PlanTask, ProgressView, Task, TaskEvent, TaskEventKind, TaskLimits,
    TaskState, TaskStore,
};
pub use todo::{
    CaptureEffect, CaptureKey, Creator, ReviewReport, Scope, Todo, TodoCapture, TodoEvent,
    TodoEventKind, TodoFilter, TodoPatch, TodoState, TodoStore, TodoTool,
};
