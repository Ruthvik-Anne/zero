//! `zero-agent` — agent loop, sessions, compaction, context files, queue,
//! artifacts, export/import, and projects/goals in later milestones.
//!
//! Contract (`architecture.md` §5): must not bypass the policy evaluator. The
//! loop is the only dispatch path; M2 inserts the evaluator here.

pub mod artifacts;
pub mod compaction;
pub mod context;
pub mod export;
pub mod r#loop;
pub mod queue;
pub mod tools;
pub mod tree;

pub use r#loop::{
    AgentLoop, CancelToken, EchoTool, LoopConfig, ReadFileTool, RunOutcome, Tool, ToolEntry,
    ToolRegistry, ToolResult, TurnRecord,
};
pub use tools::{
    activate, filter_denied, hygiene, inject_tools, search, stable_prefix_hash, wire_schemas,
    Activation, ActivationContext, PromptInjection, Route, SearchHit, ToolMeta, ToolSource,
    ToolTelemetry, Use,
};
pub use tree::{auto_name, ResumeView, SessionNode, SessionTree};

/// The core tool set loaded by the loop: echo and read-only file access.
pub fn tool_registry_with_core() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(EchoTool));
    registry.register(Box::new(ReadFileTool::default()));
    registry
}
