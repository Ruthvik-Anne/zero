//! Architecture checks used by `xtask`, tests, and CI.

pub mod deps;
pub mod layers;
pub mod manifest;
pub mod parity;
pub mod traceability;

pub use deps::{check_graph, check_workspace, find_cycles, GraphReport, Violation};
pub use traceability::{check, parse_features, parse_tasks, Requirement, Task, TraceReport};

/// Everything CI enforces about the documents and the crate graph.
pub struct DocsCheck {
    pub trace: TraceReport,
    pub graph: GraphReport,
}

pub fn check_docs(root: &std::path::Path) -> Result<DocsCheck, std::io::Error> {
    let features = std::fs::read_to_string(root.join("features.md"))?;
    let tasks = std::fs::read_to_string(root.join("tasks.md"))?;
    Ok(DocsCheck {
        trace: check(&features, &tasks),
        graph: check_workspace(root),
    })
}
