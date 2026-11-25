//! ACT-09: the registry lint. Fails CI when an implicit action has a UI control,
//! when an id is unnamespaced, or when a record is incomplete.

use std::process::ExitCode;
use zero_actions::core_registry;

fn main() -> ExitCode {
    let registry = core_registry();
    let problems = registry.lint();
    println!(
        "actions: {} registered, {} agent-invocable",
        registry.len(),
        registry.agent_visible().len()
    );
    if problems.is_empty() {
        println!("actions lint: OK");
        ExitCode::SUCCESS
    } else {
        for problem in problems {
            eprintln!("FAIL {problem}");
        }
        ExitCode::FAILURE
    }
}
