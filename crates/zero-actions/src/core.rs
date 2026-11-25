//! The core action set. One registry is shared by the TUI, daemon app, desktop,
//! web, and Android surfaces.

use crate::record::{ActionRecord, ApprovalRule, AuditMeta, Idempotency};
use crate::registry::ActionRegistry;
use serde_json::json;
use zero_policy::ActionClass;

#[allow(clippy::too_many_arguments)]
fn record(
    id: &str,
    title: &str,
    description: &str,
    category: &str,
    class: ActionClass,
    deterministic: bool,
    agent_invocable: bool,
    implicit: bool,
    ui_control: bool,
) -> ActionRecord {
    ActionRecord {
        id: id.into(),
        title: title.into(),
        description: description.into(),
        category: category.into(),
        aliases: Vec::new(),
        arguments: json!({"type": "object"}),
        capabilities: Vec::new(),
        mutating: !matches!(class, ActionClass::Read),
        deterministic,
        policy_class: class,
        approval: ApprovalRule::Never,
        agent_invocable,
        unattended: agent_invocable,
        idempotency: Idempotency::Required,
        audit: AuditMeta { redact_arguments: false },
        implicit,
        ui_control,
    }
}

fn with_required(mut record: ActionRecord, fields: &[&str]) -> ActionRecord {
    record.arguments = json!({
        "type": "object",
        "required": fields,
        "properties": fields.iter().map(|f| ((*f).to_string(), json!({"type": "string"}))).collect::<serde_json::Map<_, _>>()
    });
    record
}

/// Build the core registry. Panics only on a programming error in this file.
pub fn core_registry() -> ActionRegistry {
    let mut registry = ActionRegistry::new();
    let mut add = |record: ActionRecord| registry.register_core(record).expect("core action schema");

    add(with_required(
        record("mode.set", "Set mode", "Change the session mode", "policy", ActionClass::ModeChange, true, false, false, false),
        &["mode"],
    ));
    add(record("mode.cycle", "Cycle mode", "Advance to the next mode", "policy", ActionClass::ModeChange, true, false, false, false));
    add(with_required(
        record("session.rename", "Rename session", "Give this session a name", "session", ActionClass::Write, true, true, false, false),
        &["name"],
    ));
    add(record("session.export", "Export session", "Write a versioned bundle", "session", ActionClass::Write, true, true, false, false));
    add(record("palette.open", "Open palette", "Search every action", "ui", ActionClass::Read, true, false, false, false));
    add(record("help.show", "Show help", "Generated help for the current mode", "ui", ActionClass::Read, true, false, true, false));
    add(record("theme.select", "Select theme", "Choose a colour theme", "ui", ActionClass::Write, true, false, false, false));
    add(record("daemon.open", "Open daemon app", "Show workers and attachments", "daemon", ActionClass::Read, true, false, false, false));
    add(record("daemon.toggle", "Toggle daemon app", "Switch surfaces with Ctrl+B", "daemon", ActionClass::Read, true, false, false, false));
    add(record("doctor.run", "Run doctor", "Diagnose the installation", "diagnostics", ActionClass::Read, true, true, false, false));
    add(record("review.start", "Start security review", "Run the review checklist", "review", ActionClass::Subagent, false, true, false, false));
    add(record("actions.list", "List actions", "Actions the agent may invoke", "agent", ActionClass::Read, true, true, false, false));
    add(with_required(
        record("actions.run", "Run action", "Invoke an action by id", "agent", ActionClass::Subagent, false, true, false, false),
        &["id"],
    ));
    add(record("approval.allow", "Allow", "Approve the pending action", "approval", ActionClass::Write, true, false, false, true));
    add(record("approval.deny", "Deny", "Reject the pending action", "approval", ActionClass::Write, true, false, false, true));
    add(with_required(
        record("queue.steer", "Steer", "Queue a steering message", "queue", ActionClass::Write, true, false, false, false),
        &["text"],
    ));
    add(with_required(
        record("shell.prefix", "Run shell command", "Execute `!command` under policy", "shell", ActionClass::ShellMutating, true, false, true, false),
        &["command"],
    ));
    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_core_registry_registers_and_lints_clean() {
        let registry = core_registry();
        assert!(registry.len() >= 15);
        assert!(registry.lint().is_empty(), "{:?}", registry.lint());
        assert!(registry.agent_visible().len() >= 5);
        for action in registry.actions() {
            action.validate().unwrap();
        }
    }
}
