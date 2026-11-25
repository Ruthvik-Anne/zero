//! The action being evaluated, its hash, and its actor.

use crate::mode::{ActionClass, Mode};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    User,
    Agent,
    Subagent,
    Schedule,
    Monitor,
    Mcp,
}

impl Actor {
    pub fn is_agent(self) -> bool {
        matches!(self, Actor::Agent | Actor::Subagent)
    }

    pub fn is_unattended(self) -> bool {
        matches!(self, Actor::Schedule | Actor::Monitor | Actor::Mcp)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub class: ActionClass,
    pub tool: String,
    #[serde(default)]
    pub target: Option<PathBuf>,
    #[serde(default)]
    pub arguments: serde_json::Value,
    pub actor: Actor,
    /// The parent mode for a subagent. A child can never exceed it.
    #[serde(default)]
    pub parent_mode: Option<Mode>,
    /// MCP/network tool marked and pinned read-only by the user.
    #[serde(default)]
    pub verified_read_only: bool,
    /// The action cannot be undone (for example a purge or an overwrite).
    #[serde(default)]
    pub irreversible: bool,
    /// Requested new mode for a `mode_change` action.
    #[serde(default)]
    pub requested_mode: Option<Mode>,
}

impl Action {
    pub fn new(class: ActionClass, tool: impl Into<String>, actor: Actor) -> Self {
        Self {
            class,
            tool: tool.into(),
            target: None,
            arguments: serde_json::Value::Null,
            actor,
            parent_mode: None,
            verified_read_only: false,
            irreversible: false,
            requested_mode: None,
        }
    }

    pub fn with_target(mut self, target: impl Into<PathBuf>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn with_arguments(mut self, arguments: serde_json::Value) -> Self {
        self.arguments = arguments;
        self
    }

    pub fn with_parent_mode(mut self, mode: Mode) -> Self {
        self.parent_mode = Some(mode);
        self
    }

    pub fn verified_read_only(mut self, yes: bool) -> Self {
        self.verified_read_only = yes;
        self
    }

    pub fn irreversible(mut self, yes: bool) -> Self {
        self.irreversible = yes;
        self
    }

    /// Canonical bytes for the approval hash. Field order is fixed; the target is
    /// normalised to a slash form so a path does not silently change the hash by
    /// separator.
    pub fn canonical(&self) -> String {
        let target = self
            .target
            .as_ref()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        let args = canonical_json(&self.arguments);
        format!(
            "class={};tool={};target={};args={};irreversible={}",
            self.class.as_str(),
            self.tool,
            target,
            args,
            self.irreversible
        )
    }

    pub fn hash(&self) -> String {
        blake3::hash(self.canonical().as_bytes()).to_hex().to_string()
    }
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap_or_default(), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_across_object_key_order_and_path_separators() {
        let a = Action::new(ActionClass::ShellMutating, "bash", Actor::Agent)
            .with_arguments(serde_json::json!({"command":"rm x","cwd":"/tmp"}))
            .with_target(r"C:\work\a");
        let b = Action::new(ActionClass::ShellMutating, "bash", Actor::Agent)
            .with_arguments(serde_json::json!({"cwd":"/tmp","command":"rm x"}))
            .with_target("C:/work/a");
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn changing_the_action_changes_the_hash() {
        let base = Action::new(ActionClass::ShellMutating, "bash", Actor::Agent)
            .with_arguments(serde_json::json!({"command":"rm x"}));
        let mutated = Action::new(ActionClass::ShellMutating, "bash", Actor::Agent)
            .with_arguments(serde_json::json!({"command":"rm -rf /"}));
        assert_ne!(base.hash(), mutated.hash());
        assert_eq!(base.hash().len(), 64);
    }
}
