//! Action record schema (ACT-01, ACT-02). A record missing any required field is
//! rejected at registration; one registry is shared by every surface.

use serde::{Deserialize, Serialize};
use zero_policy::ActionClass;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRule {
    Never,
    Always,
    IrreversibleOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Idempotency {
    None,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditMeta {
    pub redact_arguments: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRecord {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// JSON Schema for the arguments object.
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub mutating: bool,
    pub deterministic: bool,
    pub policy_class: ActionClass,
    pub approval: ApprovalRule,
    pub agent_invocable: bool,
    pub unattended: bool,
    pub idempotency: Idempotency,
    pub audit: AuditMeta,
    /// True when the action is invoked without a slash command.
    pub implicit: bool,
    /// True when the palette or menu shows a control for it.
    pub ui_control: bool,
}

impl ActionRecord {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() || self.title.is_empty() || self.description.is_empty() || self.category.is_empty() {
            return Err("id, title, description, and category are required".into());
        }
        if !self.id.contains('.') && !self.id.contains(':') {
            return Err(format!("action id `{}` must be namespaced as `area.action`", self.id));
        }
        if !self.arguments.is_object() {
            return Err(format!("`{}` arguments must be a JSON Schema object", self.id));
        }
        if self.implicit && self.ui_control {
            return Err(format!("implicit action `{}` must not have a UI control", self.id));
        }
        let mut seen = std::collections::BTreeSet::new();
        for alias in &self.aliases {
            if !seen.insert(alias) {
                return Err(format!("duplicate alias `{alias}` on `{}`", self.id));
            }
        }
        Ok(())
    }

    pub fn from_json(text: &str) -> Result<Self, String> {
        let record: ActionRecord = serde_json::from_str(text).map_err(|e| format!("schema: {e}"))?;
        record.validate()?;
        Ok(record)
    }

    pub fn arguments_digest(&self) -> String {
        blake3::hash(self.arguments.to_string().as_bytes()).to_hex().to_string()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn valid_json() -> serde_json::Value {
        serde_json::json!({
            "id": "mode.set",
            "title": "Switch mode",
            "description": "Change the session mode",
            "category": "policy",
            "aliases": ["mode"],
            "arguments": {"type": "object", "properties": {"mode": {"type": "string"}}},
            "capabilities": [],
            "mutating": true,
            "deterministic": true,
            "policy_class": "mode_change",
            "approval": "never",
            "agent_invocable": false,
            "unattended": false,
            "idempotency": "required",
            "audit": {"redact_arguments": false},
            "implicit": false,
            "ui_control": false
        })
    }

    #[test]
    fn a_schema_test_rejects_a_missing_field() {
        let mut value = valid_json();
        value.as_object_mut().unwrap().remove("title");
        let err = ActionRecord::from_json(&value.to_string()).unwrap_err();
        assert!(err.contains("title") || err.contains("missing"), "{err}");

        let record = ActionRecord::from_json(&valid_json().to_string()).unwrap();
        assert_eq!(record.id, "mode.set");
        record.validate().unwrap();
    }

    #[test]
    fn namespacing_and_implicit_lint_are_enforced() {
        let mut value = valid_json();
        value["id"] = serde_json::json!("unnamespaced");
        assert!(ActionRecord::from_json(&value.to_string()).is_err());

        let mut value = valid_json();
        value["implicit"] = serde_json::json!(true);
        value["ui_control"] = serde_json::json!(true);
        assert!(ActionRecord::from_json(&value.to_string()).is_err());
    }
}
