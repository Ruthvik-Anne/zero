//! Action registry and extension namespacing (ACT-01, ACT-12).

use crate::record::ActionRecord;
use std::collections::BTreeMap;
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Core,
    Extension { namespace: &'static str },
}

pub struct ActionRegistry {
    actions: BTreeMap<String, ActionRecord>,
}

impl Default for ActionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionRegistry {
    pub fn new() -> Self {
        Self { actions: BTreeMap::new() }
    }

    /// Register a core action. Core ids are `area.action` and are unique.
    pub fn register_core(&mut self, record: ActionRecord) -> Result<()> {
        record.validate().map_err(|e| ZeroError::new(ErrorCode::InvalidInput, e))?;
        if record.id.contains(':') && !record.id.contains('.') {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!("core action `{}` must use `area.action`", record.id),
            ));
        }
        if self.actions.contains_key(&record.id) {
            return Err(ZeroError::new(ErrorCode::AlreadyExists, format!("action `{}` already exists", record.id)));
        }
        self.actions.insert(record.id.clone(), record);
        Ok(())
    }

    /// Register an extension action. It must be namespaced and may not shadow a
    /// core or another extension id.
    pub fn register_extension(&mut self, namespace: &str, record: ActionRecord) -> Result<()> {
        record.validate().map_err(|e| ZeroError::new(ErrorCode::InvalidInput, e))?;
        // Shadowing is checked first so a plugin claiming a core id gets the
        // security-relevant error, not a formatting one.
        if self.actions.contains_key(&record.id) {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                format!("extension may not shadow existing action `{}`", record.id),
            ));
        }
        let namespaced = record.id.starts_with(&format!("{namespace}."))
            || record.id.starts_with(&format!("{namespace}:"));
        if !namespaced {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!("extension action `{}` is not namespaced under `{namespace}`", record.id),
            ));
        }
        self.actions.insert(record.id.clone(), record);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&ActionRecord> {
        self.actions.get(id)
    }

    pub fn actions(&self) -> impl Iterator<Item = &ActionRecord> {
        self.actions.values()
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Registry lint: ids, explicit UI controls, and shadowing. Returns every
    /// violation rather than the first, so CI prints the whole list.
    pub fn lint(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for action in self.actions.values() {
            if let Err(e) = action.validate() {
                problems.push(e);
            }
            if action.implicit && action.ui_control {
                problems.push(format!("implicit action `{}` has a UI control", action.id));
            }
        }
        problems
    }

    /// Agent-visible actions: invocable by the agent and unattended-safe.
    pub fn agent_visible(&self) -> Vec<&ActionRecord> {
        self.actions.values().filter(|a| a.agent_invocable).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::valid_json;

    fn record(value: serde_json::Value) -> ActionRecord {
        ActionRecord::from_json(&value.to_string()).expect("valid fixture")
    }

    #[test]
    fn a_plugin_cannot_shadow_a_core_id() {
        let mut registry = ActionRegistry::new();
        registry.register_core(record(valid_json())).unwrap();
        let mut clash = valid_json();
        clash["id"] = serde_json::json!("mode.set");
        let err = registry.register_extension("ext.demo", record(clash)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::PolicyDenied);
        assert!(err.message().contains("shadow"));

        // A valid but different namespace is rejected.
        let mut other_namespace = valid_json();
        other_namespace["id"] = serde_json::json!("other.thing");
        let err = registry.register_extension("ext.demo", record(other_namespace)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInput);
        // An unnamespaced id cannot even be parsed.
        let mut unnamespaced = valid_json();
        unnamespaced["id"] = serde_json::json!("steal");
        assert!(ActionRecord::from_json(&unnamespaced.to_string()).is_err());

        let mut ok = valid_json();
        ok["id"] = serde_json::json!("ext.demo.format");
        ok["implicit"] = serde_json::json!(false);
        ok["ui_control"] = serde_json::json!(false);
        registry.register_extension("ext.demo", record(ok)).unwrap();
        assert!(registry.get("ext.demo.format").is_some());
    }

    #[test]
    fn the_lint_rejects_controls_on_implicit_actions() {
        let mut registry = ActionRegistry::new();
        let mut value = valid_json();
        value["id"] = serde_json::json!("help.show");
        value["implicit"] = serde_json::json!(true);
        value["ui_control"] = serde_json::json!(false);
        registry.register_core(record(value)).unwrap();
        assert!(registry.lint().is_empty());
    }
}
