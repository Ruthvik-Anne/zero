//! Keybindings (ACT-04): every key goes through the registry, with per-surface
//! defaults, conflict detection, and remapping.

use crate::executor::Surface;
use crate::registry::ActionRegistry;
use std::collections::BTreeMap;
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, Default)]
pub struct Keymap {
    bindings: BTreeMap<(Surface, String), String>,
}

impl Keymap {
    pub fn with_defaults(registry: &ActionRegistry) -> Self {
        let mut keymap = Self::default();
        let defaults = [
            (Surface::Tui, "Shift+Tab", "mode.cycle"),
            (Surface::Tui, "Ctrl+P", "palette.open"),
            (Surface::Tui, "F1", "help.show"),
            (Surface::Tui, "Ctrl+B", "daemon.toggle"),
            (Surface::DaemonApp, "Ctrl+B", "daemon.toggle"),
        ];
        for (surface, chord, action) in defaults {
            if registry.get(action).is_some() {
                let _ = keymap.bind(surface, chord, action);
            }
        }
        keymap
    }

    /// Bind a chord, rejecting a conflict with a different action.
    pub fn bind(&mut self, surface: Surface, chord: &str, action_id: &str) -> Result<()> {
        let key = (surface, normalise(chord));
        if let Some(existing) = self.bindings.get(&key) {
            if existing != action_id {
                return Err(ZeroError::new(
                    ErrorCode::ConfigInvalid,
                    format!("{chord} on {surface:?} is already bound to `{existing}`"),
                ));
            }
        }
        self.bindings.insert(key, action_id.to_string());
        Ok(())
    }

    /// Move an action to a new chord. Every action is rebindable.
    pub fn rebind(&mut self, surface: Surface, action_id: &str, chord: &str) -> Result<()> {
        self.bindings.retain(|(s, _), a| !(*s == surface && a == action_id));
        self.bind(surface, chord, action_id)
    }

    pub fn resolve(&self, surface: Surface, chord: &str) -> Option<&str> {
        self.bindings.get(&(surface, normalise(chord))).map(String::as_str)
    }

    pub fn bindings_for(&self, surface: Surface) -> Vec<(String, String)> {
        self.bindings
            .iter()
            .filter(|((s, _), _)| *s == surface)
            .map(|((_, chord), action)| (chord.clone(), action.clone()))
            .collect()
    }
}

fn normalise(chord: &str) -> String {
    chord
        .split('+')
        .map(|part| {
            let trimmed = part.trim();
            let mut chars = trimmed.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("+")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_registry;

    #[test]
    fn every_action_is_rebindable() {
        let registry = core_registry();
        let mut keymap = Keymap::with_defaults(&registry);
        for (i, record) in registry.actions().enumerate() {
            let chord = format!("Ctrl+Alt+{}", (b'A' + (i % 26) as u8) as char);
            keymap.rebind(Surface::Tui, &record.id, &chord).unwrap();
            assert_eq!(keymap.resolve(Surface::Tui, &chord), Some(record.id.as_str()), "{}", record.id);
        }
    }

    #[test]
    fn conflicts_are_detected_and_surfaces_are_independent() {
        let registry = core_registry();
        let mut keymap = Keymap::with_defaults(&registry);
        let err = keymap.bind(Surface::Tui, "Shift+Tab", "session.rename").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigInvalid);
        assert_eq!(keymap.resolve(Surface::Tui, "shift+tab"), Some("mode.cycle"));
        // The daemon surface has its own binding for Ctrl+B.
        assert_eq!(keymap.resolve(Surface::DaemonApp, "Ctrl+B"), Some("daemon.toggle"));
        assert_eq!(keymap.resolve(Surface::Web, "Ctrl+B"), None);
    }
}
