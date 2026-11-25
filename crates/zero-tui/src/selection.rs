//! Identity-based selection (TUI-09): selection is an ID plus the generation it
//! was made in; a stale async refresh cannot move it.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    selected: Option<String>,
    generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refresh {
    pub accepted: bool,
    pub changed: bool,
}

impl Selection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Select an item only if the generation is current or newer.
    pub fn select(&mut self, id: impl Into<String>, generation: u64) -> bool {
        if generation < self.generation {
            return false;
        }
        self.generation = generation;
        self.selected = Some(id.into());
        true
    }

    /// Apply an async list refresh. A stale generation is rejected wholesale; a
    /// current one keeps the selection when the item still exists.
    pub fn refresh(&mut self, ids: &[String], generation: u64) -> Refresh {
        if generation < self.generation {
            return Refresh { accepted: false, changed: false };
        }
        self.generation = generation;
        match &self.selected {
            Some(id) if ids.iter().any(|candidate| candidate == id) => Refresh { accepted: true, changed: false },
            Some(_) => {
                self.selected = None;
                Refresh { accepted: true, changed: true }
            }
            None => Refresh { accepted: true, changed: false },
        }
    }

    pub fn clear(&mut self) {
        self.selected = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_async_refresh_cannot_move_the_selection() {
        let mut selection = Selection::new();
        assert!(selection.select("m3", 2));
        // An older list result arrives late: rejected, selection unchanged.
        let stale = selection.refresh(&["m1".into(), "m2".into()], 1);
        assert!(!stale.accepted);
        assert_eq!(selection.selected(), Some("m3"));

        // A current refresh keeps the row even though the order changed.
        let ok = selection.refresh(&["m9".into(), "m3".into()], 2);
        assert!(ok.accepted);
        assert!(!ok.changed);
        assert_eq!(selection.selected(), Some("m3"));
    }

    #[test]
    fn a_removed_item_clears_the_selection_on_a_current_generation() {
        let mut selection = Selection::new();
        selection.select("gone", 1);
        let refresh = selection.refresh(&["kept".into()], 2);
        assert!(refresh.accepted);
        assert!(refresh.changed);
        assert_eq!(selection.selected(), None);
    }
}
