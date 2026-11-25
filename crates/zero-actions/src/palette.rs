//! Palette and generated help (ACT-13): fuzzy search, categories, mode filtering,
//! and denied actions carrying the reason.

use crate::record::ActionRecord;
use crate::registry::ActionRegistry;
use zero_policy::mode::{default_verdict, Mode, Verdict};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaletteItem {
    pub id: String,
    pub title: String,
    pub category: String,
    pub available: bool,
    /// Why the action is unavailable or will ask first.
    pub reason: Option<String>,
}

pub fn palette(registry: &ActionRegistry, mode: Mode) -> Vec<PaletteItem> {
    let mut items: Vec<PaletteItem> = registry
        .actions()
        .map(|record| item_for(record, mode))
        .collect();
    items.sort_by(|a, b| a.category.cmp(&b.category).then(a.title.cmp(&b.title)));
    items
}

fn item_for(record: &ActionRecord, mode: Mode) -> PaletteItem {
    match default_verdict(mode, record.policy_class) {
        Verdict::Allow => PaletteItem {
            id: record.id.clone(),
            title: record.title.clone(),
            category: record.category.clone(),
            available: true,
            reason: None,
        },
        Verdict::Ask => PaletteItem {
            id: record.id.clone(),
            title: record.title.clone(),
            category: record.category.clone(),
            available: true,
            reason: Some(format!("asks for approval in {}", mode.as_str())),
        },
        Verdict::Deny => PaletteItem {
            id: record.id.clone(),
            title: record.title.clone(),
            category: record.category.clone(),
            available: false,
            reason: Some(format!("denied in {}", mode.as_str())),
        },
    }
}

/// Fuzzy subsequence search over id, title, and category. Higher scores win;
/// ties keep the category/title order.
pub fn search(query: &str, items: &[PaletteItem]) -> Vec<PaletteItem> {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return items.to_vec();
    }
    let mut scored: Vec<(i32, PaletteItem)> = items
        .iter()
        .filter_map(|item| {
            let haystack = format!("{} {} {}", item.id, item.title, item.category).to_ascii_lowercase();
            score(&query, &haystack).map(|s| (s, item.clone()))
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.title.cmp(&b.1.title)));
    scored.into_iter().map(|(_, item)| item).collect()
}

fn score(query: &str, haystack: &str) -> Option<i32> {
    let mut chars = haystack.chars();
    let mut points = 0;
    let mut last_index = 0usize;
    for (i, q) in query.chars().enumerate() {
        let mut found = None;
        for (offset, c) in chars.by_ref().enumerate() {
            if c == q {
                found = Some(last_index + offset);
                break;
            }
        }
        let index = found?;
        points += 10 - (index.saturating_sub(last_index)).min(9) as i32;
        if i == 0 {
            points += 5;
        }
        last_index = index + 1;
    }
    Some(points)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_registry;

    #[test]
    fn denied_actions_carry_the_reason_and_are_absent_in_plan_mode() {
        let registry = core_registry();
        let plan = palette(&registry, Mode::Plan);
        let write = plan.iter().find(|i| i.id == "session.rename").unwrap();
        assert!(!write.available);
        assert!(write.reason.as_deref().unwrap().contains("denied in plan"));

        let auto = palette(&registry, Mode::Auto);
        let write = auto.iter().find(|i| i.id == "session.rename").unwrap();
        assert!(write.available);
        assert!(write.reason.is_none());
    }

    #[test]
    fn fuzzy_search_prefers_a_prefix_and_finds_acronyms() {
        let registry = core_registry();
        let items = palette(&registry, Mode::Auto);
        let top = search("help", &items);
        assert_eq!(top[0].id, "help.show");

        let acronym = search("sren", &items);
        assert!(acronym.iter().any(|i| i.id == "session.rename"), "{:?}", acronym.iter().map(|i| &i.id).collect::<Vec<_>>());
        assert!(search("zzzz", &items).is_empty());
    }

    #[test]
    fn categories_group_the_list() {
        let registry = core_registry();
        let items = palette(&registry, Mode::Auto);
        let categories: std::collections::BTreeSet<&str> = items.iter().map(|i| i.category.as_str()).collect();
        assert!(categories.contains("policy"));
        assert!(categories.contains("session"));
        assert!(items.windows(2).all(|w| w[0].category <= w[1].category));
    }
}
