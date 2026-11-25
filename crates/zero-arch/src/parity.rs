//! Parity audit (PAR-01, T-PAR-03): every item in Parts 1, 2, and 8 of
//! `features.md` must have exactly one row with a state and a reason.
//!
//! ## Item parser
//!
//! `features.md` has three item shapes in the audited parts and the parser is
//! deliberately tolerant of all of them:
//!
//! - Part 1 uses a bold lead-in: `- **Recursive Language Model (RLM).** ...`.
//!   The bold segment (minus its trailing full stop) is the title.
//! - Part 2 findings are plain bullets: `- Classify every parity item ...`.
//!   The first sentence is the title.
//! - Part 8 mixes both, and some bullets start with a backticked command
//!   (`- `zero resume` ...`); the first sentence is again the title.
//!
//! A bullet is a line that starts with `- ` in column zero. Its continuation
//! lines are the indented lines that follow. Headings, blank lines, and a new
//! bullet end an item. A part starts at `## Part <n>` and ends at the next
//! `## Part` or `## ` heading.
//!
//! IDs are generated, because the source items have none: `p<part>-<section
//! slug>-<two-digit ordinal within the section>`, for example
//! `p1-core-model-01`. They are stable while the section and item order stay
//! the same, and `check` rejects a row whose ID is not in `features.md`.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The audited parts. Part 10 is the requirements catalogue and is checked by
/// `traceability` instead.
pub const AUDITED_PARTS: [u8; 3] = [1, 2, 8];

/// One item parsed from `features.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FeatureItem {
    pub id: String,
    pub part: u8,
    pub section: String,
    pub title: String,
    pub text: String,
}

/// The assessed state of one item.
///
/// `OutOfScope` is a deliberate product decision (for example the Part 8 CLI
/// reduction or a PAR-03 non-goal). `Deferred` means it is not built and no
/// current task covers it. `Partial` means some of it exists and the reason
/// names the gap. `Unassessed` is the seed value and always fails the check.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum State {
    Implemented,
    Partial,
    Deferred,
    OutOfScope,
    Unassessed,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Implemented => "Implemented",
            State::Partial => "Partial",
            State::Deferred => "Deferred",
            State::OutOfScope => "OutOfScope",
            State::Unassessed => "Unassessed",
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One row of `crates/zero-arch/data/parity.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParityItem {
    pub id: String,
    pub state: State,
    pub reason: String,
    #[serde(default)]
    pub refs: Vec<String>,
}

/// The versioned parity data file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParityData {
    pub version: u32,
    pub items: Vec<ParityItem>,
}

/// One feature item joined with its parity row, in document order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParityRow {
    pub id: String,
    pub part: u8,
    pub section: String,
    pub title: String,
    pub state: State,
    pub reason: String,
    pub refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParityReport {
    /// Number of items parsed from `features.md`.
    pub items: usize,
    pub ok: bool,
    pub unassessed: Vec<String>,
    pub unknown: Vec<String>,
    pub missing: Vec<String>,
    pub duplicates: Vec<String>,
    pub empty_reasons: Vec<String>,
    pub implemented_without_refs: Vec<String>,
    /// Human-readable failures, in the same deterministic order as the lists.
    pub errors: Vec<String>,
    pub states: BTreeMap<String, usize>,
    pub rows: Vec<ParityRow>,
}

impl ParityReport {
    pub fn is_ok(&self) -> bool {
        self.ok
    }

    /// Count of one state across the parsed items.
    pub fn state_count(&self, state: State) -> usize {
        self.states.get(state.as_str()).copied().unwrap_or(0)
    }
}

/// Parse Parts 1, 2, and 8 into items, in document order.
pub fn parse_items(features_text: &str) -> Vec<FeatureItem> {
    let mut items = Vec::new();
    let mut part: Option<u8> = None;
    let mut section = String::new();
    let mut section_slug = String::new();
    let mut ordinal = 0usize;

    let mut lines = features_text.lines().peekable();
    while let Some(line) = lines.next() {
        if let Some(rest) = line.strip_prefix("## Part ") {
            let number: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            part = number.parse().ok().filter(|n| AUDITED_PARTS.contains(n));
            section.clear();
            section_slug.clear();
            ordinal = 0;
            continue;
        }
        if line.starts_with("## ") {
            part = None;
            continue;
        }
        if part.is_none() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("### ") {
            section = strip_leading_number(rest.trim()).to_string();
            section_slug = slug(&section);
            ordinal = 0;
            continue;
        }
        if !line.starts_with("- ") {
            continue;
        }

        // Collect the indented continuation lines of this bullet.
        let mut text = line[2..].trim().to_string();
        while let Some(next) = lines.peek() {
            if next.starts_with(' ') || next.starts_with('\t') {
                let next = lines.next().unwrap_or_default();
                text.push(' ');
                text.push_str(next.trim());
            } else {
                break;
            }
        }
        let text = collapse_whitespace(&text);
        if text.is_empty() {
            continue;
        }
        ordinal += 1;
        let slug = if section_slug.is_empty() { "section" } else { &section_slug };
        let id = format!("p{}-{slug}-{ordinal:02}", part.unwrap_or_default());
        items.push(FeatureItem {
            id,
            part: part.unwrap_or_default(),
            section: section.clone(),
            title: title_of(&text),
            text,
        });
    }
    items
}

/// A bold lead-in is the title when present; otherwise the first sentence is.
fn title_of(text: &str) -> String {
    if let Some(rest) = text.strip_prefix("**") {
        if let Some(end) = rest.find("**") {
            let label = rest[..end].trim().trim_end_matches(['.', ':']).trim();
            if !label.is_empty() {
                return label.to_string();
            }
        }
    }
    let first = match text.find(". ") {
        Some(end) => &text[..end],
        None => text,
    };
    first.trim().trim_end_matches('.').trim().to_string()
}

fn strip_leading_number(text: &str) -> &str {
    let trimmed = text.trim_start();
    let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return trimmed;
    }
    let rest = &trimmed[digits.len()..];
    match rest.strip_prefix(". ") {
        Some(after) => after.trim_start(),
        None => trimmed,
    }
}

fn slug(text: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            if dash && !out.is_empty() {
                out.push('-');
            }
            out.push(ch.to_ascii_lowercase());
            dash = false;
        } else if !out.is_empty() {
            dash = true;
        }
    }
    out
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Parse the parity data file.
pub fn load_parity(json: &str) -> Result<ParityData, String> {
    serde_json::from_str(json).map_err(|e| format!("parity.json: {e}"))
}

/// Check the data file against every item in Parts 1, 2, and 8.
pub fn check(features_text: &str, parity_json: &str) -> ParityReport {
    let items = parse_items(features_text);
    let mut errors = Vec::new();
    let data = match load_parity(parity_json) {
        Ok(data) => data,
        Err(e) => {
            errors.push(e);
            ParityData { version: 0, items: Vec::new() }
        }
    };

    let known: BTreeSet<&str> = items.iter().map(|i| i.id.as_str()).collect();
    let mut by_id: BTreeMap<&str, &ParityItem> = BTreeMap::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut duplicates = Vec::new();
    let mut unknown = Vec::new();
    for row in &data.items {
        if !seen.insert(row.id.as_str()) {
            if !duplicates.iter().any(|d| d == &row.id) {
                duplicates.push(row.id.clone());
            }
            continue;
        }
        if !known.contains(row.id.as_str()) {
            unknown.push(row.id.clone());
            continue;
        }
        by_id.insert(row.id.as_str(), row);
    }

    let mut unassessed = Vec::new();
    let mut missing = Vec::new();
    let mut empty_reasons = Vec::new();
    let mut implemented_without_refs = Vec::new();
    let mut states: BTreeMap<String, usize> = BTreeMap::new();
    let mut rows = Vec::with_capacity(items.len());

    for item in &items {
        let row = match by_id.get(item.id.as_str()) {
            Some(row) => {
                if row.reason.trim().is_empty() {
                    empty_reasons.push(item.id.clone());
                }
                if row.state == State::Implemented
                    && row.refs.iter().all(|r| r.trim().is_empty())
                {
                    implemented_without_refs.push(item.id.clone());
                }
                if row.state == State::Unassessed {
                    unassessed.push(item.id.clone());
                }
                *states.entry(row.state.as_str().to_string()).or_insert(0) += 1;
                ParityRow {
                    id: item.id.clone(),
                    part: item.part,
                    section: item.section.clone(),
                    title: item.title.clone(),
                    state: row.state,
                    reason: row.reason.trim().to_string(),
                    refs: row.refs.clone(),
                }
            }
            None => {
                missing.push(item.id.clone());
                *states.entry(State::Unassessed.as_str().to_string()).or_insert(0) += 1;
                ParityRow {
                    id: item.id.clone(),
                    part: item.part,
                    section: item.section.clone(),
                    title: item.title.clone(),
                    state: State::Unassessed,
                    reason: String::new(),
                    refs: Vec::new(),
                }
            }
        };
        rows.push(row);
    }

    for id in &missing {
        errors.push(format!("item {id} has no parity row"));
    }
    for id in &unassessed {
        errors.push(format!("item {id} is Unassessed"));
    }
    for id in &unknown {
        errors.push(format!("parity row {id} is not an item in features.md Parts 1, 2, or 8"));
    }
    for id in &duplicates {
        errors.push(format!("duplicate parity row {id}"));
    }
    for id in &empty_reasons {
        errors.push(format!("item {id} has an empty reason"));
    }
    for id in &implemented_without_refs {
        errors.push(format!("item {id} is Implemented without a ref"));
    }

    let ok = errors.is_empty();
    ParityReport {
        items: items.len(),
        ok,
        unassessed,
        unknown,
        missing,
        duplicates,
        empty_reasons,
        implemented_without_refs,
        errors,
        states,
        rows,
    }
}

/// Render the generated audit table. The caller writes `docs/parity.md`.
pub fn render_markdown(report: &ParityReport) -> String {
    let mut out = String::new();
    out.push_str("# Parity audit\n\n");
    out.push_str("Generated by `cargo run -p xtask -- parity-doc --write` from\n");
    out.push_str("`features.md` Parts 1, 2, and 8 and `crates/zero-arch/data/parity.json`.\n");
    out.push_str("Do not edit by hand. `cargo test -p zero-arch parity` fails when an item is\n");
    out.push_str("missing, unknown, unassessed, duplicated, or lacks a reason or (for an\n");
    out.push_str("implemented item) a reference. IDs are generated from the part, section,\n");
    out.push_str("and item order; the parser is documented in `crates/zero-arch/src/parity.rs`.\n\n");
    out.push_str("States: **Implemented** (evidence exists), **Partial** (some of it exists;\n");
    out.push_str("the reason names the gap), **Deferred** (not built and no current task),\n");
    out.push_str("**OutOfScope** (a deliberate product decision).\n\n");
    out.push_str(&format!(
        "{} items: {} implemented, {} partial, {} deferred, {} out of scope, {} unassessed.\n\n",
        report.items,
        report.state_count(State::Implemented),
        report.state_count(State::Partial),
        report.state_count(State::Deferred),
        report.state_count(State::OutOfScope),
        report.state_count(State::Unassessed),
    ));
    out.push_str("| ID | Part | Section | Item | State | Reason | Refs |\n");
    out.push_str("|---|---|---|---|---|---|---|\n");
    for row in &report.rows {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} | {} |\n",
            row.id,
            row.part,
            escape_cell(&row.section),
            escape_cell(&row.title),
            row.state,
            escape_cell(&row.reason),
            escape_cell(&row.refs.join(", "))
        ));
    }
    out
}

fn escape_cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEATURES: &str = "\
## Part 1: Features

### Core model

- **Recursive Language Model (RLM).** The model works in a kernel.
- **Continual Harness.** Durable state.

### Interfaces

- Named, resumed, and forked sessions. Another sentence.

## Part 2: Research

### 1. Claude Code parity research

- Classify every item. Do not present decorative parity.
- Never hardcode key checks; never block loops on I/O.

## Part 3: Ignored

- **OUT-01** Not audited.

## Part 8: OpenCode feature parity

### CLI surface to match

- **CLI:** `zero resume`, `zero login`.
- Windows, macOS, and Linux builds.
";

    fn item(id: &str, state: State, reason: &str, refs: &[&str]) -> ParityItem {
        ParityItem {
            id: id.into(),
            state,
            reason: reason.into(),
            refs: refs.iter().map(|r| r.to_string()).collect(),
        }
    }

    fn json(items: Vec<ParityItem>) -> String {
        serde_json::to_string(&ParityData { version: 1, items }).unwrap()
    }

    fn all_rows() -> Vec<ParityItem> {
        vec![
            item("p1-core-model-01", State::Implemented, "kernel", &["KRN-01"]),
            item("p1-core-model-02", State::Partial, "no refine", &["SI-01"]),
            item("p1-interfaces-01", State::Partial, "no fork UI", &["SES-02"]),
            item("p2-claude-code-parity-research-01", State::Implemented, "audited", &["PAR-01"]),
            item("p2-claude-code-parity-research-02", State::Implemented, "registry", &["ACT-04"]),
            item("p8-cli-surface-to-match-01", State::Partial, "four verbs", &["FND-11"]),
            item("p8-cli-surface-to-match-02", State::Partial, "installers pending", &["INST-01"]),
        ]
    }

    #[test]
    fn parses_the_three_item_shapes_and_ignores_other_parts() {
        let items = parse_items(FEATURES);
        assert_eq!(items.len(), 7, "{items:#?}");
        assert_eq!(items[0].id, "p1-core-model-01");
        assert_eq!(items[0].title, "Recursive Language Model (RLM)");
        assert_eq!(items[2].title, "Named, resumed, and forked sessions");
        assert_eq!(items[3].part, 2);
        assert_eq!(items[3].section, "Claude Code parity research");
        assert_eq!(items[5].title, "CLI");
        assert!(!items.iter().any(|i| i.id.contains("out-")));
        assert!(!items.iter().any(|i| i.text.contains("Not audited")));
    }

    #[test]
    fn the_real_data_passes() {
        let report = check(FEATURES, &json(all_rows()));
        assert!(report.ok, "{:?}", report.errors);
        assert_eq!(report.items, 7);
        assert_eq!(report.state_count(State::Implemented), 3);
        assert!(report.unassessed.is_empty());
    }

    #[test]
    fn a_missing_row_fails() {
        let mut rows = all_rows();
        rows.pop();
        let report = check(FEATURES, &json(rows));
        assert!(!report.ok);
        assert_eq!(report.missing, vec!["p8-cli-surface-to-match-02"]);
        assert_eq!(report.state_count(State::Unassessed), 1);
    }

    #[test]
    fn an_unassessed_row_fails() {
        let mut rows = all_rows();
        rows[0].state = State::Unassessed;
        let report = check(FEATURES, &json(rows));
        assert!(!report.ok);
        assert_eq!(report.unassessed, vec!["p1-core-model-01"]);
    }

    #[test]
    fn an_unknown_id_fails() {
        let mut rows = all_rows();
        rows.push(item("p1-core-model-99", State::Deferred, "no such item", &[]));
        let report = check(FEATURES, &json(rows));
        assert!(!report.ok);
        assert_eq!(report.unknown, vec!["p1-core-model-99"]);
    }

    #[test]
    fn a_duplicate_id_fails() {
        let mut rows = all_rows();
        rows.push(item("p1-core-model-02", State::Deferred, "second row", &[]));
        let report = check(FEATURES, &json(rows));
        assert!(!report.ok);
        assert_eq!(report.duplicates, vec!["p1-core-model-02"]);
    }

    #[test]
    fn an_empty_reason_fails() {
        let mut rows = all_rows();
        rows[1].reason = "   ".into();
        let report = check(FEATURES, &json(rows));
        assert!(!report.ok);
        assert_eq!(report.empty_reasons, vec!["p1-core-model-02"]);
    }

    #[test]
    fn an_implemented_row_without_refs_fails() {
        let mut rows = all_rows();
        rows[0].refs.clear();
        let report = check(FEATURES, &json(rows));
        assert!(!report.ok);
        assert_eq!(report.implemented_without_refs, vec!["p1-core-model-01"]);
    }

    #[test]
    fn ordering_is_document_order_and_deterministic() {
        let report = check(FEATURES, &json(all_rows()));
        let ids: Vec<&str> = report.rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "p1-core-model-01",
                "p1-core-model-02",
                "p1-interfaces-01",
                "p2-claude-code-parity-research-01",
                "p2-claude-code-parity-research-02",
                "p8-cli-surface-to-match-01",
                "p8-cli-surface-to-match-02",
            ]
        );
        assert_eq!(report.errors, check(FEATURES, &json(all_rows())).errors);
    }

    #[test]
    fn a_malformed_data_file_fails_instead_of_panicking() {
        let report = check(FEATURES, "{not json");
        assert!(!report.ok);
        assert!(report.errors[0].starts_with("parity.json:"));
        assert_eq!(report.items, 7);
    }
}
