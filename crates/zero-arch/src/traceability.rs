//! Requirement-to-task traceability (PAR-01): the build fails when a requirement
//! has no task, a task has no requirement, or a task references an unknown ID.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Requirement {
    pub id: String,
    pub area: String,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Task {
    pub id: String,
    pub milestone: String,
    pub refs: Vec<String>,
    pub title: String,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct TraceReport {
    pub requirements: usize,
    pub tasks: usize,
    pub uncovered_requirements: Vec<String>,
    pub tasks_without_refs: Vec<String>,
    pub unknown_refs: Vec<(String, String)>,
    pub duplicate_task_ids: Vec<String>,
    pub uncovered_areas: Vec<String>,
    pub areas: BTreeMap<String, usize>,
}

impl TraceReport {
    pub fn ok(&self) -> bool {
        self.uncovered_requirements.is_empty()
            && self.tasks_without_refs.is_empty()
            && self.unknown_refs.is_empty()
            && self.duplicate_task_ids.is_empty()
            && self.uncovered_areas.is_empty()
    }

    pub fn errors(&self) -> Vec<String> {
        let mut out = Vec::new();
        for r in &self.uncovered_requirements {
            out.push(format!("requirement {r} has no task"));
        }
        for t in &self.tasks_without_refs {
            out.push(format!("task {t} has no requirement reference"));
        }
        for (t, r) in &self.unknown_refs {
            out.push(format!("task {t} references unknown requirement {r}"));
        }
        for d in &self.duplicate_task_ids {
            out.push(format!("duplicate task id {d}"));
        }
        for a in &self.uncovered_areas {
            out.push(format!("area {a} has requirements but no task"));
        }
        out
    }
}

fn is_upper(b: u8) -> bool {
    b.is_ascii_uppercase()
}

/// Find requirement-like tokens (`ABC-01`) in a string, including both ends of
/// `ABC-01..ABC-05` ranges. Task IDs (`T-ABC-01`) are excluded.
pub fn extract_ids(text: &str, known_areas: &BTreeSet<String>) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if is_upper(bytes[i]) && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'-')) {
            let start = i;
            let mut j = i;
            while j < bytes.len() && is_upper(bytes[j]) {
                j += 1;
            }
            let area = &text[start..j];
            let area_ok = known_areas.contains(area) && j - start >= 2 && j - start <= 4;
            if area_ok && j < bytes.len() && bytes[j] == b'-' && j + 2 < bytes.len() + 1 {
                let digits_start = j + 1;
                let mut k = digits_start;
                while k < bytes.len() && bytes[k].is_ascii_digit() {
                    k += 1;
                }
                if k - digits_start >= 2 {
                    out.push(text[start..k].to_string());
                    i = k;
                    continue;
                }
            }
            i = j.max(i + 1);
            continue;
        }
        i += 1;
    }
    out.dedup();
    out
}

/// Parse Part 10 of `features.md` into requirements and their areas.
pub fn parse_features(text: &str) -> Vec<Requirement> {
    let mut out = Vec::new();
    let mut area = String::new();
    let mut in_part10 = false;
    for line in text.lines() {
        if line.starts_with("## Part 10") {
            in_part10 = true;
            continue;
        }
        if in_part10 && line.starts_with("## ") && !line.starts_with("## Part 10") {
            in_part10 = false;
        }
        if !in_part10 {
            continue;
        }
        if line.starts_with("### 10.") {
            if let Some(start) = line.find("(`") {
                if let Some(end) = line[start + 2..].find("`)") {
                    area = line[start + 2..start + 2 + end].to_string();
                }
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("- **") {
            // The id is the first whitespace-delimited token after `- **`.
            let id_end = rest.find([' ', '*']).unwrap_or(rest.len());
            let id = &rest[..id_end];
            if !is_requirement_id(id) {
                continue;
            }
            let after = rest[id_end..].trim_start_matches(['*', ' ', '.']);
            let title = match after.find("**") {
                Some(end) => after[..end].trim().to_string(),
                None => after.trim().to_string(),
            };
            out.push(Requirement { id: id.to_string(), area: area.clone(), title });
        }
    }
    out
}

fn is_requirement_id(id: &str) -> bool {
    if !id.contains('-') || id.starts_with("T-") {
        return false;
    }
    let (area, num) = match id.split_once('-') {
        Some(v) => v,
        None => return false,
    };
    !area.is_empty()
        && area.len() <= 5
        && area.bytes().all(|b| b.is_ascii_uppercase())
        && num.len() >= 2
        && num.bytes().all(|b| b.is_ascii_digit())
}

/// Parse `tasks.md` into tasks, milestone, and references from each block.
pub fn parse_tasks(text: &str) -> Vec<Task> {
    let mut tasks = Vec::new();
    let mut milestone = String::new();
    let mut current: Option<Task> = None;
    let mut in_refs = false;

    let flush = |current: &mut Option<Task>, tasks: &mut Vec<Task>| {
        if let Some(t) = current.take() {
            tasks.push(t);
        }
    };

    for line in text.lines() {
        if line.starts_with("## ") && !line.starts_with("## Coverage") {
            flush(&mut current, &mut tasks);
            milestone = line
                .trim_start_matches("## ")
                .split('—')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            in_refs = false;
            continue;
        }
        if let Some(rest) = line.strip_prefix("- **") {
            let id_end = rest.find([' ', '*']).unwrap_or(rest.len());
            let id = rest[..id_end].trim_end_matches('.');
            if !id.starts_with("T-") {
                continue;
            }
            flush(&mut current, &mut tasks);
            let after = rest[id_end..].trim_start_matches(['*', ' ', '.']);
            let title = match after.find("**") {
                Some(end) => after[..end].trim().to_string(),
                None => after.trim().to_string(),
            };
            let mut task = Task { id: id.to_string(), milestone: milestone.clone(), refs: Vec::new(), title };
            in_refs = false;
            if let Some(pos) = line.find("**Refs:**") {
                in_refs = true;
                push_refs(&mut task, &line[pos + "**Refs:**".len()..]);
            }
            current = Some(task);
            continue;
        }
        if let Some(task) = current.as_mut() {
            if line.trim().is_empty() {
                // A blank line ends the block; continue scanning is harmless
                // because a new task flushes too.
                continue;
            }
            if let Some(pos) = line.find("**Refs:**") {
                in_refs = true;
                push_refs(task, &line[pos + "**Refs:**".len()..]);
                continue;
            }
            if in_refs {
                push_refs(task, line);
            }
        }
    }
    flush(&mut current, &mut tasks);
    tasks
}

fn push_refs(task: &mut Task, slice: &str) {
    for token in slice.split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' || c == '.')) {
        if token.is_empty() {
            continue;
        }
        // Accept `ABC-01` or a range `ABC-01..ABC-05`; reject prose like `200-`.
        let valid = token.split_once("..").map(|(a, b)| {
            is_requirement_id(a) && (b.is_empty() || is_requirement_id(b.trim_end_matches('.')))
        }).unwrap_or_else(|| is_requirement_id(token.trim_end_matches('.')));
        if valid && !task.refs.iter().any(|r| r == token) {
            task.refs.push(token.trim_end_matches('.').to_string());
        }
    }
}

/// Check coverage both ways.
pub fn check(features: &str, tasks: &str) -> TraceReport {
    let requirements = parse_features(features);
    let areas: BTreeSet<String> = requirements.iter().map(|r| r.area.clone()).collect();
    let parsed = parse_tasks(tasks);
    let known: BTreeSet<String> = requirements.iter().map(|r| r.id.clone()).collect();

    // Expand ranges and normalise references (some refs are written as ranges).
    let mut report = TraceReport {
        requirements: requirements.len(),
        tasks: parsed.len(),
        ..TraceReport::default()
    };

    let mut covered: BTreeSet<String> = BTreeSet::new();
    let mut seen_ids: BTreeSet<String> = BTreeSet::new();
    for task in &parsed {
        if !seen_ids.insert(task.id.clone()) {
            report.duplicate_task_ids.push(task.id.clone());
        }
        let mut refs: BTreeSet<String> = BTreeSet::new();
        for raw in &task.refs {
            for token in expand_range(raw) {
                if known.contains(&token) {
                    covered.insert(token.clone());
                    refs.insert(token);
                } else if token.starts_with("T-") {
                    continue;
                } else {
                    report.unknown_refs.push((task.id.clone(), token));
                }
            }
        }
        if refs.is_empty() {
            report.tasks_without_refs.push(task.id.clone());
        }
    }

    for req in &requirements {
        if !covered.contains(&req.id) {
            report.uncovered_requirements.push(req.id.clone());
        }
        *report.areas.entry(req.area.clone()).or_insert(0) += 1;
    }
    for area in areas {
        let has_task = parsed.iter().any(|t| {
            t.refs.iter().any(|r| {
                expand_range(r).iter().any(|id| {
                    requirements.iter().any(|req| req.id == *id && req.area == area)
                })
            })
        });
        if !has_task {
            report.uncovered_areas.push(area);
        }
    }
    report
}

/// `POL-01..POL-05` yields both endpoints (and interior ids when the span is
/// small enough to matter for coverage).
fn expand_range(raw: &str) -> Vec<String> {
    let mut parts = raw.split("..");
    let first = parts.next().unwrap_or("");
    let Some(second) = parts.next() else {
        return vec![raw.to_string()];
    };
    let Some((a_area, a_num)) = split_id(first) else {
        return vec![raw.to_string()];
    };
    let (b_area, b_num) = match split_id(second) {
        Some(v) => v,
        None => return vec![raw.to_string()],
    };
    if a_area != b_area {
        return vec![first.to_string(), second.to_string()];
    }
    let (lo, hi) = if a_num <= b_num { (a_num, b_num) } else { (b_num, a_num) };
    (lo..=hi)
        .take(64)
        .map(|n| format!("{a_area}-{n:02}"))
        .collect()
}

fn split_id(id: &str) -> Option<(&str, u32)> {
    let (area, num) = id.rsplit_once('-')?;
    let num = num.parse::<u32>().ok()?;
    if area.is_empty() || !area.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
        return None;
    }
    Some((area, num))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEATURES: &str = "## Part 9\n- **OLD-01** Ignored.\n\n## Part 10: Requirements\n\n### 10.1 Foundations (`FND`)\n\n- **FND-01 One.** MUST.\n- **FND-02 Two.** MUST.\n\n### 10.2 Actions (`ACT`)\n\n- **ACT-01 One.** MUST.\n\n## Part 11\n- **XXX-01 Not in part 10.**\n";

    #[test]
    fn parses_requirements_only_from_part_10() {
        let reqs = parse_features(FEATURES);
        assert_eq!(reqs.len(), 3);
        assert_eq!(reqs[0].id, "FND-01");
        assert_eq!(reqs[0].area, "FND");
        assert_eq!(reqs[2].area, "ACT");
        assert!(!reqs.iter().any(|r| r.id.starts_with("OLD")));
        assert!(!reqs.iter().any(|r| r.id.starts_with("XXX")));
    }

    #[test]
    fn range_references_expand() {
        let ids = expand_range("POL-01..POL-04");
        assert_eq!(ids, vec!["POL-01", "POL-02", "POL-03", "POL-04"]);
        assert_eq!(expand_range("FND-01"), vec!["FND-01"]);
        assert_eq!(expand_range("TODO-11..TODO-03").len(), 9);
    }

    #[test]
    fn missing_task_for_a_requirement_fails() {
        let tasks = "## M0 — Foundations\n\n- **T-A.** Does one. **Refs:** FND-01. **Done:** x.\n\n- **T-B.** Does two. **Refs:** ACT-01. **Done:** x.\n";
        let report = check(FEATURES, tasks);
        assert!(!report.ok());
        assert_eq!(report.uncovered_requirements, vec!["FND-02"]);
    }

    #[test]
    fn task_without_refs_fails() {
        let tasks = "## M0 — Foundations\n\n- **T-A.** Nothing. **Done:** x.\n";
        let report = check(FEATURES, tasks);
        assert_eq!(report.tasks_without_refs, vec!["T-A"]);
    }

    #[test]
    fn unknown_reference_fails() {
        let tasks = "## M0 — Foundations\n\n- **T-A.** X. **Refs:** FND-01, FND-99. **Done:** x.\n";
        let report = check(FEATURES, tasks);
        assert!(report.unknown_refs.iter().any(|(t, r)| t == "T-A" && r == "FND-99"));
    }

    #[test]
    fn duplicate_task_id_fails() {
        let tasks = "## M0 — Foundations\n\n- **T-A.** One. **Refs:** FND-01. **Done:** x.\n\n- **T-A.** Two. **Refs:** FND-02. **Done:** x.\n";
        let report = check(FEATURES, tasks);
        assert_eq!(report.duplicate_task_ids, vec!["T-A"]);
    }

    #[test]
    fn full_coverage_passes() {
        let tasks = "## M0 — Foundations\n\n- **T-A.** One. **Refs:** FND-01, FND-02. **Done:** x.\n\n- **T-B.** Two. **Refs:** ACT-01. **Done:** x.\n";
        let report = check(FEATURES, tasks);
        assert!(report.ok(), "{:?}", report.errors());
    }
}

