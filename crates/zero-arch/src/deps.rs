//! Dependency-direction and cycle checks over the crate graph.

use crate::layers::{layer_of, declared_names};
use crate::manifest::{parse_manifest, workspace_members};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Violation {
    UpwardEdge { from: String, to: String },
    UndeclaredDependency { from: String, to: String },
    UndeclaredCrate { name: String },
    MissingMember { name: String },
    Cycle { path: Vec<String> },
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Violation::UpwardEdge { from, to } => write!(f, "upward edge: {from} -> {to}"),
            Violation::UndeclaredDependency { from, to } => {
                write!(f, "undeclared edge: {from} -> {to} (not in the layer table)")
            }
            Violation::UndeclaredCrate { name } => write!(f, "workspace crate `{name}` is not in the layer table"),
            Violation::MissingMember { name } => write!(f, "declared crate `{name}` is missing from the workspace"),
            Violation::Cycle { path } => write!(f, "cycle: {}", path.join(" -> ")),
        }
    }
}

/// Crates that exist only to build and test the product.
pub const TOOLING: &[&str] = &["zero-arch", "xtask"];

/// Check an in-memory graph against the declared layers.
pub fn check_graph(edges: &BTreeMap<String, Vec<String>>) -> Vec<Violation> {
    let mut violations = Vec::new();
    for (from, targets) in edges {
        if TOOLING.contains(&from.as_str()) {
            continue;
        }
        let Some(from_layer) = layer_of(from) else {
            violations.push(Violation::UndeclaredCrate { name: from.clone() });
            continue;
        };
        for to in targets {
            if TOOLING.contains(&to.as_str()) {
                continue;
            }
            let Some(to_layer) = layer_of(to) else {
                violations.push(Violation::UndeclaredCrate { name: to.clone() });
                continue;
            };
            if to_layer.level >= from_layer.level {
                violations.push(Violation::UpwardEdge { from: from.clone(), to: to.clone() });
            } else if !from_layer.may_depend_on.contains(&to.as_str()) {
                violations.push(Violation::UndeclaredDependency { from: from.clone(), to: to.clone() });
            }
        }
    }
    violations.extend(find_cycles(edges));
    violations
}

pub fn find_cycles(edges: &BTreeMap<String, Vec<String>>) -> Vec<Violation> {
    #[derive(Clone, Copy, PartialEq)]
    enum Color {
        White,
        Grey,
        Black,
    }
    let mut color: BTreeMap<&str, Color> = BTreeMap::new();
    let mut stack: Vec<String> = Vec::new();
    let mut out = Vec::new();
    fn visit<'a>(
        node: &'a str,
        edges: &'a BTreeMap<String, Vec<String>>,
        color: &mut BTreeMap<&'a str, Color>,
        stack: &mut Vec<String>,
        out: &mut Vec<Violation>,
    ) {
        color.insert(node, Color::Grey);
        stack.push(node.to_string());
        if let Some(targets) = edges.get(node) {
            for target in targets {
                // Only follow nodes present as keys (edges map keys are crates).
                if !edges.contains_key(target.as_str()) {
                    continue;
                }
                match color.get(target.as_str()).copied().unwrap_or(Color::White) {
                    Color::White => visit(
                        edges.get_key_value(target.as_str()).map(|(k, _)| k.as_str()).unwrap_or(""),
                        edges,
                        color,
                        stack,
                        out,
                    ),
                    Color::Grey => {
                        let start = stack.iter().position(|n| n == target).unwrap_or(0);
                        let mut path = stack[start..].to_vec();
                        path.push(target.clone());
                        out.push(Violation::Cycle { path });
                    }
                    Color::Black => {}
                }
            }
        }
        stack.pop();
        color.insert(node, Color::Black);
    }

    let keys: Vec<&str> = edges.keys().map(|k| k.as_str()).collect();
    for key in keys {
        if color.get(key).copied().unwrap_or(Color::White) == Color::White {
            visit(key, edges, &mut color, &mut stack, &mut out);
        }
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphReport {
    pub crates: Vec<String>,
    pub edges: BTreeMap<String, Vec<String>>,
    pub violations: Vec<Violation>,
}

/// Read the workspace and check the real crate graph.
pub fn check_workspace(root: &Path) -> GraphReport {
    let members = workspace_members(root);
    let mut crates = Vec::new();
    let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut seen = BTreeSet::new();

    for member in &members {
        let manifest_path = member.join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest_path) else {
            continue;
        };
        let manifest = parse_manifest(&text);
        if manifest.name.is_empty() {
            continue;
        }
        crates.push(manifest.name.clone());
        seen.insert(manifest.name.clone());
        let targets: Vec<String> = manifest
            .dependencies
            .keys()
            .filter(|k| k.starts_with("zero-"))
            .cloned()
            .collect();
        if manifest.name.starts_with("zero-") {
            edges.entry(manifest.name.clone()).or_default().extend(targets);
        }
    }

    let mut violations = Vec::new();
    for declared in declared_names() {
        if !seen.contains(declared) {
            violations.push(Violation::MissingMember { name: declared.to_string() });
        }
    }
    for name in &crates {
        if name.starts_with("zero-") && !TOOLING.contains(&name.as_str()) && layer_of(name).is_none() {
            violations.push(Violation::UndeclaredCrate { name: name.clone() });
        }
    }
    violations.extend(check_graph(&edges));
    GraphReport { crates, edges, violations }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(pairs: &[(&str, &str)]) -> BTreeMap<String, Vec<String>> {
        let mut g: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (from, to) in pairs {
            g.entry(from.to_string()).or_default().push(to.to_string());
        }
        g
    }

    #[test]
    fn real_workspace_has_no_upward_edge_or_cycle() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let report = check_workspace(&root);
        assert!(report.violations.is_empty(), "{:#?}", report.violations);
        assert!(report.crates.len() >= 20, "workspace should have the full crate map");
    }

    #[test]
    fn upward_edge_is_rejected() {
        let g = graph(&[("zero-types", "zero-store")]);
        let v = check_graph(&g);
        assert!(v.iter().any(|x| matches!(x, Violation::UpwardEdge { .. })), "{v:?}");
    }

    #[test]
    fn same_layer_edge_is_rejected() {
        let g = graph(&[("zero-store", "zero-actions")]);
        let v = check_graph(&g);
        assert!(!v.is_empty());
    }

    #[test]
    fn cycle_is_rejected_with_the_path() {
        let g = graph(&[
            ("zero-types", "zero-store"),
            ("zero-store", "zero-policy"),
            ("zero-policy", "zero-types"),
        ]);
        let v = check_graph(&g);
        let cycle = v.iter().find(|x| matches!(x, Violation::Cycle { .. })).expect("cycle detected");
        match cycle {
            Violation::Cycle { path } => {
                assert!(path.len() >= 3);
                assert_eq!(path.first(), path.last());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn declared_but_unlisted_edge_is_rejected() {
        // zero-agent may not depend on zero-web in the table.
        let g = graph(&[("zero-agent", "zero-web")]);
        let v = check_graph(&g);
        assert!(v.iter().any(|x| matches!(x, Violation::UndeclaredDependency { .. })));
    }
}


