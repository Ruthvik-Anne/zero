//! Minimal manifest reader: no TOML dependency, only the two constructs the
//! dependency check needs (workspace `members` and dependency keys).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct Manifest {
    pub name: String,
    /// Dependency name -> optional local path.
    pub dependencies: BTreeMap<String, Option<PathBuf>>,
}

/// Extract `[package] name` and all dependency sections from one manifest.
pub fn parse_manifest(text: &str) -> Manifest {
    let text = text.trim_start_matches('\u{feff}');
    let mut out = Manifest::default();
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(|c| c == '[' || c == ']').to_string();
            continue;
        }
        if section == "package" {
            if let Some(rest) = line.strip_prefix("name") {
                if let Some(v) = quoted_value(rest) {
                    out.name = v;
                }
            }
            continue;
        }
        let is_dep_section = matches!(
            section.as_str(),
            "dependencies" | "dev-dependencies" | "build-dependencies"
        ) || section.starts_with("target.");
        if is_dep_section {
            let key = line.split('=').next().unwrap_or("").trim().trim_matches('"').to_string();
            if key.is_empty() {
                continue;
            }
            let value = line.split_once('=').map(|(_, v)| v).unwrap_or("");
            let path = if value.contains("path") {
                quoted_after(value, "path")
            } else {
                None
            };
            out.dependencies.insert(key, path);
        }
    }
    out
}

fn quoted_value(rest: &str) -> Option<String> {
    let rest = rest.trim_start_matches([' ', '=']);
    let start = rest.find('"')?;
    let tail = &rest[start + 1..];
    let end = tail.find('"')?;
    Some(tail[..end].to_string())
}

fn quoted_after(value: &str, key: &str) -> Option<PathBuf> {
    let idx = value.find(key)?;
    let tail = &value[idx + key.len()..];
    let start = tail.find('"')?;
    let rest = &tail[start + 1..];
    let end = rest.find('"')?;
    Some(PathBuf::from(&rest[..end]))
}

/// Workspace member paths from the root manifest.
pub fn workspace_members(root: &Path) -> Vec<PathBuf> {
    let text = std::fs::read_to_string(root.join("Cargo.toml")).expect("root Cargo.toml");
    let mut members = Vec::new();
    let mut in_members = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("members") {
            in_members = true;
        }
        if in_members {
            let mut rest = line;
            while let Some(start) = rest.find('"') {
                let after = &rest[start + 1..];
                match after.find('"') {
                    Some(end) => {
                        members.push(root.join(&after[..end]));
                        rest = &after[end + 1..];
                    }
                    None => break,
                }
            }
            if line.ends_with(']') {
                in_members = false;
            }
        }
    }
    members
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_name_and_path_dependencies() {
        let m = parse_manifest(
            r#"
[package]
name = "zero-demo"
version = "0.1"

[dependencies]
zero-types = { workspace = true }
serde = "1"
zero-store = { workspace = true }

[dev-dependencies]
tempfile = "3"
"#,
        );
        assert_eq!(m.name, "zero-demo");
        assert!(m.dependencies.contains_key("zero-types"));
        assert!(m.dependencies.contains_key("zero-store"));
        assert!(m.dependencies.contains_key("tempfile"));
        assert!(!m.dependencies.contains_key("package"));
    }
}

