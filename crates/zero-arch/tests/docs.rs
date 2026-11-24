//! Document-level checks that are not the traceability report itself:
//! the requirement index must cover every Part 10 area, and the four top-level
//! documents must cross-link.

#[cfg(test)]
mod tests {
    use std::path::Path;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn requirement_index_covers_every_part_10_area() {
        let features = std::fs::read_to_string(root().join("features.md")).unwrap();
        let index = std::fs::read_to_string(root().join("docs/requirements-index.md")).unwrap();
        let reqs = zero_arch::parse_features(&features);
        assert!(!reqs.is_empty());
        let areas: std::collections::BTreeSet<&str> =
            reqs.iter().map(|r| r.area.as_str()).collect();
        for area in &areas {
            assert!(
                index.contains(&format!("`{area}`")),
                "requirement index is missing area {area}"
            );
        }
        assert_eq!(areas.len(), 38, "Part 10 declares 38 areas");
    }

    #[test]
    fn the_four_documents_cross_link() {
        let files = ["features.md", "architecture.md", "plan.md", "tasks.md"];
        for file in files {
            let text = std::fs::read_to_string(root().join(file)).unwrap_or_default();
            for other in files {
                if other == file {
                    continue;
                }
                assert!(
                    text.contains(other),
                    "{file} must link to {other}"
                );
            }
        }
    }

    #[test]
    fn task_statuses_use_the_documented_vocabulary() {
        let tasks = std::fs::read_to_string(root().join("tasks.md")).unwrap();
        for line in tasks.lines() {
            if let Some(idx) = line.find("**Status:**") {
                let value = line[idx + "**Status:**".len()..].trim();
                // The legend line lists the vocabulary in backticks.
                if value.starts_with('`') {
                    continue;
                }
                let first = value.split([' ', '—', '.']).next().unwrap_or("");
                assert!(
                    ["todo", "doing", "done", "blocked", "moved"].contains(&first),
                    "unknown status `{first}` in: {line}"
                );
            }
        }
    }
}
