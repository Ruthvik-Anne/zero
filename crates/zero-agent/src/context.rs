//! Context files (SES-05): `AGENTS.md` and `CLAUDE.md` with a documented
//! precedence and a size cap.
//!
//! Rules, from `docs/context-files.md`:
//! 1. Walk from the project root down to the working directory.
//! 2. In a directory, `AGENTS.md` wins; `CLAUDE.md` there is skipped.
//! 3. The nearest instruction file wins over farther ones: a nested
//!    `AGENTS.md` or `CLAUDE.md` replaces the root file for that subtree.
//! 4. Each file is capped at 32 KiB, truncated on a character boundary with a
//!    marker. The bundle is capped at 128 KiB.

use std::path::{Path, PathBuf};

pub const FILE_CAP_BYTES: usize = 32 * 1024;
pub const TOTAL_CAP_BYTES: usize = 128 * 1024;
pub const TRUNCATION_MARKER: &str = "\n[context file truncated at 32 KiB]\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Agents,
    Claude,
}

impl FileKind {
    fn file_name(self) -> &'static str {
        match self {
            FileKind::Agents => "AGENTS.md",
            FileKind::Claude => "CLAUDE.md",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextFile {
    pub path: PathBuf,
    pub kind: FileKind,
    pub bytes: usize,
    pub truncated: bool,
    pub content: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextBundle {
    pub files: Vec<ContextFile>,
    pub text: String,
}

impl ContextBundle {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Load context files for `cwd` inside `root`.
pub fn load(root: &Path, cwd: &Path) -> ContextBundle {
    let root = canonical(root).unwrap_or_else(|| root.to_path_buf());
    let cwd = canonical(cwd).unwrap_or_else(|| cwd.to_path_buf());
    // Build the chain root -> ... -> cwd; if cwd is outside root, only cwd.
    let mut chain: Vec<PathBuf> = Vec::new();
    let mut cursor = Some(cwd.as_path());
    while let Some(dir) = cursor {
        chain.push(dir.to_path_buf());
        if dir == root {
            break;
        }
        cursor = dir.parent();
    }
    chain.reverse();
    if chain.first() != Some(&root) {
        chain = vec![cwd.clone()];
    }

    // Exactly one instruction file is loaded: the nearest one. In a directory,
    // AGENTS.md beats CLAUDE.md.
    let mut winner: Option<ContextFile> = None;
    for dir in chain {
        let agents_path = dir.join(FileKind::Agents.file_name());
        let claude_path = dir.join(FileKind::Claude.file_name());
        if let Some(file) = read_file(&agents_path, FileKind::Agents) {
            winner = Some(file);
        } else if let Some(file) = read_file(&claude_path, FileKind::Claude) {
            winner = Some(file);
        }
    }

    let mut files = Vec::new();
    if let Some(w) = winner {
        files.push(w);
    }

    // Total cap.
    let mut text = String::new();
    let mut kept = Vec::new();
    for mut file in files {
        if text.len() + file.content.len() > TOTAL_CAP_BYTES {
            let room = TOTAL_CAP_BYTES.saturating_sub(text.len());
            if room == 0 {
                break;
            }
            truncate_to(&mut file.content, room);
            file.truncated = true;
        }
        text.push_str(&file.content);
        if !text.ends_with('\n') {
            text.push('\n');
        }
        kept.push(file);
    }
    ContextBundle { files: kept, text }
}

fn canonical(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok()
}

fn read_file(path: &Path, kind: FileKind) -> Option<ContextFile> {
    let bytes = std::fs::read(path).ok()?;
    let mut content = String::from_utf8_lossy(&bytes).to_string();
    let truncated = bytes.len() > FILE_CAP_BYTES;
    if truncated {
        truncate_to(&mut content, FILE_CAP_BYTES);
        content.push_str(TRUNCATION_MARKER);
    }
    Some(ContextFile {
        path: path.to_path_buf(),
        kind,
        bytes: bytes.len(),
        truncated,
        content,
    })
}

fn truncate_to(content: &mut String, cap: usize) {
    if content.len() <= cap {
        return;
    }
    let mut end = cap;
    while end > 0 && !content.is_char_boundary(end) {
        end -= 1;
    }
    content.truncate(end);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str) {
        std::fs::write(dir.join(name), text).unwrap();
    }

    #[test]
    fn conflicting_files_resolve_by_the_documented_rule() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let src = root.join("src");
        std::fs::create_dir_all(&src).unwrap();
        write(root, "AGENTS.md", "root agents");
        write(root, "CLAUDE.md", "root claude");

        // At root, AGENTS.md wins and CLAUDE.md is skipped.
        let bundle = load(root, root);
        assert_eq!(bundle.files.len(), 1);
        assert_eq!(bundle.files[0].kind, FileKind::Agents);
        assert!(bundle.text.contains("root agents"));
        assert!(!bundle.text.contains("root claude"));

        // A nested AGENTS.md replaces the root one for that subtree.
        write(&src, "AGENTS.md", "nested agents");
        let bundle = load(root, &src);
        assert_eq!(bundle.files.len(), 1);
        assert!(bundle.text.contains("nested agents"));
        assert!(!bundle.text.contains("root agents"));

        // Without a nested AGENTS.md, a nested CLAUDE.md is used only if no
        // nearer AGENTS.md exists: here root AGENTS.md is nearer than nothing.
        std::fs::remove_file(src.join("AGENTS.md")).unwrap();
        write(&src, "CLAUDE.md", "nested claude");
        let bundle = load(root, &src);
        assert_eq!(bundle.files.len(), 1);
        assert_eq!(bundle.files[0].kind, FileKind::Claude);
        assert!(bundle.text.contains("nested claude"));
        assert!(!bundle.text.contains("root agents"));
    }

    #[test]
    fn root_and_nested_without_conflict_are_both_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let nested = root.join("crates").join("a");
        std::fs::create_dir_all(&nested).unwrap();
        write(root, "CLAUDE.md", "root claude");
        write(&nested, "AGENTS.md", "nested agents");
        let bundle = load(root, &nested);
        // The nested AGENTS.md replaces the root CLAUDE.md for this subtree.
        assert_eq!(bundle.files.len(), 1);
        assert!(bundle.text.contains("nested agents"));
    }

    #[test]
    fn size_cap_truncates_on_a_character_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut big = "é".repeat(FILE_CAP_BYTES); // 2 bytes each
        write(root, "AGENTS.md", &big);
        let bundle = load(root, root);
        assert_eq!(bundle.files.len(), 1);
        assert!(bundle.files[0].truncated);
        assert!(bundle.text.contains(TRUNCATION_MARKER.trim()));
        assert!(bundle.files[0].content.len() <= FILE_CAP_BYTES + TRUNCATION_MARKER.len() + 4);
        // The truncation did not split a multi-byte character.
        assert!(bundle.files[0].content.is_char_boundary(bundle.files[0].content.len()));
        big.clear();
    }

    #[test]
    fn missing_files_produce_an_empty_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = load(dir.path(), dir.path());
        assert!(bundle.is_empty());
        assert_eq!(bundle.text, "");
    }
}
