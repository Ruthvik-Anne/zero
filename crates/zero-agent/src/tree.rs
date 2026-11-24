//! Session tree (SES-02): named, resumed, forked, cloned, and tree-structured
//! sessions with parent links and cumulative file tracking.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zero_store::session::{
    read_meta, write_meta, BranchSummary, Cursor, Entry, Record, SessionLog, SessionMeta,
    ENTRY_SCHEMA_VERSION,
};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionNode {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub parent: Option<String>,
    pub created_ts: i64,
    /// Files this session itself touched, with edit counts.
    #[serde(default)]
    pub files: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResumeView {
    pub node: SessionNode,
    pub visible: Vec<Record>,
    pub summary: Option<BranchSummary>,
    pub cumulative_files: BTreeMap<String, u64>,
    pub cursor: Cursor,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TreeFile {
    nodes: BTreeMap<String, SessionNode>,
}

pub struct SessionTree {
    root: PathBuf,
    nodes: BTreeMap<String, SessionNode>,
}

impl SessionTree {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        let path = root.join("tree.json");
        let nodes = if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            let file: TreeFile = serde_json::from_str(&text)?;
            file.nodes
        } else {
            BTreeMap::new()
        };
        Ok(Self { root, nodes })
    }

    fn save(&self) -> Result<()> {
        let path = self.root.join("tree.json");
        let tmp = path.with_extension("tmp");
        let file = TreeFile { nodes: self.nodes.clone() };
        std::fs::write(&tmp, serde_json::to_vec_pretty(&file)?)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn log_path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.jsonl"))
    }

    pub fn node(&self, id: &str) -> Option<&SessionNode> {
        self.nodes.get(id)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &SessionNode> {
        self.nodes.values()
    }

    fn new_id(&self) -> String {
        let mut n = self.nodes.len() as u64 + 1;
        loop {
            let id = format!("s{n:04}");
            if !self.nodes.contains_key(&id) {
                return id;
            }
            n += 1;
        }
    }

    pub fn create(&mut self, name: impl Into<String>, project: Option<String>, ts: i64) -> Result<SessionNode> {
        let id = self.new_id();
        let node = SessionNode {
            id: id.clone(),
            name: name.into(),
            parent: None,
            created_ts: ts,
            files: BTreeMap::new(),
        };
        let log_path = self.log_path(&id);
        SessionLog::create(
            &log_path,
            SessionMeta {
                schema: ENTRY_SCHEMA_VERSION,
                generation: 1,
                created_ts: ts,
                name: node.name.clone(),
                project,
                parent: None,
            },
        )?;
        self.nodes.insert(id, node.clone());
        self.save()?;
        Ok(node)
    }

    fn copy_until(&mut self, parent: &str, at: Option<u64>, name: impl Into<String>, ts: i64) -> Result<SessionNode> {
        let parent_node = self
            .nodes
            .get(parent)
            .cloned()
            .ok_or_else(|| ZeroError::new(ErrorCode::SessionNotFound, format!("parent session `{parent}`")))?;
        let source = SessionLog::open(self.log_path(parent))?;
        let records = source.records()?;
        let taken: Vec<Record> = match at {
            Some(seq) => records.into_iter().filter(|r| r.seq <= seq).collect(),
            None => records,
        };
        let id = self.new_id();
        let node = SessionNode {
            id: id.clone(),
            name: name.into(),
            parent: Some(parent.to_string()),
            created_ts: ts,
            files: BTreeMap::new(),
        };
        let log_path = self.log_path(&id);
        SessionLog::create(
            &log_path,
            SessionMeta {
                schema: ENTRY_SCHEMA_VERSION,
                generation: 1,
                created_ts: ts,
                name: node.name.clone(),
                project: source.meta().project.clone(),
                parent: Some(parent.to_string()),
            },
        )?;
        let mut log = SessionLog::open(&log_path)?;
        for record in taken {
            log.append(record.ts, record.entry)?;
        }
        let _ = parent_node;
        self.nodes.insert(id, node.clone());
        self.save()?;
        Ok(node)
    }

    /// Fork at an entry (inclusive). The new session keeps the prefix.
    pub fn fork(&mut self, parent: &str, at_seq: u64, name: impl Into<String>, ts: i64) -> Result<SessionNode> {
        if !self.nodes.contains_key(parent) {
            return Err(ZeroError::new(ErrorCode::SessionNotFound, format!("session `{parent}`")));
        }
        let log = SessionLog::open(self.log_path(parent))?;
        if !log.records()?.iter().any(|r| r.seq == at_seq) {
            return Err(ZeroError::new(
                ErrorCode::ForkFailed,
                format!("entry {at_seq} does not exist in `{parent}`"),
            ));
        }
        self.copy_until(parent, Some(at_seq), name, ts)
    }

    /// Clone every entry of the parent.
    pub fn clone_session(&mut self, parent: &str, name: impl Into<String>, ts: i64) -> Result<SessionNode> {
        if !self.nodes.contains_key(parent) {
            return Err(ZeroError::new(ErrorCode::SessionNotFound, format!("session `{parent}`")));
        }
        self.copy_until(parent, None, name, ts)
    }

    pub fn log(&self, id: &str) -> Result<SessionLog> {
        if !self.nodes.contains_key(id) {
            return Err(ZeroError::new(ErrorCode::SessionNotFound, format!("session `{id}`")));
        }
        SessionLog::open(self.log_path(id))
    }

    pub fn append(&mut self, id: &str, ts: i64, entry: Entry) -> Result<Record> {
        let mut log = self.log(id)?;
        let record = log.append(ts, entry)?;
        Ok(record)
    }

    pub fn record_file(&mut self, id: &str, path: &str) -> Result<()> {
        let node = self
            .nodes
            .get_mut(id)
            .ok_or_else(|| ZeroError::new(ErrorCode::SessionNotFound, format!("session `{id}`")))?;
        *node.files.entry(path.to_string()).or_insert(0) += 1;
        self.save()
    }

    /// Files touched by this session and every ancestor.
    pub fn cumulative_files(&self, id: &str) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        let mut cursor = self.nodes.get(id);
        while let Some(node) = cursor {
            for (path, count) in &node.files {
                *out.entry(path.clone()).or_insert(0) += count;
            }
            cursor = node.parent.as_ref().and_then(|p| self.nodes.get(p));
        }
        out
    }

    pub fn path_from_root(&self, id: &str) -> Vec<String> {
        let mut chain = Vec::new();
        let mut cursor = self.nodes.get(id);
        while let Some(node) = cursor {
            chain.push(node.name.clone());
            cursor = node.parent.as_ref().and_then(|p| self.nodes.get(p));
        }
        chain.reverse();
        chain
    }

    pub fn render(&self) -> String {
        fn walk(nodes: &BTreeMap<String, SessionNode>, parent: Option<&str>, depth: usize, out: &mut String) {
            let mut children: Vec<&SessionNode> =
                nodes.values().filter(|n| n.parent.as_deref() == parent).collect();
            children.sort_by(|a, b| a.created_ts.cmp(&b.created_ts).then(a.id.cmp(&b.id)));
            for child in children {
                out.push_str(&format!("{}- {} ({})\n", "  ".repeat(depth), child.name, child.id));
                walk(nodes, Some(&child.id), depth + 1, out);
            }
        }
        let mut out = String::new();
        walk(&self.nodes, None, 0, &mut out);
        out
    }

    /// Resume: the visible tail, the latest branch summary, and cumulative files.
    pub fn resume(&self, id: &str) -> Result<ResumeView> {
        let node = self
            .nodes
            .get(id)
            .cloned()
            .ok_or_else(|| ZeroError::new(ErrorCode::SessionNotFound, format!("session `{id}`")))?;
        let log = SessionLog::open(self.log_path(id))?;
        let records = log.records()?;
        let visible = zero_store::session::visible_slice(&records);
        let summary = records.iter().rev().find_map(|r| match &r.entry {
            Entry::BranchSummary { summary } => Some(summary.clone()),
            _ => None,
        });
        let meta = read_meta(log.path()).unwrap_or_default();
        let sequence = records.last().map(|r| r.seq + 1).unwrap_or(0);
        Ok(ResumeView {
            node,
            visible,
            summary,
            cumulative_files: self.cumulative_files(id),
            cursor: Cursor::new(meta.generation.max(1), sequence),
        })
    }

    /// Persist the name after a resume or rename.
    pub fn rename(&mut self, id: &str, name: impl Into<String>) -> Result<()> {
        let name = name.into();
        {
            let node = self
                .nodes
                .get_mut(id)
                .ok_or_else(|| ZeroError::new(ErrorCode::SessionNotFound, format!("session `{id}`")))?;
            node.name = name.clone();
        }
        let log_path = self.log_path(id);
        if let Ok(mut meta) = read_meta(&log_path) {
            meta.name = name;
            write_meta(&log_path, &meta)?;
        }
        self.save()
    }
}

/// Auto-name from project and timestamp (SES-11).
pub fn auto_name(project: Option<&str>, ts: zero_types::id::Timestamp) -> String {
    let project = project.unwrap_or("session");
    format!("{project} {}", ts.as_stamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_types::id::Timestamp;

    fn message(text: &str) -> Entry {
        Entry::Message {
            role: zero_store::session::Role::User,
            text: text.into(),
            tool_calls: vec![],
            tool_call_id: None,
        }
    }

    #[test]
    fn three_level_tree_forks_resumes_and_renders() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = SessionTree::open(dir.path()).unwrap();
        let a = tree.create("root", Some("proj".into()), 100).unwrap();
        for i in 0..4 {
            tree.append(&a.id, 101 + i as i64, message(&format!("a{i}"))).unwrap();
        }
        tree.record_file(&a.id, "src/lib.rs").unwrap();

        let b = tree.fork(&a.id, 2, "branch-b", 200).unwrap();
        tree.append(&b.id, 201, message("b0")).unwrap();
        tree.record_file(&b.id, "src/main.rs").unwrap();

        let c = tree.fork(&b.id, 3, "branch-c", 300).unwrap();
        tree.append(&c.id, 301, message("c0")).unwrap();
        tree.record_file(&c.id, "src/lib.rs").unwrap();

        // Parent links form a three-level chain.
        assert_eq!(tree.node(&b.id).unwrap().parent.as_deref(), Some(a.id.as_str()));
        assert_eq!(c.parent.as_deref(), Some(b.id.as_str()));
        assert_eq!(tree.path_from_root(&c.id), vec!["root", "branch-b", "branch-c"]);

        // Fork copied the prefix only.
        let b_log = tree.log(&b.id).unwrap().records().unwrap();
        let texts: Vec<&str> = b_log.iter().filter_map(|r| r.entry.message_text()).collect();
        assert_eq!(texts, vec!["a0", "a1", "a2", "b0"]);

        // Resume shows the visible tail and cumulative files from all ancestors.
        let resumed = tree.resume(&c.id).unwrap();
        assert_eq!(resumed.node.name, "branch-c");
        assert!(resumed.visible.iter().any(|r| r.entry.message_text() == Some("c0")));
        assert_eq!(resumed.cumulative_files.get("src/lib.rs"), Some(&2));
        assert_eq!(resumed.cumulative_files.get("src/main.rs"), Some(&1));

        // Render is a tree with indentation.
        let rendered = tree.render();
        assert_eq!(rendered, "- root (s0001)\n  - branch-b (s0002)\n    - branch-c (s0003)\n");

        // Clone takes every entry.
        let cloned = tree.clone_session(&b.id, "clone-b", 400).unwrap();
        let cloned_log = tree.log(&cloned.id).unwrap().records().unwrap();
        assert_eq!(cloned_log.len(), b_log.len());
    }

    #[test]
    fn missing_parent_and_bad_fork_are_typed() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = SessionTree::open(dir.path()).unwrap();
        assert_eq!(
            tree.fork("nope", 0, "x", 0).unwrap_err().code(),
            ErrorCode::SessionNotFound
        );
        let a = tree.create("a", None, 0).unwrap();
        assert_eq!(tree.fork(&a.id, 99, "x", 0).unwrap_err().code(), ErrorCode::ForkFailed);
    }

    #[test]
    fn auto_names_from_project_and_timestamp() {
        let ts = Timestamp::from_millis(1_700_000_000_000);
        assert_eq!(auto_name(Some("zero"), ts), "zero 20231114-221320");
        assert_eq!(auto_name(None, ts), "session 20231114-221320");
    }
}
